"""
ingest/downloader.py
Downloads and updates NVD CVE JSON feeds from the community-maintained fkie-cad mirror
with local caching (using HTTP HEAD requests for cache validation),
exponential backoff retry mechanisms, and structured logging.
Supports yearly archives (2019-2024) and incremental updates via the modified feed.
"""

import os
import time
import gzip
import shutil
import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import requests
from dotenv import load_dotenv

load_dotenv()

# Setup logging configuration
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "downloader.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDDownloader")


class NVDDownloader:
    """
    Enterprise-grade manager for downloading NVD 2.0 feeds from NIST.
    Implements HTTP Range checks for resume capability, skips existing files,
    shows streaming progress, and logs metrics.
    """

    CACHE_META_FILE = "cache_meta.json"

    def __init__(
        self,
        data_dir: Optional[str] = None,
        years: Optional[List[int]] = None,
        max_retries: int = 5,
        backoff_factor: float = 2.0,
    ):
        self.data_dir = Path(data_dir or os.getenv("NVD_DATA_PATH", "./data/nvd"))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.years = years or list(range(2002, 2027))
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.cache_meta_path = self.data_dir / self.CACHE_META_FILE
        self.cache_meta = self._load_cache_metadata()
        self.http_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

    def _load_cache_metadata(self) -> Dict[str, Any]:
        """Load local cache metadata to check ETags and Last-Modified headers."""
        if self.cache_meta_path.exists():
            try:
                with open(self.cache_meta_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.warning("Failed to load cache metadata, starting fresh: %s", e)
        return {}

    def _save_cache_metadata(self):
        """Save ETag/Last-Modified cache metadata to disk."""
        try:
            with open(self.cache_meta_path, "w", encoding="utf-8") as f:
                json.dump(self.cache_meta, f, indent=2)
        except Exception as e:
            logger.error("Failed to save cache metadata: %s", e)

    def _fetch_headers(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch headers using a HEAD request with retry logic, returning content_length."""
        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.head(url, headers=self.http_headers, allow_redirects=True, timeout=15)
                
                # Check for rate limiting or explicit blocks (like 403 / 429)
                if response.status_code == 403 or response.status_code == 429:
                    logger.warning("NVD HEAD check returned status %d. Bypassing cache to download directly.", response.status_code)
                    return None
                    
                if response.status_code in [200, 206]:
                    content_length = response.headers.get("Content-Length")
                    return {
                        "etag": response.headers.get("ETag", "").strip('"'),
                        "last_modified": response.headers.get("Last-Modified", ""),
                        "content_length": int(content_length) if content_length else None
                    }
                logger.warning("HEAD request to %s returned status %d", url, response.status_code)
            except requests.RequestException as e:
                logger.warning("HEAD request attempt %d/%d failed: %s", attempt, self.max_retries, e)
            
            if attempt < self.max_retries:
                sleep_time = self.backoff_factor ** attempt
                time.sleep(sleep_time)
        return None

    def sync_feed(self, feed_id: Union[int, str]) -> Optional[Path]:
        """
        Sync a single NVD feed (either a year or 'modified').
        Downloads the GZ archive from the official NIST NVD feeds,
        supports HTTP Range-based resume capability, decompresses it, and writes JSON.
        """
        src_filename = f"nvdcve-2.0-{feed_id}.json.gz"
        target_json_filename = f"nvdcve-2.0-{feed_id}.json"
        
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/{src_filename}"
        gz_part_path = self.data_dir / f"{src_filename}.part"
        json_path = self.data_dir / target_json_filename

        start_time = time.perf_counter()
        logger.info("Sync check for feed: %s", target_json_filename)

        # 1. Skip check for static archives (ignore 'modified' since it updates continuously)
        if feed_id != "modified" and json_path.exists() and json_path.stat().st_size > 0:
            logger.info("File %s already exists. Skipping download.", target_json_filename)
            logger.info("event=duplicate_skipped | cve_id=feed_%s", feed_id)
            return json_path

        # 2. Fetch remote headers
        live_headers = self._fetch_headers(url)
        remote_size = live_headers.get("content_length") if live_headers else None

        # 3. Cache hit check for modified feed if etag/last-modified matches
        if feed_id == "modified" and json_path.exists() and live_headers:
            cached = self.cache_meta.get(src_filename, {})
            if cached.get("etag") == live_headers["etag"] and cached.get("last_modified") == live_headers["last_modified"]:
                logger.info("Cache hit for %s (no download needed)", target_json_filename)
                return json_path

        # 4. Prepare resume / range download parameters
        headers = self.http_headers.copy()
        existing_size = 0
        file_mode = "wb"
        
        if gz_part_path.exists():
            existing_size = gz_part_path.stat().st_size
            if existing_size > 0:
                if remote_size and existing_size == remote_size:
                    logger.info("Found completed part file %s. Skipping download.", gz_part_path.name)
                elif remote_size and existing_size > remote_size:
                    logger.warning("Part file size %d > remote size %d. Resetting.", existing_size, remote_size)
                    gz_part_path.unlink()
                    existing_size = 0
                else:
                    headers["Range"] = f"bytes={existing_size}-"
                    file_mode = "ab"
                    logger.info("Resuming download of %s from byte %d", src_filename, existing_size)

        success = False
        downloaded_bytes = existing_size

        for attempt in range(1, self.max_retries + 1):
            try:
                # If already downloaded
                if remote_size and downloaded_bytes == remote_size:
                    success = True
                    break

                response = requests.get(url, headers=headers, stream=True, timeout=60)
                
                # Check response code
                if response.status_code == 206:
                    pass
                elif response.status_code == 200:
                    if file_mode == "ab":
                        logger.warning("Server ignored Range request. Downloading from scratch.")
                        file_mode = "wb"
                        downloaded_bytes = 0
                elif response.status_code == 416:
                    logger.warning("Range not satisfiable (416). Resetting download.")
                    if gz_part_path.exists():
                        gz_part_path.unlink()
                    file_mode = "wb"
                    downloaded_bytes = 0
                    headers.pop("Range", None)
                    response = requests.get(url, headers=headers, stream=True, timeout=60)
                    response.raise_for_status()
                else:
                    response.raise_for_status()

                # Get expected length of this stream
                stream_len = response.headers.get("Content-Length")
                total_expected = remote_size or (downloaded_bytes + int(stream_len) if stream_len else None)

                with open(gz_part_path, file_mode) as f:
                    for chunk in response.iter_content(chunk_size=32768):
                        if chunk:
                            f.write(chunk)
                            downloaded_bytes += len(chunk)
                            # Print progress bar to stdout
                            if total_expected:
                                percent = (downloaded_bytes / total_expected) * 100
                                bar_length = 30
                                filled_length = int(round(bar_length * downloaded_bytes / total_expected))
                                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                                print(f"\rDownloading {src_filename}: |{bar}| {percent:.1f}% ({downloaded_bytes}/{total_expected} bytes)", end="", flush=True)
                            else:
                                print(f"\rDownloading {src_filename}: {downloaded_bytes} bytes", end="", flush=True)

                print() # Move cursor to next line
                success = True
                break
            except requests.RequestException as e:
                logger.warning("\nDownload attempt %d/%d failed for %s: %s", attempt, self.max_retries, src_filename, e)
            
            if attempt < self.max_retries:
                sleep_time = self.backoff_factor ** attempt
                logger.info("Waiting %s seconds before retry...", sleep_time)
                time.sleep(sleep_time)
                # Re-adjust Range headers
                if gz_part_path.exists():
                    existing_size = gz_part_path.stat().st_size
                    headers["Range"] = f"bytes={existing_size}-"
                    file_mode = "ab"
                    downloaded_bytes = existing_size

        if not success:
            duration = (time.perf_counter() - start_time) * 1000
            logger.error("All download attempts failed for %s", src_filename)
            logger.error("event=nvd_download | status=failed | feed=%s | latency_ms=%.2f | error=download_failed", target_json_filename, duration)
            if json_path.exists():
                logger.warning("Returning stale cached feed file as fallback: %s", json_path)
                return json_path
            return None

        # 5. Decompress GZIP to JSON and clean up
        try:
            logger.info("Decompressing %s to %s", gz_part_path.name, target_json_filename)
            with gzip.open(gz_part_path, "rb") as gz_in:
                with open(json_path, "wb") as json_out:
                    shutil.copyfileobj(gz_in, json_out)
            
            gz_part_path.unlink() # Delete part file

            # Save cache metadata
            if live_headers:
                self.cache_meta[src_filename] = {
                    "etag": live_headers["etag"],
                    "last_modified": live_headers["last_modified"]
                }
                self._save_cache_metadata()

            duration = (time.perf_counter() - start_time) * 1000
            file_size = json_path.stat().st_size
            logger.info("Successfully synced and decompressed %s", target_json_filename)
            logger.info("event=nvd_download | status=success | feed=%s | latency_ms=%.2f | file_size=%d", target_json_filename, duration, file_size)
            return json_path
        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            logger.error("Decompression failed for %s: %s", src_filename, e)
            logger.error("event=nvd_download | status=failed | feed=%s | latency_ms=%.2f | error=decompression_failed", target_json_filename, duration)
            if gz_part_path.exists():
                gz_part_path.unlink()
            return None

    def sync_yearly_feeds(self) -> List[Path]:
        """Download or update yearly CVE feeds (2002-2026)."""
        logger.info("Starting yearly feeds synchronization...")
        downloaded_paths = []
        for year in self.years:
            path = self.sync_feed(year)
            if path:
                downloaded_paths.append(path)
        return downloaded_paths

    def sync_incremental(self) -> Optional[Path]:
        """Download NVD modified feed (latest changes) for incremental updates."""
        logger.info("Starting incremental updates synchronization...")
        return self.sync_feed("modified")

    def count_total_cves(self) -> int:
        """Helper to print and return total CVE counts in downloaded files."""
        total = 0
        for year in self.years:
            json_path = self.data_dir / f"nvdcve-2.0-{year}.json"
            if json_path.exists():
                try:
                    with open(json_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        count = data.get("totalResults", 0)
                        logger.info("Year %d feed: %s CVEs", year, f"{count:,}")
                        total += count
                except Exception as e:
                    logger.error("Failed to read CVE count for %d: %s", year, e)
        logger.info("Total CVEs in yearly archives: %s", f"{total:,}")
        return total


if __name__ == "__main__":
    # Test downloader run with single year for verification
    downloader = NVDDownloader(years=[2002])
    downloader.sync_yearly_feeds()
    downloader.sync_incremental()
    downloader.count_total_cves()
