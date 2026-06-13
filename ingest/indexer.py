"""
ingest/indexer.py
Embeds CVE records and stores them in ChromaDB with full CRUD support.
Uses BAAI/bge-small-en-v1.5 for dense vector embeddings.
Supports scaled NVD feeds (2002-2026), CWE, CAPEC, CISA KEV, and MITRE ATT&CK.
"""

import os
import json
import time
import logging
import threading
from pathlib import Path
from typing import Union, List, Dict, Any, Optional
import chromadb
from chromadb.utils import embedding_functions
from pydantic import BaseModel
from dotenv import load_dotenv

from ingest.parser import CVERecord

load_dotenv()

# Force HuggingFace to run in offline mode to prevent checking for updates online
os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"

# Setup logging configuration
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "indexer.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDIndexer")

CHROMA_DB_PATH = os.getenv("CHROMA_DB_PATH", "./data/chromadb")
COLLECTION_NAME = "vulnsentinel_cves"
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
BATCH_SIZE = 200

# Thread-safe global client cache
_chroma_client: Optional[chromadb.PersistentClient] = None
_client_lock = threading.Lock()


def get_chroma_client() -> chromadb.PersistentClient:
    """Initialize persistent ChromaDB client using a thread-safe singleton pattern."""
    global _chroma_client
    if _chroma_client is None:
        with _client_lock:
            if _chroma_client is None:
                logger.info("Initializing persistent ChromaDB client at path: %s", CHROMA_DB_PATH)
                _chroma_client = chromadb.PersistentClient(path=CHROMA_DB_PATH)
    return _chroma_client


def get_collection(client: Optional[chromadb.PersistentClient] = None) -> chromadb.Collection:
    """Get or create the CVE collection with the BAAI embedding function."""
    if client is None:
        client = get_chroma_client()

    import torch
    device = "cpu"
    if torch.cuda.is_available():
        device = "cuda"
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        device = "mps"

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBED_MODEL,
        device=device
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )
    return collection


# ─── Pre-computed Statistics Cache ──────────────────────────────────────────

STATS_FILE = Path("./data/db_stats.json")


def _load_db_stats() -> Dict[str, Any]:
    """Load pre-computed statistics from db_stats.json."""
    if STATS_FILE.exists():
        try:
            with open(STATS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load db_stats.json: %s", e)
    return {
        "total_cves": 0,
        "vendors": 0,
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "years": [],
        "last_sync": "Never",
        "cvss_scores": [],
        "years_dist": {},
        "vendors_dist": {},
        "source_dist": {"NVD": 0, "CWE": 0, "CAPEC": 0, "CISA_KEV": 0, "MITRE_ATTACK": 0}
    }


def _save_db_stats(stats: Dict[str, Any]):
    """Save statistics to disk."""
    try:
        STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(STATS_FILE, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        logger.error("Failed to save db_stats.json: %s", e)


def update_stats_on_add(record: Dict[str, Any]):
    """Incrementally update statistics when a record is added/updated."""
    stats = _load_db_stats()
    
    cve_id = record["cve_id"].upper()
    severity = record["severity"].upper()
    cvss = float(record["cvss_score"]) if record.get("cvss_score") is not None else 0.0
    year = str(record["year"]) if record.get("year") else "UNKNOWN"
    source = record.get("source", "NVD")
    products = record.get("products", [])
    
    # Increment totals
    stats["total_cves"] += 1
    
    # Severity
    if severity in stats["severity"]:
        stats["severity"][severity] += 1
    else:
        stats["severity"]["UNKNOWN"] += 1
        
    # Source
    if "source_dist" not in stats:
        stats["source_dist"] = {"NVD": 0, "CWE": 0, "CAPEC": 0, "CISA_KEV": 0, "MITRE_ATTACK": 0}
    stats["source_dist"][source] = stats["source_dist"].get(source, 0) + 1
    
    # CVSS
    stats["cvss_scores"].append(cvss)
    if len(stats["cvss_scores"]) > 1000:
        step = len(stats["cvss_scores"]) // 1000 + 1
        stats["cvss_scores"] = stats["cvss_scores"][::step]
        
    # Year
    if year and year != "UNKNOWN":
        if year not in stats["years"]:
            stats["years"].append(year)
            stats["years"] = sorted(stats["years"])
        stats["years_dist"][year] = stats["years_dist"].get(year, 0) + 1
        
    # Vendors
    vendors_added = set()
    for prod in products:
        parts = prod.split("/")
        if parts and parts[0] and parts[0] != "*":
            vendors_added.add(parts[0])
            
    for vendor in vendors_added:
        stats["vendors_dist"][vendor] = stats["vendors_dist"].get(vendor, 0) + 1
        
    stats["vendors"] = len(stats["vendors_dist"])
    
    from datetime import datetime
    stats["last_sync"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_db_stats(stats)


def update_stats_on_batch(records: List[Dict[str, Any]]):
    """Incrementally update statistics for a batch of records in a single disk I/O operation."""
    if not records:
        return
    stats = _load_db_stats()
    
    from datetime import datetime
    
    for record in records:
        cve_id = record["cve_id"].upper()
        severity = record["severity"].upper()
        cvss = float(record["cvss_score"]) if record.get("cvss_score") is not None else 0.0
        year = str(record["year"]) if record.get("year") else "UNKNOWN"
        source = record.get("source", "NVD")
        products = record.get("products", [])
        
        stats["total_cves"] += 1
        
        # Severity
        if severity in stats["severity"]:
            stats["severity"][severity] += 1
        else:
            stats["severity"]["UNKNOWN"] += 1
            
        # Source
        if "source_dist" not in stats:
            stats["source_dist"] = {"NVD": 0, "CWE": 0, "CAPEC": 0, "CISA_KEV": 0, "MITRE_ATTACK": 0}
        stats["source_dist"][source] = stats["source_dist"].get(source, 0) + 1
        
        # CVSS
        stats["cvss_scores"].append(cvss)
            
        # Year
        if year and year != "UNKNOWN":
            if year not in stats["years"]:
                stats["years"].append(year)
            stats["years_dist"][year] = stats["years_dist"].get(year, 0) + 1
            
        # Vendors
        vendors_added = set()
        for prod in products:
            parts = prod.split("/")
            if parts and parts[0] and parts[0] != "*":
                vendors_added.add(parts[0])
                
        for vendor in vendors_added:
            stats["vendors_dist"][vendor] = stats["vendors_dist"].get(vendor, 0) + 1
            
    stats["years"] = sorted(stats["years"])
    stats["vendors"] = len(stats["vendors_dist"])
    
    # Downsample CVSS scores list if it's too large to save space
    if len(stats["cvss_scores"]) > 1000:
        step = len(stats["cvss_scores"]) // 1000 + 1
        stats["cvss_scores"] = stats["cvss_scores"][::step]
        
    stats["last_sync"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_db_stats(stats)


def update_stats_on_delete(cve_id: str):
    """Incrementally update statistics when a record is deleted."""
    stats = _load_db_stats()
    
    record = get_cve(cve_id)
    if not record:
        return
        
    meta = record.get("metadata", {})
    severity = meta.get("severity", "UNKNOWN").upper()
    cvss = float(meta.get("cvss_score", 0.0))
    year = str(meta.get("year")) if meta.get("year") else "UNKNOWN"
    source = meta.get("source", "NVD")
    products_str = meta.get("products", "[]")
    
    stats["total_cves"] = max(0, stats["total_cves"] - 1)
    
    if severity in stats["severity"]:
        stats["severity"][severity] = max(0, stats["severity"][severity] - 1)
        
    if "source_dist" in stats and source in stats["source_dist"]:
        stats["source_dist"][source] = max(0, stats["source_dist"][source] - 1)
        
    if cvss in stats["cvss_scores"]:
        try:
            stats["cvss_scores"].remove(cvss)
        except ValueError:
            pass
        
    if year and year != "UNKNOWN":
        if year in stats["years_dist"]:
            stats["years_dist"][year] = max(0, stats["years_dist"][year] - 1)
            if stats["years_dist"][year] == 0:
                stats["years_dist"].pop(year)
                if year in stats["years"]:
                    stats["years"].remove(year)
                    
    try:
        products = json.loads(products_str)
        vendors_removed = set()
        for prod in products:
            parts = prod.split("/")
            if parts and parts[0]:
                vendors_removed.add(parts[0])
                
        for vendor in vendors_removed:
            if vendor in stats["vendors_dist"]:
                stats["vendors_dist"][vendor] = max(0, stats["vendors_dist"][vendor] - 1)
                if stats["vendors_dist"][vendor] == 0:
                    stats["vendors_dist"].pop(vendor)
    except Exception:
        pass
        
    stats["vendors"] = len(stats["vendors_dist"])
    from datetime import datetime
    stats["last_sync"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _save_db_stats(stats)


def rebuild_db_stats_from_collection():
    """Rebuild db_stats.json from scratch in a memory-safe, batched manner."""
    logger.info("Rebuilding db_stats.json from ChromaDB...")
    collection = get_collection()
    
    stats = {
        "total_cves": 0,
        "vendors": 0,
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "years": [],
        "last_sync": "Never",
        "cvss_scores": [],
        "years_dist": {},
        "vendors_dist": {},
        "source_dist": {"NVD": 0, "CWE": 0, "CAPEC": 0, "CISA_KEV": 0, "MITRE_ATTACK": 0}
    }
    
    limit = 10000
    offset = 0
    
    while True:
        results = collection.get(limit=limit, offset=offset, include=['metadatas'])
        metadatas = results.get("metadatas", [])
        if not isinstance(metadatas, list) or len(metadatas) == 0:
            break
            
        for meta in metadatas:
            if meta.get("source") == "uploaded_pdf":
                continue
            stats["total_cves"] += 1
            
            # Severity
            severity = meta.get("severity", "UNKNOWN").upper()
            if severity in stats["severity"]:
                stats["severity"][severity] += 1
            else:
                stats["severity"]["UNKNOWN"] += 1
                
            # Source
            cve_id = meta.get("cve_id", "").upper()
            source = meta.get("source")
            if not source:
                if cve_id.startswith("CVE-"):
                    source = "NVD"
                elif cve_id.startswith("CWE-"):
                    source = "CWE"
                elif cve_id.startswith("CAPEC-"):
                    source = "CAPEC"
                else:
                    source = "MITRE_ATTACK"
                    
            stats["source_dist"][source] = stats["source_dist"].get(source, 0) + 1
            
            # CVSS
            cvss = float(meta.get("cvss_score", 0.0))
            stats["cvss_scores"].append(cvss)
            
            # Year
            year = str(meta.get("year")) if meta.get("year") else "UNKNOWN"
            if year and year != "UNKNOWN":
                if year not in stats["years"]:
                    stats["years"].append(year)
                stats["years_dist"][year] = stats["years_dist"].get(year, 0) + 1
                
            # Products
            products_str = meta.get("products", "[]")
            try:
                products = json.loads(products_str)
                vendors_found = set()
                for prod in products:
                    parts = prod.split("/")
                    if parts and parts[0]:
                        vendors_found.add(parts[0])
                for v in vendors_found:
                    stats["vendors_dist"][v] = stats["vendors_dist"].get(v, 0) + 1
            except Exception:
                pass
                
        logger.info("Processed %d items for stats...", offset + len(metadatas))
        offset += limit
        
    stats["years"] = sorted(stats["years"])
    stats["vendors"] = len(stats["vendors_dist"])
    
    # Downsample CVSS scores list if it's too large to save space
    if len(stats["cvss_scores"]) > 1000:
        step = len(stats["cvss_scores"]) // 1000 + 1
        stats["cvss_scores"] = stats["cvss_scores"][::step]
        
    from datetime import datetime
    stats["last_sync"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    _save_db_stats(stats)
    logger.info("Successfully rebuilt db_stats.json: %d total records", stats["total_cves"])


# ─── Indexing Operations ───────────────────────────────────────────────────

PROGRESS_FILE = Path("./data/nvd/indexing_progress.json")


def _load_progress() -> Dict[str, Any]:
    if PROGRESS_FILE.exists():
        try:
            with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load indexing progress: %s", e)
    return {}


def _save_progress(progress: Dict[str, Any]):
    try:
        PROGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PROGRESS_FILE, "w", encoding="utf-8") as f:
            json.dump(progress, f, indent=2)
    except Exception as e:
        logger.error("Failed to save indexing progress: %s", e)


def index_cve_batch(
    collection: chromadb.Collection, 
    cve_records: List[Union[Dict[str, Any], CVERecord]], 
    source: Optional[str] = None
) -> int:
    """
    Upsert a batch of CVE/CWE/CAPEC/ATT&CK records into ChromaDB.
    Uses upsert so existing records are updated (no full database rebuild).
    """
    ids = []
    documents = []
    metadatas = []

    for record in cve_records:
        if isinstance(record, BaseModel):
            rec_dict = record.model_dump()
        else:
            rec_dict = record

        # Determine source
        rec_source = source or rec_dict.get("source")
        if not rec_source:
            cve_id = rec_dict["cve_id"].upper()
            if cve_id.startswith("CVE-"):
                if "[CISA KEV" in rec_dict.get("description", ""):
                    rec_source = "CISA_KEV"
                else:
                    rec_source = "NVD"
            elif cve_id.startswith("CWE-"):
                rec_source = "CWE"
            elif cve_id.startswith("CAPEC-"):
                rec_source = "CAPEC"
            else:
                rec_source = "MITRE_ATTACK"

        # Extract primary vendor
        vendor = "UNKNOWN"
        if rec_dict.get("products"):
            vendors_set = set()
            for prod in rec_dict["products"]:
                parts = prod.split("/")
                if parts and parts[0] and parts[0] != "*":
                    vendors_set.add(parts[0])
            if vendors_set:
                vendor = ", ".join(sorted(vendors_set))

        ids.append(rec_dict["cve_id"])
        documents.append(rec_dict["doc_text"])
        metadatas.append({
            "cve_id": rec_dict["cve_id"],
            "year": rec_dict["year"],
            "severity": rec_dict["severity"],
            "cvss_score": float(rec_dict["cvss_score"]),
            "published": rec_dict["published"],
            "products": json.dumps(rec_dict["products"]),
            "references": json.dumps(rec_dict["references"][:3]),
            "source": rec_source,
            "vendor": vendor,
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    
    # Update stats incrementally in batch
    try:
        batch_records_stats = []
        for record in cve_records:
            if isinstance(record, BaseModel):
                rec_dict = record.model_dump()
            else:
                rec_dict = record
            
            rec_source_stats = source or rec_dict.get("source")
            if not rec_source_stats:
                cve_id = rec_dict["cve_id"].upper()
                if cve_id.startswith("CVE-"):
                    if "[CISA KEV" in rec_dict.get("description", ""):
                        rec_source_stats = "CISA_KEV"
                    else:
                        rec_source_stats = "NVD"
                elif cve_id.startswith("CWE-"):
                    rec_source_stats = "CWE"
                elif cve_id.startswith("CAPEC-"):
                    rec_source_stats = "CAPEC"
                else:
                    rec_source_stats = "MITRE_ATTACK"
                    
            record_copy = rec_dict.copy()
            record_copy["source"] = rec_source_stats
            batch_records_stats.append(record_copy)
            
        update_stats_on_batch(batch_records_stats)
    except Exception as e:
        logger.error("Failed to incrementally update stats in batch: %s", e)
        logger.error("Failed to incrementally update stats in batch: %s", e)

    return len(ids)


def index_all_feeds(nvd_data_path: str = "./data/nvd"):
    """Index all downloaded datasets (NVD, CWE, CAPEC, KEV, ATT&CK) into ChromaDB with offset resume."""
    from ingest.parser import parse_nvd_feed
    from ingest.cwe_parser import parse_cwe_catalog
    from ingest.capec_parser import parse_capec_catalog
    from ingest.kev_parser import parse_kev_catalog
    from ingest.attack_parser import parse_attack_catalog

    logger.info("=" * 50)
    logger.info("VulnSentinel — Indexing Datasets into ChromaDB (%s)", EMBED_MODEL)
    logger.info("=" * 50)

    client = get_chroma_client()
    collection = get_collection(client)

    progress = _load_progress()
    
    # Build a registry of feed tasks (feed_key, generator_function, source)
    tasks = []
    
    # 1. CWE
    cwe_path = "./data/cwe/cwec_v4.20.xml"
    if Path(cwe_path).exists():
        tasks.append(("cwe", lambda: parse_cwe_catalog(cwe_path), "CWE"))
        
    # 2. CAPEC
    capec_path = "./data/capec/capec_latest.xml"
    if Path(capec_path).exists():
        tasks.append(("capec", lambda: parse_capec_catalog(capec_path), "CAPEC"))
        
    # 3. CISA KEV
    kev_path = "./data/cisa_kev/known_exploited_vulnerabilities.json"
    if Path(kev_path).exists():
        tasks.append(("cisa_kev", lambda: parse_kev_catalog(kev_path), "CISA_KEV"))
        
    # 4. MITRE ATT&CK
    attack_path = "./data/mitre_attack/enterprise-attack/enterprise-attack.json"
    if Path(attack_path).exists():
        tasks.append(("mitre_attack", lambda: parse_attack_catalog(attack_path), "MITRE_ATTACK"))

    # 5. NVD 2.0 Feeds
    nvd_path = Path(nvd_data_path)
    nvd_files = sorted(nvd_path.glob("nvdcve-2.0-*.json"))
    for f in nvd_files:
        tasks.append((f.name, lambda f_path=f: parse_nvd_feed(f_path), "NVD"))

    # 6. Legacy NVD files (for backward compatibility if any exist)
    nvd_legacy_files = sorted(nvd_path.glob("nvdcve-1.1-*.json"))
    for f in nvd_legacy_files:
        tasks.append((f.name, lambda f_path=f: parse_nvd_feed(f_path), "NVD"))

    total_indexed = 0

    for feed_key, gen_fn, source in tasks:
        status = progress.get(feed_key, 0)
        if status == "completed":
            logger.info("Feed %s already indexed. Skipping.", feed_key)
            continue
            
        offset = int(status)
        logger.info("event=feed_start | feed=%s | offset=%d", feed_key, offset)
        
        batch = []
        counter = 0
        feed_indexed = 0
        
        try:
            generator = gen_fn()
            for record in generator:
                counter += 1
                if counter <= offset:
                    continue
                    
                batch.append(record)
                
                if len(batch) >= BATCH_SIZE:
                    start_time = time.perf_counter()
                    logger.info("event=batch_start | feed=%s | offset=%d | size=%d", feed_key, counter - len(batch), len(batch))
                    count = index_cve_batch(collection, batch, source=source)
                    duration = (time.perf_counter() - start_time) * 1000
                    total_indexed += count
                    feed_indexed += count
                    logger.info("event=batch_complete | feed=%s | size=%d | latency_ms=%.2f", feed_key, count, duration)
                    
                    # Update progress offset
                    progress[feed_key] = counter
                    _save_progress(progress)
                    batch = []

            # Process remaining items in last batch
            if batch:
                start_time = time.perf_counter()
                logger.info("event=batch_start | feed=%s | offset=%d | size=%d", feed_key, counter - len(batch), len(batch))
                count = index_cve_batch(collection, batch, source=source)
                duration = (time.perf_counter() - start_time) * 1000
                total_indexed += count
                feed_indexed += count
                logger.info("event=batch_complete | feed=%s | size=%d | latency_ms=%.2f", feed_key, count, duration)
                
            progress[feed_key] = "completed"
            _save_progress(progress)
            logger.info("event=feed_complete | feed=%s | indexed=%d", feed_key, feed_indexed)
        except Exception as e:
            logger.error("Failed processing feed %s: %s", feed_key, e)
            
    logger.info("event=index_complete | total_indexed=%d", total_indexed)
    try:
        coll_count = collection.count()
        coll_count_str = f"{coll_count:,}" if isinstance(coll_count, int) else str(coll_count)
    except Exception:
        coll_count_str = "N/A"
    logger.info("Collection size: %s", coll_count_str)
    
    # Rebuild final stats database file at the end
    try:
        rebuild_db_stats_from_collection()
    except Exception as e:
        logger.error("Failed to rebuild stats collection: %s", e)


# ─── CRUD Operations ──────────────────────────────────────────────────────────

def add_cve(cve_record: Union[Dict[str, Any], CVERecord]) -> bool:
    """Add or update a single CVE record (CRUD: Create/Update)."""
    try:
        collection = get_collection()
        index_cve_batch(collection, [cve_record])
        cve_id = cve_record.cve_id if isinstance(cve_record, BaseModel) else cve_record["cve_id"]
        logger.info("[✓] Added/Updated CVE: %s", cve_id)
        return True
    except Exception as e:
        logger.error("[✗] Failed to add CVE: %s", e)
        return False


def delete_cve(cve_id: str) -> bool:
    """Delete a CVE by ID (CRUD: Delete)."""
    try:
        # Update statistics in cache first
        try:
            update_stats_on_delete(cve_id.upper())
        except Exception as se:
            logger.error("Failed to update stats on deletion of %s: %s", cve_id, se)
            
        collection = get_collection()
        collection.delete(ids=[cve_id.upper()])
        logger.info("[✓] Deleted CVE: %s", cve_id)
        return True
    except Exception as e:
        logger.error("[✗] Failed to delete %s: %s", cve_id, e)
        return False


def update_cve(cve_id: str, updated_record: Union[Dict[str, Any], CVERecord]) -> bool:
    """Update an existing CVE record (CRUD: Update)."""
    if isinstance(updated_record, BaseModel):
        rec_dict = updated_record.model_dump()
        rec_dict["cve_id"] = cve_id.upper()
    else:
        updated_record["cve_id"] = cve_id.upper()
        rec_dict = updated_record

    return add_cve(rec_dict)


def get_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve a specific CVE by ID (CRUD: Read)."""
    try:
        collection = get_collection()
        result = collection.get(ids=[cve_id.upper()], include=["documents", "metadatas"])
        if result["ids"]:
            return {
                "cve_id": cve_id.upper(),
                "document": result["documents"][0],
                "metadata": result["metadatas"][0],
            }
        return None
    except Exception as e:
        logger.error("[✗] Failed to retrieve CVE %s: %s", cve_id, e)
        return None


def get_collection_stats() -> Dict[str, Any]:
    """Return statistics about the indexed collection."""
    stats = _load_db_stats()
    
    # Fallback to collection count if the stats file is empty/incomplete
    total = stats.get("total_cves", 0)
    if total == 0:
        try:
            collection = get_collection()
            total = collection.count()
        except Exception:
            total = 0
            
    return {
        "total_cves": total,
        "collection_name": COLLECTION_NAME,
        "embed_model": EMBED_MODEL,
        "db_path": CHROMA_DB_PATH,
        "earliest_year": stats.get("years")[0] if stats.get("years") else "2002",
        "latest_year": stats.get("years")[-1] if stats.get("years") else "2026",
        "severity_counts": stats.get("severity", {}),
        "source_distribution": stats.get("source_dist", {})
    }


if __name__ == "__main__":
    index_all_feeds()
    stats = get_collection_stats()
    logger.info("Current stats: %s", stats)
