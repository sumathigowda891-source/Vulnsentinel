import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from ingest.downloader import NVDDownloader

@patch("ingest.downloader.requests.head")
def test_downloader_fetch_headers(mock_head):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"ETag": "etag_val", "Last-Modified": "last_mod_val"}
    mock_head.return_value = mock_resp
    
    downloader = NVDDownloader(years=[2024])
    headers = downloader._fetch_headers("http://test-url")
    assert headers is not None
    assert headers["etag"] == "etag_val"
    assert headers["last_modified"] == "last_mod_val"

@patch("ingest.downloader.requests.get")
@patch("ingest.downloader.NVDDownloader._fetch_headers")
def test_downloader_sync_feed(mock_fetch_headers, mock_get, tmp_path):
    mock_fetch_headers.return_value = {"etag": "123", "last_modified": "abc", "content_length": 23}
    
    # Mock download response
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.iter_content.return_value = [b"mocked_compressed_bytes"]
    mock_resp.headers = {"Content-Length": "23"}
    mock_get.return_value = mock_resp
    
    downloader = NVDDownloader(data_dir=str(tmp_path), years=[2024])
    
    # Mock decompression block using a patch
    with patch("ingest.downloader.gzip.open") as mock_gzip, \
         patch("ingest.downloader.shutil.copyfileobj") as mock_copy, \
         patch("ingest.downloader.Path.unlink") as mock_unlink:
        path = downloader.sync_feed(2024)
        assert path is not None
        assert path.name == "nvdcve-2.0-2024.json"
