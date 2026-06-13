import pytest
from unittest.mock import patch, MagicMock
from ingest.indexer import (
    add_cve,
    get_cve,
    delete_cve,
    update_cve,
    get_collection_stats,
    index_cve_batch,
    index_all_feeds,
    get_chroma_client,
    get_collection
)
from ingest.parser import CVERecord
from pathlib import Path

_real_exists = Path.exists

def mock_exists_side_effect(*args, **kwargs):
    if args:
        self_obj = args[0]
        path_str = str(self_obj)
        if any(name in path_str for name in ["cwec_v4.20.xml", "capec_latest.xml", "known_exploited_vulnerabilities.json", "enterprise-attack.json"]):
            return False
        return _real_exists(self_obj)
    return False


@pytest.fixture(autouse=True)
def mock_db_stats_save():
    with patch("ingest.indexer._save_db_stats") as mock_save:
        yield mock_save


@pytest.fixture
def sample_record():
    return {
        "cve_id": "CVE-2024-99999",
        "year": "2024",
        "description": "Buffer overflow in components.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "published": "2024-06-07",
        "modified": "2024-06-07",
        "products": ["example/component"],
        "references": ["http://ref1"],
        "doc_text": "CVE ID: CVE-2024-99999..."
    }

@patch("ingest.indexer.get_collection")
def test_add_cve_success(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    success = add_cve(sample_record)
    assert success is True
    mock_collection.upsert.assert_called_once()

@patch("ingest.indexer.get_collection")
def test_add_cve_pydantic_model(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    pydantic_rec = CVERecord(
        cve_id=sample_record["cve_id"],
        year=sample_record["year"],
        description=sample_record["description"],
        cvss_score=sample_record["cvss_score"],
        severity=sample_record["severity"],
        published=sample_record["published"],
        modified=sample_record["modified"],
        products=sample_record["products"],
        references=sample_record["references"],
        doc_text=sample_record["doc_text"]
    )
    success = add_cve(pydantic_rec)
    assert success is True
    mock_collection.upsert.assert_called_once()

@patch("ingest.indexer.get_collection")
def test_add_cve_failure(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_collection.upsert.side_effect = Exception("Write permission denied")
    mock_get_collection.return_value = mock_collection
    
    success = add_cve(sample_record)
    assert success is False

@patch("ingest.indexer.get_collection")
def test_get_cve_found(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.get.return_value = {
        "ids": ["CVE-2024-99999"],
        "documents": ["CVE ID: CVE-2024-99999..."],
        "metadatas": [{"cvss_score": 9.8, "severity": "CRITICAL"}]
    }
    mock_get_collection.return_value = mock_collection
    
    result = get_cve("CVE-2024-99999")
    assert result is not None
    assert result["cve_id"] == "CVE-2024-99999"
    assert result["document"] == "CVE ID: CVE-2024-99999..."
    mock_collection.get.assert_called_once_with(ids=["CVE-2024-99999"], include=["documents", "metadatas"])

@patch("ingest.indexer.get_collection")
def test_get_cve_not_found(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.get.return_value = {"ids": []}
    mock_get_collection.return_value = mock_collection
    
    result = get_cve("CVE-2024-00000")
    assert result is None

@patch("ingest.indexer.get_collection")
def test_get_cve_exception(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.get.side_effect = Exception("Connection timed out")
    mock_get_collection.return_value = mock_collection
    
    result = get_cve("CVE-2024-99999")
    assert result is None

@patch("ingest.indexer.get_collection")
def test_delete_cve_success(mock_get_collection):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    success = delete_cve("CVE-2024-99999")
    assert success is True
    mock_collection.delete.assert_called_once_with(ids=["CVE-2024-99999"])

@patch("ingest.indexer.get_collection")
def test_delete_cve_failure(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.delete.side_effect = Exception("Delete lock error")
    mock_get_collection.return_value = mock_collection
    
    success = delete_cve("CVE-2024-99999")
    assert success is False

@patch("ingest.indexer.get_collection")
def test_update_cve(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    success = update_cve("CVE-2024-99999", sample_record)
    assert success is True
    mock_collection.upsert.assert_called_once()

@patch("ingest.indexer.get_collection")
def test_update_cve_pydantic(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    pydantic_rec = CVERecord(
        cve_id="CVE-2024-99999",
        year=sample_record["year"],
        description=sample_record["description"],
        cvss_score=sample_record["cvss_score"],
        severity=sample_record["severity"],
        published=sample_record["published"],
        modified=sample_record["modified"],
        products=sample_record["products"],
        references=sample_record["references"],
        doc_text=sample_record["doc_text"]
    )
    success = update_cve("CVE-2024-99999", pydantic_rec)
    assert success is True
    mock_collection.upsert.assert_called_once()

@patch("ingest.indexer._load_db_stats")
@patch("ingest.indexer.get_collection")
def test_get_collection_stats(mock_get_collection, mock_load_stats):
    mock_load_stats.return_value = {
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
    mock_collection = MagicMock()
    mock_collection.count.return_value = 100
    mock_get_collection.return_value = mock_collection
    
    stats = get_collection_stats()
    assert stats["total_cves"] == 100
    assert stats["collection_name"] == "vulnsentinel_cves"

@patch("ingest.indexer.get_collection")
def test_duplicate_insertions(mock_get_collection, sample_record):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection
    
    # We call add_cve multiple times with the same record ID
    success_first = add_cve(sample_record)
    success_second = add_cve(sample_record)
    
    assert success_first is True
    assert success_second is True
    assert mock_collection.upsert.call_count == 2

@patch("ingest.indexer.Path.exists", autospec=True, side_effect=mock_exists_side_effect)
@patch("ingest.indexer.get_chroma_client")
@patch("ingest.indexer.get_collection")
@patch("ingest.indexer.Path.glob")
@patch("ingest.parser.parse_nvd_feed")
def test_index_all_feeds(mock_parse_feed, mock_glob, mock_get_collection, mock_get_client, mock_exists, sample_record):
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client
    
    mock_collection = MagicMock()
    mock_collection.count.return_value = 5
    mock_get_collection.return_value = mock_collection
    
    # Mock files
    mock_file = MagicMock()
    mock_glob.return_value = [mock_file]
    
    # Yield 3 sample records
    pydantic_rec = CVERecord(
        cve_id=sample_record["cve_id"],
        year=sample_record["year"],
        description=sample_record["description"],
        cvss_score=sample_record["cvss_score"],
        severity=sample_record["severity"],
        published=sample_record["published"],
        modified=sample_record["modified"],
        products=sample_record["products"],
        references=sample_record["references"],
        doc_text=sample_record["doc_text"]
    )
    mock_parse_feed.return_value = [pydantic_rec, pydantic_rec, pydantic_rec]
    
    with patch("ingest.indexer.BATCH_SIZE", 2):  # batch size is 2, so it will index one batch of 2 and one batch of 1
        index_all_feeds(nvd_data_path="/dummy/path")
        
    assert mock_collection.upsert.call_count == 2
    assert mock_glob.call_count == 2

@patch("ingest.indexer.Path.exists", autospec=True, side_effect=mock_exists_side_effect)
@patch("ingest.indexer.get_chroma_client")
@patch("ingest.indexer.get_collection")
@patch("ingest.indexer.Path.glob")
def test_index_all_feeds_no_files(mock_glob, mock_get_collection, mock_get_client, mock_exists):
    mock_glob.return_value = []
    mock_collection = MagicMock()
    mock_collection.count.return_value = 0
    mock_get_collection.return_value = mock_collection
    
    index_all_feeds(nvd_data_path="/dummy/path")
    # Should call get_chroma_client but exit early without other processing
    mock_get_client.assert_called_once()
    assert mock_glob.call_count == 2

@patch("ingest.indexer.chromadb.PersistentClient")
def test_get_chroma_client_singleton(mock_persistent_client):
    # Clear the singleton cache
    import ingest.indexer
    ingest.indexer._chroma_client = None
    
    client1 = get_chroma_client()
    client2 = get_chroma_client()
    
    assert client1 is client2
    mock_persistent_client.assert_called_once()
