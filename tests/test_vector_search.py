import pytest
from unittest.mock import patch, MagicMock
from retrieval.vector_search import vector_search, search_by_cve_id

@patch("retrieval.vector_search.get_collection")
def test_vector_search_successful(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.count.return_value = 1
    mock_collection.query.return_value = {
        "ids": [["CVE-2024-99999"]],
        "distances": [[0.2]],
        "metadatas": [[{
            "cve_id": "CVE-2024-99999",
            "year": "2024",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "published": "2024-06-07",
            "products": '["example/component"]',
            "references": '["http://ref1"]'
        }]],
        "documents": [["CVE ID: CVE-2024-99999\nDescription: RCE."]]
    }
    mock_get_collection.return_value = mock_collection
    
    results = vector_search("Apache Log4j RCE", top_k=5, severity_filter="CRITICAL", year_filter="2024")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-99999"
    assert results[0]["similarity"] == 0.8  # 1 - 0.2
    assert results[0]["products"] == ["example/component"]
    
    # Assert filters were passed to query where clause
    mock_collection.query.assert_called_once()
    called_kwargs = mock_collection.query.call_args[1]
    assert called_kwargs["where"] == {"$and": [{"severity": "CRITICAL"}, {"year": "2024"}]}

@patch("retrieval.vector_search.get_collection")
def test_vector_search_empty_db(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.count.return_value = 0
    mock_get_collection.return_value = mock_collection
    
    results = vector_search("Log4j")
    assert results == []

@patch("retrieval.vector_search.get_collection")
def test_vector_search_get_collection_failure(mock_get_collection):
    mock_get_collection.side_effect = Exception("Chroma server unreachable")
    
    results = vector_search("Log4j")
    assert results == []

@patch("retrieval.vector_search.get_collection")
def test_vector_search_simulated_db_failure(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.count.return_value = 10
    mock_collection.query.side_effect = Exception("SQLite read failure")
    mock_get_collection.return_value = mock_collection
    
    results = vector_search("Log4j")
    assert results == []  # Gracefully falls back to safe default empty list

@patch("retrieval.vector_search.get_collection")
def test_vector_search_malformed_metadata(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.count.return_value = 2
    mock_collection.query.return_value = {
        "ids": [["CVE-2024-99999", "CVE-2024-88888"]],
        "distances": [[0.2, 0.3]],
        "metadatas": [[
            {
                "cve_id": "CVE-2024-99999",
                "year": "2024",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "published": "2024-06-07",
                "products": "{malformed json}",
                "references": "[invalid structure"
            },
            {
                "cve_id": "CVE-2024-88888",
                "year": "2024",
                "severity": "HIGH",
                "cvss_score": 8.5,
                "published": "2024-06-07",
                # missing products and references entirely
            }
        ]],
        "documents": [["CVE ID: CVE-2024-99999\nDescription: RCE.", "CVE ID: CVE-2024-88888\nDescription: Buffer overflow."]]
    }
    mock_get_collection.return_value = mock_collection
    
    results = vector_search("Apache Log4j RCE", top_k=5)
    assert len(results) == 2
    assert results[0]["products"] == []     # Falls back to empty list
    assert results[0]["references"] == []   # Falls back to empty list
    assert results[1]["products"] == []
    assert results[1]["references"] == []

@patch("retrieval.vector_search.search_by_cve_id")
@patch("retrieval.vector_search.get_collection")
def test_vector_search_cve_id_not_in_results(mock_get_collection, mock_search_by_cve_id):
    mock_search_by_cve_id.return_value = None
    mock_collection = MagicMock()
    mock_collection.count.return_value = 1
    mock_collection.query.return_value = {
        "ids": [[]],
        "distances": [[]],
        "metadatas": [[]],
        "documents": [[]]
    }
    mock_collection.get.return_value = {"ids": []}
    mock_get_collection.return_value = mock_collection
    
    results = vector_search("CVE-2024-99999")
    assert results == []

@patch("ingest.indexer.get_cve")
def test_search_by_cve_id_success(mock_get_cve):
    mock_get_cve.return_value = {"cve_id": "CVE-2024-99999", "document": "CVE description"}
    res = search_by_cve_id("CVE-2024-99999")
    assert res is not None
    assert res["cve_id"] == "CVE-2024-99999"
    mock_get_cve.assert_called_once_with("CVE-2024-99999")

@patch("ingest.indexer.get_cve")
def test_search_by_cve_id_failure(mock_get_cve):
    mock_get_cve.side_effect = Exception("Read error")
    res = search_by_cve_id("CVE-2024-99999")
    assert res is None
