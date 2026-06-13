import pytest
from unittest.mock import patch, MagicMock
from retrieval.reranker import (
    rerank_results,
    get_ranker,
    preload_ranker,
    retrieve_and_rerank
)

@patch("retrieval.reranker.get_ranker")
def test_rerank_results_empty(mock_get_ranker):
    results = rerank_results("Log4j", [])
    assert results == []
    mock_get_ranker.assert_not_called()

@patch("retrieval.reranker.get_ranker")
def test_rerank_results_single(mock_get_ranker):
    mock_ranker = MagicMock()
    mock_ranker.rerank.return_value = [
        {"id": 0, "score": 0.95, "meta": {"cve_id": "CVE-2024-99999", "document": "CVE ID: CVE-2024-99999..."}}
    ]
    mock_get_ranker.return_value = mock_ranker
    
    candidates = [{"cve_id": "CVE-2024-99999", "document": "CVE ID: CVE-2024-99999..."}]
    results = rerank_results("Log4j", candidates, top_k=1)
    
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-99999"
    assert results[0]["rerank_score"] == 0.95

@patch("retrieval.reranker.get_ranker")
def test_rerank_results_multiple(mock_get_ranker):
    mock_ranker = MagicMock()
    mock_ranker.rerank.return_value = [
        {"id": 1, "score": 0.98, "meta": {"cve_id": "CVE-2024-22222", "document": "Doc 2"}},
        {"id": 0, "score": 0.85, "meta": {"cve_id": "CVE-2024-11111", "document": "Doc 1"}}
    ]
    mock_get_ranker.return_value = mock_ranker
    
    candidates = [
        {"cve_id": "CVE-2024-11111", "document": "Doc 1"},
        {"cve_id": "CVE-2024-22222", "document": "Doc 2"}
    ]
    results = rerank_results("Log4j", candidates, top_k=2)
    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2024-22222"
    assert results[0]["rerank_score"] == 0.98
    assert results[1]["cve_id"] == "CVE-2024-11111"
    assert results[1]["rerank_score"] == 0.85

@patch("retrieval.reranker.Ranker")
def test_get_ranker_singleton(mock_ranker_class):
    # Clear singleton cache
    import retrieval.reranker
    retrieval.reranker._ranker = None
    
    mock_instance = MagicMock()
    mock_ranker_class.return_value = mock_instance
    
    ranker1 = get_ranker()
    ranker2 = get_ranker()
    
    assert ranker1 is ranker2
    mock_ranker_class.assert_called_once()

@patch("retrieval.reranker.get_ranker")
def test_preload_ranker(mock_get_ranker):
    preload_ranker()
    mock_get_ranker.assert_called_once()

@patch("retrieval.vector_search.vector_search")
@patch("retrieval.reranker.rerank_results")
def test_retrieve_and_rerank_normal(mock_rerank, mock_vector_search):
    mock_vector_search.return_value = [{"cve_id": "CVE-2024-99999", "document": "Doc"}]
    mock_rerank.return_value = [{"cve_id": "CVE-2024-99999", "document": "Doc", "rerank_score": 0.9}]
    
    res = retrieve_and_rerank("Log4j", severity_filter="HIGH", year_filter="2024")
    assert len(res) == 1
    assert res[0]["cve_id"] == "CVE-2024-99999"
    mock_vector_search.assert_called_once_with(
        query="Log4j",
        top_k=20,
        severity_filter="HIGH",
        year_filter="2024"
    )
    mock_rerank.assert_called_once_with(query="Log4j", candidates=[{"cve_id": "CVE-2024-99999", "document": "Doc"}], top_k=5)

@patch("retrieval.vector_search.vector_search")
@patch("retrieval.reranker.rerank_results")
def test_retrieve_and_rerank_empty(mock_rerank, mock_vector_search):
    mock_vector_search.return_value = []
    
    res = retrieve_and_rerank("Log4j")
    assert res == []
    mock_rerank.assert_not_called()
