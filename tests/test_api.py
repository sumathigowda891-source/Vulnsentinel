import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from api import app, SeverityEnum

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["status"] == "online"
    assert json_data["app"] == "VulnSentinel API"
    assert json_data["docs_url"] == "/docs"

# ─── GET /api/cve/{cve_id} ──────────────────────────────────────────────────

@patch("api.get_cve")
def test_get_cve_endpoint_valid(mock_get_cve):
    mock_get_cve.return_value = {
        "cve_id": "CVE-2021-44228",
        "document": "Description text",
        "metadata": {
            "cve_id": "CVE-2021-44228",
            "year": "2021",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "products": '["apache/log4j"]',
            "references": '["http://ref"]'
        }
    }
    
    response = client.get("/api/cve/CVE-2021-44228")
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["cve_id"] == "CVE-2021-44228"
    assert json_data["metadata"]["severity"] == "CRITICAL"

def test_get_cve_endpoint_invalid_format():
    # Invalid CVE ID format should trigger FastAPIPath regex validation error (422)
    response = client.get("/api/cve/invalid-cve-id")
    assert response.status_code == 422

@patch("api.get_cve")
def test_get_cve_endpoint_not_found(mock_get_cve):
    mock_get_cve.return_value = None
    response = client.get("/api/cve/CVE-2024-00000")
    assert response.status_code == 404
    assert "not found in knowledge base" in response.json()["detail"]

# ─── POST /api/cve ────────────────────────────────────────────────────────────

@patch("api.add_cve")
def test_add_cve_endpoint_valid(mock_add_cve):
    mock_add_cve.return_value = True
    
    payload = {
        "cve_id": "CVE-2024-99999",
        "description": "Buffer overflow in component.",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "published": "2024-06-07",
        "products": ["example/component"],
        "references": []
    }
    response = client.post("/api/cve", json=payload)
    assert response.status_code == 201
    assert "Successfully indexed CVE" in response.json()["message"]

@patch("api.add_cve")
def test_add_cve_endpoint_database_error(mock_add_cve):
    mock_add_cve.return_value = False
    
    payload = {
        "cve_id": "CVE-2024-99999",
        "description": "Buffer overflow in component.",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "published": "2024-06-07",
        "products": ["example/component"],
        "references": []
    }
    response = client.post("/api/cve", json=payload)
    assert response.status_code == 500
    assert "Failed to index CVE record" in response.json()["detail"]

def test_add_cve_endpoint_invalid_severity():
    payload = {
        "cve_id": "CVE-2024-99999",
        "description": "Buffer overflow in component.",
        "severity": "VERY_CRITICAL",  # Not in SeverityEnum
        "cvss_score": 8.8,
        "published": "2024-06-07"
    }
    response = client.post("/api/cve", json=payload)
    assert response.status_code == 422

def test_add_cve_endpoint_invalid_cvss_score():
    payload = {
        "cve_id": "CVE-2024-99999",
        "description": "Buffer overflow.",
        "severity": "HIGH",
        "cvss_score": 15.0,  # Must be <= 10.0
        "published": "2024-06-07"
    }
    response = client.post("/api/cve", json=payload)
    assert response.status_code == 422

# ─── DELETE /api/cve/{cve_id} ─────────────────────────────────────────────────

@patch("api.delete_cve")
def test_delete_cve_endpoint_valid(mock_delete_cve):
    mock_delete_cve.return_value = True
    response = client.delete("/api/cve/CVE-2021-44228")
    assert response.status_code == 200
    assert "Successfully deleted CVE" in response.json()["message"]

@patch("api.delete_cve")
def test_delete_cve_endpoint_not_found(mock_delete_cve):
    mock_delete_cve.return_value = False
    response = client.delete("/api/cve/CVE-2021-44228")
    assert response.status_code == 404

def test_delete_cve_endpoint_invalid_format():
    response = client.delete("/api/cve/invalid-format")
    assert response.status_code == 422

# ─── GET /api/stats ───────────────────────────────────────────────────────────

@patch("api.get_collection_stats")
def test_stats_endpoint(mock_get_stats):
    mock_get_stats.return_value = {
        "total_cves": 3604,
        "collection_name": "vulnsentinel_cves",
        "embed_model": "BAAI/bge-small-en-v1.5",
        "db_path": "./data/chromadb"
    }
    response = client.get("/api/stats")
    assert response.status_code == 200
    assert response.json()["total_cves"] == 3604

@patch("api.get_collection_stats")
def test_stats_endpoint_error(mock_get_stats):
    mock_get_stats.side_effect = Exception("DB file corrupt")
    response = client.get("/api/stats")
    assert response.status_code == 500

# ─── POST /api/search ─────────────────────────────────────────────────────────

@patch("api.run_rag_pipeline")
def test_search_endpoint_success(mock_run_pipeline):
    mock_run_pipeline.return_value = {
        "mode": "AI_GENERATED",
        "blocked": False,
        "query": "Log4j",
        "response": "Report details",
        "chunks": []
    }
    
    payload = {
        "query": "Log4j",
        "top_k_vector": 10,
        "top_k_final": 5,
        "severity_filter": "CRITICAL"
    }
    response = client.post("/api/search", json=payload)
    assert response.status_code == 200
    json_data = response.json()
    assert json_data["mode"] == "AI_GENERATED"
    assert json_data["query"] == "Log4j"

@patch("api.run_rag_pipeline")
def test_search_endpoint_pipeline_error(mock_run_pipeline):
    mock_run_pipeline.side_effect = Exception("Gemini API out of credits")
    
    payload = {
        "query": "Log4j"
    }
    response = client.post("/api/search", json=payload)
    assert response.status_code == 500
    assert "RAG pipeline error" in response.json()["detail"]

# ─── POST /api/report ─────────────────────────────────────────────────────────

@patch("api.generate_pdf_report")
def test_report_endpoint_success(mock_gen_report, tmp_path):
    temp_pdf = tmp_path / "test_report.pdf"
    temp_pdf.write_bytes(b"%PDF-1.4 mock content")
    mock_gen_report.return_value = temp_pdf
    
    payload = {
        "query": "Log4j",
        "rag_result": {
            "chunks": [],
            "response": "AI Response text"
        }
    }
    response = client.post("/api/report", json=payload)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content == b"%PDF-1.4 mock content"

@patch("api.generate_pdf_report")
def test_report_endpoint_generator_error(mock_gen_report):
    mock_gen_report.side_effect = Exception("ReportLab engine crashed")
    
    payload = {
        "query": "Log4j",
        "rag_result": {
            "chunks": []
        }
    }
    response = client.post("/api/report", json=payload)
    assert response.status_code == 500
    assert "PDF generation failed" in response.json()["detail"]

@patch("api.generate_pdf_report")
def test_report_endpoint_file_not_found(mock_gen_report, tmp_path):
    # Mock generation returning a non-existent path
    non_existent = tmp_path / "does_not_exist.pdf"
    mock_gen_report.return_value = non_existent
    
    payload = {
        "query": "Log4j",
        "rag_result": {
            "chunks": []
        }
    }
    response = client.post("/api/report", json=payload)
    assert response.status_code == 500
    assert "PDF was not generated" in response.json()["detail"]
