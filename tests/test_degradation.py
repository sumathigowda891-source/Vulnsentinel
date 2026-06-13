import pytest
from unittest.mock import MagicMock, patch
from fallback.degradation import format_raw_chunks, handle_api_failure, APIFailoverClient

def test_format_raw_chunks_valid_types():
    # Test format with list type products & references
    chunks = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "document": "Description of Log4Shell.",
            "products": ["apache/log4j"],
            "references": ["http://ref1"]
        }
    ]
    text = format_raw_chunks(chunks)
    assert "CVE ID:    CVE-2021-44228" in text
    assert "Severity:  CRITICAL (CVSS: 10.0)" in text
    assert "Products:  apache/log4j" in text
    assert "Reference: http://ref1" in text

def test_format_raw_chunks_stringified_types():
    # Test format with json-serialized products & references
    chunks = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "document": "Description of Log4Shell.",
            "products": '["apache/log4j", "apache/log4j-core"]',
            "references": '["http://ref1", "http://ref2"]'
        }
    ]
    text = format_raw_chunks(chunks)
    assert "CVE ID:    CVE-2021-44228" in text
    assert "Products:  apache/log4j, apache/log4j-core" in text
    assert "Reference: http://ref1" in text

def test_format_raw_chunks_malformed_stringified_types():
    # Test format with malformed json-serialized products & references
    chunks = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "document": "Description of Log4Shell.",
            "products": '{malformed json}',
            "references": '[invalid structure'
        }
    ]
    text = format_raw_chunks(chunks)
    assert "CVE ID:    CVE-2021-44228" in text
    assert "Products" not in text  # Falls back to no products line
    assert "Reference" not in text

def test_format_raw_chunks_empty_list():
    text = format_raw_chunks([])
    assert "AI GENERATION OFFLINE" in text
    assert "The LLM API is currently unavailable." in text

def test_handle_api_failure_classifications():
    errors_and_causes = [
        (Exception("Rate limit exceeded 429 status code"), "Rate limit exceeded"),
        (Exception("API timeout after 30s"), "API request timed out"),
        (Exception("API timed out waiting for socket"), "API request timed out"),
        (Exception("Authentication key invalid 401"), "Authentication error (check API key)"),
        (Exception("HTTP 503 service unavailable"), "API service temporarily unavailable"),
        (Exception("502 Bad Gateway"), "API service temporarily unavailable"),
        (Exception("Gemini API is overloaded"), "API service temporarily unavailable"),
        (Exception("Network connection failed"), "Network connection error"),
        (Exception("Something went wrong 500"), "Unexpected error: Exception")
    ]
    
    for err, expected_cause in errors_and_causes:
        res = handle_api_failure(err, "Log4j", [])
        assert res["is_fallback"] is True
        assert res["mode"] == "FALLBACK"
        assert res["error_cause"] == expected_cause

def test_api_failover_client_success():
    mock_response = MagicMock()
    mock_response.text = "Gemini's analysis report."

    mock_client = MagicMock()
    mock_client.generate_content.return_value = mock_response

    failover = APIFailoverClient(mock_client, max_retries=2)
    res = failover.generate("System", "User", "Query", [])

    assert res["is_fallback"] is False
    assert res["response"] == "Gemini's analysis report."
    assert res["mode"] == "AI_GENERATED"
    assert res["chunks_used"] == 0

@patch("time.sleep")
def test_api_failover_client_retry_then_success(mock_sleep):
    mock_response = MagicMock()
    mock_response.text = "Success report after retry."

    mock_client = MagicMock()
    # Fails first, succeeds second
    mock_client.generate_content.side_effect = [Exception("Temporary 503 error"), mock_response]

    failover = APIFailoverClient(mock_client, max_retries=2)
    res = failover.generate("System", "User", "Query", [])

    assert res["is_fallback"] is False
    assert res["response"] == "Success report after retry."
    assert res["mode"] == "AI_GENERATED"
    assert mock_client.generate_content.call_count == 2
    mock_sleep.assert_called_once_with(2)  # exponential backoff 2^1

@patch("time.sleep")
def test_api_failover_client_all_retries_fail(mock_sleep):
    mock_client = MagicMock()
    mock_client.generate_content.side_effect = Exception("Permanent 401 Unauthorized")

    failover = APIFailoverClient(mock_client, max_retries=2)
    res = failover.generate("System", "User", "Query", [])

    assert res["is_fallback"] is True
    assert res["mode"] == "FALLBACK"
    assert res["error_cause"] == "Authentication error (check API key)"
    assert mock_client.generate_content.call_count == 2
    assert mock_sleep.call_count == 1  # slept after attempt 1
