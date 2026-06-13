import pytest
from unittest.mock import patch, MagicMock
from pipeline.rag_engine import run_assistant_chat

@patch("pipeline.rag_engine.check_input")
@patch("google.generativeai.GenerativeModel.generate_content")
def test_run_assistant_chat_greeting_online(mock_generate, mock_check_input):
    mock_check_input.return_value = (True, "Safe", "SAFE")
    
    mock_response = MagicMock()
    mock_response.text = "Hello! I am online."
    mock_generate.return_value = mock_response

    res = run_assistant_chat(history=[], query="hi")
    
    assert res["mode"] == "AI_GENERATED"
    assert res["blocked"] is False
    assert res["response"] == "Hello! I am online."
    assert res["is_fallback"] is False
    assert res["chunks"] == []

@patch("pipeline.rag_engine.check_input")
@patch("pipeline.rag_engine.retrieve_and_rerank")
@patch("google.generativeai.GenerativeModel.generate_content")
@patch("pipeline.rag_engine.check_output")
def test_run_assistant_chat_vulnerability_online(mock_check_output, mock_generate, mock_retrieve, mock_check_input):
    mock_check_input.return_value = (True, "Safe", "SAFE")
    mock_retrieve.return_value = [{"cve_id": "CVE-2021-44228", "severity": "CRITICAL"}]
    
    mock_response = MagicMock()
    mock_response.text = "Here is the details for Log4j vulnerability."
    mock_generate.return_value = mock_response
    mock_check_output.return_value = (True, "Here is the details for Log4j vulnerability.", [])

    res = run_assistant_chat(history=[], query="Log4j details")
    
    assert res["mode"] == "AI_GENERATED"
    assert res["blocked"] is False
    assert res["response"] == "Here is the details for Log4j vulnerability."
    assert res["is_fallback"] is False
    assert len(res["chunks"]) == 1
    assert res["chunks"][0]["cve_id"] == "CVE-2021-44228"

@patch("pipeline.rag_engine.check_input")
@patch("google.generativeai.GenerativeModel.generate_content")
def test_run_assistant_chat_greeting_fallback_429(mock_generate, mock_check_input):
    mock_check_input.return_value = (True, "Safe", "SAFE")
    mock_generate.side_effect = Exception("ResourceExhausted: 429 You exceeded your current quota")

    res = run_assistant_chat(history=[], query="hi")
    
    assert res["mode"] == "FALLBACK"
    assert res["blocked"] is False
    assert res["is_fallback"] is True
    assert res["chunks"] == []
    assert "offline fallback mode" in res["response"]
    assert "rate limit or quota exceeded" in res["response"]

@patch("pipeline.rag_engine.check_input")
@patch("pipeline.rag_engine.retrieve_and_rerank")
@patch("google.generativeai.GenerativeModel.generate_content")
def test_run_assistant_chat_vulnerability_fallback_timeout(mock_generate, mock_retrieve, mock_check_input):
    mock_check_input.return_value = (True, "Safe", "SAFE")
    mock_retrieve.return_value = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "document": "Description: Log4Shell vulnerability in Apache Log4j.",
            "products": ["apache/log4j"],
            "references": ["http://nvd"]
        }
    ]
    mock_generate.side_effect = Exception("API request timed out after 30s")

    res = run_assistant_chat(history=[], query="Tell me about Log4j")
    
    assert res["mode"] == "FALLBACK"
    assert res["blocked"] is False
    assert res["is_fallback"] is True
    assert len(res["chunks"]) == 1
    assert res["chunks"][0]["cve_id"] == "CVE-2021-44228"
    assert "Graceful Degradation Active" in res["response"]
    assert "API request timeout" in res["response"]
    assert "CVE-2021-44228" in res["response"]
