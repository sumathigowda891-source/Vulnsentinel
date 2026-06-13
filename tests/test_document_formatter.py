import pytest
from utils.document_formatter import build_doc_text, normalize_products, normalize_references

def test_normalize_products_various():
    assert normalize_products(None) == []
    assert normalize_products("") == []
    assert normalize_products('["prod1", "prod2"]') == ["prod1", "prod2"]
    assert normalize_products("prod1, prod2") == ["prod1", "prod2"]
    assert normalize_products(["prod1", None, "prod2"]) == ["prod1", "prod2"]

def test_normalize_references_various():
    assert normalize_references(None) == []
    assert normalize_references("") == []
    assert normalize_references('["http://ref1", "http://ref2"]') == ["http://ref1", "http://ref2"]
    assert normalize_references("http://ref1 | http://ref2") == ["http://ref1", "http://ref2"]
    assert normalize_references(["http://ref1", "http://ref2"]) == ["http://ref1", "http://ref2"]

def test_build_doc_text_edge_cases():
    doc = build_doc_text(None, None, None, None, None, None, None)
    assert "CVE ID: UNKNOWN" in doc
    assert "Severity: UNKNOWN" in doc
    assert "CVSS: 0.0" in doc
    assert "Published: N/A" in doc
