import pytest
import json
from pathlib import Path
from ingest.parser import (
    parse_cve_item,
    parse_cvss_v3,
    parse_cvss_v2,
    extract_affected_products,
    extract_references,
    parse_nvd_feed
)

def test_parse_cvss_v3_valid():
    metrics = {
        "cvssMetricV31": [{
            "cvssData": {
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
            }
        }]
    }
    score, severity = parse_cvss_v3(metrics)
    assert score == 9.8
    assert severity == "CRITICAL"

def test_parse_cvss_v3_missing_cvss_data():
    metrics = {
        "cvssMetricV31": [{
            "baseSeverity": "HIGH"
        }]
    }
    score, severity = parse_cvss_v3(metrics)
    assert score == 0.0
    assert severity == "HIGH"

def test_parse_cvss_v3_exception():
    metrics = {
        "cvssMetricV31": "not-a-list"
    }
    score, severity = parse_cvss_v3(metrics)
    assert score == 0.0
    assert severity == "UNKNOWN"

def test_parse_cvss_v2_valid():
    metrics = {
        "cvssMetricV2": [{
            "cvssData": {
                "baseScore": 7.5
            },
            "baseSeverity": "HIGH"
        }]
    }
    score, severity = parse_cvss_v2(metrics)
    assert score == 7.5
    assert severity == "HIGH"

def test_parse_cvss_v2_exception():
    metrics = {
        "cvssMetricV2": "not-a-list"
    }
    score, severity = parse_cvss_v2(metrics)
    assert score == 0.0
    assert severity == "UNKNOWN"

def test_extract_affected_products_valid():
    configurations = [{
        "nodes": [{
            "cpeMatch": [
                {"criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"}
            ]
        }]
    }]
    products = extract_affected_products(configurations)
    assert products == ["apache/log4j"]

def test_extract_affected_products_children():
    configurations = [{
        "nodes": [{
            "children": [{
                "cpeMatch": [
                    {"criteria": "cpe:2.3:a:microsoft:windows_10:*:*:*:*:*:*:*:*"}
                ]
            }]
        }]
    }]
    products = extract_affected_products(configurations)
    assert products == ["microsoft/windows_10"]

def test_extract_affected_products_exception():
    products = extract_affected_products("invalid-configs-structure")
    assert products == []

def test_extract_references():
    refs_list = [
        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
    ]
    refs = extract_references(refs_list)
    assert refs == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]

def test_parse_cve_item_valid():
    item = {
        "id": "CVE-2024-11111",
        "descriptions": [{"lang": "en", "value": "Valid description text details"}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH"}}]
        },
        "published": "2024-06-07T12:00:00Z",
        "lastModified": "2024-06-07T12:00:00Z",
        "configurations": [],
        "references": []
    }
    record = parse_cve_item(item)
    assert record is not None
    assert record.cve_id == "CVE-2024-11111"
    assert record.cvss_score == 8.8
    assert record.severity == "HIGH"
    assert record.published == "2024-06-07"
    assert record.year == "2024"

def test_parse_cve_item_missing_fields_defaults():
    item = {
        "id": "CVE-2024-22222",
        "descriptions": [{"lang": "en", "value": "Another valid CVE."}]
    }
    record = parse_cve_item(item)
    assert record is not None
    assert record.cve_id == "CVE-2024-22222"
    assert record.cvss_score == 0.0
    assert record.severity == "UNKNOWN"
    assert record.published == ""

def test_parse_cve_item_rejected_cve():
    item = {
        "id": "CVE-2024-33333",
        "descriptions": [{"lang": "en", "value": "** REJECT ** This record has been rejected."}]
    }
    record = parse_cve_item(item)
    assert record is None

def test_parse_cve_item_validation_error():
    # cvss_score is validated to be <= 10.0 in Pydantic, so 15.0 causes ValidationError
    item = {
        "id": "CVE-2024-44444",
        "descriptions": [{"lang": "en", "value": "Validation error test."}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 15.0, "baseSeverity": "CRITICAL"}}]
        }
    }
    record = parse_cve_item(item)
    assert record is None

def test_parse_nvd_feed_valid(tmp_path):
    feed_data = {
        "cve_items": [
            {
                "id": "CVE-2024-12345",
                "descriptions": [{"lang": "en", "value": "Valid feed item."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]
                }
            }
        ]
    }
    feed_file = tmp_path / "nvdcve-1.1-2024.json"
    feed_file.write_text(json.dumps(feed_data))
    
    records = list(parse_nvd_feed(feed_file))
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-12345"

def test_parse_nvd_feed_malformed_json(tmp_path):
    feed_file = tmp_path / "malformed.json"
    feed_file.write_text("{ malformed json }")
    
    with pytest.raises(Exception):
        list(parse_nvd_feed(feed_file))
