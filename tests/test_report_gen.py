import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from output.report_gen import generate_pdf_report, get_severity_color, build_emergency_report

def test_get_severity_color():
    from reportlab.lib import colors
    assert get_severity_color("CRITICAL") == colors.HexColor("#DC2626")
    assert get_severity_color("HIGH") == colors.HexColor("#EA580C")
    assert get_severity_color("MEDIUM") == colors.HexColor("#D97706")
    assert get_severity_color("LOW") == colors.HexColor("#16A34A")
    assert get_severity_color("UNKNOWN") == colors.HexColor("#6B7280")
    assert get_severity_color("NONEXISTENT") == colors.grey

def test_generate_pdf_report_normal():
    query = "Apache Log4j RCE"
    rag_result = {
        "chunks": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "published": "2021-12-10",
                "document": "Description: Apache log4j RCE vulnerability.",
                "products": ["apache/log4j"],
                "references": ["http://ref1"]
            }
        ],
        "is_fallback": False,
        "response": "### Analysis\nApache Log4j affects enterprise systems.",
        "hallucinated_cves": ["CVE-2024-0001"]
    }
    
    filename = "test_normal_report.pdf"
    pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
    
    assert pdf_path.exists()
    assert pdf_path.name == filename
    # Cleanup file
    pdf_path.unlink()

def test_generate_pdf_report_empty_and_malformed():
    query = "Unknown system scan"
    # Products field is a malformed JSON string, references is missing
    rag_result = {
        "chunks": [
            {
                "cve_id": "CVE-2024-99999",
                "severity": "MEDIUM",
                "cvss_score": 5.5,
                "published": "2024-06-07",
                "document": "Description: Malformed attributes test.",
                "products": "{invalid JSON}",
                "references": None
            }
        ],
        "is_fallback": True
    }
    
    filename = "test_malformed_report.pdf"
    pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
    
    assert pdf_path.exists()
    assert pdf_path.name == filename
    # Cleanup file
    pdf_path.unlink()

@patch("output.report_gen.build_emergency_report")
@patch("output.report_gen.build_styles")
def test_generate_pdf_report_styles_exception_triggers_emergency(mock_build_styles, mock_build_emergency, tmp_path):
    mock_build_styles.side_effect = Exception("Failed loading fonts")
    mock_build_emergency.return_value = tmp_path / "test_emergency_style_report.pdf"
    
    query = "Critical query"
    rag_result = {"chunks": []}
    filename = "test_emergency_style_report.pdf"
    
    with patch("output.report_gen.OUTPUT_DIR", tmp_path):
        pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
        assert pdf_path == tmp_path / "test_emergency_style_report.pdf"
        mock_build_emergency.assert_called_once()

@patch("output.report_gen.build_emergency_report")
@patch("output.report_gen.SimpleDocTemplate")
def test_generate_pdf_report_doc_template_exception_triggers_emergency(mock_doc_template, mock_build_emergency, tmp_path):
    mock_doc_template.side_effect = Exception("Initialization failed")
    mock_build_emergency.return_value = tmp_path / "test_emergency_layout_report.pdf"
    
    query = "Emergency layout test"
    rag_result = {
        "chunks": [{"cve_id": "CVE-2021-44228", "document": "Description: Apache log4j RCE"}]
    }
    filename = "test_emergency_layout_report.pdf"
    
    with patch("output.report_gen.OUTPUT_DIR", tmp_path):
        pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
        assert pdf_path == tmp_path / "test_emergency_layout_report.pdf"
        mock_build_emergency.assert_called_once()

def test_emergency_report_critical_failure(tmp_path):
    # If the emergency builder fails, it raises an exception
    output_path = tmp_path / "emergency_fail.pdf"
    
    # Passing an invalid document type that will fail standard pdf initialization
    with pytest.raises(Exception):
        build_emergency_report(None, None, "/invalid/directory/path/nonexistent.pdf", "Some Error")


def test_generate_pdf_report_exactly_three_pages():
    import fitz  # PyMuPDF
    query = "Test three pages RAG"
    rag_result = {
        "chunks": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "published": "2021-12-10",
                "document": "Description: Apache log4j RCE vulnerability.",
                "products": ["apache/log4j"],
                "references": ["http://ref1"]
            }
        ],
        "is_fallback": False,
        "response": "### Executive Summary\nAnalysis paragraph 1.\n\n### Detailed Technical Details\nAnalysis paragraph 2.",
        "hallucinated_cves": []
    }
    filename = "test_three_pages.pdf"
    pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
    
    assert pdf_path.exists()
    assert pdf_path.name == filename
    
    # Open and verify page count
    doc = fitz.open(pdf_path)
    page_count = len(doc)
    doc.close()
    
    # Cleanup file
    pdf_path.unlink()
    
    assert page_count == 3


def test_generate_pdf_report_exactly_three_pages_fallback():
    import fitz
    query = "Test three pages fallback"
    rag_result = {
        "chunks": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "published": "2021-12-10",
                "document": "Description: Apache log4j RCE vulnerability.",
                "products": ["apache/log4j"],
                "references": ["http://ref1"]
            }
        ],
        "is_fallback": True,
        "response": "",
        "hallucinated_cves": []
    }
    filename = "test_three_pages_fallback.pdf"
    pdf_path = generate_pdf_report(query, rag_result, output_filename=filename)
    
    assert pdf_path.exists()
    assert pdf_path.name == filename
    
    # Open and verify page count
    doc = fitz.open(pdf_path)
    page_count = len(doc)
    doc.close()
    
    # Cleanup file
    pdf_path.unlink()
    
    assert page_count == 3

