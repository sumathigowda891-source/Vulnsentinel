import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from ingest.pdf_processor import (
    extract_text_from_pdf,
    index_pdf,
    delete_pdf,
    get_uploaded_pdf_stats
)

@pytest.fixture(autouse=True)
def mock_pdf_stats_file(tmp_path):
    temp_stats_file = tmp_path / "pdf_stats_test.json"
    with patch("ingest.pdf_processor.PDF_STATS_FILE", temp_stats_file):
        yield

@patch("pdfplumber.open")
def test_extract_text_pdfplumber_success(mock_pdfplumber_open):
    # Setup mock pdfplumber
    mock_pdf = MagicMock()
    mock_page1 = MagicMock()
    mock_page1.extract_text.return_value = "This is page 1 content"
    mock_page2 = MagicMock()
    mock_page2.extract_text.return_value = "This is page 2 content"
    mock_pdf.pages = [mock_page1, mock_page2]
    mock_pdfplumber_open.return_value.__enter__.return_value = mock_pdf

    pages = extract_text_from_pdf("fake_path.pdf")
    assert len(pages) == 2
    assert pages[0] == (1, "This is page 1 content")
    assert pages[1] == (2, "This is page 2 content")


@patch("pdfplumber.open", side_effect=Exception("pdfplumber error"))
@patch("builtins.open")
@patch("PyPDF2.PdfReader")
def test_extract_text_pypdf2_fallback(mock_pdf_reader, mock_open, mock_pdfplumber_open):
    # Setup mock PyPDF2 reader
    mock_reader = MagicMock()
    mock_page = MagicMock()
    mock_page.extract_text.return_value = "Fallback text content"
    mock_reader.pages = [mock_page]
    mock_pdf_reader.return_value = mock_reader

    pages = extract_text_from_pdf("fake_path.pdf")
    assert len(pages) == 1
    assert pages[0] == (1, "Fallback text content")


@patch("ingest.pdf_processor.get_collection")
@patch("ingest.pdf_processor.extract_text_from_pdf")
def test_index_pdf_success(mock_extract, mock_get_collection):
    mock_extract.return_value = [(1, "This is page 1 content")]
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection

    res = index_pdf("fake_path.pdf", "fake_path.pdf")
    assert res["success"] is True
    assert res["page_count"] == 1
    assert res["chunk_count"] > 0
    mock_collection.upsert.assert_called_once()


@patch("ingest.pdf_processor.get_collection")
def test_delete_pdf_success(mock_get_collection):
    mock_collection = MagicMock()
    mock_get_collection.return_value = mock_collection

    res = delete_pdf("fake_path.pdf")
    assert res is True
    mock_collection.delete.assert_called_once_with(where={"document_name": "fake_path.pdf"})


@patch("ingest.pdf_processor.get_collection")
def test_get_uploaded_pdf_stats(mock_get_collection):
    mock_collection = MagicMock()
    mock_collection.count.return_value = 5
    mock_collection.get.return_value = {
        "metadatas": [
            {"source": "uploaded_pdf", "document_name": "doc1.pdf", "page_number": 1, "chunk_id": "chunk1"},
            {"source": "uploaded_pdf", "document_name": "doc1.pdf", "page_number": 2, "chunk_id": "chunk2"},
            {"source": "uploaded_pdf", "document_name": "doc2.pdf", "page_number": 1, "chunk_id": "chunk3"}
        ]
    }
    mock_get_collection.return_value = mock_collection

    stats = get_uploaded_pdf_stats()
    assert stats["uploaded_documents"] == 2
    assert stats["total_pages"] == 3
    assert stats["chunks_indexed"] == 3
