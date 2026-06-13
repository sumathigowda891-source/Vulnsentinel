"""
ingest/pdf_processor.py
Helper module for extracting text, chunking, indexing, and deleting multi-format documents (PDF, DOCX, TXT, JSON, XML, CSV, ZIP) in ChromaDB.
"""

import os
import logging
import json
import zipfile
import shutil
import time
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
from langchain_text_splitters import RecursiveCharacterTextSplitter
from ingest.indexer import get_collection

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "pdf_processor.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("PDFProcessor")

UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class ProcessingCancelled(Exception):
    """Raised when user cancels an ongoing document processing job."""
    pass


def _fitz_extract_shard(args: Tuple) -> List[Tuple[int, str]]:
    """
    Worker function: opens a fresh fitz handle and extracts a range of pages.
    Safe to call from multiple threads (each has its own fitz.Document).
    """
    pdf_path, start, end = args
    import fitz
    results = []
    try:
        doc = fitz.open(pdf_path)
        for i in range(start, end):
            text = doc[i].get_text("text")
            if text and text.strip():
                results.append((i + 1, text))
        doc.close()
    except Exception as e:
        logger.warning("Shard %d-%d extraction error: %s", start, end, e)
    return results


def extract_text_from_pdf(pdf_path: str, cancel_event=None, max_pages: int = 0) -> List[Tuple[int, str]]:
    """
    Extract text from a PDF using parallel PyMuPDF workers (one per CPU core).
    Each worker opens its own fitz.Document handle to avoid GIL/thread-safety issues.
    Falls back to pdfplumber → PyPDF2 if PyMuPDF is unavailable.

    Args:
        pdf_path:     Path to the PDF file.
        cancel_event: threading.Event — set it to cancel extraction mid-way.
        max_pages:    If > 0, only extract the first N pages.

    Returns:
        List of (page_number, page_text) tuples sorted by page number.
    """
    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # ── 1. Parallel PyMuPDF ───────────────────────────────────────────────────
    try:
        import fitz
        logger.info("Extracting text using parallel PyMuPDF from: %s", pdf_path)

        with fitz.open(pdf_path) as probe:
            total = len(probe)

        limit = min(total, max_pages) if max_pages > 0 else total

        # Split pages into shards — one per CPU core (max 8 workers)
        n_workers = min(os.cpu_count() or 4, 8)
        shard_size = max(1, limit // n_workers)
        shards = [
            (pdf_path, i, min(i + shard_size, limit))
            for i in range(0, limit, shard_size)
        ]

        pages_text: List[Tuple[int, str]] = []
        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(_fitz_extract_shard, s) for s in shards]
            for fut in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    raise ProcessingCancelled("Extraction cancelled by user.")
                pages_text.extend(fut.result())

        # Re-sort — as_completed() returns in completion order, not page order
        pages_text.sort(key=lambda x: x[0])

        if pages_text:
            logger.info("PyMuPDF parallel extracted %d pages (workers=%d)", len(pages_text), n_workers)
            return pages_text
    except ProcessingCancelled:
        raise
    except Exception as e:
        logger.warning("PyMuPDF parallel extraction failed, falling back to pdfplumber: %s", e)

    # ── 2. pdfplumber fallback ────────────────────────────────────────────────
    try:
        import pdfplumber
        logger.info("Extracting text using pdfplumber from: %s", pdf_path)
        pages_text = []
        with pdfplumber.open(pdf_path) as pdf:
            pages = pdf.pages[:max_pages] if max_pages > 0 else pdf.pages
            for i, page in enumerate(pages, 1):
                if cancel_event and cancel_event.is_set():
                    raise ProcessingCancelled("Extraction cancelled by user.")
                text = page.extract_text()
                if text:
                    pages_text.append((i, text))
        if pages_text:
            return pages_text
    except ProcessingCancelled:
        raise
    except Exception as e:
        logger.warning("pdfplumber extraction failed, falling back to PyPDF2: %s", e)

    # ── 3. PyPDF2 last resort ─────────────────────────────────────────────────
    try:
        import PyPDF2
        logger.info("Extracting text using PyPDF2 from: %s", pdf_path)
        pages_text = []
        with open(pdf_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            total = len(reader.pages)
            limit = min(total, max_pages) if max_pages > 0 else total
            for i in range(limit):
                if cancel_event and cancel_event.is_set():
                    raise ProcessingCancelled("Extraction cancelled by user.")
                text = reader.pages[i].extract_text()
                if text:
                    pages_text.append((i + 1, text))
        return pages_text
    except ProcessingCancelled:
        raise
    except Exception as e:
        logger.error("PyPDF2 extraction failed: %s", e)

    return []


def extract_text_from_docx(docx_path: str) -> List[Tuple[int, str]]:
    """Extract text from a DOCX file using python standard library (zipfile + xml parsing)."""
    pages_text = []
    try:
        with zipfile.ZipFile(docx_path) as docx:
            xml_content = docx.read('word/document.xml')
            root = ET.fromstring(xml_content)
            
            paragraphs = []
            for para in root.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p'):
                text = "".join(node.text for node in para.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t') if node.text)
                if text.strip():
                    paragraphs.append(text.strip())
            
            full_text = "\n\n".join(paragraphs)
            if full_text.strip():
                chars_per_page = 1500
                pages = [full_text[i:i+chars_per_page] for i in range(0, len(full_text), chars_per_page)]
                for idx, page_content in enumerate(pages, 1):
                    pages_text.append((idx, page_content))
    except Exception as e:
        logger.error("Failed to parse docx %s: %s", docx_path, e)
    return pages_text


def extract_text_from_txt(txt_path: str) -> List[Tuple[int, str]]:
    """Extract text from a TXT file and split into pages."""
    pages_text = []
    try:
        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if content.strip():
                chars_per_page = 1500
                pages = [content[i:i+chars_per_page] for i in range(0, len(content), chars_per_page)]
                for idx, p in enumerate(pages, 1):
                    pages_text.append((idx, p))
    except Exception as e:
        logger.error("Failed to parse txt %s: %s", txt_path, e)
    return pages_text


def extract_text_from_json(json_path: str) -> List[Tuple[int, str]]:
    """Extract and format JSON file contents."""
    pages_text = []
    try:
        with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
            formatted = json.dumps(data, indent=2)
            if formatted.strip():
                chars_per_page = 1500
                pages = [formatted[i:i+chars_per_page] for i in range(0, len(formatted), chars_per_page)]
                for idx, p in enumerate(pages, 1):
                    pages_text.append((idx, p))
    except Exception as e:
        logger.error("Failed to parse json %s: %s", json_path, e)
    return pages_text


def extract_text_from_xml(xml_path: str) -> List[Tuple[int, str]]:
    """Extract text from XML file."""
    pages_text = []
    try:
        with open(xml_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if content.strip():
                chars_per_page = 1500
                pages = [content[i:i+chars_per_page] for i in range(0, len(content), chars_per_page)]
                for idx, p in enumerate(pages, 1):
                    pages_text.append((idx, p))
    except Exception as e:
        logger.error("Failed to parse xml %s: %s", xml_path, e)
    return pages_text


def extract_text_from_csv(csv_path: str) -> List[Tuple[int, str]]:
    """Extract and format CSV file contents row by row."""
    pages_text = []
    try:
        rows = []
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.reader(f)
            for row_idx, row in enumerate(reader, 1):
                if any(cell.strip() for cell in row):
                    rows.append(f"Row {row_idx}: " + ", ".join(row))
        full_text = "\n".join(rows)
        if full_text.strip():
            chars_per_page = 1500
            pages = [full_text[i:i+chars_per_page] for i in range(0, len(full_text), chars_per_page)]
            for idx, p in enumerate(pages, 1):
                pages_text.append((idx, p))
    except Exception as e:
        logger.error("Failed to parse csv %s: %s", csv_path, e)
    return pages_text


def index_zip(zip_path: str, doc_name: str, progress_callback=None) -> Dict[str, Any]:
    """Extract zip archives and index all supported documents inside them recursively."""
    extract_dir = UPLOAD_DIR / f"unzipped_{Path(doc_name).stem}_{int(time.time())}"
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    success_count = 0
    failed_files = []
    total_pages = 0
    total_chunks = 0
    
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
            
        all_files = []
        for r, d, f in os.walk(extract_dir):
            for filename in f:
                if not filename.startswith('.'):
                    all_files.append(Path(r) / filename)
                    
        if not all_files:
            raise ValueError("ZIP file is empty or contains no valid files.")
            
        total_files = len(all_files)
        for file_idx, filepath in enumerate(all_files, 1):
            suffix = filepath.suffix.lower()
            if suffix in [".pdf", ".docx", ".txt", ".json", ".xml", ".csv"]:
                relative_name = str(filepath.relative_to(extract_dir))
                sub_doc_name = f"{doc_name}/{relative_name}"
                
                if progress_callback:
                    progress_callback(3, 4, f"Indexing unzipped file {file_idx}/{total_files}: {relative_name}...")
                
                res = index_pdf(str(filepath), sub_doc_name, progress_callback=None)
                if res["success"]:
                    success_count += 1
                    total_pages += res["page_count"]
                    total_chunks += res["chunk_count"]
                else:
                    failed_files.append(f"{relative_name} ({res['error']})")
                    
        try:
            shutil.rmtree(extract_dir)
        except Exception:
            pass
            
        if success_count == 0:
            raise ValueError(f"No supported documents could be indexed from ZIP. Failures: {', '.join(failed_files)}")
            
        return {
            "success": True,
            "page_count": total_pages,
            "chunk_count": total_chunks,
            "error": None if not failed_files else f"Partial success. Failed: {', '.join(failed_files)}"
        }
    except Exception as e:
        try:
            shutil.rmtree(extract_dir)
        except Exception:
            pass
        logger.error("Failed to index ZIP %s: %s", doc_name, e)
        return {
            "success": False,
            "page_count": 0,
            "chunk_count": 0,
            "error": str(e)
        }


def index_pdf(pdf_path: str, doc_name: str, progress_callback=None,
              cancel_event=None, max_pages: int = 0) -> Dict[str, Any]:
    """
    General document indexer (supports PDF, DOCX, TXT, JSON, XML, CSV, ZIP).
    Extracts text, chunks it, and performs batched upserts into ChromaDB.

    Args:
        pdf_path:         Path to saved file.
        doc_name:         Original filename used as the document identifier.
        progress_callback: Optional fn(pct: int, total: int, text: str).
        cancel_event:     threading.Event — set to stop processing immediately.
        max_pages:        Cap on pages to extract (keeps runtime bounded, default 500).
    """
    suffix = Path(doc_name).suffix.lower()
    if suffix == '.zip':
        return index_zip(pdf_path, doc_name, progress_callback)

    try:
        if progress_callback:
            progress_callback(1, 100, f"Extracting text from document...")

        if suffix == '.pdf':
            pages_text = extract_text_from_pdf(pdf_path, cancel_event=cancel_event, max_pages=max_pages)
        elif suffix == '.docx':
            pages_text = extract_text_from_docx(pdf_path)
        elif suffix == '.txt':
            pages_text = extract_text_from_txt(pdf_path)
        elif suffix == '.json':
            pages_text = extract_text_from_json(pdf_path)
        elif suffix == '.xml':
            pages_text = extract_text_from_xml(pdf_path)
        elif suffix == '.csv':
            pages_text = extract_text_from_csv(pdf_path)
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

        if not pages_text:
            raise ValueError("No text could be extracted from this document.")

        page_count = len(pages_text)
        logger.info("Extracted %d pages/sections from %s", page_count, doc_name)

        # Larger chunks = far fewer embeddings = much faster ChromaDB upsert
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=2000,    # was 1000 — cuts chunk count by ~60%
            chunk_overlap=100,  # was 200 — less redundancy, more speed
        )
        collection = get_collection()

        chunk_counter = 0
        BATCH_SIZE = 500   # was 200 — fewer round-trips to ChromaDB
        UPDATE_EVERY = 100 # only update progress UI every N pages (avoids Streamlit re-render overhead)
        ids, documents, metadatas = [], [], []

        for i, (page_num, text) in enumerate(pages_text):
            # Check cancellation before each page
            if cancel_event and cancel_event.is_set():
                raise ProcessingCancelled("Processing cancelled by user.")

            # Throttled progress updates — UI re-renders are expensive in Streamlit
            if progress_callback and (i % UPDATE_EVERY == 0 or i == page_count - 1):
                pct = 5 + int(((i + 1) / page_count) * 90)
                progress_callback(pct, 100, f"Indexing page {page_num}/{page_count} ({chunk_counter} chunks so far)...")

            chunks = splitter.split_text(text)
            for idx, chunk in enumerate(chunks, 1):
                chunk_counter += 1
                ids.append(f"{doc_name}_P{page_num}_C{idx}")
                documents.append(f"Document: {doc_name}\nPage: {page_num}\nContent: {chunk.strip()}")
                metadatas.append({
                    "source": "uploaded_pdf",
                    "document_name": doc_name,
                    "page_number": int(page_num)
                })

            # Flush batch to ChromaDB
            if len(ids) >= BATCH_SIZE:
                if cancel_event and cancel_event.is_set():
                    raise ProcessingCancelled("Processing cancelled by user.")
                collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
                ids, documents, metadatas = [], [], []

        # Flush any remaining chunks
        if ids:
            collection.upsert(ids=ids, documents=documents, metadatas=metadatas)

        logger.info("Indexed document %s successfully. Pages: %d  Chunks: %d", doc_name, page_count, chunk_counter)
        _invalidate_pdf_stats()
        return {"success": True, "page_count": page_count, "chunk_count": chunk_counter, "error": None}

    except ProcessingCancelled:
        logger.info("Indexing of %s was cancelled by user.", doc_name)
        return {"success": False, "page_count": 0, "chunk_count": 0, "error": "cancelled"}
    except Exception as e:
        logger.error("Failed to index document %s: %s", doc_name, e)
        return {"success": False, "page_count": 0, "chunk_count": 0, "error": str(e)}


def delete_pdf(doc_name: str) -> bool:
    """
    Remove all chunks matching document_name from ChromaDB,
    and delete the local copy in data/uploads/.
    """
    try:
        # 1. Delete from ChromaDB
        collection = get_collection()
        collection.delete(where={"document_name": doc_name})
        logger.info("Deleted chunks for %s from ChromaDB.", doc_name)
        
        # 2. Delete local file if it exists
        local_path = UPLOAD_DIR / doc_name
        if local_path.exists():
            local_path.unlink()
            logger.info("Deleted local file: %s", local_path)
            
        _invalidate_pdf_stats()
        return True
    except Exception as e:
        logger.error("Failed to delete PDF %s: %s", doc_name, e)
        return False


PDF_STATS_FILE = Path("data/pdf_stats.json")


def _invalidate_pdf_stats():
    try:
        if PDF_STATS_FILE.exists():
            PDF_STATS_FILE.unlink()
            logger.info("Invalidated pdf_stats.json")
    except Exception as e:
        logger.warning("Failed to invalidate pdf_stats.json: %s", e)


def get_uploaded_pdf_stats() -> Dict[str, Any]:
    """
    Retrieve statistics of indexed uploaded PDFs.
    First tries to load cached stats from data/pdf_stats.json (O(1)).
    If not cached, queries ChromaDB and caches the result.
    """
    if PDF_STATS_FILE.exists():
        try:
            with open(PDF_STATS_FILE, "r", encoding="utf-8") as f:
                stats = json.load(f)
            required_keys = {"uploaded_documents", "total_pages", "chunks_indexed", "documents_list"}
            if all(k in stats for k in required_keys):
                return stats
        except Exception as e:
            logger.warning("Failed to load cached pdf stats: %s", e)

    try:
        collection = get_collection()
        
        # Verify collection count
        if collection.count() == 0:
            return {
                "uploaded_documents": 0,
                "total_pages": 0,
                "chunks_indexed": 0,
                "documents_list": []
            }
            
        results = collection.get(where={"source": "uploaded_pdf"}, include=["metadatas"])
        metadatas = results.get("metadatas", [])
        
        doc_pages = {}       # map doc_name -> set of pages
        doc_chunks = {}      # map doc_name -> chunks count
        
        for meta in metadatas:
            doc_name = meta.get("document_name")
            page_num = meta.get("page_number")
            if doc_name:
                if doc_name not in doc_pages:
                    doc_pages[doc_name] = set()
                if doc_name not in doc_chunks:
                    doc_chunks[doc_name] = 0
                
                if page_num is not None:
                    doc_pages[doc_name].add(page_num)
                doc_chunks[doc_name] += 1
                
        docs_summary = []
        total_pages = 0
        
        for doc_name, pages_set in doc_pages.items():
            page_cnt = len(pages_set)
            total_pages += page_cnt
            docs_summary.append({
                "document_name": doc_name,
                "page_count": page_cnt,
                "chunk_count": doc_chunks[doc_name]
            })
            
        result = {
            "uploaded_documents": len(doc_pages),
            "total_pages": total_pages,
            "chunks_indexed": len(metadatas),
            "documents_list": docs_summary
        }

        try:
            PDF_STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(PDF_STATS_FILE, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)
            logger.info("Saved cached pdf stats to %s", PDF_STATS_FILE)
        except Exception as se:
            logger.warning("Failed to cache pdf stats: %s", se)

        return result
    except Exception as e:
        logger.error("Failed to get uploaded PDF stats: %s", e)
        return {
            "uploaded_documents": 0,
            "total_pages": 0,
            "chunks_indexed": 0,
            "documents_list": []
        }
