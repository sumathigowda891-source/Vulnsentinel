"""
api.py
FastAPI backend for VulnSentinel.
Provides REST API access to search/RAG, CRUD operations, database stats, and PDF report generation.
"""

import os
import time
import logging
from pathlib import Path
from typing import List, Optional
import json
from enum import Enum

from fastapi import FastAPI, HTTPException, status, Path as FastAPIPath
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

# Import VulnSentinel modules
from pipeline.rag_engine import run_rag_pipeline
from ingest.indexer import get_cve, add_cve, delete_cve, get_collection_stats
from output.report_gen import generate_pdf_report

# Setup logging configuration
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "api.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDApi")

app = FastAPI(
    title="VulnSentinel API",
    description="Enterprise-Grade RAG-Powered CVE Intelligence REST API Backend",
    version="1.0.0",
)

@app.on_event("startup")
def startup_event():
    """Run startup validation and preload components."""
    from retrieval.reranker import preload_ranker
    preload_ranker()

# Enable CORS for frontend integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Request Timing Middleware
@app.middleware("http")
async def add_process_time_header(request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = (time.perf_counter() - start_time) * 1000
    logger.info(
        "event=api_request | endpoint='%s %s' | status_code=%d | latency_ms=%.2f",
        request.method, request.url.path, response.status_code, process_time
    )
    return response

# ─── Enums & Schema Models ───────────────────────────────────────────────────

class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

class SearchRequest(BaseModel):
    query: str = Field(..., description="Natural language query or CVE ID", examples=["Apache Log4j remote code execution 2021"])
    client_id: str = Field("default", description="Client tracing identifier for rate limiting", examples=["client_01"])
    top_k_vector: int = Field(20, ge=1, le=100, description="Initial vector candidates retrieval count", examples=[20])
    top_k_final: int = Field(5, ge=1, le=20, description="Final candidate count after reranking", examples=[5])
    severity_filter: Optional[SeverityEnum] = Field(None, description="Optional severity classification filter", examples=[SeverityEnum.CRITICAL])
    year_filter: Optional[str] = Field(None, description="Optional publication year filter", examples=["2021"])
    simulate_failure: bool = Field(False, description="Simulate primary LLM failure to trigger fallback flow", examples=[False])

class CVERecordInput(BaseModel):
    cve_id: str = Field(..., description="CVE ID (e.g. CVE-2024-99999)", pattern=r"^(?i)cve-\d{4}-\d{4,}$", examples=["CVE-2024-99999"])
    description: str = Field(..., description="Detailed vulnerability description text", examples=["A buffer overflow vulnerability exists in the product component."])
    severity: SeverityEnum = Field(SeverityEnum.UNKNOWN, description="Vulnerability severity", examples=[SeverityEnum.HIGH])
    cvss_score: float = Field(0.0, ge=0.0, le=10.0, description="CVSS base score", examples=[8.5])
    published: Optional[str] = Field(None, description="Vulnerability publication date (YYYY-MM-DD)", examples=["2024-06-07"])
    products: List[str] = Field(default_factory=list, description="List of affected products (vendor/product format)", examples=[["example/vendor", "example/product"]])
    references: List[str] = Field(default_factory=list, description="Reference information links", examples=[["https://nvd.nist.gov/vuln/detail/CVE-2024-99999"]])

class ReportRequest(BaseModel):
    query: str = Field(..., description="The original search query", examples=["Apache Log4j remote code execution 2021"])
    rag_result: dict = Field(..., description="Response output dictionary from /api/search")

# ─── Response Models ─────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str = Field(..., examples=["online"])
    app: str = Field(..., examples=["VulnSentinel API"])
    version: str = Field(..., examples=["1.0.0"])
    docs_url: str = Field(..., examples=["/docs"])

class SearchResponse(BaseModel):
    mode: str = Field(..., description="Response category: AI_GENERATED, FALLBACK, BLOCKED, NO_RESULTS, ERROR", examples=["AI_GENERATED"])
    blocked: bool = Field(..., description="Indicates if the query was blocked by input guardrails", examples=[False])
    block_category: Optional[str] = Field(None, description="Category of the guardrail violation", examples=["PROMPT_INJECTION"])
    block_reason: Optional[str] = Field(None, description="Detailed explanation of block event", examples=["🚫 Prompt injection detected."])
    query: str = Field(..., description="The query evaluated by the pipeline", examples=["Apache Log4j remote code execution 2021"])
    response: Optional[str] = Field(None, description="AI intelligence analysis report in Markdown", examples=["### Executive Summary..."])
    raw_response: Optional[str] = Field(None, description="Fallback raw formatting output", examples=["⚠️ AI GENERATION OFFLINE..."])
    is_fallback: Optional[bool] = Field(None, description="Indicates if fallback was triggered", examples=[False])
    error_cause: Optional[str] = Field(None, description="Brief cause for API degradation", examples=["API request timed out"])
    error_detail: Optional[str] = Field(None, description="Raw fallback error message", examples=["Gemini API 429..."])
    chunks_used: Optional[int] = Field(None, description="Count of retrieved chunks used", examples=[5])
    chunks_count: Optional[int] = Field(None, description="Count of retrieved chunks in fallback list", examples=[5])
    input_tokens: Optional[int] = Field(None, description="API Input tokens count", examples=[620])
    output_tokens: Optional[int] = Field(None, description="API Output tokens count", examples=[450])
    chunks: List[dict] = Field(default_factory=list, description="Retrieved CVE records details")
    hallucinated_cves: List[str] = Field(default_factory=list, description="List of hallucinated CVEs blocked by guardrails")
    output_guardrail_triggered: Optional[bool] = Field(None, description="Indicates if output fact-checking was triggered", examples=[False])
    error: Optional[str] = Field(None, description="Fatal pipeline error details", examples=["Retrieval failed..."])
    timestamp: Optional[str] = Field(None, description="Generation ISO timestamp", examples=["2026-06-07T19:33:21"])

class CVEMetadata(BaseModel):
    cve_id: str = Field(..., examples=["CVE-2021-44228"])
    year: str = Field(..., examples=["2021"])
    severity: str = Field(..., examples=["CRITICAL"])
    cvss_score: float = Field(..., examples=[10.0])
    published: str = Field(..., examples=["2021-12-10"])
    products: str = Field(..., description="JSON-serialized affected products list", examples=['["apache/log4j"]'])
    references: str = Field(..., description="JSON-serialized references list", examples=['["https://nvd..."]'])

class CVERecordResponse(BaseModel):
    cve_id: str = Field(..., examples=["CVE-2021-44228"])
    document: str = Field(..., examples=["CVE ID: CVE-2021-44228\nSeverity: CRITICAL..."])
    metadata: CVEMetadata

class AddCVEResponse(BaseModel):
    message: str = Field(..., examples=["Successfully indexed CVE CVE-2024-99999"])
    cve_id: str = Field(..., examples=["CVE-2024-99999"])

class DeleteResponse(BaseModel):
    message: str = Field(..., examples=["Successfully deleted CVE CVE-2021-44228"])
    cve_id: str = Field(..., examples=["CVE-2021-44228"])

class StatsResponse(BaseModel):
    total_cves: int = Field(..., examples=[3604])
    collection_name: str = Field(..., examples=["vulnsentinel_cves"])
    embed_model: str = Field(..., examples=["BAAI/bge-small-en-v1.5"])
    db_path: str = Field(..., examples=["./data/chromadb"])

class ErrorResponse(BaseModel):
    detail: str = Field(..., examples=["CVE CVE-2021-44228 not found in knowledge base."])

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/", status_code=status.HTTP_200_OK, response_model=HealthResponse, summary="API Health status check")
def read_root():
    """Welcome and API Health status check."""
    return {
        "status": "online",
        "app": "VulnSentinel API",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

@app.post("/api/search", status_code=status.HTTP_200_OK, response_model=SearchResponse, summary="Search and run RAG query pipeline")
def search_vulnerabilities(request: SearchRequest):
    """
    Run VulnSentinel RAG query pipeline.
    Retrieves, reranks, and analyzes relevant CVEs with full guardrails.
    """
    try:
        result = run_rag_pipeline(
            query=request.query,
            client_id=request.client_id,
            top_k_vector=request.top_k_vector,
            top_k_final=request.top_k_final,
            severity_filter=request.severity_filter.value if request.severity_filter else None,
            year_filter=request.year_filter,
            simulate_failure=request.simulate_failure,
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"RAG pipeline error: {str(e)}"
        )

@app.get(
    "/api/cve/{cve_id}",
    status_code=status.HTTP_200_OK,
    response_model=CVERecordResponse,
    summary="Lookup a specific CVE by ID",
    responses={
        404: {"model": ErrorResponse, "description": "CVE ID not found in database"},
        422: {"model": ErrorResponse, "description": "Invalid CVE ID pattern validation error"}
    }
)
def get_cve_record(
    cve_id: str = FastAPIPath(..., pattern=r"^(?i)cve-\d{4}-\d{4,}$", description="The CVE ID (format: CVE-YYYY-NNNN+)", examples=["CVE-2021-44228"])
):
    """
    Lookup a specific CVE by ID in ChromaDB.
    """
    result = get_cve(cve_id.upper())
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {cve_id.upper()} not found in knowledge base."
        )
    return result

@app.post(
    "/api/cve",
    status_code=status.HTTP_201_CREATED,
    response_model=AddCVEResponse,
    summary="Add or update a CVE record in the database",
    responses={
        500: {"model": ErrorResponse, "description": "Failed to index CVE record"}
    }
)
def add_or_update_cve(record_input: CVERecordInput):
    """
    Add or update a CVE record in ChromaDB (Create/Update).
    """
    cve_id = record_input.cve_id.upper()
    year = record_input.published[:4] if record_input.published else "2024"
    severity_str = record_input.severity.value
    
    from utils.document_formatter import build_doc_text, normalize_products, normalize_references

    # Construct doc_text text block using centralized utility
    doc_text = build_doc_text(
        cve_id=cve_id,
        severity=severity_str,
        cvss_score=record_input.cvss_score,
        published=record_input.published,
        description=record_input.description,
        products=record_input.products,
        references=record_input.references
    )

    record = {
        "cve_id": cve_id,
        "year": year,
        "description": record_input.description,
        "cvss_score": record_input.cvss_score,
        "severity": severity_str,
        "published": record_input.published or "",
        "modified": record_input.published or "",
        "products": normalize_products(record_input.products),
        "references": normalize_references(record_input.references),
        "doc_text": doc_text,
    }

    success = add_cve(record)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to index CVE record."
        )
    return {"message": f"Successfully indexed CVE {cve_id}", "cve_id": cve_id}

@app.delete(
    "/api/cve/{cve_id}",
    status_code=status.HTTP_200_OK,
    response_model=DeleteResponse,
    summary="Delete a specific CVE from the database",
    responses={
        404: {"model": ErrorResponse, "description": "CVE ID not found in database"},
        422: {"model": ErrorResponse, "description": "Invalid CVE ID pattern validation error"}
    }
)
def delete_cve_record(
    cve_id: str = FastAPIPath(..., pattern=r"^(?i)cve-\d{4}-\d{4,}$", description="The CVE ID to delete", examples=["CVE-2021-44228"])
):
    """
    Delete a specific CVE from ChromaDB.
    """
    success = delete_cve(cve_id.upper())
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE {cve_id.upper()} could not be deleted or does not exist."
        )
    return {"message": f"Successfully deleted CVE {cve_id.upper()}", "cve_id": cve_id.upper()}

@app.get(
    "/api/stats",
    status_code=status.HTTP_200_OK,
    response_model=StatsResponse,
    summary="Retrieve collection size and database statistics",
    responses={
        500: {"model": ErrorResponse, "description": "Failed to load database stats"}
    }
)
def get_db_stats():
    """
    Retrieve statistics about the index/collection size in ChromaDB.
    """
    try:
        stats = get_collection_stats()
        return stats
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load collection stats: {str(e)}"
        )

@app.post(
    "/api/report",
    status_code=status.HTTP_200_OK,
    response_class=FileResponse,
    summary="Generate a PDF threat intelligence report",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Returns the generated PDF threat intelligence report.",
        },
        500: {"model": ErrorResponse, "description": "Failed to generate report PDF"}
    }
)
def create_report(request: ReportRequest):
    """
    Generate a PDF threat intelligence report and return the file.
    """
    try:
        pdf_path = generate_pdf_report(request.query, request.rag_result)
        if not os.path.exists(pdf_path):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="PDF was not generated."
            )
        
        return FileResponse(
            path=pdf_path,
            media_type="application/pdf",
            filename=pdf_path.name
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
