"""
retrieval/vector_search.py
Fast initial vector similarity search against ChromaDB.
Returns top-N candidates before reranking.
"""

import json
import time
import logging
from pathlib import Path
from ingest.indexer import get_collection

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "vector_search.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDVectorSearch")


def vector_search(
    query: str,
    top_k: int = 20,
    severity_filter: str | None = None,
    year_filter: str | None = None,
) -> list[dict]:
    """
    Perform fast cosine similarity search in ChromaDB.
    Returns top_k candidates with metadata.

    Args:
        query: Natural language query or software/CVE name
        top_k: Number of initial candidates to retrieve
        severity_filter: Optional filter (CRITICAL, HIGH, MEDIUM, LOW)
        year_filter: Optional year filter e.g. "2024"

    Returns:
        List of CVE result dicts with scores
    """
    start_time = time.perf_counter()
    db_latency = 0.0

    try:
        collection = get_collection()
        collection_count = collection.count()
        if collection_count == 0:
            logger.info("event=empty_vector_response | query='%s' | reason=collection_empty", query)
            return []
    except Exception as e:
        db_latency = (time.perf_counter() - start_time) * 1000
        logger.error(
            "event=vector_search_error | query='%s' | error_type=%s | error='%s' | latency_ms=%.2f",
            query, type(e).__name__, str(e), db_latency
        )
        return []

    # Build optional where clause for metadata filtering
    where = {}
    filters = []
    if severity_filter:
        filters.append({"severity": severity_filter.upper()})
    if year_filter:
        filters.append({"year": str(year_filter)})

    if len(filters) == 1:
        where = filters[0]
    elif len(filters) > 1:
        where = {"$and": filters}

    # Direct CVE lookup injection
    import re
    direct_candidates = []
    cve_pattern = r'(?i)\bcve-\d{4}-\d{4,}\b'
    matched_ids = re.findall(cve_pattern, query)
    seen_ids = set()
    if matched_ids:
        for cve_id in matched_ids:
            cve_id_upper = cve_id.upper()
            if cve_id_upper in seen_ids:
                continue
            try:
                record = search_by_cve_id(cve_id_upper)
                if record:
                    metadata = record.get("metadata", {})
                    # Apply filters
                    passes_filter = True
                    if severity_filter and metadata.get("severity", "").upper() != severity_filter.upper():
                        passes_filter = False
                    if year_filter and str(metadata.get("year", "")) != str(year_filter):
                        passes_filter = False
                    
                    if passes_filter:
                        source = metadata.get("source")
                        is_pdf = (source == "uploaded_pdf")
                        try:
                            products = json.loads(metadata.get("products", "[]")) if not is_pdf else []
                        except Exception:
                            products = []
                        try:
                            references = json.loads(metadata.get("references", "[]")) if not is_pdf else []
                        except Exception:
                            references = []
                        
                        direct_candidates.append({
                            "cve_id": cve_id_upper,
                            "similarity": 1.0,  # Max similarity score for exact match
                            "document": record["document"],
                            "metadata": metadata,
                            "severity": "N/A" if is_pdf else metadata.get("severity", "UNKNOWN"),
                            "cvss_score": 0.0 if is_pdf else float(metadata.get("cvss_score", 0.0)),
                            "published": "" if is_pdf else metadata.get("published", ""),
                            "year": "" if is_pdf else metadata.get("year", ""),
                            "products": products,
                            "references": references,
                        })
                        seen_ids.add(cve_id_upper)
            except Exception as ex:
                logger.error("event=direct_lookup_error | cve_id=%s | error='%s'", cve_id_upper, str(ex))

    query_params = {
        "query_texts": [query],
        "n_results": min(top_k, collection_count),
        "include": ["documents", "metadatas", "distances"],
    }
    if where:
        query_params["where"] = where

    start_time = time.perf_counter()
    try:
        results = collection.query(**query_params)
        db_latency = (time.perf_counter() - start_time) * 1000
    except Exception as e:
        db_latency = (time.perf_counter() - start_time) * 1000
        logger.error(
            "event=vector_search_error | query='%s' | error_type=%s | error='%s' | latency_ms=%.2f",
            query, type(e).__name__, str(e), db_latency
        )
        # Return direct candidates if query failed but direct lookup worked
        return direct_candidates

    output = []
    # Initialize output with direct candidates
    for dc in direct_candidates:
        output.append(dc)

    if not results["ids"] or not results["ids"][0]:
        logger.info(
            "event=vector_search | query='%s' | severity_filter=%s | year_filter=%s | results_count=%d | latency_ms=%.2f",
            query, severity_filter, year_filter, len(output), db_latency
        )
        return output

    for i, cve_id in enumerate(results["ids"][0]):
        cve_id_upper = cve_id.upper()
        if cve_id_upper in seen_ids:
            continue
        try:
            distance = results["distances"][0][i]
            similarity = 1 - distance  # Cosine: lower distance = higher similarity
            metadata = results["metadatas"][0][i]
            document = results["documents"][0][i]

            source = metadata.get("source")
            is_pdf = (source == "uploaded_pdf")
            
            if is_pdf:
                doc_name = metadata.get("document_name", "Unknown Document")
                page_num = metadata.get("page_number", 1)
                display_id = f"PDF: {doc_name} (Page {page_num})"
            else:
                display_id = cve_id

            # Protect metadata fields parsing
            try:
                products = json.loads(metadata.get("products", "[]")) if not is_pdf else []
            except Exception as pe:
                logger.error("event=metadata_parse_error | cve_id=%s | field=products | error='%s'", cve_id, str(pe))
                products = []

            try:
                references = json.loads(metadata.get("references", "[]")) if not is_pdf else []
            except Exception as re:
                logger.error("event=metadata_parse_error | cve_id=%s | field=references | error='%s'", cve_id, str(re))
                references = []

            output.append({
                "cve_id": display_id,
                "similarity": round(float(similarity), 4),
                "document": document,
                "metadata": metadata,
                "severity": "N/A" if is_pdf else metadata.get("severity", "UNKNOWN"),
                "cvss_score": 0.0 if is_pdf else float(metadata.get("cvss_score", 0.0)),
                "published": "" if is_pdf else metadata.get("published", ""),
                "year": "" if is_pdf else metadata.get("year", ""),
                "products": products,
                "references": references,
            })
            seen_ids.add(cve_id_upper)
        except Exception as e:
            logger.error("event=metadata_parse_error | cve_id=%s | error='%s'", cve_id, str(e))
            continue

    # Sort by similarity descending
    output.sort(key=lambda x: x["similarity"], reverse=True)
    logger.info(
        "event=vector_search | query='%s' | severity_filter=%s | year_filter=%s | results_count=%d | latency_ms=%.2f",
        query, severity_filter, year_filter, len(output), db_latency
    )
    return output


def search_by_cve_id(cve_id: str) -> dict | None:
    """Direct lookup by CVE ID."""
    from ingest.indexer import get_cve
    try:
        return get_cve(cve_id)
    except Exception as e:
        logger.error("event=direct_lookup_error | cve_id=%s | error='%s'", cve_id, str(e))
        return None


if __name__ == "__main__":
    results = vector_search("Apache Log4j remote code execution", top_k=5)
    for r in results:
        print(f"{r['cve_id']} | {r['severity']} | Score: {r['similarity']:.3f}")
        print(f"  {r['document'][:120]}...\n")
