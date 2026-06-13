"""
utils/document_formatter.py
Centralized document formatting and metadata normalization utility.
Ensures token formatting is perfectly aligned across ingest, API, and UI platforms,
preserving absolute consistency for vector embeddings.
"""

import json
import logging
from typing import List, Union, Any

logger = logging.getLogger("DocumentFormatter")


def normalize_products(products: Union[str, List[str], None]) -> List[str]:
    """
    Standardize product field formats.
    Handles list instances, None values, and JSON-serialized product strings.
    """
    if not products:
        return []
    
    if isinstance(products, str):
        products_str = products.strip()
        if not products_str:
            return []
        if products_str.startswith("[") and products_str.endswith("]"):
            try:
                parsed = json.loads(products_str)
                if isinstance(parsed, list):
                    return [str(p).strip() for p in parsed if p]
            except Exception as e:
                logger.warning("Failed to parse JSON-serialized products field: %s", e)
        # Fallback to comma-separated splitting
        return [p.strip() for p in products_str.split(",") if p.strip()]
        
    if isinstance(products, list):
        return [str(p).strip() for p in products if p]
        
    return []


def normalize_references(references: Union[str, List[str], None]) -> List[str]:
    """
    Standardize reference links formats.
    Handles list instances, None values, and JSON-serialized link strings.
    """
    if not references:
        return []
        
    if isinstance(references, str):
        refs_str = references.strip()
        if not refs_str:
            return []
        if refs_str.startswith("[") and refs_str.endswith("]"):
            try:
                parsed = json.loads(refs_str)
                if isinstance(parsed, list):
                    return [str(r).strip() for r in parsed if r]
            except Exception as e:
                logger.warning("Failed to parse JSON-serialized references field: %s", e)
        # Fallback to pipeline-separated splitting
        return [r.strip() for r in refs_str.split("|") if r.strip()]
        
    if isinstance(references, list):
        return [str(r).strip() for r in references if r]
        
    return []


def build_doc_text(
    cve_id: str,
    severity: str,
    cvss_score: float,
    published: str,
    description: str,
    products: Union[str, List[str], None],
    references: Union[str, List[str], None],
) -> str:
    """
    Generate the standardized token-optimized doc_text context block.
    Matches the existing format to preserve full vector compatibility.
    """
    cve_id_clean = str(cve_id or "UNKNOWN").strip().upper()
    severity_clean = str(severity or "UNKNOWN").strip().upper()
    cvss_score_clean = float(cvss_score) if cvss_score is not None else 0.0
    published_clean = str(published or "").strip()
    description_clean = str(description or "").strip()

    norm_products = normalize_products(products)
    norm_references = normalize_references(references)

    doc_text = (
        f"CVE ID: {cve_id_clean}\n"
        f"Severity: {severity_clean} (CVSS: {cvss_score_clean})\n"
        f"Published: {published_clean or 'N/A'}\n"
        f"Description: {description_clean}\n"
        f"Affected Products: {', '.join(norm_products) if norm_products else 'Not specified'}\n"
        f"References: {' | '.join(norm_references[:3]) if norm_references else 'None'}"
    )
    return doc_text
