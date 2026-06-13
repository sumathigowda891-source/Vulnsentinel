"""
ingest/parser.py
Parses raw community NVD JSON feeds (NVD API v2 schema) into structured,
Pydantic-validated CVE records.
Extracts CVE ID, description, CVSS score, severity, references, and affected products.
"""

import json
import logging
from pathlib import Path
from typing import Generator, List, Optional, Tuple
from pydantic import BaseModel, Field, ValidationError

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "parser.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDParser")


class CVERecord(BaseModel):
    """Pydantic model representing a parsed and validated NVD CVE record."""
    cve_id: str = Field(..., description="CVE ID, e.g., CVE-2024-12345")
    year: str = Field(..., description="Year of publication")
    description: str = Field(..., description="Vulnerability description text")
    cvss_score: float = Field(0.0, ge=0.0, le=10.0, description="CVSS base score")
    severity: str = Field("UNKNOWN", description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN")
    published: str = Field("", description="Publication date (YYYY-MM-DD)")
    modified: str = Field("", description="Modification date (YYYY-MM-DD)")
    products: List[str] = Field(default_factory=list, description="Affected products list")
    references: List[str] = Field(default_factory=list, description="Reference links")
    doc_text: str = Field(..., description="Optimized text context block for embeddings")


def parse_cvss_v3(metrics: dict) -> Tuple[float, str]:
    """Extract CVSS v3.1 or v3.0 base score and severity from metrics block."""
    # Try CVSS v3.1 first, then v3.0
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        metric_list = metrics.get(key, [])
        if metric_list:
            try:
                # Use the first available metric block (often Primary)
                metric = metric_list[0]
                cvss_data = metric.get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                severity = str(cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))).upper()
                return score, severity
            except Exception as e:
                logger.debug("Failed parsing CVSS v3 from %s: %s", key, e)
    return 0.0, "UNKNOWN"


def parse_cvss_v2(metrics: dict) -> Tuple[float, str]:
    """Extract CVSS v2 base score and severity from metrics block."""
    metric_list = metrics.get("cvssMetricV2", [])
    if metric_list:
        try:
            metric = metric_list[0]
            cvss_data = metric.get("cvssData", {})
            score = float(cvss_data.get("baseScore", 0.0))
            severity = str(metric.get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))).upper()
            return score, severity
        except Exception as e:
            logger.debug("Failed parsing CVSS v2: %s", e)
    return 0.0, "UNKNOWN"


def extract_affected_products(configurations: list) -> List[str]:
    """Extract affected vendor/product names from configurations node criteria (CPE 2.3)."""
    products = []
    try:
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                # Check cpeMatch in node
                for cpe_match in node.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        if vendor != "*" and product != "*":
                            products.append(f"{vendor}/{product}")
                # Check children nodes
                for child in node.get("children", []):
                    for cpe_match in child.get("cpeMatch", []):
                        criteria = cpe_match.get("criteria", "")
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            if vendor != "*" and product != "*":
                                products.append(f"{vendor}/{product}")
    except Exception as e:
        logger.debug("Failed to parse affected products: %s", e)
    
    # Remove duplicates and cap at 10 items for token efficiency
    return list(set(products))[:10]


def extract_references(references_list: list) -> List[str]:
    """Extract reference URLs from references block."""
    refs = []
    try:
        for ref in references_list[:5]:  # Cap at 5 references
            url = ref.get("url", "")
            if url:
                refs.append(url)
    except Exception as e:
        logger.debug("Failed to parse references: %s", e)
    return refs


def parse_cve_item(item: dict) -> Optional[CVERecord]:
    """Parse a single NVD raw JSON dictionary item (API v2) into a validated CVERecord."""
    try:
        cve_id = item.get("id", "")
        if not cve_id:
            return None

        # Description (English preferred)
        descriptions = item.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description or description.startswith("** REJECT"):
            return None

        # CVSS scores inside metrics block
        metrics = item.get("metrics", {})
        cvss_score, severity = parse_cvss_v3(metrics)
        if cvss_score == 0.0:
            cvss_score, severity = parse_cvss_v2(metrics)

        # Metadata Dates
        published = item.get("published", "")[:10]
        modified = item.get("lastModified", "")[:10]
        year = published[:4] if published else "UNKNOWN"

        # Affected products
        configurations = item.get("configurations", [])
        products = extract_affected_products(configurations)

        # References
        references_list = item.get("references", [])
        references = extract_references(references_list)

        from utils.document_formatter import build_doc_text, normalize_products, normalize_references

        # Build token-optimized doc_text context block using centralized utility
        doc_text = build_doc_text(
            cve_id=cve_id,
            severity=severity,
            cvss_score=cvss_score,
            published=published,
            description=description,
            products=products,
            references=references
        )

        # Build and validate model
        record = CVERecord(
            cve_id=cve_id,
            year=year,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            published=published,
            modified=modified,
            products=normalize_products(products),
            references=normalize_references(references),
            doc_text=doc_text,
        )
        return record

    except ValidationError as ve:
        logger.warning("Validation failed for CVE %s: %s", item.get("id", "UNKNOWN"), ve)
        return None
    except Exception as e:
        logger.error("Parsing error: %s", e)
        return None


def parse_nvd_feed(json_path: Path) -> Generator[CVERecord, None, None]:
    """Parse an entire NVD JSON feed file, yielding validated CVERecord objects."""
    logger.info("Parsing NVD feed file: %s", json_path.name)
    try:
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)

        parsed = 0
        skipped = 0

        if "vulnerabilities" in data:
            # Official NVD 2.0 JSON format
            vulns = data.get("vulnerabilities", [])
            for vuln in vulns:
                cve_item = vuln.get("cve")
                if cve_item:
                    try:
                        record = parse_cve_item(cve_item)
                        if record:
                            parsed += 1
                            yield record
                        else:
                            skipped += 1
                    except Exception as item_err:
                        logger.warning("Failed parsing a CVE item in %s: %s", json_path.name, item_err)
                        skipped += 1
                else:
                    skipped += 1
        else:
            # Legacy/mirror formats
            items = data.get("cve_items", data.get("CVE_Items", []))
            for item in items:
                try:
                    record = parse_cve_item(item)
                    if record:
                        parsed += 1
                        yield record
                    else:
                        skipped += 1
                except Exception as item_err:
                    logger.warning("Failed parsing a legacy CVE item in %s: %s", json_path.name, item_err)
                    skipped += 1

        logger.info("Completed parsing %s: %d validated, %d skipped/filtered", json_path.name, parsed, skipped)

    except Exception as e:
        logger.error("Failed to parse feed file %s: %s", json_path, e)
        raise


if __name__ == "__main__":
    # Test parser on the modified feed file
    test_path = Path("./data/nvd/nvdcve-1.1-modified.json")
    if test_path.exists():
        count = 0
        for cve in parse_nvd_feed(test_path):
            count += 1
            if count <= 2:
                print(f"\n[Validated Record {count}]")
                print(cve.model_dump_json(indent=2))
        print(f"\nTotal parsed and validated: {count}")
    else:
        print("Run NVDDownloader first to download nvdcve-1.1-modified.json")
