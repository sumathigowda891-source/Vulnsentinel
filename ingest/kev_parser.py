"""
ingest/kev_parser.py
Parses CISA Known Exploited Vulnerabilities (KEV) JSON catalog and converts items to standardized CVERecord models.
"""

import json
import logging
from pathlib import Path
from typing import Generator
from ingest.parser import CVERecord
from utils.document_formatter import build_doc_text, normalize_products, normalize_references

logger = logging.getLogger("KEVParser")


def parse_kev_catalog(json_path: str = "./data/cisa_kev/known_exploited_vulnerabilities.json") -> Generator[CVERecord, None, None]:
    """
    Parse CISA KEV JSON file and yield CVERecord objects.
    Reuses build_doc_text to ensure format consistency.
    """
    json_file = Path(json_path)
    if not json_file.exists():
        logger.error("CISA KEV file not found at %s", json_path)
        return

    logger.info("Parsing CISA KEV: %s", json_file.name)
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        vulns = data.get("vulnerabilities", [])
        parsed = 0
        skipped = 0

        for item in vulns:
            try:
                cve_id = item.get("cveID", "").upper().strip()
                if not cve_id:
                    skipped += 1
                    continue

                vendor = item.get("vendorProject", "Unknown").strip()
                product = item.get("product", "Unknown").strip()
                vuln_name = item.get("vulnerabilityName", "").strip()
                short_desc = item.get("shortDescription", "").strip()
                req_action = item.get("requiredAction", "").strip()
                date_added = item.get("dateAdded", "").strip()

                # Build enriched description
                description = f"{vuln_name}. {short_desc}"
                if req_action:
                    description += f" Required Action: {req_action}"
                description += " [CISA KEV - Active Exploitation]"

                # Extract year
                year = "UNKNOWN"
                parts = cve_id.split("-")
                if len(parts) >= 2 and parts[1].isdigit():
                    year = parts[1]

                severity = "HIGH"  # Default to HIGH for actively exploited
                cvss_score = 8.5   # Enriched default score for KEVs
                
                products = [f"{vendor}/{product}"]
                references = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]

                # Reuse centralized formatting
                doc_text = build_doc_text(
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    published=date_added,
                    description=description,
                    products=products,
                    references=references
                )

                record = CVERecord(
                    cve_id=cve_id,
                    year=year,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published=date_added,
                    modified=date_added,
                    products=products,
                    references=references,
                    doc_text=doc_text
                )
                parsed += 1
                yield record
            except Exception as e:
                logger.warning("Failed to parse CISA KEV vulnerability: %s", e)
                skipped += 1

        logger.info("Completed parsing CISA KEV: %d parsed, %d skipped", parsed, skipped)
    except Exception as e:
        logger.error("Failed to parse KEV file %s: %s", json_path, e)
