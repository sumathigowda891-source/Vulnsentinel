"""
ingest/capec_parser.py
Parses MITRE CAPEC Catalog XML and converts attack patterns into standardized CVERecord models.
Uses XML iterparse for low memory footprints.
"""

import logging
from pathlib import Path
from typing import Generator
import xml.etree.ElementTree as ET
from ingest.parser import CVERecord
from utils.document_formatter import build_doc_text, normalize_products, normalize_references

logger = logging.getLogger("CAPECParser")


def parse_capec_catalog(xml_path: str = "./data/capec/capec_latest.xml") -> Generator[CVERecord, None, None]:
    """
    Parse the CAPEC XML catalog and yield CVERecord objects.
    Reuses build_doc_text to ensure format consistency.
    """
    xml_file = Path(xml_path)
    if not xml_file.exists():
        logger.error("CAPEC file not found at %s", xml_path)
        return

    logger.info("Parsing CAPEC Catalog: %s", xml_file.name)
    try:
        context = ET.iterparse(xml_file, events=("end",))
        parsed = 0
        skipped = 0

        for event, elem in context:
            tag_name = elem.tag.split("}")[-1]  # Strip namespace
            if tag_name == "Attack_Pattern":
                try:
                    capec_id = elem.get("ID")
                    name = elem.get("Name")
                    if not capec_id or not name:
                        skipped += 1
                        elem.clear()
                        continue

                    # Description extraction
                    desc_elem = elem.find(".//{*}Description")
                    description = desc_elem.text if desc_elem is not None and desc_elem.text else ""
                    
                    # Optional typical severity
                    sev_elem = elem.find(".//{*}Typical_Severity")
                    severity = "UNKNOWN"
                    if sev_elem is not None and sev_elem.text:
                        raw_sev = sev_elem.text.upper()
                        if "VERY HIGH" in raw_sev or "CRITICAL" in raw_sev:
                            severity = "CRITICAL"
                        elif "HIGH" in raw_sev:
                            severity = "HIGH"
                        elif "MEDIUM" in raw_sev:
                            severity = "MEDIUM"
                        elif "LOW" in raw_sev:
                            severity = "LOW"

                    description = description.strip()
                    if not description:
                        description = name
                    else:
                        description = f"{name}. {description}"

                    published = "2023-01-24"  # Default catalog date
                    year = "2023"
                    cve_id_formatted = f"CAPEC-{capec_id}"

                    # Standard MITRE URL
                    references = [f"https://capec.mitre.org/data/definitions/{capec_id}.html"]

                    # Reuse centralized formatting
                    doc_text = build_doc_text(
                        cve_id=cve_id_formatted,
                        severity=severity,
                        cvss_score=0.0,
                        published=published,
                        description=description,
                        products=[],
                        references=references
                    )

                    record = CVERecord(
                        cve_id=cve_id_formatted,
                        year=year,
                        description=description,
                        cvss_score=0.0,
                        severity=severity,
                        published=published,
                        modified=published,
                        products=[],
                        references=references,
                        doc_text=doc_text
                    )
                    parsed += 1
                    yield record
                except Exception as e:
                    logger.warning("Failed to parse CAPEC weakness: %s", e)
                    skipped += 1
                elem.clear()  # Free memory

        logger.info("Completed parsing CAPEC: %d parsed, %d skipped", parsed, skipped)
    except Exception as e:
        logger.error("Failed to parse CAPEC file %s: %s", xml_path, e)
