"""
ingest/cwe_parser.py
Parses MITRE CWE Catalog XML and converts weaknesses into standardized CVERecord models.
Uses XML iterparse for low memory footprints.
"""

import logging
from pathlib import Path
from typing import Generator
import xml.etree.ElementTree as ET
from ingest.parser import CVERecord
from utils.document_formatter import build_doc_text, normalize_products, normalize_references

logger = logging.getLogger("CWEParser")


def parse_cwe_catalog(xml_path: str = "./data/cwe/cwec_v4.20.xml") -> Generator[CVERecord, None, None]:
    """
    Parse the CWE XML catalog and yield CVERecord objects.
    Reuses build_doc_text to ensure format consistency.
    """
    xml_file = Path(xml_path)
    if not xml_file.exists():
        logger.error("CWE file not found at %s", xml_path)
        return

    logger.info("Parsing CWE Catalog: %s", xml_file.name)
    try:
        context = ET.iterparse(xml_file, events=("end",))
        parsed = 0
        skipped = 0

        for event, elem in context:
            tag_name = elem.tag.split("}")[-1]  # Strip namespace
            if tag_name == "Weakness":
                try:
                    cwe_id = elem.get("ID")
                    name = elem.get("Name")
                    if not cwe_id or not name:
                        skipped += 1
                        elem.clear()
                        continue

                    # Description extraction
                    desc_elem = elem.find(".//{*}Description")
                    description = desc_elem.text if desc_elem is not None and desc_elem.text else ""
                    
                    ext_desc_elem = elem.find(".//{*}Extended_Description")
                    if ext_desc_elem is not None:
                        ext_text = "".join(ext_desc_elem.itertext()).strip()
                        if ext_text:
                            description += " " + ext_text

                    description = description.strip()
                    if not description:
                        description = name
                    else:
                        description = f"{name}. {description}"

                    # Likelihood to Severity mapping
                    likelihood_elem = elem.find(".//{*}Likelihood_Of_Exploit")
                    severity = "UNKNOWN"
                    if likelihood_elem is not None and likelihood_elem.text:
                        lik = likelihood_elem.text.upper()
                        if "HIGH" in lik:
                            severity = "HIGH"
                        elif "MEDIUM" in lik:
                            severity = "MEDIUM"
                        elif "LOW" in lik:
                            severity = "LOW"

                    published = "2026-04-30"  # Default catalog release date
                    year = "2026"
                    cve_id_formatted = f"CWE-{cwe_id}"

                    # Standard MITRE URL
                    references = [f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"]

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
                    logger.warning("Failed to parse CWE weakness: %s", e)
                    skipped += 1
                elem.clear()  # Free memory

        logger.info("Completed parsing CWE: %d parsed, %d skipped", parsed, skipped)
    except Exception as e:
        logger.error("Failed to parse CWE file %s: %s", xml_path, e)
