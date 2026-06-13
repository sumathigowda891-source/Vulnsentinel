"""
ingest/attack_parser.py
Parses MITRE ATT&CK STIX JSON files and converts techniques, malware, tools, and intrusion sets to standardized CVERecord models.
"""

import json
import logging
from pathlib import Path
from typing import Generator
from ingest.parser import CVERecord
from utils.document_formatter import build_doc_text, normalize_products, normalize_references

logger = logging.getLogger("AttackParser")


def parse_attack_catalog(json_path: str = "./data/mitre_attack/enterprise-attack/enterprise-attack.json") -> Generator[CVERecord, None, None]:
    """
    Parse MITRE ATT&CK STIX JSON file and yield CVERecord objects.
    Reuses build_doc_text to ensure format consistency.
    """
    json_file = Path(json_path)
    if not json_file.exists():
        logger.error("MITRE ATT&CK file not found at %s", json_path)
        return

    logger.info("Parsing MITRE ATT&CK Catalog: %s", json_file.name)
    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        objects = data.get("objects", [])
        parsed = 0
        skipped = 0

        target_types = {"attack-pattern", "malware", "tool", "intrusion-set"}

        for obj in objects:
            try:
                # 1. Type filter
                obj_type = obj.get("type")
                if obj_type not in target_types:
                    continue

                # 2. Skip revoked and deprecated items
                if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                    continue

                # 3. Find External ID and reference URL
                external_id = None
                ref_url = None
                ext_refs = obj.get("external_references", [])
                
                # Check official sources first
                for ref in ext_refs:
                    src_name = ref.get("source_name", "")
                    if src_name in ["mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"]:
                        external_id = ref.get("external_id")
                        ref_url = ref.get("url")
                        break

                # Fallback to first available external_id
                if not external_id:
                    for ref in ext_refs:
                        if ref.get("external_id"):
                            external_id = ref.get("external_id")
                            ref_url = ref.get("url")
                            break

                if not external_id:
                    skipped += 1
                    continue

                name = obj.get("name", "").strip()
                desc_raw = obj.get("description", "").strip()
                description = f"{name}. {desc_raw}" if desc_raw else name

                # Format created date to published YYYY-MM-DD
                created = obj.get("created", "")
                published = created[:10] if created else "2020-01-01"
                year = published[:4] if published else "2020"

                severity = "UNKNOWN"
                cvss_score = 0.0
                
                products = []
                references = [ref_url] if ref_url else []

                # Add type prefix description indicator
                type_indicator = f"[{obj_type.replace('-', ' ').title()}]"
                description = f"{type_indicator} {description}"

                # Reuse centralized formatting
                doc_text = build_doc_text(
                    cve_id=external_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    published=published,
                    description=description,
                    products=products,
                    references=references
                )

                record = CVERecord(
                    cve_id=external_id,
                    year=year,
                    description=description,
                    cvss_score=cvss_score,
                    severity=severity,
                    published=published,
                    modified=obj.get("modified", "")[:10] if obj.get("modified") else published,
                    products=products,
                    references=references,
                    doc_text=doc_text
                )
                parsed += 1
                yield record
            except Exception as e:
                logger.warning("Failed to parse MITRE ATT&CK object: %s", e)
                skipped += 1

        logger.info("Completed parsing MITRE ATT&CK: %d parsed, %d skipped", parsed, skipped)
    except Exception as e:
        logger.error("Failed to parse ATT&CK file %s: %s", json_path, e)
