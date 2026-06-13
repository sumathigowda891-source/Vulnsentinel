"""
output/report_gen.py
Generates a professional PDF threat intelligence report using ReportLab.
Called after the RAG pipeline produces a result.
"""

import os
import re
import html
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "report_gen.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDReportGen")

OUTPUT_DIR = Path("./data/reports")


def clean_markdown_to_html(text: str) -> str:
    """
    Escape XML special characters and convert markdown syntax to ReportLab HTML-like tags.
    """
    if not text:
        return ""
    # 1. Escape HTML/XML special characters first so they don't break the PDF parser
    text = (
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
    )
    # 2. Convert markdown bold (**text**) to <b>text</b>
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # 3. Convert markdown italic (*text*) to <i>italic</i>
    text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
    # 4. Convert markdown inline code (`code`) to font face Courier
    text = re.sub(r'`(.*?)`', r'<font face="Courier">\1</font>', text)
    # 5. Convert markdown links ([text](url)) to clickable hyperlinks
    text = re.sub(r'\[(.*?)\]\((.*?)\)', r'<a href="\2" color="#1E3A5F"><u>\1</u></a>', text)
    
    return text


def get_severity_color(severity: str):
    """Return ReportLab color for severity level."""
    mapping = {
        "CRITICAL": colors.HexColor("#DC2626"),
        "HIGH":     colors.HexColor("#EA580C"),
        "MEDIUM":   colors.HexColor("#D97706"),
        "LOW":      colors.HexColor("#16A34A"),
        "UNKNOWN":  colors.HexColor("#6B7280"),
    }
    return mapping.get(severity.upper(), colors.grey)


def build_styles():
    """Build custom paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        name="ReportTitle",
        fontSize=22,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=6,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="Subtitle",
        fontSize=11,
        fontName="Helvetica",
        textColor=colors.HexColor("#475569"),
        spaceAfter=4,
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader",
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1E3A5F"),
        spaceBefore=14,
        spaceAfter=6,
        borderPad=4,
    ))
    styles.add(ParagraphStyle(
        name="Body",
        fontSize=10,
        fontName="Helvetica",
        textColor=colors.HexColor("#1E293B"),
        spaceAfter=4,
        leading=14,
    ))
    styles.add(ParagraphStyle(
        name="Warning",
        fontSize=10,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#B45309"),
        backColor=colors.HexColor("#FEF3C7"),
        spaceAfter=4,
        borderPad=6,
    ))
    styles.add(ParagraphStyle(
        name="TableHeader",
        fontSize=9,
        fontName="Helvetica-Bold",
        textColor=colors.white,
        leading=12,
    ))
    styles.add(ParagraphStyle(
        name="TableHeaderCenter",
        parent=styles["TableHeader"],
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="TableBody",
        fontSize=8.5,
        fontName="Helvetica",
        textColor=colors.HexColor("#1E293B"),
        leading=11,
    ))
    styles.add(ParagraphStyle(
        name="TableBodyCenter",
        parent=styles["TableBody"],
        alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="BulletText",
        parent=styles["Body"],
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3,
        leading=13,
    ))
    return styles


def build_emergency_report(query: str, rag_result: dict, output_path: Path, error_msg: str) -> Path:
    """
    Generate a basic emergency PDF report when standard layout rendering fails.
    Guaranteed to use standard basic styles to prevent layout crash.
    """
    logger.warning("event=pdf_emergency_fallback | query='%s' | error='%s' | output_path='%s'", query, error_msg, output_path)
    try:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []
        
        story.append(Paragraph("VulnSentinel — EMERGENCY REPORT", styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(f"<b>Query:</b> {query}", styles["Normal"]))
        story.append(Paragraph(f"<b>Timestamp:</b> {datetime.now().isoformat()} UTC", styles["Normal"]))
        story.append(Spacer(1, 0.4 * cm))
        
        story.append(Paragraph("<b>System Recovery Warning:</b>", styles["Heading3"]))
        story.append(Paragraph(
            f"Standard report generation layout crashed. Render failure details: "
            f"<code>{error_msg}</code>. Critical records are attached below.",
            styles["Normal"]
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph("<b>Retrieved CVE Evidences:</b>", styles["Heading3"]))
        cve_chunks = rag_result.get("chunks", [])
        if cve_chunks:
            for cve in cve_chunks:
                cve_id = cve.get("cve_id", "N/A")
                severity = cve.get("severity", "N/A")
                cvss = cve.get("cvss_score", "N/A")
                desc = cve.get("document", "")
                
                # Extract Description safely
                for line in desc.split("\n"):
                    if line.startswith("Description:"):
                        desc = line.replace("Description:", "").strip()
                        break
                desc = desc[:200] + "..." if len(desc) > 200 else desc
                
                story.append(Paragraph(f"• <b>{cve_id}</b> (Severity: {severity} | CVSS: {cvss})<br/>{desc}", styles["Normal"]))
                story.append(Spacer(1, 0.3 * cm))
        else:
            story.append(Paragraph("No CVEs retrieved.", styles["Normal"]))

        doc.build(story)
        logger.info("event=pdf_generation_complete | type=emergency | query='%s'", query)
        return output_path
    except Exception as ex:
        logger.critical("event=pdf_generation_error | type=emergency_critical | error='%s'", str(ex))
        raise ex


def generate_pdf_report(
    query: str,
    rag_result: dict,
    output_filename: str | None = None,
) -> Path:
    """
    Generate a PDF threat intelligence report from RAG pipeline output.
    """
    start_time = time.perf_counter()
    logger.info("event=pdf_generation_start | query='%s'", query)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not output_filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_query = "".join(c if c.isalnum() else "_" for c in query[:30])
        output_filename = f"vulnsentinel_{safe_query}_{timestamp}.pdf"

    output_path = OUTPUT_DIR / output_filename
    
    try:
        styles = build_styles()
    except Exception as e:
        logger.error("event=report_section_error | section=styles | error='%s'", str(e))
        return build_emergency_report(query, rag_result, output_path, f"Styles initialization failure: {str(e)}")

    try:
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
    except Exception as e:
        logger.error("event=report_section_error | section=document_template | error='%s'", str(e))
        return build_emergency_report(query, rag_result, output_path, f"Document initialization failure: {str(e)}")

    story = []
    cve_chunks = rag_result.get("chunks", [])
    is_fallback = rag_result.get("is_fallback", False)

    # ── Header ────────────────────────────────────────────────────────────────
    try:
        story.append(Paragraph("VulnSentinel", styles["ReportTitle"]))
        story.append(Paragraph("Threat Intelligence Report", styles["Subtitle"]))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%B %d, %Y %H:%M UTC')} | "
            f"Data Source: NVD/NIST",
            styles["Subtitle"]
        ))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1E3A5F")))
        story.append(Spacer(1, 0.3 * cm))
    except Exception as e:
        logger.error("event=report_section_error | section=header | error='%s'", str(e))

    # ── Query ─────────────────────────────────────────────────────────────────
    try:
        story.append(Paragraph("Query", styles["SectionHeader"]))
        story.append(Paragraph(query, styles["Body"]))
    except Exception as e:
        logger.error("event=report_section_error | section=query | error='%s'", str(e))

    # ── Fallback warning ──────────────────────────────────────────────────────
    try:
        if is_fallback:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph(
                "WARNING: AI generation was offline during this report. "
                "The data below represents raw retrieved CVE records without AI analysis.",
                styles["Warning"]
            ))
    except Exception as e:
        logger.error("event=report_section_error | section=fallback_warning | error='%s'", str(e))

    # ── Hallucination warning ─────────────────────────────────────────────────
    try:
        hallucinated = rag_result.get("hallucinated_cves", [])
        if hallucinated:
            story.append(Paragraph(
                f"OUTPUT GUARDRAIL: The following CVE IDs were flagged as unverified: "
                f"{', '.join(hallucinated)}. Verify at nvd.nist.gov.",
                styles["Warning"]
            ))
    except Exception as e:
        logger.error("event=report_section_error | section=hallucination_warning | error='%s'", str(e))

    # ── CVE Summary Table ─────────────────────────────────────────────────────
    try:
        story.append(Paragraph("Critical Vulnerabilities Found", styles["SectionHeader"]))

        if cve_chunks:
            table_data = [[
                Paragraph("CVE ID", styles["TableHeader"]),
                Paragraph("CVSS", styles["TableHeaderCenter"]),
                Paragraph("Severity", styles["TableHeaderCenter"]),
                Paragraph("Published", styles["TableHeaderCenter"]),
                Paragraph("Summary", styles["TableHeader"])
            ]]
            for cve in cve_chunks:
                desc = cve.get("document", "")
                # Extract just the description line safely
                for line in desc.split("\n"):
                    if line.startswith("Description:"):
                        desc = line.replace("Description:", "").strip()
                        break
                desc = desc[:150] + "..." if len(desc) > 150 else desc

                cve_id = cve.get("cve_id", "N/A")
                cvss = str(cve.get("cvss_score", "N/A"))
                sev = cve.get("severity", "N/A")
                pub = cve.get("published", "N/A")

                # Get severity color inline HTML
                sev_color_hex = "#6B7280"
                if sev.upper() == "CRITICAL":
                    sev_color_hex = "#DC2626"
                elif sev.upper() == "HIGH":
                    sev_color_hex = "#EA580C"
                elif sev.upper() == "MEDIUM":
                    sev_color_hex = "#D97706"
                elif sev.upper() == "LOW":
                    sev_color_hex = "#16A34A"
                sev_html = f"<b><font color='{sev_color_hex}'>{sev}</font></b>"

                table_data.append([
                    Paragraph(clean_markdown_to_html(cve_id), styles["TableBody"]),
                    Paragraph(clean_markdown_to_html(cvss), styles["TableBodyCenter"]),
                    Paragraph(sev_html, styles["TableBodyCenter"]),
                    Paragraph(clean_markdown_to_html(pub), styles["TableBodyCenter"]),
                    Paragraph(clean_markdown_to_html(desc), styles["TableBody"]),
                ])

            col_widths = [3.2 * cm, 1.5 * cm, 2.0 * cm, 2.3 * cm, 8.0 * cm]
            table = Table(table_data, colWidths=col_widths, repeatRows=1)

            table_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A5F")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8FAFC"), colors.white]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
            table.setStyle(TableStyle(table_style))
            story.append(table)
        else:
            story.append(Paragraph("No CVEs retrieved.", styles["Body"]))
    except Exception as e:
        logger.error("event=report_section_error | section=cve_table | error='%s'", str(e))
        story.append(Paragraph("[Error rendering CVE summary table]", styles["Body"]))

    story.append(PageBreak())

    # ── AI Analysis ───────────────────────────────────────────────────────────
    try:
        if not is_fallback and rag_result.get("response"):
            story.append(Paragraph("AI-Generated Analysis", styles["SectionHeader"]))
            # Split response into paragraphs
            for line in rag_result["response"].split("\n"):
                line = line.strip()
                if not line:
                    story.append(Spacer(1, 0.15 * cm))
                    continue

                # Parse markdown headers
                header_match = re.match(r'^(#{1,6})\s+(.*)$', line)
                if header_match:
                    clean = header_match.group(2).strip()
                    # Skip redundant report title headers
                    if "VulnSentinel" in clean or "Threat Intelligence Report" in clean:
                        continue
                    story.append(Paragraph(clean_markdown_to_html(clean), styles["SectionHeader"]))
                    continue

                # Parse bullet lists
                if line.startswith("- ") or line.startswith("* ") or line.startswith("• "):
                    clean_line = re.sub(r'^[-*•]\s+', '', line).strip()
                    story.append(Paragraph(clean_markdown_to_html(clean_line), styles["BulletText"], bulletText="&bull;"))
                    continue

                # Parse numbered lists
                num_match = re.match(r'^(\d+)\.\s+(.*)$', line)
                if num_match:
                    num = num_match.group(1)
                    clean_line = num_match.group(2).strip()
                    story.append(Paragraph(clean_markdown_to_html(clean_line), styles["BulletText"], bulletText=f"{num}."))
                    continue

                # Table lines (like markdown table separators or borders)
                if line.startswith("|"):
                    continue

                # Standard body text
                story.append(Paragraph(clean_markdown_to_html(line), styles["Body"]))
        else:
            story.append(Paragraph("AI-Generated Analysis", styles["SectionHeader"]))
            story.append(Paragraph("AI-Generated Analysis is not available for this report (Offline/Fallback Mode).", styles["Body"]))
    except Exception as e:
        logger.error("event=report_section_error | section=ai_analysis | error='%s'", str(e))
        story.append(Paragraph("[Error rendering AI-Generated Analysis]", styles["Body"]))

    story.append(PageBreak())

    # ── Affected Products ─────────────────────────────────────────────────────
    try:
        story.append(Paragraph("Affected Products & Systems", styles["SectionHeader"]))
        all_products = set()
        for cve in cve_chunks:
            products = cve.get("products", [])
            if isinstance(products, str):
                try:
                    products = json.loads(products)
                except Exception:
                     products = []
            all_products.update(products)

        if all_products:
            for product in sorted(all_products)[:20]:
                story.append(Paragraph(clean_markdown_to_html(product), styles["BulletText"], bulletText="&bull;"))
        else:
            story.append(Paragraph("Product information not available.", styles["Body"]))
    except Exception as e:
        logger.error("event=report_section_error | section=affected_products | error='%s'", str(e))

    # ── References ────────────────────────────────────────────────────────────
    try:
        story.append(Paragraph("References", styles["SectionHeader"]))
        all_refs = set()
        for cve in cve_chunks:
            refs = cve.get("references", [])
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except Exception:
                     refs = []
            all_refs.update(refs[:2])

        if all_refs:
            for ref in sorted(all_refs)[:10]:
                story.append(Paragraph(clean_markdown_to_html(ref), styles["BulletText"], bulletText="&bull;"))
        else:
            story.append(Paragraph("https://nvd.nist.gov/vuln/search", styles["BulletText"], bulletText="&bull;"))
    except Exception as e:
        logger.error("event=report_section_error | section=references | error='%s'", str(e))

    # ── Footer ────────────────────────────────────────────────────────────────
    try:
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1")))
        story.append(Paragraph(
            "VulnSentinel — Enterprise-Grade RAG Vulnerability Intelligence System | "
            "Data: NVD/NIST | For authorized security use only.",
            styles["Subtitle"]
        ))
    except Exception as e:
        logger.error("event=report_section_error | section=footer | error='%s'", str(e))

    # Build Document
    try:
        doc.build(story)
        duration = (time.perf_counter() - start_time) * 1000
        logger.info("event=pdf_generation_complete | query='%s' | latency_ms=%.2f", query, duration)
        return output_path
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000
        logger.error(
            "event=reportlab_exception | query='%s' | error_type=%s | error='%s' | latency_ms=%.2f",
            query, type(e).__name__, str(e), duration
        )
        return build_emergency_report(query, rag_result, output_path, str(e))


if __name__ == "__main__":
    # Test with dummy data
    test_result = {
        "mode": "AI_GENERATED",
        "is_fallback": False,
        "response": "## Executive Summary\nApache Log4j CVE-2021-44228 is critical.",
        "chunks": [
            {
                "cve_id": "CVE-2021-44228",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "published": "2021-12-10",
                "document": "CVE ID: CVE-2021-44228\nDescription: Apache Log4j2 JNDI lookup RCE vulnerability.",
                "products": ["apache/log4j"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            }
        ],
        "hallucinated_cves": [],
    }
    path = generate_pdf_report("Apache Log4j vulnerabilities", test_result)
    print(f"Generated: {path}")
