"""
fallback/degradation.py
Graceful degradation handler when the Gemini API fails.
Instead of crashing, shows raw retrieved CVE chunks with a clear warning.
Satisfies assignment requirement: partial RAG response on API failure.
"""

import json
import logging
from datetime import datetime

logger = logging.getLogger("NVDFallback")


def format_raw_chunks(cve_chunks: list[dict]) -> str:
    """
    Format raw retrieved CVE chunks into a readable fallback response.
    This is shown to the user when the LLM API is unavailable.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("⚠️  AI GENERATION OFFLINE — SHOWING RAW RETRIEVED DATA")
    lines.append("The LLM API is currently unavailable.")
    lines.append("Below are the most relevant CVEs retrieved from the knowledge base.")
    lines.append("=" * 60)
    lines.append("")

    for i, cve in enumerate(cve_chunks, 1):
        lines.append(f"─── Result {i} ───────────────────────────────────────")
        lines.append(f"CVE ID:    {cve.get('cve_id', 'N/A')}")
        lines.append(f"Severity:  {cve.get('severity', 'N/A')} (CVSS: {cve.get('cvss_score', 'N/A')})")
        lines.append(f"Published: {cve.get('published', 'N/A')}")

        products = cve.get("products", [])
        if isinstance(products, str):
            try:
                products = json.loads(products)
            except Exception:
                products = []
        if products:
            lines.append(f"Products:  {', '.join(products[:5])}")

        lines.append(f"Details:   {cve.get('document', '')[:500]}")

        refs = cve.get("references", [])
        if isinstance(refs, str):
            try:
                refs = json.loads(refs)
            except Exception:
                refs = []
        if refs:
            lines.append(f"Reference: {refs[0]}")

        lines.append("")

    lines.append("─" * 60)
    lines.append("Please try again later for AI-enhanced analysis.")
    lines.append(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    return "\n".join(lines)


def handle_api_failure(
    error: Exception,
    query: str,
    cve_chunks: list[dict],
) -> dict:
    """
    Main fallback handler. Called when any LLM API exception occurs.

    Returns a structured response dict indicating fallback mode.
    """
    error_type = type(error).__name__
    error_msg = str(error)

    # Classify error type
    if "rate_limit" in error_msg.lower() or "429" in error_msg:
        cause = "Rate limit exceeded"
    elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
        cause = "API request timed out"
    elif "authentication" in error_msg.lower() or "401" in error_msg:
        cause = "Authentication error (check API key)"
    elif "503" in error_msg or "502" in error_msg or "overloaded" in error_msg.lower():
        cause = "API service temporarily unavailable"
    elif "connection" in error_msg.lower():
        cause = "Network connection error"
    else:
        cause = f"Unexpected error: {error_type}"

    # Structured Telemetry Logging
    logger.warning(
        "event=degradation_fallback | cause='%s' | error_type=%s | error_detail='%s' | query='%s' | chunks_count=%d",
        cause, error_type, error_msg[:100], query, len(cve_chunks)
    )

    raw_fallback = format_raw_chunks(cve_chunks)

    return {
        "mode": "FALLBACK",
        "is_fallback": True,
        "error_cause": cause,
        "error_detail": error_msg[:200],
        "query": query,
        "raw_response": raw_fallback,
        "chunks_count": len(cve_chunks),
        "timestamp": datetime.now().isoformat(),
    }


class APIFailoverClient:
    """
    Wraps Gemini API calls with automatic fallback.
    Tries primary API; on failure, returns raw chunk fallback.
    """

    def __init__(self, gemini_client, max_retries: int = 2):
        self.client = gemini_client
        self.max_retries = max_retries

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        query: str,
        cve_chunks: list[dict],
        max_tokens: int = 1500,
    ) -> dict:
        """
        Attempt LLM generation with retry logic.
        Falls back to raw chunks on failure.
        """
        import time

        last_error = None
        prompt = f"{system_prompt}\n\n{user_prompt}"

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.client.generate_content(
                    prompt,
                )

                content = response.text if response else ""

                return {
                    "mode": "AI_GENERATED",
                    "is_fallback": False,
                    "response": content,
                    "query": query,
                    "chunks_used": len(cve_chunks),
                }

            except Exception as e:
                last_error = e
                print(f"[!] API attempt {attempt}/{self.max_retries} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff

        # All retries exhausted — activate fallback
        print(f"[!] All API attempts failed. Activating graceful degradation.")
        return handle_api_failure(last_error, query, cve_chunks)


if __name__ == "__main__":
    # Test fallback formatting
    test_chunks = [
        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "published": "2021-12-10",
            "document": "Log4Shell vulnerability in Apache Log4j allowing remote code execution via JNDI lookup.",
            "products": ["apache/log4j"],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        }
    ]

    result = handle_api_failure(
        Exception("API timeout after 30s"),
        "Apache Log4j RCE",
        test_chunks,
    )
    print(result["raw_response"])
