"""
pipeline/rag_engine.py
Main RAG orchestrator for VulnSentinel.
Wires together: guardrails → retrieval → reranking → CoT prompting → LLM → output guardrail → fallback.
"""

import os
import time
import logging
from pathlib import Path
from dotenv import load_dotenv
import google.generativeai as genai

from pipeline.guardrails import check_input, check_output, check_rate_limit
from pipeline.prompts import SYSTEM_PROMPT, build_cot_prompt, build_react_prompt
from retrieval.reranker import retrieve_and_rerank

load_dotenv()
genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)

gemini_model = genai.GenerativeModel(
    "gemini-2.5-flash"
)

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "rag_engine.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDRagEngine")


def configure_api_key():
    """Dynamically reload .env file and reconfigure Gemini API key."""
    global gemini_model
    env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=env_path, override=True)
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        genai.configure(api_key=api_key)
    gemini_model = genai.GenerativeModel("gemini-2.5-flash")


def is_complex_query(query: str) -> bool:
    """Heuristic to decide if ReAct (vs CoT) is better for this query."""
    complex_keywords = [
        "compare", "multiple", "chain", "attack chain", "related",
        "all vulnerabilities", "combination", "step by step",
        "what should i do", "full audit", "comprehensive"
    ]
    return any(kw in query.lower() for kw in complex_keywords)


def run_rag_pipeline(
    query: str,
    client_id: str = "default",
    top_k_vector: int = 20,
    top_k_final: int = 5,
    severity_filter: str | None = None,
    year_filter: str | None = None,
    simulate_failure: bool = False,
) -> dict:
    """
    Full VulnSentinel RAG pipeline.

    Steps:
    1. Rate limit check
    2. Input guardrail (blocks injections, exploits, OOS)
    3. Vector search (top 20)
    4. FlashRank reranking (top 5)
    5. CoT or ReAct prompt building
    6. Gemini API call with fallback
    7. Output guardrail (hallucination check)

    Returns:
        dict with response, mode, metadata
    """

    configure_api_key()
    start_time = time.perf_counter()
    logger.info("event=rag_pipeline_start | client_id=%s | query='%s'", client_id, query)

    # ── Step 1: Rate limiting ──────────────────────────────────────────────────
    rate_ok, rate_msg = check_rate_limit(client_id)
    if not rate_ok:
        logger.warning("event=rag_rate_limit | client_id=%s | blocked=True | reason='%s'", client_id, rate_msg)
        return {
            "mode": "BLOCKED",
            "blocked": True,
            "block_reason": rate_msg,
            "block_category": "RATE_LIMIT",
            "query": query,
        }

    # ── Step 2: Input guardrail ────────────────────────────────────────────────
    is_safe, reason, category = check_input(query)
    if not is_safe:
        logger.warning("event=rag_input_guardrail | client_id=%s | safe=False | category=%s | reason='%s'", client_id, category, reason)
        return {
            "mode": "BLOCKED",
            "blocked": True,
            "block_reason": reason,
            "block_category": category,
            "query": query,
        }
    logger.info("event=rag_input_guardrail | client_id=%s | safe=True | category=%s", client_id, category)

    # ── Step 3 & 4: Retrieve + Rerank ─────────────────────────────────────────
    retrieval_start = time.perf_counter()
    try:
        cve_chunks = retrieve_and_rerank(
            query=query,
            top_k_vector=top_k_vector,
            top_k_final=top_k_final,
            severity_filter=severity_filter,
            year_filter=year_filter,
        )
        retrieval_latency = (time.perf_counter() - retrieval_start) * 1000
        logger.info(
            "event=rag_retrieval | client_id=%s | chunks_retrieved=%d | latency_ms=%.2f",
            client_id, len(cve_chunks), retrieval_latency
        )
    except Exception as e:
        retrieval_latency = (time.perf_counter() - retrieval_start) * 1000
        logger.error(
            "event=rag_retrieval_error | client_id=%s | error='%s' | latency_ms=%.2f",
            client_id, str(e), retrieval_latency
        )
        return {
            "mode": "ERROR",
            "blocked": False,
            "error": f"Retrieval failed: {str(e)}",
            "query": query,
        }

    if not cve_chunks:
        logger.info("event=rag_no_results | client_id=%s | query='%s'", client_id, query)
        return {
            "mode": "NO_RESULTS",
            "blocked": False,
            "response": "No relevant CVEs found in the knowledge base for your query. Try different keywords.",
            "query": query,
            "chunks": [],
        }

    # ── Step 5: Build prompt (CoT or ReAct) ───────────────────────────────────
    if is_complex_query(query):
        user_prompt = build_react_prompt(query, cve_chunks)
    else:
        user_prompt = build_cot_prompt(query, cve_chunks)

    # ── Step 6: LLM Call with Failover ────────────────────────────────────────

        # ── Step 6: LLM Call with Failover ────────────────────────────────────────
    llm_start = time.perf_counter()

    if simulate_failure:
        logger.warning(
            "event=rag_llm_failure_simulated | client_id=%s",
            client_id
        )

        from fallback.degradation import handle_api_failure

        result = handle_api_failure(
            Exception("Simulated API failure for demo"),
            query,
            cve_chunks,
        )

    else:
        try:
            prompt = f"""
{SYSTEM_PROMPT}

{user_prompt}
"""

            response = gemini_model.generate_content(prompt)

            result = {
                "mode": "AI_GENERATED",
                "response": response.text,
                "is_fallback": False
            }

        except Exception as e:
            from fallback.degradation import handle_api_failure

            result = handle_api_failure(
                e,
                query,
                cve_chunks
            )

    llm_latency = (time.perf_counter() - llm_start) * 1000
    mode = result.get("mode")
    is_fallback = result.get("is_fallback", False)

    logger.info(
        "event=rag_llm_generation | client_id=%s | mode=%s | is_fallback=%s | latency_ms=%.2f",
        client_id,
        mode,
        is_fallback,
        llm_latency
    )

    # ── Step 7: Output guardrail ───────────────────────────────────────────────
    if result.get("mode") == "AI_GENERATED" and result.get("response"):
        is_output_safe, cleaned_response, hallucinated = check_output(
            result["response"],
            cve_chunks
        )

        result["response"] = cleaned_response
        result["hallucinated_cves"] = hallucinated
        result["output_guardrail_triggered"] = not is_output_safe

        logger.info(
            "event=rag_output_guardrail | client_id=%s | output_safe=%s | hallucinated_count=%d",
            client_id,
            is_output_safe,
            len(hallucinated)
        )

    result["chunks"] = cve_chunks
    result["blocked"] = False

    total_latency = (time.perf_counter() - start_time) * 1000

    logger.info(
        "event=rag_pipeline_complete | client_id=%s | mode=%s | total_latency_ms=%.2f",
        client_id,
        mode,
        total_latency
    )

    return result


def run_assistant_chat(
    history: list,
    query: str,
    simulate_failure: bool = False,
) -> dict:
    """
    Run chat assistant using conversation history and RAG context if applicable.
    history: list of dicts [{"role": "user"|"assistant", "content": "..."}]
    query: the latest user message from the user
    """
    configure_api_key()
    start_time = time.perf_counter()
    logger.info("event=assistant_chat_start | query='%s'", query)

    # ── Step 1: Input guardrail (bypass for simple greeting/command/short words)
    query_clean = query.strip().lower()
    is_greeting = query_clean in ["hi", "hello", "hey", "help", "clear", "reset", "who are you", "who are you?", "greet", "greetings"]
    
    if not is_greeting and len(query_clean) >= 3:
        is_safe, reason, category = check_input(query)
        if not is_safe:
            logger.warning("event=assistant_input_blocked | category=%s | reason='%s'", category, reason)
            return {
                "mode": "BLOCKED",
                "blocked": True,
                "block_reason": reason,
                "block_category": category,
                "response": reason,
                "chunks": []
            }

    # ── Step 2: Retrieve CVE database context if vulnerability-related
    cve_chunks = []
    if not is_greeting and len(query_clean) >= 3:
        try:
            cve_chunks = retrieve_and_rerank(
                query=query,
                top_k_vector=10,
                top_k_final=3,
            )
            logger.info("event=assistant_retrieval | chunks=%d", len(cve_chunks))
        except Exception as e:
            logger.error("event=assistant_retrieval_error | error='%s'", str(e))

    # ── Step 3: Call Gemini with simulated or live error failover
    try:
        if simulate_failure:
            logger.warning("event=assistant_failure_simulated")
            raise Exception("Simulated API failure for assistant (Demo mode active)")

        # Build prompt using system instructions, retrieved CVE context, and history
        system_instructions = (
            "You are VulnSentinel AI Assistant, a helpful and expert cybersecurity threat intelligence assistant. "
            "You help users analyze, understand, and remediate software vulnerabilities and CVEs. "
            "Be precise, clear, and professional. Use markdown formatting. "
            "Ensure you do NOT suggest or use blue themes/styling in your responses. Keep it aligned with our warm, creamy palette."
        )

        prompt_parts = [system_instructions]

        if cve_chunks:
            context_str = ""
            for idx, c in enumerate(cve_chunks):
                context_str += (
                    f"[{idx+1}] CVE ID: {c.get('cve_id')}\n"
                    f"    Vendor/Product: {c.get('vendor', 'Unknown')} / {c.get('product', 'Unknown')}\n"
                    f"    Severity: {c.get('severity', 'UNKNOWN')} (Score: {c.get('cvss_score', 'N/A')})\n"
                    f"    Published: {c.get('published_date', 'Unknown')}\n"
                    f"    Description: {c.get('description', '')}\n\n"
                )
            prompt_parts.append(
                f"Here is some retrieved CVE context from the VulnSentinel local knowledge base:\n"
                f"{context_str.strip()}\n"
                f"Use this retrieved context to answer the user's question. If the context is not sufficient, "
                f"you can supplement it with your general knowledge, but clearly state what is from the local database vs general intelligence."
            )

        prompt_parts.append("Conversation History:")
        for msg in history:
            role_name = "User" if msg["role"] == "user" else "Assistant"
            prompt_parts.append(f"{role_name}: {msg['content']}")

        prompt_parts.append(f"User: {query}")
        prompt_parts.append("Assistant:")

        full_prompt = "\n\n".join(prompt_parts)

        response = gemini_model.generate_content(full_prompt)
        ai_response = response.text

        # Run output guardrails if context was retrieved
        if cve_chunks:
            is_output_safe, cleaned_response, hallucinated = check_output(
                ai_response,
                cve_chunks
            )
            ai_response = cleaned_response

        total_latency = (time.perf_counter() - start_time) * 1000
        logger.info("event=assistant_chat_complete | latency_ms=%.2f", total_latency)

        return {
            "mode": "AI_GENERATED",
            "blocked": False,
            "response": ai_response,
            "is_fallback": False,
            "chunks": cve_chunks
        }

    except Exception as e:
        logger.error("event=assistant_error | error='%s'", str(e))
        
        # Classify the error type
        error_type = type(e).__name__
        error_msg = str(e)
        if "simulated" in error_msg.lower():
            cause = "simulated API failure for demonstration purposes"
        elif "rate_limit" in error_msg.lower() or "429" in error_msg:
            cause = "Gemini API rate limit or quota exceeded"
        elif "timeout" in error_msg.lower() or "timed out" in error_msg.lower():
            cause = "Gemini API request timeout"
        elif "authentication" in error_msg.lower() or "401" in error_msg:
            cause = "Gemini API authentication issue (check API key)"
        elif "503" in error_msg or "502" in error_msg or "overloaded" in error_msg.lower():
            cause = "Gemini API service temporarily overloaded/offline"
        elif "connection" in error_msg.lower():
            cause = "network connection error to Gemini API"
        else:
            cause = f"Gemini API unexpected error ({error_type})"

        if cve_chunks:
            from fallback.degradation import handle_api_failure
            result = handle_api_failure(e, query, cve_chunks)
            fallback_text = result.get("raw_response", "")
            return {
                "mode": "FALLBACK",
                "blocked": False,
                "response": (
                    f"### ⚠️ Gemini API Offline — Graceful Degradation Active\n\n"
                    f"I encountered a **{cause}** when contacting the primary AI model. "
                    f"However, I successfully retrieved matching threat intelligence records from the local VulnSentinel CVE database.\n\n"
                    f"Here is the retrieved evidence and advisory details from our local knowledge base:\n\n"
                    f"{fallback_text}\n\n"
                    f"*(Raw error details: `{error_msg}`)*"
                ),
                "is_fallback": True,
                "chunks": cve_chunks
            }
        else:
            return {
                "mode": "FALLBACK",
                "blocked": False,
                "response": (
                    f"### 🤖 VulnSentinel Assistant (Offline Fallback Mode)\n\n"
                    f"Hello! I am your AI Security Assistant. I'm currently running in **offline fallback mode** "
                    f"due to a **{cause}**.\n\n"
                    f"**What you can do right now:**\n"
                    f"* **Database Lookup:** You can still query our local CVE database! Just ask about a vulnerability, CVE ID, or product (e.g., *'Log4j'*, *'CVE-2021-44228'*, or *'Heartbleed'*).\n"
                    f"* **Review evidence:** When you query a vulnerability, I will fetch matching records from our local knowledge base and format them for you below.\n\n"
                    f"*(Raw error details: `{error_msg}`)*"
                ),
                "is_fallback": True,
                "chunks": []
            }


if __name__ == "__main__":
    print("VulnSentinel RAG Engine — Test Run")
    result = run_rag_pipeline("Apache Log4j remote code execution 2021")

    if result.get("blocked"):
        print(f"BLOCKED: {result['block_reason']}")
    elif result.get("is_fallback"):
        print("FALLBACK MODE:")
        print(result["raw_response"])
    else:
        print(f"Mode: {result['mode']}")
        print(f"Chunks used: {result.get('chunks_used', 0)}")
        print(result.get("response", "")[:500])
