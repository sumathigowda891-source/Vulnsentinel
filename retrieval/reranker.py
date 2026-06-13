import os
import time
import logging
import threading
from pathlib import Path
from typing import Optional
from flashrank import Ranker, RerankRequest

# Configure logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "reranker.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("NVDReRanker")

# Load reranker once at module level (avoid reloading on each call)
_ranker: Optional[Ranker] = None
_ranker_lock = threading.Lock()
FLASHRANK_CACHE_DIR = os.getenv("FLASHRANK_CACHE_DIR", "./data/flashrank_cache")


def get_ranker() -> Ranker:
    """Get or initialize the FlashRank reranker singleton thread-safely."""
    global _ranker
    if _ranker is None:
        with _ranker_lock:
            if _ranker is None:
                start_time = time.perf_counter()
                logger.info("Loading FlashRank reranker model 'ms-marco-MiniLM-L-12-v2' (cached at: %s)...", FLASHRANK_CACHE_DIR)
                # Ensure cache directory exists
                Path(FLASHRANK_CACHE_DIR).mkdir(parents=True, exist_ok=True)
                
                # Instantiate model
                _ranker = Ranker(model_name="ms-marco-MiniLM-L-12-v2", cache_dir=FLASHRANK_CACHE_DIR)
                
                duration = time.perf_counter() - start_time
                logger.info("FlashRank model successfully loaded in %.4f seconds.", duration)
            else:
                logger.debug("FlashRank reranker already initialized concurrently.")
    else:
        logger.debug("Reusing existing FlashRank reranker instance.")
    return _ranker


def preload_ranker() -> None:
    """Preload the reranker model into memory during startup."""
    logger.info("Triggering FlashRank reranker startup preloading...")
    get_ranker()


def rerank_results(
    query: str,
    candidates: list[dict],
    top_k: int = 5,
) -> list[dict]:
    """
    Rerank vector search candidates using FlashRank cross-encoder.
    Filters noisy/irrelevant chunks before they reach the LLM.

    Args:
        query: Original user query
        candidates: List of dicts from vector_search (must have 'document' key)
        top_k: Final number of results after reranking

    Returns:
        Top-K reranked results with added 'rerank_score' field
    """
    if not candidates:
        return []

    ranker = get_ranker()

    # Build passages for FlashRank
    passages = [
        {"id": i, "text": c["document"], "meta": c}
        for i, c in enumerate(candidates)
    ]

    start_time = time.perf_counter()
    rerank_request = RerankRequest(query=query, passages=passages)
    reranked = ranker.rerank(rerank_request)
    duration = (time.perf_counter() - start_time) * 1000

    # Reconstruct output with rerank scores
    output = []
    for item in reranked[:top_k]:
        original = item["meta"]
        original["rerank_score"] = round(float(item["score"]), 4)
        output.append(original)

    # Sort by rerank score descending
    output.sort(key=lambda x: x.get("rerank_score", 0), reverse=True)
    logger.info(
        "event=rerank | query='%s' | input_chunks=%d | output_chunks=%d | latency_ms=%.2f",
        query, len(passages), len(output), duration
    )
    return output


def retrieve_and_rerank(
    query: str,
    top_k_vector: int = 20,
    top_k_final: int = 5,
    severity_filter: str | None = None,
    year_filter: str | None = None,
) -> list[dict]:
    """
    Full retrieval pipeline:
    1. Fast vector search (recall) → top_k_vector candidates
    2. Cross-encoder rerank (precision) → top_k_final results

    This is the core retrieval pipeline per assignment requirements.
    """
    from retrieval.vector_search import vector_search

    # Step 1: Vector search
    candidates = vector_search(
        query=query,
        top_k=top_k_vector,
        severity_filter=severity_filter,
        year_filter=year_filter,
    )

    if not candidates:
        return []

    # Step 2: Rerank
    final = rerank_results(query=query, candidates=candidates, top_k=top_k_final)
    return final


if __name__ == "__main__":
    results = retrieve_and_rerank(
        "Apache Log4j remote code execution vulnerability",
        top_k_vector=20,
        top_k_final=5,
    )
    print(f"Top {len(results)} reranked results:")
    for r in results:
        print(f"  {r['cve_id']} | {r['severity']} | Rerank: {r['rerank_score']:.4f}")
