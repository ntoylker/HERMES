"""Query decomposition: split a multi-intent user query into standalone semantic parts.

The LLM proposes a split; this module deterministically validates, caps, and
deduplicates the result, and fails open to the original query on any error.
Called in-process from generate_offense_rag.py (not via subprocess) since it is
a preprocessing step within Stage 1, not an independent pipeline stage.
See docs/GENERATE_OFFENSE_RAG_INTERNALS.md for the full Stage 1 flow.
"""

import argparse
import json
import os

from dotenv import load_dotenv
load_dotenv()

import numpy as np
import requests

from hosted_embeddings import create_embedding_client, load_embedding_config

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEN_MODEL = "gemini-2.5-pro"
DEFAULT_MAX_SUBQUERIES = 4
DEFAULT_MIN_CHARS = 6
DEFAULT_DEDUPE_THRESHOLD = 0.92
# Decomposition is a mechanical splitting task: lower temperature than technique-linking generation.
DECOMPOSE_TEMPERATURE = 0.1
DECOMPOSE_MAX_OUTPUT_TOKENS = 600


class GenerationEmptyTextError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        finish_reason: str | None = None,
        prompt_feedback: dict | None = None,
        safety_ratings: list | None = None,
    ) -> None:
        super().__init__(message)
        self.finish_reason = finish_reason
        self.prompt_feedback = prompt_feedback
        self.safety_ratings = safety_ratings


def _env(name: str) -> str | None:
    value = os.getenv(name)
    return value if value and value.strip() else None


def _strip_json_fences(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _try_parse_json(text: str) -> dict | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _parse_json_response(text: str) -> dict | None:
    parsed = _try_parse_json(text)
    if parsed is not None:
        return parsed

    unfenced = _strip_json_fences(text)
    parsed = _try_parse_json(unfenced)
    if parsed is not None:
        return parsed

    start = unfenced.find("{")
    end = unfenced.rfind("}")
    if start != -1 and end != -1 and end > start:
        parsed = _try_parse_json(unfenced[start : end + 1])
        if parsed is not None:
            return parsed

    return None


def _extract_debug_fields(response_json: dict) -> dict:
    candidates = response_json.get("candidates") or []
    candidate = candidates[0] if candidates else {}
    return {
        "finish_reason": candidate.get("finishReason"),
        "prompt_feedback": response_json.get("promptFeedback"),
        "safety_ratings": candidate.get("safetyRatings"),
    }


def _extract_text(response_json: dict) -> str:
    candidates = response_json.get("candidates") or []
    if not candidates:
        raise GenerationEmptyTextError("Generation returned no candidates", **_extract_debug_fields(response_json))
    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []
    texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
    text = "".join(texts).strip()
    if not text:
        raise GenerationEmptyTextError("Generation returned empty text", **_extract_debug_fields(response_json))
    return text


def _resolve_thinking_budget(model: str, requested: int | None) -> int | None:
    if requested is None:
        return None
    if requested > 0:
        return requested
    if "gemini-2.5" in model.lower():
        return 256
    return None


def _call_gemini_raw(
    *,
    prompt: str,
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    max_output_tokens: int,
    thinking_budget: int | None,
) -> dict:
    url = f"{base_url.rstrip('/')}/models/{model}:generateContent?key={api_key}"
    generation_config: dict = {
        "temperature": float(temperature),
        "maxOutputTokens": int(max_output_tokens),
        "responseMimeType": "application/json",
    }
    if thinking_budget is not None:
        generation_config["thinkingConfig"] = {"thinkingBudget": int(thinking_budget)}

    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": generation_config,
    }

    resp = requests.post(url, json=payload, timeout=60)
    if resp.status_code != 200:
        raise RuntimeError(f"Decomposition request failed ({resp.status_code}): {resp.text[:500]}")
    return resp.json()


def _build_decompose_prompt(query: str, max_subqueries: int) -> str:
    return (
        "You are a query analysis assistant for a cybersecurity ATT&CK retrieval system. Decide whether "
        "the user's query describes more than one DISTINCT attacker behavior, each mapping to a different "
        "MITRE ATT&CK technique family, and split it only if so.\n\n"
        "Rules:\n"
        "- Split only when the query genuinely mixes multiple distinct tactical behaviors "
        "(e.g. \"keylog credentials AND exfiltrate them over DNS\" = 2 behaviors).\n"
        "- Do NOT split a query describing one behavior with multiple steps that serve the same technique "
        "(e.g. \"compress and encrypt files with 7-zip before exfiltration\" is one archive-then-exfil technique).\n"
        "- If unsure, do NOT split.\n"
        f"- Produce at most {max_subqueries} parts.\n"
        "- Each part must be standalone and reuse the user's original wording - do not paraphrase or add new details.\n"
        "- Output ONLY valid JSON (no markdown, no commentary) with this exact shape:\n"
        "{\n"
        "  \"decomposition_needed\": <boolean>,\n"
        "  \"sub_queries\": [<string>, ...]\n"
        "}\n"
        "- If decomposition_needed is false, sub_queries must contain exactly one string equal to the "
        "original query unchanged.\n\n"
        f"User query:\n{query}\n"
    )


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0.0:
        return 0.0
    return float(np.dot(a, b) / denom)


def _validate_subqueries(
    parsed: dict, *, original_query: str, max_subqueries: int, min_chars: int
) -> tuple[list[str], list[str]]:
    # Fail open to a trivial single part on any structural problem; never raises.
    warnings: list[str] = []
    raw = parsed.get("sub_queries")
    if not isinstance(raw, list) or not raw:
        return [original_query], ["missing_or_empty_sub_queries"]

    cleaned: list[str] = []
    for i, entry in enumerate(raw, start=1):
        if not isinstance(entry, str):
            warnings.append(f"entry_{i}_not_string")
            continue
        text = entry.strip()
        if len(text) < min_chars or len(text.split()) < 2:
            warnings.append(f"entry_{i}_too_short")
            continue
        cleaned.append(text)

    if len(cleaned) > max_subqueries:
        warnings.append(f"truncated_from_{len(cleaned)}_to_{max_subqueries}")
        cleaned = cleaned[:max_subqueries]

    if not cleaned:
        return [original_query], warnings + ["no_valid_subqueries_after_guardrails"]

    if len(cleaned) == 1:
        # Single surviving part: guarantee verbatim fidelity to the user's original text.
        return [original_query], warnings

    return cleaned, warnings


def _dedupe_near_duplicates(texts: list[str], *, embed_client, threshold: float) -> tuple[list[str], list[str]]:
    if len(texts) < 2:
        return texts, []

    try:
        embeddings = embed_client.embed_texts(texts)
        vectors = [np.asarray(e, dtype=np.float32) for e in embeddings]
    except Exception as exc:  # noqa: BLE001 - dedup is a best-effort optimization, never fatal
        return texts, [f"dedupe_skipped_embedding_error: {exc}"]

    warnings: list[str] = []
    kept: list[str] = []
    kept_vectors: list[np.ndarray] = []
    for text, vec in zip(texts, vectors):
        is_dup = False
        for other_vec in kept_vectors:
            if _cosine_similarity(vec, other_vec) >= threshold:
                warnings.append(f"near_duplicate_collapsed: {text!r}")
                is_dup = True
                break
        if not is_dup:
            kept.append(text)
            kept_vectors.append(vec)

    return kept, warnings


def decompose_query(
    query: str,
    *,
    api_key: str,
    base_url: str,
    model: str,
    max_subqueries: int = DEFAULT_MAX_SUBQUERIES,
    min_chars: int = DEFAULT_MIN_CHARS,
    dedupe_threshold: float = DEFAULT_DEDUPE_THRESHOLD,
    embed_provider: str | None = None,
    embed_model: str | None = None,
    thinking_budget: int | None = 0,
) -> dict:
    """Split `query` into standalone semantic parts, or fail open to a single part.

    Returns {"decomposed": bool, "sub_queries": [{"id": "Q1", "text": ...}, ...], "guardrails": {...}}.
    """
    report: dict = {"warnings": [], "raw_decomposition_needed": None, "fallback_used": False, "fallback_reason": None}

    try:
        prompt = _build_decompose_prompt(query, max_subqueries)
        resolved_budget = _resolve_thinking_budget(model, thinking_budget)
        response_json = _call_gemini_raw(
            prompt=prompt,
            api_key=api_key,
            base_url=base_url,
            model=model,
            temperature=DECOMPOSE_TEMPERATURE,
            max_output_tokens=DECOMPOSE_MAX_OUTPUT_TOKENS,
            thinking_budget=resolved_budget,
        )
        text = _extract_text(response_json)
        parsed = _parse_json_response(text)
        if parsed is None:
            raise RuntimeError("Decomposition model did not return valid JSON")
    except Exception as exc:  # noqa: BLE001 - any decomposition failure falls back to the original query
        report["fallback_used"] = True
        report["fallback_reason"] = str(exc)
        return {"decomposed": False, "sub_queries": [{"id": "Q1", "text": query}], "guardrails": report}

    report["raw_decomposition_needed"] = bool(parsed.get("decomposition_needed"))
    texts, warnings = _validate_subqueries(
        parsed, original_query=query, max_subqueries=max_subqueries, min_chars=min_chars
    )
    report["warnings"].extend(warnings)

    if len(texts) > 1:
        try:
            embed_cfg = load_embedding_config(provider=embed_provider, model=embed_model)
            embed_client = create_embedding_client(embed_cfg)
            texts, dedupe_warnings = _dedupe_near_duplicates(texts, embed_client=embed_client, threshold=dedupe_threshold)
            report["warnings"].extend(dedupe_warnings)
        except Exception as exc:  # noqa: BLE001 - dedup is best-effort, never fatal
            report["warnings"].append(f"dedupe_skipped: {exc}")
        if len(texts) == 1:
            texts = [query]

    sub_queries = [{"id": f"Q{i}", "text": t} for i, t in enumerate(texts, start=1)]
    return {"decomposed": len(sub_queries) > 1, "sub_queries": sub_queries, "guardrails": report}


def main() -> None:
    parser = argparse.ArgumentParser(description="Split a query into standalone semantic parts (or pass it through unchanged)")
    parser.add_argument("query", help="User query")
    parser.add_argument("--gen-model", default=None, help="Gemini model for decomposition")
    parser.add_argument("--max-subqueries", type=int, default=DEFAULT_MAX_SUBQUERIES, help="Max parts allowed")
    parser.add_argument(
        "--dedupe-threshold",
        type=float,
        default=DEFAULT_DEDUPE_THRESHOLD,
        help="Cosine similarity threshold for collapsing near-duplicate parts",
    )
    parser.add_argument("--provider", default=None, help="Override embedding provider (used for dedup)")
    parser.add_argument("--model", default=None, help="Override embedding model (used for dedup)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    api_key = _env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing GOOGLE_API_KEY (or GEMINI_API_KEY)")
    base_url = _env("GEMINI_BASE_URL") or DEFAULT_BASE_URL
    gen_model = args.gen_model or _env("GEMINI_GEN_MODEL") or DEFAULT_GEN_MODEL

    result = decompose_query(
        str(args.query),
        api_key=api_key,
        base_url=base_url,
        model=gen_model,
        max_subqueries=int(args.max_subqueries),
        dedupe_threshold=float(args.dedupe_threshold),
        embed_provider=args.provider,
        embed_model=args.model,
    )

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"decomposed={result['decomposed']}")
    for sq in result["sub_queries"]:
        print(f"  {sq['id']}: {sq['text']}")
    if result["guardrails"].get("warnings"):
        print(f"warnings: {result['guardrails']['warnings']}")
    if result["guardrails"].get("fallback_used"):
        print(f"fallback_reason: {result['guardrails']['fallback_reason']}")


if __name__ == "__main__":
    main()
