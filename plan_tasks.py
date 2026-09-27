"""Stage 2 planner: convert Stage 1 ATT&CK links into validated coding-task plans.

Acts as the System Architect for the HERMES pipeline:
1. Ingests Stage 1 output (query, phases, top techniques, alternatives).
2. Queries SQLite index (artifacts/offense_index/offense_index.sqlite) for MITRE ATT&CK procedure evidence.
3. Uses dual-backend LLM provider (local LM Studio Qwen or Gemini REST fallback).
4. Enforces deterministic validation: JSON schema, acyclic DAG, provides/consumes symbol contracts,
   vocabulary check, and TTP coverage.
5. Runs a self-repair retry loop upon validation failure.
6. Persists machine records (.jsonl) and formatted human summaries (.json).
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import requests
from dotenv import load_dotenv

from hosted_embeddings import create_embedding_client, load_embedding_config
from query_offense_index import (
    _cache_connect,
    _cache_db_path,
    _cache_get,
    _cache_init,
    _cache_put,
    _normalize,
    _normalize_query,
)

load_dotenv()

DEFAULT_LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
DEFAULT_LMSTUDIO_MODEL = "local-model"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEMINI_MODEL = "gemini-2.5-pro"
DEFAULT_TIMEOUT = 600
DEFAULT_MAX_TOKENS = 16384
DEFAULT_MAX_RETRIES = 3

# Chunk types that are always included when present (canonical technique text, not "examples").
MANDATORY_CHUNK_TYPES = ("technique_description", "technique_overview")
# Global ceiling on procedure-example chunks across the whole evidence block, so a query that
# resolves to many well-documented techniques can't blow the LM Studio context window on evidence
# alone (Stage 2 runs against the same fixed-context local model as Stage 3).
GLOBAL_MAX_EXAMPLE_CHUNKS = 24


def _example_slot_budget(example_count: int) -> int:
    """Chunk-count-scaled cap: well-documented techniques get more example slots than sparse ones."""
    if example_count <= 2:
        return example_count
    if example_count <= 10:
        return 3
    if example_count <= 50:
        return 5
    return 8


def _timestamped_stem() -> str:
    return datetime.now().strftime("%Y%m%d_%H_%M_%S")


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
        val = json.loads(text)
        return val if isinstance(val, dict) else None
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


class ContextBuilder:
    """Builds prompt context from Stage 1 artifacts, SQLite evidence, and configuration."""

    def __init__(
        self,
        stage1_path: Path,
        db_path: Path = Path("artifacts/offense_index/offense_index.sqlite"),
        constraints_path: Path = Path("data/config/stage2_constraints.json"),
    ) -> None:
        self.stage1_path = stage1_path
        self.db_path = db_path
        self.constraints_path = constraints_path
        self._chunk_embedding_index_loaded = False
        self._chunk_embedding_index: tuple[Any, Any, np.ndarray] | None = None
        self._query_embedding_cache: dict[str, np.ndarray] = {}

    def load_stage1_artifact(self) -> dict[str, Any]:
        if not self.stage1_path.exists():
            raise FileNotFoundError(f"Missing Stage 1 output file: {self.stage1_path}")
        data = json.loads(self.stage1_path.read_text(encoding="utf-8"))
        if not data.get("query"):
            raise ValueError(f"Stage 1 output missing 'query': {self.stage1_path}")
        return data

    def load_constraints(self) -> dict[str, Any]:
        if not self.constraints_path.exists():
            raise FileNotFoundError(f"Missing constraints file: {self.constraints_path}")
        return json.loads(self.constraints_path.read_text(encoding="utf-8"))

    def extract_stage1_elements(
        self, stage1_data: dict[str, Any]
    ) -> tuple[str, str, list[dict[str, str]], set[str], set[str], dict[str, str]]:
        query = str(stage1_data.get("query", ""))
        summary = str(stage1_data.get("summary", ""))

        sub_queries: list[dict[str, str]] = []
        decomposition = stage1_data.get("decomposition") or {}
        if isinstance(decomposition, dict) and decomposition.get("sub_queries"):
            for sq in decomposition.get("sub_queries") or []:
                if isinstance(sq, dict) and sq.get("id") and sq.get("text"):
                    sub_queries.append({"id": str(sq["id"]), "text": str(sq["text"])})
        elif isinstance(stage1_data.get("parts"), list):
            for part in stage1_data["parts"]:
                if isinstance(part, dict) and part.get("id") and part.get("text"):
                    sub_queries.append({"id": str(part["id"]), "text": str(part["text"])})

        top_tech_ids: set[str] = set()
        alt_tech_ids: set[str] = set()
        # Maps a technique to the specific sub-query/part text that surfaced it, so evidence for
        # that technique can be ranked against the phase it's actually relevant to, rather than the
        # whole (possibly multi-intent) composite query. First occurrence wins if a technique shows
        # up under more than one part, mirroring _merge_parts' own dedup convention in Stage 1.
        technique_query_map: dict[str, str] = {}

        if isinstance(stage1_data.get("top_techniques"), list):
            for t in stage1_data["top_techniques"]:
                if isinstance(t, dict) and t.get("mitre_id"):
                    top_tech_ids.add(str(t["mitre_id"]).strip())

        if isinstance(stage1_data.get("alternatives"), list):
            for t in stage1_data["alternatives"]:
                if isinstance(t, dict) and t.get("mitre_id"):
                    alt_tech_ids.add(str(t["mitre_id"]).strip())

        if isinstance(stage1_data.get("parts"), list):
            for part in stage1_data["parts"]:
                if not isinstance(part, dict):
                    continue
                part_text = str(part.get("text") or "").strip()
                for t in part.get("top_techniques") or []:
                    if isinstance(t, dict) and t.get("mitre_id"):
                        mid = str(t["mitre_id"]).strip()
                        top_tech_ids.add(mid)
                        if part_text:
                            technique_query_map.setdefault(mid, part_text)
                for t in part.get("alternatives") or []:
                    if isinstance(t, dict) and t.get("mitre_id"):
                        mid = str(t["mitre_id"]).strip()
                        alt_tech_ids.add(mid)
                        if part_text:
                            technique_query_map.setdefault(mid, part_text)

        if not top_tech_ids and isinstance(stage1_data.get("parts"), list):
            for part in stage1_data["parts"]:
                if not isinstance(part, dict):
                    continue
                part_text = str(part.get("text") or "").strip()
                for t in (part.get("retrieved_techniques") or [])[:3]:
                    if isinstance(t, dict) and t.get("mitre_id"):
                        mid = str(t["mitre_id"]).strip()
                        top_tech_ids.add(mid)
                        if part_text:
                            technique_query_map.setdefault(mid, part_text)

        return query, summary, sub_queries, top_tech_ids, alt_tech_ids, technique_query_map

    def _load_chunk_embedding_index(self) -> tuple[Any, Any, np.ndarray] | None:
        """Load the embedding client/config and the index's chunk-embedding matrix, once per run.

        Cached on the instance (not per-call) since a PlannerEngine retry loop can call
        fetch_attack_evidence several times per Stage 2 run. Returns None (never raises) if
        embeddings aren't available, so evidence selection can fall back to a deterministic order
        instead of failing Stage 2 outright.
        """
        if self._chunk_embedding_index_loaded:
            return self._chunk_embedding_index

        self._chunk_embedding_index_loaded = True
        try:
            meta_path = self.db_path.parent / "index_meta.json"
            emb_path = self.db_path.parent / "embeddings.npy"
            if not meta_path.exists() or not emb_path.exists():
                return None

            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            emb_meta = meta.get("embeddings")
            if not emb_meta:
                return None

            cfg = load_embedding_config(provider=emb_meta.get("provider"), model=emb_meta.get("model"))
            client = create_embedding_client(cfg)
            emb_matrix = np.load(str(emb_path), mmap_mode="r")
            if emb_matrix.ndim != 2:
                return None

            self._chunk_embedding_index = (cfg, client, emb_matrix)
        except Exception as e:
            print(f"[!] Relevance-ranked evidence selection unavailable, falling back to default ordering: {e}", file=sys.stderr)
            self._chunk_embedding_index = None
        return self._chunk_embedding_index

    def _embed_text_cached(self, text: str, cfg: Any, client: Any) -> np.ndarray | None:
        """Embed text via the same cache DB Stage 1 uses, memoized per-instance for repeat texts."""
        if text in self._query_embedding_cache:
            return self._query_embedding_cache[text]
        try:
            cache_conn = _cache_connect(_cache_db_path())
            _cache_init(cache_conn)
            query_norm = _normalize_query(text)
            cache_model = cfg.model or cfg.azure_deployment or "unknown"
            try:
                cached = _cache_get(cache_conn, query_norm=query_norm, provider=cfg.provider, model=cache_model)
                if cached is None:
                    q_emb = client.embed_texts([text])[0]
                    _cache_put(
                        cache_conn, query_norm=query_norm, provider=cfg.provider,
                        model=cache_model, embedding=q_emb,
                    )
                else:
                    q_emb = cached
            finally:
                cache_conn.close()
            q_vec = _normalize(np.asarray(q_emb, dtype=np.float32))
        except Exception as e:
            print(f"[!] Failed to embed text for relevance ranking: {e}", file=sys.stderr)
            return None
        self._query_embedding_cache[text] = q_vec
        return q_vec

    def fetch_attack_evidence(
        self,
        technique_ids: set[str],
        top_tech_ids: set[str],
        technique_query_map: dict[str, str],
        fallback_query_text: str,
        max_chars: int = 800,
    ) -> dict[str, list[dict[str, str]]]:
        if not self.db_path.exists():
            raise FileNotFoundError(f"Missing SQLite index: {self.db_path}")

        evidence_map: dict[str, list[dict[str, str]]] = {tid: [] for tid in technique_ids}
        if not technique_ids:
            return evidence_map

        conn = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True)
        try:
            placeholders = ",".join("?" for _ in technique_ids)
            query = f"""
                SELECT id, mitre_id, name, chunk_type, text
                FROM chunks
                WHERE mitre_id IN ({placeholders})
            """
            rows = conn.execute(query, list(technique_ids)).fetchall()
        finally:
            conn.close()

        names_by_tech: dict[str, str] = {}
        mandatory_by_tech: dict[str, dict[str, str]] = {}
        examples_by_tech: dict[str, list[tuple[int, str, str]]] = {}

        for row_id, mitre_id, name, chunk_type, text in rows:
            mid = str(mitre_id).strip()
            if mid not in evidence_map:
                continue
            names_by_tech.setdefault(mid, str(name or ""))
            if chunk_type in MANDATORY_CHUNK_TYPES:
                mandatory_by_tech.setdefault(mid, {})[chunk_type] = text or ""
            else:
                examples_by_tech.setdefault(mid, []).append((int(row_id), str(chunk_type or ""), text or ""))

        embed_index = self._load_chunk_embedding_index()

        # Rank each technique's example (procedure-usage) chunks by relevance to the specific
        # sub-query/part that surfaced this technique (not the whole composite query) - see
        # technique_query_map's docstring in extract_stage1_elements for why. Falls back to the
        # whole query only if this technique has no known originating part (e.g. single-intent
        # queries with no decomposition).
        selected_examples: list[dict[str, Any]] = []
        for mid in technique_ids:
            candidates = examples_by_tech.get(mid, [])
            if not candidates:
                continue
            budget = _example_slot_budget(len(candidates))
            if budget <= 0:
                continue

            q_vec = None
            if embed_index is not None:
                cfg, client, emb_matrix = embed_index
                relevance_text = technique_query_map.get(mid) or fallback_query_text
                q_vec = self._embed_text_cached(relevance_text, cfg, client)

            if q_vec is not None:
                scored = []
                for row_id, chunk_type, text in candidates:
                    idx = row_id - 1
                    score = float(emb_matrix[idx] @ q_vec) if 0 <= idx < emb_matrix.shape[0] else -1.0
                    scored.append((score, row_id, chunk_type, text))
                scored.sort(key=lambda c: c[0], reverse=True)
            else:
                # Fallback (no embeddings available): stable, deterministic id order.
                scored = [(0.0, rid, ct, tx) for rid, ct, tx in sorted(candidates, key=lambda c: c[0])]

            for score, _row_id, chunk_type, text in scored[:budget]:
                selected_examples.append({
                    "mitre_id": mid,
                    "is_top": mid in top_tech_ids,
                    "score": score,
                    "chunk_type": chunk_type,
                    "text": text,
                })

        # Global ceiling: trim lowest-priority examples first (alt-technique examples before
        # top-technique ones, lowest relevance score before higher) if the budget is still too big.
        if len(selected_examples) > GLOBAL_MAX_EXAMPLE_CHUNKS:
            selected_examples.sort(key=lambda e: (not e["is_top"], -e["score"]))
            selected_examples = selected_examples[:GLOBAL_MAX_EXAMPLE_CHUNKS]

        for mid in technique_ids:
            chunks: list[dict[str, str]] = []
            mand = mandatory_by_tech.get(mid, {})
            for ctype in MANDATORY_CHUNK_TYPES:
                if ctype in mand:
                    chunks.append({
                        "name": names_by_tech.get(mid, ""),
                        "chunk_type": ctype,
                        "text": mand[ctype][:max_chars].strip(),
                    })
            evidence_map[mid] = chunks

        for ex in selected_examples:
            evidence_map[ex["mitre_id"]].append({
                "name": names_by_tech.get(ex["mitre_id"], ""),
                "chunk_type": ex["chunk_type"],
                "text": ex["text"][:max_chars].strip(),
            })

        return evidence_map

    def build_prompts(
        self,
        feedback: list[str] | None = None,
        previous_plan: dict | None = None,
    ) -> tuple[str, str, set[str]]:
        stage1_data = self.load_stage1_artifact()
        constraints = self.load_constraints()
        query, summary, sub_queries, top_tech_ids, alt_tech_ids, technique_query_map = (
            self.extract_stage1_elements(stage1_data)
        )

        all_techniques = top_tech_ids | alt_tech_ids
        evidence_map = self.fetch_attack_evidence(all_techniques, top_tech_ids, technique_query_map, query)

        allowed_task_types = constraints.get("allowed_task_types", [])
        target_language = constraints.get("target_language", "python")
        min_py_version = constraints.get("min_python_version", "3.11")

        system_prompt = (
            "You are the Lead Systems Architect for the HERMES offensive security research pipeline.\n"
            "Your role in Stage 2 is to translate high-level MITRE ATT&CK techniques and attack phases into a "
            "coherent, modular, executable Directed Acyclic Graph (DAG) of technical implementation tasks.\n"
            "These tasks will be passed to Stage 3 (code generation) for automated synthesis and sandbox testing.\n"
            "You must output ONLY valid, well-formed JSON conforming strictly to the requested schema, with no "
            "conversational preamble or markdown commentary outside JSON."
        )

        user_prompt_lines = [
            "# HERMES STAGE 2: TASK PLAN SYNTHESIS",
            "",
            "## 1. RESEARCH & OPERATIONAL CONSTRAINTS",
            f"- Environment: Isolated research sandbox (academic red-teaming research).",
            f"- Target Language: {target_language} ({min_py_version}+).",
            f"- Allowed Task Types: {json.dumps(allowed_task_types)}",
            "",
            "## 2. SOURCE QUERY & ATTACK PHASES",
            f"Source Query:\n{query}",
            "",
        ]

        if sub_queries:
            user_prompt_lines.append("Attack Phases (Decomposition):")
            for sq in sub_queries:
                user_prompt_lines.append(f"  - [{sq['id']}] {sq['text']}")
            user_prompt_lines.append("")

        if summary:
            user_prompt_lines.append(f"Stage 1 Synthesis Summary:\n{summary}\n")

        user_prompt_lines.append("## 3. MITRE ATT&CK EVIDENCE & PROCEDURES")
        user_prompt_lines.append("Required Top Techniques to map into tasks:")
        for tid in sorted(top_tech_ids):
            chunks = evidence_map.get(tid, [])
            tech_name = chunks[0]["name"] if chunks else "Unknown"
            user_prompt_lines.append(f"- {tid} ({tech_name}):")
            for c in chunks:
                user_prompt_lines.append(f"    * [{c['chunk_type']}] {c['text']}")

        if alt_tech_ids:
            user_prompt_lines.append("\nAlternative / Supporting Techniques:")
            for tid in sorted(alt_tech_ids):
                chunks = evidence_map.get(tid, [])
                tech_name = chunks[0]["name"] if chunks else "Unknown"
                user_prompt_lines.append(f"- {tid} ({tech_name})")

        user_prompt_lines.extend([
            "",
            "## 4. ARCHITECTURAL CONTRACT REQUIREMENTS",
            "1. Output a modular, ordered DAG of tasks (e.g. TASK_001, TASK_002, etc.).",
            "2. Every task must declare:",
            "   - `task_id`: e.g. 'TASK_001', 'TASK_002'",
            f"   - `task_type`: MUST be one of {allowed_task_types}",
            "   - `suggested_filename`: Python filename describing the task's module (e.g. 'task_module.py')",
            "   - `description`: 1-2 sentence description of the task's responsibility.",
            "   - `technique_ids`: array of MITRE ATT&CK technique IDs in the 'Txxxx' / 'Txxxx.xxx' format used in section 3 above. ALL top techniques listed above MUST be covered across the tasks.",
            "   - `dependencies`: array of prerequisite task_ids that must run/be built before this task (e.g. ['TASK_001']). Form a strictly acyclic DAG.",
            "   - `provides`: list of exact exported class/function/variable symbol names created by this task.",
            "   - `consumes`: list of imported symbol names needed by this task. RULE: Every symbol in `consumes` MUST be provided by at least one task listed in `dependencies`.",
            "   - `implementation_details`: Concrete architecture instructions specifying standard libraries (e.g., configparser, ctypes, socket, ssl, urllib, subprocess) or mechanics.",
            "   - `rag_retrieval_hints`: 2-4 search queries for Stage 3 RAG to retrieve real Python implementation patterns.",
            "",
            "## 4b. DATA MODEL & COHESION PRINCIPLES",
            "Design tasks for semantic cohesion and proper layering, not just syntactic correctness:",
            "",
            "1. CO-LOCATE RETURN TYPES WITH FUNCTIONS:",
            "   If a function returns a custom type (dataclass, class, NamedTuple), define that type in the SAME task",
            "   as the function, not in a downstream/dependent task. The return type is part of the function's contract.",
            "   Example: execute_shell_command() returns ExecutionResult → both belong in the same task.",
            "",
            "2. INFRASTRUCTURE LAYERING PATTERN:",
            "   Organize tasks hierarchically to minimize coupling:",
            "   - LAYER 1 (Foundation): Shared data models, utility functions, no dependencies (foundational tasks)",
            "   - LAYER 2 (Domain): Tasks implementing specific functionality, depend on Layer 1 only",
            "   - LAYER 3 (Orchestration): Wires components together, depends on all others",
            "",
            "3. MINIMIZE UPWARD COUPLING:",
            "   Coupling should flow downward (domain → infrastructure), never upward (infrastructure → domain).",
            "   If a symbol is defined in task A and consumed by ONLY ONE downstream task B, strongly consider",
            "   moving that symbol into task B instead. Avoid infrastructure bloat.",
            "",
            "4. GROUP RELATED SYMBOLS:",
            "   In the 'provides' list, group semantically related items together: return types, parameter types,",
            "   configuration classes, and factories that create instances of those types should all be in the",
            "   same task as the function(s) that use them.",
            "",
            "5. SYMBOL NAMING & DISCOVERY:",
            "   Each symbol name in 'provides' should make sense in context: if you see 'ExecutionResult' in",
            "   a task's 'provides', it should be obvious what function(s) use it. Avoid orphaned types.",
            "",
            "## 5. TARGET JSON OUTPUT SCHEMA",
            "Return JSON adhering strictly to this schema. The concrete values below (filenames, symbol "
            "names, technique IDs, descriptions) are generic placeholders illustrating structure only, not "
            "content to imitate. Derive all real task content from the query, attack phases, and MITRE "
            "evidence in sections 2-3 above.",
            "```json",
            "{",
            '  "plan_id": "PLAN_<TIMESTAMP>",',
            f'  "source_query": {json.dumps(query)},',
            f'  "stage1_ref": {json.dumps(self.stage1_path.name)},',
            '  "tasks": [',
            "    {",
            '      "task_id": "TASK_001",',
            '      "task_type": "<one of the allowed_task_types listed above>",',
            '      "suggested_filename": "task_module.py",',
            '      "description": "One or two sentences describing what this task is responsible for.",',
            '      "technique_ids": ["<a technique ID from section 3 above>"],',
            '      "dependencies": [],',
            '      "provides": ["SymbolA", "SymbolB"],',
            '      "consumes": [],',
            '      "implementation_details": "Concrete architecture notes: which stdlib modules and mechanics this task uses.",',
            '      "rag_retrieval_hints": ["search query 1", "search query 2"]',
            "    },",
            "    {",
            '      "task_id": "TASK_002",',
            '      "task_type": "<one of the allowed_task_types listed above>",',
            '      "suggested_filename": "another_module.py",',
            '      "description": "One or two sentences describing what this task is responsible for.",',
            '      "technique_ids": ["<a technique ID from section 3 above>"],',
            '      "dependencies": ["TASK_001"],',
            '      "provides": ["SymbolC"],',
            '      "consumes": ["SymbolA"],',
            '      "implementation_details": "Concrete architecture notes, including how it uses SymbolA from its TASK_001 dependency.",',
            '      "rag_retrieval_hints": ["search query 1", "search query 2"]',
            "    }",
            "  ]",
            "}",
            "```",
            "Note how TASK_002 demonstrates the dependency contract: it lists TASK_001 in `dependencies` and "
            "consumes `SymbolA`, which TASK_001 declared in `provides`. `SymbolB` is provided but not "
            "consumed anywhere in this example, which is fine — a symbol only needs to be consumed if "
            "another task actually needs it.",
        ])

        if feedback:
            user_prompt_lines.extend([
                "",
                "## REPAIR FEEDBACK (PREVIOUS ATTEMPT REJECTED)",
                "Your previous plan failed validation. Correct the errors below:",
            ])
            for err in feedback:
                user_prompt_lines.append(f"- {err}")
            if previous_plan:
                user_prompt_lines.extend([
                    "",
                    "Previous invalid plan was:",
                    json.dumps(previous_plan, indent=2),
                ])

        return system_prompt, "\n".join(user_prompt_lines), top_tech_ids


class LLMProvider:
    """Dual-backend LLM client supporting local LM Studio (primary) and Gemini REST (fallback)."""

    def __init__(
        self,
        provider: str = "lmstudio",
        lmstudio_url: str = DEFAULT_LMSTUDIO_URL,
        lmstudio_model: str = DEFAULT_LMSTUDIO_MODEL,
        gemini_api_key: str | None = None,
        gemini_model: str = DEFAULT_GEMINI_MODEL,
        timeout: int = DEFAULT_TIMEOUT,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.provider = provider
        self.lmstudio_url = lmstudio_url
        self.lmstudio_model = lmstudio_model
        self.gemini_api_key = gemini_api_key or os.getenv("GEMINI_API_KEY")
        self.gemini_model = gemini_model
        self.timeout = timeout
        self.max_tokens = max_tokens

    def generate(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        if self.provider == "lmstudio":
            try:
                return self._call_lmstudio(system_prompt, user_prompt)
            except Exception as e:
                print(f"[WARN] LM Studio call failed: {e}. Falling back to Gemini...", file=sys.stderr)
                return self._call_gemini(system_prompt, user_prompt)
        elif self.provider == "gemini":
            return self._call_gemini(system_prompt, user_prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _call_lmstudio(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.lmstudio_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
        }
        resp = requests.post(self.lmstudio_url, json=payload, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"LM Studio error ({resp.status_code}): {resp.text[:400]}")

        resp_json = resp.json()
        choices = resp_json.get("choices") or []
        if not choices:
            raise RuntimeError(f"LM Studio returned no choices: {resp_json}")
        raw_text = choices[0].get("message", {}).get("content", "")
        parsed = _parse_json_response(raw_text)
        if parsed is None:
            raise ValueError(f"Failed to parse JSON from LM Studio response:\n{raw_text[:500]}")
        return parsed

    def _call_gemini(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        if not self.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable is required for Gemini fallback.")

        url = f"{DEFAULT_GEMINI_BASE_URL}/models/{self.gemini_model}:generateContent?key={self.gemini_api_key}"
        payload = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
                "maxOutputTokens": min(self.max_tokens, 8192),
            },
        }
        resp = requests.post(url, json=payload, timeout=min(self.timeout, 120))
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini API error ({resp.status_code}): {resp.text[:400]}")

        resp_json = resp.json()
        candidates = resp_json.get("candidates") or []
        if not candidates:
            raise RuntimeError(f"Gemini returned no candidates: {resp_json}")
        parts = candidates[0].get("content", {}).get("parts", [])
        raw_text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        parsed = _parse_json_response(raw_text)
        if parsed is None:
            raise ValueError(f"Failed to parse JSON from Gemini response:\n{raw_text[:500]}")
        return parsed


class PlanValidator:
    """Performs deterministic validation on generated task plans."""

    REQUIRED_TASK_KEYS = {
        "task_id",
        "task_type",
        "suggested_filename",
        "description",
        "technique_ids",
        "dependencies",
        "provides",
        "consumes",
        "implementation_details",
        "rag_retrieval_hints",
    }

    def __init__(self, allowed_task_types: list[str], top_technique_ids: set[str]) -> None:
        self.allowed_task_types = set(allowed_task_types)
        self.top_technique_ids = top_technique_ids

    def validate(self, plan: dict[str, Any]) -> tuple[bool, list[str]]:
        errors: list[str] = []

        if not isinstance(plan, dict):
            return False, ["Plan must be a JSON object."]

        raw_tasks = plan.get("tasks")
        if not isinstance(raw_tasks, list) or not raw_tasks:
            return False, ["Plan must contain a non-empty 'tasks' array."]

        task_ids: set[str] = set()
        task_map: dict[str, dict] = {}
        provided_symbols_by_task: dict[str, set[str]] = {}

        # 1. Schema Validation for each task
        for idx, task in enumerate(raw_tasks, start=1):
            if not isinstance(task, dict):
                errors.append(f"Task index {idx} is not an object.")
                continue

            tid = task.get("task_id")
            if not tid or not isinstance(tid, str):
                errors.append(f"Task index {idx} missing valid 'task_id'.")
                continue
            tid = tid.strip()
            if tid in task_ids:
                errors.append(f"Duplicate task_id detected: '{tid}'.")
            task_ids.add(tid)
            task_map[tid] = task

            missing_keys = self.REQUIRED_TASK_KEYS - set(task.keys())
            if missing_keys:
                errors.append(f"Task '{tid}' missing required keys: {sorted(missing_keys)}.")

            # Vocabulary Validation
            ttype = task.get("task_type")
            if ttype not in self.allowed_task_types:
                errors.append(f"Task '{tid}' invalid task_type '{ttype}'. Allowed: {sorted(self.allowed_task_types)}.")

            # Record provided symbols
            provides = task.get("provides")
            if isinstance(provides, list):
                provided_symbols_by_task[tid] = {str(s).strip() for s in provides if str(s).strip()}
            else:
                errors.append(f"Task '{tid}' 'provides' must be a list.")
                provided_symbols_by_task[tid] = set()

            if not isinstance(task.get("consumes"), list):
                errors.append(f"Task '{tid}' 'consumes' must be a list.")

            if not isinstance(task.get("dependencies"), list):
                errors.append(f"Task '{tid}' 'dependencies' must be a list.")

            if not isinstance(task.get("technique_ids"), list):
                errors.append(f"Task '{tid}' 'technique_ids' must be a list.")

            if not isinstance(task.get("rag_retrieval_hints"), list):
                errors.append(f"Task '{tid}' 'rag_retrieval_hints' must be a list.")

        if errors:
            return False, errors

        # 2. Acyclic DAG Verification (DFS Cycle Detection)
        adj: dict[str, list[str]] = {tid: [] for tid in task_ids}
        for tid, task in task_map.items():
            deps = task.get("dependencies") or []
            for dep in deps:
                dep_str = str(dep).strip()
                if dep_str not in task_ids:
                    errors.append(f"Task '{tid}' specifies unknown dependency '{dep_str}'.")
                elif dep_str == tid:
                    errors.append(f"Task '{tid}' has self-dependency.")
                else:
                    adj[tid].append(dep_str)

        visited: dict[str, int] = {}

        def dfs(node: str, path: list[str]) -> bool:
            visited[node] = 1
            for neighbor in adj.get(node, []):
                if visited.get(neighbor) == 1:
                    cycle = " -> ".join(path + [neighbor])
                    errors.append(f"Circular dependency detected in DAG: {cycle}.")
                    return False
                if visited.get(neighbor, 0) == 0:
                    if not dfs(neighbor, path + [neighbor]):
                        return False
            visited[node] = 2
            return True

        for tid in task_ids:
            if visited.get(tid, 0) == 0:
                dfs(tid, [tid])

        # 3. Interface Symbol Cross-Validation
        for tid, task in task_map.items():
            consumes = [str(s).strip() for s in (task.get("consumes") or []) if str(s).strip()]
            deps = [str(d).strip() for d in (task.get("dependencies") or []) if str(d).strip() in task_ids]

            available_symbols: set[str] = set()
            for dep in deps:
                available_symbols |= provided_symbols_by_task.get(dep, set())

            for symbol in consumes:
                if symbol not in available_symbols:
                    errors.append(
                        f"Task '{tid}' consumes symbol '{symbol}', but '{symbol}' is not provided by any "
                        f"declared dependency ({deps})."
                    )

        # 4. TTP Coverage Check
        covered_techniques: set[str] = set()
        for task in task_map.values():
            for mid in task.get("technique_ids") or []:
                covered_techniques.add(str(mid).strip())

        missing_ttps = self.top_technique_ids - covered_techniques
        if missing_ttps:
            errors.append(f"Plan fails TTP coverage. Missing top MITRE techniques: {sorted(missing_ttps)}.")

        return len(errors) == 0, errors


class PlannerEngine:
    """Orchestrates context extraction, LLM generation, self-repair retry loop, and persistence."""

    def __init__(
        self,
        context_builder: ContextBuilder,
        llm_provider: LLMProvider,
        max_retries: int = DEFAULT_MAX_RETRIES,
        machine_out_dir: Path = Path("data/plans/machine_outs"),
        human_out_dir: Path = Path("data/plans/human_outs"),
    ) -> None:
        self.context_builder = context_builder
        self.llm_provider = llm_provider
        self.max_retries = max_retries
        self.machine_out_dir = machine_out_dir
        self.human_out_dir = human_out_dir

    def run(self) -> dict[str, Any]:
        constraints = self.context_builder.load_constraints()
        allowed_task_types = constraints.get("allowed_task_types", [])

        feedback: list[str] | None = None
        previous_plan: dict | None = None
        stage1_stem = self.context_builder.stage1_path.stem
        stem = f"PLAN_{stage1_stem}"
        plan_id = stem

        print(f"[*] Starting Stage 2 Planner for: {self.context_builder.stage1_path}")
        print(f"[*] Primary provider: {self.llm_provider.provider}")

        for attempt in range(1, self.max_retries + 1):
            print(f"[*] Planner attempt {attempt}/{self.max_retries}...")
            system_prompt, user_prompt, top_tech_ids = self.context_builder.build_prompts(
                feedback=feedback, previous_plan=previous_plan
            )

            validator = PlanValidator(allowed_task_types, top_tech_ids)

            try:
                draft_plan = self.llm_provider.generate(system_prompt, user_prompt)
            except Exception as e:
                print(f"[!] Generation error on attempt {attempt}: {e}", file=sys.stderr)
                if attempt == self.max_retries:
                    self.persist(previous_plan or {}, stem, status="invalid", errors=[f"Generation failed with error: {e}"])
                    raise
                feedback = [f"Generation failed with error: {e}. Please return valid JSON."]
                continue

            if isinstance(draft_plan, dict):
                draft_plan["plan_id"] = plan_id
                draft_plan["stage1_ref"] = self.context_builder.stage1_path.name

            valid, errors = validator.validate(draft_plan)
            if valid:
                print(f"[+] Task plan validated successfully on attempt {attempt}!")
                self.persist(draft_plan, stem, status="valid")
                return draft_plan
            else:
                print(f"[-] Validation failed on attempt {attempt}: {errors}")
                feedback = errors
                previous_plan = draft_plan

        self.persist(previous_plan or {}, stem, status="invalid", errors=feedback)
        raise RuntimeError(f"Planner failed to produce a valid plan after {self.max_retries} attempts: {feedback}")

    def persist(
        self,
        plan: dict[str, Any],
        stem: str,
        status: str = "valid",
        errors: list[str] | None = None,
    ) -> None:
        self.machine_out_dir.mkdir(parents=True, exist_ok=True)
        self.human_out_dir.mkdir(parents=True, exist_ok=True)

        machine_record = {
            "plan_id": plan.get("plan_id", f"PLAN_{stem}"),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "stage1_ref": self.context_builder.stage1_path.name,
            "source_query": plan.get("source_query", ""),
            "tasks": plan.get("tasks", []),
            "errors": errors or [],
        }

        machine_file = self.machine_out_dir / f"{stem}.jsonl"
        with machine_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(machine_record, ensure_ascii=False) + "\n")
        print(f"[+] Saved machine record to {machine_file}")

        if status == "valid":
            human_file = self.human_out_dir / f"{stem}.json"
            human_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(f"[+] Saved human summary to {human_file}")


def _find_latest_stage1_file() -> Path:
    human_outs = Path("data/human_outs")
    if human_outs.exists():
        candidates = sorted(human_outs.glob("*.json"))
        if candidates:
            return candidates[-1]

    machine_outs = Path("data/machine_outs")
    if machine_outs.exists():
        candidates = sorted(machine_outs.glob("*.jsonl"))
        if candidates:
            return candidates[-1]

    raise FileNotFoundError("No Stage 1 output files found in data/human_outs/ or data/machine_outs/.")


def main() -> None:
    parser = argparse.ArgumentParser(description="HERMES Stage 2 Planner: Decompose ATT&CK into modular task plans.")
    parser.add_argument(
        "--stage1-input",
        type=Path,
        default=None,
        help="Path to Stage 1 JSON file (defaults to latest in data/human_outs/).",
    )
    parser.add_argument(
        "--provider",
        choices=["lmstudio", "gemini"],
        default="lmstudio",
        help="LLM provider: lmstudio (default) or gemini.",
    )
    parser.add_argument(
        "--lmstudio-url",
        type=str,
        default=DEFAULT_LMSTUDIO_URL,
        help=f"LM Studio API URL (default: {DEFAULT_LMSTUDIO_URL}).",
    )
    parser.add_argument(
        "--lmstudio-model",
        type=str,
        default=DEFAULT_LMSTUDIO_MODEL,
        help=f"LM Studio model name (default: {DEFAULT_LMSTUDIO_MODEL}).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Maximum output tokens (default: {DEFAULT_MAX_TOKENS}).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=DEFAULT_MAX_RETRIES,
        help=f"Max self-repair attempts (default: {DEFAULT_MAX_RETRIES}).",
    )

    args = parser.parse_args()

    stage1_file = args.stage1_input
    if stage1_file is None:
        stage1_file = _find_latest_stage1_file()
        print(f"[*] Auto-selected latest Stage 1 input: {stage1_file}")

    context_builder = ContextBuilder(stage1_path=stage1_file)
    llm_provider = LLMProvider(
        provider=args.provider,
        lmstudio_url=args.lmstudio_url,
        lmstudio_model=args.lmstudio_model,
        timeout=args.timeout,
        max_tokens=args.max_tokens,
    )

    engine = PlannerEngine(
        context_builder=context_builder,
        llm_provider=llm_provider,
        max_retries=args.max_retries,
    )

    engine.run()


if __name__ == "__main__":
    main()

