import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import requests

from dotenv import load_dotenv
load_dotenv()

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_GEN_MODEL = "gemini-2.5-pro"


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


def _timestamped_stem() -> str:
    return datetime.now().strftime("%Y%m%d_%H_%M_%S")


def _write_jsonl_record(path: Path, payload: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _write_pretty_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
        debug = _extract_debug_fields(response_json)
        raise GenerationEmptyTextError("Generation returned no candidates", **debug)
    content = candidates[0].get("content") or {}
    parts = content.get("parts") or []
    texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
    text = "".join(texts).strip()
    if not text:
        debug = _extract_debug_fields(response_json)
        raise GenerationEmptyTextError("Generation returned empty text", **debug)
    return text


def _resolve_thinking_budget(model: str, requested: int | None) -> int | None:
    if requested is None:
        return None
    if requested > 0:
        return requested
    model_l = model.lower()
    if "gemini-2.5" in model_l:
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

    resp = requests.post(url, json=payload, timeout=90)
    if resp.status_code != 200:
        raise RuntimeError(f"Generation request failed ({resp.status_code}): {resp.text[:500]}")
    return resp.json()


def _load_stage1_output(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"Missing Stage 1 output file: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not data.get("query"):
        raise RuntimeError(f"Stage 1 output missing 'query': {path}")
    return data


def _load_constraints(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"Missing constraints file: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _fetch_attack_evidence(db_path: Path, mitre_id: str, limit: int, max_chars: int = 1000) -> list[dict]:
    if not db_path.exists():
        raise RuntimeError(f"Missing index database: {db_path}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            """
            SELECT chunk_id, chunk_type, text FROM chunks
            WHERE mitre_id = ?
            ORDER BY CASE chunk_type
                WHEN 'technique_description' THEN 0
                WHEN 'technique_overview' THEN 1
                ELSE 2 END, id ASC
            LIMIT ?
            """,
            (mitre_id, limit),
        ).fetchall()
    finally:
        conn.close()

    return [
        {"chunk_id": chunk_id, "chunk_type": chunk_type, "text": (text or "")[:max_chars]}
        for chunk_id, chunk_type, text in rows
    ]


def _load_pattern_library(path: Path) -> list[dict]:
    if not path.exists():
        return []
    patterns: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            patterns.append(json.loads(line))
    return patterns


def _retrieve_patterns(patterns: list[dict], mitre_id: str, limit: int) -> list[dict]:
    matches = [p for p in patterns if mitre_id in (p.get("techniques") or [])]
    return matches[:limit]


def _build_technique_context(
    *,
    mitre_id: str,
    name: str,
    rationale: str,
    index_dir: Path,
    patterns: list[dict],
    evidence_per_technique: int,
    patterns_per_technique: int,
) -> dict:
    evidence = _fetch_attack_evidence(index_dir / "offense_index.sqlite", mitre_id, evidence_per_technique)
    matched_patterns = _retrieve_patterns(patterns, mitre_id, patterns_per_technique)
    return {
        "mitre_id": mitre_id,
        "name": name,
        "rationale": rationale,
        "evidence": evidence,
        "patterns": [
            {
                "pattern_id": p["pattern_id"],
                "title": p.get("title"),
                "intent": p.get("intent"),
                "pattern_type": p.get("pattern_type"),
                "language": p.get("language"),
                "inputs": p.get("inputs"),
                "outputs": p.get("outputs"),
                "constraints": p.get("constraints"),
                "code_excerpt": p.get("code_excerpt"),
            }
            for p in matched_patterns
        ],
    }


def _build_planning_context(
    *,
    stage1: dict,
    index_dir: Path,
    patterns: list[dict],
    constraints: dict,
    request_id: str,
    include_alternatives: bool,
    evidence_per_technique: int,
    patterns_per_technique: int,
) -> dict:
    primary = [
        _build_technique_context(
            mitre_id=t["mitre_id"],
            name=t.get("name") or "Unknown",
            rationale=t.get("rationale") or "",
            index_dir=index_dir,
            patterns=patterns,
            evidence_per_technique=evidence_per_technique,
            patterns_per_technique=patterns_per_technique,
        )
        for t in (stage1.get("top_techniques") or [])
        if t.get("mitre_id")
    ]

    alternatives: list[dict] = []
    if include_alternatives:
        primary_ids = {t["mitre_id"] for t in primary}
        alternatives = [
            _build_technique_context(
                mitre_id=t["mitre_id"],
                name=t.get("name") or "Unknown",
                rationale=t.get("rationale") or "",
                index_dir=index_dir,
                patterns=patterns,
                evidence_per_technique=evidence_per_technique,
                patterns_per_technique=patterns_per_technique,
            )
            for t in (stage1.get("alternatives") or [])
            if t.get("mitre_id") and t["mitre_id"] not in primary_ids
        ]

    return {
        "schema_version": "1.0",
        "request_id": request_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {"stage": "stage_1", "query": stage1.get("query")},
        "techniques": {"primary": primary, "alternatives": alternatives},
        "planning_constraints": constraints,
    }


def _build_prompt(context: dict, repair_notes: list[str] | None) -> str:
    allowed_task_types = context["planning_constraints"].get("allowed_task_types", [])
    allowed_languages = context["planning_constraints"].get("allowed_languages", [])

    lines = [
        "You are a technical task planner supporting an academic, defensive security-research pipeline.",
        "The system runs entirely inside an isolated sandbox with no external network access and no real "
        "target systems. You do not write code and you do not provide operational attack instructions.",
        "",
        "Decompose the given MITRE ATT&CK techniques into implementation-neutral coding tasks that a later "
        "coding agent will implement as benign simulations, interfaces, telemetry, or tests.",
        "",
        "Rules:",
        "- Use ONLY the techniques, evidence, and patterns provided below.",
        "- Every task must include maps_to_techniques using only the technique IDs provided.",
        "- Every primary technique must be covered by at least one task.",
        "- task_type must be one of: " + ", ".join(allowed_task_types),
        "- language must be one of: " + ", ".join(allowed_languages),
        "- Assign each task a short local_id (e.g. t1, t2) and reference dependencies via depends_on using "
        "only those local_ids.",
        "- Cite evidence_refs.attack_chunks (chunk_id strings) and evidence_refs.patterns (pattern_id strings) "
        "ONLY from the values provided below. Do not invent IDs.",
        "- Do not include real exploit code, credentials, or live network/C2 behavior in any field.",
        "- Output ONLY valid JSON of the shape: "
        '{"tasks": [{"local_id": <string>, "title": <string>, "task_type": <string>, "purpose": <string>, '
        '"maps_to_techniques": [<string>...], "depends_on": [<local_id>...], "inputs": [...], "outputs": [...], '
        '"language": <string>, "constraints": [<string>...], "acceptance_criteria": [<string>...], '
        '"evidence_refs": {"attack_chunks": [<string>...], "patterns": [<string>...]}}]}',
        "",
        f"User query:\n{context['source']['query']}",
        "",
        "Primary techniques:",
        json.dumps(context["techniques"]["primary"], ensure_ascii=False, indent=2),
    ]

    if context["techniques"]["alternatives"]:
        lines += [
            "",
            "Alternative techniques (optional context only):",
            json.dumps(context["techniques"]["alternatives"], ensure_ascii=False, indent=2),
        ]

    if repair_notes:
        lines += [
            "",
            "The previous attempt was rejected for these reasons. Fix them:",
            json.dumps(repair_notes, ensure_ascii=False, indent=2),
        ]

    return "\n".join(lines)


def _topo_order(local_ids: list[str], edges: dict[str, list[str]]) -> tuple[list[str] | None, bool]:
    visited: dict[str, int] = {}
    order: list[str] = []

    def visit(node: str) -> bool:
        state = visited.get(node)
        if state == 1:
            return False
        if state == 2:
            return True
        visited[node] = 1
        for dep in edges.get(node, []):
            if not visit(dep):
                return False
        visited[node] = 2
        order.append(node)
        return True

    for lid in local_ids:
        if visited.get(lid) != 2:
            if not visit(lid):
                return None, True
    return order, False


def _validate_and_normalize(draft: dict, context: dict) -> tuple[dict | None, bool, list[str], list[str]]:
    constraints = context["planning_constraints"]
    allowed_task_types = set(constraints.get("allowed_task_types") or [])
    allowed_languages = set(constraints.get("allowed_languages") or [])
    forbidden_keywords = [k.lower() for k in constraints.get("forbidden_capability_keywords") or []]

    known_ids = {t["mitre_id"] for t in context["techniques"]["primary"]}
    known_ids |= {t["mitre_id"] for t in context["techniques"]["alternatives"]}

    evidence_by_tech: dict[str, list[dict]] = {}
    pattern_by_tech: dict[str, list[dict]] = {}
    valid_chunk_ids: set[str] = set()
    valid_pattern_ids: set[str] = set()
    for group in ("primary", "alternatives"):
        for t in context["techniques"][group]:
            evidence_by_tech[t["mitre_id"]] = t["evidence"]
            pattern_by_tech[t["mitre_id"]] = t["patterns"]
            valid_chunk_ids |= {e["chunk_id"] for e in t["evidence"]}
            valid_pattern_ids |= {p["pattern_id"] for p in t["patterns"]}

    raw_tasks = draft.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        return None, False, ["no_tasks_returned"], []

    blocking: list[str] = []
    advisories: list[str] = []
    local_ids: list[str] = []
    by_local: dict[str, dict] = {}

    for idx, t in enumerate(raw_tasks, start=1):
        if not isinstance(t, dict):
            blocking.append(f"task_{idx}_not_object")
            continue
        local_id = str(t.get("local_id") or f"t{idx}")
        if local_id in by_local:
            local_id = f"{local_id}_{idx}"
        local_ids.append(local_id)
        by_local[local_id] = t

    edges: dict[str, list[str]] = {}
    for local_id, t in by_local.items():
        if not t.get("title") or not isinstance(t.get("title"), str):
            blocking.append(f"{local_id}: missing_title")
        if t.get("task_type") not in allowed_task_types:
            blocking.append(f"{local_id}: invalid_task_type={t.get('task_type')}")

        maps_to = t.get("maps_to_techniques") or []
        if not isinstance(maps_to, list) or not maps_to:
            blocking.append(f"{local_id}: missing_maps_to_techniques")
        else:
            for mid in maps_to:
                if mid not in known_ids:
                    blocking.append(f"{local_id}: unknown_technique_reference={mid}")

        language = t.get("language")
        if language and allowed_languages and language not in allowed_languages:
            blocking.append(f"{local_id}: disallowed_language={language}")

        dep_list: list[str] = []
        for dep in (t.get("depends_on") or []):
            dep = str(dep)
            if dep == local_id:
                blocking.append(f"{local_id}: self_dependency")
                continue
            if dep not in by_local:
                blocking.append(f"{local_id}: unknown_dependency_reference={dep}")
                continue
            dep_list.append(dep)
        edges[local_id] = dep_list

        haystack = " ".join(
            [
                str(t.get("title", "")),
                str(t.get("purpose", "")),
                " ".join(str(c) for c in (t.get("constraints") or [])),
            ]
        ).lower()
        for kw in forbidden_keywords:
            if kw in haystack:
                advisories.append(f"{local_id}: possible_forbidden_capability_keyword={kw}")

    if blocking:
        return None, False, blocking, advisories

    order, has_cycle = _topo_order(local_ids, edges)
    if has_cycle or order is None:
        return None, False, ["dependency_cycle"], advisories

    canonical_map = {lid: f"TASK-{i:03d}" for i, lid in enumerate(order, start=1)}
    tasks_out = []
    coverage: dict[str, list[str]] = {}

    for lid in order:
        t = by_local[lid]
        canon = canonical_map[lid]
        maps_to = t.get("maps_to_techniques") or []
        for mid in maps_to:
            coverage.setdefault(mid, []).append(canon)

        given_refs = t.get("evidence_refs") or {}
        chunk_refs = [c for c in (given_refs.get("attack_chunks") or []) if c in valid_chunk_ids]
        pattern_refs = [p for p in (given_refs.get("patterns") or []) if p in valid_pattern_ids]
        if not chunk_refs and not pattern_refs and maps_to:
            primary_mid = maps_to[0]
            chunk_refs = [e["chunk_id"] for e in evidence_by_tech.get(primary_mid, [])[:1]]
            pattern_refs = [p["pattern_id"] for p in pattern_by_tech.get(primary_mid, [])[:1]]
            advisories.append(f"{canon}: auto_filled_evidence")

        tasks_out.append(
            {
                "task_id": canon,
                "title": t.get("title"),
                "task_type": t.get("task_type"),
                "purpose": t.get("purpose") or "",
                "maps_to_techniques": maps_to,
                "evidence_refs": {"attack_chunks": chunk_refs, "patterns": pattern_refs},
                "depends_on": [canonical_map[d] for d in edges.get(lid, [])],
                "inputs": t.get("inputs") or [],
                "outputs": t.get("outputs") or [],
                "language": t.get("language") or (sorted(allowed_languages)[0] if allowed_languages else None),
                "constraints": t.get("constraints") or [],
                "acceptance_criteria": t.get("acceptance_criteria") or [],
            }
        )

    coverage_out = []
    uncovered = []
    for mid in [t["mitre_id"] for t in context["techniques"]["primary"]]:
        task_ids = coverage.get(mid) or []
        status = "covered" if task_ids else "uncovered"
        if status == "uncovered":
            uncovered.append(mid)
        coverage_out.append({"mitre_id": mid, "status": status, "task_ids": task_ids})

    if uncovered:
        return None, False, [f"uncovered_primary_techniques={uncovered}"], advisories

    plan = {
        "tasks": tasks_out,
        "execution_order": [canonical_map[l] for l in order],
        "technique_coverage": coverage_out,
    }
    return plan, True, [], advisories


def main() -> None:
    parser = argparse.ArgumentParser(description="Stage 2: plan implementation tasks from Stage 1 ATT&CK output")
    parser.add_argument("stage1_output", help="Path to a Stage 1 data/human_outs/<timestamp>.json file")
    parser.add_argument("--index-dir", default="artifacts/offense_index", help="Stage 1 index directory")
    parser.add_argument("--pattern-library", default="data/patterns/code_patterns.jsonl", help="Vetted code pattern library JSONL")
    parser.add_argument("--constraints-file", default="data/config/stage2_constraints.json", help="Deterministic planning constraints")
    parser.add_argument("--evidence-per-technique", type=int, default=1, help="ATT&CK evidence chunks per technique")
    parser.add_argument("--patterns-per-technique", type=int, default=2, help="Code patterns per technique")
    parser.add_argument("--include-alternatives", action="store_true", help="Include Stage 1 alternatives as optional context")
    parser.add_argument("--human-output-dir", default="data/plans/human_outs", help="Directory for pretty JSON plan output")
    parser.add_argument("--machine-output-dir", default="data/plans/machine_outs", help="Directory for JSONL plan output and planning input")
    parser.add_argument("--gen-model", default=None, help="Gemini generation model")
    parser.add_argument("--temperature", type=float, default=0.2, help="Generation temperature")
    parser.add_argument("--max-output-tokens", type=int, default=4000, help="Max output tokens")
    parser.add_argument("--thinking-budget", type=int, default=0, help="Gemini thinking budget (0 uses model default)")
    parser.add_argument("--max-repair-attempts", type=int, default=2, help="Max LLM planning attempts before giving up")
    parser.add_argument("--debug", action="store_true", help="Include debug metadata in error output")
    args = parser.parse_args()

    stage1_path = Path(args.stage1_output)
    stage1 = _load_stage1_output(stage1_path)
    request_id = stage1_path.stem

    index_dir = Path(args.index_dir)
    constraints = _load_constraints(Path(args.constraints_file))
    patterns = _load_pattern_library(Path(args.pattern_library))

    human_output_dir = Path(args.human_output_dir)
    machine_output_dir = Path(args.machine_output_dir)
    human_output_dir.mkdir(parents=True, exist_ok=True)
    machine_output_dir.mkdir(parents=True, exist_ok=True)
    stem = _timestamped_stem()

    if not (stage1.get("top_techniques") or []):
        payload = {
            "schema_version": "1.0",
            "plan_id": f"plan_{stem}",
            "request_id": request_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "planning_status": "no_techniques",
            "source_query": stage1.get("query"),
            "tasks": [],
            "execution_order": [],
            "technique_coverage": [],
        }
        _write_jsonl_record(machine_output_dir / f"{stem}.jsonl", payload)
        _write_pretty_json(human_output_dir / f"{stem}.json", payload)
        print(str(human_output_dir / f"{stem}.json"))
        return

    context = _build_planning_context(
        stage1=stage1,
        index_dir=index_dir,
        patterns=patterns,
        constraints=constraints,
        request_id=request_id,
        include_alternatives=bool(args.include_alternatives),
        evidence_per_technique=int(args.evidence_per_technique),
        patterns_per_technique=int(args.patterns_per_technique),
    )
    _write_pretty_json(machine_output_dir / f"{stem}.input.json", context)

    api_key = _env("GOOGLE_API_KEY") or _env("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing GOOGLE_API_KEY (or GEMINI_API_KEY)")

    base_url = _env("GEMINI_BASE_URL") or DEFAULT_BASE_URL
    gen_model = args.gen_model or _env("GEMINI_GEN_MODEL") or DEFAULT_GEN_MODEL
    thinking_budget = _resolve_thinking_budget(gen_model, args.thinking_budget)

    plan = None
    valid = False
    violations: list[str] = []
    advisories: list[str] = []
    attempts_used = 0

    for attempt in range(1, int(args.max_repair_attempts) + 1):
        attempts_used = attempt
        prompt = _build_prompt(context, violations if violations else None)
        response_json = _call_gemini_raw(
            prompt=prompt,
            api_key=api_key,
            base_url=base_url,
            model=gen_model,
            temperature=float(args.temperature),
            max_output_tokens=int(args.max_output_tokens),
            thinking_budget=thinking_budget,
        )

        try:
            text = _extract_text(response_json)
        except GenerationEmptyTextError as exc:
            violations = [f"generation_empty_text: {exc}"]
            continue

        draft = _parse_json_response(text)
        if draft is None:
            violations = ["invalid_json_output"]
            continue

        plan, valid, violations, advisories = _validate_and_normalize(draft, context)
        if valid:
            break

    planning_status = "valid" if valid else "invalid"
    final_plan = {
        "schema_version": "1.0",
        "plan_id": f"plan_{stem}",
        "request_id": request_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "planning_status": planning_status,
        "scope": {
            "environment": constraints.get("environment"),
            "network_policy": constraints.get("network_policy"),
            "implementation_mode": constraints.get("implementation_mode"),
        },
        "source_query": stage1.get("query"),
        "tasks": plan["tasks"] if plan else [],
        "execution_order": plan["execution_order"] if plan else [],
        "technique_coverage": plan["technique_coverage"]
        if plan
        else [
            {"mitre_id": t["mitre_id"], "status": "uncovered", "task_ids": []}
            for t in context["techniques"]["primary"]
        ],
        "validation": {
            "attempts_used": attempts_used,
            "blocking_violations": violations if not valid else [],
            "advisories": advisories,
        },
        "planner_metadata": {"model": gen_model, "prompt_version": "stage2-planner-v1"},
    }

    _write_jsonl_record(machine_output_dir / f"{stem}.jsonl", final_plan)
    _write_pretty_json(human_output_dir / f"{stem}.json", final_plan)
    print(str(human_output_dir / f"{stem}.json"))


if __name__ == "__main__":
    main()
