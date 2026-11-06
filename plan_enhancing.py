"""Stage 2.5 plan enhancer: add cross-task narrative context to Stage 2 task plans.

Takes a finalized Stage 2 plan and one batch LLM call to add per-task narrative framing so
Stage 3's code generator understands how each task fits into the broader attack chain.
narrative_role/consistency_notes/non_goals are always present; upstream_assumptions and
downstream_contract are included only when the task has a real dependency/dependent in the
plan's DAG (see _expected_context_keys) -- a task with no real edge there has nothing true to
report, since its external contract is already fully defined by source_query and its own
implementation_details.

A single bad task no longer costs the other N-1 their enhancement: the batch call is retried
only for genuine structural failures (unparseable JSON, wrong task_id set); once it's
structurally valid, each task's content is validated on its own, a task that fails is retried
in isolation (_retry_single_task), and if that still fails its context is computed
deterministically from the plan's own structure (_deterministic_task_context) rather than
given up on. Reuses Stage 2's dual-backend pattern (LM Studio primary, Gemini fallback).
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv()

DEFAULT_LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
DEFAULT_LMSTUDIO_MODEL = "local-model"
DEFAULT_GEMINI_MODEL = "gemini-3.1-pro-preview"
DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_TIMEOUT = 600
DEFAULT_MAX_TOKENS = 16384
DEFAULT_MAX_RETRIES = 3
OUTPUT_DIR = "data/plans/enhanced_outs"
MANIFEST_NAME = "enhancement_manifest.jsonl"

REQUIRED_CONTEXT_KEYS = {
    "narrative_role",
    "upstream_assumptions",
    "downstream_contract",
    "consistency_notes",
    "non_goals",
}


def _load_plan(path: Path) -> dict:
    """Load and validate a Stage 2 plan JSON."""
    if not path.exists():
        raise RuntimeError(f"Plan file not found: {path}")
    plan = json.loads(path.read_text(encoding="utf-8"))
    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise RuntimeError(f"Plan has no 'tasks' array or it's empty: {path}")
    return plan


def _load_stage1_summary(stage1_ref: str, stage1_base_dir: Path = Path("data/human_outs")) -> str:
    """Load Stage 1's summary field from the referenced artifact."""
    stage1_path = stage1_base_dir / stage1_ref
    if not stage1_path.exists():
        return ""
    try:
        stage1_data = json.loads(stage1_path.read_text(encoding="utf-8"))
        return str(stage1_data.get("summary", ""))
    except (json.JSONDecodeError, IOError):
        return ""


def _dependents_map(plan: dict) -> dict[str, list[str]]:
    """For each task_id, which other task_ids in the plan actually declare it as a dependency --
    the reverse of each task's own 'dependencies' list. A task's OWN dependencies are a local
    read (they're sitting right in its own JSON object); who depends on IT is not local at all --
    answering that means scanning every other task in the plan. Computed once here so the model
    is handed the fact directly, once, instead of needing to re-derive it itself by re-scanning
    the whole plan per task -- which is exactly the computation that empirically falls apart for
    a small local model once it has to repeat it across every task in one long batch generation
    (see docs/LLM_PROMPTS_REFERENCE.md and this session's 12-task test: every single validation
    failure was this one lookup, never the symmetric-looking but actually-local upstream one)."""
    tasks = plan.get("tasks", [])
    dependents: dict[str, list[str]] = {t["task_id"]: [] for t in tasks}
    for t in tasks:
        for dep_id in t.get("dependencies") or []:
            if dep_id in dependents:
                dependents[dep_id].append(t["task_id"])
    return dependents


def _terminal_task_ids(plan: dict) -> list[str]:
    """Task IDs with no real dependents (see _dependents_map) -- i.e. nothing downstream of
    them exists in-pipeline, so their real contract is with whoever runs the file by hand,
    not with another task. Computed deterministically rather than left for the model to judge,
    the same way Stage 3 derives dependency facts instead of asking the model to get them right."""
    dependents = _dependents_map(plan)
    return [tid for tid, deps in dependents.items() if not deps]


def _expected_context_keys(task: dict, terminal_ids: set[str]) -> set[str]:
    """Which of the 5 scenario_context keys are actually answerable for this task, given its
    real position in the plan's DAG -- not a fixed 5 for every task regardless of shape.

    'upstream_assumptions' and 'downstream_contract' each describe a real edge to another task.
    When that edge doesn't exist (no declared dependencies / no declared dependents), there is
    nothing true to report -- asking for the field anyway doesn't surface a fact, it manufactures
    one. A task with no dependents already has its external contract fully defined by the plan's
    own source_query and implementation_details; restating that in free text is redundant surface
    area for drift, not new information. 'narrative_role', 'consistency_notes', and 'non_goals'
    stay unconditional: they're meaningful even for a single-task plan (environment constraints
    and scope discipline don't depend on DAG shape).
    """
    keys = {"narrative_role", "consistency_notes", "non_goals"}
    if task.get("dependencies"):
        keys.add("upstream_assumptions")
    if task["task_id"] not in terminal_ids:
        keys.add("downstream_contract")
    return keys


def _format_dependency_facts(task: dict, tasks_by_id: dict, dependents: dict[str, list[str]]) -> list[str]:
    """Render the precomputed forward (dependencies -> their provides) and backward
    (dependents -> who actually consumes this task) edges as plain facts to hand the model,
    so it never has to scan the rest of the plan to answer 'who depends on me' itself --
    that global scan, repeated once per task in a batch, is the specific thing that was
    failing; this removes the need to do it at all."""
    tid = task["task_id"]
    fact_lines = []

    deps = task.get("dependencies") or []
    if deps:
        dep_facts = []
        for dep_id in deps:
            dep_task = tasks_by_id.get(dep_id)
            provided = ", ".join(dep_task.get("provides") or []) if dep_task else "unknown"
            dep_facts.append(f"{dep_id} (provides: {provided})")
        fact_lines.append(f"    upstream_assumptions fact: depends on {', '.join(dep_facts)}")

    real_dependents = dependents.get(tid) or []
    if real_dependents:
        own_provides = ", ".join(task.get("provides") or []) or "nothing named"
        fact_lines.append(
            f"    downstream_contract fact: provides {own_provides}; actually consumed in this "
            f"plan by {', '.join(real_dependents)} -- base the field on this, don't re-derive it"
        )

    return fact_lines


def _build_context_prompt(plan: dict, source_query: str, stage1_summary: str) -> str:
    """Assemble the single batch prompt to enhance all tasks at once."""
    tasks = plan.get("tasks", [])
    tasks_by_id = {t["task_id"]: t for t in tasks}
    dependents = _dependents_map(plan)
    terminal_ids = set(_terminal_task_ids(plan))
    expected_by_task = {t["task_id"]: _expected_context_keys(t, terminal_ids) for t in tasks}

    key_listing_lines = []
    for t in tasks:
        tid = t["task_id"]
        expected = sorted(expected_by_task[tid])
        omitted = sorted(REQUIRED_CONTEXT_KEYS - expected_by_task[tid])
        line = f"  - {tid}: include ONLY {expected}"
        if omitted:
            reasons = []
            if "upstream_assumptions" in omitted:
                reasons.append("no 'dependencies' declared, so nothing upstream to assume")
            if "downstream_contract" in omitted:
                reasons.append("no other task in this plan depends on it (terminal task) --"
                                " its contract is already the source_query + its own"
                                " implementation_details, not something to restate here")
            line += f" (omit {omitted}: {'; '.join(reasons)})"
        key_listing_lines.append(line)
        key_listing_lines.extend(_format_dependency_facts(t, tasks_by_id, dependents))

    lines = [
        "You are the Continuity Architect for the HERMES offensive-security research sandbox.",
        "A Stage 2 task plan is finalized in front of you. Your job: add cross-task narrative context",
        "so each task's code generator understands how its piece fits into the whole attack chain.",
        "This is isolated academic red-team research on offline/sandboxed systems only.",
        "",
        "Output ONLY valid JSON: a map from task_id -> context object. NOT every task gets the",
        "same 5 keys -- which keys apply to each task_id is listed explicitly below; this is",
        "computed from the plan's actual dependency structure, not a judgment call for you to make.",
        "",
        "## ORIGINAL OBJECTIVE",
        f"Source query: {source_query}",
        "",
        "Stage 1 synthesis:",
        stage1_summary if stage1_summary else "(No Stage 1 summary available)",
        "",
        "## FINALIZED TASK PLAN",
        json.dumps(plan, indent=2),
        "",
        "## PER-TASK REQUIRED KEYS (exact -- a listed key is required; an unlisted key must be",
        "## left out of that task's object entirely, not included empty or with a placeholder).",
        "## Where a task has an 'upstream_assumptions fact' or 'downstream_contract fact' line,",
        "## that fact was already computed from the plan's real dependency edges -- write the",
        "## field's prose FROM that given fact, do not re-scan the plan yourself to re-derive it.",
        *key_listing_lines,
        "",
        "## KEY MEANINGS (only write a key if it's listed above for that task_id)",
        "  - 'narrative_role': Where this task sits relative to the objective in source_query.",
        "    Write as much as is genuinely useful.",
        "  - 'upstream_assumptions': Expand this task's 'upstream_assumptions fact' line above into",
        "    prose -- what it can assume already exists, in terms of what those symbols represent",
        "    semantically, not just their names. Use ONLY the dependency task_ids given in that fact.",
        "  - 'downstream_contract': Expand this task's 'downstream_contract fact' line above into",
        "    prose -- what shape/semantics the named consumer(s) expect from this task's output.",
        "    Use ONLY the consumer task_ids given in that fact, never a different or hypothetical one.",
        "  - 'consistency_notes': Shared conventions this task must honor to stay consistent",
        "    with the rest of the plan (target OS/environment, naming/config conventions, etc.).",
        "  - 'non_goals': What this task should explicitly NOT attempt. If another task_id in the",
        "    plan above actually owns that responsibility, name it by its real task_id. If no task",
        "    in this plan handles it, say plainly that it's out of scope -- do NOT attribute it to a",
        "    hypothetical task that might be 'added later'; only reference tasks that exist above.",
        "",
        "Do NOT reference any task, capability, or architectural layer that does not appear in the",
        "FINALIZED TASK PLAN above, under any field.",
        "Do NOT restate the task's own 'description' verbatim; add what it doesn't already know.",
        "Each field should be as detailed as necessary to be genuinely useful for code generation.",
        "",
        "## RESPONSE FORMAT",
        "Shape varies by task per the PER-TASK REQUIRED KEYS list above -- e.g. for a plan where",
        "TASK_001 has no dependencies/dependents and TASK_002 depends on it:",
        "{",
        '  "TASK_001": { "narrative_role": "...", "consistency_notes": "...", "non_goals": "..." },',
        '  "TASK_002": { "narrative_role": "...", "upstream_assumptions": "...",',
        '               "downstream_contract": "...", "consistency_notes": "...", "non_goals": "..." }',
        "}",
    ]

    return "\n".join(lines)


def _append_repair_note(prompt: str, reason: str) -> str:
    """Retry prompt: same context plus why the last attempt was rejected."""
    return (
        f"{prompt}\n\n"
        f"Your previous response was rejected: {reason}\n"
        "Ensure your response is valid JSON, and that every task_id has EXACTLY the keys listed "
        "for it under PER-TASK REQUIRED KEYS above -- no key missing, and no extra key included."
    )


def _parse_json_response(text: str) -> dict | None:
    """Extract and parse JSON from model response (strip markdown fence if present)."""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if len(lines) > 2 else ""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _validate_batch_shape(response: dict, plan: dict) -> tuple[bool, str]:
    """Structural check only: is this a dict covering exactly the plan's real task_ids, each
    mapped to an object? Does NOT check per-task key correctness -- that's _validate_single_task_
    context's job, applied per task_id after this passes, so one task's bad content never fails
    the whole response. A genuine failure here (unparseable shape, wrong task_id set) really is
    all-or-nothing and does warrant a full batch retry; a single task's bad content does not."""
    if not isinstance(response, dict):
        return False, "Response is not a JSON object"

    task_ids_in_plan = {t["task_id"] for t in plan.get("tasks", [])}
    task_ids_in_response = set(response.keys())

    missing = task_ids_in_plan - task_ids_in_response
    if missing:
        return False, f"Missing context for tasks: {', '.join(sorted(missing))}"

    extra = task_ids_in_response - task_ids_in_plan
    if extra:
        return False, f"Unknown task_ids in response: {', '.join(sorted(extra))}"

    non_object = [tid for tid, ctx in response.items() if not isinstance(ctx, dict)]
    if non_object:
        return False, f"Context for task(s) {sorted(non_object)} is not an object"

    return True, ""


def _validate_single_task_context(
    task_id: str, ctx: dict, task: dict, terminal_ids: set[str]
) -> tuple[bool, str]:
    """Per-task validation: does this one context object have exactly the keys
    _expected_context_keys says apply to this task -- no required key missing, no
    not-applicable key included -- and is every present key a non-empty string?"""
    if not isinstance(ctx, dict):
        return False, f"Context for {task_id} is not an object"

    expected = _expected_context_keys(task, terminal_ids)
    present = set(ctx.keys())

    missing_keys = expected - present
    if missing_keys:
        return False, f"Task {task_id} missing required keys {sorted(missing_keys)}"

    not_applicable = (REQUIRED_CONTEXT_KEYS - expected) & present
    if not_applicable:
        return False, (
            f"Task {task_id} includes key(s) {sorted(not_applicable)} that don't apply to it "
            f"(no real dependency/dependent in the plan for that key) -- omit them entirely, "
            f"don't fill them in"
        )

    for key in expected:
        val = ctx.get(key)
        if not isinstance(val, str) or not val.strip():
            return False, f"Task {task_id} '{key}' is empty or not a string"

    return True, ""


def _build_single_task_prompt(
    task: dict, plan: dict, source_query: str, stage1_summary: str, terminal_ids: set[str]
) -> str:
    """Scoped-down version of _build_context_prompt for isolated retry of exactly one task,
    so a retry doesn't have to regenerate (and risk breaking) every other task's already-good
    context. Same information, same per-task key gating, but the response is one flat object."""
    task_id = task["task_id"]
    expected = sorted(_expected_context_keys(task, terminal_ids))
    omitted = sorted(REQUIRED_CONTEXT_KEYS - set(expected))
    tasks_by_id = {t["task_id"]: t for t in plan.get("tasks", [])}
    dependents = _dependents_map(plan)
    fact_lines = _format_dependency_facts(task, tasks_by_id, dependents)

    lines = [
        "You are the Continuity Architect for the HERMES offensive-security research sandbox.",
        f"You previously enhanced a Stage 2 task plan, but task {task_id} needs to be redone.",
        "This is isolated academic red-team research on offline/sandboxed systems only.",
        "",
        "## ORIGINAL OBJECTIVE",
        f"Source query: {source_query}",
        "",
        "Stage 1 synthesis:",
        stage1_summary if stage1_summary else "(No Stage 1 summary available)",
        "",
        "## FULL TASK PLAN (for context -- you are only writing a context object for one task)",
        json.dumps(plan, indent=2),
        "",
        f"## THE ONE TASK YOU ARE WRITING CONTEXT FOR: {task_id}",
        f"Required keys for this task, exactly: {expected}",
    ]
    if fact_lines:
        lines.append(
            "These facts were already computed from the plan's real dependency edges -- write"
            " the matching field's prose FROM them, do not re-scan the plan to re-derive them:"
        )
        lines.extend(fact_lines)
    if omitted:
        reasons = []
        if "upstream_assumptions" in omitted:
            reasons.append("no 'dependencies' declared, so nothing upstream to assume")
        if "downstream_contract" in omitted:
            reasons.append("no other task in this plan depends on it -- its contract is already"
                            " the source_query + its own implementation_details")
        lines.append(f"Do NOT include {omitted}: {'; '.join(reasons)}.")
    lines += [
        "",
        "## KEY MEANINGS (write only the keys listed above)",
        "  - 'narrative_role': Where this task sits relative to the objective in source_query.",
        "  - 'upstream_assumptions': Expand the 'upstream_assumptions fact' above into prose,",
        "    using ONLY the dependency task_ids given there.",
        "  - 'downstream_contract': Expand the 'downstream_contract fact' above into prose,",
        "    using ONLY the consumer task_ids given there -- never a different or hypothetical one.",
        "  - 'consistency_notes': Shared conventions this task must honor (target OS/environment,",
        "    naming/config conventions, etc.).",
        "  - 'non_goals': What this task should explicitly NOT attempt. If another real task_id",
        "    owns that responsibility, name it; if nothing in this plan does, say it's out of",
        "    scope plainly -- never attribute it to a hypothetical future task.",
        "",
        "Do NOT reference any task, capability, or layer that does not appear in the plan above.",
        "Do NOT restate the task's own 'description' verbatim; add what it doesn't already know.",
        "",
        "## RESPONSE FORMAT",
        "Output ONLY valid JSON: a single flat object with exactly the required keys above.",
        "{",
        *(f'  "{k}": "..."{"," if i < len(expected) - 1 else ""}' for i, k in enumerate(expected)),
        "}",
    ]
    return "\n".join(lines)


def _append_single_task_repair_note(prompt: str, reason: str) -> str:
    """Retry prompt for the isolated single-task path: same context plus why it was rejected."""
    return (
        f"{prompt}\n\n"
        f"Your previous response was rejected: {reason}\n"
        "Ensure your response is valid JSON with EXACTLY the required keys listed above for this "
        "one task -- no key missing, and no extra key included."
    )


def _deterministic_task_context(task: dict, plan: dict, terminal_ids: set[str]) -> dict:
    """Last-resort fallback when the LLM can't produce a valid context for this task even after
    an isolated retry: compute the applicable keys directly from the plan's own structure. Never
    asks the model's judgment for anything a dependency edge, a provides/consumes list, or another
    task's own description already answers -- same principle as Stage 3's _inject_dependency_imports
    computing an import instead of trusting the model to get it right. Plainer than an LLM-authored
    version, but it cannot hallucinate a relationship that doesn't exist in the plan, which is the
    actual failure mode this whole mechanism exists to prevent."""
    tasks_by_id = {t["task_id"]: t for t in plan.get("tasks", [])}
    task_id = task["task_id"]
    expected = _expected_context_keys(task, terminal_ids)
    ctx: dict[str, str] = {}

    if "narrative_role" in expected:
        techniques = ", ".join(task.get("technique_ids") or []) or "none listed"
        ctx["narrative_role"] = (
            f"Implements: {task.get('description', '').strip() or task_id}. "
            f"ATT&CK techniques covered: {techniques}."
        )

    if "upstream_assumptions" in expected:
        parts = []
        for dep_id in task.get("dependencies") or []:
            dep = tasks_by_id.get(dep_id)
            provided = ", ".join(dep.get("provides") or []) if dep else "unknown"
            parts.append(f"{dep_id} provides: {provided}")
        ctx["upstream_assumptions"] = (
            "May assume the following, from its declared dependencies: " + "; ".join(parts)
            if parts else "No declared dependencies."
        )

    if "downstream_contract" in expected:
        own_provides = ", ".join(task.get("provides") or []) or "nothing"
        consumers = [
            other["task_id"] for other in plan.get("tasks", [])
            if task_id in (other.get("dependencies") or [])
        ]
        ctx["downstream_contract"] = (
            f"Provides: {own_provides}. Consumed in this plan by: "
            + (", ".join(consumers) if consumers else "no other task")
            + "."
        )

    if "consistency_notes" in expected:
        ctx["consistency_notes"] = (
            f"Task type '{task.get('task_type', 'unspecified')}'; follow this plan's own "
            f"implementation_details for this task: {task.get('implementation_details', '').strip() or '(none specified)'}"
        )

    if "non_goals" in expected:
        others = [
            f"{t['task_id']} ({t.get('description', '').strip()})"
            for t in plan.get("tasks", []) if t["task_id"] != task_id
        ]
        ctx["non_goals"] = (
            "Responsibilities belonging to other tasks in this plan are out of scope: "
            + ("; ".join(others) if others else "no other tasks exist in this plan.")
        )

    return ctx


def _retry_single_task(
    *,
    task: dict,
    plan: dict,
    source_query: str,
    stage1_summary: str,
    terminal_ids: set[str],
    provider: "LLMProvider",
    max_retries: int,
) -> dict | None:
    """Isolated retry loop for exactly one task. Returns the valid context dict, or None if
    every attempt was exhausted without producing something that passes per-task validation."""
    task_id = task["task_id"]
    prompt = _build_single_task_prompt(task, plan, source_query, stage1_summary, terminal_ids)
    last_error: str | None = None

    for attempt in range(1, max_retries + 1):
        attempt_prompt = (
            _append_single_task_repair_note(prompt, last_error) if last_error else prompt
        )
        try:
            response_text = provider.generate(attempt_prompt)
        except requests.RequestException as exc:
            last_error = f"Request failed: {exc}"
            continue

        parsed = _parse_json_response(response_text)
        if parsed is None:
            last_error = "Failed to parse JSON from response"
            continue

        valid, error_msg = _validate_single_task_context(task_id, parsed, task, terminal_ids)
        if valid:
            return parsed
        last_error = error_msg

    return None


def _write_jsonl_record(path: Path, payload: dict) -> None:
    """Append one record to the manifest JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _merge_context_into_plan(plan: dict, context_map: dict) -> dict:
    """Create a new plan dict with scenario_context added to each task."""
    enhanced = plan.copy()
    enhanced_tasks = []
    for task in plan.get("tasks", []):
        task_copy = task.copy()
        task_id = task["task_id"]
        if task_id in context_map:
            task_copy["scenario_context"] = context_map[task_id]
        enhanced_tasks.append(task_copy)
    enhanced["tasks"] = enhanced_tasks
    return enhanced


class LLMProvider:
    """Dual-backend LLM client: LM Studio primary, Gemini fallback."""

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

    def generate(self, prompt: str) -> str:
        """Single-shot generation with automatic fallback."""
        if self.provider == "lmstudio":
            try:
                return self._call_lmstudio(prompt)
            except Exception as e:
                print(f"[WARN] LM Studio call failed: {e}. Falling back to Gemini...", file=sys.stderr)
                return self._call_gemini(prompt)
        elif self.provider == "gemini":
            return self._call_gemini(prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def _call_lmstudio(self, prompt: str) -> str:
        """Call local LM Studio server."""
        payload = {
            "model": self.lmstudio_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
            "max_tokens": self.max_tokens,
        }
        resp = requests.post(self.lmstudio_url, json=payload, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"LM Studio error ({resp.status_code}): {resp.text[:400]}")
        resp_json = resp.json()
        choices = resp_json.get("choices") or []
        if not choices:
            raise RuntimeError("LM Studio returned no choices")
        return choices[0].get("message", {}).get("content", "")

    def _call_gemini(self, prompt: str) -> str:
        """Call Gemini REST API."""
        if not self.gemini_api_key:
            raise RuntimeError("GEMINI_API_KEY environment variable required for Gemini fallback")
        url = f"{DEFAULT_GEMINI_BASE_URL}/models/{self.gemini_model}:generateContent?key={self.gemini_api_key}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
                "maxOutputTokens": min(self.max_tokens, 8192),
            },
        }
        resp = requests.post(url, json=payload, timeout=min(self.timeout, 120))
        if resp.status_code != 200:
            raise RuntimeError(f"Gemini error ({resp.status_code}): {resp.text[:400]}")
        resp_json = resp.json()
        usage = resp_json.get("usageMetadata", {})
        print(
            f"[GEMINI] model={resp_json.get('modelVersion', self.gemini_model)} "
            f"prompt_tokens={usage.get('promptTokenCount')} "
            f"output_tokens={usage.get('candidatesTokenCount')} "
            f"total_tokens={usage.get('totalTokenCount')}",
            file=sys.stderr,
        )
        parts = (resp_json.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        if not parts:
            raise RuntimeError("Gemini returned no parts")
        return parts[0].get("text", "")


def _enhance_plan(
    *,
    plan: dict,
    provider: LLMProvider,
    max_retries: int,
) -> tuple[dict, str, list[dict]]:
    """Enhance every task's context. One task's bad content never drops the other N-1:
    1. One batch call attempt (retried up to max_retries, but ONLY for genuine structural
       failures -- unparseable JSON or the wrong set of task_ids -- which really are
       all-or-nothing). As soon as a structurally valid batch response comes back, stop
       retrying the batch, even if some individual task's content is wrong.
    2. Each task is then validated on its own. A task that already passed is kept as-is.
       A task that failed gets logged by name and retried in isolation (its own prompt, its
       own small retry budget) -- the other tasks are never touched or re-generated.
    3. If a task still fails after its isolated retries (or the batch call never produced a
       usable response at all), that task's context is computed deterministically from the
       plan's own dependency/provides structure instead of asked for again. This never leaves
       a task with zero context and never discards the whole plan's worth of work over one
       task's mistake.

    Returns (enhanced_plan, status, dropped_tasks):
      - status: "enhanced" if every task's context came from the model, "enhanced_partial" if
        any task needed the deterministic fallback.
      - dropped_tasks: one {"task_id": ..., "reason": ...} entry per task that needed the
        fallback (empty list if none) -- the per-run manifest record persists this so a run
        where the model quietly produced no real content for a task is traceable afterward,
        not indistinguishable from a run where everything actually came from the LLM.
    """
    source_query = plan.get("source_query", "")
    stage1_ref = plan.get("stage1_ref", "")
    stage1_summary = _load_stage1_summary(stage1_ref) if stage1_ref else ""
    terminal_ids = set(_terminal_task_ids(plan))
    tasks_by_id = {t["task_id"]: t for t in plan.get("tasks", [])}

    # Step 1: batch call, retried only on structural failure.
    batch_prompt = _build_context_prompt(plan, source_query, stage1_summary)
    batch_response: dict | None = None
    last_error: str | None = None

    for attempt in range(1, max_retries + 1):
        attempt_prompt = _append_repair_note(batch_prompt, last_error) if last_error else batch_prompt
        try:
            response_text = provider.generate(attempt_prompt)
        except requests.RequestException as exc:
            last_error = f"Request failed: {exc}"
            continue

        parsed = _parse_json_response(response_text)
        if parsed is None:
            last_error = "Failed to parse JSON from response"
            continue

        shape_ok, shape_error = _validate_batch_shape(parsed, plan)
        if not shape_ok:
            last_error = shape_error
            continue

        batch_response = parsed
        break

    context_map: dict[str, dict] = {}
    dropped_tasks: list[dict] = []

    if batch_response is None:
        print(
            f"[-] Batch call never produced a structurally valid response after "
            f"{max_retries} attempt(s): {last_error}",
            file=sys.stderr,
        )
        print(
            "[!] Computing every task's context deterministically instead of retrying further.",
            file=sys.stderr,
        )
        for task_id, task in tasks_by_id.items():
            context_map[task_id] = _deterministic_task_context(task, plan, terminal_ids)
            dropped_tasks.append({
                "task_id": task_id,
                "reason": f"batch call never produced a structurally valid response: {last_error}",
            })
    else:
        # Step 2: validate each task's content independently.
        for task_id, task in tasks_by_id.items():
            ctx = batch_response.get(task_id)
            valid, error_msg = _validate_single_task_context(task_id, ctx or {}, task, terminal_ids)
            if valid:
                context_map[task_id] = ctx
                continue

            print(f"[-] Task {task_id} is the one that fails validation: {error_msg}", file=sys.stderr)
            print(f"[*] Retrying {task_id} in isolation (other tasks unaffected)...", file=sys.stderr)

            # Step 3a: isolated retry for just this task.
            resolved = _retry_single_task(
                task=task,
                plan=plan,
                source_query=source_query,
                stage1_summary=stage1_summary,
                terminal_ids=terminal_ids,
                provider=provider,
                max_retries=max_retries,
            )
            if resolved is not None:
                print(f"[+] {task_id} resolved via isolated retry.", file=sys.stderr)
                context_map[task_id] = resolved
                continue

            # Step 3b: isolated retry also failed -- compute it instead of asking again.
            print(
                f"[!] {task_id} still fails after isolated retry -- computing its context "
                f"deterministically from the plan's own structure instead.",
                file=sys.stderr,
            )
            context_map[task_id] = _deterministic_task_context(task, plan, terminal_ids)
            dropped_tasks.append({
                "task_id": task_id,
                "reason": f"batch validation: {error_msg}; isolated retry also failed to produce a valid response",
            })

    enhanced = _merge_context_into_plan(plan, context_map)
    status = "enhanced_partial" if dropped_tasks else "enhanced"
    if dropped_tasks:
        dropped_ids = [d["task_id"] for d in dropped_tasks]
        print(
            f"[!] {len(dropped_tasks)}/{len(tasks_by_id)} task(s) used the deterministic "
            f"fallback, not the LLM: {dropped_ids}",
            file=sys.stderr,
        )
    return enhanced, status, dropped_tasks


def main() -> None:
    """CLI entry point: load plan, enhance, write to enhanced_outs/."""
    parser = argparse.ArgumentParser(
        description="Stage 2.5 Plan Enhancer: add cross-task narrative context to Stage 2 plans"
    )
    parser.add_argument("stage2_plan", help="Path to Stage 2 data/plans/human_outs/PLAN_*.json")
    parser.add_argument("--provider", choices=["lmstudio", "gemini"], default="lmstudio")
    parser.add_argument("--lmstudio-url", default=DEFAULT_LMSTUDIO_URL)
    parser.add_argument("--lmstudio-model", default=DEFAULT_LMSTUDIO_MODEL)
    parser.add_argument("--gemini-model", default=DEFAULT_GEMINI_MODEL)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--max-retries", type=int, default=DEFAULT_MAX_RETRIES)
    parser.add_argument("--output-dir", default=OUTPUT_DIR)
    args = parser.parse_args()

    plan_path = Path(args.stage2_plan)
    print(f"[*] Loading Stage 2 plan: {plan_path}")
    plan = _load_plan(plan_path)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / MANIFEST_NAME

    # Derive output filename from input
    stem = plan_path.stem
    if stem.startswith("PLAN_"):
        stem = stem[5:]

    out_path = output_dir / f"PLAN_{stem}.json"

    print(f"[*] Enhancing plan (up to {args.max_retries} LLM attempt(s))...")
    provider = LLMProvider(
        provider=args.provider,
        lmstudio_url=args.lmstudio_url,
        lmstudio_model=args.lmstudio_model,
        gemini_api_key=None,  # Will use env var if needed
        gemini_model=args.gemini_model,
        timeout=args.timeout,
        max_tokens=args.max_tokens,
    )

    enhanced_plan, status, dropped_tasks = _enhance_plan(
        plan=plan, provider=provider, max_retries=args.max_retries
    )

    # Write enhanced plan
    out_path.write_text(json.dumps(enhanced_plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Wrote enhanced plan to {out_path}")

    # Write manifest
    timestamp = datetime.now(timezone.utc).isoformat()
    manifest_record = {
        "plan_id": plan.get("plan_id", f"PLAN_{stem}"),
        "stage1_ref": plan.get("stage1_ref", ""),
        "status": status,
        "output_file": str(out_path),
        "timestamp": timestamp,
        "task_count": len(plan.get("tasks", [])),
        # Which tasks (if any) didn't get LLM-authored context and fell back to the
        # deterministic, plan-derived version instead -- empty list means none did. This is
        # the trace that makes a degraded-content run distinguishable from a clean one after
        # the fact; `status` alone tells you IF something fell back, this tells you WHAT and WHY.
        "dropped_tasks": dropped_tasks,
        "dropped_task_count": len(dropped_tasks),
    }
    _write_jsonl_record(manifest_path, manifest_record)
    print(f"[+] Recorded in manifest: {manifest_path}")

    if status == "degraded":
        # Should no longer happen in practice -- _enhance_plan now falls back to deterministic
        # per-task context instead of giving up entirely. Kept only as a defensive branch.
        print("[!] Enhancement degraded — original plan passed through unmodified")
    elif status == "enhanced_partial":
        print("[!] Plan enhancement partially successful — see stderr above for which task(s) "
              "used the deterministic fallback instead of the LLM")
    else:
        print("[+] Plan enhancement successful")


if __name__ == "__main__":
    main()
