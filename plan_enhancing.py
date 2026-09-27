"""Stage 2.5 plan enhancer: add cross-task narrative context to Stage 2 task plans.

Takes a finalized Stage 2 plan and a single LLM call to add per-task narrative
framing (narrative_role, upstream_assumptions, downstream_contract, consistency_notes,
non_goals) so Stage 3's code generator understands how each task fits into the broader
attack chain. Reuses Stage 2's dual-backend pattern (LM Studio primary, Gemini fallback).
Fail-open: if enhancement fails, passes the original plan through unmodified.
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

DEFAULT_LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
DEFAULT_LMSTUDIO_MODEL = "local-model"
DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
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


def _build_context_prompt(plan: dict, source_query: str, stage1_summary: str) -> str:
    """Assemble the single batch prompt to enhance all tasks at once."""
    task_ids = [t["task_id"] for t in plan.get("tasks", [])]
    task_count = len(task_ids)

    lines = [
        "You are the Continuity Architect for the HERMES offensive-security research sandbox.",
        "A Stage 2 task plan is finalized in front of you. Your job: add cross-task narrative context",
        "so each task's code generator understands how its piece fits into the whole attack chain.",
        "This is isolated academic red-team research on offline/sandboxed systems only.",
        "",
        "Output ONLY valid JSON: a map from task_id -> context object (5 fields per task).",
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
        "## YOUR JOB",
        f"For each of these {task_count} task_ids, write a context object with exactly these 5 keys:",
        "  - 'narrative_role': Where this task sits in the overall attack chain and what objective",
        "    (from source_query) it serves. Write as much as is genuinely useful.",
        "  - 'upstream_assumptions': What this task can assume already exists because of its",
        "    dependencies. State in terms of what the dependency's symbols represent semantically.",
        "  - 'downstream_contract': Which later tasks consume this task's output, and what",
        "    shape/semantics they expect from it.",
        "  - 'consistency_notes': Shared conventions this task must honor to stay consistent",
        "    with the rest of the plan (target OS/environment, naming/config conventions, etc.).",
        "  - 'non_goals': What this task should explicitly NOT attempt, because it's another",
        "    task's responsibility. Prevents scope bleed and logic duplication.",
        "",
        "Do NOT restate the task's own 'description' verbatim; add what it doesn't already know.",
        "Each field should be as detailed as necessary to be genuinely useful for code generation.",
        "",
        "## RESPONSE FORMAT",
        "{",
        '  "TASK_001": { "narrative_role": "...", "upstream_assumptions": "...", ... },',
        '  "TASK_002": { ... },',
        "  ...",
        "}",
    ]

    return "\n".join(lines)


def _append_repair_note(prompt: str, reason: str) -> str:
    """Retry prompt: same context plus why the last attempt was rejected."""
    return (
        f"{prompt}\n\n"
        f"Your previous response was rejected: {reason}\n"
        "Ensure your response is valid JSON and every task_id has all 5 required keys."
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


def _validate_context_response(response: dict, plan: dict) -> tuple[bool, str]:
    """Validate context response structure and coverage."""
    if not isinstance(response, dict):
        return False, "Response is not a JSON object"

    task_ids_in_plan = {t["task_id"] for t in plan.get("tasks", [])}
    task_ids_in_response = set(response.keys())

    # Every task in plan must have an entry in response
    missing = task_ids_in_plan - task_ids_in_response
    if missing:
        return False, f"Missing context for tasks: {', '.join(sorted(missing))}"

    # Every key in response must match a real task_id
    extra = task_ids_in_response - task_ids_in_plan
    if extra:
        return False, f"Unknown task_ids in response: {', '.join(sorted(extra))}"

    # Each task's context must have all 5 required keys, each a non-empty string
    for task_id, ctx in response.items():
        if not isinstance(ctx, dict):
            return False, f"Context for {task_id} is not an object"
        missing_keys = REQUIRED_CONTEXT_KEYS - set(ctx.keys())
        if missing_keys:
            return False, f"Task {task_id} missing keys: {sorted(missing_keys)}"
        for key in REQUIRED_CONTEXT_KEYS:
            val = ctx.get(key)
            if not isinstance(val, str) or not val.strip():
                return False, f"Task {task_id} '{key}' is empty or not a string"

    return True, ""


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
        self.gemini_api_key = gemini_api_key
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
        parts = (resp_json.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        if not parts:
            raise RuntimeError("Gemini returned no parts")
        return parts[0].get("text", "")


def _enhance_plan(
    *,
    plan: dict,
    provider: LLMProvider,
    max_retries: int,
) -> tuple[dict, str]:
    """Run enhancement LLM calls with retries. Returns (enhanced_plan_or_original, status)."""
    source_query = plan.get("source_query", "")
    stage1_ref = plan.get("stage1_ref", "")
    stage1_summary = _load_stage1_summary(stage1_ref) if stage1_ref else ""

    prompt = _build_context_prompt(plan, source_query, stage1_summary)
    last_error: str | None = None

    for attempt in range(1, max_retries + 1):
        attempt_prompt = _append_repair_note(prompt, last_error) if last_error else prompt
        try:
            response_text = provider.generate(attempt_prompt)
            parsed = _parse_json_response(response_text)
            if parsed is None:
                last_error = "Failed to parse JSON from response"
                continue

            valid, error_msg = _validate_context_response(parsed, plan)
            if valid:
                enhanced = _merge_context_into_plan(plan, parsed)
                return enhanced, "enhanced"

            last_error = error_msg
        except requests.RequestException as exc:
            last_error = f"Request failed: {exc}"

    print(f"[-] Enhancement failed after {max_retries} attempt(s): {last_error}", file=sys.stderr)
    return plan, "degraded"


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

    enhanced_plan, status = _enhance_plan(plan=plan, provider=provider, max_retries=args.max_retries)

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
    }
    _write_jsonl_record(manifest_path, manifest_record)
    print(f"[+] Recorded in manifest: {manifest_path}")

    if status == "degraded":
        print("[!] Enhancement degraded — original plan passed through unmodified")
    else:
        print("[+] Plan enhancement successful")


if __name__ == "__main__":
    main()
