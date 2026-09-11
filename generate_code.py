"""Stage 3 code generator: turn a Stage 2 task plan into per-task Python files.

Each task is sent to a local LM Studio model as one independent chat request. The model
must reply with a single fenced code block containing the complete file; the plan
(not the model) determines each task's output filename. This module parses,
syntax-checks, and persists that response, then moves to the next task.
"""

import argparse
import ast
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

DEFAULT_BASE_URL = "http://localhost:1234/v1"
DEFAULT_MODEL = "qwen3.8-9b-heretic-uncensored-nvfp4"
DEFAULT_MAX_TOKENS = 16384
DEFAULT_OUTPUT_DIR = "data/code_scripts"
MANIFEST_NAME = "manifest.jsonl"

FILENAME_RE = re.compile(r"^[A-Za-z0-9_]+\.py$")
FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)  # first fenced block only
OPEN_FENCE_RE = re.compile(r"```[^\n]*\n(.*)", re.DOTALL)  # fallback: opening fence with no closing fence (truncated reply)

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
}


def _load_plan(path: Path) -> dict:
    # Stage 2 (schema v2.0) only ever persists already-validated plans to human_outs/; check shape defensively.
    if not path.exists():
        raise RuntimeError(f"Missing Stage 2 plan file: {path}")
    plan = json.loads(path.read_text(encoding="utf-8"))
    tasks = plan.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise RuntimeError(f"Plan has no 'tasks' array: {path}")
    for task in tasks:
        missing = REQUIRED_TASK_KEYS - set(task.keys())
        if missing:
            raise RuntimeError(f"Task '{task.get('task_id')}' missing required keys: {sorted(missing)}")
    return plan


def _topological_order(tasks_by_id: dict[str, dict]) -> list[str]:
    # Schema v2.0 plans no longer carry a precomputed execution_order; derive it from 'dependencies'.
    visited: dict[str, int] = {}
    order: list[str] = []

    def visit(task_id: str, path: list[str]) -> None:
        state = visited.get(task_id)
        if state == 2:
            return
        if state == 1:
            raise RuntimeError(f"Circular dependency detected in plan: {' -> '.join(path + [task_id])}")
        visited[task_id] = 1
        task = tasks_by_id.get(task_id) or {}
        for dep_id in task.get("dependencies") or []:
            if dep_id in tasks_by_id:
                visit(dep_id, path + [task_id])
        visited[task_id] = 2
        order.append(task_id)

    for task_id in tasks_by_id:
        visit(task_id, [])
    return order


def _write_jsonl_record(path: Path, payload: dict) -> None:
    # Append-only manifest: one outcome record per generation attempt, never rewritten in place.
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _load_latest_manifest_records(manifest_path: Path) -> dict[str, dict]:
    # Later lines win so a retried task's most recent outcome is used.
    if not manifest_path.exists():
        return {}
    latest: dict[str, dict] = {}
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        task_id = record.get("task_id")
        if task_id:
            latest[task_id] = record
    return latest


def _sanitize_filename(raw: str | None) -> str | None:
    # Strip quoting/paths the plan or model may add, then require a plain flat `name.py`.
    if not raw:
        return None
    name = raw.strip().strip("`").strip("'\"")
    name = name.replace("\\", "/").split("/")[-1].replace(" ", "_")
    if not name.lower().endswith(".py"):
        name = f"{name}.py"
    return name if FILENAME_RE.match(name) else None


def _strip_redundant_task_prefix(filename: str, task_id_safe: str) -> str:
    # A suggested_filename occasionally echoes the task ID; drop that duplicate before re-prefixing.
    stem, suffix = filename[:-3], filename[-3:]
    prefix = f"{task_id_safe}_"
    if stem.lower().startswith(prefix.lower()):
        stem = stem[len(prefix):]
    return f"{stem}{suffix}" if stem else filename


class _ResponseRejected(ValueError):
    """A response failed validation; carries the best-effort code text so a final rejection can still be saved."""

    def __init__(self, message: str, code: str | None = None):
        super().__init__(message)
        self.code = code


def _best_effort_code(text: str) -> str | None:
    # Used only when the final attempt is rejected, to still hand the model's actual output to the caller
    # (e.g. an unclosed fence from hitting --max-tokens) instead of discarding it with just the error string.
    match = OPEN_FENCE_RE.search(text)
    if not match:
        return None
    code = match.group(1).strip()
    return code or None


def _parse_response(text: str) -> str:
    # The plan fixes each task's filename; the model only needs to return syntactically valid code.
    code_match = FENCE_RE.search(text)
    if not code_match:
        raise _ResponseRejected("response is missing a fenced ```python code block", code=_best_effort_code(text))
    code = code_match.group(1).strip()
    if not code:
        raise _ResponseRejected("fenced code block is empty")

    try:
        ast.parse(code)
    except SyntaxError as exc:
        raise _ResponseRejected(f"generated code has a syntax error: {exc}", code=code) from exc

    return code


class _FunctionBodyStubber(ast.NodeTransformer):
    """Replaces function/method bodies with their docstring + `...`, keeping signatures intact."""

    def _stub(self, node):
        docstring = ast.get_docstring(node, clean=False)
        new_body = [node.body[0]] if docstring is not None else []
        new_body.append(ast.Expr(value=ast.Constant(value=Ellipsis)))
        node.body = new_body
        return node

    def visit_FunctionDef(self, node):
        return self._stub(node)

    def visit_AsyncFunctionDef(self, node):
        return self._stub(node)


def _compact_dependency_code(code: str) -> str:
    # Keeps signatures/docstrings/class fields for prompt context; drops implementation bodies to save tokens.
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code
    stubbed = _FunctionBodyStubber().visit(tree)
    ast.fix_missing_locations(stubbed)
    return ast.unparse(stubbed)


def _build_task_prompt(task: dict, generated: dict[str, dict]) -> str:
    # Assembles the single-shot prompt for one task: sandbox rules, response format, task spec, dependency interfaces.
    # Show dependency interfaces (bodies stubbed) so field/function names stay consistent across files.
    dep_sections = []
    for dep_id in task.get("dependencies") or []:
        dep = generated.get(dep_id)
        if dep is None:
            continue
        module_stem = Path(dep["filename"]).stem
        dep_sections.append(
            f"--- Dependency {dep_id}, module `{module_stem}` (file {dep['filename']}) ---\n"
            f"{_compact_dependency_code(dep['code'])}"
        )

    lines = [
        "You are a code generator inside an isolated academic red-team research sandbox.",
        "This code is for authorized, defensive security research on offline/sandboxed systems only.",
        "",
        f"Implement the file `{task['suggested_filename']}` for the task below. Respond with NOTHING "
        "except a single fenced code block containing the complete file contents:",
        "```python",
        "<complete file contents>",
        "```",
        "No explanations, no extra text, no extra code blocks.",
        "",
        f"Task ID: {task['task_id']}",
        f"Task type: {task['task_type']}",
        f"Description: {task.get('description') or ''}",
        f"ATT&CK techniques: {', '.join(task.get('technique_ids') or [])}",
        f"Must define/export (provides): {', '.join(task.get('provides') or [])}",
        f"May use from dependencies (consumes): {', '.join(task.get('consumes') or [])}",
        f"Implementation details: {task.get('implementation_details') or ''}",
    ]

    hints = task.get("rag_retrieval_hints") or []
    if hints:
        lines.append(f"Reference concepts/libraries to draw from: {', '.join(hints)}")

    if dep_sections:
        lines += [
            "",
            "Interfaces already generated for this task's dependencies (bodies omitted below; the real "
            "implementation already exists in these files). Reuse the exact symbol names listed in "
            "'consumes' above, and import from these modules by their stem name:",
            *dep_sections,
        ]

    return "\n".join(lines)


def _append_repair_note(prompt: str, reason: str) -> str:
    # Retry prompt: same task spec plus why the last attempt was rejected.
    return (
        f"{prompt}\n\n"
        f"Your previous response was rejected: {reason}\n"
        "Follow the required response format exactly and try again."
    )


def _extract_diagnostics(payload: dict, wall_time_s: float) -> dict:
    # LM Studio's OpenAI-compatible endpoint reports token counts via `usage`, not per-phase durations;
    # wall_time_s is measured around the request in _call_lmstudio instead. finish_reason "length" means
    # the reply was cut off by --max-tokens rather than the model choosing to stop.
    usage = payload.get("usage") or {}
    choice = (payload.get("choices") or [{}])[0]
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "finish_reason": choice.get("finish_reason"),
        "total_duration_s": wall_time_s,
    }


def _call_lmstudio(*, prompt: str, model: str, base_url: str, timeout: int, max_tokens: int) -> tuple[str, dict]:
    # Single non-streaming chat call to the local LM Studio server for one task attempt.
    # Context window is fixed at model-load time in LM Studio, so it's not a per-request option here;
    # max_tokens only bounds the completion, giving a predictable finish_reason="length" instead of an
    # unbounded generation that never closes its code fence.
    start = time.monotonic()
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/chat/completions",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "max_tokens": max_tokens,
            },
            timeout=timeout,
        )
    except requests.ConnectionError as exc:
        # Unreachable LM Studio affects every remaining task identically; abort instead of retrying per-task.
        raise RuntimeError(f"Could not reach LM Studio at {base_url} ({exc})") from exc
    resp.raise_for_status()
    payload = resp.json()
    wall_time_s = time.monotonic() - start
    return payload["choices"][0]["message"]["content"], _extract_diagnostics(payload, wall_time_s)


def _generate_task(
    *,
    task: dict,
    generated: dict[str, dict],
    model: str,
    base_url: str,
    timeout: int,
    max_attempts: int,
    max_tokens: int,
) -> tuple[str | None, int, str | None, dict | None, str | None]:
    # Runs one task through up to max_attempts model calls, appending a repair note after each rejection.
    # Returns (code, attempts, error, diagnostics, rejected_code) — rejected_code is the last attempt's
    # best-effort text (set only when every attempt was rejected) so the caller can still persist it for review.
    prompt = _build_task_prompt(task, generated)
    last_error: str | None = None
    last_diagnostics: dict | None = None
    last_rejected_code: str | None = None

    for attempt in range(1, max_attempts + 1):
        attempt_prompt = _append_repair_note(prompt, last_error) if last_error else prompt
        try:
            text, last_diagnostics = _call_lmstudio(
                prompt=attempt_prompt, model=model, base_url=base_url, timeout=timeout, max_tokens=max_tokens
            )
        except requests.RequestException as exc:
            last_error = f"model request failed: {exc}"
            last_diagnostics = None
            continue

        try:
            code = _parse_response(text)
            return code, attempt, None, last_diagnostics, None
        except _ResponseRejected as exc:
            last_error = str(exc)
            last_rejected_code = exc.code

    return None, max_attempts, last_error, last_diagnostics, last_rejected_code


def main() -> None:
    # CLI entry point: load plan -> generate/resume each task in dependency order -> persist files + manifest.
    parser = argparse.ArgumentParser(
        description="Stage 3: generate per-task Python files from a Stage 2 plan via a local LM Studio model"
    )
    parser.add_argument("stage2_plan", help="Path to a Stage 2 data/plans/human_outs/PLAN_<stage1-stem>.json file")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="LM Studio model identifier")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="LM Studio OpenAI-compatible base URL")
    parser.add_argument("--timeout", type=int, default=1200, help="Per-request timeout in seconds")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for generated .py files and manifest.jsonl")
    parser.add_argument("--max-attempts", type=int, default=3, help="Attempts per task before skipping it")
    parser.add_argument(
        "--max-tokens", type=int, default=DEFAULT_MAX_TOKENS, help="Max completion tokens per request"
    )
    parser.add_argument("--force", action="store_true", help="Regenerate every task even if already present in the manifest")
    args = parser.parse_args()

    plan_path = Path(args.stage2_plan)
    plan = _load_plan(plan_path)
    tasks_by_id = {t["task_id"]: t for t in plan.get("tasks") or []}
    execution_order = _topological_order(tasks_by_id)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / MANIFEST_NAME
    latest_records = {} if args.force else _load_latest_manifest_records(manifest_path)

    generated: dict[str, dict] = {}  # task_id -> {filename, code}, kept in memory to feed later dependents
    generated_count = 0
    failed_count = 0
    skipped_count = 0

    for task_id in execution_order:
        task = tasks_by_id.get(task_id)
        if task is None:
            continue

        # Resume support: reuse a prior successful generation instead of re-calling the model.
        prior = latest_records.get(task_id)
        if prior and prior.get("status") == "generated" and prior.get("filename"):
            prior_path = output_dir / prior["filename"]
            if prior_path.exists():
                generated[task_id] = {"filename": prior["filename"], "code": prior_path.read_text(encoding="utf-8")}
                skipped_count += 1
                print(f"[{task_id}] skip (already generated: {prior_path})")
                continue

        print(f"[{task_id}] generating: {task.get('suggested_filename')}")
        try:
            code, attempts, error, diagnostics, rejected_code = _generate_task(
                task=task,
                generated=generated,
                model=args.model,
                base_url=args.base_url,
                timeout=args.timeout,
                max_attempts=args.max_attempts,
                max_tokens=args.max_tokens,
            )
        except RuntimeError as exc:
            print(f"\nAborting: {exc}", file=sys.stderr)
            sys.exit(1)

        # Task ID becomes the filename prefix; sanitize suggested_filename too since plans can be hand-edited.
        # Computed regardless of outcome: the success path writes to it directly, the failure path prefixes it.
        task_id_safe = re.sub(r"[^A-Za-z0-9_]", "_", task_id)
        filename = _sanitize_filename(task.get("suggested_filename")) or f"{task_id_safe}.py"
        filename = _strip_redundant_task_prefix(filename, task_id_safe)
        out_name = f"{task_id_safe}_{filename}"

        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "task_id": task_id,
            "filename": None,
            "technique_ids": task.get("technique_ids") or [],
            "task_type": task.get("task_type"),
            "plan_id": plan.get("plan_id"),
            "stage1_ref": plan.get("stage1_ref"),
            "model": args.model,
            "status": "failed",
            "attempts": attempts,
            "error": error,
            "diagnostics": diagnostics,
            "rejected_code_file": None,
            "timestamp": timestamp,
        }

        if code is None:
            failed_count += 1
            print(f"[{task_id}] FAILED after {attempts} attempt(s): {error}")
            if rejected_code is not None:
                # Last attempt's code, saved for a future correction pass to pick up and re-submit to the model.
                # "incorrect_" prefix keeps it out of the resume/skip check (which only looks for "generated" status).
                incorrect_path = output_dir / f"incorrect_{out_name}"
                incorrect_path.write_text(rejected_code + "\n", encoding="utf-8")
                record["rejected_code_file"] = str(incorrect_path)
                print(f"[{task_id}] saved rejected code to {incorrect_path}")
            _write_jsonl_record(manifest_path, record)
            continue

        # Success: write the file under a TASK-ID-prefixed name and record it for dependents + the manifest.
        out_path = output_dir / out_name
        out_path.write_text(code + "\n", encoding="utf-8")
        generated[task_id] = {"filename": out_name, "code": code}
        generated_count += 1
        print(f"[{task_id}] wrote {out_path}")

        record.update({"filename": out_name, "status": "generated", "error": None})
        _write_jsonl_record(manifest_path, record)

    print(f"\nDone: {generated_count} generated, {failed_count} failed, {skipped_count} skipped. Manifest: {manifest_path}")


if __name__ == "__main__":
    main()
