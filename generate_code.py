"""Stage 3 code generator: turn a Stage 2 task plan into per-task Python files.

Each task is sent to a local Ollama model as one independent chat request. The model
must reply with only a filename line and a single fenced code block; this module
parses, syntax-checks, and persists that response, then moves to the next task.
"""

import argparse
import ast
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "huihui_ai/Qwen3.8-abliterated:latest"
DEFAULT_OUTPUT_DIR = "data/code_scripts"
MANIFEST_NAME = "manifest.jsonl"

FILENAME_RE = re.compile(r"^[A-Za-z0-9_]+\.py$")
FILENAME_LINE_RE = re.compile(r"FILENAME:\s*(\S+)", re.IGNORECASE)
FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def _load_plan(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"Missing Stage 2 plan file: {path}")
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan.get("planning_status") != "valid":
        raise RuntimeError(
            f"Plan status is '{plan.get('planning_status')}', not 'valid'; nothing to generate."
        )
    return plan


def _write_jsonl_record(path: Path, payload: dict) -> None:
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
    if not raw:
        return None
    name = raw.strip().strip("`").strip("'\"")
    name = name.replace("\\", "/").split("/")[-1].replace(" ", "_")
    if not name.lower().endswith(".py"):
        name = f"{name}.py"
    return name if FILENAME_RE.match(name) else None


def _parse_response(text: str) -> tuple[str, str]:
    match = FILENAME_LINE_RE.search(text)
    if not match:
        raise ValueError("response is missing a 'FILENAME: <name>.py' line")
    filename = _sanitize_filename(match.group(1))
    if filename is None:
        raise ValueError(f"filename '{match.group(1).strip()}' is not a valid simple '<name>.py'")

    code_match = FENCE_RE.search(text)
    if not code_match:
        raise ValueError("response is missing a fenced ```python code block")
    code = code_match.group(1).strip()
    if not code:
        raise ValueError("fenced code block is empty")

    try:
        ast.parse(code)
    except SyntaxError as exc:
        raise ValueError(f"generated code has a syntax error: {exc}") from exc

    return filename, code


def _build_task_prompt(task: dict, generated: dict[str, dict]) -> str:
    # Show already-generated dependency code so field/function names stay consistent across files.
    dep_sections = []
    for dep_id in task.get("depends_on") or []:
        dep = generated.get(dep_id)
        if dep is None:
            continue
        module_stem = Path(dep["filename"]).stem
        dep_sections.append(
            f"--- Dependency {dep_id}, module `{module_stem}` (file {dep['filename']}) ---\n{dep['code']}"
        )

    lines = [
        "You are a code generator inside an isolated academic research sandbox.",
        "All tasks are benign simulation/telemetry/data-model/test code for defensive research only: "
        "no real exploits, no persistence, no credential access, no live network or C2 behavior.",
        "",
        "Implement EXACTLY one task below. Respond with NOTHING except the required format:",
        "FILENAME: <short_snake_case_name>.py",
        "```python",
        "<complete file contents>",
        "```",
        "No explanations, no extra text, no extra code blocks.",
        "",
        f"Task ID: {task['task_id']}",
        f"Title: {task['title']}",
        f"Task type: {task['task_type']}",
        f"Language: {task.get('language') or 'python'}",
        f"Purpose: {task.get('purpose') or ''}",
        f"Maps to ATT&CK techniques: {', '.join(task.get('maps_to_techniques') or [])}",
        f"Inputs: {json.dumps(task.get('inputs') or [], ensure_ascii=False)}",
        f"Outputs: {json.dumps(task.get('outputs') or [], ensure_ascii=False)}",
        f"Constraints: {json.dumps(task.get('constraints') or [], ensure_ascii=False)}",
        f"Acceptance criteria: {json.dumps(task.get('acceptance_criteria') or [], ensure_ascii=False)}",
    ]

    if dep_sections:
        lines += [
            "",
            "Code already generated for this task's dependencies. Reuse the same field/function names "
            "for consistency; import from these modules by their stem name if useful:",
            *dep_sections,
        ]

    return "\n".join(lines)


def _append_repair_note(prompt: str, reason: str) -> str:
    return (
        f"{prompt}\n\n"
        f"Your previous response was rejected: {reason}\n"
        "Follow the required response format exactly and try again."
    )


def _call_ollama(*, prompt: str, model: str, base_url: str, timeout: int) -> str:
    try:
        resp = requests.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            },
            timeout=timeout,
        )
    except requests.ConnectionError as exc:
        # Unreachable Ollama affects every remaining task identically; abort instead of retrying per-task.
        raise RuntimeError(f"Could not reach Ollama at {base_url} ({exc})") from exc
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _generate_task(
    *,
    task: dict,
    generated: dict[str, dict],
    model: str,
    base_url: str,
    timeout: int,
    max_attempts: int,
) -> tuple[str | None, str | None, int, str | None]:
    prompt = _build_task_prompt(task, generated)
    last_error: str | None = None

    for attempt in range(1, max_attempts + 1):
        attempt_prompt = _append_repair_note(prompt, last_error) if last_error else prompt
        try:
            text = _call_ollama(prompt=attempt_prompt, model=model, base_url=base_url, timeout=timeout)
        except requests.RequestException as exc:
            last_error = f"model request failed: {exc}"
            continue

        try:
            filename, code = _parse_response(text)
            return filename, code, attempt, None
        except ValueError as exc:
            last_error = str(exc)

    return None, None, max_attempts, last_error


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage 3: generate per-task Python files from a Stage 2 plan via a local Ollama model"
    )
    parser.add_argument("stage2_plan", help="Path to a Stage 2 data/plans/human_outs/<timestamp>.json file")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Ollama base URL")
    parser.add_argument("--timeout", type=int, default=300, help="Per-request timeout in seconds")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Directory for generated .py files and manifest.jsonl")
    parser.add_argument("--max-attempts", type=int, default=2, help="Attempts per task before skipping it")
    parser.add_argument("--force", action="store_true", help="Regenerate every task even if already present in the manifest")
    args = parser.parse_args()

    plan_path = Path(args.stage2_plan)
    plan = _load_plan(plan_path)
    tasks_by_id = {t["task_id"]: t for t in plan.get("tasks") or []}
    execution_order = plan.get("execution_order") or list(tasks_by_id.keys())
    if not tasks_by_id:
        print("Plan has no tasks; nothing to generate.")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / MANIFEST_NAME
    latest_records = {} if args.force else _load_latest_manifest_records(manifest_path)

    generated: dict[str, dict] = {}
    generated_count = 0
    failed_count = 0
    skipped_count = 0

    for task_id in execution_order:
        task = tasks_by_id.get(task_id)
        if task is None:
            continue

        prior = latest_records.get(task_id)
        if prior and prior.get("status") == "generated" and prior.get("filename"):
            prior_path = output_dir / prior["filename"]
            if prior_path.exists():
                generated[task_id] = {"filename": prior["filename"], "code": prior_path.read_text(encoding="utf-8")}
                skipped_count += 1
                print(f"[{task_id}] skip (already generated: {prior_path})")
                continue

        print(f"[{task_id}] generating: {task.get('title')}")
        try:
            filename, code, attempts, error = _generate_task(
                task=task,
                generated=generated,
                model=args.model,
                base_url=args.base_url,
                timeout=args.timeout,
                max_attempts=args.max_attempts,
            )
        except RuntimeError as exc:
            print(f"\nAborting: {exc}", file=sys.stderr)
            sys.exit(1)

        timestamp = datetime.now(timezone.utc).isoformat()
        record = {
            "task_id": task_id,
            "filename": None,
            "maps_to_techniques": task.get("maps_to_techniques") or [],
            "task_type": task.get("task_type"),
            "language": task.get("language"),
            "plan_id": plan.get("plan_id"),
            "request_id": plan.get("request_id"),
            "model": args.model,
            "status": "failed",
            "attempts": attempts,
            "error": error,
            "timestamp": timestamp,
        }

        if filename is None:
            failed_count += 1
            print(f"[{task_id}] FAILED after {attempts} attempt(s): {error}")
            _write_jsonl_record(manifest_path, record)
            continue

        # Task ID becomes the filename prefix; sanitize it too since plan files can be hand-edited.
        task_id_safe = re.sub(r"[^A-Za-z0-9_]", "_", task_id)
        out_name = f"{task_id_safe}_{filename}"
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
