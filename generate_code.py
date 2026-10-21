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

from pipeline_ast import (
    collect_module_level_defs,
    collect_module_level_imports,
    collect_optional_dependency_fallback_names,
    collect_referenced_names,
    sibling_stem_from_import,
)

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


def _dependency_module_stems(task: dict, generated: dict[str, dict]) -> dict[str, str]:
    # Real output module stem per declared dependency, for dependencies already generated.
    stems: dict[str, str] = {}
    for dep_id in task.get("dependencies") or []:
        dep = generated.get(dep_id)
        if dep is not None:
            stems[dep_id] = Path(dep["filename"]).stem
    return stems


def _build_task_prompt(task: dict, generated: dict[str, dict]) -> str:
    # Assembles the single-shot prompt for one task: sandbox rules, response format, task spec, dependency interfaces.
    # Show dependency interfaces (bodies stubbed) so field/function names stay consistent across files.
    dep_stems = _dependency_module_stems(task, generated)
    dep_sections = []
    for dep_id in task.get("dependencies") or []:
        dep = generated.get(dep_id)
        if dep is None:
            continue
        dep_sections.append(
            f"--- Dependency {dep_id}, module `{dep_stems[dep_id]}` (file {dep['filename']}) ---\n"
            f"{_compact_dependency_code(dep['code'])}"
        )

    lines = [
        "You are a code generator inside an isolated academic red-team research sandbox.",
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

    # Add explicit import instructions for consumed symbols from dependencies.
    consumes = task.get("consumes") or []
    dependencies = task.get("dependencies") or []
    if consumes and dependencies:
        lines += [
            "",
            "IMPORT REQUIREMENTS: For each symbol you consume, add a corresponding import statement at the top of your file.",
            "Map each consumed symbol to the dependency module that provides it, using this format:",
            "  from TASK_NNN_module_name import symbol_name",
        ]
        import_map = dep_stems

        if import_map:
            lines += ["", "Dependency module mappings:"]
            for dep_id, module_stem in import_map.items():
                lines.append(f"  {dep_id} → {module_stem}")
            lines.append("")
            lines.append(
                "CRITICAL: You must have an import statement for EACH symbol in 'consumes' at the top of your file, "
                "BEFORE any code that uses those symbols. Missing imports will cause runtime NameError."
            )

    # Add cross-task narrative context from Stage 2.5 enhancement (if present).
    scenario = task.get("scenario_context")
    if scenario:
        lines += [
            "",
            "Context within the attack chain (from plan enhancement):",
            f"  - Narrative role: {scenario.get('narrative_role', '')}",
            f"  - Upstream assumptions: {scenario.get('upstream_assumptions', '')}",
            f"  - Downstream contract: {scenario.get('downstream_contract', '')}",
            f"  - Consistency notes: {scenario.get('consistency_notes', '')}",
            f"  - Out of scope: {scenario.get('non_goals', '')}",
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


def _resolve_symbol_sources(task: dict, tasks_by_id: dict[str, dict], dep_stems: dict[str, str]) -> dict[str, str]:
    # Which dependency's module actually provides each symbol, per the plan (not the generated
    # code). Shared by the contract check below and the deterministic import injector, so both
    # agree on exactly where a consumed symbol is supposed to come from. Known limitation, accepted:
    # a dependency missing from `dep_stems` (failed to generate) leaves its provided symbols with
    # no entry here, so a caller can't fix or flag an import of them against a real module.
    symbol_source: dict[str, str] = {}
    for dep_id in task.get("dependencies") or []:
        dep_stem = dep_stems.get(dep_id)
        if dep_stem is None:
            continue
        for symbol in (tasks_by_id.get(dep_id) or {}).get("provides") or []:
            symbol_source.setdefault(symbol, dep_stem)
    return symbol_source


def _inject_dependency_imports(code: str, task: dict, tasks_by_id: dict[str, dict], dep_stems: dict[str, str]) -> str:
    # Deterministically fixes sibling imports instead of hoping the model gets them right: the plan's
    # provides/consumes edges plus each dependency's real on-disk stem already say exactly what every
    # sibling import line must be, so there's no need to ask a 9B model to get that right and then
    # just check it. Removes whatever top-level `from <sibling> import ...` line(s) the model wrote
    # for this task's dependencies — recognizing any of the three forms seen in practice (portable
    # bare stem, repo-root-anchored dotted path, or a relative import) — then prepends one canonical
    # `from <stem> import <symbols>` line per dependency actually consumed, grouped and ordered by
    # the plan's own 'consumes' list. Operates on exact source line ranges so every untouched line
    # (comments, formatting, unrelated imports, code) survives byte-for-byte. Only direct top-level
    # ImportFrom statements are touched — one nested in a try/except (a pattern the Stage 3 prompt
    # doesn't ask for) is left alone rather than risk mangling a deliberate fallback block; worst
    # case that symbol ends up imported twice, which is harmless. Falls back to the original code
    # untouched if there's nothing safe to inject, or if the rewritten result would fail to parse —
    # this patch is never allowed to be the thing that breaks an otherwise-valid file.
    consumes = task.get("consumes") or []
    if not consumes or not dep_stems:
        return code

    symbol_source = _resolve_symbol_sources(task, tasks_by_id, dep_stems)
    known_stems = set(dep_stems.values())

    symbols_by_stem: dict[str, list[str]] = {}
    for symbol in consumes:
        stem = symbol_source.get(symbol)
        if stem is not None:
            symbols_by_stem.setdefault(stem, []).append(symbol)
    if not symbols_by_stem:
        return code  # no consumed symbol maps to a known dependency; nothing safe to inject

    canonical_lines = [f"from {stem} import {', '.join(symbols)}" for stem, symbols in symbols_by_stem.items()]

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code  # _parse_response already guarantees this parses; defensive only

    delete_ranges: list[tuple[int, int]] = []
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            stem = sibling_stem_from_import(node.module, node.level, known_stems)
            if stem is not None:
                delete_ranges.append((node.lineno, node.end_lineno))

    lines = code.splitlines()
    delete_line_nos = {ln for start, end in delete_ranges for ln in range(start, end + 1)}
    kept_lines = [line for i, line in enumerate(lines, start=1) if i not in delete_line_nos]

    # Insert right after the module docstring (if any) and any `from __future__` imports — matching
    # where Python requires __future__ imports to stay, and where the model's own docstring (if any)
    # starts the file. Neither can ever fall inside delete_line_nos (a docstring/__future__ import is
    # never itself a sibling import), so translating this position into kept_lines is always safe.
    insert_at = 0
    first = tree.body[0] if tree.body else None
    if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
        insert_at = first.end_lineno or 0
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insert_at = max(insert_at, node.end_lineno or 0)
    kept_insert_at = sum(1 for i in range(1, insert_at + 1) if i not in delete_line_nos)

    new_lines = kept_lines[:kept_insert_at] + canonical_lines + kept_lines[kept_insert_at:]
    new_code = "\n".join(new_lines)

    try:
        ast.parse(new_code)
    except SyntaxError:
        return code  # self-check failed; prefer the model's original over a corrupted patch

    return new_code


def _validate_contract(code: str, task: dict, tasks_by_id: dict[str, dict], dep_stems: dict[str, str]) -> None:
    # Enforces the plan's provides/consumes contract end-to-end: a symbol this task promises must
    # actually be defined (an import alone doesn't make it this task's provider), and a symbol it
    # borrows must be imported from the specific dependency that actually provides it — not
    # redeclared, not left unbound, and not sourced from the wrong module. Runs after
    # _inject_dependency_imports, so the sibling-import half of this is normally already fixed by
    # construction; this remains the backstop for what injection can't fix — a symbol no dependency
    # actually provides, or one redeclared locally despite being marked consumed.
    tree = ast.parse(code)
    defined = collect_module_level_defs(tree)
    imported_from, has_star = collect_module_level_imports(tree)
    referenced = collect_referenced_names(tree)
    fallback_names = collect_optional_dependency_fallback_names(tree)
    symbol_source = _resolve_symbol_sources(task, tasks_by_id, dep_stems)

    violations: list[str] = []

    for symbol in task.get("provides") or []:
        if symbol in fallback_names:
            # `try: from fast_impl import X / except ImportError: def X(): ...` — a deliberate
            # either/or, not the ambiguous "defined and imported at the same level" case below.
            continue
        is_defined = symbol in defined
        is_imported = symbol in imported_from
        if is_defined and is_imported:
            violations.append(
                f"`{symbol}` is declared in provides but is both locally defined and imported "
                f"(from `{imported_from[symbol]}`) — ambiguous; keep only the local definition"
            )
        elif is_imported:
            violations.append(
                f"`{symbol}` is declared in provides but only imported (from `{imported_from[symbol]}`), "
                "never defined — importing a symbol doesn't make this task its provider"
            )
        elif not is_defined:
            violations.append(f"`{symbol}` is declared in provides but never defined anywhere in the file")

    if not has_star:
        for symbol in task.get("consumes") or []:
            is_defined = symbol in defined
            is_imported = symbol in imported_from
            correct_module = symbol_source.get(symbol)
            target = f"`{correct_module}`" if correct_module else "the dependency that provides it"

            if is_defined and is_imported:
                violations.append(
                    f"`{symbol}` is declared in consumes but is both locally defined and imported "
                    f"(from `{imported_from[symbol]}`) — ambiguous; keep only the import from {target}"
                )
            elif is_defined:
                violations.append(
                    f"`{symbol}` is redeclared instead of imported — remove this definition and add "
                    f"`from {correct_module or '<dependency module>'} import {symbol}` instead"
                )
            elif is_imported:
                actual_module = imported_from[symbol]
                if correct_module and actual_module != correct_module:
                    violations.append(
                        f"`{symbol}` is imported from `{actual_module}` instead of {target} — "
                        "use the bare module stem so the import resolves regardless of working directory"
                    )
            elif symbol in referenced:
                violations.append(
                    f"`{symbol}` is used without being imported or defined (NameError at runtime) — "
                    f"import it from {target}"
                )

    if violations:
        raise _ResponseRejected(
            "generated code violates the plan's provides/consumes contract: " + "; ".join(violations),
            code=code,
        )


def _generate_task(
    *,
    task: dict,
    generated: dict[str, dict],
    tasks_by_id: dict[str, dict],
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
            dep_stems = _dependency_module_stems(task, generated)
            code = _inject_dependency_imports(code, task, tasks_by_id, dep_stems)
            _validate_contract(code, task, tasks_by_id, dep_stems)
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
                tasks_by_id=tasks_by_id,
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
