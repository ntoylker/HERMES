"""Stage 4a: pre-sandbox static validator. Compiles and resolves imports for every generated
Python file in a Stage 3 run directory — no code is ever executed here. Meant to run after Stage 3
and before any dynamic execution (the Tier 1 container smoke-run, then Cuckoo/CAPE), so cheap,
deterministic checks catch what they can before paying for an execution environment. Covers both
manifest-tracked generator output and files that were hand-edited afterward (no manifest entry).
"""

import argparse
import ast
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from pipeline_ast import (
    collect_module_level_defs,
    collect_module_level_imports,
    iter_all_import_statements,
    sibling_stem_from_import,
)

VALIDATION_MANIFEST_NAME = "validation_manifest.jsonl"
GENERATE_MANIFEST_NAME = "manifest.jsonl"
REJECTED_PREFIX = "incorrect_"


def _load_stage2_plan(path: Path) -> dict:
    # Reuses Stage 3's own plan-shape validation so both stages agree on what a valid plan looks like.
    from generate_code import _load_plan

    return _load_plan(path)


def _load_latest_generation_records(manifest_path: Path) -> dict[str, dict]:
    # Same "later line wins" dedup as generate_code.py's own manifest reader. Kept local rather than
    # imported: each stage's manifest handling is self-contained by convention in this pipeline
    # (Stage 2.5 does the same instead of sharing Stage 2/3's manifest I/O).
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


def _resolve_candidates(run_dir: Path, tasks_by_id: dict[str, dict], include_rejected: bool) -> list[dict]:
    # One entry per file to validate: {"path": Path, "task_id": str | None, "stem": str}. Prefers
    # the generation manifest (status == "generated") when present; any .py file in the directory
    # not accounted for there is still validated ("untracked" — covers hand-edited files that never
    # went through generate_code.py at all), with its task_id recovered by filename-prefix match
    # against a supplied plan when possible, so the provides/consumes check still applies to it too.
    candidates: dict[str, dict] = {}

    manifest_path = run_dir / GENERATE_MANIFEST_NAME
    for task_id, record in _load_latest_generation_records(manifest_path).items():
        if record.get("status") != "generated":
            continue
        filename = record.get("filename")
        if not filename:
            continue
        path = run_dir / filename
        if path.exists():
            candidates[filename] = {"path": path, "task_id": task_id, "stem": path.stem}

    for path in sorted(run_dir.glob("*.py")):
        if path.name in candidates:
            continue
        if not include_rejected and path.name.startswith(REJECTED_PREFIX):
            continue
        task_id = None
        for candidate_id in tasks_by_id:
            if path.stem == candidate_id or path.stem.startswith(f"{candidate_id}_"):
                task_id = candidate_id
                break
        candidates[path.name] = {"path": path, "task_id": task_id, "stem": path.stem}

    return sorted(candidates.values(), key=lambda c: (c["task_id"] or "~untracked", c["path"].name))


def _finding(level: str, category: str, message: str) -> dict:
    return {"level": level, "category": category, "message": message}


def _check_file(
    candidate: dict,
    all_stems: set[str],
    parsed_cache: dict[str, ast.Module],
    spec_cache: dict[str, bool],
) -> dict:
    # L1 (compile) -> L2/L3 (import classification + resolution) -> L3b (sibling symbol existence).
    # Returns {"verdict": "pass"|"warn"|"fail", "findings": [...], "missing_dependencies": [...]}.
    path: Path = candidate["path"]
    findings: list[dict] = []
    missing_deps: set[str] = set()

    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return {"verdict": "fail", "findings": [_finding("fail", "read_error", str(exc))], "missing_dependencies": []}

    # L1: compile() is a strict superset of ast.parse() — it also catches things pure grammar
    # accepts but CPython doesn't, e.g. `return`/`yield`/`continue`/`break` outside a context that
    # allows them (ast.parse("return 1") succeeds; compile("return 1", ..., "exec") does not).
    try:
        compile(source, str(path), "exec")
    except SyntaxError as exc:
        msg = f"{exc.msg} (line {exc.lineno}, col {exc.offset})"
        return {"verdict": "fail", "findings": [_finding("fail", "compile_error", msg)], "missing_dependencies": []}

    tree = ast.parse(source)
    parsed_cache[candidate["stem"]] = tree

    # L2/L3: every import anywhere in the file (not just module scope — a third-party import inside
    # a function still needs the package installed) classified as stdlib / sibling / third-party.
    for node in iter_all_import_statements(tree):
        if isinstance(node, ast.ImportFrom):
            stem = sibling_stem_from_import(node.module, node.level, all_stems)
            if node.level > 0 and stem is None:
                findings.append(_finding(
                    "fail", "relative_import",
                    "relative import (no sibling module resolved) — raises ImportError when this "
                    "file is run directly, since it has no parent package",
                ))
                continue
            if stem is not None:
                if not (path.parent / f"{stem}.py").exists():
                    findings.append(_finding(
                        "fail", "missing_sibling",
                        f"imports sibling module `{stem}`, but `{stem}.py` does not exist in this run directory",
                    ))
                elif node.level == 0 and node.module and "." in node.module:
                    findings.append(_finding(
                        "warn", "non_portable_import",
                        f"imports `{stem}` via the repo-root-anchored path `{node.module}`, which only "
                        "resolves when launched with the repo root on sys.path — use the bare module "
                        f"stem (`from {stem} import ...`) instead",
                    ))
                continue
            top_levels = [node.module.split(".")[0]] if node.module else []
        else:  # ast.Import — may bind several modules in one statement (`import os, sys`)
            top_levels = [alias.name.split(".")[0] for alias in node.names]

        for top_level in top_levels:
            if not top_level or top_level in sys.stdlib_module_names:
                continue
            if top_level not in spec_cache:
                try:
                    spec_cache[top_level] = importlib.util.find_spec(top_level) is not None
                except (ImportError, ValueError):
                    spec_cache[top_level] = False
            if not spec_cache[top_level]:
                missing_deps.add(top_level)
                findings.append(_finding(
                    "fail", "missing_dependency",
                    f"third-party import `{top_level}` is not installed in this environment",
                ))

    # L3b: for a sibling `from X import a, b`, confirm X actually has that attribute — anything
    # that becomes a real attribute on the sibling module object (its own def, assignment, or
    # import), not just a top-level def, since that's what "from X import a" actually needs.
    for node in tree.body:
        if not isinstance(node, ast.ImportFrom):
            continue
        stem = sibling_stem_from_import(node.module, node.level, all_stems)
        if stem is None or not (path.parent / f"{stem}.py").exists():
            continue
        sibling_tree = parsed_cache.get(stem)
        if sibling_tree is None:
            try:
                sibling_tree = ast.parse((path.parent / f"{stem}.py").read_text(encoding="utf-8"))
            except (OSError, SyntaxError):
                continue
            parsed_cache[stem] = sibling_tree
        sib_defs = collect_module_level_defs(sibling_tree)
        sib_imports, sib_has_star = collect_module_level_imports(sibling_tree)
        if sib_has_star:
            findings.append(_finding(
                "warn", "unverifiable_sibling",
                f"cannot verify symbols imported from `{stem}` because it uses `from ... import *`",
            ))
            continue
        available = sib_defs | set(sib_imports)
        for alias in node.names:
            if alias.name != "*" and alias.name not in available:
                findings.append(_finding(
                    "fail", "missing_symbol",
                    f"`{alias.name}` is imported from `{stem}`, but `{stem}.py` defines no such name "
                    "— ImportError at runtime",
                ))

    # Dedup (e.g. the same missing sibling referenced by two separate import lines).
    findings = list({f["message"]: f for f in findings}.values())
    levels = {f["level"] for f in findings}
    verdict = "fail" if "fail" in levels else ("warn" if "warn" in levels else "pass")
    return {"verdict": verdict, "findings": findings, "missing_dependencies": sorted(missing_deps)}


def _check_contract(source: str, task: dict, tasks_by_id: dict, dep_stems: dict[str, str]) -> list[dict]:
    # Same provides/consumes policy as generate_code.py's _validate_contract, applied post-hoc to
    # whatever is actually on disk — including files that never went through that generation-time
    # check at all (a hand-edited run). Reuses the policy function itself so the two never drift.
    from generate_code import _ResponseRejected, _validate_contract

    try:
        _validate_contract(source, task, tasks_by_id, dep_stems)
    except _ResponseRejected as exc:
        return [_finding("fail", "contract_violation", str(exc))]
    return []


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage 4a: static pre-flight validation (compile + import resolution) for a Stage 3 run directory"
    )
    parser.add_argument("run_dir", help="Directory of generated .py files (a data/code_scripts/<run> directory)")
    parser.add_argument("--plan", help="Optional Stage 2 plan JSON; enables the provides/consumes contract check")
    parser.add_argument("--include-rejected", action="store_true", help="Also validate incorrect_*.py rejected drafts")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        print(f"Not a directory: {run_dir}", file=sys.stderr)
        sys.exit(1)

    tasks_by_id: dict[str, dict] = {}
    if args.plan:
        plan = _load_stage2_plan(Path(args.plan))
        tasks_by_id = {t["task_id"]: t for t in plan.get("tasks") or []}

    candidates = _resolve_candidates(run_dir, tasks_by_id, args.include_rejected)
    if not candidates:
        print(f"No .py files found to validate in {run_dir}")
        sys.exit(0)

    all_stems = {c["stem"] for c in candidates}
    dep_stems_all = {c["task_id"]: c["stem"] for c in candidates if c["task_id"]}

    manifest_path = run_dir / VALIDATION_MANIFEST_NAME
    parsed_cache: dict[str, ast.Module] = {}
    spec_cache: dict[str, bool] = {}
    pass_count = warn_count = fail_count = 0
    all_missing_deps: set[str] = set()

    for candidate in candidates:
        result = _check_file(candidate, all_stems, parsed_cache, spec_cache)

        task = tasks_by_id.get(candidate["task_id"]) if candidate["task_id"] else None
        if task is not None and result["verdict"] != "fail":
            # Skip the contract check once L1 already failed — there's no clean tree to check anyway.
            source = candidate["path"].read_text(encoding="utf-8")
            contract_findings = _check_contract(source, task, tasks_by_id, dep_stems_all)
            if contract_findings:
                result["findings"].extend(contract_findings)
                result["verdict"] = "fail"

        all_missing_deps.update(result["missing_dependencies"])
        if result["verdict"] == "fail":
            fail_count += 1
        elif result["verdict"] == "warn":
            warn_count += 1
        else:
            pass_count += 1

        glyph = {"pass": "OK", "warn": "WARN", "fail": "FAIL"}[result["verdict"]]
        label = candidate["task_id"] or "untracked"
        print(f"[{label}] {glyph}: {candidate['path'].name}")
        for finding in result["findings"]:
            print(f"    - ({finding['level']}) {finding['message']}")

        record = {
            "run_dir": str(run_dir),
            "task_id": candidate["task_id"],
            "filename": candidate["path"].name,
            "verdict": result["verdict"],
            "findings": result["findings"],
            "missing_dependencies": result["missing_dependencies"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\nDone: {pass_count} passed, {warn_count} warned, {fail_count} failed. Manifest: {manifest_path}")
    if all_missing_deps:
        print(f"Missing third-party dependencies across this run: {', '.join(sorted(all_missing_deps))}")

    sys.exit(1 if fail_count else 0)


if __name__ == "__main__":
    main()
