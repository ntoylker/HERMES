"""Tier 1: fast, disposable, network-isolated execution gate that runs strictly between Stage 4a's
static validator and any Cuckoo/CAPE submission. For each candidate file, imports it inside a
throwaway Docker container (no network, capped CPU/memory, read-only rootfs) and records whether
that import completed cleanly, raised, or hung past the wall-clock timeout. This is the "runs
without errors" floor oracle (rung 3/4 of the functional-code ladder) — it proves the file's
module-level code executes cleanly, not that its behavior is correct (that's Cuckoo/CAPE's job, and
eventually a richer per-task-type or self-test oracle's).
"""

import argparse
import json
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from validate_scripts import _load_stage2_plan, _resolve_candidates

TIER1_MANIFEST_NAME = "tier1_manifest.jsonl"
DEFAULT_IMAGE = "hermes-tier1-base:latest"
DEFAULT_TIMEOUT_S = 15
DEFAULT_MEMORY = "256m"
DEFAULT_CPUS = "1"


def _parse_sentinel(logs: str, sentinel: str) -> dict | None:
    # The in-container runner brackets its one-line JSON result with a per-run random sentinel, so it
    # can be found in the container's logs even if the imported module also printed to stdout/stderr.
    # Take the text between the first pair of sentinel markers.
    first = logs.find(sentinel)
    if first == -1:
        return None
    second = logs.find(sentinel, first + len(sentinel))
    if second == -1:
        return None
    try:
        return json.loads(logs[first + len(sentinel):second].strip())
    except json.JSONDecodeError:
        return None


def _run_container(
    *, image: str, run_dir: Path, filename: str, timeout_s: int, memory: str, cpus: str
) -> dict:
    # Runs detached (not --rm) so this function fully controls cleanup itself: `docker wait` with a
    # timeout, `docker kill` on a hang, recover the result from `docker logs`, then an explicit
    # `docker rm -f` in every case. The result travels on the container's stdout (a sentinel-wrapped
    # JSON line), not a shared file: a host bind mount on Docker Desktop can hand back a file the host
    # user can't read, and `docker cp` can't read a volume/tmpfs out of a stopped container.
    name = f"hermes-tier1-{uuid.uuid4().hex[:12]}"
    sentinel = f"<<TIER1:{uuid.uuid4().hex}>>"
    cmd = [
        "docker", "run", "-d", "--name", name,
        "--network", "none",
        f"--memory={memory}",
        f"--cpus={cpus}",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=16m",
        "-e", f"TIER1_SENTINEL={sentinel}",
        "-v", f"{run_dir}:/task:ro",
        image, f"/task/{filename}",
    ]
    start = time.monotonic()
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=30)
    except subprocess.CalledProcessError as exc:
        return {"outcome": "runner_error", "message": f"docker run failed to start: {exc.stderr}"}
    except subprocess.TimeoutExpired:
        return {"outcome": "runner_error", "message": "docker run (start) itself timed out after 30s"}

    timed_out = False
    try:
        subprocess.run(["docker", "wait", name], capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["docker", "kill", name], capture_output=True, text=True)

    # Capture the container's output before removing it. docker logs sends container stdout to its own
    # stdout and container stderr to its stderr; combine both so the sentinel block is found wherever
    # it landed. Skipped on a timeout: the container was killed and never emitted a result.
    logs = ""
    if not timed_out:
        logs_proc = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        logs = (logs_proc.stdout or "") + (logs_proc.stderr or "")

    duration = time.monotonic() - start
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)  # best-effort; always runs

    if timed_out:
        # Not automatically a failure: a long-lived listener (c2_transport, etc.) with no peer
        # attached in this floor oracle will hit this every time by design, not because it's broken.
        return {"outcome": "timeout", "wall_time_s": duration}

    payload = _parse_sentinel(logs, sentinel)
    if payload is None:
        payload = {"outcome": "runner_error",
                   "message": "no result found in container output (runner crashed before emitting?)"}
    payload["wall_time_s"] = duration
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tier 1: run each generated file's import inside a disposable, network-isolated container"
    )
    parser.add_argument("run_dir", help="Directory of generated .py files (a data/code_scripts/<run> directory)")
    parser.add_argument("--plan", help="Optional Stage 2 plan JSON, for task_id recovery on untracked files")
    parser.add_argument("--image", default=DEFAULT_IMAGE, help="Tier 1 base image tag")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_S, help="Per-file wall-clock timeout in seconds")
    parser.add_argument("--memory", default=DEFAULT_MEMORY, help="Per-container memory limit (docker --memory syntax)")
    parser.add_argument("--cpus", default=DEFAULT_CPUS, help="Per-container CPU limit (docker --cpus syntax)")
    parser.add_argument("--include-rejected", action="store_true", help="Also run incorrect_*.py rejected drafts")
    args = parser.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.is_dir():
        print(f"Not a directory: {run_dir}", file=sys.stderr)
        sys.exit(1)

    tasks_by_id: dict[str, dict] = {}
    if args.plan:
        plan = _load_stage2_plan(Path(args.plan))
        tasks_by_id = {t["task_id"]: t for t in plan.get("tasks") or []}

    candidates = _resolve_candidates(run_dir, tasks_by_id, args.include_rejected)
    if not candidates:
        print(f"No .py files found to run in {run_dir}")
        sys.exit(0)

    manifest_path = run_dir / TIER1_MANIFEST_NAME
    ok_count = err_count = timeout_count = 0

    for candidate in candidates:
        print(f"[{candidate['task_id'] or 'untracked'}] running: {candidate['path'].name}")
        try:
            result = _run_container(
                image=args.image, run_dir=run_dir, filename=candidate["path"].name,
                timeout_s=args.timeout, memory=args.memory, cpus=args.cpus,
            )
        except Exception as exc:  # never let one file's container plumbing abort the whole run
            result = {"outcome": "runner_error", "message": f"tier1 host error: {exc}"}

        outcome = result.get("outcome", "runner_error")
        if outcome == "import_ok":
            ok_count += 1
            print(f"    OK ({result.get('duration_s', 0):.2f}s)")
        elif outcome == "timeout":
            timeout_count += 1
            print(f"    TIMEOUT (still running after {args.timeout}s)")
        else:
            err_count += 1
            label = result.get("exception_type", outcome)
            detail = result.get("exception_message") or result.get("message")
            print(f"    FAIL: {label}: {detail}")

        record = {
            "run_dir": str(run_dir),
            "task_id": candidate["task_id"],
            "filename": candidate["path"].name,
            "image": args.image,
            **result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        with manifest_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\nDone: {ok_count} ok, {timeout_count} timed out, {err_count} failed. Manifest: {manifest_path}")
    sys.exit(1 if err_count else 0)


if __name__ == "__main__":
    main()
