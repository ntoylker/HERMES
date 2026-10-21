#!/usr/bin/env python3
"""One-shot driver (v2): run mvp-v1.py (Stage 1 -> 2 -> 3) then continue into Stage 4
(4a static validation + Tier 1 disposable-container import gate) on its output."""
import subprocess
import sys
from pathlib import Path

PY = sys.executable
IMAGE = "hermes-tier1-base:latest"
RUN_DIR = Path("data/code_scripts")        # mvp-v1 runs generate_code.py with its default output dir
HUMAN_OUTS = Path("data/human_outs")       # Stage 1 writes a fresh timestamped .json here per run
PLAN_DIR = Path("data/plans/human_outs")   # Stage 2 writes PLAN_<stage1-stem>.json here on success


def _run(cmd: list) -> subprocess.CompletedProcess:
    # Echo the command and stream its output live (no capture); return the finished process.
    print(f"\n$ {' '.join(str(c) for c in cmd)}", flush=True)
    return subprocess.run(cmd)


def _stage1_jsons() -> set[Path]:
    return set(HUMAN_OUTS.glob("*.json")) if HUMAN_OUTS.is_dir() else set()


def _require_docker() -> None:
    # "Require Tier 1": fail loudly if docker is missing or the daemon isn't responding.
    try:
        proc = subprocess.run(["docker", "version"], capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        sys.exit("ERROR: Tier 1 requires Docker, but the `docker` command was not found on PATH.")
    except subprocess.TimeoutExpired:
        sys.exit("ERROR: `docker version` timed out — the Docker daemon may be hung or not running.")
    if proc.returncode != 0:
        sys.exit(f"ERROR: Docker is installed but not responding (is the daemon running?):\n{proc.stderr.strip()}")


def _ensure_image() -> None:
    # Build the Tier 1 base image from Dockerfile.tier1 on first use; abort if the build fails.
    inspect = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True)
    if inspect.returncode == 0:
        return
    print(f"\nTier 1 image {IMAGE} not found; building from Dockerfile.tier1 ...", flush=True)
    if _run(["docker", "build", "-f", "Dockerfile.tier1", "-t", IMAGE, "."]).returncode != 0:
        sys.exit("ERROR: failed to build the Tier 1 base image.")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python mvp-v2.py <query.txt>")
    query_file = sys.argv[1]

    # --- Stages 1-3: run mvp-v1 unchanged, with live output. mvp-v1 uses check=True internally, so a
    #     failing stage makes it exit non-zero; mirror that by not continuing to Stage 4. ---
    before = _stage1_jsons()
    if _run([PY, "mvp-v1.py", query_file]).returncode != 0:
        sys.exit("mvp-v1 (Stage 1-3) failed; not continuing to Stage 4.")

    # Identify this run's Stage 1 output by set-difference (robust vs. parsing mvp-v1's interleaved
    # stdout), then derive the Stage 2 plan path deterministically, exactly as mvp-v1 does internally.
    new_stage1 = _stage1_jsons() - before
    if not new_stage1:
        sys.exit("Could not identify this run's Stage 1 output in data/human_outs/ after mvp-v1 finished.")
    stage1_path = max(new_stage1, key=lambda p: p.stat().st_mtime)
    plan_path = PLAN_DIR / f"PLAN_{stage1_path.stem}.json"
    if not plan_path.exists():
        sys.exit(f"Expected Stage 2 plan not found: {plan_path}")
    if not (RUN_DIR / "manifest.jsonl").exists():
        sys.exit(f"No Stage 3 manifest at {RUN_DIR / 'manifest.jsonl'} — mvp-v1 wrote no code to validate.")

    print(f"\n=== Stage 4 targets ===\n  run dir: {RUN_DIR}\n  plan:    {plan_path}", flush=True)

    # Docker prerequisites first, so a missing daemon fails fast rather than after Stage 4a.
    _require_docker()
    _ensure_image()

    # --- Stage 4a (static) and Tier 1 (container import). A non-zero exit from either means "files were
    #     flagged", not "the tool crashed", so report it rather than aborting; Tier 1 runs regardless
    #     (the user required it). ---
    s4a = _run([PY, "validate_scripts.py", str(RUN_DIR), "--plan", str(plan_path)])
    t1 = _run([PY, "run_tier1_sandbox.py", str(RUN_DIR), "--plan", str(plan_path)])

    print("\n=== mvp-v2 summary ===")
    print("  Stage 1-3 (mvp-v1):      ok")
    print(f"  Stage 4a (static):       {'pass' if s4a.returncode == 0 else 'FAIL (see findings above)'}")
    print(f"  Tier 1 (container run):  {'pass' if t1.returncode == 0 else 'FAIL (an import raised; see above)'}")
    sys.exit(0 if s4a.returncode == 0 and t1.returncode == 0 else 1)


if __name__ == "__main__":
    main()
