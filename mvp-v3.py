#!/usr/bin/env python3
"""One-shot driver (v3): Stage 1 (Linux-filtered RAG index) -> Stage 2 (Gemini) ->
Stage 2.5 (Gemini) -> Stage 3 (local LM Studio) -> Stage 4 (static validation + Tier 1)."""
import subprocess
import sys
from pathlib import Path

PY = sys.executable
IMAGE = "hermes-tier1-base:latest"
INDEX_DIR = "artifacts/offense_index_linux"      # route-change baseline, see CLAUDE.md
GEMINI_MODEL = "gemini-3.1-pro-preview"
# generate_code.py's own DEFAULT_MODEL ("qwen3.8-9b-heretic-uncensored-nvfp4") does not match what
# LM Studio actually serves locally; verified via GET /v1/models per CLAUDE.md's guidance and pinned
# here explicitly rather than relying on that stale default.
STAGE3_MODEL = "qwen3.8-9b-heretic-uncensored@q4_k_m"
RUN_DIR = Path("data/code_scripts")              # generate_code.py's default --output-dir
PLAN_DIR = Path("data/plans/human_outs")         # Stage 2 writes PLAN_<stage1-stem>.json here
ENHANCED_DIR = Path("data/plans/enhanced_outs")  # Stage 2.5 writes PLAN_<stage1-stem>.json here


def _run(cmd: list) -> subprocess.CompletedProcess:
    # Echo the command and stream its output live (no capture); return the finished process.
    print(f"\n$ {' '.join(str(c) for c in cmd)}", flush=True)
    return subprocess.run(cmd)


def _require_docker() -> None:
    # "Require Tier 1": fail loudly if docker is missing or the daemon isn't responding, before
    # three LLM-backed stages have already run.
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
        sys.exit("usage: python mvp-v3.py <query.txt>")

    # Docker prerequisites checked up front, same as mvp-v2.py, so a missing daemon fails fast
    # rather than after three LLM-backed stages have already run.
    _require_docker()
    _ensure_image()

    query_path = Path(sys.argv[1])
    query = query_path.read_text(encoding="utf-8").strip()
    if not query:
        sys.exit(f"ERROR: {query_path} is empty.")

    # --- Stage 1: retrieval against the Linux-filtered index. Captured (not streamed) because the
    #     output path is read from its last stdout line, same convention as mvp-v1.py. ---
    print(f"\n$ {PY} generate_offense_rag.py <query> --index-dir {INDEX_DIR}", flush=True)
    s1 = subprocess.run([PY, "generate_offense_rag.py", query, "--index-dir", INDEX_DIR],
                        capture_output=True, text=True)
    print(s1.stdout, end="")
    if s1.returncode != 0:
        print(s1.stderr, file=sys.stderr, end="")
        sys.exit("Stage 1 failed.")
    stage1_path = s1.stdout.strip().splitlines()[-1]

    # --- Stage 2: Gemini-backed planning. Deterministic output path, same as mvp-v1.py. ---
    if _run([PY, "plan_tasks.py", "--stage1-input", stage1_path,
             "--provider", "gemini", "--gemini-model", GEMINI_MODEL]).returncode != 0:
        sys.exit("Stage 2 failed.")
    plan_path = PLAN_DIR / f"PLAN_{Path(stage1_path).stem}.json"
    if not plan_path.exists():
        sys.exit(f"Expected Stage 2 plan not found: {plan_path}")

    # --- Stage 2.5: Gemini-backed narrative enhancement. Same stem, separate output directory. ---
    if _run([PY, "plan_enhancing.py", str(plan_path),
             "--provider", "gemini", "--gemini-model", GEMINI_MODEL]).returncode != 0:
        sys.exit("Stage 2.5 failed.")
    enhanced_path = ENHANCED_DIR / f"PLAN_{Path(stage1_path).stem}.json"
    if not enhanced_path.exists():
        sys.exit(f"Expected Stage 2.5 output not found: {enhanced_path}")

    # --- Stage 3: per-task code generation via the local LM Studio model (default provider — no
    #     --provider flag needed). Consumes the Stage 2.5-enhanced plan. ---
    if _run([PY, "generate_code.py", str(enhanced_path),
             "--model", STAGE3_MODEL, "--timeout", "1200"]).returncode != 0:
        sys.exit("Stage 3 failed.")
    if not (RUN_DIR / "manifest.jsonl").exists():
        sys.exit(f"No Stage 3 manifest at {RUN_DIR / 'manifest.jsonl'} — nothing to validate.")

    print(f"\n=== Stage 4 targets ===\n  run dir: {RUN_DIR}\n  plan:    {enhanced_path}", flush=True)

    # --- Stage 4: static validation (4a) + Tier 1 disposable-container import gate. Both run
    #     regardless of each other's outcome, same as mvp-v2.py. ---
    s4a = _run([PY, "validate_scripts.py", str(RUN_DIR), "--plan", str(enhanced_path)])
    t1 = _run([PY, "run_tier1_sandbox.py", str(RUN_DIR), "--plan", str(enhanced_path)])

    print("\n=== mvp-v3 summary ===")
    print("  Stage 1   (Linux-filtered RAG):  ok")
    print("  Stage 2   (Gemini planning):     ok")
    print("  Stage 2.5 (Gemini enhancement):  ok")
    print("  Stage 3   (local LM Studio):     ok")
    print(f"  Stage 4a  (static):              {'pass' if s4a.returncode == 0 else 'FAIL (see findings above)'}")
    print(f"  Tier 1    (container run):       {'pass' if t1.returncode == 0 else 'FAIL (an import raised; see above)'}")
    sys.exit(0 if s4a.returncode == 0 and t1.returncode == 0 else 1)


if __name__ == "__main__":
    main()
