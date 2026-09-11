#!/usr/bin/env python3
"""One-shot driver: run a query .txt file through Stage 1 -> 2 -> 3."""
import subprocess, sys
from pathlib import Path

py = sys.executable
query = Path(sys.argv[1]).read_text(encoding="utf-8").strip()

# Stage 1: prints the Stage 1 output json path as its last stdout line.
s1 = subprocess.run([py, "generate_offense_rag.py", query], check=True,
                    capture_output=True, text=True)
print(s1.stdout, end="")
stage1_path = s1.stdout.strip().splitlines()[-1]

# Stage 2: deterministic output at data/plans/human_outs/PLAN_<stage1-stem>.json.
subprocess.run([py, "plan_tasks.py", "--stage1-input", stage1_path], check=True)
plan_path = f"data/plans/human_outs/PLAN_{Path(stage1_path).stem}.json"

# Stage 3: generate per-task code from the validated plan.
subprocess.run([py, "generate_code.py", plan_path], check=True)
