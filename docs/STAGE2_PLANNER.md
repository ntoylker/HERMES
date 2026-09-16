# Stage 2 Task Planner

`plan_tasks.py` turns a Stage 1 ATT&CK technique-linking result into a validated, per-task implementation
plan. The model assigns each task's final `task_id`, dependencies, and symbol-level interface
(`provides`/`consumes`) directly; a deterministic validator checks the draft and drives a self-repair retry
loop, but it does not renumber tasks or compute a separate execution order — that is left to Stage 3.

## Inputs

The input is a Stage 1 JSON result created by `generate_offense_rag.py` (normally under
`data/human_outs/`), passed via `--stage1-input`. If omitted, the planner auto-selects the
lexicographically-latest file in `data/human_outs/*.json`, falling back to `data/machine_outs/*.jsonl`.

From that file the planner reads:

- `query`, `summary`
- `decomposition.sub_queries` (or, if absent, `parts[].id`/`parts[].text`) — shown to the model as
  "Attack Phases" context, not otherwise consumed
- `top_techniques` (plus `parts[].top_techniques`, merged) as the **required** primary technique set; if
  still empty, the first 3 of each part's `retrieved_techniques` are used as a fallback
- `alternatives` (plus `parts[].alternatives`, merged) as **optional** supporting context

Alternatives are always included in the prompt (there is no flag to exclude them) but are never required
for coverage and never independently drive task creation.

## Evidence

For every top + alternative technique ID, `fetch_attack_evidence` queries `chunks` in
`artifacts/offense_index/offense_index.sqlite` (hardcoded path, not a CLI option), returning up to 3 chunks
per technique (`technique_description` chunks first, then `technique_overview`, then everything else),
each truncated to 800 characters. Top techniques get their evidence text inlined in the prompt; alternative
techniques are listed by ID/name only.

## Constraints

`data/config/stage2_constraints.json` (hardcoded path, not a CLI option) is schema v2.0 and currently
supplies only `allowed_task_types`, `target_language`, and `min_python_version` — all three are read into
the prompt and `allowed_task_types` is enforced by the validator. Its `environment` and `schema_version`
keys exist but are not consumed anywhere; the "Environment" line shown to the model is a hardcoded string,
not read from this file. There is no `forbidden_capability_keywords` list, network-policy field, or
implementation-mode field in the current schema.

## Prompt Design

The prompt's `## 5. TARGET JSON OUTPUT SCHEMA` section shows the model a worked JSON example so it learns
the expected shape. Every concrete value in that example (filenames, symbol names, technique IDs,
descriptions) is a generic placeholder, not a suggestion — an explicit instruction tells the model so. This
replaced an earlier version whose example used concrete domain content (a credential-harvesting task),
which generated plans were anchoring on: `TASK_001` tended to be a near-identical "credential data model"
task regardless of the query. The example now shows two linked tasks specifically to demonstrate the
`dependencies`/`provides`/`consumes` contract concretely — `TASK_002` depends on `TASK_001` and consumes a
symbol `TASK_001` provides, while a second provided symbol is left unconsumed to show that's legal (only
`consumes` requires a provider; the reverse isn't required).

## Planning Flow

1. Load the Stage 1 result and `stage2_constraints.json`.
2. Build per-technique evidence from the SQLite ATT&CK index.
3. Call the configured LLM provider (`--provider`, default `lmstudio`) for a single JSON draft. LM Studio
   failures automatically fall back to Gemini (`GEMINI_API_KEY` required); `--provider gemini` uses Gemini
   directly.
4. Validate the draft deterministically (see below).
5. On a failed validation, feed the errors and the previous draft back to the model and retry, up to
   `--max-retries` attempts (default 3). If every attempt fails, the run persists an `invalid` machine
   record and then raises — the process exits non-zero.
6. On success, persist the plan.

The validator (`PlanValidator.validate`) checks, in order:

1. **Schema** — `tasks` is a non-empty list; each task has a unique string `task_id` and all of
   `task_type`, `suggested_filename`, `description`, `technique_ids`, `dependencies`, `provides`,
   `consumes`, `implementation_details`, `rag_retrieval_hints`; `task_type` is one of
   `allowed_task_types`. Any schema error short-circuits the remaining checks for that attempt.
2. **Acyclic DAG** — every `dependencies` entry resolves to a known `task_id` (no self-deps), verified with
   a DFS cycle check.
3. **Symbol contract** — every name in a task's `consumes` must appear in the `provides` list of at least
   one of its declared `dependencies`.
4. **TTP coverage** — the union of every task's `technique_ids` must be a superset of the Stage 1 **top**
   technique IDs (alternatives are not required to be covered).

There is no `evidence_refs` field, no per-task language field, no `forbidden_capability_keywords` scan, and
no canonical-ID remapping step — the model's own `TASK_NNN`-style `task_id` values are used as-is in the
persisted plan.

## Run the Planner

```bash
python plan_tasks.py --stage1-input data/human_outs/<stage1-timestamp>.json
```

Omit `--stage1-input` to auto-select the latest Stage 1 output.

Options:

- `--provider {lmstudio,gemini}`: LLM backend; default `lmstudio` (falls back to Gemini on failure)
- `--lmstudio-url`: LM Studio chat-completions URL; default `http://localhost:1234/v1/chat/completions`
- `--lmstudio-model`: model name sent to LM Studio; default `local-model`
- `--max-tokens`: max completion tokens; default `16384`
- `--timeout`: per-request timeout in seconds; default `600` (Gemini calls are additionally capped at 120s)
- `--max-retries`: self-repair attempts; default `3`

`--index-dir`, `--constraints-file`, `--evidence-per-technique`, `--include-alternatives`,
`--max-repair-attempts`, and `--max-output-tokens` do not exist on this script.

## Output Contract

Each run touches exactly two files, both named after the **Stage 1 input's** filename stem (not a fresh
timestamp for the planner run itself), so rerunning the planner against the same Stage 1 file appends to
the same machine record rather than creating new artifacts:

- `data/plans/machine_outs/PLAN_<stage1-stem>.jsonl` — always appended to (one line per attempted run),
  regardless of outcome. Each line is `{plan_id, created_at, status, stage1_ref, source_query, tasks,
  errors}` with `status` ∈ `valid`/`invalid`.
- `data/plans/human_outs/PLAN_<stage1-stem>.json` — written (overwritten) **only when `status == "valid"`**.
  Its content is exactly the model's validated draft: `{plan_id, source_query, stage1_ref, tasks: [...]}`.
  There is no `planning_status`, `scope`, `execution_order`, `technique_coverage`, or `validation` field —
  the file simply does not exist for an invalid plan, and that absence is what gates Stage 3, not a status
  field inside it.

No `.input.json` reproducibility dump of the model context is written.

## Relationship to Stage 1

Stage 1 answers which ATT&CK techniques describe a query. Stage 2 uses the top techniques as the required
coverage set and produces a task plan with each task's own `technique_ids`. The planner does not rerank
retrieval results or modify the Stage 1 result.

## Relationship to Stage 3

Stage 3 ([STAGE3_CODE_GENERATION.md](STAGE3_CODE_GENERATION.md)) loads the human-readable plan directly,
re-derives its own execution order from each task's `dependencies` via topological sort (it does not read
or expect a precomputed `execution_order`), and generates one Python file per task.
