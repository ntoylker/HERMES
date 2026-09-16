# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HERMES is a diploma-thesis MVP: a research pipeline studying whether LLMs can write malicious code when
given structured adversary knowledge via RAG. The intended design has 4 stages, of which the first 3 are
implemented; **Stage 4 (sandboxed execution/validation) and a second RAG over malware-code samples do not
exist yet** — the current Stage 3 code generation is task-conditioned only, not malware-sample-grounded.

All work in this repo must stay thesis-safe: isolated sandbox, no real exploit code, no operational attack
instructions, no real targets/credentials/persistence/live C2/exfiltration. **This is a prompt-level
instruction today, not a machine-checked one**: `data/config/stage2_constraints.json` only constrains
structure (allowed task-type taxonomy, target language), and its `allowed_task_types` list explicitly
permits `credential_access` and `c2_transport` as task categories — neither it nor Stage 2's validator
scans task content for forbidden capabilities (see Architecture below). A `forbidden_capability_keywords`
advisory scan existed in a prior schema version but was dropped when Stage 2 moved to the current schema
v2.0. The only safety net enforced today is the Stage 1/Stage 3 prompts instructing the model to avoid
step-by-step offensive detail and treat the work as sandboxed research — model compliance, not code.

## Commands

No test suite, linter, or pinned dependency manifest exists in this repo (no `requirements.txt`/`pyproject.toml`).
`docs/OFFENSE_RAG_QUICKSTART.md`'s reference to `requirements-offense-corpus.txt` is a doc gap — that file
does not exist. Python 3.14, `.venv` in repo root.

Run the pipeline stages in order (all scripts are directly executable via `python <script>.py` once `.venv`
is activated):

```bash
# Stage 0: build corpus + hybrid index (only needed once; artifacts already exist on disk normally)
python build_offense_corpus.py --input data/raw/enterprise-attack/enterprise-attack.json --output data/processed/rag_offense_mitre_chunks.jsonl
python build_offense_index.py --corpus data/processed/rag_offense_mitre_chunks.jsonl --outdir artifacts/offense_index --overwrite

# Stage 1: retrieve + link a query to ATT&CK techniques
python query_offense_index.py "abuse wmi to execute payload remotely" --index-dir artifacts/offense_index --top-techniques 10
python generate_offense_rag.py "abuse wmi to execute payload remotely" --index-dir artifacts/offense_index

# Stage 2: turn a Stage 1 output into a validated task plan
python plan_tasks.py --stage1-input data/human_outs/<stage1-timestamp>.json

# Stage 3: generate per-task Python files from a Stage 2 plan (local LM Studio)
python generate_code.py data/plans/human_outs/<stage2-timestamp>.json --timeout 1200

# One-shot smoke-test driver: runs Stage 1 -> 2 -> 3 back-to-back for a query stored in a .txt file
python mvp-v1.py path/to/query.txt

# Evaluation
python eval_offense_retrieval.py --cases data/eval/eval_cases.jsonl --index-dir artifacts/offense_index
python eval_offense_generation.py --cases data/eval/eval_cases.jsonl --index-dir artifacts/offense_index
python sweep_offense_retrieval_fast.py   # baseline single-config run by default; pass comma-separated
                                          # --vector-ks/--bm25-ks/--lexical-weights for an actual grid search
```

- `generate_code.py --timeout` defaults to 1200s; raise it if a task times out. At GPU-only speeds
  (~10 t/s) a full `--max-tokens` (8192) reply takes ~845s, so the 1200s default leaves margin even for a
  max-length generation — a shorter default would time out long generations before the token cap could cut
  them cleanly.
- `--force` on `generate_code.py` ignores the manifest and regenerates every task from scratch; without it,
  already-generated tasks (per `manifest.jsonl`) are skipped and reused as dependency context.
- Stage 3 requires a local LM Studio server (OpenAI-compatible API) at `http://localhost:1234/v1` with a
  Qwen3.8-9B-heretic-uncensored-NVFP4 model loaded, served as `qwen3.8-9b-heretic-uncensored-nvfp4` — LM
  Studio normalizes the HuggingFace repo name (`Noobito45/Qwen3.8-9B-heretic-uncensored-NVFP4-GGUF`) into
  that shorter ID; verify via `GET /v1/models` before trusting a repo name as the `--model` value. LM
  Studio's context window is fixed at model-load time (currently 43000 tokens, sized to fit an 8GB-VRAM
  GPU-only load), not a per-request option — there is no `--num-ctx`-equivalent flag.
- `mvp-v1.py` is a **first-version, temporary smoke-test script** (the most recent step in this pipeline's
  progress), not a fourth pipeline stage: it chains the three real stages together via
  `subprocess.run(..., check=True)` — `generate_offense_rag.py <query>` -> captures Stage 1's printed
  output path -> `plan_tasks.py --stage1-input <path>` -> computes the resulting
  `data/plans/human_outs/PLAN_<stage1-stem>.json` path deterministically -> `generate_code.py <plan_path>`.
  It takes one argument (a path to a `.txt` file holding the query text) and exposes no flags of its own;
  every stage runs with its hardcoded defaults, and the whole run aborts on the first stage that raises.
  Expect this file to change shape or be deleted as the pipeline matures — treat it as a convenience
  integration check, not a stable entry point to build on.

## Architecture

Four scripts form a strict linear pipeline; everything else either evaluates/tunes one of its stages, or
(`mvp-v1.py`) drives all three end-to-end as a smoke test.

```
data/raw/enterprise-attack/enterprise-attack.json (STIX bundle)
  -> build_offense_corpus.py       -> data/processed/rag_offense_mitre_chunks.jsonl (chunked corpus)
  -> build_offense_index.py        -> artifacts/offense_index/ (SQLite FTS5 + embeddings.npy, via hosted_embeddings.py)
  -> query_offense_index.py        (hybrid vector+BM25 retrieval, called by everything below)
  -> generate_offense_rag.py       STAGE 1: query decomposition + Gemini technique linking + citation validation
  -> plan_tasks.py                 STAGE 2: LM Studio (Gemini-fallback) task planning + deterministic Python validation
  -> generate_code.py              STAGE 3: per-task Python file generation via local LM Studio
```

None of `eval_offense_retrieval.py`, `eval_offense_generation.py`, or `sweep_offense_retrieval_fast.py` are
pipeline stages themselves, but they reach `query_offense_index.py` three different ways.
`eval_offense_retrieval.py` subprocess-calls `query_offense_index.py` directly to measure raw retrieval in
isolation.
`eval_offense_generation.py` instead subprocess-calls `generate_offense_rag.py`, so it measures the full
Stage 1 pipeline (decomposition + retrieval + Gemini generation + citation validation), reaching retrieval
only transitively. `sweep_offense_retrieval_fast.py` imports `query_offense_index.py`'s shared
`_lexical_candidates`/`_hybrid_score` functions directly in-process (no subprocess) so it can precompute
each case's candidates once and reuse them across its whole `vector_k`/`bm25_k`/`lexical_weight` grid
without recomputing embeddings per config.

### Retrieval (`query_offense_index.py`)

Hybrid score = `vector_max + (lexical_weight * lexical_best)`, where `vector_max` is the best cosine
similarity across a technique's chunks and `lexical_best` is a rank-based FTS5 BM25 score
(`1/(1+rank)`). Standard repo-wide defaults, hardcoded in every entry point:
`vector_k=25, bm25_k=25, lexical_weight=0.05` (chosen by a 13-case eval sweep; see
`docs/RETRIEVAL_CONFIG.md`). Query embeddings are cached in `cache/query_cache.sqlite`, keyed by
`(normalized_query, provider, model)`.

### Stage 1 (`generate_offense_rag.py`)

Splits multi-intent queries into standalone parts, runs retrieval + Gemini generation per part — each
part's `generateContent` call sets a `responseSchema` constraining the JSON shape and is retried (same
prompt, up to `--max-retries` times, default `3`) on empty text, a request error, or unparseable JSON —
validates that every returned technique's citations are grounded in retrieved evidence and that no
`alternatives` entry duplicates a `top_techniques` `mitre_id` (dropping violators in both cases), then
merges parts back into one answer — deduping by `mitre_id` across parts (first occurrence wins) and
re-prefixing each part's citation IDs to avoid collisions — for backward compatibility with Stage 2.
Prompt explicitly tells the
model to ignore instructions embedded in retrieved sources (prompt-injection defense against
adversarial STIX/procedure text) and to never provide step-by-step offensive instructions. Always writes a
timestamped pretty `.json` to `data/human_outs/` and a compact `.jsonl` to `data/machine_outs/`, even on
empty retrieval or Gemini failure.

### Stage 2 (`plan_tasks.py`)

Takes a Stage 1 output and asks a dual-backend LLM (local LM Studio by default, falling back to Gemini on
failure, or Gemini directly via `--provider gemini`) to decompose top ATT&CK techniques directly into
tasks — the model assigns each task's own final `TASK_NNN`-style `task_id`, `task_type`,
`suggested_filename`, `technique_ids`, `dependencies`, `provides`/`consumes` symbol contract,
`implementation_details`, and `rag_retrieval_hints`. The model's JSON is never trusted structurally — a
deterministic validator checks required keys and `task_type` against
`data/config/stage2_constraints.json`'s `allowed_task_types`, detects dependency cycles via DFS (blocking),
cross-validates that every `consumes` symbol is `provides`d by a declared dependency, and requires every
Stage 1 top/primary technique to be covered by at least one task's `technique_ids` or the whole plan is
invalid. There is no `evidence_refs` field, no `forbidden_capability_keywords` scan, and no canonical-ID
remapping step in the current schema (v2.0) — the model's own task IDs are persisted as-is. On failure,
validation errors and the previous draft are fed back for up to `--max-retries` attempts. Always appends a
machine record (`status` ∈ `valid`/`invalid`) to `data/plans/machine_outs/`; the human-readable plan under
`data/plans/human_outs/` is written only when validation succeeds, so its existence — not a
`planning_status` field — is what gates Stage 3. The prompt's worked JSON example (in the schema section)
uses deliberately generic placeholder values, not real task content — an earlier version's concrete
credential-harvesting example caused generated plans to anchor on a near-identical first task regardless of
the query; the example now also links two tasks to demonstrate the `provides`/`consumes` contract
concretely.

### Stage 3 (`generate_code.py`)

Aborts unless the input plan's `tasks` array is non-empty and every task has all required keys (`task_id`,
`task_type`, `suggested_filename`, `description`, `technique_ids`, `dependencies`, `provides`, `consumes`,
`implementation_details`) — there is no `planning_status` field to check. Derives its own execution order
from each task's `dependencies` via a DFS topological sort (`_topological_order`, raises on a cycle); the
plan itself carries no `execution_order` field (schema v2.0 dropped it). For each task, in that derived
order, prompts a local LM Studio model with the task's own fields plus AST-compacted interfaces of
already-generated dependency tasks (function/method bodies replaced with `docstring + ...`, via
`_compact_dependency_code`) so prompt size stays bounded as dependency chains grow. The model must reply
with nothing but a single fenced ```python code block containing the complete file — there is no
`FILENAME:` line in the contract; the output filename comes entirely from the plan's own
`suggested_filename` (sanitized, then prefixed with the task ID). The reply is validated with `ast.parse`;
retried up to `--max-attempts` on any violation. Resumable: skips tasks already `"generated"` in
`manifest.jsonl` whose output file still exists, reusing that file as dependency context. Every attempt
(success or failure) is appended to `data/code_scripts/manifest.jsonl` — an append-only audit trail, never
overwritten. **Generated files can `import` sibling generated modules by filename** — renaming a file under
`data/code_scripts/` requires grepping every other generated file for imports of the old name.

### `hosted_embeddings.py`

Shared embedding-provider abstraction. Imported by `build_offense_index.py`, `query_offense_index.py`,
`decompose_query.py` (Stage 1's near-duplicate dedup when splitting a multi-intent query),
`eval_offense_generation.py`, and `sweep_offense_retrieval_fast.py`.
Auto-detects provider from env vars (Google AI Studio -> Azure OpenAI -> OpenAI, in that priority) unless
`EMBED_PROVIDER` is set explicitly. Three client classes (`OpenAIEmbeddingClient`,
`AzureOpenAIEmbeddingClient`, `GoogleAIStudioEmbeddingClient`) each implement `embed_texts`.

## Conventions

- Output pattern: Stage 1 always writes a fresh timestamped pretty `.json` (human-facing) + compact
  `.jsonl` (machine-facing) pair per run, even on failure. Stage 2 does not follow this pattern — it writes
  to `PLAN_<stage1-stem>`-named files instead of a fresh timestamp: the machine `.jsonl` is appended to on
  every run (valid or invalid), while the human `.json` is only written when validation succeeds, and its
  existence (not a status field inside it) is what gates Stage 3.
- LLM output is never trusted structurally — Stage 2's validator and Stage 3's `ast.parse`/fenced-code-block
  checks always gate model output in plain Python before it is persisted or used downstream.
- Every generation attempt (success or failure) is recorded, never silently discarded: `manifest.jsonl` for
  Stage 3, and a flat `errors` list on each Stage 2 machine record (there is no separate
  `blocking_violations`/`advisories` split in the current schema).
- Retrieval defaults (`vector_k=25, bm25_k=25, lexical_weight=0.05`) are a checked-in standard across every
  entry point; deviations for one-off experiments should be recorded next to that experiment's output
  rather than changing the shared defaults.
- Stage 2 currently only allows `target_language: "python"` for generated tasks. `target_language` in
  `stage2_constraints.json` is a single string, not a list — there is no `allowed_languages` key and no
  per-task `language` field in the current schema.
- Python comment style: concise, inline, for a software-engineer audience. Module docstrings are 1-3 lines
  stating which stage the file belongs to. Comment only non-obvious logic, JSON schemas, validation loops,
  and domain-specific ATT&CK/STIX concepts — not self-explanatory code or standard Python patterns.
- The entire `data/` directory, `cache/`, `logs/`, `*.sqlite`, `*.npy`, and most `*.jsonl` are `.gitignore`d
  (exception: `data/eval/eval_cases.jsonl` is tracked). A default content search over `data/**` will
  silently miss everything unless ignored files are explicitly included.
