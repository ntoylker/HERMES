# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HERMES is a diploma-thesis MVP: a research pipeline studying whether LLMs can write malicious code when
given structured adversary knowledge via RAG. The intended design has 4 stages, of which the first 3 are
implemented; **Stage 4 (sandboxed execution/validation) and a second RAG over malware-code samples do not
exist yet** — the current Stage 3 code generation is task-conditioned only, not malware-sample-grounded.
See `REPO_CONTEXT.md` (untracked, local snapshot) for the fullest single-file account of the project,
including known gaps, data schemas, and thesis alignment analysis.

All work in this repo must stay thesis-safe: isolated sandbox, no real exploit code, no operational attack
instructions, no real targets/credentials/persistence/live C2/exfiltration. Stage 2's
`data/config/stage2_constraints.json` encodes this as machine-checked policy (see Architecture below).

## Commands

No test suite, linter, or pinned dependency manifest exists in this repo (no `requirements.txt`/`pyproject.toml`).
`docs/OFFENSE_RAG_QUICKSTART.md`'s reference to `requirements-offense-corpus.txt` is a doc gap — that file
does not exist. Python 3.14, `.venv` in repo root.

Run the pipeline stages in order (all scripts are directly executable, e.g. `./venv/bin/python <script>.py` or
`python <script>.py` on Windows):

```bash
# Stage 0: build corpus + hybrid index (only needed once; artifacts already exist on disk normally)
python build_offense_corpus.py --input data/raw/enterprise-attack/enterprise-attack.json --output data/processed/rag_offense_mitre_chunks.jsonl
python build_offense_index.py --corpus data/processed/rag_offense_mitre_chunks.jsonl --outdir artifacts/offense_index --overwrite

# Stage 1: retrieve + link a query to ATT&CK techniques
python query_offense_index.py "abuse wmi to execute payload remotely" --index-dir artifacts/offense_index --top-techniques 10
python generate_offense_rag.py "abuse wmi to execute payload remotely" --index-dir artifacts/offense_index

# Stage 2: turn a Stage 1 output into a validated task plan
python plan_tasks.py data/human_outs/<stage1-timestamp>.json --index-dir artifacts/offense_index

# Stage 3: generate per-task Python files from a Stage 2 plan (local LM Studio)
python generate_code.py data/plans/human_outs/<stage2-timestamp>.json --timeout 1200

# Evaluation
python eval_offense_retrieval.py --cases data/eval/eval_cases.jsonl --index-dir artifacts/offense_index
python eval_offense_generation.py --cases data/eval/eval_cases.jsonl --index-dir artifacts/offense_index
python sweep_offense_retrieval_fast.py   # grid search over vector_k/bm25_k/lexical_weight
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

## Architecture

Four scripts form a strict linear pipeline; everything else evaluates or tunes one of its stages.

```
data/raw/enterprise-attack/enterprise-attack.json (STIX bundle)
  -> build_offense_corpus.py       -> data/processed/rag_offense_mitre_chunks.jsonl (chunked corpus)
  -> build_offense_index.py        -> artifacts/offense_index/ (SQLite FTS5 + embeddings.npy, via hosted_embeddings.py)
  -> query_offense_index.py        (hybrid vector+BM25 retrieval, called by everything below)
  -> generate_offense_rag.py       STAGE 1: query decomposition + Gemini technique linking + citation validation
  -> plan_tasks.py                 STAGE 2: Gemini task planning + deterministic Python validation
  -> generate_code.py              STAGE 3: per-task Python file generation via local LM Studio
```

`eval_offense_retrieval.py`, `eval_offense_generation.py`, and `sweep_offense_retrieval_fast.py` all call
into `query_offense_index.py`'s retrieval logic to measure or tune it; they are not pipeline stages
themselves.

### Retrieval (`query_offense_index.py`)

Hybrid score = `vector_max + (lexical_weight * lexical_best)`, where `vector_max` is the best cosine
similarity across a technique's chunks and `lexical_best` is a rank-based FTS5 BM25 score
(`1/(1+rank)`). Standard repo-wide defaults, hardcoded in every entry point:
`vector_k=25, bm25_k=25, lexical_weight=0.05` (chosen by a 13-case eval sweep; see
`docs/RETRIEVAL_CONFIG.md`). Query embeddings are cached in `cache/query_cache.sqlite`, keyed by
`(normalized_query, provider, model)`.

### Stage 1 (`generate_offense_rag.py`)

Splits multi-intent queries into standalone parts, runs retrieval + Gemini generation per part, validates
that every returned technique's citations are grounded in retrieved evidence (dropping ungrounded ones),
then merges parts back into one answer for backward compatibility with Stage 2. Prompt explicitly tells the
model to ignore instructions embedded in retrieved sources (prompt-injection defense against
adversarial STIX/procedure text) and to never provide step-by-step offensive instructions. Always writes a
timestamped pretty `.json` to `data/human_outs/` and a compact `.jsonl` to `data/machine_outs/`, even on
empty retrieval or Gemini failure.

### Stage 2 (`plan_tasks.py`)

Takes a Stage 1 output and asks Gemini to decompose techniques into implementation-neutral tasks with
`local_id`, `depends_on`, and `evidence_refs`. The model's JSON is never trusted structurally — a
deterministic validator checks `task_type`/`language` against `data/config/stage2_constraints.json`,
resolves `depends_on` and topologically orders tasks (cycle = blocking violation), filters `evidence_refs`
to IDs actually present in the supplied context, and requires every primary Stage 1 technique to be
*covered* by at least one task or the whole plan is invalid. `forbidden_capability_keywords`
(persistence, credential_access, evasion, etc.) are scanned as a **non-blocking advisory only**, not an
automatic rejection. Canonical `TASK-00N` IDs are assigned only after validation passes. Always persists a
result (`planning_status` ∈ `valid`/`invalid`/`no_techniques`) so Stage 3 can gate on that field alone.

### Stage 3 (`generate_code.py`)

Aborts unless the input plan's `planning_status == "valid"`. For each task in `execution_order`, prompts a
local LM Studio model with the task's own fields plus AST-compacted interfaces of already-generated dependency
tasks (function/method bodies replaced with `docstring + ...`, via `_compact_dependency_code`) so prompt
size stays bounded as dependency chains grow. Requires the model reply in a strict
`FILENAME: <name>.py` + fenced code block contract, validated with `ast.parse`; retried up to
`--max-attempts` on any violation. Resumable: skips tasks already `"generated"` in `manifest.jsonl` whose
output file still exists, reusing that file as dependency context. Every attempt (success or failure) is
appended to `data/code_scripts/manifest.jsonl` — an append-only audit trail, never overwritten.
**Generated files can `import` sibling generated modules by filename** — renaming a file under
`data/code_scripts/` requires grepping every other generated file for imports of the old name.

### `hosted_embeddings.py`

Shared embedding-provider abstraction used only by `build_offense_index.py` and `query_offense_index.py`.
Auto-detects provider from env vars (Google AI Studio -> Azure OpenAI -> OpenAI, in that priority) unless
`EMBED_PROVIDER` is set explicitly. Three client classes (`OpenAIEmbeddingClient`,
`AzureOpenAIEmbeddingClient`, `GoogleAIStudioEmbeddingClient`) each implement `embed_texts`.

## Conventions

- Output pattern: a timestamped pretty `.json` (human-facing) + compact `.jsonl` (machine-facing) pair is
  standard for both Stage 1 and Stage 2 outputs.
- LLM output is never trusted structurally — Stage 2's validator and Stage 3's `ast.parse`/`FILENAME:`/fence
  checks always gate model output in plain Python before it is persisted or used downstream.
- Every generation attempt (success or failure) is recorded, never silently discarded (`manifest.jsonl` for
  Stage 3; `blocking_violations`/`advisories` embedded in each Stage 2 plan).
- Retrieval defaults (`vector_k=25, bm25_k=25, lexical_weight=0.05`) are a checked-in standard across every
  entry point; deviations for one-off experiments should be recorded next to that experiment's output
  rather than changing the shared defaults.
- Stage 2 currently only allows `language: "python"` for generated tasks
  (`allowed_languages` in `stage2_constraints.json`).
- Python comment style: concise, inline, for a software-engineer audience. Module docstrings are 1-3 lines
  stating which stage the file belongs to. Comment only non-obvious logic, JSON schemas, validation loops,
  and domain-specific ATT&CK/STIX concepts — not self-explanatory code or standard Python patterns.
- The entire `data/` directory, `cache/`, `logs/`, `*.sqlite`, `*.npy`, and most `*.jsonl` are `.gitignore`d
  (exception: `data/eval/eval_cases.jsonl` is tracked). A default content search over `data/**` will
  silently miss everything unless ignored files are explicitly included.
