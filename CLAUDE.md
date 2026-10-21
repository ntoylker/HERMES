# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

HERMES is a diploma-thesis MVP: a research pipeline studying whether LLMs can write malicious code when
given structured adversary knowledge via RAG. The intended design has 4 stages, of which the first 3 are
implemented and **Stage 4 (sandboxed execution/validation) is now partially built**: a static pre-flight
validator (**Stage 4a**, `validate_scripts.py`) and a disposable network-isolated container import gate
(**Tier 1**, `run_tier1_sandbox.py` + `tier1_runner.py` + `Dockerfile.tier1`) exist as standalone tools
run against a finished Stage 3 run directory. They are **not yet wired into the pipeline chain** (neither
`mvp-v1.py` nor anything else calls them automatically — you invoke them by hand). The heavier end of
Stage 4 — a full behavioral sandbox (Cuckoo/CAPE) and a richer per-task-type/self-test oracle — still does
not exist, and neither does the second RAG over malware-code samples: the current Stage 3 code generation
is task-conditioned only, not malware-sample-grounded.

All work in this repo must stay thesis-safe: isolated sandbox, no real exploit code, no operational attack
instructions, no real targets/credentials/persistence/live C2/exfiltration. **Content safety is still a
prompt-level instruction, not a machine-checked one**: `data/config/stage2_constraints.json` only
constrains structure (allowed task-type taxonomy, target language), and its `allowed_task_types` list
explicitly permits `credential_access` and `c2_transport` as task categories — neither it nor Stage 2's
validator scans task content for forbidden capabilities (see Architecture below). A
`forbidden_capability_keywords` advisory scan existed in a prior schema version but was dropped when Stage 2
moved to the current schema v2.0. The only *content* safety net enforced today is the Stage 1/Stage 3
prompts instructing the model to avoid step-by-step offensive detail and treat the work as sandboxed
research — model compliance, not code. What **is** now machine-enforced is *execution containment*: Tier 1
runs each generated file inside a throwaway Docker container with no network, capped CPU/memory, a
read-only rootfs and a non-root user, so running a generated file to the "does it import cleanly" floor no
longer touches the host or the network. That boundary contains execution; it does not vet content.

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

# Stage 2.5 (optional, manual — not called by mvp-v1.py): attach cross-task narrative context to a
# Stage 2 plan; writes to data/plans/enhanced_outs/, separate from Stage 2's data/plans/human_outs/
python plan_enhancing.py data/plans/human_outs/PLAN_<stage1-stem>.json

# Stage 3: generate per-task Python files from a Stage 2 (or Stage 2.5-enhanced) plan (local LM Studio)
python generate_code.py data/plans/human_outs/<stage2-timestamp>.json --timeout 1200

# Stage 4a (standalone, manual — not called by mvp-v1.py): static pre-flight validation of a finished
# Stage 3 run directory. No code is executed. --plan enables the provides/consumes contract check.
python validate_scripts.py data/code_scripts/<run-dir> --plan data/plans/human_outs/PLAN_<stage1-stem>.json

# Tier 1 (standalone, manual): build the base image once, then import each generated file inside a
# disposable, network-isolated, resource-capped container. Requires Docker. Run after Stage 4a.
docker build -f Dockerfile.tier1 -t hermes-tier1-base:latest .
python run_tier1_sandbox.py data/code_scripts/<run-dir> --plan data/plans/human_outs/PLAN_<stage1-stem>.json

# One-shot smoke-test driver: runs Stage 1 -> 2 -> 3 back-to-back for a query stored in a .txt file
# (Stage 2.5 and Stage 4 are not part of this chain)
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
- `<run-dir>` for Stage 4a / Tier 1 is a Stage 3 output directory — the dir that holds the generated
  `*.py` files plus `manifest.jsonl` (e.g. `data/code_scripts/stage3_<name>`). Stage 3's default
  `--output-dir` is `data/code_scripts` itself, but in practice each run is pointed at its own
  `stage3_<name>` subdirectory; the validators operate on whatever directory you hand them.
- `validate_scripts.py` exits non-zero if any file fails, so it works as a gate; `--include-rejected` also
  checks `incorrect_*.py` rejected drafts, and omitting `--plan` skips only the provides/consumes contract
  check (compile + import-resolution checks still run). It writes `validation_manifest.jsonl` into the run
  dir.
- `run_tier1_sandbox.py` needs a working Docker daemon and the `hermes-tier1-base:latest` image (built from
  `Dockerfile.tier1`). Per-file defaults: 15s wall-clock timeout (`--timeout`), `256m` memory
  (`--memory`), 1 CPU (`--cpus`). A timeout is **not** counted as a failure (a long-lived listener with no
  peer hits it by design); only an import that raises is. It writes `tier1_manifest.jsonl` into the run dir.
  The base image ships with zero third-party packages on purpose — add one to `Dockerfile.tier1` and
  rebuild only if `validate_scripts.py`'s missing-dependency list names it for a real run.

## Architecture

Four scripts form the core linear pipeline; everything else either evaluates/tunes one of its stages,
drives Stages 1-3 end-to-end as a smoke test (`mvp-v1.py`), or post-processes a finished Stage 3 run
(the Stage 4a / Tier 1 validators). A fifth script, `plan_enhancing.py` (Stage 2.5), sits between Stage 2
and Stage 3 but is optional and manual — `mvp-v1.py` does not call it. The Stage 4 validators
(`validate_scripts.py`, `run_tier1_sandbox.py`) are likewise optional and manual, and share scope-aware AST
primitives with Stage 3 via `pipeline_ast.py`.

```
data/raw/enterprise-attack/enterprise-attack.json (STIX bundle)
  -> build_offense_corpus.py       -> data/processed/rag_offense_mitre_chunks.jsonl (chunked corpus)
  -> build_offense_index.py        -> artifacts/offense_index/ (SQLite FTS5 + embeddings.npy, via hosted_embeddings.py)
  -> query_offense_index.py        (hybrid vector+BM25 retrieval, called by everything below)
  -> generate_offense_rag.py       STAGE 1: query decomposition + Gemini technique linking + citation validation
  -> plan_tasks.py                 STAGE 2: LM Studio (Gemini-fallback) task planning + deterministic Python validation
  -> plan_enhancing.py             STAGE 2.5 (optional, manual): adds per-task narrative context; not called by mvp-v1.py
  -> generate_code.py              STAGE 3: per-task Python file generation via local LM Studio
  -> validate_scripts.py           STAGE 4a (optional, manual): execution-free static validation of a Stage 3 run dir
  -> run_tier1_sandbox.py          TIER 1 (optional, manual): disposable network-isolated container import gate
                                   (in-container runner: tier1_runner.py; image: Dockerfile.tier1)

pipeline_ast.py                    shared scope-aware AST primitives, imported by generate_code.py (Stage 3)
                                   and validate_scripts.py (Stage 4a)
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

Evidence retrieval (`ContextBuilder.fetch_attack_evidence`) is not a flat per-technique slice: canonical
`technique_description`/`technique_overview` chunks are always included, while procedure-example chunks are
embedded and ranked by cosine similarity against the specific Stage 1 sub-query/part that originally
surfaced each technique (`technique_query_map`, built in `extract_stage1_elements`; falls back to the whole
composite query for a technique with no known originating part), reusing Stage 1's embedding client and its
`cache/query_cache.sqlite` cache (same `(normalized_query, provider, model)` key, via `hosted_embeddings.py`
and `query_offense_index.py`'s cache helpers). Each technique gets an example-chunk slot budget scaled by
how many candidates it has (`_example_slot_budget`: 1:1 up to 2 candidates, then 3/5/8 as the pool grows),
and a global ceiling (`GLOBAL_MAX_EXAMPLE_CHUNKS = 24`) trims the lowest-priority examples first
(alt-technique before top-technique, lowest relevance score before higher) if the combined budget across
all techniques is still too large. Falls back to deterministic id-order selection, never raising, if the
chunk-embedding index isn't available.

### Stage 2.5 (`plan_enhancing.py`, optional)

Not part of the core pipeline and not called by `mvp-v1.py` — a manual step that takes a finalized Stage 2
plan (`data/plans/human_outs/PLAN_*.json`) and makes a single batch LLM call (same dual-backend pattern as
Stage 2: LM Studio primary, Gemini fallback) to attach a 5-key `scenario_context` object to every task —
`narrative_role`, `upstream_assumptions`, `downstream_contract`, `consistency_notes`, `non_goals` —
describing how that task fits into the broader attack chain. The response is validated
(`_validate_context_response`) to cover exactly the plan's task IDs with all 5 non-empty string keys per
task, retrying up to `--max-retries` with the rejection reason appended to the prompt
(`_append_repair_note`). Fail-open: if every retry fails, the original plan is written through unmodified
and the manifest records `status: "degraded"` instead of blocking the pipeline; a successful run records
`status: "enhanced"`. Output goes to `data/plans/enhanced_outs/PLAN_<stem>.json` — a separate directory from
Stage 2's `data/plans/human_outs/` — and every run appends one record to
`data/plans/enhanced_outs/enhancement_manifest.jsonl`. `scenario_context` is read opportunistically by
Stage 3 (`task.get("scenario_context")`, see below) and is not part of the required-task-keys contract
Stage 3 enforces, so plans that never go through Stage 2.5 are unaffected.

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
`suggested_filename` (sanitized, then prefixed with the task ID). The reply then passes a three-step
accept gate, each step retried up to `--max-attempts` on failure: (1) `_parse_response` — a fenced
```python block that is non-empty and `ast.parse`s; (2) `_inject_dependency_imports` — a deterministic
rewrite of the sibling-import lines (see below); (3) `_validate_contract` — the provides/consumes
contract backstop. Resumable: skips tasks already `"generated"` in `manifest.jsonl` whose output file
still exists, reusing that file as dependency context. Every attempt (success or failure) is appended to
`data/code_scripts/manifest.jsonl` — an append-only audit trail, never overwritten. **Generated files can
`import` sibling generated modules by filename** — renaming a file under `data/code_scripts/` requires
grepping every other generated file for imports of the old name.

A Stage 2 plan is effectively one multi-file program sliced into tasks, stitched together by the
`provides`/`consumes` symbol contract and the `dependencies` edges — but each file is generated by a small
local model in isolation, which routinely gets the cross-file glue wrong (redeclaring a symbol it should
import, importing from the wrong module, or writing a non-portable `from data.code_scripts.<run>.TASK_001_x
import Y` path that only resolves with the repo root on `sys.path`). The correct import is fully derivable
from information the pipeline already has — the plan's edges plus each already-generated dependency's real
on-disk module stem (`_dependency_module_stems`) — so Stage 3 does not ask the model to get it right and
merely check it. `_resolve_symbol_sources` maps each consumed symbol to the dependency stem that provides
it; `_inject_dependency_imports` then deletes whatever top-level sibling-import line(s) the model wrote
(recognizing all three forms seen in practice via `pipeline_ast.sibling_stem_from_import`) and prepends one
canonical `from <stem> import <symbols>` line per consumed dependency. It edits exact source line ranges so
every untouched line survives byte-for-byte, inserts after the module docstring and any `__future__`
imports, leaves imports nested in a `try/except` fallback alone, and self-checks with `ast.parse`, falling
back to the model's original text on any doubt — the injector is never allowed to be what breaks an
otherwise-valid file. `_validate_contract` is the backstop for what injection can't fix: a `provides`
symbol must actually be *defined* (an import alone doesn't make this task its provider), and a `consumes`
symbol must be imported from the specific providing dependency, not redeclared locally, left unbound, or
sourced from the wrong module — using the shared scope-aware collectors in `pipeline_ast.py` (and
exempting the `try: import X / except ImportError: def X(): ...` optional-dependency idiom from the
"defined and imported at once" ambiguity check).

### Stage 4a (`validate_scripts.py`, optional/manual)

Execution-free static pre-flight over a whole Stage 3 run directory, meant to run after Stage 3 and before
any dynamic execution (Tier 1, then Cuckoo/CAPE) so cheap deterministic checks catch what they can before
paying for an execution environment. **Nothing is ever executed or imported here** — it only reads and
parses. `_resolve_candidates` builds the file set from the generation `manifest.jsonl` (status
`"generated"`) first, then adds any other `*.py` in the directory as `"untracked"` (recovering its
`task_id` by filename-prefix match against the supplied plan) — so hand-edited files that never went
through Stage 3 at all are still validated. Per file, `_check_file` runs: L1 `compile()` (a stricter
superset of `ast.parse` — it also rejects e.g. `return`/`yield` outside a function); L2/L3 import
classification over **every** import site in the file (not just module scope — a third-party import inside
a function still needs the package installed), splitting imports into stdlib / sibling / third-party,
resolving third-party ones with `importlib.util.find_spec` and sibling ones against the actual `*.py`
files present (`missing_sibling`, `non_portable_import` warning for a repo-root-anchored path,
`relative_import` fail); and L3b, which confirms a sibling `from X import a, b` actually finds `a`/`b` as
real module attributes of `X` (checking only top-level `ImportFrom` statements). When a `--plan` is given
and L1 passed, it then re-applies Stage 3's own `_validate_contract` to whatever is on disk (reusing that
exact function so the two never drift). Each file gets a `pass`/`warn`/`fail` verdict; one record per file
is appended to `validation_manifest.jsonl` in the run dir, and the process exits non-zero if any file
failed (so it doubles as a gate). The contract portion of this is **deliberately** redundant with Stage 3's
generation-time check for a pristine `"generated"` file (same bytes, same function, same verdict) — kept on
purpose, not an oversight to optimize away: it is a microsecond AST pass (the other four checks are *not*
redundant even on a clean run — a per-file generator can't see cross-file or environment facts), and it
keeps the gate correct for the inputs it actually exists to cover (hand-edited, untracked, or older-run
files). See `docs/STAGE4_A_STATIC_VALIDATION.md` ("On deliberately re-running the contract check").

### Tier 1 (`run_tier1_sandbox.py` + `tier1_runner.py` + `Dockerfile.tier1`, optional/manual)

The fast, disposable, network-isolated execution gate that sits strictly between Stage 4a and any
Cuckoo/CAPE submission — the "runs without errors" floor oracle (rung 3/4 of the functional-code ladder):
it proves each file's module-level code executes cleanly, not that its behavior is correct (that is
Cuckoo/CAPE's job, and eventually a richer per-task-type or self-test oracle's). It reuses Stage 4a's
`_resolve_candidates`/`_load_stage2_plan` to pick the same file set, then for each file runs a throwaway
container (`docker run -d`, image `hermes-tier1-base:latest`) with `--network none`, `--memory 256m`,
`--cpus 1`, `--read-only` rootfs + a small `/tmp` tmpfs and the run dir mounted read-only at `/task` (no
writable host mount at all). Inside, `tier1_runner.py` imports exactly one file via
`importlib.util.spec_from_file_location` + `exec_module` (with the target's own directory on `sys.path[0]`,
mirroring `python <file>.py`, which is what lets the bare-stem sibling imports resolve), redirects the
target's own stdout/stderr to a throwaway buffer so it can't pollute the result, and emits a single JSON
object — outcome `import_ok` or `import_error` (+ exception type/message/traceback) — on its stdout,
bracketed by a per-invocation random sentinel. The two other outcomes are decided host-side, never by the
runner: `timeout` (the host killed a container still running past the per-file wall-clock limit) and
`runner_error` (a container/transport failure, or no sentinel found in the logs). The host runs the
container detached and controls cleanup itself (`docker wait` with a per-file timeout -> `docker kill` on a
hang -> recover the result from `docker logs` -> `docker rm -f` always), so disposal never races `--rm`. The result
travels on the container's **stdout**, not a shared file, on purpose: on Docker Desktop a host bind mount
can hand back a file the host user can't read, and `docker cp` can't read a volume/tmpfs out of a stopped
container — `docker logs` sidesteps both (see `docs/STAGE4_A_STATIC_VALIDATION.md`). A `timeout` is
deliberately **not** a failure (a long-lived `c2_transport`-style listener with no peer hits it every time
by design). One record per file is appended to `tier1_manifest.jsonl` in the run dir; exits non-zero only
if some file's import raised.

### `pipeline_ast.py`

Shared, execution-free AST primitives for inspecting generated Python files, imported by `generate_code.py`
(Stage 3's generation-time contract check) and `validate_scripts.py` (Stage 4a) so both apply **identical**
module-scope semantics instead of two drifting copies. The key subtlety is scope-awareness:
`collect_module_level_defs` and `collect_module_level_imports` descend through module-scope control flow
(`if`/`try`/`with`/`for`/`while`) but stop at any `def`/`class` boundary, because only module-scope names
become importable attributes of the module — while `iter_all_import_statements` is deliberately *not*
scope-aware (a package imported only inside a function still has to be installed). `sibling_stem_from_import`
recognizes the three sibling-import forms seen in this corpus (bare stem, repo-root-anchored dotted path,
explicit relative import) against the stems that actually exist in the run, and
`collect_optional_dependency_fallback_names` recognizes the `try: import X / except ImportError: def X()`
idiom so a name legitimately both imported and defined there isn't flagged as a collision.

### `hosted_embeddings.py`

Shared embedding-provider abstraction. Imported by `build_offense_index.py`, `query_offense_index.py`,
`decompose_query.py` (Stage 1's near-duplicate dedup when splitting a multi-intent query), `plan_tasks.py`
(Stage 2's relevance-ranked evidence selection — see Stage 2 above), `eval_offense_generation.py`, and
`sweep_offense_retrieval_fast.py`.
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
  checks always gate model output in plain Python before it is persisted or used downstream. Where a correct
  answer is *derivable* rather than a matter of model judgment (e.g. which module a consumed symbol must be
  imported from), Stage 3 computes and injects it deterministically instead of prompting for it and then
  grading the result (`_inject_dependency_imports`).
- Scope-aware AST analysis of generated files lives in one place (`pipeline_ast.py`) and is shared by
  Stage 3's generation-time contract check and Stage 4a's static validator; keep the policy itself single-
  sourced too (Stage 4a imports Stage 3's `_validate_contract` rather than reimplementing it) so the
  generation-time and post-hoc checks can't drift apart.
- Every generation attempt (success or failure) is recorded, never silently discarded: `manifest.jsonl` for
  Stage 3, and a flat `errors` list on each Stage 2 machine record (there is no separate
  `blocking_violations`/`advisories` split in the current schema). The Stage 4 validators follow the same
  append-only-manifest convention, one record per file, written into the run dir they were pointed at:
  `validation_manifest.jsonl` (Stage 4a) and `tier1_manifest.jsonl` (Tier 1).
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
