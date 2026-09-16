# HERMES MVP: Offense-Only MITRE ATT&CK RAG

HERMES is a diploma-thesis MVP: a research pipeline studying whether LLMs can write malicious code when
given structured adversary knowledge via RAG.

**Scope**: 4 stages are planned. Stages 0-3 are implemented; **Stage 4 (sandboxed execution/validation) and
a second RAG over malware-code samples do not exist yet** — Stage 3 code generation today is
task-conditioned only, not malware-sample-grounded.

**Safety**: all work must stay thesis-safe — isolated sandbox, no real exploit code, no operational attack
instructions, no real targets/credentials/persistence/live C2/exfiltration. This is a prompt-level
instruction today, not a machine-checked one: Stage 2's `data/config/stage2_constraints.json` only
constrains structure (task-type taxonomy, target language), not task content. See [CLAUDE.md](CLAUDE.md)
for the full breakdown.

## Pipeline

| Stage | Script(s) | What it does |
| --- | --- | --- |
| 0 — Corpus + Index | `build_offense_corpus.py`, `build_offense_index.py` | Chunks the ATT&CK STIX bundle and builds a hybrid BM25 + hosted-embedding retrieval index. Run once; artifacts persist on disk. |
| 1 — Technique Linking | `generate_offense_rag.py` (uses `decompose_query.py`, `query_offense_index.py`) | Splits a multi-intent query into parts, retrieves evidence per part, links each to ATT&CK techniques via Gemini, and validates that citations are grounded in retrieved evidence. |
| 2 — Task Planning | `plan_tasks.py` | Turns Stage 1's linked techniques into a validated, dependency-ordered task plan, via a dual-backend LLM (local LM Studio, Gemini fallback) plus a deterministic Python validator. |
| 3 — Code Generation | `generate_code.py` | Generates one Python file per plan task via a local LM Studio model; each reply is validated with `ast.parse`. |

`mvp-v1.py` is a temporary smoke-test driver chaining Stages 1→2→3 for a single query file — not a stable
entry point, expect it to change.

**Supporting scripts**: `hosted_embeddings.py` (shared embedding-provider abstraction),
`eval_offense_retrieval.py` / `eval_offense_generation.py` (scoring against `data/eval/eval_cases.jsonl`),
`sweep_offense_retrieval_fast.py` (retrieval parameter sweeps).

## Repository Layout

| Path | Purpose |
| --- | --- |
| `docs/` | Human-facing documentation and repo guidance. |
| `data/raw/` | Source inputs, including the MITRE ATT&CK STIX bundle. |
| `data/processed/` | Derived corpora and intermediate JSONL outputs. |
| `data/eval/` | Evaluation cases used for retrieval and generation scoring (tracked in git). |
| `data/human_outs/` / `data/machine_outs/` | Stage 1 pretty-JSON / JSONL outputs. |
| `data/config/stage2_constraints.json` | Stage 2's task-type/language constraints (structure only, not content safety). |
| `data/plans/human_outs/` / `data/plans/machine_outs/` | Stage 2 validated plans (pretty JSON, success only) / every attempted run (JSONL, valid and invalid). |
| `data/code_scripts/` | Stage 3 generated per-task Python files and `manifest.jsonl`. |
| `artifacts/offense_index/` | Hybrid index artifacts (SQLite FTS5 + embeddings). |
| `cache/` | Query embedding cache. |
| `logs/` | Run logs and sweep output. |

Note: `data/`, `cache/`, `logs/`, `*.sqlite`, `*.npy`, and most `*.jsonl` are `.gitignore`d (except
`data/eval/eval_cases.jsonl`) — these artifacts exist on disk but aren't tracked in git.

## Running the Pipeline

Requires Python 3.14 and a `.venv` in the repo root (no `requirements.txt`/`pyproject.toml` yet). See
[CLAUDE.md](CLAUDE.md) for full commands, flags, and the Stage 3 LM Studio setup (local server at
`http://localhost:1234/v1`, Qwen3.8-9B-heretic-uncensored-NVFP4 model).

## Docs

- [CLAUDE.md](CLAUDE.md) — full architecture reference
- [Quickstart](docs/OFFENSE_RAG_QUICKSTART.md)
- [Retrieval Config](docs/RETRIEVAL_CONFIG.md) — current standard: `vector_k=25`, `bm25_k=25`, `lexical_weight=0.05`
- [Data Preparation](docs/DATA_PREPARATION.md)
- [Stage 2 Planner](docs/STAGE2_PLANNER.md)
- [Stage 3 Code Generation](docs/STAGE3_CODE_GENERATION.md)
- [Generate Offense RAG Internals](docs/GENERATE_OFFENSE_RAG_INTERNALS.md)
