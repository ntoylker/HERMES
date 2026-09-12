# HERMES MVP: Offense-Only MITRE ATT&CK RAG

HERMES is a diploma-thesis MVP: a research pipeline studying whether LLMs can write malicious code
when given structured adversary knowledge via RAG. Stage 0 ingests the ATT&CK STIX bundle, builds an
offense-only chunked corpus, and creates a hybrid retrieval index with lexical FTS5 plus hosted
embeddings. Stage 1 links an abstract query to ATT&CK techniques. Stage 2 converts those linked
techniques into an evidence-grounded, dependency-ordered task plan. Stage 3 generates one Python file
per plan task via a local LM Studio model.

The intended design has 4 stages, of which the first 3 are implemented. **Stage 4 (sandboxed
execution/validation) and a second RAG over malware-code samples do not exist yet** — Stage 3 code
generation today is task-conditioned only, not malware-sample-grounded.

All work in this repo must stay thesis-safe: isolated sandbox, no real exploit code, no operational
attack instructions, no real targets/credentials/persistence/live C2/exfiltration. Stage 2's
`data/config/stage2_constraints.json` encodes this as machine-checked policy — see
[Architecture](CLAUDE.md) for details.

## What Has Been Done

- Built the offense-only corpus from the MITRE ATT&CK Enterprise bundle.
- Built and validated the hybrid retrieval index.
- Swept retrieval parameters on the 13-case eval set.
- Standardized the repository retrieval settings to `vector_k=25`, `bm25_k=25`, `lexical_weight=0.05`.
- Implemented Stage 1 (technique linking + citation validation) and Stage 2 (task planning +
  deterministic Python validation), each with their own JSON/JSONL output pair.
- Implemented Stage 3 (per-task code generation) against a local LM Studio server, with a resumable
  manifest and AST-compacted dependency context.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `docs/` | Human-facing documentation and repo guidance. |
| `data/raw/` | Source inputs, including the MITRE ATT&CK STIX bundle. |
| `data/processed/` | Derived corpora and intermediate JSONL outputs. |
| `data/eval/` | Evaluation cases used for retrieval and generation scoring (tracked in git). |
| `data/human_outs/` | Pretty JSON outputs from `generate_offense_rag.py` for human review. |
| `data/machine_outs/` | JSONL outputs from `generate_offense_rag.py` for machine ingestion. |
| `data/config/stage2_constraints.json` | Deterministic policy and scope for Stage 2 planning. |
| `data/plans/` | Stage 2 human-readable plans, machine-readable plans, and saved planning contexts. |
| `data/code_scripts/` | Stage 3 generated per-task Python files and `manifest.jsonl`. |
| `artifacts/offense_index/` | Primary hybrid index artifacts (SQLite FTS5 + embeddings). |
| `cache/` | Query embedding cache and other transient cache state. |
| `logs/` | Run logs and sweep output. |

Note: `data/`, `cache/`, `logs/`, `*.sqlite`, `*.npy`, and most `*.jsonl` are `.gitignore`d (except
`data/eval/eval_cases.jsonl`), so these artifacts exist on disk but aren't tracked in git.

## Main Pipeline Files

- `build_offense_corpus.py` builds the chunked corpus from the raw STIX bundle.
- `build_offense_index.py` creates the SQLite FTS5 index and hosted embeddings.
- `query_offense_index.py` runs single-query hybrid retrieval (called by everything below).
- `generate_offense_rag.py` — **Stage 1**: splits multi-intent queries (via `decompose_query.py`),
  retrieves evidence, links techniques with Gemini, and validates that citations are grounded.
- `plan_tasks.py` — **Stage 2**: turns a Stage 1 output into a validated, dependency-ordered task
  plan, deterministically checked against `data/config/stage2_constraints.json`.
- `generate_code.py` — **Stage 3**: turns a Stage 2 plan into per-task Python files via a local
  LM Studio model, gated on `planning_status == "valid"`.
- `hosted_embeddings.py` abstracts the hosted embedding providers (Google AI Studio, Azure OpenAI,
  OpenAI).
- `eval_offense_retrieval.py` evaluates retrieval quality on the fixed eval cases.
- `eval_offense_generation.py` evaluates Stage 1 generation quality on the fixed eval cases.
- `sweep_offense_retrieval_fast.py` sweeps retrieval parameters efficiently.
- `mvp-v1.py` is a one-shot driver that runs a query `.txt` file through Stages 1 -> 2 -> 3.

`generate_offense_rag.py` always emits timestamped outputs to separate locations, even on empty
retrieval or Gemini failure:

- `data/human_outs/<timestamp>.json` for human-friendly review
- `data/machine_outs/<timestamp>.jsonl` for line-delimited machine processing

Stage 2 follows the same pretty-JSON/JSONL pattern under `data/plans/`.

## Running the Pipeline

See `CLAUDE.md` for full commands, flags, and the Stage 3 LM Studio setup (local server at
`http://localhost:1234/v1`, Qwen3.8-9B-heretic-uncensored-NVFP4 model). No test suite, linter, or
pinned dependency manifest exists in this repo yet.

## Canonical References

- [Quickstart](docs/OFFENSE_RAG_QUICKSTART.md)
- [Retrieval Config](docs/RETRIEVAL_CONFIG.md)
- [Data Preparation Notes](docs/DATA_PREPARATION.md)
- [Stage 2 Planner](docs/STAGE2_PLANNER.md)
- [Stage 3 Code Generation](docs/STAGE3_CODE_GENERATION.md)
- [Generate Offense RAG Internals](docs/GENERATE_OFFENSE_RAG_INTERNALS.md)

## Current Standard

The repo standard retrieval settings are:

- `vector_k = 25`
- `bm25_k = 25`
- `lexical_weight = 0.05`

These are the default values in the query, eval, generation, and sweep entry points.
