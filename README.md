# HERMES MVP: Offense-Only MITRE ATT&CK RAG

This repository contains an offense-focused MITRE ATT&CK retrieval pipeline.
It ingests the ATT&CK STIX bundle, builds an offense-only chunked corpus,
creates a hybrid retrieval index with lexical FTS5 plus hosted embeddings,
and exposes query, evaluation, sweep, and generation entry points.

## What Has Been Done

- Built the offense-only corpus from the MITRE ATT&CK Enterprise bundle.
- Built and validated the hybrid index.
- Swept retrieval parameters on the 13-case eval set.
- Standardized the repository retrieval settings to `vector_k=25`, `bm25_k=25`, `lexical_weight=0.05`.
- Cleaned the markdown docs and reorganized the repository into semantic folders.
- Committed the checkpoint state for future rollback and comparison.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `docs/` | Human-facing documentation and repo guidance. |
| `data/raw/` | Source inputs, including the MITRE ATT&CK STIX bundle. |
| `data/processed/` | Derived corpora and intermediate JSONL outputs. |
| `data/eval/` | Evaluation cases used for retrieval scoring. |
| `data/human_outs/` | Pretty JSON outputs from `generate_offense_rag.py` for human review. |
| `data/machine_outs/` | JSONL outputs from `generate_offense_rag.py` for machine ingestion. |
| `artifacts/offense_index/` | Primary hybrid index artifacts. |
| `artifacts/offense_index_lex/` | Lexical index artifacts. |
| `cache/` | Query embedding cache and other transient cache state. |
| `logs/` | Run logs and sweep output. |

## Main Pipeline Files

- `build_offense_corpus.py` builds the chunked corpus from the raw STIX bundle.
- `build_offense_index.py` creates the SQLite FTS5 index and hosted embeddings.
- `query_offense_index.py` runs single-query hybrid retrieval.
- `eval_offense_retrieval.py` evaluates retrieval quality on the fixed cases.
- `sweep_offense_retrieval_fast.py` sweeps retrieval parameters efficiently.
- `generate_offense_rag.py` turns retrieved evidence into a cited RAG response.
- `hosted_embeddings.py` abstracts the hosted embedding providers.

`generate_offense_rag.py` now emits timestamped outputs to separate locations by default:

- `data/human_outs/<timestamp>.json` for human-friendly review
- `data/machine_outs/<timestamp>.jsonl` for line-delimited machine processing

## Canonical References

- [Quickstart](docs/OFFENSE_RAG_QUICKSTART.md)
- [Retrieval Config](docs/RETRIEVAL_CONFIG.md)
- [Data Preparation Notes](docs/DATA_PREPARATION.md)

## Current Standard

The repo standard retrieval settings are:

- `vector_k = 25`
- `bm25_k = 25`
- `lexical_weight = 0.05`

These are the default values in the query, eval, generation, and sweep entry points.