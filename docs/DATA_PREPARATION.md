# Data Preparation Notes

This file is kept as a legacy reference. The canonical, current instructions live in [OFFENSE_RAG_QUICKSTART.md](OFFENSE_RAG_QUICKSTART.md) and [RETRIEVAL_CONFIG.md](RETRIEVAL_CONFIG.md).

## What the pipeline does

1. `build_offense_corpus.py` reads `data/raw/enterprise-attack/enterprise-attack.json`, filters for offense-only techniques, and writes `data/processed/rag_offense_mitre_chunks.jsonl`.
2. `build_offense_index.py` builds `artifacts/offense_index/offense_index.sqlite`, `artifacts/offense_index/embeddings.npy`, and `artifacts/offense_index/index_meta.json` using a hosted embedding provider.
3. `query_offense_index.py` runs hybrid retrieval over SQLite FTS5 plus vector embeddings and caches query embeddings in `cache/query_cache.sqlite`.
4. `generate_offense_rag.py` retrieves supporting chunks, asks Gemini to produce a cited answer, and writes outputs to `data/human_outs/<timestamp>.json` and `data/machine_outs/<timestamp>.jsonl`.

## Notes

- The retrieval defaults are standardized elsewhere in the repo; use [RETRIEVAL_CONFIG.md](RETRIEVAL_CONFIG.md) as the source of truth.
- `hosted_embeddings.py` is a shared helper module and is not run directly.
- `eval_offense_retrieval.py` is the batch evaluation entry point for `data/eval/eval_cases.jsonl`.