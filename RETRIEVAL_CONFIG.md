# Retrieval Config

This file is the source of truth for the standard hybrid retrieval parameters used across the repo.

## Canonical Parameters

- `vector_k = 25`
- `bm25_k = 25`
- `lexical_weight = 0.05`

## Why These Values

These are the winning parameters from the 13-case retrieval sweep run on 2026-07-10. They achieved `recall@10 = 1.0` and `mrr = 0.8461538461538461` on the current eval set.

## Where They Apply

- `query_offense_index.py`
- `eval_offense_retrieval.py`
- `generate_offense_rag.py`
- `sweep_offense_retrieval_fast.py` as the baseline standard when you want to compare against alternatives

## Operational Rule

If you intentionally deviate from these parameters for an experiment, record the override next to the experiment or sweep output so the checkpoint remains reproducible.