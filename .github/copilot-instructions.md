# Project Context

Diploma thesis MVP: two-stage MITRE ATT&CK pipeline (Stage 1: query → TTPs via RAG; Stage 2: TTPs → task plans).

See [README.md](../README.md) for architecture, [docs/OFFENSE_RAG_QUICKSTART.md](../docs/OFFENSE_RAG_QUICKSTART.md) for Stage 1, and [docs/STAGE2_PLANNER.md](../docs/STAGE2_PLANNER.md) for Stage 2.

## Key Terms

- **TTP**: MITRE ATT&CK Tactics, Techniques, Procedures
- **STIX**: Structured Threat Information eXpression (MITRE data format)
- **Offense corpus**: ATT&CK techniques filtered for offensive operations only
- **Hybrid retrieval**: BM25 + vector embeddings (vector_k=25, bm25_k=25, lexical_weight=0.05)

## Coding Standards

- **Python**: Concise inline comments for software engineers only — no verbose explanations
- **Documentation**: Brief, precise — link to docs, don't duplicate
- **Retrieval**: All embeddings are hosted (no local GPU)
- **Academic context**: Isolated sandbox, defensive research — no real exploit code or operational attack instructions
