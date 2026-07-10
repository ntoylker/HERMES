# Offense-Only MITRE ATT&CK RAG (Hybrid Retrieval)

This workspace contains a small pipeline that:

1. Builds an offense-only chunked MITRE ATT&CK JSONL corpus
2. Builds a hybrid index: SQLite FTS5 plus hosted embeddings
3. Queries the index and aggregates hits to the technique level

Canonical retrieval config: [RETRIEVAL_CONFIG.md](RETRIEVAL_CONFIG.md)

Recommended repo layout:

- [docs/](docs)
- [data/raw/enterprise-attack/enterprise-attack.json](data/raw/enterprise-attack/enterprise-attack.json)
- [data/processed/rag_offense_mitre_chunks.jsonl](data/processed/rag_offense_mitre_chunks.jsonl)
- [data/eval/eval_cases.jsonl](data/eval/eval_cases.jsonl)
- [data/human_outs/](data/human_outs)
- [data/machine_outs/](data/machine_outs)
- [artifacts/offense_index/](artifacts/offense_index)
- [artifacts/offense_index_lex/](artifacts/offense_index_lex)
- [cache/query_cache.sqlite](cache/query_cache.sqlite)
- [logs/](logs)

## 1) Build the offense-only chunked corpus

```bash
./venv/bin/python build_offense_corpus.py \
  --input data/raw/enterprise-attack/enterprise-attack.json \
  --output data/processed/rag_offense_mitre_chunks.jsonl
```

Output: `data/processed/rag_offense_mitre_chunks.jsonl`

## 2) Configure hosted embeddings

Choose one provider.

Note: If you do not set `EMBED_PROVIDER`, the code auto-detects the provider based on which API key env var you set, in this order: Google AI Studio → Azure OpenAI → OpenAI.

### Option A: OpenAI

```bash
export EMBED_PROVIDER=openai
export OPENAI_API_KEY="..."
# Optional
export OPENAI_EMBED_MODEL="text-embedding-3-small"
export OPENAI_BASE_URL="https://api.openai.com/v1"
```

### Option B: Azure OpenAI

```bash
export EMBED_PROVIDER=azure_openai
export AZURE_OPENAI_ENDPOINT="https://<your-resource>.openai.azure.com"
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_EMBED_DEPLOYMENT="<your-embedding-deployment-name>"
# Optional
export AZURE_OPENAI_API_VERSION="2024-02-15-preview"
```

### Option C: Google AI Studio (Gemini API)

1) Create an API key in AI Studio: https://aistudio.google.com/app/apikey

2) Set one of these env vars (recommended: `GOOGLE_API_KEY`):

```bash
export EMBED_PROVIDER=google_ai_studio
export GOOGLE_API_KEY="..."   # or: export GEMINI_API_KEY="..."

# Optional: choose the embedding model
export GEMINI_EMBED_MODEL="gemini-embedding-001"  # or: gemini-embedding-2

# Optional: choose the generation model (used by generate_offense_rag.py)
export GEMINI_GEN_MODEL="gemini-2.5-pro"
```

## 3) Build the hybrid index

This creates:
- `artifacts/offense_index/offense_index.sqlite` (chunks + FTS)
- `artifacts/offense_index/embeddings.npy` (float32, normalized)
- `artifacts/offense_index/index_meta.json`

```bash
./venv/bin/python build_offense_index.py \
  --corpus data/processed/rag_offense_mitre_chunks.jsonl \
  --outdir artifacts/offense_index \
  --overwrite
```

If you use Gemini and hit request-size errors, try a smaller batch size, e.g. `--batch-size 16`.

Note: If you change the embedding model, rebuild the index with `--overwrite` to avoid dimension mismatches.

Tips:
- Quick/dev run: add `--limit 2000`
- Lexical-only (no API calls): add `--skip-embeddings`

## 4) Query and aggregate to techniques

The repository standard for everyday query/eval/generate runs is `vector_k=25`, `bm25_k=25`, `lexical_weight=0.05`. Those are also the defaults in the code.

```bash
./venv/bin/python query_offense_index.py \
  "abuse wmi to execute payload remotely" \
  --index-dir artifacts/offense_index \
  --top-techniques 10
```

Lexical-only (no embeddings required):

```bash
./venv/bin/python query_offense_index.py \
  "abuse wmi to execute payload remotely" \
  --index-dir artifacts/offense_index \
  --lexical-only
```

JSON output:

```bash
./venv/bin/python query_offense_index.py "..." --json
```

The query embedding cache is stored as `cache/query_cache.sqlite`, not inside the index directory.

## 5) Generate technique links (RAG)

This wraps retrieval + Gemini generation and writes:
- a pretty `.json` file to `data/human_outs/`
- a compact `.jsonl` file to `data/machine_outs/`

For implementation details (ranking logic, source/citation behavior, and alternatives generation), see [GENERATE_OFFENSE_RAG_INTERNALS.md](GENERATE_OFFENSE_RAG_INTERNALS.md).

```bash
./venv/bin/python generate_offense_rag.py \
  "abuse wmi to execute payload remotely" \
  --index-dir artifacts/offense_index
```

Optional knobs:
- `--top-techniques`, `--top-chunks`
- `--vector-k`, `--bm25-k`, `--lexical-weight` if you are intentionally deviating from the standard config
- `--max-sources`, `--max-chars-per-source`
- `--gen-model`, `--temperature`, `--max-output-tokens`
- `--human-output-dir` to override the default `data/human_outs/` destination
- `--machine-output-dir` to override the default `data/machine_outs/` destination

The `.json` file is the human-friendly view; the `.jsonl` file is the machine-friendly line-delimited artifact.

## 6) Evaluate retrieval

Create eval cases in `data/eval/eval_cases.jsonl` (one JSON object per line):

```json
{"query": "abuse wmi to execute payload remotely", "expected": ["T1047"]}
{"query": "remote services via psexec", "expected": ["T1569.002"]}
```

Run evaluation:

```bash
./venv/bin/python eval_offense_retrieval.py \
  --cases data/eval/eval_cases.jsonl \
  --index-dir artifacts/offense_index
```

Lexical-only baseline:

```bash
./venv/bin/python eval_offense_retrieval.py \
  --cases data/eval/eval_cases.jsonl \
  --index-dir artifacts/offense_index \
  --lexical-only
```
