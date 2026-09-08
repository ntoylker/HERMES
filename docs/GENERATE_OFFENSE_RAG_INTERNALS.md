# generate_offense_rag.py Internals

This document explains how [generate_offense_rag.py](../generate_offense_rag.py) works end-to-end: retrieval, source selection, citation labeling, and generation behavior.

Use this file when you need implementation-level clarity.
Use [OFFENSE_RAG_QUICKSTART.md](OFFENSE_RAG_QUICKSTART.md) for standard operational usage.

## 1) Purpose and Scope

[generate_offense_rag.py](../generate_offense_rag.py) is an orchestration entry point. It does not build its own retriever. It performs six steps:

1. Splits the query into standalone semantic parts if it mixes multiple distinct attacker behaviors, else keeps it as a single part (see section 3).
2. Runs [query_offense_index.py](../query_offense_index.py) per part with configured retrieval parameters.
3. Pulls source chunks from the SQLite index for explainability, per part.
4. Builds a constrained prompt with source IDs (`S1`, `S2`, ...), per part.
5. Calls Gemini and parses the JSON response, per part.
6. Validates each returned technique's citations against the retrieved evidence and drops any that fail (see section 5.4), per part, then merges all parts back into a single set of top-level fields (see section 3.5).

It returns a JSON object with:

- `query`
- `decomposition`: `{"decomposed": bool, "sub_queries": [...], "guardrails": {...}}` - the decision trail from step 1
- `parts`: one entry per part with its own `retrieved_techniques`, `top_techniques`, `alternatives`, `summary`, `citation_validation`
- `top_techniques` (merged across parts, post-validation; ungrounded entries already removed)
- `summary` (merged across parts)
- `alternatives` (merged across parts, post-validation; ungrounded entries already removed)
- `citation_validation`: `{"dropped": [...], "warnings": [...]}` merged audit report from step 6 (omitted, not null, if no part ever reached generation)

## 2) End-to-End Flow

Execution flow:

1. Parse CLI args in [generate_offense_rag.py](../generate_offense_rag.py).
2. Resolve the Gemini API key, base URL, and model once, up front - both decomposition and per-part generation need them.
3. Decompose the query into one or more parts via `decompose_query()` (section 3), or skip straight to a single part if `--no-decompose` is set.
4. For each part, independently:
   - Retrieve ranked techniques through [query_offense_index.py](../query_offense_index.py) using subprocess.
   - If retrieval is empty, record a deterministic empty part and move on (no Gemini call for that part).
   - Otherwise, load source text snippets from `artifacts/offense_index/offense_index.sqlite`, build a prompt with the part's text, its ranked retrieved techniques, and numbered source blocks `[S1]`, `[S2]`, ..., call Gemini `generateContent` with JSON response MIME type, parse the output as JSON (with fence/substring fallback), then validate citations - drop any `top_techniques`/`alternatives` entry whose technique or citations are not grounded in that part's retrieved evidence (section 5.4).
5. Merge all parts into top-level `top_techniques`/`alternatives`/`summary`/`citation_validation` (section 3.5).
6. Write final outputs (`.json` + `.jsonl`) and print the `.json` path.

Important boundary:

- Retrieval ranking is deterministic Python logic in [query_offense_index.py](../query_offense_index.py).
- Whether to split the query is model output constrained by a dedicated prompt; the split itself is then deterministically validated and capped, and any failure falls back to a single part (section 3.3).
- Explanations, citations assignment to claims, summary wording, and `alternatives` are model output constrained by the prompt.
- Citation validation (section 5.4) is deterministic Python logic that filters model output; it does not rewrite or repair claims.

## 3) Query Decomposition (Multi-Intent Splitting)

Before retrieval runs, [generate_offense_rag.py](../generate_offense_rag.py) calls `decompose_query()` from [decompose_query.py](../decompose_query.py) to decide whether the user's query mixes more than one distinct attacker behavior (e.g. "keylog credentials and exfiltrate them over DNS") and, if so, splits it into standalone parts that are each retrieved and generated independently.

### 3.1 Why this exists

A single combined query can retrieve techniques for its dominant behavior while starving a secondary one of retrieval budget and prompt attention - e.g. a keylogging-plus-exfiltration query that surfaces `T1056.001` cleanly but never surfaces `T1041`. Splitting first, retrieving per part, then merging closes that gap without changing the retrieval algorithm itself.

### 3.2 LLM contract

`decompose_query()` calls Gemini with a dedicated prompt (not the technique-linking prompt) and requires this exact JSON shape:

```json
{
  "decomposition_needed": true,
  "sub_queries": ["<standalone part text>", "..."]
}
```

The model is instructed to split only when the query genuinely mixes distinct tactical behaviors, to prefer NOT splitting when unsure, to reuse the user's original wording verbatim per part (no paraphrasing), and to cap output at `--max-subqueries` parts (default `4`).

### 3.3 Deterministic guardrails (fail open)

The LLM's `sub_queries` list is never trusted as-is. `_validate_subqueries()` and `_dedupe_near_duplicates()` in [decompose_query.py](../decompose_query.py) apply, in order:

1. Type/shape check - non-string entries or a missing/empty list are dropped.
2. Minimum informativeness - entries under 6 characters or fewer than 2 words are dropped as degenerate fragments.
3. Hard cap - entries beyond `--max-subqueries` are truncated.
4. Near-duplicate collapsing - remaining parts are embedded with the same hosted-embeddings client used elsewhere in the repo, and any part whose cosine similarity to an already-kept part is `>= --dedupe-threshold` (default `0.92`) is dropped.
5. Single-survivor normalization - if only one part remains after any of the above, it is replaced with the **original query text verbatim** (never a paraphrase), and the result is treated as "not decomposed".

Any exception anywhere in this path (Gemini request failure, invalid JSON, embedding failure) is caught and the whole step fails open to a single part containing the original query. This is why decomposition never blocks or crashes Stage 1: an optimization that silently declines to fire is preferred over one that injects an error. The full decision trail (raw model flag, warnings, whether a fallback fired and why) is persisted under the `decomposition` output key.

Use `--no-decompose` to skip this step entirely (useful for A/B comparison in [eval_offense_generation.py](../eval_offense_generation.py)).

### 3.4 Per-part retrieval and generation

Each surviving part (`{"id": "Q1", "text": "..."}`, ...) is run through the exact same retrieval -> source-fetch -> prompt -> Gemini -> citation-validation path described in sections 4-6, independently, with its own local `S1, S2, ...` source numbering. A part whose retrieval returns nothing skips generation entirely (same "No retrieval results." shape as the single-query case); a part whose generation call fails (empty text, invalid JSON, request error) is recorded with an `error`/`raw_text` field but does not stop the other parts from completing.

### 3.5 Merging parts into the top-level answer

`_merge_parts()` combines all parts back into the top-level `top_techniques`/`alternatives`/`summary`/`citation_validation` fields that Stage 2 already consumes:

- When there is exactly one part (no decomposition happened), the top-level fields are that part's fields unchanged - identical output shape to before this feature existed.
- When there are 2+ parts, entries are deduplicated by `mitre_id` (first occurrence across parts wins), tagged with `"from_part": "Q<n>"`, and their `citations` are re-prefixed as `"Q<n>:S<i>"` since local `S#` numbering is only unique within a part. `citation_validation.dropped`/`.warnings` entries are concatenated with the same `"Q<n>:"` prefix. `summary` becomes `"[Q1] ... [Q2] ..."`.

The top-level `citation_validation` key is omitted entirely (not `null`) when no part ever reached generation, matching the pre-decomposition contract that [eval_offense_generation.py](../eval_offense_generation.py) relies on to detect an upstream miss.

## 4) How Top Techniques Are Ranked

Ranking logic lives in [query_offense_index.py](../query_offense_index.py).

### 4.1 Candidate generation

Two candidate lists are created per query:

1. Vector candidates (`vector_k`):
   - Query embedding is generated once (or read from `cache/query_cache.sqlite`).
   - Dot-product similarity is computed against normalized chunk embeddings from `embeddings.npy`.
   - Top K chunks are selected.
2. Lexical candidates (`bm25_k`):
   - SQLite FTS5 query is built from tokenized terms.
   - BM25-ranked chunk hits are selected.

Candidate set = union(vector chunk IDs, lexical chunk IDs).

### 4.2 Technique-level aggregation

Each candidate chunk is mapped to a MITRE technique ID. For each technique:

- `vector_max` = maximum vector similarity across its candidate chunks.
- `lexical_best` = best lexical rank-derived score across its candidate chunks.

Lexical score is not raw BM25; it is transformed by rank:

$$
\text{lexical\_rank\_score} = \frac{1}{1 + \text{rank}}
$$

So top lexical hit gets `1.0`, second `0.5`, third `0.333...`, etc.

### 4.3 Final hybrid score

Default (hybrid) mode:

$$
\text{hybrid\_score} = \text{vector\_max} + (\text{lexical\_weight} \times \text{lexical\_best})
$$

Lexical-only mode:

$$
\text{hybrid\_score} = \text{lexical\_best}
$$

Techniques are sorted descending by `hybrid_score`, then truncated to `top_techniques`.

### 4.4 What this means in practice

- Vector relevance dominates by design.
- Lexical evidence is a tie-breaker/boost controlled by `lexical_weight` (default `0.05`).
- `top_techniques` in final output are grounded in this ranked retrieval list.

Canonical defaults are documented in [RETRIEVAL_CONFIG.md](RETRIEVAL_CONFIG.md).

## 5) How Sources and Citations Work

### 5.1 Source selection

[generate_offense_rag.py](../generate_offense_rag.py) iterates through retrieved techniques in ranked order and collects chunk documents from each technique's `chunks` list.

Key rules:

- Source deduplication is by `doc_id`.
- Collection stops at `max_sources` (default `40`).
- Source text is truncated to `max_chars_per_source` (default `1200`).
- A source includes: `doc_id`, `chunk_id`, `mitre_id`, `name`, `chunk_type`, `text`.

This is selection, not reranking. The script does not compute a separate source score.

### 5.2 Citation IDs (`S1`, `S2`, ...)

In prompt construction, each selected source is enumerated in order and labeled:

- `[S1] ...`
- `[S2] ...`
- `[S3] ...`

These labels are ephemeral per run. They are not persistent database identifiers.

### 5.3 Are citations ranked?

Not explicitly.

- The ordering of source blocks reflects retrieval traversal order.
- The model is instructed to cite source IDs for claims.
- `citations` arrays in output are chosen by the model from available `S#` blocks.

Therefore, `S1` does not mean "best globally." It means "first source block in this prompt instance."

### 5.4 Citation validation (groundedness gate)

Before output is written, `validate_generated_links()` checks every entry in `top_techniques` and `alternatives` against the retrieved evidence, not just against the model's own claims:

- `mitre_id` must be one of the techniques actually returned by [query_offense_index.py](../query_offense_index.py) for this run.
- `citations` must be a non-empty list of known `S#` labels from the prompt's source blocks.
- At least one cited source must belong to the same technique being claimed (technique-to-source consistency) - citing `S3` (a different technique's evidence) to support a claim about `T1059.001` fails this check.
- A non-fatal warning (not a rejection) is recorded when a multi-sentence rationale is backed by a single citation, flagging thin evidence for human review.

Any entry that fails a hard check is dropped from the output entirely (fail closed); entries are never rewritten or auto-corrected. The full accounting - which entries were dropped and why, plus any soft warnings - is persisted under the `citation_validation` key for audit, but Stage 2 ([plan_tasks.py](../plan_tasks.py)) does not read that key.

This exists because valid JSON with a plausible `mitre_id` and `citations: ["S1", "S3"]` is not proof of grounding - nothing upstream stops the model from citing a source that does not exist or that supports a different technique. See [../eval_offense_generation.py](../eval_offense_generation.py) for a corpus-level faithfulness metric built on top of this same gate.

## 6) How Alternatives Are Produced

`alternatives` are generated by Gemini from the same prompt context. There is no separate deterministic Python algorithm that computes alternatives.

Mechanism:

1. Prompt specifies required JSON schema, including `alternatives`.
2. Prompt includes ranked retrieved techniques and source blocks.
3. Model returns candidate alternatives with rationale + citations.
4. Script parses and emits the JSON.

Implication:

- `top_techniques` are retrieval-anchored.
- `alternatives` are model-synthesized, evidence-constrained by provided sources.

## 7) Configuration Surface

### 7.1 Retrieval controls

- `--top-techniques` (default `8` in generation script) - applied per part; a 2-part query can surface up to 16 techniques pre-merge
- `--top-chunks` (default `3` in generation script)
- `--vector-k` (default `25`)
- `--bm25-k` (default `25`)
- `--lexical-weight` (default `0.05`)
- `--lexical-only` (skip embeddings)
- `--human-output-dir` (default `data/human_outs`)
- `--machine-output-dir` (default `data/machine_outs`)

The script writes two files per run:

- `data/machine_outs/<timestamp>.jsonl` for machine consumption
- `data/human_outs/<timestamp>.json` for human reading

Note on defaults:

- [generate_offense_rag.py](../generate_offense_rag.py) defaults to `top-techniques=8`, `top-chunks=3` for generation context.
- [query_offense_index.py](../query_offense_index.py) defaults to `top-techniques=10`, `top-chunks=2` for direct query usage.

### 7.2 Source packaging controls

- `--max-sources` (default `40`)
- `--max-chars-per-source` (default `1200`)

These control prompt size and evidence breadth/depth tradeoff, applied per part.

### 7.3 Generation controls

- `--gen-model` (or `GEMINI_GEN_MODEL`, default `gemini-2.5-pro`) - also used for the decomposition call (section 3.2)
- `--temperature` (default `0.2`)
- `--max-output-tokens` (default `2048`; raised from `900` after empirical truncation was observed on multi-technique parts)
- `--thinking-budget` (model-dependent behavior)
- `--debug` (adds diagnostic excerpt on empty-text failures)

### 7.4 Decomposition controls

- `--no-decompose` (skip query decomposition; each run becomes a single part)
- `--max-subqueries` (default `4`)
- `--dedupe-threshold` (default `0.92`, cosine similarity threshold for collapsing near-duplicate parts)

Required environment key:

- `GOOGLE_API_KEY` (or `GEMINI_API_KEY`)

## 8) Practical Run Modes

Standard run:

```bash
./venv/bin/python generate_offense_rag.py \
  "compress and encrypt stolen files using winrar or 7-zip before exfiltration" \
  --index-dir artifacts/offense_index
```

This writes `data/machine_outs/20260710_14_23_55.jsonl` and `data/human_outs/20260710_14_23_55.json`, then prints the pretty `.json` path to the terminal.

Higher evidence breadth:

```bash
./venv/bin/python generate_offense_rag.py \
  "compress and encrypt stolen files using winrar or 7-zip before exfiltration" \
  --index-dir artifacts/offense_index \
  --top-techniques 12 \
  --top-chunks 4 \
  --max-sources 60
```

Lexical-only fallback:

```bash
./venv/bin/python generate_offense_rag.py \
  "compress and encrypt stolen files using winrar or 7-zip before exfiltration" \
  --index-dir artifacts/offense_index \
  --lexical-only
```

Tighter, cheaper generation:

```bash
./venv/bin/python generate_offense_rag.py \
  "compress and encrypt stolen files using winrar or 7-zip before exfiltration" \
  --index-dir artifacts/offense_index \
  --max-output-tokens 500 \
  --max-sources 25 \
  --max-chars-per-source 800
```

## 9) Failure Modes and Diagnostics

Common failure classes:

1. Decomposition failure (Gemini request error, invalid JSON, embedding error during dedup):
   - Caught internally; the whole step fails open to a single part containing the original query (section 3.3). Never crashes the run.
2. Retrieval failure:
   - Underlying subprocess call to [query_offense_index.py](../query_offense_index.py) fails; not caught, crashes the run (same as before this feature).
3. Empty retrieval (per part):
   - That part gets empty arrays and "No retrieval results." summary; other parts still proceed.
4. Missing API key:
   - Runtime error if `GOOGLE_API_KEY`/`GEMINI_API_KEY` is absent, checked once up front.
5. Generation empty text or request failure (per part):
   - Structured error payload with finish reason and safety metadata, or a generic `generation_request_failed` error; other parts still proceed.
6. Non-JSON model output (per part):
   - Fallback JSON with `raw_text` excerpt for that part; other parts still proceed.

Use `--debug` when investigating model-returned empty text.

## 10) Relationship to Existing Docs

- Operational quickstart: [OFFENSE_RAG_QUICKSTART.md](OFFENSE_RAG_QUICKSTART.md)
- Canonical retrieval defaults: [RETRIEVAL_CONFIG.md](RETRIEVAL_CONFIG.md)
- Stage 2 planning contract: [STAGE2_PLANNER.md](STAGE2_PLANNER.md)
- Query decomposition implementation: [decompose_query.py](../decompose_query.py) (see section 3)
- Generation-quality evaluation: `eval_offense_generation.py` (see [OFFENSE_RAG_QUICKSTART.md](OFFENSE_RAG_QUICKSTART.md) section 9)

This file is the implementation deep dive for section "5) Generate technique links (RAG)" in [OFFENSE_RAG_QUICKSTART.md](OFFENSE_RAG_QUICKSTART.md).

## 11) Stage 2 Handoff

The pretty JSON written to `data/human_outs/<timestamp>.json` is the direct input to `plan_tasks.py`. Stage 2 uses `query` and `top_techniques` as its required planning inputs; it can include `alternatives` only when explicitly requested. Stage 2 does not use the generated `S1`, `S2`, citation labels as persistent identifiers. Instead, it resolves each selected technique against the SQLite index and records durable `chunk_id` references in the task plan.

`top_techniques` and `alternatives` are already post-validation and already merged across any decomposed parts by the time Stage 2 sees them (ungrounded entries were dropped per section 5.4, parts were combined per section 3.5); Stage 2 does not re-check citations and ignores the `citation_validation`, `decomposition`, and `parts` keys entirely.