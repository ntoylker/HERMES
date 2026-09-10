# Stage 3 Code Generation

`generate_code.py` turns a Stage 2 task plan (schema v2.0) into one Python file per task. Each task is sent to a **local LM Studio** model (via its OpenAI-compatible `/v1/chat/completions` endpoint) as an independent chat request; the script parses, syntax-checks, and persists the reply, then moves to the next task in dependency order.

## Inputs

The required positional input is a Stage 2 plan file, normally `data/plans/human_outs/PLAN_<stage1-stem>.json`. The plan must contain a non-empty `tasks` array where every task has the required v2.0 keys (`task_id`, `task_type`, `suggested_filename`, `description`, `technique_ids`, `dependencies`, `provides`, `consumes`, `implementation_details`); otherwise generation aborts before calling the model. There is no `execution_order` field anymore — it is derived from each task's `dependencies` via a DFS topological sort (`_topological_order`), which also raises if it detects a cycle.

For each task, in that derived order, the script builds a prompt from:

- The task's own fields: `task_type`, `suggested_filename`, `description`, `technique_ids`, `provides`, `consumes`, `implementation_details`, `rag_retrieval_hints`.
- Interfaces of already-generated dependency tasks (`dependencies`), so field and function names stay consistent across files. Dependency bodies are stripped to their signature and docstring (`_compact_dependency_code`) to keep the prompt small; only already-generated dependencies can be shown this way.

## Model Contract

The plan (not the model) fixes each task's output filename via `suggested_filename`. The prompt requires the model to reply with nothing but:

````
```python
<complete file contents>
```
````

The parser (`_parse_response`) rejects a reply that is missing a fenced code block, has an empty code block, or fails `ast.parse` (a syntax error). A rejected reply is retried with a repair note appended to the same prompt, up to `--max-attempts` times; a task that still fails is recorded as `"failed"` and generation continues with the next task.

## Run

Requires a local LM Studio server with the target model loaded (Developer tab → "Start Server", default `http://localhost:1234`). LM Studio's context window is fixed when the model is loaded (in its UI/CLI), not per-request — there is no `--num-ctx`-style flag here.

```bash
python generate_code.py data/plans/human_outs/PLAN_<stage1-stem>.json
```

Useful options:

- `--model`: LM Studio model identifier (check `GET /v1/models` on your server — LM Studio normalizes the
  HuggingFace repo name); default `qwen3.8-9b-heretic-uncensored-nvfp4`
- `--base-url`: LM Studio OpenAI-compatible base URL; default `http://localhost:1234/v1`
- `--timeout`: per-request timeout in seconds; default `1200` (at ~10 t/s GPU-only, a full 8192-token reply
  takes ~845s, so this leaves margin for a max-length generation)
- `--output-dir`: destination for generated files and the manifest; default `data/code_scripts`
- `--max-attempts`: model attempts per task before it is marked failed; default `2`
- `--max-tokens`: max completion tokens per request; default `8192` (bounds a single reply so a task that
  never closes its code fence fails fast with `finish_reason: "length"` instead of silently consuming the
  model's whole context)
- `--force`: regenerate every task even if already marked `"generated"` in the manifest

## Resuming

Generation is resumable: on each run the script loads `manifest.jsonl` and skips any task whose latest record has `status: "generated"` and whose output file still exists, reusing that file's code as dependency context. Use `--force` to ignore prior manifest state and regenerate everything.

## Output Contract

Each generated task writes `data/code_scripts/<TASK-ID>_<filename>.py`, where `<filename>` comes from the plan's `suggested_filename` (a redundant `TASK-ID_` prefix inside it is stripped first).

Every attempt — successful or failed — appends one record to `data/code_scripts/manifest.jsonl`:

- `task_id`, `filename` (`null` on failure), `technique_ids`, `task_type`
- `plan_id`, `stage1_ref`: traceability back to the Stage 2 plan and Stage 1 output file
- `model`, `status` (`generated` or `failed`), `attempts`, `error`
- `diagnostics`: `prompt_tokens`/`completion_tokens`/`total_tokens` from LM Studio's `usage` field, `finish_reason` (`"stop"` if the model closed cleanly, `"length"` if it hit `--max-tokens` and was cut off), plus `total_duration_s` measured as request wall-clock time (LM Studio's OpenAI-compatible endpoint doesn't report per-phase timings the way Ollama did)
- `timestamp`

Because generated files can import from their dependencies' generated modules by filename, renaming a file under `data/code_scripts/` requires updating any other generated file that imports it.

## Relationship to Stage 2

Stage 2 produces an ordered, evidence-grounded task plan without writing any source code. Stage 3 is the only stage that calls a code-generation model, and it does so once per task, independently, using the plan as its sole specification.
