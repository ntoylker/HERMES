# Stage 3 Code Generation

`generate_code.py` turns a validated Stage 2 task plan into one Python file per task. Each task is sent to a **local Ollama** model as an independent chat request; the script parses, syntax-checks, and persists the reply, then moves to the next task in dependency order.

## Inputs

The required positional input is a Stage 2 plan file, normally `data/plans/human_outs/<timestamp>.json`. The plan's `planning_status` must be `valid`, otherwise generation aborts before calling the model.

For each task, in `execution_order`, the script builds a prompt from:

- The task's own fields: `title`, `task_type`, `language`, `purpose`, `maps_to_techniques`, `inputs`, `outputs`, `constraints`, `acceptance_criteria`.
- Interfaces of already-generated dependency tasks (`depends_on`), so field and function names stay consistent across files. Dependency bodies are stripped to their signature and docstring (`_compact_dependency_code`) to keep the prompt small; only already-generated dependencies can be shown this way.

## Model Contract

The prompt requires the model to reply with nothing but:

````
FILENAME: <short_snake_case_name>.py
```python
<complete file contents>
```
````

The parser (`_parse_response`) rejects a reply that is missing the `FILENAME:` line, missing a fenced code block, has an empty code block, or fails `ast.parse` (a syntax error). A rejected reply is retried with a repair note appended to the same prompt, up to `--max-attempts` times; a task that still fails is recorded as `"failed"` and generation continues with the next task.

## Run

Requires a local Ollama server with the target model pulled.

```bash
python generate_code.py data/plans/human_outs/<stage2-timestamp>.json
```

Useful options:

- `--model`: Ollama model name; default `huihui_ai/Qwen3.8-abliterated:latest`
- `--base-url`: Ollama server URL; default `http://localhost:11434`
- `--timeout`: per-request timeout in seconds; default `300` (large models generating full files can need much longer — raise this if requests time out)
- `--output-dir`: destination for generated files and the manifest; default `data/code_scripts`
- `--max-attempts`: model attempts per task before it is marked failed; default `2`
- `--num-ctx`: Ollama context window size (`options.num_ctx`); default `8192`
- `--force`: regenerate every task even if already marked `"generated"` in the manifest

## Resuming

Generation is resumable: on each run the script loads `manifest.jsonl` and skips any task whose latest record has `status: "generated"` and whose output file still exists, reusing that file's code as dependency context. Use `--force` to ignore prior manifest state and regenerate everything.

## Output Contract

Each generated task writes `data/code_scripts/<TASK-ID>_<filename>.py`, where `<filename>` is the model-chosen name (a redundant `TASK-ID_` prefix echoed by the model is stripped first).

Every attempt — successful or failed — appends one record to `data/code_scripts/manifest.jsonl`:

- `task_id`, `filename` (`null` on failure), `maps_to_techniques`, `task_type`, `language`
- `plan_id`, `request_id`: traceability back to the Stage 2 plan and Stage 1 request
- `model`, `status` (`generated` or `failed`), `attempts`, `error`
- `diagnostics`: Ollama's `prompt_eval_count`, `eval_count`, and duration fields converted from nanoseconds to seconds
- `timestamp`

Because generated files can import from their dependencies' generated modules by filename, renaming a file under `data/code_scripts/` requires updating any other generated file that imports it.

## Relationship to Stage 2

Stage 2 produces an ordered, evidence-grounded task plan without writing any source code. Stage 3 is the only stage that calls a code-generation model, and it does so once per task, independently, using the plan as its sole specification.
