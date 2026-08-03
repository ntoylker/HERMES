# Stage 2 Task Planner

`plan_tasks.py` turns a Stage 1 ATT&CK technique-linking result into an ordered, evidence-grounded task plan. The planner proposes implementation-neutral tasks for benign simulations, telemetry, interfaces, and tests; it does not generate source code.

## Inputs

The required positional input is a pretty JSON result created by `generate_offense_rag.py`, normally under `data/human_outs/`.

The planner uses these Stage 1 fields:

- `query`
- `top_techniques` as the required primary techniques
- `alternatives` only when `--include-alternatives` is set

For each selected technique, it obtains additional context from two local sources:

1. `artifacts/offense_index/offense_index.sqlite`: one or more ATT&CK chunks, selected with the technique description first, then the overview. This supplies persistent `chunk_id` evidence references rather than Stage 1's run-specific `S1`, `S2`, citation labels.
2. `data/patterns/code_patterns.jsonl`: up to `--patterns-per-technique` vetted pattern records matched by exact MITRE ATT&CK ID. A missing pattern is allowed; the planner still uses ATT&CK evidence.

The exact planning context given to the model is written to `data/plans/machine_outs/<timestamp>.input.json`.

## Constraints

`data/config/stage2_constraints.json` declares the planning environment, network policy, implementation mode, allowed task types, allowed languages, and review keywords.

Allowed task types and languages are included in the model prompt and enforced by the Python validator. The environment, network policy, and implementation mode are persisted in the plan's `scope`. `forbidden_capability_keywords` are recorded as advisories for human review when found in a task's title, purpose, or constraints; they do not independently reject a plan.

## Planning Flow

1. Load the Stage 1 result and planning constraints.
2. Build per-technique context from the SQLite ATT&CK index and exact-ID pattern matches.
3. Ask Gemini for a JSON draft containing locally named tasks and dependencies.
4. Validate and normalize the draft deterministically.
5. On a blocking validation failure, provide the violations to Gemini and retry up to `--max-repair-attempts` times.
6. Persist the canonical plan and its planning context.

The validator checks:

- allowed task types and languages
- known primary or optional-alternative technique IDs
- known task dependency references and dependency cycles
- coverage of every primary technique
- evidence references against the context supplied to the model

The model provides local task IDs such as `t1`. The validator applies the final topological ordering, assigns canonical `TASK-001`-style IDs, and rewrites dependency references to those canonical IDs. When a task cites no valid ATT&CK chunk or pattern, the validator fills one available evidence reference for its first mapped technique and records an advisory.

## Run the Planner

Gemini generation requires `GOOGLE_API_KEY` or `GEMINI_API_KEY`; the planner uses `GEMINI_GEN_MODEL` when set, otherwise `gemini-2.5-pro`.

```bash
./venv/bin/python plan_tasks.py \
  data/human_outs/<stage1-timestamp>.json \
  --index-dir artifacts/offense_index
```

Useful options:

- `--pattern-library`: pattern JSONL location; default `data/patterns/code_patterns.jsonl`
- `--constraints-file`: planning policy JSON location; default `data/config/stage2_constraints.json`
- `--evidence-per-technique`: ATT&CK chunks included per technique; default `1`
- `--patterns-per-technique`: exact-ID pattern records included per technique; default `2`
- `--include-alternatives`: add Stage 1 alternatives as optional planning context
- `--max-repair-attempts`: number of model attempts after validation failures; default `2`
- `--max-output-tokens`: model output budget; default `4000`

## Output Contract

Each execution creates three timestamped artifacts:

- `data/plans/human_outs/<timestamp>.json`: formatted canonical plan
- `data/plans/machine_outs/<timestamp>.jsonl`: single-line machine-readable canonical plan
- `data/plans/machine_outs/<timestamp>.input.json`: persisted model context for reproducibility

The canonical plan includes:

- `planning_status`: `valid`, `invalid`, or `no_techniques`
- `scope`: the environment, network, and implementation constraints used for planning
- `tasks`: normalized tasks with canonical IDs, inputs, outputs, dependencies, acceptance criteria, and ATT&CK/pattern evidence references
- `execution_order`: a dependency-safe order of canonical task IDs
- `technique_coverage`: the tasks covering each primary ATT&CK technique
- `validation`: repair-attempt count, blocking violations when invalid, and non-blocking advisories

An invalid plan is still persisted with an empty task list, `uncovered` primary techniques, and the final blocking validation violations. This lets downstream code reject it without parsing model text.

## Relationship to Stage 1

Stage 1 answers which ATT&CK techniques describe a query. Stage 2 uses those techniques as the required coverage set and produces a structured task plan with durable evidence references. The planner does not rerank retrieval results or modify the Stage 1 result.