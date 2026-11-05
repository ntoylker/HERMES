# Stage 2.5 Plan Enhancement

`plan_enhancing.py` is an optional, manual step between Stage 2 and Stage 3. It takes a finalized Stage 2
plan and attaches a per-task `scenario_context` object — narrative framing describing how each task fits
into the broader attack chain — so Stage 3's code generator gets more than the task's own
`description`/`implementation_details` when writing a file that has to integrate with its siblings. It is
**not** called by `mvp-v1.py` and not required for Stage 3 to run; a plan that never goes through this
stage is unaffected, since `scenario_context` is read opportunistically (`task.get("scenario_context")`)
and is not part of Stage 3's required-task-keys contract.

## Inputs

The required positional argument is a Stage 2 plan file, normally `data/plans/human_outs/PLAN_<stage1-
stem>.json`. `_load_plan` only checks that `tasks` exists and is non-empty — it does not re-run Stage 2's
own validator. `plan.source_query` and `plan.stage1_ref` are read to pull in the original query and (via
`_load_stage1_summary`, which looks under `data/human_outs/` and fails open to an empty string if the file
is missing or unparseable) the Stage 1 summary — both are folded into the prompt as framing context, not
validated.

## Why keys are gated per task, not fixed at 5

`scenario_context` has 5 possible keys: `narrative_role`, `upstream_assumptions`, `downstream_contract`,
`consistency_notes`, `non_goals`. Only the first, third, and fifth are unconditional. The other two each
describe a real edge in the plan's dependency DAG, and a task without that edge has nothing true to put
there:

- **`upstream_assumptions`** only applies if the task has a non-empty `dependencies` list. A task with no
  dependencies has nothing upstream to assume.
- **`downstream_contract`** only applies if some *other* task in the plan actually lists this task's
  `task_id` in its own `dependencies` — i.e. this task is not **terminal**. A terminal task's external
  contract is already fully defined by the plan's `source_query` and its own `implementation_details`;
  restating that in free text manufactures a "contract" with nothing on the other end of it, which is a
  hallucination risk, not new information.

`_dependents_map(plan)` computes the reverse edge (who lists *me* as a dependency) once for the whole plan
— a task's own `dependencies` is a local read, but "who depends on me" requires scanning every other task,
which is exactly the computation that empirically fell apart for the local model once it had to repeat it
once per task inside one long batch generation (see `docs/LLM_PROMPTS_REFERENCE.md` and the note in
`_dependents_map`'s own docstring: in a 12-task test, every single per-task validation failure was this one
lookup — never the symmetric-looking but actually local upstream check). `_terminal_task_ids(plan)` is the
set of task IDs with an empty entry in that map. `_expected_context_keys(task, terminal_ids)` combines both
facts into the exact key set for one task — this function is the single source of truth for "which keys
does this task_id need," called identically by the batch prompt builder, the per-task validator, the
isolated-retry prompt builder, and the deterministic fallback, so none of them can drift from the others.

## Dependency facts are computed, not left for the model to re-derive

`_format_dependency_facts(task, tasks_by_id, dependents)` renders the forward edge (this task's
`dependencies`, with each one's `provides`) and the backward edge (this task's real dependents, from
`_dependents_map`, with this task's own `provides`) as plain pre-computed fact lines, e.g.:

```
    upstream_assumptions fact: depends on TASK_001 (provides: ProcessInfo)
    downstream_contract fact: provides enumerate_processes; actually consumed in this plan by TASK_003 -- base the field on this, don't re-derive it
```

The prompt tells the model to expand each fact into prose, not to re-scan the plan and recompute the edge
itself. This is the same principle Stage 3 applies to import injection
([STAGE3_CODE_GENERATION.md](STAGE3_CODE_GENERATION.md)): where the correct answer is mechanically
derivable from the plan's own structure, Stage 2.5 computes it and hands it over, rather than prompting for
it and hoping.

## Enhancement Flow (`_enhance_plan`)

A single bad task no longer costs the other N-1 their enhancement. The flow has three steps, and only the
first one is genuinely all-or-nothing:

1. **One batch call, retried only on structural failure.** `_build_context_prompt` assembles one prompt
   covering every task at once (full plan JSON inlined, plus a per-task "include ONLY these keys" listing
   and each task's dependency facts). The response is retried up to `--max-retries` times, but **only**
   for failures that really are all-or-nothing: unparseable JSON, or a task_id set that doesn't exactly
   match the plan (`_validate_batch_shape`). As soon as a structurally valid batch response comes back —
   right shape, right task_ids, each mapped to an object — the batch retry loop stops, even if some
   individual task's *content* inside that response is wrong. Content correctness is deliberately not
   checked here.
2. **Per-task validation, with isolated retry on failure.** Each task's context object from the batch
   response is checked independently by `_validate_single_task_context`: does it have *exactly* the keys
   `_expected_context_keys` says apply to this task_id (no required key missing, no not-applicable key
   smuggled in), and is every present value a non-empty string? A task that passes is kept as-is. A task
   that fails is retried alone, via `_retry_single_task`: a scoped-down prompt (`_build_single_task_prompt`)
   that shows the full plan for context but asks for only that one task's flat object, with its own small
   `--max-retries` budget. The other tasks are never touched, re-sent, or put at risk by this retry.
3. **Deterministic fallback, never a dead end.** If a task still fails after its isolated retries — or the
   batch call never produced a structurally valid response at all, in which case every task skips straight
   here — its context is computed directly from the plan's own structure by
   `_deterministic_task_context`, instead of asking the model again. It derives `narrative_role` from the
   task's own `description` and `technique_ids`, `upstream_assumptions`/`downstream_contract` from the same
   dependency/dependents facts `_format_dependency_facts` would have shown the model, `consistency_notes`
   from `task_type` and `implementation_details`, and `non_goals` by listing every other task's
   `description`. It is plainer prose than an LLM-authored version, but by construction it cannot
   hallucinate a relationship that doesn't exist in the plan — which is the actual failure mode the whole
   per-task-key-gating mechanism exists to prevent.

This means `_enhance_plan` never gives up on the plan as a whole, and never leaves a task with zero
context. What it tracks instead is **which** tasks needed the fallback and **why**, via `dropped_tasks` — a
list of `{"task_id", "reason"}` entries, empty if none did.

## Status values

`_enhance_plan` returns `(enhanced_plan, status, dropped_tasks)`:

- `"enhanced"` — every task's `scenario_context` came from the model (batch or isolated retry), no
  deterministic fallback used.
- `"enhanced_partial"` — at least one task fell back to `_deterministic_task_context`; `dropped_tasks`
  names which and why.
- `"degraded"` — dead code path, kept only defensively. In the current flow `_enhance_plan` always returns
  a fully-populated plan (steps 2-3 guarantee every task gets *some* context), so this status can no
  longer actually be produced; `main()`'s `if status == "degraded":` branch is unreachable in practice.

Unlike the pre-rewrite version, a failed enhancement run no longer passes the original plan through
unmodified — there is always a `scenario_context` on every task in the output file, authored by the model
unless noted otherwise in `dropped_tasks`.

## Run

```bash
python plan_enhancing.py data/plans/human_outs/PLAN_<stage1-stem>.json
```

Options:

- `--provider {lmstudio,gemini}` — LLM backend; default `lmstudio` (falls back to Gemini on failure, same
  `LLMProvider` dual-backend pattern as Stage 2)
- `--lmstudio-url`, `--lmstudio-model`, `--gemini-model` — backend endpoint/model overrides
- `--timeout` — per-request timeout in seconds; default `600` (Gemini calls are additionally capped at
  120s inside `LLMProvider._call_gemini`)
- `--max-tokens` — max completion tokens; default `16384`
- `--max-retries` — retry budget, applied independently to the batch call and to *each* isolated single-
  task retry; default `3`
- `--output-dir` — default `data/plans/enhanced_outs`

`GEMINI_API_KEY` is read from the environment, not accepted as a CLI flag (`LLMProvider`'s constructor
takes `gemini_api_key=None` from `main()` and relies on the fallback path to raise if it's actually needed
and absent).

## Output Contract

Output filename is derived from the **input** plan's filename stem (stripping a leading `PLAN_` if
present), not a fresh timestamp — the same convention Stage 2 uses for its own output, so re-running
enhancement against the same Stage 2 plan always targets the same output path:

- `data/plans/enhanced_outs/PLAN_<stem>.json` — the enhanced plan: every task from the input, each now
  carrying a `scenario_context` object (keys vary per task per `_expected_context_keys`). Always written,
  even on a run where every task used the deterministic fallback.
- `data/plans/enhanced_outs/enhancement_manifest.jsonl` — appended to on every run (one record per run,
  regardless of outcome): `plan_id`, `stage1_ref`, `status`, `output_file`, `timestamp`, `task_count`,
  `dropped_tasks`, `dropped_task_count`. `dropped_tasks` is what makes a run where the model quietly
  produced nothing useful for a task traceable after the fact — `status` alone only tells you *whether*
  something fell back, not *what* or *why*.

## Relationship to Stage 2

Stage 2 ([STAGE2_PLANNER.md](STAGE2_PLANNER.md)) produces the finalized task plan this stage reads —
`task_id`, `dependencies`, `provides`/`consumes`, `description`, `implementation_details`, etc. Stage 2.5
does not re-validate or mutate any of those fields; it only adds `scenario_context` on top, derived from
the same `dependencies`/`provides` edges Stage 2 already established.

## Relationship to Stage 3

Stage 3 ([STAGE3_CODE_GENERATION.md](STAGE3_CODE_GENERATION.md)) reads `task.get("scenario_context")`
opportunistically when building a task's prompt: if present, it renders only the keys actually present on
that task's object (not a fixed 5-line block — see that doc's prompt section), labeled e.g. "Narrative
role:", "Upstream assumptions:", etc. A plan that skipped Stage 2.5 entirely has no `scenario_context` on
any task, and Stage 3's prompt simply omits that section — `scenario_context` is not part of the required-
task-keys contract Stage 3 enforces before generation starts.
