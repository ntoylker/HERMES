# Stage 3 Code Generation

`generate_code.py` turns a Stage 2 task plan (schema v2.0) into one Python file per task. Each task is sent to a **local LM Studio** model (via its OpenAI-compatible `/v1/chat/completions` endpoint) as an independent chat request; the script parses, syntax-checks, **deterministically fixes the reply's sibling imports, verifies it against the plan's symbol contract, and checks it for undeclared names**, persists it, then moves to the next task in dependency order.

A Stage 2 plan is really a single multi-file program sliced into tasks, held together by the `provides`/`consumes` symbol contract and the `dependencies` edges. Because each file is generated independently by a small local model, the model frequently gets the cross-file glue wrong — redeclaring a symbol it was supposed to import, importing from the wrong module, or writing a non-portable import path. Rather than prompt the model for these and hope, Stage 3 computes the correct imports from information it already has and rewrites them in place; see [Cross-file contract enforcement](#cross-file-contract-enforcement) below.

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

A reply passes through a four-step accept gate before it is kept, and failing any step rejects the whole attempt:

1. **`_parse_response`** — rejects a reply that is missing a fenced code block, has an empty code block, or fails `ast.parse` (a syntax error).
2. **`_inject_dependency_imports`** — deterministically rewrites the sibling-import lines (see below); this step never rejects on its own, but the code it produces is what the next steps check.
3. **`_validate_contract`** — rejects code that violates the plan's `provides`/`consumes` symbol contract (see below).
4. **`_check_undeclared_names`** — rejects code that reads, inside some function or class body, a name that is never imported, never defined at module level, and isn't a builtin (see [Undeclared-name check](#undeclared-name-check) below).

A rejected reply is retried with a repair note (the specific rejection reason) appended to the same prompt, up to `--max-attempts` times; a task that still fails is recorded as `"failed"` and generation continues with the next task. When a task is finally rejected, its last attempt's code is still saved as `incorrect_<name>.py` (kept out of the resume/skip scan) so a later correction pass can pick it up.

## Cross-file contract enforcement

The plan assigns each task a `provides` set (symbols this file must define and export) and a `consumes` set (symbols it borrows from its declared `dependencies`). Steps 2 and 3 of the accept gate turn that from a hope into an invariant, using the scope-aware AST primitives in `pipeline_ast.py` (the same module Stage 4a's static validator uses, so generation-time and post-hoc checks apply identical rules).

**Deterministic import injection (`_inject_dependency_imports`).** The correct import line for each consumed symbol is fully derivable: the plan says which dependency provides the symbol, and that dependency's real output file is already on disk with a known module stem (`_dependency_module_stems` → `_resolve_symbol_sources`). So instead of asking a 9B model to write `from <stem> import <symbol>` correctly and merely grading it, Stage 3 computes the canonical line itself. It deletes whatever top-level sibling-import line(s) the model wrote for this task's dependencies — recognizing all three forms seen in practice (a portable bare stem, a repo-root-anchored dotted path like `from data.code_scripts.<run>.TASK_001_x import Y`, or an explicit relative import) via `pipeline_ast.sibling_stem_from_import` — and prepends one canonical `from <stem> import <symbols>` line per consumed dependency, inserted after the module docstring and any `from __future__` imports. It operates on exact source line ranges, so every untouched line (comments, formatting, unrelated imports, actual code) survives byte-for-byte; it leaves imports nested in a `try/except` fallback alone (worst case a harmless double import); and it self-checks the rewritten source with `ast.parse`, falling back to the model's original text if anything would break. This patch is never allowed to be what turns a valid file invalid.

**Contract validation (`_validate_contract`).** The backstop for what injection can't fix. Using `pipeline_ast`'s module-scope collectors, it checks that:

- every `provides` symbol is actually **defined** in the file (a function/class/assignment, not merely imported — importing a symbol doesn't make this file its provider);
- every `consumes` symbol is **imported from the specific dependency that provides it** — not redeclared locally, not left unbound (used as a bare name with no binding → runtime `NameError`), and not imported from the wrong module.

The `try: from fast_impl import X / except ImportError: def X(): ...` optional-dependency idiom is recognized (`collect_optional_dependency_fallback_names`) and exempted from the "defined and imported at once" ambiguity complaint, since exactly one branch ever executes. A violation raises with a specific, human-readable reason that becomes the repair note for the next attempt.

## Undeclared-name check

Step 4 of the accept gate, `_check_undeclared_names`, catches a class of `NameError` that none of the first three steps can see: a name read inside one function or class body that is never imported, never bound at module level, and isn't a builtin — e.g. a name assigned in one method and read only in a sibling method, or a stdlib module used but never imported anywhere. It runs after `_validate_contract` and operates on the already-injected code.

It delegates to `pipeline_ast.find_undeclared_names(source)`, which is built on Python's own `symtable` module rather than a hand-rolled scope walk: it builds the module's `symtable.symtable(...)` table, walks every descendant scope (every function, class, and nested function), and flags any symbol that is `is_referenced()` and `is_global()` in that scope (read as a global, not a local) unless it is bound at module level (assigned or imported, per `symtable`'s own per-symbol flags), declared `global` and assigned inside some function (a real runtime module binding), one of Python's implicit module names (`__file__`, `__cached__`, `__builtins__`, `__class__`), or a `builtins` attribute. `_check_undeclared_names` wraps `ast.parse`'s `SyntaxError` the same way `_parse_response` does (since `compile()`-only-rejected constructs like a top-level `return` can still slip past `ast.parse`), then raises `_ResponseRejected` listing every undeclared name, its reading scope, and the line it's read on.

**Known false-positive case: `from X import *`.** `find_undeclared_names` returns a second value, `unverifiable`, which is `True` when the file has a module-scope `from X import *` — `symtable` has no symbol entry for a name a star-import brings in, since the compiler can't know those names statically. `_check_undeclared_names` receives this value but does not act on it (bound to `_unverifiable`, never read) — despite its own inline comment stating this case is "skipped," the check runs unconditionally regardless of a star import's presence. In practice this means a name genuinely supplied by a star import, but read only inside a function or class body, is misclassified as undeclared and can cause a false-positive rejection. Verified directly:

```python
>>> import pipeline_ast
>>> pipeline_ast.find_undeclared_names('''
... from os.path import *
...
... def f():
...     return join("a", "b")
... ''')
([(4, 'function `f`', 'join')], True)
```

`join` is undeclared only because `symtable` cannot attribute it to the star import — not because the generated file is actually broken. Stage 4a's static validator ([STAGE4_A_STATIC_VALIDATION.md](STAGE4_A_STATIC_VALIDATION.md)) calls the same function for its own L4 check and has the identical limitation: it still emits a `fail` finding for the false positive, and only adds a separate, informational `warn` finding (`unverifiable_names`) alongside it — that `warn` does not suppress the `fail`.

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
- `--max-attempts`: model attempts per task before it is marked failed; default `3`
- `--max-tokens`: max completion tokens per request; default `16384` (bounds a single reply so a task that
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

## Relationship to Stage 4

Stage 4a ([STAGE4_A_STATIC_VALIDATION.md](STAGE4_A_STATIC_VALIDATION.md)) is an execution-free static validator run over a finished Stage 3 run directory. It re-applies this stage's own `_validate_contract` (imported directly from `generate_code.py`, not reimplemented) and the same `pipeline_ast.find_undeclared_names` this stage's step 4 uses, to whatever is actually on disk — plus compile and import-resolution checks Stage 3 doesn't do, which only make sense run after the whole directory exists (e.g. verifying a sibling module Stage 3 itself generated really defines the symbol another file imports from it). A file produced by an up-to-date Stage 3 should pass Stage 4a's contract, undeclared-name, and sibling-import checks by construction; Stage 4a still earns its place by catching hand-edited files that bypassed generation, cross-file problems a per-file generator can't see, and uninstalled third-party dependencies. Tier 1 then imports each file inside a disposable, network-isolated container as the first machine-enforced execution boundary in the pipeline. Neither Stage 4 tool is wired into the automated chain — both are run manually.
