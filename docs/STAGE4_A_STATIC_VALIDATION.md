# Stage 4a Static Validation

`validate_scripts.py` is the first, cheapest gate of Stage 4: an **execution-free** static pre-flight over
a whole Stage 3 run directory. It reads and parses every generated Python file and reports, per file,
whether it compiles, whether all its imports resolve, and whether it honors the Stage 2 plan's
`provides`/`consumes` symbol contract — **without ever importing or running any of it**. It is meant to run
after Stage 3 and before any dynamic execution, so that deterministic, millisecond-cheap checks catch what
they can before you pay for an execution environment.

## Where it sits

Stage 4 is being built as a "functional-code ladder" — successively more expensive oracles, each run only
on what passed the one below it:

```
Stage 3 (generate)
  -> Stage 4a  validate_scripts.py   static: compile + import resolution + contract   (no execution)   <-- this doc
  -> Tier 1    run_tier1_sandbox.py  dynamic: "does it import cleanly" in a disposable, network-isolated container
  -> (future)  Cuckoo/CAPE          behavioral sandbox: what the code actually does when run
  -> (future)  per-task-type / self-test oracle: is the behavior correct for this task
```

Stage 4a is the only rung that never executes code, which is exactly why it is cheap enough to run on
everything, every time. It is a standalone, manual tool — nothing in the pipeline (including `mvp-v1.py`)
calls it automatically.

## Inputs

The required positional argument is a **run directory**: a Stage 3 output directory holding the generated
`*.py` files and their `manifest.jsonl` (e.g. `data/code_scripts/stage3_<name>`). Two optional flags:

- `--plan <PLAN_*.json>`: a Stage 2 plan. Enables the `provides`/`consumes` **contract check** and lets
  untracked files recover their `task_id` by filename prefix. Without it, only the compile and
  import-resolution checks run.
- `--include-rejected`: also validate `incorrect_*.py` rejected drafts (Stage 3 saves the last rejected
  attempt under that prefix). Skipped by default.

### How the file set is chosen (`_resolve_candidates`)

The validator does not simply glob `*.py`. It builds one entry per file, preferring the generation
manifest and then filling in the rest:

1. **Manifest-tracked** — every record in `manifest.jsonl` with `status == "generated"` whose file still
   exists on disk, keyed to its `task_id`.
2. **Untracked** — any other `*.py` in the directory that the manifest didn't account for. This is the key
   design point: **hand-edited files that never went through `generate_code.py` are still validated.** A
   `task_id` is recovered for them by matching the filename stem against the supplied plan's task IDs
   (`<id>` or `<id>_...`), so the contract check still applies to them where possible.

`incorrect_*.py` files are excluded unless `--include-rejected` is passed.

## What it checks

Per file, `_check_file` runs a short ladder of its own; the first hard failure of a kind short-circuits the
rest of that kind.

### L1 — compile

`compile(source, path, "exec")`, **not** `ast.parse`. `compile` is a strict superset: it also rejects
things the grammar accepts but CPython does not (e.g. `return`/`yield`/`break`/`continue` outside a context
that allows them). A compile error is a `fail` and short-circuits the rest of the file — there is no clean
tree to analyze further.

### L2 / L3 — import classification and resolution

Every import site **anywhere in the file** is examined via `pipeline_ast.iter_all_import_statements` — not
just module-scope imports, because a third-party package imported inside a function still has to be
installed for that function to run. Each import is classified:

- **stdlib** (`sys.stdlib_module_names`) — ignored.
- **sibling** (resolved by `pipeline_ast.sibling_stem_from_import` against the other files present in the
  run dir):
  - `missing_sibling` (**fail**) — imports `foo` but `foo.py` isn't in the directory.
  - `non_portable_import` (**warn**) — imports a sibling via a repo-root-anchored dotted path
    (`from data.code_scripts.<run>.TASK_001_x import Y`), which only resolves when launched with the repo
    root on `sys.path`; the portable fix is the bare stem (`from TASK_001_x import Y`).
  - `relative_import` (**fail**) — an explicit relative import (`from .x import y`) that resolves to no
    known sibling; raises `ImportError` when the file is run directly as a script, since it has no parent
    package.
- **third-party** — resolved with `importlib.util.find_spec` (cached per top-level name across the run).
  `missing_dependency` (**fail**) if not installed in the current environment; the set of all such names is
  also summarized at the end of the run.

### L3b — sibling symbol existence

For a top-level `from X import a, b` where `X` is a sibling that exists, the validator parses `X.py` and
confirms `a` and `b` are actually module attributes of `X` — using `pipeline_ast`'s module-scope collectors,
so "attribute of `X`" means `X`'s own def/class, module-level assignment, or import, not just a top-level
`def`. A name that isn't there is `missing_symbol` (**fail**, `ImportError` at runtime). If `X` uses
`from ... import *`, per-name attribution can't be trusted and the finding is `unverifiable_sibling`
(**warn**). (Note the deliberate asymmetry with L2/L3: classification looks at every import site in the
file, but this symbol-existence check looks only at top-level `ImportFrom` statements.)

### Contract check (only with `--plan`, only if not already failing)

When a plan is supplied and the file hasn't already failed L1–L3b, the validator re-applies **Stage 3's own**
`_validate_contract` to the on-disk source (importing the function directly from `generate_code.py` so the
generation-time and post-hoc checks can never drift). This enforces the plan's symbol contract: a `provides`
symbol must actually be *defined* in the file (an import alone doesn't make this file its provider), and a
`consumes` symbol must be imported from the specific dependency that provides it — not redeclared locally,
left unbound, or sourced from the wrong module. A violation is `contract_violation` (**fail**). The symbol
→ module map it checks against is built from every candidate file's `task_id` → stem, so it knows the real
on-disk module name each provided symbol should come from.

## Verdicts

Findings are deduplicated by message, then rolled up: a file is `fail` if it has any `fail` finding, else
`warn` if it has any `warn`, else `pass`. The process exits non-zero if **any** file failed, so the script
doubles as a CI/pipeline gate.

## Run

```bash
# Full run with the contract check enabled
python validate_scripts.py data/code_scripts/stage3_<name> --plan data/plans/human_outs/PLAN_<stage1-stem>.json

# Without a plan: compile + import resolution only (no contract check)
python validate_scripts.py data/code_scripts/stage3_<name>

# Also check the rejected incorrect_*.py drafts
python validate_scripts.py data/code_scripts/stage3_<name> --plan <plan.json> --include-rejected
```

Console output is one line per file plus a run summary, e.g.:

```
[TASK_001] OK: TASK_001_shell_result.py
[TASK_002] FAIL: TASK_002_shell_utils.py
    - (fail) generated code violates the plan's provides/consumes contract: `ExecutionResult` is
      redeclared instead of imported — remove this definition and add
      `from TASK_001_shell_result import ExecutionResult` instead; ...
[TASK_003] FAIL: TASK_003_reverse_shell_server.py
    - (warn) imports `TASK_001_shell_result` via the repo-root-anchored path
      `data.code_scripts.stage3_<name>.TASK_001_shell_result`, which only resolves when launched with the
      repo root on sys.path — use the bare module stem instead
    - (fail) `CommandExecutor` is declared in provides but never defined anywhere in the file; ...

Done: 1 passed, 0 warned, 3 failed. Manifest: data/code_scripts/stage3_<name>/validation_manifest.jsonl
```

(That example is drawn from a real early run generated *before* Stage 3's deterministic import injector was
added — the non-portable `data.code_scripts.<run>...` imports and the redeclared contract symbols are
exactly the failure classes the injector now prevents at generation time. See the note below.)

## Output Contract

One JSON record is **appended** per file to `validation_manifest.jsonl` in the run directory (append-only,
matching the rest of the pipeline's manifest convention — a rerun adds new lines rather than rewriting):

- `run_dir`, `task_id` (`null` for an untracked file with no recovered ID), `filename`
- `verdict`: `pass` | `warn` | `fail`
- `findings`: a list of `{level, category, message}` — `level` ∈ `fail`/`warn`, `category` is the slug
  (`compile_error`, `missing_sibling`, `non_portable_import`, `relative_import`, `missing_dependency`,
  `missing_symbol`, `unverifiable_sibling`, `contract_violation`, `read_error`)
- `missing_dependencies`: the uninstalled third-party top-level module names found in this file
- `timestamp` (UTC, ISO-8601)

Process exit code is `1` if any file failed, else `0`.

## Shared AST core (`pipeline_ast.py`)

Stage 4a does not reimplement its own view of Python scope — it imports `pipeline_ast.py`, the same
execution-free AST module Stage 3 uses for its generation-time contract check, so both apply identical
rules. The pieces Stage 4a relies on:

- `collect_module_level_defs` / `collect_module_level_imports` — names bound in **module scope only**
  (descending through `if`/`try`/`with`/`for`/`while`, but stopping at any `def`/`class` boundary, since
  only module-scope names become importable attributes of the module). Used for L3b and (inside
  `_validate_contract`) the contract check.
- `iter_all_import_statements` — **every** import node regardless of scope. Used for L2/L3, because an
  install requirement doesn't care what scope the import is in.
- `sibling_stem_from_import` — recognizes the three sibling-import forms (bare stem, repo-root-anchored
  dotted path, explicit relative) against the stems actually present in the run.

## Relationship to Stage 3

Stage 3 ([STAGE3_CODE_GENERATION.md](STAGE3_CODE_GENERATION.md)) already enforces the same
`provides`/`consumes` contract at generation time and deterministically rewrites sibling imports, so a file
produced by an up-to-date Stage 3 should normally pass Stage 4a's contract and sibling-import checks by
construction. Stage 4a is still worth running for three reasons it is positioned to catch that Stage 3
can't: **hand-edited files** that bypassed generation entirely; **cross-file** problems a per-file generator
never sees (a missing sibling module, a symbol a dependency failed to actually define); and **environment**
problems (an uninstalled third-party dependency) that only matter at the point of execution. It is an
independent audit of what is actually on disk, not a replay of the generator's own self-checks.

### On deliberately re-running the contract check

In a clean, from-scratch research run — no hand-edits, no files left over from an older Stage 3 — the
contract portion of Stage 4a **is** redundant, and that is intentional. Stage 4a reads the exact bytes
Stage 3 wrote and calls the exact same `_validate_contract`, so for a pristine `"generated"` file it will
reach the same verdict Stage 3 already reached. This is accepted belt-and-suspenders, kept on purpose; it
is **not** an oversight to be optimized away. Two things make keeping it the right call:

- **It is the *only* redundant check, and it is the cheap one.** The contract re-check is one `ast.parse`
  plus set math — microseconds, in a stage that is milliseconds overall (the expensive, don't-repeat-it
  work in this pipeline is the LLM generation and the Tier 1 container runs, not an AST pass). The other
  four checks — `compile()`, missing-sibling, sibling-symbol existence (L3b), and missing-dependency — are
  **not** redundant even on a pristine run, because a per-file generator working one file at a time
  structurally cannot see the cross-file and environment facts they test.
- **It keeps the gate self-contained.** `validate_scripts.py` takes an arbitrary `run_dir` and has an
  `--include-rejected` flag and untracked-file recovery — it is built to be pointed at *any* directory, not
  only pristine current-Stage-3 output. A gate whose correctness depended on "this came straight from an
  unmodified contract-aware Stage 3" would silently under-check the moment that assumption broke (an edit,
  a rerun on an old dir). Re-verifying on-disk bytes right before execution, rather than trusting the tool
  that produced them, is the standard shape of a pre-execution gate.

Note that sharing `_validate_contract` is the opposite of duplicated logic: the policy is written once and
*called* at two legitimately distinct decision points — Stage 3's call is a generation-time acceptance test
that drives the retry loop (reject → re-prompt the model), Stage 4a's is a pre-execution gate on what is
actually on disk. Single-sourcing the function is exactly what stops the two definitions of "contract-valid"
from drifting. If a run ever needs to prove the contract check happens exactly once, the intended lever is a
future `--assume-generated`-style flag that skips it for manifest-tracked `"generated"` files while still
running it for untracked/edited ones — not deleting it, which would weaken the gate for the very inputs it
exists to cover.

## Relationship to Tier 1

Stage 4a answers "could this plausibly run?" statically; Tier 1 (`run_tier1_sandbox.py`) answers "does its
module-level code actually run?" by importing each file inside a disposable, network-isolated,
resource-capped, read-only container. Running Stage 4a first keeps the more expensive container gate off
files that can't even compile or whose imports obviously can't resolve. The two share their candidate-file
resolution (Tier 1 reuses Stage 4a's `_resolve_candidates` / `_load_stage2_plan`) so they validate the same
set of files, and both write append-only per-file manifests into the run dir (`validation_manifest.jsonl`
here, `tier1_manifest.jsonl` there).

### How Tier 1 gets its result back

Worth recording because it is non-obvious and was arrived at the hard way. The in-container runner
(`tier1_runner.py`) does **not** write its result to a shared file; it prints a single JSON object to the
container's stdout, bracketed by a per-run random sentinel (passed in via `$TIER1_SENTINEL`), and
`run_tier1_sandbox.py` recovers it from `docker logs` after `docker wait`. The container therefore has **no
writable host mount at all** — only the read-only `/task` and a throwaway `/tmp` tmpfs. Two Docker Desktop
(Windows) dead-ends forced this: a host **bind mount** can hand back a file the container's non-root user
wrote but the *host* user then can't read (`PermissionError`), and an **anonymous volume** is created
root-owned (so the non-root runner can't write it) and can't be read with `docker cp` off a *stopped*
container anyway. Routing the result over stdout avoids the filesystem — and thus the file-sharing layer
and container/host uid mismatch — entirely. The runner redirects the imported module's own stdout/stderr to
a discard buffer first, so module output can't collide with the sentinel-wrapped result line.

## Tier 1 — current limitations and validity boundary

Tier 1 **imports** each file (`exec_module`) and reports whether module-level code loaded; it never calls
the module's functions and — because it imports rather than runs as `__main__` — never executes an
`if __name__ == "__main__":` block. A green (`import_ok`) verdict therefore licenses exactly one claim:
*the file is structurally sound and loads cleanly in isolation.* It does **not** establish that the code
does what the task intended. This matters for any dataset label derived from the pipeline — a green Tier 1
is evidence of *loadable code*, not of *capability*.

**Truly tested today:**

- the file parses, compiles, and its module-level code runs without raising;
- imports resolve at load (missing sibling module, missing third-party dependency, a `provides`/`consumes`
  break that only bites at import time);
- module-level statements don't crash, and nothing blocks at import (a listener bound at module scope, or a
  top-level sleep/`input`, hits the wall-clock `timeout`).

**Not tested — a green verdict says nothing about these (this is the rung-4 gap):**

- **Behavior / functional correctness.** Logic behind `def`/`__main__` is never exercised; a reverse shell
  that is broken, a no-op, or fully working all import identically. The reference run went 6/6 `import_ok`
  in ~0.03–0.15 s precisely because the behavior lives in functions Tier 1 never called.
- **Anything needing the network.** `--network none` means no connect-back, C2 handshake, reachable
  listener, DNS, or exfil — so the defining behavior of a `c2_transport` / reverse-shell task is
  structurally unobservable here.
- **Interaction/sessions, persistence, privilege, and OS/kernel effects** — there is no peer or victim, the
  rootfs is read-only and ephemeral, the user is non-root, and the guest is a Linux `python:3.14-slim`
  image.
- **Platform-mismatched techniques.** A Windows-targeted task can import cleanly on the Linux base image
  while being meaningless to test there — a pure false-green from the wrong guest OS.
- **Any side effect at all**, because Tier 1 has no behavioral instrumentation (no syscall / network /
  filesystem capture); it observes only "did the import raise?".

The properties that make Tier 1 safe (`--network none`, no target, read-only, ephemeral) are the same ones
that cap what it can prove. A green Tier 1 must not be read as "the generated code works" — it means "it
loads." Establishing *attempted or observed behavior* is the job of the not-yet-built rung 4 (behavioral
detonation under observation), and field efficacy against a real target is deliberately out of scope for
every sealed stage of this pipeline.
