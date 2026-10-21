"""Tier 1 in-container runner: imports exactly one generated file inside this disposable, network-
isolated container and reports the outcome as one JSON object. The result is written to stdout
wrapped in a per-invocation sentinel (supplied via $TIER1_SENTINEL) so the host can recover it from
`docker logs` — no shared file, which avoids bind-mount file-permission issues and the fact that
`docker cp` can't read a volume/tmpfs out of a stopped container. Never run this outside a container
— it executes the target file's module-level code, which is the whole point of Tier 1 but is exactly
the thing the host-side static validator (Stage 4a) never does.
"""

import importlib.util
import io
import json
import os
import sys
import time
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


def _emit(payload: dict) -> None:
    # Write the result to the real stdout, bracketed by the host-supplied sentinel so the host can find
    # it even amongst whatever the imported module itself printed. Fixed fallback token if unset.
    sentinel = os.environ.get("TIER1_SENTINEL", "<<TIER1_RESULT>>")
    sys.stdout.write(f"\n{sentinel}{json.dumps(payload)}{sentinel}\n")
    sys.stdout.flush()


def main() -> None:
    if len(sys.argv) != 2:
        _emit({"outcome": "runner_error", "message": "usage: tier1_runner.py <path-to-.py>"})
        sys.exit(2)

    target = Path(sys.argv[1])
    module_name = target.stem

    # Put the target's own directory on sys.path first, exactly like a normal `python <file>.py`
    # invocation would (sys.path[0] is normally the running script's own directory) — this is what
    # lets the target's own `from <sibling-stem> import X` lines resolve, matching the bare-stem
    # import style the pipeline standardizes on (see pipeline_ast.sibling_stem_from_import).
    sys.path.insert(0, str(target.parent))

    # Swallow anything the target prints while importing so it can't pollute the sentinel-wrapped result
    # on stdout; we only care whether the module-level code imports cleanly or raises.
    sink = io.StringIO()
    start = time.monotonic()
    try:
        with redirect_stdout(sink), redirect_stderr(sink):
            spec = importlib.util.spec_from_file_location(module_name, target)
            if spec is None or spec.loader is None:
                raise ImportError(f"could not build an import spec for {target}")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
    except BaseException as exc:  # deliberately broad: anything the target raises is the signal we want
        _emit({
            "outcome": "import_error",
            "exception_type": type(exc).__name__,
            "exception_message": str(exc),
            "traceback": traceback.format_exc(),
            "duration_s": time.monotonic() - start,
        })
        sys.exit(1)

    _emit({"outcome": "import_ok", "duration_s": time.monotonic() - start})


if __name__ == "__main__":
    main()
