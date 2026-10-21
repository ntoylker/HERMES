"""Shared, execution-free AST primitives for inspecting generated Python files: scope-aware
name-binding/import collection and sibling-module recognition. Used by Stage 3's generation-time
provides/consumes contract check (generate_code.py) and the Stage 4a static validator
(validate_scripts.py) so both apply identical module-scope semantics instead of two
independently-maintained (and potentially drifting) copies.
"""

import ast
from typing import Iterator

# A name bound here starts a new scope; module-scope collectors never look inside one, since names
# bound in there don't become attributes of the module itself.
_SCOPE_BOUNDARY = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _module_scope_statements(tree: ast.Module) -> list[ast.stmt]:
    # Every statement that executes directly in module scope: top-level statements, plus ones
    # nested inside if/try/with/for/while at any depth (their bodies still run in module scope),
    # but not statements inside a nested def/class (those start a new scope — the def/class
    # statement itself is still included, just not descended into).
    result: list[ast.stmt] = []
    stack: list[ast.stmt] = list(tree.body)
    while stack:
        node = stack.pop()
        result.append(node)
        if isinstance(node, _SCOPE_BOUNDARY):
            continue
        children: list[ast.stmt] = []
        children += getattr(node, "body", None) or []
        children += getattr(node, "orelse", None) or []
        children += getattr(node, "finalbody", None) or []
        for handler in getattr(node, "handlers", None) or []:
            children += handler.body
        stack.extend(children)
    return result


def _assignment_targets(target: ast.expr) -> list[str]:
    # Flattens a (possibly nested tuple/list/starred) assignment target into the plain names it
    # binds. Attribute/subscript targets (`obj.x = ...`, `d[k] = ...`) bind no new module name.
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [n for elt in target.elts for n in _assignment_targets(elt)]
    if isinstance(target, ast.Starred):
        return _assignment_targets(target.value)
    return []


def collect_module_level_defs(tree: ast.Module) -> set[str]:
    """Names bound directly in module scope: function/class defs and assignments (including
    tuple/list/starred unpacking), found anywhere in the module's control flow (if/try/with/for/
    while) but not inside a nested function/class body. Import statements are deliberately
    excluded — collected separately by collect_module_level_imports, since 'defined' vs 'imported'
    matters for the provides/consumes contract check. `except ... as name` is also excluded on
    purpose: Python unbinds that name at the end of the except block, so it's never a real,
    durable module attribute the way a def/class/assignment is."""
    names: set[str] = set()
    for node in _module_scope_statements(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_assignment_targets(target))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    names.update(_assignment_targets(item.optional_vars))
    return names


def collect_module_level_imports(tree: ast.Module) -> tuple[dict[str, str], bool]:
    """Module-scope-only `{bound_name: source}` map (source is the dotted path for `import x.y`,
    or the `from`-module string for `from m import x`), plus whether a module-scope
    `from m import *` was seen (after which per-name attribution can't be trusted). Uses the same
    scope rules as collect_module_level_defs — e.g. a `try: from fast import X / except
    ImportError: def X(): ...` fallback is visible to both — so 'defined' and 'imported' are judged
    consistently rather than one being scope-aware and the other an unconditional whole-file walk."""
    imported: dict[str, str] = {}
    has_star = False
    for node in _module_scope_statements(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[alias.asname or alias.name.split(".")[0]] = alias.name
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    has_star = True
                else:
                    imported[alias.asname or alias.name] = node.module or ""
    return imported, has_star


def iter_all_import_statements(tree: ast.Module) -> Iterator[ast.Import | ast.ImportFrom]:
    """Every Import/ImportFrom node anywhere in the file, regardless of scope. Deliberately NOT
    scope-aware, unlike the two collectors above: a third-party package imported only inside a
    function still has to be installed for that function to ever run, so dependency-resolution
    checks must see every import site, not just module-scope ones."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node


def collect_referenced_names(tree: ast.Module) -> set[str]:
    """Every identifier referenced (read) anywhere in the file, regardless of scope. Used only for
    one narrow, specific check — whether one particular expected symbol is used as a bare name
    anywhere in the file — not as a general undefined-name analysis (which needs real per-scope
    resolution to avoid flagging ordinary local variables and function parameters as undefined)."""
    return {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}


def collect_optional_dependency_fallback_names(tree: ast.Module) -> set[str]:
    """Names bound by the `try: import X ... except ImportError: def X(): ...`-style optional-
    dependency idiom: imported in a Try statement's body, with a same-named fallback def/class/
    assignment in one of its except handlers. Exactly one branch ever executes, so a name in this
    set being seen as both 'imported' (by collect_module_level_imports) and 'defined' (by
    collect_module_level_defs) isn't a real contradiction — those collectors are flat sets and can't
    see that the two bindings come from mutually-exclusive branches. A def and an import of the same
    name both reachable unconditionally at the same level is still a real, worth-flagging collision;
    this only exempts the specific try/except-fallback shape."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        try_imports: set[str] = set()
        for stmt in node.body:
            if isinstance(stmt, ast.Import):
                try_imports.update(a.asname or a.name.split(".")[0] for a in stmt.names)
            elif isinstance(stmt, ast.ImportFrom):
                try_imports.update(a.asname or a.name for a in stmt.names if a.name != "*")
        if not try_imports:
            continue
        for handler in node.handlers:
            for stmt in handler.body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if stmt.name in try_imports:
                        names.add(stmt.name)
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        names.update(n for n in _assignment_targets(target) if n in try_imports)
    return names


def sibling_stem_from_import(module: str | None, level: int, candidate_stems: set[str]) -> str | None:
    """Recognizes a sibling-module reference among the import forms seen in this corpus, grounded
    in the stems that actually exist in this run (never guessed): a bare stem (`from X import y` —
    the portable form Stage 3's prompt asks for), a repo-root-anchored dotted path
    (`from data.code_scripts.<run>.X import y` — resolves only when launched in a way that puts the
    repo root on sys.path; non-portable), or an explicit relative import with a module
    (`from .X import y` — raises ImportError when the file is run directly as a script, since it
    has no parent package). Returns the matched stem, or None if this import doesn't reference a
    known sibling at all. Deliberately does not handle the bare `from . import X` form (module is
    None, X only appears in the alias list) — that shape isn't produced by this pipeline's prompts
    or seen in practice, and handling it would need the caller to also pass alias names in, for no
    observed benefit."""
    if level > 0:
        return module if module in candidate_stems else None
    if not module:
        return None
    last_segment = module.rsplit(".", 1)[-1]
    return last_segment if last_segment in candidate_stems else None
