#!/usr/bin/env python3
"""Gate: no RAW file I/O on a repo-derived path in `scripts/`.

WHY THIS EXISTS
===============
One defect class — reading or writing an agent-writable repo file through a
path an attacker can pre-link, swap, or replace with a FIFO — recurred across
SIX consecutive external audit rounds while being fixed correctly each time.
The first postmortem in that series named the reason: the class was
"documented but not MECHANIZED, so each new writer was free to reintroduce it."

Shared helpers (`safe_read_text`, `safe_atomic_write`, `refuse_linked_leaf`,
`within_root`, `read_lock`) make the safe path available. Only a gate makes it
mandatory.

FAIL CLOSED — THE v1 LESSON
===========================
The first cut of this gate classified anything it could not resolve as
"unknown" and SKIPPED it. That is the same shape as every bug it was written to
prevent: an unresolved case defaulted to "allow". It also matched only
`<expr>.<method>()` receivers, so a bare `open(str(p), "w")` — whose callee is
a Name, not an Attribute — was invisible while the docstring claimed `open` was
covered. A security auditor found three real unguarded governed writers the
gate happily reported `ok` over, one of them in a file that same change had
edited.

So: resolution is DATA-FLOW based, not token based; `unknown` is REPORTED, not
skipped; and the call surface includes bare builtins and `os`/`shutil`
functions, not just Path methods.

RESOLUTION
==========
Within each scope (module and each function), assignments are tracked so a path
bound to a local name resolves to its origin:

    cfg = ROOT / ".substrate" / "config"   # cfg -> GOVERNED
    cfg.write_text(...)                    # flagged

GOVERNED — rooted at the process's own repo root (`ROOT`, `_ROOT`,
    `repo_root()`, `SCRIPTS`, a module-level ALL-CAPS path constant, or a
    `root`/`target` parameter naming a repo the tool operates on). An attacker
    who can write into that checkout can prepare these paths BEFORE the process
    runs, so they must use the guarded helpers.

FIXTURE — bound, by EVIDENCE, from a freshly created temporary directory
    (`tempfile.mkdtemp()`, `TemporaryDirectory()`, a `with ... as td`, or a
    pytest `tmp_path`). v1 used a NAME list here, which meant calling a
    governed variable `td` hid it; a name is not evidence.

UNRESOLVED — everything else. Reported, never silently passed. If the count is
    non-zero the gate still exits 0 (these are usually CLI arguments and
    genuinely out of scope) but they are PRINTED, so the blind spot is visible
    instead of invisible. Anything security-relevant among them must be either
    resolved or allowlisted with a reason.

STATED LIMITS — what this gate does NOT catch
============================================
Its threat model is ACCIDENTAL reintroduction by a contributor who has not read
six rounds of postmortems. It is not a defense against a malicious committer:
anyone who can add code to `scripts/` can also edit this file, and that path is
covered by CODEOWNERS plus the trusted-base freeze, not by static analysis.

Known residuals, stated rather than implied. This list has been WRONG before:
an earlier version of it claimed two-step `getattr` indirection surfaced as
`unresolved` when it was in fact dropped silently, so treat every claim here as
something to re-verify rather than trust.
  - Interprocedural propagation is ONE MODULE deep and follows only calls whose
    callee is a bare NAME. A governed path passed into a module-local helper
    marks that helper's parameter governed (to a bounded fixpoint, so wrappers
    nest, resolved against the innermost enclosing definition of that name and
    mapped through posonly/positional/keyword/`*args` correctly). A path handed
    to a function in ANOTHER module, or to a METHOD (`self.commit(p)`, whose
    callee is an Attribute), is still only `unresolved`. Before v3.8.44 there
    was no propagation at all, and a one-line wrapper was enough to demote a
    governed write to a line that does not fail the build.
  - IMPORT bindings are resolved per scope in a pre-pass (module-level imports
    bind everywhere regardless of textual order; a function's own imports bind
    only inside it), so the "module-wide alias map" limit stated here through
    v3.8.45 no longer applies — and it was never merely an over-report: it let
    a nested import clobber a sibling's alias and drop a real violation.
    ASSIGNMENT aliases (`op = open`) are still walker-maintained and per-scope
    by construction, since a name assigned later genuinely is not bound yet.
  - Paths built entirely from CLI arguments are out of scope by design and are
    the bulk of the `unresolved` count.
  - Indirection beyond one `getattr` binding (a method stored in a dict, a
    partial, a callable attribute on an object) is not resolved. Verified as of
    v3.8.43: single-expression `getattr(p,"write_text")(x)` AND the two-step
    `fn = getattr(p,"write_text"); fn(x)` are both caught as violations.
The intent is that nothing is dropped in SILENCE — a case this gate cannot
resolve should appear in `--list-unresolved`. Silence was the v1 defect. If you
find a construct that produces no output at all, that is a bug in this gate,
not an accepted limit.

ALLOWLIST
=========
`ALLOWLIST` maps "<file>:<symbol>.<method>" to a REASON. A stale entry — one
that no longer matches any call site — fails the gate, so exemptions cannot rot
into permanent cover.

Exit: 0 clean | 1 unguarded governed I/O (or a stale allowlist entry) | 2 error.
Stdlib only.
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
_ROOT_FALLBACK = False
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    # v3.8.44 (round-27 P3): the fallback was Path.cwd(), so invoking THIS
    # script by absolute path from an unrelated checkout scanned that
    # checkout and reported ok about a tree the operator never named. The
    # script's own location is the one thing the invocation actually pins,
    # so fall back to it — and say the resolution failed either way.
    ROOT = Path(__file__).resolve().parent.parent
    _ROOT_FALLBACK = True

SCRIPTS = ROOT / "scripts"

# Path-object methods that touch the filesystem by NAME.
PATH_IO_METHODS = {
    "read_text", "write_text", "read_bytes", "write_bytes", "mkdir", "open",
    "touch", "unlink", "rename", "replace", "symlink_to", "hardlink_to", "rmdir",
    "chmod", "lchmod",
}
# Module-level functions that do the same. `os.open` re-resolves by name too.
FUNC_IO = {
    ("os", "open"), ("os", "replace"), ("os", "rename"), ("os", "remove"),
    ("os", "unlink"), ("os", "mkdir"), ("os", "makedirs"), ("os", "rmdir"),
    ("os", "truncate"), ("os", "symlink"), ("os", "link"),
    ("os", "chmod"), ("os", "chown"), ("os", "utime"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
    ("shutil", "copytree"), ("shutil", "move"), ("shutil", "rmtree"),
}
# Bare builtin.
BUILTIN_IO = {"open"}

# Operations with TWO path operands — the destination is as governed as the
# source, and inspecting only argument 0 hid it entirely (round-27 P1).
TWO_PATH_FUNCS = {
    ("os", "replace"), ("os", "rename"), ("os", "link"), ("os", "symlink"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
    ("shutil", "copytree"), ("shutil", "move"),
}
TWO_PATH_LABELS = {f"{m}.{f}" for m, f in TWO_PATH_FUNCS}
TWO_PATH_METHODS = {"replace", "rename", "symlink_to", "hardlink_to"}

# Keyword names that carry a PATH on the operations above. v3.8.45 (round-28
# P1): operand collection walked `node.args` only, so `open(file=ROOT/"x","w")`,
# `shutil.copy(src=tmp, dst=ROOT/"x")` and `os.replace(src=..., dst=...)`
# vanished entirely — no finding AND no unresolved line. That is the positional
# multi-path bug of round 27 in a second spelling, which is exactly the shape a
# fix should have generalized the first time. These names are only consulted on
# a call already identified as one of the covered I/O operations.
PATH_KWARGS = {"file", "path", "src", "dst", "target", "oldpath", "newpath",
               "filename", "name"}

# Metadata-changing operations (chmod/lchmod/touch; os.chmod/chown/utime)
# follow links and mutate governed or outside-routed files even though they
# write no content (round-27 P2). They live in PATH_IO_METHODS and FUNC_IO
# above rather than in a table of their own — a second table that nothing
# consulted was dead code implying coverage it did not provide.

# Base symbols denoting the PROCESS's own repo root or a constant derived from
# one. `root`/`target_root` are parameter names for a repo the tool operates on
# (bootstrap/upgrade/profile all take one) — equally attacker-preparable.
GOVERNED_BASES = {
    "ROOT", "_ROOT", "SCRIPTS", "MEM", "EVENTS", "TODO_STATE", "HISTORY_MD",
    "REJECTED_MD", "TASKS_STATE", "TRACES", "PATTERNS", "SESSION_START",
    "CONFIG", "CUR", "_HISTORY", "_REPO", "repo_root", "root", "target_root",
}
# Calls whose RESULT is a fresh temp dir — evidence, not a name convention.
FIXTURE_CALLS = {"mkdtemp", "TemporaryDirectory", "mkstemp", "gettempdir"}
FIXTURE_PARAMS = {"tmp_path", "tmpdir"}

# "<file>:<symbol>.<method>" -> why this raw call is acceptable.
ALLOWLIST: dict[str, str] = {
    "_doc_common.py:root.os.open":
        "IS the component-walk descent — this is the single os.open of the ROOT "
        "the caller supplied, after which every step is a single-component "
        "O_NOFOLLOW|O_DIRECTORY openat relative to a pinned fd",
    "substrate_upgrade.py:root.shutil.copy2":
        "upgrade installs the NEW KIT into the target; the destination tree is "
        "the thing being created and its parent chain is validated by the "
        "upgrade's own containment checks before this runs",
    "substrate_upgrade.py:root.shutil.copytree":
        "same upgrade install path — directory copy from the new kit into the "
        "target being upgraded",
    "memory_log.py:MEM.mkdir":
        "append() runs STRICT within_root containment and refuses a "
        "symlinked/hard-linked/non-regular .lock and events.jsonl leaf on the "
        "lines immediately above, with no intervening blocking call",
    "memory_log.py:EVENTS.open":
        "same guarded block as MEM.mkdir — containment plus leaf-type refusal "
        "run first and the append holds the .lock for the duration",
    "memory_log.py:lock.open":
        "the .lock leaf is one of the two explicitly refused above (symlink, "
        "hard link, non-regular) before this open, inside the same guarded block",
    "run_substrate_evals.py:SCRIPTS.shutil.copytree": (
        "stages a copy of the kit's OWN scripts/ into a fresh TemporaryDirectory "
        "so the raw-IO gate can be run against a planted violation; source is "
        "code under review, destination is a temp dir. TWO sites, identical "
        "shape: the planted-write eval and the wrapped-write eval, each staging "
        "a bad/ok pair. The second was added in v3.8.44 and silently inherited "
        "this reason until v3.8.45 started counting matches", 2),
    "run_substrate_evals.py:SCRIPTS.read_text":
        "reads the substrate's own validator SOURCE to hash/compare it — code "
        "under review, not agent-writable state",
    "run_substrate_evals.py:src.read_text":
        "stages a copy of the kit's OWN script source into a fresh temp fixture; "
        "the source is code under review (and CODEOWNED + hash-pinned), not "
        "agent-writable state, and the destination is a temp dir",
    "run_substrate_evals.py:ag.read_text":
        "same fixture staging — reads the kit's own agentsync.sh source to copy "
        "it into a temp repo",
    "check_harness_smoke.py:src.read_text":
        "same fixture staging — copies the kit's own scanner dependencies into a "
        "temp tree so the real scanner can be run against planted payloads",
    "substrate_upgrade.py:src.shutil.copy2":
        "copies a file FROM the new kit INTO the target during upgrade; the "
        "source is the kit being installed, and the destination tree is "
        "validated by the upgrade's own containment checks",
    "substrate_upgrade.py:src.shutil.copytree":
        "same upgrade install path — copies a directory from the new kit into "
        "the target",
    "substrate_upgrade.py:root.read_bytes":
        "refuse_linked_leaf() runs on the immediately preceding line and routes "
        "an unsafe leaf to the existing None path, so this read only happens on "
        "a private regular file",
    "_doc_common.py:cfg.os.open":
        "IS the guarded reader for .substrate/config in _code_suffixes() — "
        "O_NOFOLLOW|O_NONBLOCK, S_ISREG, bounded — and it runs at MODULE "
        "IMPORT, so it cannot call the helpers defined later in this same file",
    "check_agent_harness.py:p.os.open":
        "IS the guarded reader for harness_patterns.json — O_NOFOLLOW|O_NONBLOCK "
        "plus fstat S_ISREG and st_nlink==1; kept inline because this module is "
        "AST-pinned and must not gain an import",
    "check_substrate_config.py:p.os.open":
        "same inline guarded reader for the same pattern file in the config "
        "hook, which must stay import-light because it runs on every tool call",
    "command_policy.py:cfg.os.open":
        "IS the guarded reader — inline O_NOFOLLOW|O_NONBLOCK open plus fstat "
        "S_ISREG/st_nlink and a bounded read, kept inline because this module is "
        "AST-pinned and must not gain an import",
    "command_policy.py:req.os.open":
        "same inline guarded lock reader for .substrate/required_profile, "
        "AST-pinned and deliberately dependency-free",
    "session_handoff.py:TASKS_STATE.os.open":
        "IS the guarded reader for current.json — O_NOFOLLOW plus st_nlink==1 "
        "refusal, the check that keeps restore from pulling an outside file "
        "into model context",
    "memory_log.py:path.os.open":
        "IS the guarded reader — strict containment against `root` on the lines "
        "immediately above, then O_NOFOLLOW|O_NONBLOCK plus fstat S_ISREG and "
        "st_nlink==1; kept inline so the memory chain has no import dependency",
    "session_handoff.py:path.os.open":
        "IS this hook's inline mirror of safe_read_text (_safe_read_text) — "
        "_within_root, O_NOFOLLOW|O_NONBLOCK, fstat S_ISREG and st_nlink==1; "
        "inline because the SessionStart hook stays stdlib-only and "
        "self-contained",
    "write_install_json.py:root.read_bytes":
        "refuse_linked_leaf() runs on the immediately preceding line and skips "
        "an unsafe leaf, so provenance never attests a hash read through a link",
}


# How many call sites each ALLOWLIST key actually matched this run. v3.8.45
# (round-28 P1): a key covered EVERY matching call site, so a second raw call
# with the same base and method silently inherited a reason reviewed for the
# first. An exemption is granted to a specific call site that a human read; if
# it starts covering more, that is a review event, not a detail. Declare a
# count explicitly by making the value a (reason, count) tuple.
_ALLOWLIST_HITS: dict[str, int] = {}


def _allow_count(v) -> int:
    return v[1] if isinstance(v, tuple) else 1


def _base_symbol(node: ast.AST) -> str | None:
    """Walk an `a / b / c` chain (or Name/Attribute/Call) to its base symbol."""
    seen = 0
    while seen < 64:
        seen += 1
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            node = node.left
            continue
        # v3.8.46 (round-29 P2): a governed path collected into *args or
        # **kwargs is reached by SUBSCRIPT — `args[0].write_text(...)`,
        # `kwargs["p"].write_text(...)`. The container is what propagation
        # marks governed, so the element inherits it.
        if isinstance(node, ast.Subscript):
            node = node.value
            continue
        # `(p := ROOT / "x").write_text(...)` — the receiver IS the assignment
        # expression, so the origin is its value (round-30 P2).
        if isinstance(node, ast.NamedExpr):
            node = node.value
            continue
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Call):
            f = node.func
            # TRANSPARENT WRAPPERS: `open(str(ROOT / "x"), "w")` and
            # `os.replace(str(ROOT / "a"), ...)` hid a governed path behind a
            # str()/Path() call, which the first cut resolved to the useless
            # base "str". Recurse through the wrapper to the real path
            # expression — a conversion is not a change of origin.
            if isinstance(f, ast.Name) and f.id in {"str", "Path", "fspath"} and node.args:
                node = node.args[0]
                continue
            # v3.8.46 (round-29 P1): the transparent-wrapper list was the
            # wrappers I happened to think of. `os.path.join(ROOT, "docs", x)`
            # — the most ordinary way anyone builds a path — was not among
            # them, so it resolved to the useless base "join" and an ordinary
            # governed write passed the build. A path CONSTRUCTOR does not
            # change where the path came from.
            if (isinstance(f, ast.Attribute)
                    and f.attr in {"join", "normpath", "abspath", "realpath"}
                    and node.args):
                node = node.args[0]
                continue
            if (isinstance(f, ast.Attribute) and f.attr in {"fspath", "resolve", "absolute",
                                                            "expanduser", "joinpath"}):
                node = f.value if f.attr != "fspath" else (node.args[0] if node.args else f.value)
                continue
            if isinstance(f, ast.Name):
                return f.id
            if isinstance(f, ast.Attribute):
                # tempfile.mkdtemp() etc. -> report the callee so FIXTURE_CALLS
                # can match it as evidence of a fresh temp dir.
                return f.attr
            return None
        return None
    return None


def _scope_body(node):
    """Yield the statements belonging to THIS scope, not to nested ones.

    Imports inside `if`/`try` at module level still bind module-wide, but a
    nested def/class is its own namespace and must not leak outward.
    """
    # v3.8.47 (round-30 P1): this walked with a LIFO stack, so statements came
    # back in an order unrelated to the source. `if True: import os as io`
    # followed by `import shutil as io` resolved to whichever the stack popped
    # last, which is not what Python binds. Later binding wins at runtime, so
    # the enumeration has to be in DOCUMENT order — collect, then sort by
    # position. `match`/`case` keeps its statements under .cases[i].body, which
    # is neither body nor orelse (v3.8.46 in-release).
    out: list = []

    def _collect(stmts):
        for n in stmts or []:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue        # its own namespace
            out.append(n)
            for f in ("body", "orelse", "finalbody"):
                _collect(getattr(n, f, None))
            for h in getattr(n, "handlers", []) or []:
                _collect(getattr(h, "body", None))
            for c in getattr(n, "cases", []) or []:
                _collect(getattr(c, "body", None))

    _collect(getattr(node, "body", []))
    _collect(getattr(node, "orelse", []))
    _collect(getattr(node, "finalbody", []))
    yield from sorted(out, key=lambda n: (getattr(n, "lineno", 0),
                                          getattr(n, "col_offset", 0)))


def _collect_bindings(tree: ast.AST):
    """Resolve import bindings BEFORE scanning any body, module scope apart.

    v3.8.46 (round-29 P1 x3) — one design error wearing three hats. Aliases
    were learned DURING the same ordered visit that scans function bodies, and
    kept in flat module-wide dicts, so:

      * a function using an alias defined by a LATER import line was dropped
        entirely (the visitor had not reached the binding yet) — perfectly
        valid Python, since the import runs before the call does;
      * a nested `import os as io` overwrote a sibling function's module-level
        `import shutil as io`, because there was one dict for the whole file;
      * the v3.8.45 star-import shadow fix collected def names with `ast.walk`,
        so an unrelated NESTED `def copy` inside some other function suppressed
        a real `from shutil import *` call. That is the ast.walk scope-collapse
        mistake caught in v3.8.44 in a different place, reintroduced two
        releases later by code written to fix something else.

    Binding structure is a property of the module's SHAPE, so it is resolved up
    front: module-level imports bind everywhere regardless of textual order, a
    function's own imports bind only inside it, and only MODULE-level defs
    shadow a star import. Returns (effective_by_scope, module_defs) where the
    effective maps are precomputed per scope path.
    """
    module_defs = frozenset(
        n.name for n in getattr(tree, "body", [])
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))

    # v3.8.47 in-release: the ALL-CAPS "module-level path constant" convention
    # fires on any shouty name, and once loop targets inherit their iterable's
    # classification that reached string constants too — `_KIT_TOKENS =
    # ("./manage.sh", "manage.sh")` made `s.replace(tok, ...)`, an ordinary
    # STRING replace, look like Path.replace on a governed path. A name whose
    # module-level value is plainly a string literal (or a tuple/list of them)
    # is not a path constant.
    literal_strs: set[str] = set()
    for n in getattr(tree, "body", []):
        if not (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)):
            continue
        v = n.value
        if isinstance(v, ast.Constant) and isinstance(v.value, str):
            literal_strs.add(n.targets[0].id)
        elif isinstance(v, (ast.Tuple, ast.List, ast.Set)) and v.elts and all(
                isinstance(e, ast.Constant) and isinstance(e.value, str) for e in v.elts):
            literal_strs.add(n.targets[0].id)

    def _own(node):
        mods: dict[str, str] = {}
        funcs: dict[str, str] = {}
        bound: dict[str, str] = {}
        # v3.8.47 (round-30 P1): ASSIGNMENT aliases were still learned during
        # the ordered body walk, so `def f(): op(ROOT / "x", "w")` with a
        # module-level `op = open` written LATER in the file was dropped — the
        # module initialises fully before f() is ever called. v3.8.46 moved
        # import resolution into this pre-pass and left assignment resolution
        # behind: one correct idea applied to one of the binding forms.
        for n in _scope_body(node):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name):
                tgt, val = n.targets[0].id, n.value
                if isinstance(val, ast.Name) and val.id in BUILTIN_IO:
                    funcs.setdefault(tgt, "open")
                elif (isinstance(val, ast.Attribute)
                      and isinstance(val.value, ast.Name)
                      and (val.value.id, val.attr) in FUNC_IO):
                    funcs.setdefault(tgt, f"{val.value.id}.{val.attr}")
                elif isinstance(val, ast.Attribute) and val.attr in PATH_IO_METHODS:
                    bound.setdefault(tgt, f"{_base_symbol(val.value) or '?'}|{val.attr}")
                elif (isinstance(val, ast.Call) and isinstance(val.func, ast.Name)
                      and val.func.id == "getattr" and len(val.args) >= 2
                      and isinstance(val.args[1], ast.Constant)
                      and isinstance(val.args[1].value, str)):
                    bound.setdefault(
                        tgt, f"{_base_symbol(val.args[0]) or '?'}|{val.args[1].value}")
        for n in _scope_body(node):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name in {"os", "shutil"}:
                        mods[a.asname or a.name] = a.name
            elif isinstance(n, ast.ImportFrom) and n.module in {"os", "shutil"}:
                for a in n.names:
                    if a.name == "*":
                        for mod, fname in FUNC_IO:
                            # Only a MODULE-level def shadows the star import.
                            if mod == n.module and fname not in module_defs:
                                funcs.setdefault(fname, f"{mod}.{fname}")
                    elif (n.module, a.name) in FUNC_IO:
                        funcs[a.asname or a.name] = f"{n.module}.{a.name}"
        return mods, funcs, bound

    effective: dict[tuple[str, ...], tuple[dict, dict, dict]] = {}
    root_mods, root_funcs, root_bound = _own(tree)
    effective[()] = (root_mods, root_funcs, root_bound)

    def _descend(node, path, mods, funcs, bound):
        for n in ast.iter_child_nodes(node):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                own_m, own_f, own_b = _own(n)
                m2 = {**mods, **own_m}
                f2 = {**funcs, **own_f}
                b2 = {**bound, **own_b}
                sub = (*path, n.name)
                effective[sub] = (m2, f2, b2)
                _descend(n, sub, m2, f2, b2)
            elif isinstance(n, ast.ClassDef):
                # The class name is part of the scope path. Passing `path`
                # through unchanged made a method's key collide with a
                # same-named module-level function, and whichever the walk
                # reached LAST overwrote the other's bindings — an
                # order-dependent silent fail-open (v3.8.46 in-release BLOCK).
                #
                # v3.8.47 (round-30 P1): a class BODY EXECUTES. `class C:
                # import shutil as io; io.copy(...)` runs at definition time,
                # and treating the class purely as a namespace to skip meant
                # that raw I/O vanished entirely. The body gets its own
                # bindings, exactly like a function's.
                own_m, own_f, own_b = _own(n)
                cm, cf = {**mods, **own_m}, {**funcs, **own_f}
                cb = {**bound, **own_b}
                sub = (*path, n.name)
                effective[sub] = (cm, cf, cb)
                _descend(n, sub, cm, cf, cb)
            else:
                _descend(n, path, mods, funcs, bound)

    _descend(tree, (), root_mods, root_funcs, root_bound)
    return effective, module_defs, frozenset(literal_strs)


class _ScopeResolver(ast.NodeVisitor):
    """Resolve path-bearing names to GOVERNED / FIXTURE within each scope."""

    def __init__(self, seed: dict[str, set[str]] | None = None,
                 bindings: dict | None = None,
                 literal_strs: frozenset[str] = frozenset()) -> None:
        self._literal_strs = literal_strs
        # Set only while classifying an operand of an unambiguous file-I/O
        # call, so a bare relative string counts as a path there and nowhere.
        self._literal_ok = False
        # Import bindings resolved up front by _collect_bindings, keyed by
        # scope path: module-level imports bind everywhere regardless of
        # textual order, a function's own imports bind only inside it.
        self._bindings = bindings if bindings is not None else {(): ({}, {}, {})}
        self.findings: list[tuple[int, str, str]] = []   # (line, base, method)
        self.unresolved: list[tuple[int, str, str]] = []
        # Calls to module-local helpers carrying a governed path, recorded so
        # scan() can propagate GOVERNED into the callee's parameters (round-27
        # P2: a one-line wrapper demoted a governed write to `unresolved`,
        # which does not fail the build).
        self.local_calls: list[tuple[tuple[str, ...], str, list[str],
                                     dict[str, str]]] = []
        self._seed = seed or {}
        self._scopes: list[dict[str, str]] = [{}]
        # `import os as _o` / `import shutil as _s` aliased the module, so a
        # literal "os"/"shutil" name check missed os.replace/shutil.copy behind
        # the alias. Track aliases so the module identity, not the spelling, is
        # what matters.
        # `from os import unlink as remove_file` and `op = open` both produce a
        # bare-Name callee that is not literally `open`, so both were dropped in
        # SILENCE (round-27 P2). Map alias -> canonical label.
        self._funcalias: dict[str, str] = {}
        # Enclosing function names, innermost last. Keying definitions and
        # seeds by this PATH rather than by a bare name is what keeps a nested
        # `def helper(q)` from being confused with a module-level `def
        # helper(x)` — an in-release auditor BLOCK: `ast.walk` + `setdefault`
        # collapsed both into one entry, so the fixpoint seeded the wrong
        # function's parameter (a false positive on the unreached definition
        # AND a false negative on the one that actually received the path).
        self._fnstack: list[str] = []
        self.defs: dict[tuple[str, ...], ast.AST] = {}

    # --- scope handling -------------------------------------------------
    def _push(self, params: list[str]) -> None:
        env = dict(self._scopes[-1])          # inherit module-level constants
        for p in params:
            env[p] = "fixture" if p in FIXTURE_PARAMS else env.get(p, "")
        self._scopes.append(env)

    def _pop(self) -> None:
        self._scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        path = (*self._fnstack, node.name)
        self.defs[path] = node
        params = [a.arg for a in (node.args.posonlyargs + node.args.args
                                  + node.args.kwonlyargs)]
        if node.args.vararg is not None:
            params.append(node.args.vararg.arg)
        if node.args.kwarg is not None:
            params.append(node.args.kwarg.arg)
        self._push(params)
        # v3.8.47 (round-30 P2): a governed DEFAULT binds the parameter for
        # every call that omits it — `def f(p=ROOT / "docs" / "x")` writes to
        # the checkout with no caller involvement at all — and defaults were
        # never classified. Positional and keyword-only defaults both.
        _defaults = list(node.args.defaults) + [
            d for d in node.args.kw_defaults if d is not None]
        _posnames = [a.arg for a in (node.args.posonlyargs + node.args.args)]
        for _name, _d in zip(_posnames[len(_posnames) - len(node.args.defaults):],
                             node.args.defaults):
            _k = self._classify_expr(_d)
            if _k:
                self._scopes[-1][_name] = _k
        for _a, _d in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if _d is not None:
                _k = self._classify_expr(_d)
                if _k:
                    self._scopes[-1][_a.arg] = _k
        # A parameter this helper is CALLED with a governed path through is
        # governed inside the body. Governed wins over the fixture-name
        # heuristic: over-reporting is the safe direction here.
        for p in self._seed.get(path, ()):
            if p in params:
                self._scopes[-1][p] = "governed"
        self._fnstack.append(node.name)
        self.generic_visit(node)
        self._fnstack.pop()
        self._pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        # Mirror _collect_bindings: the class name is part of the scope path,
        # so a method's lookup key matches the map built for it. Without this
        # the resolver asks for ("helper",) while the pre-pass stored
        # ("Widget", "helper") and the lookup silently falls back to module
        # scope (v3.8.46 in-release BLOCK).
        self._fnstack.append(node.name)
        self.generic_visit(node)
        self._fnstack.pop()

    # --- binding --------------------------------------------------------
    def _bind(self, target: ast.AST, value: ast.AST) -> None:
        if not isinstance(target, ast.Name):
            return
        # BOUND-METHOD BINDING. `fn = getattr(p, "write_text")` then `fn(x)` left
        # `fn` unbound, so the later call matched no branch and vanished — the
        # silent-drop defect again, one indirection further out. Record the
        # (base, attr) pair under a reserved key so the call site can resolve it.
        if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                and value.func.id == "getattr" and len(value.args) >= 2
                and isinstance(value.args[1], ast.Constant)
                and isinstance(value.args[1].value, str)):
            base = _base_symbol(value.args[0]) or "?"
            self._scopes[-1][f"@bound:{target.id}"] = f"{base}|{value.args[1].value}"
            return
        # `op = open` / `rm = os.unlink` — alias a callable, not a path.
        if isinstance(value, ast.Name) and (value.id in BUILTIN_IO
                                            or self._func_of(value.id)):
            self._funcalias[target.id] = self._func_of(value.id) or "open"
            return
        if (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                and (self._mod_of(value.value.id),
                     value.attr) in FUNC_IO):
            mod = self._mod_of(value.value.id)
            self._funcalias[target.id] = f"{mod}.{value.attr}"
            return
        # `fn = p.write_text` — a BOUND METHOD taken as an attribute rather than
        # via getattr(). Same silent drop, different spelling (round-27 P2).
        if isinstance(value, ast.Attribute) and value.attr in PATH_IO_METHODS:
            b = _base_symbol(value.value) or "?"
            self._scopes[-1][f"@bound:{target.id}"] = f"{b}|{value.attr}"
            return
        kind = self._classify_expr(value)
        if kind:
            # GOVERNED IS STICKY. The analysis is path-INSENSITIVE, so a later
            # (even unreachable) `p = tmp_path / x` rebind used to erase an
            # earlier governed origin and hide the write — `if False:` was enough
            # (round-27 P1). Downgrading on a rebind is the fail-OPEN direction;
            # keeping governed may over-report, which is the safe direction.
            if self._scopes[-1].get(target.id) == "governed" and kind != "governed":
                return
            self._scopes[-1][target.id] = kind


    # --- alias resolution (scope-resolved, not walk-order) ---------------
    def _mods(self) -> dict:
        return self._bindings.get(tuple(self._fnstack), self._bindings[()])[0]

    def _funcs(self) -> dict:
        return self._bindings.get(tuple(self._fnstack), self._bindings[()])[1]

    def _bound(self) -> dict:
        return self._bindings.get(tuple(self._fnstack), self._bindings[()])[2]

    def _bound_of(self, name: str):
        # Walker-recorded binding first (an assignment earlier in THIS body),
        # then the scope-resolved one from the pre-pass.
        return self._scopes[-1].get(f"@bound:{name}") or self._bound().get(name)

    def _mod_of(self, name: str) -> str:
        return self._mods().get(name, name)

    def _func_of(self, name: str):
        return self._funcalias.get(name) or self._funcs().get(name)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for t in node.targets:
            self._bind(t, node.value)
            # v3.8.47 (round-30 P2): DESTRUCTURING. `p, _ = ROOT / "x", 1`
            # binds p just as plainly as `p = ROOT / "x"`, and only plain
            # Name targets were tracked. Pair element-wise where the shapes
            # match; otherwise let every element inherit the whole value, which
            # over-reports rather than dropping.
            if isinstance(t, (ast.Tuple, ast.List)):
                vals = (node.value.elts
                        if isinstance(node.value, (ast.Tuple, ast.List))
                        and len(node.value.elts) == len(t.elts)
                        else [node.value] * len(t.elts))
                for el, v in zip(t.elts, vals):
                    self._bind(el, v)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        """`for p in [ROOT / "x"]: p.write_text(...)` — the loop target takes
        the iterable's origin (round-30 P2).

        v3.8.47 in-release (checklist BLOCK): the first cut classified only
        `elts[0]`. `for p in [td, ROOT / "x"]` therefore bound the target
        FIXTURE for the whole body, and a fixture-classified write is not even
        reported as unresolved — so a governed write inside that loop produced
        NEITHER a finding NOR an unresolved line. Every element is classified
        and governed dominates, exactly as the multi-operand join fix does; the
        loop variable is each element in turn, so anything less is a guess
        about which iteration matters.
        """
        src = node.iter
        kind = ""
        if isinstance(src, (ast.List, ast.Tuple, ast.Set)) and src.elts:
            kinds = [self._classify_expr(e) for e in src.elts]
            kind = ("governed" if "governed" in kinds
                    else next((k for k in kinds if k), ""))
            src = src.elts[0]
        else:
            kind = self._classify_expr(src)
        targets = ([node.target] if not isinstance(node.target, (ast.Tuple, ast.List))
                   else list(node.target.elts))
        for tgt in targets:
            if isinstance(tgt, ast.Starred):
                tgt = tgt.value
            if isinstance(tgt, ast.Name) and kind:
                if self._scopes[-1].get(tgt.id) == "governed" and kind != "governed":
                    continue        # governed is sticky
                self._scopes[-1][tgt.id] = kind
            else:
                self._bind(tgt, src)
        self.generic_visit(node)

    visit_AsyncFor = visit_For  # type: ignore[assignment]

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:  # noqa: N802
        # `(p := ROOT / "x").write_text(...)` (round-30 P2).
        self._bind(node.target, node.value)
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:  # noqa: N802
        # `match ROOT / "x":` / `case p:` captures the subject (round-30 P2).
        for case in node.cases:
            pat = case.pattern
            if isinstance(pat, ast.MatchAs) and pat.name and pat.pattern is None:
                kind = self._classify_expr(node.subject)
                if kind:
                    self._scopes[-1][pat.name] = kind
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if node.value is not None:
            self._bind(node.target, node.value)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:  # noqa: N802
        for item in node.items:
            if item.optional_vars is not None:
                self._bind(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    # --- classification -------------------------------------------------
    def _classify_expr(self, expr: ast.AST) -> str:
        # v3.8.47 (round-30 P2): an origin does not have to say ROOT to BE the
        # checkout. A bare relative literal resolves against the process's cwd,
        # `Path.cwd()` is the checkout for every tool here, and
        # `Path(__file__).resolve().parent.parent` is how half these scripts
        # spell their own repo root. Treating only the blessed symbol as
        # governed is the same "list of the forms I thought of" that
        # os.path.join exposed one round earlier.
        if self._is_repo_relative(expr, allow_literal=self._literal_ok):
            return "governed"
        # os.path.join takes MANY path operands and the last absolute one wins
        # at runtime, so following argument 0 alone can miss a governed path in
        # a later position (in-release auditor WARN). Classify every operand
        # and let governed dominate — over-reporting is the safe direction.
        if (isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute)
                and expr.func.attr == "join" and len(expr.args) > 1):
            kinds = [self._classify_base(_base_symbol(a)) for a in expr.args]
            if "governed" in kinds:
                return "governed"
        base = _base_symbol(expr)
        return self._classify_base(base)

    def _classify_base(self, base: str | None) -> str:
        if base is None:
            return ""
        if base in FIXTURE_CALLS or base in FIXTURE_PARAMS:
            return "fixture"
        env = self._scopes[-1]
        if base in env and env[base]:
            return env[base]
        if base in GOVERNED_BASES:
            return "governed"
        if base.isupper() and len(base) > 2 and base not in self._literal_strs:
            return "governed"      # module-level path constant by convention
        return ""

    @staticmethod
    def _is_repo_relative(expr: ast.AST, allow_literal: bool = False) -> bool:
        """True for path origins that are the checkout without naming ROOT.

        `allow_literal` is only set where a bare relative STRING is
        unambiguously a path — the operand of `open()` or an `os`/`shutil`
        function. Path methods share names with str methods (`replace`,
        `join`), so a literal there is usually not a path at all: the first cut
        of this rule made `raw.replace("Z", "+00:00")` a governed write, and 32
        such false positives is a gate nobody would keep switched on.
        """
        node = expr
        for _ in range(64):
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
                node = node.left
                continue
            if isinstance(node, ast.Call):
                f = node.func
                # Path.cwd() / os.getcwd() — the process's own checkout.
                if isinstance(f, ast.Attribute) and f.attr in {"cwd", "getcwd"}:
                    return True
                # Path(__file__)... — a script naming its own tree.
                if (isinstance(f, ast.Name) and f.id == "Path" and node.args
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id == "__file__"):
                    return True
                if isinstance(f, ast.Attribute) and f.attr in {
                        "resolve", "absolute", "expanduser", "parent", "joinpath"}:
                    node = f.value
                    continue
                return False
            if isinstance(node, ast.Attribute) and node.attr in {"parent", "parents"}:
                node = node.value
                continue
            if isinstance(node, ast.Subscript):
                node = node.value
                continue
            if isinstance(node, ast.NamedExpr):
                node = node.value
                continue
            # A bare RELATIVE string literal resolves against cwd — but only
            # where the surrounding call proves it is a path.
            if allow_literal and isinstance(node, ast.Constant) and isinstance(node.value, str):
                v = node.value
                return bool(v) and not v.startswith(("/", "~")) and "://" not in v
            return False
        return False

    # --- call inspection ------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        # A call can touch MORE THAN ONE path. v3.8.43 inspected argument 0 only,
        # so the governed DESTINATION of `os.replace(tmp/src, ROOT/docs/dst)`,
        # `shutil.copy(...)` and `(tmp/src).replace(ROOT/docs/dst)` was invisible —
        # a governed write that produced no finding AND no unresolved line.
        # Collect every path-bearing position instead of picking one.
        cands: list[tuple[str | None, str]] = []

        def _operands(npaths: int):
            """Every path-bearing operand of this call: the first `npaths`
            POSITIONAL arguments plus any keyword named like a path. Keyword
            operands were invisible before v3.8.45 (round-28 P1).

            Returns (operands, opaque). `opaque` is True when the call carries
            a `**` unpacking whose contents cannot be read, so the caller can
            report an UNRESOLVED entry instead of nothing. v3.8.45 in-release
            (ast-parsing checklist BLOCK): a `**` keyword node has `arg=None`,
            so the first cut of this filter dropped `shutil.copy(**{"src": ...,
            "dst": ROOT / "x"})` entirely — no finding AND no unresolved line.
            That is the silent drop this file's own docstring calls a bug, and
            the refactor that fixed keyword operands reintroduced it.
            """
            out = [node.args[i] for i in range(min(npaths, len(node.args)))]
            opaque = False
            for k in node.keywords:
                if k.arg is not None:
                    if k.arg in PATH_KWARGS:
                        out.append(k.value)
                    continue
                # `**something`. A literal dict with constant keys is readable;
                # anything else is not, and unreadable must mean REPORTED.
                if isinstance(k.value, ast.Dict) and all(
                        isinstance(key, ast.Constant) and isinstance(key.value, str)
                        for key in k.value.keys):
                    for key, val in zip(k.value.keys, k.value.values):
                        if key.value in PATH_KWARGS:
                            out.append(val)
                else:
                    opaque = True
            return out, opaque

        # v3.8.47 (round-30 P2): operands resolved through _base_symbol alone,
        # so the all-operand os.path.join logic added in v3.8.46 only ever
        # protected paths that had been ASSIGNED to a name — an inline
        # `open(os.path.join("/tmp", ROOT, "docs", "x"), "w")` still passed.
        # Candidates now carry the expression so classification sees what
        # assignment classification sees.
        exprs: dict[int, ast.AST] = {}

        def _cand(expr, label):
            b = _base_symbol(expr)
            exprs[len(cands)] = expr
            cands.append((b, label))

        if isinstance(fn, ast.Attribute):
            if isinstance(fn.value, ast.Name) and (
                    self._mod_of(fn.value.id), fn.attr) in FUNC_IO:
                mod = self._mod_of(fn.value.id)
                label = f"{mod}.{fn.attr}"
                npaths = 2 if (mod, fn.attr) in TWO_PATH_FUNCS else 1
                ops, opaque = _operands(npaths)
                for a in ops:
                    _cand(a, label)
                if opaque:
                    cands.append((None, label))
            elif fn.attr in PATH_IO_METHODS:
                # The RECEIVER is an operand too — routed through _cand so it
                # gets the same expression-level classification the arguments
                # get (round-30 P2: `(Path.cwd() / "docs" / "x").write_text()`
                # resolved only through _base_symbol and passed).
                _cand(fn.value, fn.attr)
                if fn.attr in TWO_PATH_METHODS:
                    ops, opaque = _operands(1)
                    for a in ops:
                        _cand(a, fn.attr)
                    if opaque:
                        cands.append((None, fn.attr))
        elif isinstance(fn, ast.Name) and self._bound_of(fn.id):
            _b, _a = self._bound_of(fn.id).split("|", 1)
            cands.append((_b, _a))
        elif isinstance(fn, ast.Name) and (
                fn.id in BUILTIN_IO or self._func_of(fn.id) is not None):
            # `op = open` and `from os import unlink as remove_file` were both
            # dropped in silence: the callee is a bare Name that is not literally
            # `open`. Aliases are resolved through _funcalias.
            label = self._func_of(fn.id) or "open"
            npaths = 2 if label in TWO_PATH_LABELS else 1
            ops, opaque = _operands(npaths)
            for a in ops:
                _cand(a, label)
            if opaque:
                cands.append((None, label))
        elif isinstance(fn, ast.Call):
            gf = fn.func
            if (isinstance(gf, ast.Name) and gf.id == "getattr" and len(fn.args) >= 2
                    and isinstance(fn.args[1], ast.Constant)
                    and isinstance(fn.args[1].value, str)):
                attr = fn.args[1].value
                cands.append((_base_symbol(fn.args[0]),
                              attr if attr in PATH_IO_METHODS else f"getattr:{attr}"))
            else:
                cands.append((_base_symbol(fn), "<dynamic-call>"))
        if isinstance(fn, ast.Name) and not cands:
            pos = [self._classify_expr(a) for a in node.args]
            kw = {k.arg: self._classify_expr(k.value)
                  for k in node.keywords if k.arg is not None}
            # v3.8.46 (round-29 P2): `sink(**{"p": ROOT / "x"})` left the
            # callee's parameter unseeded, so the write inside stayed a passing
            # `unresolved` line. A literal dict is readable; read it.
            for k in node.keywords:
                if k.arg is None and isinstance(k.value, ast.Dict):
                    for key, val in zip(k.value.keys, k.value.values):
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            kw[key.value] = self._classify_expr(val)
            if "governed" in pos or "governed" in kw.values():
                self.local_calls.append((tuple(self._fnstack), fn.id, pos, kw))
        for _i, (base, method) in enumerate(cands):
            kind = self._classify_base(base)
            if kind != "governed" and _i in exprs:
                prev = self._literal_ok
                self._literal_ok = ("." in method or method == "open")
                try:
                    kind = self._classify_expr(exprs[_i]) or kind
                finally:
                    self._literal_ok = prev
            if kind == "governed":
                self.findings.append((node.lineno, base or "?", method))
            elif kind != "fixture":
                self.unresolved.append((node.lineno, base or "?", method))
        self.generic_visit(node)


def _read_source(path: Path) -> str | None:
    """Read a candidate file without following links or blocking on a FIFO."""
    import stat as _st
    try:
        fd = os.open(str(path), os.O_RDONLY
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except (OSError, ValueError):
        return None
    try:
        if not _st.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _resolve_module(tree: ast.AST) -> _ScopeResolver:
    """Resolve one module, propagating GOVERNED one call level at a time.

    v3.8.43 had no interprocedural step, so `raw_write(ROOT / "docs" / "x")`
    with `def raw_write(p): p.write_text(...)` produced no violation — only an
    `unresolved` line, which does NOT fail the build (round-27 P2). A one-line
    wrapper was therefore enough to reintroduce the class the gate exists to
    prevent, while the gate said `ok`.

    So: run the resolver, take every call to a module-local function that
    passes a governed path, map those arguments onto the callee's parameter
    names, and re-run with those parameters seeded as governed. Repeat to a
    fixpoint (bounded) so a wrapper behind a wrapper resolves too.

    Definitions and seeds are keyed by SCOPE PATH, not by bare name. The first
    cut used `ast.walk` + `setdefault`, which collapsed a nested `def
    helper(q)` and a module-level `def helper(x)` into a single entry: the
    fixpoint then seeded the outer function's parameter, producing a finding on
    a definition the call never reached AND leaving the write that did receive
    the governed path merely `unresolved`. Wrong in both directions at once.
    Argument mapping likewise uses `posonlyargs + args` for positions (they are
    excluded from keywords) and skips a leading `self`/`cls`, because an
    off-by-one in that mapping seeds an unrelated parameter.
    """
    # v3.8.45 (round-28 P2): the bound was a flat 4, so a five-deep
    # module-local wrapper chain left the write merely `unresolved` and the
    # build passed — a number chosen to feel like "enough" is a guess about
    # other people's code, and a 65-deep chain would only move the same defect
    # further out. Each pass either adds at least one (scope, parameter) pair
    # to the seed or halts, and the pairs a module can have is finite and
    # countable, so bound the loop by THAT: the fixpoint is reached before the
    # cap by construction, and the cap is a runaway backstop rather than a
    # depth limit. Counted once here, not re-derived per pass.
    _params = sum(len(n.args.posonlyargs) + len(n.args.args) + len(n.args.kwonlyargs) + 1
                  for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    bindings, _module_defs, literal_strs = _collect_bindings(tree)
    seed: dict[tuple[str, ...], set[str]] = {}
    r = _ScopeResolver(seed, bindings, literal_strs)
    r.visit(tree)
    for _ in range(_params + 1):
        grew = False
        for scope, name, pos, kw in r.local_calls:
            # Innermost enclosing definition of `name` wins, then outward —
            # the same order Python resolves the call in.
            fnode = None
            for depth in range(len(scope), -1, -1):
                fnode = r.defs.get((*scope[:depth], name))
                if fnode is not None:
                    key = (*scope[:depth], name)
                    break
            if fnode is None:
                continue
            positional = [a.arg for a in fnode.args.posonlyargs + fnode.args.args]
            if positional and positional[0] in {"self", "cls"}:
                positional = positional[1:]
            byname = {a.arg for a in fnode.args.args + fnode.args.kwonlyargs}
            want = set()
            for i, k in enumerate(pos):
                if k != "governed":
                    continue
                if i < len(positional):
                    want.add(positional[i])
                elif fnode.args.vararg is not None:
                    want.add(fnode.args.vararg.arg)   # collected into *args
            want |= {k for k, v in kw.items() if v == "governed" and k in byname}
            # A governed keyword the callee does not name by hand is collected
            # into **kwargs, and `kwargs["p"]` reaches it by subscript
            # (round-29 P2). Seed the container.
            if fnode.args.kwarg is not None and any(
                    v == "governed" and k not in byname for k, v in kw.items()):
                want.add(fnode.args.kwarg.arg)
            if want - seed.get(key, set()):
                seed.setdefault(key, set()).update(want)
                grew = True
        if not grew:
            break
        r = _ScopeResolver(seed, bindings, literal_strs)
        r.visit(tree)
    return r


def _walk_sources(scripts_dir: Path):
    """Yield (rel, path) for every candidate, or (rel, None) for a directory
    that cannot be trusted to be part of the scan surface.

    v3.8.45 (round-28 P2): the top-level `scripts` symlink was refused but
    `rglob` happily followed a symlinked CHILD directory, so `scripts/linked ->
    /outside` silently redirected part of the surface and the gate still said
    ok. A scan surface that quietly changes shape is the same failure as an
    exemption that quietly stops matching.
    """
    stack = [scripts_dir]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as _it:
                entries = sorted(_it, key=lambda e: e.name)
        except OSError as e:
            yield (str(d.relative_to(scripts_dir)) if d != scripts_dir else ".",
                   None, f"unreadable directory ({e.__class__.__name__})")
            continue
        for e in entries:
            child = Path(e.path)
            rel = child.relative_to(scripts_dir).as_posix()
            if e.is_symlink():
                # A symlinked FILE is caught by _read_source; a symlinked DIR
                # would silently swap the surface, so refuse it here.
                if e.is_dir(follow_symlinks=False) or child.is_dir():
                    yield (rel, None, "symlinked directory — refusing a "
                                      "redirected scan surface")
                    continue
            if e.is_dir(follow_symlinks=False):
                if e.name in {"__pycache__", ".git"}:
                    continue
                stack.append(child)
            elif e.name.endswith(".py"):
                yield (rel, child, None)


def scan(scripts_dir: Path, label: str = "") -> tuple[list[str], set[str], list[str]]:
    """Return (violations, matched allowlist keys, unresolved notes).

    `label` prefixes every reported path AND every allowlist key, so a file in a
    staging tree can never share an exemption with a same-named file in
    scripts/. Adding a second scan surface without that prefix would have
    reintroduced the basename-collision defect this same release fixed, one
    layer further out.
    """
    violations: list[str] = []
    matched: set[str] = set()
    unresolved: list[str] = []
    self_path = Path(__file__).resolve()
    for rel, path, why in sorted(_walk_sources(scripts_dir), key=lambda x: x[0]):
        rel = f"{label}{rel}"
        if path is None:
            violations.append(f"{rel}: {why}")
            continue
        # v3.8.45 (round-28 P2): the self-skip compared BASENAMES, so any
        # nested file called check_raw_file_io.py was silently unscannable.
        try:
            if path.resolve() == self_path:
                continue  # this gate's own docstring names the primitives
        except OSError:
            pass
        # v3.8.44 (round-27 P2): this gate read every candidate with a blocking
        # path.read_text() BEFORE any non-regular check, so a FIFO in scripts/
        # HUNG it — the fourth time a component of this system carried the very
        # defect it polices. Open O_NOFOLLOW|O_NONBLOCK, require a regular file,
        # and treat anything else as a violation rather than a hang.
        src = _read_source(path)
        if src is None:
            violations.append(f"{rel}: not a readable regular file "
                              "(symlink/FIFO/socket/device) — refusing to scan it")
            continue
        # Deeply nested source can exhaust the interpreter's stack inside
        # ast.parse or the visitor, and the fixpoint runs the visitor several
        # times. An unanalyzable file must FAIL, not crash the gate out with a
        # traceback that a CI log reads as an infrastructure blip. v3.8.45
        # (round-28 P3): the guard was around the VISITOR only, so a
        # syntactically valid 12,000-term expression blew the stack inside
        # ast.parse and escaped as a traceback — the guard did not cover the
        # call that actually raises first.
        try:
            tree = ast.parse(src)
            r = _resolve_module(tree)
        except SyntaxError as e:
            violations.append(f"{rel}: unparseable ({e})")
            continue
        except (RecursionError, MemoryError) as e:
            violations.append(f"{rel}: too deeply nested to analyze "
                              f"({type(e).__name__}) — refusing to pass it")
            continue
        for line, base, method in r.findings:
            # v3.8.45 (round-28 P1): the key was the BASENAME, so an exemption
            # reviewed for scripts/_doc_common.py also covered a same-named file
            # anywhere else in the tree. A stale-exemption hole in the mechanism
            # whose selling point is that stale exemptions fail is not a detail.
            key = f"{rel}:{base}.{method}"
            if key in ALLOWLIST:
                matched.add(key)
                _ALLOWLIST_HITS[key] = _ALLOWLIST_HITS.get(key, 0) + 1
                continue
            violations.append(
                f"{rel}:{line}: raw {base}.{method}() on a repo-derived "
                f"path — use the guarded helper (safe_read_text / "
                f"safe_atomic_write / read_lock)")
        for line, base, method in r.unresolved:
            unresolved.append(f"{rel}:{line}: {base}.{method}()")
    return violations, matched, unresolved


# Directories whose files BECOME scripts/ in some profile. v3.8.45 (round-28
# follow-on, caught by a strict consumer's own gate the first run after the
# templates were wired): extras/*.py are copied into scripts/ on a strict
# install, so they are governed scripts THERE — but they live outside scripts/
# in the kit, so the kit's own gate never scanned them and their raw read/write
# survived every sweep in this series. Auditing only the directory a file
# currently sits in misses every file that moves into the surface later.
STAGED_INTO_SCRIPTS = ("extras",)


def main(argv: list[str]) -> int:
    root = ROOT
    if "--root" in argv:
        root = Path(argv[argv.index("--root") + 1]).resolve()
    scripts_dir = root / "scripts"
    # v3.8.44 (round-27 P2): a SYMLINKED scripts/ made the gate audit bytes
    # outside the requested root and report green about them. The scan surface
    # must be a real directory in the tree it claims to be auditing.
    if scripts_dir.is_symlink():
        print(f"check-raw-file-io: {scripts_dir} is a symlink — refusing to audit "
              "a redirected scan surface", file=sys.stderr)
        return 2
    if not scripts_dir.is_dir():
        print(f"check-raw-file-io: no scripts dir at {scripts_dir}", file=sys.stderr)
        return 2
    # v3.8.44 (round-27 P3): when _substrate_root fails, ROOT silently became
    # cwd, so a standalone run could scan a DIFFERENT clean checkout than the
    # script the operator invoked and report ok about it. The fallback is now
    # this script's own tree, and the degraded resolution is announced.
    if "--root" not in argv and _ROOT_FALLBACK:
        print("check-raw-file-io: repo root could not be resolved; falling back "
              f"to this script's own tree ({scripts_dir}) — pass --root to be explicit",
              file=sys.stderr)
    violations, matched, unresolved = scan(scripts_dir)
    # ...then the staging trees, under their own labels so a finding names the
    # file the author would edit rather than the copy a profile makes.
    for extra in STAGED_INTO_SCRIPTS:
        staged = root / extra
        if staged.is_symlink():
            print(f"check-raw-file-io: {staged} is a symlink — refusing to audit "
                  "a redirected scan surface", file=sys.stderr)
            return 2
        if not staged.is_dir():
            continue
        v2, m2, u2 = scan(staged, label=f"{extra}/")
        violations += v2
        matched |= m2
        unresolved += u2

    stale = sorted(set(ALLOWLIST) - matched)
    for key in stale:
        violations.append(
            f"allowlist entry no longer matches any call site: {key!r} — "
            "remove it (a stale exemption is permanent cover)")
    # v3.8.45 (round-28 P1): an exemption is granted to a call site a human
    # actually read. If it silently starts covering MORE sites, the extra ones
    # were never reviewed — the same failure as a stale entry, in the opposite
    # direction. Declare a deliberate multi-site exemption as (reason, count).
    for key, hits in sorted(_ALLOWLIST_HITS.items()):
        want = _allow_count(ALLOWLIST[key])
        if hits != want:
            violations.append(
                f"allowlist entry {key!r} matched {hits} call sites but was "
                f"reviewed for {want} — review the new site(s) and update the "
                "entry to (reason, count) if all of them are genuinely safe")

    if "--list-unresolved" in argv:
        for u in unresolved:
            print(f"  unresolved: {u}")

    if violations:
        print("check-raw-file-io: BLOCK", file=sys.stderr)
        for v in violations:
            print(f"  - {v}", file=sys.stderr)
        print(
            "\nRaw file I/O on a repo-derived path is the defect class that "
            "recurred across six audit rounds: the leaf or an ancestor can be a "
            "symlink, a hard link, a FIFO, or swapped between the check and the "
            "use. Route the call through the shared guards, or add a reviewed "
            "ALLOWLIST entry in this file explaining why it is safe.",
            file=sys.stderr)
        return 1
    print(f"check-raw-file-io: ok ({len(ALLOWLIST)} reviewed exemptions, "
          f"{len(unresolved)} unresolved call sites — run with "
          f"--list-unresolved to review)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
