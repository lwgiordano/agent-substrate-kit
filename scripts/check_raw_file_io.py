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
  - `_modalias`/`_funcalias` are module-wide, not per-scope, so an alias bound
    inside one function is visible in the next. That direction over-reports
    (more findings), never under-reports, so it is left as-is.
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
    "run_security_scanners.py:outdir.mkdir":
        "creates the report dir immediately before a safe_atomic_write into it; "
        "that writer re-validates containment and anchors to the parent fd, so "
        "the mkdir cannot be used to place content",
    "substrate_audit.py:outdir.mkdir":
        "same shape as run_security_scanners — mkdir then guarded writes into "
        "the created directory, which re-check containment themselves",
    "run_substrate_evals.py:TRACES.mkdir":
        "creates .substrate/traces immediately before a safe_atomic_write into "
        "it; that writer re-validates containment and anchors to the parent fd",
    "run_substrate_evals.py:SCRIPTS.shutil.copytree":
        "stages a copy of the kit's OWN scripts/ into a fresh TemporaryDirectory "
        "so the raw-IO gate can be run against a planted violation; source is "
        "code under review, destination is a temp dir",
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


def _base_symbol(node: ast.AST) -> str | None:
    """Walk an `a / b / c` chain (or Name/Attribute/Call) to its base symbol."""
    seen = 0
    while seen < 64:
        seen += 1
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            node = node.left
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


class _ScopeResolver(ast.NodeVisitor):
    """Resolve path-bearing names to GOVERNED / FIXTURE within each scope."""

    def __init__(self, seed: dict[str, set[str]] | None = None) -> None:
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
        self._modalias: dict[str, str] = {}
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
        self._push(params)
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
                                            or value.id in self._funcalias):
            self._funcalias[target.id] = self._funcalias.get(value.id, "open")
            return
        if (isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name)
                and (self._modalias.get(value.value.id, value.value.id),
                     value.attr) in FUNC_IO):
            mod = self._modalias.get(value.value.id, value.value.id)
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

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for a in node.names:
            if a.name in {"os", "shutil"}:
                self._modalias[a.asname or a.name] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module in {"os", "shutil"}:
            for a in node.names:
                if (node.module, a.name) in FUNC_IO:
                    self._funcalias[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for t in node.targets:
            self._bind(t, node.value)
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
        if base.isupper() and len(base) > 2:
            return "governed"      # module-level path constant by convention
        return ""

    # --- call inspection ------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        # A call can touch MORE THAN ONE path. v3.8.43 inspected argument 0 only,
        # so the governed DESTINATION of `os.replace(tmp/src, ROOT/docs/dst)`,
        # `shutil.copy(...)` and `(tmp/src).replace(ROOT/docs/dst)` was invisible —
        # a governed write that produced no finding AND no unresolved line.
        # Collect every path-bearing position instead of picking one.
        cands: list[tuple[str | None, str]] = []
        if isinstance(fn, ast.Attribute):
            if isinstance(fn.value, ast.Name) and (
                    self._modalias.get(fn.value.id, fn.value.id), fn.attr) in FUNC_IO:
                mod = self._modalias.get(fn.value.id, fn.value.id)
                label = f"{mod}.{fn.attr}"
                npaths = 2 if (mod, fn.attr) in TWO_PATH_FUNCS else 1
                for i in range(min(npaths, len(node.args))):
                    cands.append((_base_symbol(node.args[i]), label))
            elif fn.attr in PATH_IO_METHODS:
                cands.append((_base_symbol(fn.value), fn.attr))
                if fn.attr in TWO_PATH_METHODS and node.args:
                    cands.append((_base_symbol(node.args[0]), fn.attr))
        elif isinstance(fn, ast.Name) and f"@bound:{fn.id}" in self._scopes[-1]:
            _b, _a = self._scopes[-1][f"@bound:{fn.id}"].split("|", 1)
            cands.append((_b, _a))
        elif isinstance(fn, ast.Name) and (
                fn.id in BUILTIN_IO or self._funcalias.get(fn.id) is not None):
            # `op = open` and `from os import unlink as remove_file` were both
            # dropped in silence: the callee is a bare Name that is not literally
            # `open`. Aliases are resolved through _funcalias.
            label = self._funcalias.get(fn.id) or "open"
            npaths = 2 if label in TWO_PATH_LABELS else 1
            for i in range(min(npaths, len(node.args))):
                cands.append((_base_symbol(node.args[i]), label))
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
            if "governed" in pos or "governed" in kw.values():
                self.local_calls.append((tuple(self._fnstack), fn.id, pos, kw))
        for base, method in cands:
            kind = self._classify_base(base)
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
    seed: dict[tuple[str, ...], set[str]] = {}
    r = _ScopeResolver(seed)
    r.visit(tree)
    for _ in range(4):
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
            if want - seed.get(key, set()):
                seed.setdefault(key, set()).update(want)
                grew = True
        if not grew:
            break
        r = _ScopeResolver(seed)
        r.visit(tree)
    return r


def scan(scripts_dir: Path) -> tuple[list[str], set[str], list[str]]:
    """Return (violations, matched allowlist keys, unresolved notes)."""
    violations: list[str] = []
    matched: set[str] = set()
    unresolved: list[str] = []
    for path in sorted(scripts_dir.rglob("*.py")):
        if path.name == Path(__file__).name:
            continue  # this gate's own docstring names the primitives
        # v3.8.44 (round-27 P2): this gate read every candidate with a blocking
        # path.read_text() BEFORE any non-regular check, so a FIFO in scripts/
        # HUNG it — the fourth time a component of this system carried the very
        # defect it polices. Open O_NOFOLLOW|O_NONBLOCK, require a regular file,
        # and treat anything else as a violation rather than a hang.
        src = _read_source(path)
        if src is None:
            violations.append(f"{path.name}: not a readable regular file "
                              "(symlink/FIFO/socket/device) — refusing to scan it")
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError as e:
            violations.append(f"{path.name}: unparseable ({e})")
            continue
        # Deeply nested source can exhaust the interpreter's stack inside
        # ast.parse or the visitor, and the fixpoint runs the visitor up to
        # five times. An unanalyzable file must FAIL, not crash the gate out
        # with a traceback that a CI log reads as an infrastructure blip.
        try:
            r = _resolve_module(tree)
        except (RecursionError, MemoryError) as e:
            violations.append(f"{path.name}: too deeply nested to analyze "
                              f"({type(e).__name__}) — refusing to pass it")
            continue
        for line, base, method in r.findings:
            key = f"{path.name}:{base}.{method}"
            if key in ALLOWLIST:
                matched.add(key)
                continue
            violations.append(
                f"{path.name}:{line}: raw {base}.{method}() on a repo-derived "
                f"path — use the guarded helper (safe_read_text / "
                f"safe_atomic_write / read_lock)")
        for line, base, method in r.unresolved:
            unresolved.append(f"{path.name}:{line}: {base}.{method}()")
    return violations, matched, unresolved


def main(argv: list[str]) -> int:
    scripts_dir = SCRIPTS
    if "--root" in argv:
        scripts_dir = Path(argv[argv.index("--root") + 1]).resolve() / "scripts"
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

    stale = sorted(set(ALLOWLIST) - matched)
    for key in stale:
        violations.append(
            f"allowlist entry no longer matches any call site: {key!r} — "
            "remove it (a stale exemption is permanent cover)")

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
