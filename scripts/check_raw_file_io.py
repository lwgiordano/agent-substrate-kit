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
  - A governed path that reaches a write only by being passed INTO a helper
    function is reported as `unresolved`, not as a violation — there is no
    interprocedural analysis.
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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

SCRIPTS = ROOT / "scripts"

# Path-object methods that touch the filesystem by NAME.
PATH_IO_METHODS = {
    "read_text", "write_text", "read_bytes", "write_bytes", "mkdir", "open",
    "touch", "unlink", "rename", "replace", "symlink_to", "hardlink_to", "rmdir",
}
# Module-level functions that do the same. `os.open` re-resolves by name too.
FUNC_IO = {
    ("os", "open"), ("os", "replace"), ("os", "rename"), ("os", "remove"),
    ("os", "unlink"), ("os", "mkdir"), ("os", "makedirs"), ("os", "rmdir"),
    ("os", "truncate"), ("os", "symlink"), ("os", "link"),
    ("shutil", "copy"), ("shutil", "copy2"), ("shutil", "copyfile"),
    ("shutil", "copytree"), ("shutil", "move"), ("shutil", "rmtree"),
}
# Bare builtin.
BUILTIN_IO = {"open"}

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

    def __init__(self) -> None:
        self.findings: list[tuple[int, str, str]] = []   # (line, base, method)
        self.unresolved: list[tuple[int, str, str]] = []
        self._scopes: list[dict[str, str]] = [{}]
        # `import os as _o` / `import shutil as _s` aliased the module, so a
        # literal "os"/"shutil" name check missed os.replace/shutil.copy behind
        # the alias. Track aliases so the module identity, not the spelling, is
        # what matters.
        self._modalias: dict[str, str] = {}

    # --- scope handling -------------------------------------------------
    def _push(self, params: list[str]) -> None:
        env = dict(self._scopes[-1])          # inherit module-level constants
        for p in params:
            env[p] = "fixture" if p in FIXTURE_PARAMS else env.get(p, "")
        self._scopes.append(env)

    def _pop(self) -> None:
        self._scopes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        params = [a.arg for a in node.args.args + node.args.kwonlyargs]
        for p in params:
            if p in GOVERNED_BASES:
                pass  # handled by classification directly
        self._push(params)
        self.generic_visit(node)
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
        kind = self._classify_expr(value)
        if kind:
            self._scopes[-1][target.id] = kind

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for a in node.names:
            if a.name in {"os", "shutil"}:
                self._modalias[a.asname or a.name] = a.name
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
        base = method = None
        if isinstance(fn, ast.Attribute):
            # MODULE-FUNCTION FIRST. `replace`/`rename`/`unlink`/`open` appear in
            # BOTH tables, so checking the Path-method table first resolved
            # `os.replace(str(ROOT/"a"), ...)` to the base "os" — a module name,
            # never governed — and the real path argument was never examined.
            if isinstance(fn.value, ast.Name) and (
                    self._modalias.get(fn.value.id, fn.value.id), fn.attr) in FUNC_IO:
                # os.replace(a, b) / shutil.copy(a, b): the PATH is arg 0.
                base = _base_symbol(node.args[0]) if node.args else None
                method = f"{self._modalias.get(fn.value.id, fn.value.id)}.{fn.attr}"
            elif fn.attr in PATH_IO_METHODS:
                base, method = _base_symbol(fn.value), fn.attr
        elif isinstance(fn, ast.Name) and f"@bound:{fn.id}" in self._scopes[-1]:
            _b, _a = self._scopes[-1][f"@bound:{fn.id}"].split("|", 1)
            base, method = _b, _a
        elif isinstance(fn, ast.Name) and fn.id in BUILTIN_IO:
            base = _base_symbol(node.args[0]) if node.args else None
            method = "open"
        elif isinstance(fn, ast.Call):
            # DYNAMIC DISPATCH. `getattr(p, "write_text")("x")` makes the callee
            # itself a Call, which matched no branch and was SILENTLY DROPPED —
            # not even counted as unresolved. That is a fail-open hole in a gate
            # whose whole point is that unresolved must stay visible.
            gf = fn.func
            if (isinstance(gf, ast.Name) and gf.id == "getattr" and len(fn.args) >= 2
                    and isinstance(fn.args[1], ast.Constant)
                    and isinstance(fn.args[1].value, str)):
                attr = fn.args[1].value
                if attr in PATH_IO_METHODS:
                    base, method = _base_symbol(fn.args[0]), attr
                else:
                    base, method = _base_symbol(fn.args[0]), f"getattr:{attr}"
            else:
                # Any other computed callee is unresolvable by static analysis;
                # record it so the blind spot is reported rather than invisible.
                base, method = _base_symbol(fn), "<dynamic-call>"
        if method is not None:
            kind = self._classify_base(base)
            if kind == "governed":
                self.findings.append((node.lineno, base or "?", method))
            elif kind != "fixture":
                self.unresolved.append((node.lineno, base or "?", method))
        self.generic_visit(node)


def scan(scripts_dir: Path) -> tuple[list[str], set[str], list[str]]:
    """Return (violations, matched allowlist keys, unresolved notes)."""
    violations: list[str] = []
    matched: set[str] = set()
    unresolved: list[str] = []
    for path in sorted(scripts_dir.rglob("*.py")):
        if path.name == Path(__file__).name:
            continue  # this gate's own docstring names the primitives
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as e:
            violations.append(f"{path.name}: unreadable/unparseable ({e})")
            continue
        r = _ScopeResolver()
        r.visit(tree)
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
    if not scripts_dir.is_dir():
        print(f"check-raw-file-io: no scripts dir at {scripts_dir}", file=sys.stderr)
        return 2
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
