#!/usr/bin/env python3
"""Engineering-SHAPE report — LOCAL, READ-ONLY, WARN-ONLY, deterministic. (v3.7.8)

The security gates stop the substrate's own threat model (exfil, injection, tamper). But
real vibe-coded repos fail in a different way: bloated unreviewable diffs, sprawling
files, god-functions, AI changes that touch source without tests, and silent churn in
governance/CI/dependency files. None of that is a security hook problem — it is a
code-SHAPE and reviewability problem.

This is a deterministic warn-only REPORT (no LLM, no gate, no network, no writes). It does
NOT block `check` — it surfaces shape so a human/agent can decide. Two views:

  REPO-WIDE   largest source files, files over a line threshold (sprawl), and long
              functions (python AST; > a line threshold = god-function risk).
  DIFF        the current change vs HEAD (tracked) + untracked new files: changed lines,
              a large-diff warning, source-changed-without-tests, and flags for new/changed
              governance/CI and dependency-manifest files (the high-review-value churn).

Thresholds are sensible defaults (file 400 lines, function 80 lines, diff 500 lines),
overridable via flags. Token counts are not involved — see `context-report` for that.

Usage: code_shape.py [--root PATH] [--json] [--file-lines N] [--func-lines N] [--diff-lines N]
Exit: 0 always (informational — warn-only, never a gate).
"""
from __future__ import annotations
import argparse, ast, json, subprocess, sys
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()

_CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".rb",
                  ".php", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
                  ".scala", ".sh", ".bash"}
_SKIP_PARTS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
               ".pytest_cache", ".ruff_cache", ".mypy_cache", "vendor", ".substrate"}
_DEP_MANIFESTS = {"package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
                  "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile", "Pipfile.lock",
                  "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile", "Gemfile.lock",
                  "composer.json", "composer.lock"}


def _is_test(rel: str) -> bool:
    p = rel.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    return ("/tests/" in f"/{p}" or p.startswith("tests/")
            or base.startswith("test_") or base.endswith("_test.go")
            or "_test." in base or ".test." in base or ".spec." in base
            or "/test/" in f"/{p}")


def _is_dep_manifest(rel: str) -> bool:
    base = rel.replace("\\", "/").rsplit("/", 1)[-1]
    return base in _DEP_MANIFESTS or base.startswith("requirements")


def _is_governance(rel: str) -> bool:
    p = rel.replace("\\", "/")
    return (p.startswith(".github/workflows/") or p.startswith(".github/")
            or p == ".pre-commit-config.yaml" or p.startswith("scripts/")
            or p == "Dockerfile" or p.endswith(".yml") and p.startswith(".github"))


def _skip(rel: str) -> bool:
    return any(part in _SKIP_PARTS for part in Path(rel).parts)


def _line_count(p: Path) -> int:
    try:
        return sum(1 for _ in p.open("rb"))
    except Exception:
        return 0


def _repo_shape(root: Path, suffixes, file_lines: int, func_lines: int) -> dict:
    files = []
    long_funcs = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if _skip(rel) or p.suffix not in suffixes:
            continue
        n = _line_count(p)
        files.append((n, rel))
        if p.suffix == ".py":
            try:
                tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        end = getattr(node, "end_lineno", node.lineno)
                        span = end - node.lineno + 1
                        if span > func_lines:
                            long_funcs.append({"loc": f"{rel}:{node.lineno}", "name": node.name, "lines": span})
            except Exception:
                pass
    files.sort(reverse=True)
    oversize = [{"path": r, "lines": n} for n, r in files if n > file_lines]
    long_funcs.sort(key=lambda d: d["lines"], reverse=True)
    return {
        "largest_files": [{"path": r, "lines": n} for n, r in files[:10]],
        "files_over_threshold": oversize,
        "long_functions": long_funcs[:15],
        "file_lines_threshold": file_lines,
        "func_lines_threshold": func_lines,
    }


def _git(root: Path, *args):
    try:
        p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    return p.stdout if p.returncode == 0 else None


def _diff_shape(root: Path, diff_lines: int) -> dict:
    if _git(root, "rev-parse", "--is-inside-work-tree") is None:
        return {"available": False, "reason": "not a git work tree"}
    # tracked changes vs HEAD (staged + unstaged). HEAD may not exist (no commits yet).
    numstat = _git(root, "diff", "HEAD", "--numstat")
    if numstat is None:
        numstat = _git(root, "diff", "--numstat") or ""
    added = deleted = 0
    changed = []
    for line in numstat.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        a, d, path = parts
        ai = int(a) if a.isdigit() else 0
        di = int(d) if d.isdigit() else 0
        added += ai; deleted += di
        changed.append(path)
    # untracked new files
    untracked = [f for f in (_git(root, "ls-files", "--others", "--exclude-standard") or "").splitlines() if f]
    for f in untracked:
        added += _line_count(root / f)
        changed.append(f)
    changed = sorted(set(c for c in changed if c))
    src = [c for c in changed if Path(c).suffix in _CODE_SUFFIXES and not _is_test(c)
           and not _is_governance(c) and not _is_dep_manifest(c)]
    tests = [c for c in changed if _is_test(c)]
    gov = [c for c in changed if _is_governance(c)]
    deps = [c for c in changed if _is_dep_manifest(c)]
    warnings = []
    if added + deleted > diff_lines:
        warnings.append(f"large diff: {added + deleted} changed lines (> {diff_lines}) — consider splitting into smaller, reviewable PRs")
    if src and not tests:
        warnings.append(f"{len(src)} source file(s) changed but NO test file changed — add/adjust tests for the change")
    if tests and not src and not gov:
        warnings.append("test file(s) changed but no source changed — verify the test matches a real requirement, not just current behavior")
    if gov:
        warnings.append(f"governance/CI files changed ({', '.join(gov[:5])}{' …' if len(gov) > 5 else ''}) — review carefully")
    if deps:
        warnings.append(f"dependency manifest changed ({', '.join(deps[:5])}) — review new/updated deps (see dep-cooldown)")
    return {
        "available": True, "files_changed": len(changed), "lines_added": added, "lines_deleted": deleted,
        "source": src, "tests": tests, "governance": gov, "dependencies": deps,
        "diff_lines_threshold": diff_lines, "warnings": warnings,
    }


def build(root: Path, file_lines: int, func_lines: int, diff_lines: int) -> dict:
    repo = _repo_shape(root, _CODE_SUFFIXES, file_lines, func_lines)
    diff = _diff_shape(root, diff_lines)
    recs = []
    if repo["files_over_threshold"]:
        recs.append(f"{len(repo['files_over_threshold'])} file(s) over {file_lines} lines — large files are hard to review/own; consider splitting.")
    if repo["long_functions"]:
        recs.append(f"{len(repo['long_functions'])} python function(s) over {func_lines} lines — long functions hide bugs; extract helpers.")
    recs.extend(diff.get("warnings", []))
    if not recs:
        recs.append("No shape warnings — files, functions, and the current diff are within thresholds.")
    return {"repo": repo, "diff": diff, "recommendations": recs}


def _print(d: dict) -> None:
    print("CODE-SHAPE REPORT  (warn-only; deterministic; NOT a gate)")
    print("=" * 60)
    repo = d["repo"]
    print(f"\nLARGEST SOURCE FILES (lines):")
    for f in repo["largest_files"]:
        print(f"  {f['lines']:>6}  {f['path']}")
    if repo["files_over_threshold"]:
        print(f"\nFILES OVER {repo['file_lines_threshold']} LINES (sprawl): {len(repo['files_over_threshold'])}")
        for f in repo["files_over_threshold"][:10]:
            print(f"  {f['lines']:>6}  {f['path']}")
    if repo["long_functions"]:
        print(f"\nLONG PYTHON FUNCTIONS (> {repo['func_lines_threshold']} lines): {len(repo['long_functions'])}")
        for fn in repo["long_functions"][:10]:
            print(f"  {fn['lines']:>5}  {fn['loc']}  {fn['name']}()")
    df = d["diff"]
    if df.get("available"):
        print(f"\nCURRENT DIFF (vs HEAD + untracked): {df['files_changed']} files, +{df['lines_added']}/-{df['lines_deleted']} lines")
        for k in ("source", "tests", "governance", "dependencies"):
            if df[k]:
                print(f"  {k}: {len(df[k])}")
    else:
        print(f"\nCURRENT DIFF: n/a ({df.get('reason', 'unavailable')})")
    print("\nRECOMMENDATIONS:")
    for r in d["recommendations"]:
        print("  - " + r)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--file-lines", type=int, default=400)
    ap.add_argument("--func-lines", type=int, default=80)
    ap.add_argument("--diff-lines", type=int, default=500)
    a = ap.parse_args()
    d = build(Path(a.root), a.file_lines, a.func_lines, a.diff_lines)
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        _print(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
