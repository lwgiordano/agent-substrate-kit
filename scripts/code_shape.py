#!/usr/bin/env python3
"""Engineering-SHAPE report — LOCAL, READ-ONLY, WARN-ONLY, deterministic. (v3.7.8; project/
substrate separation v3.7.9)

The security gates stop the substrate's own threat model (exfil, injection, tamper). But
real vibe-coded repos fail in a different way: bloated unreviewable diffs, sprawling files,
god-functions, AI changes that touch source without tests, and silent churn in
governance/CI/dependency/agent-control files. None of that is a security hook problem — it
is a code-SHAPE and reviewability problem.

This is a deterministic warn-only REPORT (no LLM, no gate, no network, no writes). It does
NOT block `check`. Crucially it measures the USER's PROJECT, not the substrate it is
installed into: substrate-owned files (the harness's own scripts/, kit tests, agent config,
docs/knowledge, …) are classified separately and excluded from the project shape by default
(v3.7.9 — else a fresh install reads as "your repo has sprawl/god-functions/a huge diff",
which is the harness, not the user). Use `--include-substrate` to dogfood the kit itself.

Views:
  PROJECT (repo-wide)  largest project source files, files over a line threshold (sprawl),
                       long python functions (AST; god-function risk) — substrate-owned
                       files excluded by default.
  SUBSTRATE (summary)  count + largest substrate-owned files, reported separately.
  DIFF (vs HEAD)       project changed lines, a large-diff warning (project lines only),
                       source-changed-without-tests, governance/agent-control churn, and
                       dependency-manifest churn. A fresh/install-dominated diff is reported
                       as "substrate install/update", NOT a large project diff.

Thresholds default to file 400 lines / function 80 lines / diff 500 lines (overridable).

Usage: code_shape.py [--root PATH] [--json] [--include-substrate]
                     [--file-lines N] [--func-lines N] [--diff-lines N]
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

# --- substrate-owned classifier: reuse the CANONICAL owned-surface inventory so it cannot
#     drift from the CODEOWNERS / harness-scan view. `tests/` is MIXED (the kit ships
#     specific test files there; users add their own), so only the kit's specific test
#     files are owned — not the whole dir. (v3.7.9)
try:
    from _substrate_surfaces import OWNED_DIRS, OWNED_FILES, OPTIONAL_DIRS, OPTIONAL_FILES
    # +extras/ (strict-profile substrate code; not in the inventory's coverage dirs).
    _OWNED_DIRS = tuple(d.rstrip("/") + "/" for d in (OWNED_DIRS + OPTIONAL_DIRS) if d != "tests") + ("extras/",)
    _OWNED_FILES = set(OWNED_FILES) | set(OPTIONAL_FILES)
except Exception:
    _OWNED_DIRS = ("scripts/", "extras/", ".claude/", ".codex/", ".agents/", ".github/hooks/",
                   ".github/instructions/", ".github/workflows/", ".github/skills/",
                   "docs/knowledge/", "docs/decisions/", "docs/blind-spot-checklists/",
                   "docs/templates/", "docs/postmortems/")
    _OWNED_FILES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", "DESIGN.md", "manage.sh", "pytest.ini",
                    ".pre-commit-config.yaml", ".gitattributes", ".gitignore",
                    ".github/copilot-instructions.md", ".github/dependabot.yml", ".mcp.json"}
# kit-source-only files + the kit's own test files (shipped into user repos by name).
_OWNED_FILES |= {"bootstrap.sh", "package_release.sh", "BENCHMARK.md", "CHANGES_V3.md"}
_KIT_TEST_FILES = {"tests/conftest.py", "tests/test_doc_consistency.py", "tests/test_hook_scripts.py",
                   "tests/test_smoke.py", "tests/test_substrate_files.py"}

# --- governance / agent-control surfaces (flag CHURN regardless of ownership): the
#     highest-review-value files an agent might casually edit in a broad patch. (v3.7.9)
_GOV_PREFIXES = (".github/", ".substrate/", ".claude/", ".codex/", ".agents/",
                 "scripts/", "docs/knowledge/", "docs/decisions/",
                 "docs/blind-spot-checklists/", "docs/templates/", "docs/postmortems/",
                 "design-system/")
_GOV_FILES = {"AGENTS.md", "CLAUDE.md", "GEMINI.md", "DESIGN.md", "CODEOWNERS",
              ".pre-commit-config.yaml", ".mcp.json", "Dockerfile",
              ".github/copilot-instructions.md", ".github/dependabot.yml",
              "docs/HISTORY.md", "docs/README.md", "docs/ARCHITECTURE.md", "docs/INTENT.md"}


def _norm(rel):
    return rel.replace("\\", "/")


def _is_substrate_owned(rel: str) -> bool:
    rel = _norm(rel)
    return rel in _OWNED_FILES or rel in _KIT_TEST_FILES or any(rel.startswith(p) for p in _OWNED_DIRS)


def _is_governance(rel: str) -> bool:
    rel = _norm(rel)
    base = rel.rsplit("/", 1)[-1]
    return rel in _GOV_FILES or base == "CODEOWNERS" or any(rel.startswith(p) for p in _GOV_PREFIXES)


def _is_test(rel: str) -> bool:
    p = _norm(rel)
    base = p.rsplit("/", 1)[-1]
    return ("/tests/" in f"/{p}" or p.startswith("tests/") or "/test/" in f"/{p}"
            or base.startswith("test_") or base.endswith("_test.go")
            or "_test." in base or ".test." in base or ".spec." in base)


def _is_dep_manifest(rel: str) -> bool:
    base = _norm(rel).rsplit("/", 1)[-1]
    return base in _DEP_MANIFESTS or base.startswith("requirements")


def _skip(rel: str) -> bool:
    return any(part in _SKIP_PARTS for part in Path(rel).parts)


def _line_count(p: Path) -> int:
    try:
        return sum(1 for _ in p.open("rb"))
    except Exception:
        return 0


def _repo_shape(root: Path, file_lines: int, func_lines: int, include_substrate: bool) -> dict:
    proj, subs = [], []
    long_funcs = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if _skip(rel) or p.suffix not in _CODE_SUFFIXES:
            continue
        owned = _is_substrate_owned(rel)
        n = _line_count(p)
        (subs if (owned and not include_substrate) else proj).append((n, rel))
        if (owned and not include_substrate) or p.suffix != ".py":
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8", errors="replace"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    span = getattr(node, "end_lineno", node.lineno) - node.lineno + 1
                    if span > func_lines:
                        long_funcs.append({"loc": f"{rel}:{node.lineno}", "name": node.name, "lines": span})
        except Exception:
            pass
    proj.sort(reverse=True); subs.sort(reverse=True)
    long_funcs.sort(key=lambda d: d["lines"], reverse=True)
    return {
        "largest_files": [{"path": r, "lines": n} for n, r in proj[:10]],
        "files_over_threshold": [{"path": r, "lines": n} for n, r in proj if n > file_lines],
        "long_functions": long_funcs[:15],
        "substrate_owned": {"files": len(subs), "lines": sum(n for n, _ in subs),
                            "largest": [{"path": r, "lines": n} for n, r in subs[:5]]},
        "file_lines_threshold": file_lines, "func_lines_threshold": func_lines,
        "include_substrate": include_substrate,
    }


def _git(root: Path, *args):
    try:
        p = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=15)
    except Exception:
        return None
    return p.stdout if p.returncode == 0 else None


def _classify(rel: str, include_substrate: bool) -> str:
    if _is_governance(rel):
        return "governance"
    if _is_dep_manifest(rel):
        return "dependencies"
    if _is_substrate_owned(rel) and not include_substrate:
        return "substrate"
    if _is_test(rel):
        return "tests"
    if Path(rel).suffix in _CODE_SUFFIXES:
        return "project_source"
    return "other"


def _diff_shape(root: Path, diff_lines: int, include_substrate: bool) -> dict:
    if _git(root, "rev-parse", "--is-inside-work-tree") is None:
        return {"available": False, "reason": "not a git work tree"}
    has_head = _git(root, "rev-parse", "HEAD") is not None
    numstat = (_git(root, "diff", "HEAD", "--numstat") if has_head else _git(root, "diff", "--numstat")) or ""
    deltas = {}  # rel -> changed lines
    for line in numstat.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        a, d, path = parts
        deltas[path] = (int(a) if a.isdigit() else 0) + (int(d) if d.isdigit() else 0)
    for f in (_git(root, "ls-files", "--others", "--exclude-standard") or "").splitlines():
        if f:
            deltas[f] = deltas.get(f, 0) + _line_count(root / f)
    buckets = {"governance": [], "dependencies": [], "substrate": [], "tests": [], "project_source": [], "other": []}
    lines = {k: 0 for k in buckets}
    for rel, n in deltas.items():
        b = _classify(rel, include_substrate)
        buckets[b].append(rel); lines[b] += n
    project_lines = lines["project_source"] + lines["tests"] + lines["dependencies"]
    substrate_lines = lines["substrate"] + lines["governance"]
    install_dominated = substrate_lines > project_lines and substrate_lines > diff_lines
    warnings = []
    if install_dominated:
        warnings.append(f"substrate install/update detected ({substrate_lines} substrate-owned lines) — "
                        "commit/review it separately from project changes (not project sprawl)")
    if project_lines > diff_lines:
        warnings.append(f"large project diff: {project_lines} changed lines (> {diff_lines}) — "
                        "split into smaller, reviewable changes")
    if buckets["project_source"] and not buckets["tests"]:
        warnings.append(f"{len(buckets['project_source'])} project source file(s) changed but NO test changed — "
                        "add/adjust tests for the change")
    if buckets["tests"] and not buckets["project_source"] and not install_dominated:
        warnings.append("test file(s) changed but no project source — verify the test asserts a real "
                        "requirement, not just current behavior")
    # Governance churn is warned whenever it is not part of a bulk substrate install — an
    # agent editing its OWN rules/config (AGENTS.md, .substrate/config, …) with no source
    # change is exactly the case the substrate cares about, so a governance-ONLY diff must
    # surface too (v3.7.10 audit P2). Split wording by whether project code also changed.
    if buckets["governance"] and not install_dominated:
        gov = buckets["governance"]
        names = f"{', '.join(gov[:5])}{' …' if len(gov) > 5 else ''}"
        if project_lines > 0:
            warnings.append(f"agent/governance control files changed alongside project code ({names}) — "
                            "review carefully (CI/config/agent-rules churn)")
        else:
            warnings.append(f"governance-only change ({names}) — an agent/config/rules edit with no project "
                            "code; review separately (did the agent change its own operating rules?)")
    if buckets["dependencies"]:
        warnings.append(f"dependency manifest changed ({', '.join(buckets['dependencies'][:5])}) — "
                        "review new/updated deps (see dep-cooldown)")
    return {"available": True, "has_head": has_head, "install_dominated": install_dominated,
            "project_lines": project_lines, "substrate_lines": substrate_lines,
            "files_changed": len(deltas), "buckets": {k: v for k, v in buckets.items() if v},
            "diff_lines_threshold": diff_lines, "warnings": warnings}


def build(root: Path, file_lines: int, func_lines: int, diff_lines: int, include_substrate: bool) -> dict:
    repo = _repo_shape(root, file_lines, func_lines, include_substrate)
    diff = _diff_shape(root, diff_lines, include_substrate)
    recs = []
    if repo["files_over_threshold"]:
        recs.append(f"{len(repo['files_over_threshold'])} project file(s) over {file_lines} lines — "
                    "large files are hard to review/own; consider splitting.")
    if repo["long_functions"]:
        recs.append(f"{len(repo['long_functions'])} python function(s) over {func_lines} lines — "
                    "long functions hide bugs; extract helpers.")
    recs.extend(diff.get("warnings", []))
    if not recs:
        recs.append("No shape warnings — project files, functions, and the current diff are within thresholds."
                    + ("" if include_substrate else
                       f" ({repo['substrate_owned']['files']} substrate-owned files excluded; --include-substrate to dogfood the kit.)"))
    return {"repo": repo, "diff": diff, "recommendations": recs}


def _print(d: dict) -> None:
    repo = d["repo"]
    scope = "PROJECT + substrate" if repo["include_substrate"] else "PROJECT (substrate-owned excluded)"
    print(f"CODE-SHAPE REPORT — {scope}  (warn-only; deterministic; NOT a gate)")
    print("=" * 66)
    print("\nLARGEST SOURCE FILES (lines):")
    for f in repo["largest_files"] or [{"path": "(none)", "lines": 0}]:
        print(f"  {f['lines']:>6}  {f['path']}")
    if repo["files_over_threshold"]:
        print(f"\nFILES OVER {repo['file_lines_threshold']} LINES (sprawl): {len(repo['files_over_threshold'])}")
        for f in repo["files_over_threshold"][:10]:
            print(f"  {f['lines']:>6}  {f['path']}")
    if repo["long_functions"]:
        print(f"\nLONG PYTHON FUNCTIONS (> {repo['func_lines_threshold']} lines): {len(repo['long_functions'])}")
        for fn in repo["long_functions"][:10]:
            print(f"  {fn['lines']:>5}  {fn['loc']}  {fn['name']}()")
    so = repo["substrate_owned"]
    if not repo["include_substrate"] and so["files"]:
        print(f"\nSUBSTRATE-OWNED (excluded from project shape): {so['files']} files, {so['lines']} lines")
    df = d["diff"]
    if df.get("available"):
        print(f"\nDIFF: {df['files_changed']} files changed; project {df['project_lines']} lines, "
              f"substrate {df['substrate_lines']} lines"
              + (" [install-dominated]" if df["install_dominated"] else ""))
        for k, v in df["buckets"].items():
            print(f"  {k}: {len(v)}")
    else:
        print(f"\nDIFF: n/a ({df.get('reason', 'unavailable')})")
    print("\nRECOMMENDATIONS:")
    for r in d["recommendations"]:
        print("  - " + r)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--include-substrate", dest="include_substrate", action="store_true",
                    help="include substrate-owned files in the project shape (dogfood the kit)")
    ap.add_argument("--file-lines", type=int, default=400)
    ap.add_argument("--func-lines", type=int, default=80)
    ap.add_argument("--diff-lines", type=int, default=500)
    a = ap.parse_args()
    d = build(Path(a.root), a.file_lines, a.func_lines, a.diff_lines, a.include_substrate)
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        _print(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
