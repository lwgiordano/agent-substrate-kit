#!/usr/bin/env python3
"""Baseline check: bandit findings outside the documented skip list.

The pre-commit bandit hook skips B101/B608/B701 because each is a
project-pattern false positive (asserts in tests, codegen SQL from
validated YAML, Jinja for SQL not HTML — see .pre-commit-config.yaml
for the documented justification per skip).

This baseline check runs bandit WITHOUT the skips and asserts the
ONLY findings are from those 3 classes. If a new B-code shows up,
it means real code added a NEW security pattern that the skips don't
cover — review BEFORE adding to the skip list.

Phase 3.20: defends against the audit-flagged "possible blind spots"
risk in the bandit skip list. Forward-going gate, not retrospective.

Operator workflow (prefix with `uv run` / `poetry run` per your dep
manager — `bandit` itself just needs to be on PATH):
  python scripts/check_bandit_skip_baseline.py

Exit codes: 0 ok | 1 new B-code outside skip list | 2 environment problem.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# Documented bandit findings the project intentionally accepts.
# Each entry MUST have a comment explaining why it's safe in this
# context (e.g., "B608: codegen from validated YAML, not user input").
# A NEW finding-id surfacing in CI means new code introduced a pattern
# the baseline doesn't cover — review and either fix the code or add
# the id here with justification. NEVER add an id without a reason.
#
# Ships empty in the kit. Populate with project-specific skips as you
# adopt bandit-clean defaults. Common candidates:
#   - "B101": assert_used (only if tests/ is included in the scan path)
#   - "B608": hardcoded_sql_expressions (codegen pipelines)
#   - "B701": jinja2_autoescape_false (when rendering non-HTML)
_DOCUMENTED_SKIPS: set[str] = set()


def main(argv: list[str] | None = None) -> int:
    # Run bandit at HIGH severity + HIGH confidence (matching pre-commit
    # config) but WITHOUT the skip list, then compare the test_id set.
    # bandit's stdout includes a progress bar even with -f json, so we
    # write to a temp file with -o instead of parsing stdout.
    # temp file in system /tmp (was REPO/), so a SIGKILL
    # mid-run doesn't leave bandit_*.json files in the repo. tempfile
    # without dir= uses tempfile.gettempdir() which is OS-managed.
    import tempfile
    with tempfile.NamedTemporaryFile(
        suffix=".json", delete=False
    ) as tmp:
        out_path = Path(tmp.name)
    # Project-customizable scan roots. Default: every dir under repo
    # root that contains *.py and isn't a tests/ tree or excluded by
    # _doc_common.DEFAULT_EXCLUDES. Override by passing roots as args.
    if argv is None:
        argv = sys.argv[1:]
    if argv:
        scan_roots = argv
    else:
        scan_roots = [
            str(p.relative_to(REPO))
            for p in sorted(REPO.iterdir())
            if p.is_dir() and not p.name.startswith(".")
            and p.name not in {"node_modules", "dist", "build", "tests",
                               "data", "seeds", "exports", "venv", ".venv",
                               "__pycache__", "htmlcov"}
            and any(p.rglob("*.py"))
        ]
    if not scan_roots:
        print("check-bandit-skip-baseline: no Python source roots found.")
        return 0
    try:
        cmd = [
            "bandit",
            "-lll", "-iii",
            "-r",
            *scan_roots,
            "-f", "json",
            "-o", str(out_path),
        ]
        try:
            subprocess.run(
                cmd, cwd=REPO, capture_output=True, text=True, check=False,
                timeout=60,
            )
        except FileNotFoundError:
            print(
                "check-bandit-skip-baseline: `bandit` not on PATH "
                "(install via your dep manager — e.g., `uv sync --group dev`).",
                file=sys.stderr,
            )
            return 2

        try:
            report = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            print(
                f"check-bandit-skip-baseline: bandit JSON parse failed: {e}",
                file=sys.stderr,
            )
            return 2
    finally:
        out_path.unlink(missing_ok=True)

    results = report.get("results", [])
    found_ids: set[str] = set()
    by_id: dict[str, list[str]] = {}
    for finding in results:
        tid = finding.get("test_id", "<unknown>")
        found_ids.add(tid)
        path = finding.get("filename", "<unknown>")
        line = finding.get("line_number", 0)
        by_id.setdefault(tid, []).append(f"{path}:{line}")

    new_ids = found_ids - _DOCUMENTED_SKIPS
    if new_ids:
        print(
            "check-bandit-skip-baseline: NEW bandit finding class outside "
            "documented skip list",
            file=sys.stderr,
        )
        print("=" * 72, file=sys.stderr)
        for tid in sorted(new_ids):
            sites = by_id[tid][:5]
            more = (
                f" (+{len(by_id[tid]) - 5} more)"
                if len(by_id[tid]) > 5
                else ""
            )
            print(f"  {tid}: {len(by_id[tid])} site(s){more}", file=sys.stderr)
            for site in sites:
                print(f"    - {site}", file=sys.stderr)
        print(
            "\nWhy this gate exists: pre-commit's bandit hook skips B101/"
            "B608/B701 because each is a documented project-pattern false "
            "positive (.pre-commit-config.yaml:60-85). A NEW B-code outside "
            "the skip list means real code added a new security pattern. "
            "Review BEFORE adding to the skip list.\n",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-bandit-skip-baseline: ok ({len(results)} findings, all in "
        f"documented skip set {sorted(_DOCUMENTED_SKIPS)})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
