#!/usr/bin/env python3
"""Per-file coverage floor enforcement.

Reads `coverage.json` (produced by `pytest --cov --cov-report=json`)
and asserts each tracked module is at or above its declared floor.
Designed for CI, not pre-commit (pytest --cov adds ~5s per run +
benchmarks; not worth the local-commit cost).

Floors are intentionally LOOSE — set 5-15 percentage points below
the current observed coverage. The goal is "catastrophic regression
detection," not "force authors to write more tests every commit."

Operator workflow (substitute `uv run` / `poetry run` / etc. as
appropriate for your dep manager):
  pytest tests/ --cov=<your_pkg> --cov-report=json
  python scripts/check_coverage_floors.py

Update `_FLOORS` only when:
  - You intentionally improved coverage and want to lock the new
    higher floor (preferred — ratchet up, not down).
  - A code refactor genuinely deletes uncovered code, raising the
    coverage % without test changes (acceptable).
  - A new module is added (explicitly add it with a floor).

Do NOT lower a floor without one of the above. If a floor fires,
the right fix is more tests, not lower expectations.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


# Per-file floors (% line coverage). tightened these from
# 5-15 points below current observed (catastrophic-regression detection
# only) to 2-4 points below (real ratchet — small regressions fire).
# Recompute via `pytest --cov ... --cov-report=json && python -c
# "import json; d=json.load(open('coverage.json'));
#  [print(p, d['files'][p]['summary']['percent_covered']) for p in d['files']]"`
# and update floors when intentionally improving coverage.
_FLOORS: dict[str, int] = {
    # Add entries as your project grows. Each entry:
    #   "path/to/module.py": <floor-percent>,
    #
    # Set floors 2-4 percentage points below current observed
    # coverage. This catches catastrophic regression without
    # flagging minor day-to-day variation.
    #
    # Recompute current coverage with:
    #   pytest tests/ --cov=path/to/module --cov-report=term-missing
    #
    # Update the floor when you intentionally improve coverage,
    # OR when a refactor genuinely deletes uncovered code.
}


def _load_coverage_json(path: Path) -> dict:  # type: ignore[type-arg]
    if not path.is_file():
        print(
            f"check-coverage-floors: {path} not found.\n"
            f"  Run: pytest --cov=<your_pkg> --cov-report=json "
            f"(prefix with `uv run` / `poetry run` per your dep manager)",
            file=sys.stderr,
        )
        sys.exit(2)
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    if not _FLOORS:
        # Empty _FLOORS is the kit's default shipping state. Nothing
        # to enforce until the operator populates entries (see
        # customization.md §"check_coverage_floors.py").
        print(
            "check-coverage-floors: _FLOORS dict is empty — nothing to "
            "enforce. Populate as you grow real test coverage on a path."
        )
        return 0
    cov_path = REPO / "coverage.json"
    data = _load_coverage_json(cov_path)
    files = data.get("files", {})
    if not files:
        print("check-coverage-floors: coverage.json has no files; nothing to check.")
        return 0

    violations: list[str] = []
    n_checked = 0

    for rel_path, floor in _FLOORS.items():
        # coverage.json keys are repo-relative POSIX paths.
        entry = files.get(rel_path)
        if entry is None:
            # Try alternative path forms (some coverage configs strip
            # leading components).
            for candidate, edata in files.items():
                if candidate.endswith(rel_path):
                    entry = edata
                    break
        if entry is None:
            violations.append(
                f"  {rel_path}: file not found in coverage.json (run `pytest "
                f"--cov` against the area first)"
            )
            continue
        n_checked += 1

        pct = entry.get("summary", {}).get("percent_covered", 0.0)
        if pct < floor:
            violations.append(
                f"  {rel_path}: {pct:.1f}% < floor {floor}% "
                f"(missing lines: {entry.get('missing_lines', [])[:8]}…)"
            )

    if violations:
        print(
            "check-coverage-floors: COVERAGE BELOW FLOOR\n"
            "========================================================================",
            file=sys.stderr,
        )
        for v in violations:
            print(v, file=sys.stderr)
        print(
            "\nWhy this gate exists: per-area coverage floors catch catastrophic\n"
            "regression (e.g., a refactor that loses 30% coverage on _input_hashes\n"
            "would silently land without it). Floors are 5-15 points below current\n"
            "observed values. Fix by adding tests, NOT by lowering the floor.\n",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-coverage-floors: ok ({n_checked} files all at or above floor)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
