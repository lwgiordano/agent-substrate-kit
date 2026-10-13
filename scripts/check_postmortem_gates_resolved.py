#!/usr/bin/env python3
"""Postmortem-to-test cross-reference validator.

The postmortem template (`docs/postmortems/_template.md`) requires a
`gates_added` field in YAML frontmatter listing the validator entries
or tests that close each bug. This validator asserts every listed
entry resolves to something real:

  - `scripts/check_X.py <STALE_PHRASE_NAME>` → file scripts/check_X.py
    must exist (best-effort; we don't check the named entry inside
    because that would require parsing each validator's data structure).
  - `tests/test_X.py::test_Y` → the test must be discoverable via
    `pytest --collect-only`.

Why this gate exists: postmortems are append-only, but their gates
can rot. A test referenced as the regression-pin can be deleted /
renamed, leaving the postmortem claiming a defense that no longer
exists. This validator catches that.

Operator workflow: runs in pre-commit on any docs/postmortems/* edit
(see .pre-commit-config.yaml). Failure means either:
  1. The referenced test/script was renamed → update the postmortem.
  2. The test/script was DELETED → restore it (this is bad — the bug
     class is now uncovered) or document why in the postmortem.

Exit codes: 0 ok | 1 unresolved gate | 2 environment problem.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.44 (round-27, surfaced by the gate's new interprocedural pass): a
# postmortem gate is satisfied by finding a symbol in a TEST FILE, so reading
# that file through a planted link would let outside bytes vouch for a gate
# that the repo's own tests do not implement. The fallback fails closed —
# no content means the symbol is absent means the gate is unresolved.
try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None
POSTMORTEMS_DIR = REPO / "docs" / "postmortems"


_TEST_REF_RE = re.compile(r"(tests/[A-Za-z0-9_/]+\.py)(?:::([A-Za-z0-9_]+))?")
_SCRIPT_REF_RE = re.compile(r"(scripts/check_[A-Za-z0-9_]+\.py)")


def _parse_frontmatter(path: Path) -> dict:  # type: ignore[type-arg]
    """Extract YAML frontmatter (between --- markers) from a markdown file.
    Returns {} if no frontmatter."""
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    # Find the closing --- line.
    lines = text.split("\n")
    closing_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            closing_idx = i
            break
    if closing_idx is None:
        return {}
    fm_text = "\n".join(lines[1:closing_idx])
    parsed = yaml.safe_load(fm_text)
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _collect_pytest_tests() -> set[str]:
    """Return all collected test IDs (path::name shape).

    Includes phase_acceptance/ explicitly even though the default
    pytest config excludes it (norecursedirs). Postmortems often
    pin gates to phase-acceptance tests."""
    tests: set[str] = set()
    # Default suite collection. Uses `pytest` from PATH (whatever the
    # operator's dep manager activated — uv/poetry/venv all expose it).
    # If pytest isn't installed yet (fresh bootstrap before
    # `uv sync --group dev`), return empty set rather than crash —
    # the validator's downstream logic treats an empty test set as
    # "couldn't enumerate; skip test-existence check, only check
    # script-paths". The operator-facing message at end-of-main
    # explains.
    pytest_cmd = "pytest"
    for args in (
        [pytest_cmd, "--collect-only", "-q", "tests/"],
        # Phase-acceptance suite (each phase marker; we just collect
        # everything once with -m "" — match-all — and override
        # norecursedirs). Project-specific path; harmless if absent.
        [pytest_cmd, "--collect-only", "-q",
         "tests/phase_acceptance/", "--override-ini=norecursedirs="],
    ):
        try:
            result = subprocess.run(
                args, cwd=REPO, capture_output=True, text=True, check=False,
                timeout=30,
            )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            # pytest missing OR slow filesystem timeout. Either way,
            # we can't enumerate tests; skip and let downstream cope.
            continue
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or "::" not in line:
                    continue
                base = re.sub(r"\[.*?\]$", "", line)
                tests.add(base)
                if "::" in base:
                    tests.add(base.split("::")[-1])
    return tests


def _file_has_symbol(test_file: Path, symbol: str) -> bool:
    """Return True if `symbol` is defined as a function OR module-level
    constant in `test_file`. Postmortem gates can reference test-file
    constants (e.g. SIZE_BUCKETS_CLOSED_ENUM) as part of the gate
    contract — they're load-bearing data, not just helpers."""
    if not test_file.is_file():
        return False
    text = _safe_read_text(test_file, REPO, max_bytes=64 << 20) or ""
    # Function or constant assignment at module level.
    return bool(
        re.search(rf"^def\s+{re.escape(symbol)}\s*\(", text, re.MULTILINE)
        or re.search(rf"^{re.escape(symbol)}\s*[:=]", text, re.MULTILINE)
    )


def _resolve_gate(gate: str, all_tests: set[str]) -> str | None:
    """Return None if resolved, else an error message."""
    # Path-shaped script reference (scripts/check_*.py).
    script_match = _SCRIPT_REF_RE.search(gate)
    if script_match:
        script_path = REPO / script_match.group(1)
        if not script_path.is_file():
            return f"script not found: {script_match.group(1)}"
        return None

    # Path-shaped test reference (tests/test_*.py[::test_name_or_constant]).
    test_match = _TEST_REF_RE.search(gate)
    if test_match:
        test_file = REPO / test_match.group(1)
        if not test_file.is_file():
            return f"test file not found: {test_match.group(1)}"
        symbol = test_match.group(2)
        if symbol:
            in_collected = (
                symbol in all_tests or
                any(t.endswith(f"::{symbol}") for t in all_tests)
            )
            # Postmortems can reference test-file CONSTANTS (e.g.
            # frozenset enums used by tests). Fall back to source
            # symbol grep — accepts function defs or constant
            # assignments at module level.
            if not in_collected and not _file_has_symbol(test_file, symbol):
                return (
                    f"test/symbol {symbol!r} not collected by pytest "
                    f"AND not found as module-level def/constant in "
                    f"{test_match.group(1)} (renamed or removed?)"
                )
        return None

    # If it's neither — accept (free-form gate descriptions are allowed).
    return None


def main(argv: list[str] | None = None) -> int:
    if not POSTMORTEMS_DIR.is_dir():
        print(f"check-postmortem-gates: {POSTMORTEMS_DIR} not a directory.")
        return 0

    # Skip templates (filenames starting with `_`) — substrate
    # convention shared with check_doc_drift + update_manifest.
    postmortems = sorted(
        p for p in POSTMORTEMS_DIR.glob("*.md")
        if not p.name.startswith("_")
    )
    if not postmortems:
        print("check-postmortem-gates: no postmortems to check.")
        return 0

    all_tests = _collect_pytest_tests()

    findings: list[str] = []
    n_postmortems = 0
    n_gates = 0

    for pm in postmortems:
        n_postmortems += 1
        fm = _parse_frontmatter(pm)
        # coverage-opt-out: substrate validator with isinstance + missing-key
        # checks built into the shape contract below.
        gates = fm.get("gates_added") or []
        if not isinstance(gates, list):
            findings.append(
                f"  {pm.relative_to(REPO)}: `gates_added` is not a list "
                f"(got {type(gates).__name__})"
            )
            continue
        if not gates:
            findings.append(
                f"  {pm.relative_to(REPO)}: missing `gates_added` in frontmatter "
                f"(per template, every postmortem must list its preventative gate)"
            )
            continue

        for gate in gates:
            gate_str = str(gate)
            n_gates += 1
            err = _resolve_gate(gate_str, all_tests)
            if err is not None:
                findings.append(
                    f"  {pm.relative_to(REPO)}: gate {gate_str!r}: {err}"
                )

    if findings:
        print(
            "check-postmortem-gates: UNRESOLVED GATE REFERENCES\n"
            "========================================================================",
            file=sys.stderr,
        )
        for f in findings:
            print(f, file=sys.stderr)
        print(
            "\nWhy this gate exists: postmortems claim a 'preventative gate added'\n"
            "section that pins the fix. If the gate gets renamed/deleted, the\n"
            "postmortem becomes a stale claim. This validator catches that.\n\n"
            "Fix by: updating the postmortem's `gates_added` frontmatter to\n"
            "match the current test/script name, OR restore the deleted gate.\n",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-postmortem-gates: ok ({n_postmortems} postmortems, "
        f"{n_gates} gates all resolved)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
