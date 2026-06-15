#!/usr/bin/env python3
"""Round-8 lesson 13 tooling gate — pre-commit fence against the
"validator field added without a corresponding adversarial-input
test" pattern. Round-10 lesson 14 adds AST-based shape detection
on top of the original substring heuristic.

The cumulative meta-postmortem records 9 rounds of the same shape:
I add a contract check on field X but don't enumerate the FULL
contract for the surrounding fields. Rules 11/12/13 in the
postmortem describe pre-commit thinking I'm supposed to do but
don't consistently invoke. This script makes the discipline a
mechanical gate.

How it works (two layers):

  Layer 1 — substring check (round-8 baseline):

    1. Find every validator script under `scripts/check_*.py` that
       imports yaml AND reads dict-shaped external input.
    2. Extract the set of YAML field names referenced via
       `<dict>.get("FIELD")` or `<dict>["FIELD"]` patterns.
    3. Locate the paired test file:
          scripts/check_<X>.py → tests/test_validator_<X>.py
       If absent, fire.
    4. For each extracted field, verify the field NAME appears at
       least once in the paired test file (literal substring).
       Catches "new validator with no tests."

  Layer 2 — AST shape detection (round-10 escalation):

    5. Parse the paired test file's AST. Find every string-literal
       node that yaml.safe_load parses to a dict or list — these
       are YAML fixtures embedded in test setup code.
    6. For each fixture, walk recursively and find every occurrence
       of FIELD as a dict key. Classify each value's shape (string,
       integer, list, dict, null, bool, float, empty-string).
    7. Require at least 1 NON-STRING shape per field. The bug class
       this catches: validator does `<dict>.get("F")` then performs
       an operation that crashes on non-string types (set membership,
       regex match, etc.). Tests that only exercise string-typed F
       won't surface the type-bug.
    8. Operator opt-out: same `# coverage-opt-out: <reason>` comment
       skips both layers for the field.

Why two layers (defense in depth):
  - Layer 1 catches "field never tested at all".
  - Layer 2 catches "field tested but only with string values" — the
    case where a substring-mention check passes but the test never
    exercises adversarial-input shapes (list, dict, None, int) that
    a TypeError-on-non-string bug would surface. Layer-1's substring
    check is too coarse on its own; this layer-2 escalation is the
    structural defense rather than another procedural rule.

Heuristic, still not perfect. Layer-2 limitations:
  - Detects YAML fixtures inside Python string literals; doesn't
    trace fixtures built from string concatenation across multiple
    Constants if those happen to be split across nodes (most YAML
    fixtures are single multi-line strings, so this is rare).
  - Treats yaml.safe_load returning a scalar as "not a fixture";
    `field: ''` as a top-level YAML doc parses to `''` (str), not
    a dict. The dominant pattern in this codebase is multi-key
    fixtures, so this is OK.
  - Operator can still game the gate by writing a fixture that
    references the field with a non-string value but doesn't
    actually call the validator. The discipline is the operator's
    own — the gate exists to keep the discipline visible during
    pre-commit, not to fight an adversary.

Exit codes: 0 ok | 1 missing field coverage | 2 env error.

Adds to the postmortem-workflow series (commits 7511bd4, efaa121,
8f32e67) as the round-8 lesson-13 tooling fence + round-10
lesson-14 AST escalation.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# Variable names that almost always hold a YAML-loaded dict in this
# codebase. Conservative — we'd rather miss a few obscure cases than
# false-positive on every dict access.
_YAML_DICT_NAMES: tuple[str, ...] = (
    "entry", "item", "cfg", "spec", "config", "doc", "fm",
    "facet", "chart", "metric", "rule", "src",
)

# Match `<name>.get("FIELD")`, `<name>.get('FIELD')`, `<name>["FIELD"]`,
# `<name>['FIELD']`. The named group `field` captures the key.
_FIELD_ACCESS_RE = re.compile(
    r"\b(?:" + "|".join(_YAML_DICT_NAMES) + r")\b"
    r"(?:\.get\(|\[)"
    r"['\"](?P<field>\w+)['\"]"
)

# Operator opt-out marker. Append `# coverage-opt-out: <reason>` to
# a read site to skip that field. Reason must be non-empty AND not a
# placeholder for the opt-out to count.
_OPT_OUT_RE = re.compile(r"#\s*coverage-opt-out\s*:\s*(?P<reason>\S.*)$")


# 2026-04-30 pass-12 (a prior round, sibling-parity per
# rule 13): `# coverage-opt-out: <reason>` had the same placeholder-
# acceptance gap as the [meta-fix-not-applicable]/[no-postmortem]
# sibling hooks. `<reason>` literally would have skipped the line.
# Same defense as the canonical version in
# scripts/check_finding_response.py — duplicated here because
# the three hooks run as standalone scripts without a shared module.
_PLACEHOLDER_BRACKET_RE = re.compile(r"^\s*[<\[{].*[>\]}]\s*$")
_PLACEHOLDER_MARKER_RE = re.compile(
    r"^\s*(?:TODO|FIXME|XXX|TBD|\?+|\.{3,}|N/?A)\s*$",
    re.IGNORECASE,
)
_PLACEHOLDER_PHRASES: tuple[str, ...] = (
    "your text here",
    "fill me in",
    "fill in",
    "to be determined",
)


def _looks_like_placeholder(value: str) -> bool:
    """Reject template-placeholder-shaped values. See
    scripts/check_finding_response.py::_looks_like_placeholder
    for the canonical commentary."""
    stripped = value.strip()
    if not stripped:
        return True
    if _PLACEHOLDER_BRACKET_RE.match(stripped):
        return True
    if _PLACEHOLDER_MARKER_RE.match(stripped):
        return True
    lower = stripped.lower()
    return any(phrase in lower for phrase in _PLACEHOLDER_PHRASES)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_validator_script(path: Path) -> bool:
    """Heuristic: scripts/check_*.py that imports yaml AND has at
    least one yaml-dict field access."""
    if not path.is_file() or path.suffix != ".py":
        return False
    if not path.name.startswith("check_"):
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False
    if "import yaml" not in text:
        return False
    # The script must actually READ yaml-dict shapes — text-only
    # validators (regex-based checkers, etc.) are out of scope.
    return bool(_FIELD_ACCESS_RE.search(text))


def _extract_yaml_fields(script: Path) -> dict[str, list[int]]:
    """Return {field_name: [line numbers]} for every yaml-dict
    field read in `script`, EXCLUDING lines marked with the
    `# coverage-opt-out: <reason>` comment WHEN the reason is real
    (non-empty + non-placeholder). Lines with a placeholder reason
    are NOT skipped — the operator hasn't actually opted out, just
    copied the template.

    The opt-out comment may appear EITHER inline on the read line
    OR on any of the immediately preceding comment lines (a single
    contiguous comment block above the read). This accommodates
    linter wrapping of long inline comments."""
    text = script.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=False)
    fields: dict[str, list[int]] = {}
    for i, line in enumerate(lines, start=1):
        # 1. Check inline opt-out on the read line itself.
        m_opt = _OPT_OUT_RE.search(line)
        opted_out = bool(m_opt) and not _looks_like_placeholder(m_opt.group("reason"))
        # 2. Walk preceding comment lines for a coverage-opt-out marker.
        if not opted_out:
            j = i - 2  # zero-indexed: previous line
            while j >= 0:
                prev = lines[j].lstrip()
                if not prev.startswith("#"):
                    break
                m_prev = _OPT_OUT_RE.search(lines[j])
                if m_prev and not _looks_like_placeholder(m_prev.group("reason")):
                    opted_out = True
                    break
                j -= 1
        if opted_out:
            continue
        for m in _FIELD_ACCESS_RE.finditer(line):
            fields.setdefault(m.group("field"), []).append(i)
    return fields


def _paired_test_file(script: Path, repo: Path) -> Path | None:
    """Find the paired test file for `script` using longest-prefix
    matching against `tests/test_validator_*.py`. The strict mapping
    `check_X_Y_Z.py → test_validator_X_Y_Z.py` doesn't always hold —
    several existing tests use abbreviated names
    (`check_extensibility_configs.py → test_validator_extensibility.py`,
    `check_pii_classification.py → test_validator_pii.py`). Match on
    underscore-separated prefixes and prefer the longest match.

    Returns None if no paired test file exists. The probable path
    (longest possible) is included in the error message so the
    operator knows where to create the test."""
    base = script.name[len("check_"):-len(".py")]   # "X_Y_Z"
    parts = base.split("_")
    tests_dir = repo / "tests"
    for n in range(len(parts), 0, -1):
        candidate = tests_dir / f"test_validator_{'_'.join(parts[:n])}.py"
        if candidate.is_file():
            return candidate
    return None


def _expected_test_file(script: Path, repo: Path) -> Path:
    """The longest-form expected name (used in error messages when
    no paired test exists)."""
    base = script.name[len("check_"):-len(".py")]
    return repo / "tests" / f"test_validator_{base}.py"


def _field_in_test(test_path: Path, field: str) -> bool:
    """Does the test file mention `field` as a whole word at least
    once? Conservative substring match guarded by `\\b` — catches
    YAML fixture strings, Python identifiers, and parametrize IDs
    without false-positive on prefixes (e.g. "audit" vs "auditing")."""
    if not test_path.is_file():
        return False
    text = test_path.read_text(encoding="utf-8")
    return bool(re.search(r"\b" + re.escape(field) + r"\b", text))


# Round-10 lesson 14: AST shape detection.

# Maximum length string literal to attempt yaml-parse. Test files
# can have huge multi-line strings (assertion messages, doctests,
# etc.) and yaml.safe_load on a 100KB non-YAML string is wasteful.
# YAML fixtures in this codebase are typically <2KB.
_AST_STRING_PARSE_MAX = 10000


def _yaml_fixtures_in_test_ast(test_path: Path) -> list[Any]:
    """Parse the test file's AST. For every string-literal node, try
    yaml.safe_load — if it parses to a dict or list, it's a YAML
    fixture and we keep it. Skip strings that don't parse, that parse
    to scalars (str/int/etc.), or that are too long to be plausibly
    YAML fixtures (avoid pathological yaml.safe_load on huge prose).
    """
    if not test_path.is_file():
        return []
    try:
        text = test_path.read_text(encoding="utf-8")
        tree = ast.parse(text)
    except (
        SyntaxError, UnicodeDecodeError, OSError,
        # rule-13 sibling-parity with
        # scripts/check_finding_response.py:_detect_python_uses.
        # Pre-Phase-2.17 the except tuple here was missing
        # RecursionError / MemoryError / TypeError. A pathologically-
        # nested test file or a 50MB synthetic fixture would crash
        # the pre-commit gate at this site (the ast.parse blew up
        # in _detect_python_uses too — fixed THAT site;
        # this site got missed). Lens-2 (sibling-cluster) dogfood
        # surfaced the gap. Same fallback as _detect_python_uses:
        # return safe-default empty list rather than propagating.
        TypeError, RecursionError, MemoryError,
    ):
        return []
    fixtures: list[Any] = []
    # wrap ast.walk too. Pre-Phase-2.17 the ast.walk
    # below had NO try/except wrapper. ast.walk recurses through
    # the tree; a parsed-but-deeply-nested AST hits the recursion
    # limit during walk and propagates RecursionError. Same
    # rule-13 sibling-parity fix as _detect_python_uses applied
    # in Phase 2.10.
    try:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Constant):
                continue
            v = node.value
            if not isinstance(v, str):
                continue
            if len(v) > _AST_STRING_PARSE_MAX:
                continue
            # Skip strings that don't look like multi-line YAML fixtures.
            # YAML fixtures in this codebase use newlines + `key: value`
            # shape; plain prose without newlines or colons isn't a
            # fixture.
            if "\n" not in v and ":" not in v:
                continue
            try:
                parsed = yaml.safe_load(v)
            except yaml.YAMLError:
                continue
            if isinstance(parsed, (dict, list)):
                fixtures.append(parsed)
    except (RecursionError, MemoryError, TypeError):
        # Fallback: bail out with no fixtures rather than crash.
        # Same rule-13 sibling-parity as _detect_python_uses Phase 2.10.
        return []
    return fixtures


def _classify_value_shape(value: Any) -> str:
    """Classify a YAML-parsed value's shape. The categorization is
    deliberately coarse — it's the input to the "non-string
    coverage" check, which only cares whether the value is a string
    or something else."""
    # Order matters: bool is a subclass of int, so check bool first.
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "empty-string" if not value.strip() else "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "null"
    return type(value).__name__


def _field_shapes_in_fixtures(fixtures: list[Any], field: str) -> set[str]:
    """Walk every YAML fixture recursively. For each occurrence of
    `field` as a dict key, classify the value's shape. Return the set
    of shapes seen across all fixtures."""
    shapes: set[str] = set()

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            if field in obj:
                shapes.add(_classify_value_shape(obj[field]))
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    for fix in fixtures:
        walk(fix)
    return shapes


# Shapes that count as "string-typed" — passing isinstance(x, str).
# A field tested only with these shapes won't surface the type-bug
# class (TypeError on non-string operations).
_STRING_SHAPES: frozenset[str] = frozenset({"string", "empty-string"})


def main(argv: list[str] | None = None) -> int:
    """Scan validator scripts for missing field-coverage.

    Pre-commit invocation passes the staged files so the gate is
    diff-aware: existing untested validators don't fire on every
    commit, only the ones the operator is currently modifying. New
    yaml-field reads added in a diff fire the gate; the ratchet
    works going forward without retrofitting all existing tests.

    Args (matches argparse help below):
      - empty argv (no files, no --all): exits 0 silently. This is
        the pre-commit no-op behavior — when no validator script is
        in the staged set, there's nothing for the gate to check.
        (Note: this is INTENTIONAL; do NOT change to scan-all-on-
        empty without also updating the .pre-commit-config.yaml
        files: filter that scopes which staged files invoke the
        hook.)
      - argv with file paths: scans only those (filtered to validator
        scripts; non-validator paths are silently passed over).
      - --all: scans every scripts/check_*.py regardless of argv.
        Use this for CI sweeps and audit reviews.
    """
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "files", nargs="*",
        help=(
            "Paths to consider. When empty AND --all is not given, "
            "exits 0 silently (pre-commit no-op semantics). When "
            "non-empty, scans only the validator scripts in the list. "
            "Pre-commit passes staged files here."
        ),
    )
    parser.add_argument(
        "--all", action="store_true",
        help=(
            "Scan every scripts/check_*.py validator regardless of "
            "argv. Use for manual full-repo sweeps; pre-commit does "
            "NOT pass this flag."
        ),
    )
    args = parser.parse_args(argv)

    repo = _repo_root()
    scripts_dir = repo / "scripts"
    if not scripts_dir.is_dir():
        print(
            f"check-validator-input-coverage: scripts/ not found at {scripts_dir}",
            file=sys.stderr,
        )
        return 2

    if args.all:
        targets = sorted(scripts_dir.glob("check_*.py"))
    elif not args.files:
        # No files passed and no --all flag: silent no-op. Mirrors
        # pre-commit semantics (the hook fires only when a matching
        # file is staged); also covers manual invocations that
        # accidentally omit args.
        return 0
    else:
        # Filter argv to the validator scripts. Other staged files
        # (test files, configs, etc.) are passed through untouched —
        # the gate's contract is "validate the validators."
        targets = []
        for f in args.files:
            p = Path(f)
            if not p.is_absolute():
                p = repo / f
            if (
                p.is_file()
                and p.suffix == ".py"
                and p.parent == scripts_dir
                and p.name.startswith("check_")
            ):
                targets.append(p)
        if not targets:
            # Nothing relevant in the staged set — silent pass. The
            # gate is scoped to validator-script changes; non-script
            # commits don't need to invoke it.
            return 0

    findings: list[str] = []
    n_validators = 0
    n_fields_total = 0

    for script in targets:
        if not _is_validator_script(script):
            continue
        n_validators += 1
        fields = _extract_yaml_fields(script)
        if not fields:
            continue
        n_fields_total += len(fields)
        test_file = _paired_test_file(script, repo)
        rel_script = script.relative_to(repo).as_posix()

        if test_file is None:
            expected = _expected_test_file(script, repo).relative_to(repo).as_posix()
            findings.append(
                f"{rel_script}: reads YAML fields {sorted(fields)} but no "
                f"paired test file (expected {expected} or a shorter prefix "
                f"like tests/test_validator_<first-word>.py). Either create "
                f"the test file with at least one negative-input test per "
                f"field, or annotate each read site with `# coverage-opt-out: <reason>`."
            )
            continue

        rel_test = test_file.relative_to(repo).as_posix()
        # Round-10 lesson 14: parse fixtures once per test file.
        # Each fixture is a YAML structure; we walk all of them to
        # find every shape the test exercises for each field.
        fixtures = _yaml_fixtures_in_test_ast(test_file)

        for field, line_numbers in sorted(fields.items()):
            if not _field_in_test(test_file, field):
                # Layer 1 (substring) miss — field never named in test
                # file at all. The validator has external input but
                # zero coverage.
                line_summary = ",".join(str(ln) for ln in line_numbers[:3])
                if len(line_numbers) > 3:
                    line_summary += "…"
                findings.append(
                    f"{rel_script}: YAML field {field!r} (read at line {line_summary}) "
                    f"is never named in {rel_test}. "
                    "Add an adversarial-input test for this field "
                    "(e.g. wrong-type / empty-string / missing) OR "
                    f"annotate the read site with `# coverage-opt-out: <reason>`."
                )
                continue

            # Layer 2 (AST shape detection — a prior round): the
            # field IS named in the test file, but is it tested with
            # non-string values? Check the YAML fixtures for the
            # field's value-shapes.
            shapes = _field_shapes_in_fixtures(fixtures, field)
            non_string_shapes = shapes - _STRING_SHAPES
            if not shapes:
                # Field appears in test file (substring) but never as
                # a YAML key in any fixture. Could be a comment, a
                # bare reference, or an assertion-message mention.
                # That's not actual coverage — fire.
                findings.append(
                    f"{rel_script}: YAML field {field!r} appears as a "
                    f"substring in {rel_test} but never as a YAML key "
                    "in any fixture (only mentioned in comments / "
                    "assertions / docstrings). Add a real YAML fixture "
                    "that sets the field, or annotate the read site "
                    "with `# coverage-opt-out: <reason>`."
                )
                continue
            if not non_string_shapes:
                findings.append(
                    f"{rel_script}: YAML field {field!r} is tested in "
                    f"{rel_test} but ONLY with string-typed values "
                    f"(shapes seen: {sorted(shapes)}). Add at least "
                    "one adversarial-input test where the field is set "
                    "to a non-string value (list / integer / null / "
                    "bool / float) — this guards against the rule-12/13 "
                    "class of bugs (TypeError on wrong-type operations). "
                    "Or annotate the read site with `# coverage-opt-out: "
                    "<reason>` if the field is genuinely unable to "
                    "crash on wrong types."
                )

    if findings:
        print(
            "check-validator-input-coverage: VALIDATOR-INPUT COVERAGE GAPS",
            file=sys.stderr,
        )
        print("=" * 72, file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        print(
            f"\n{len(findings)} gap(s) across {n_validators} validator script(s).",
            file=sys.stderr,
        )
        print(
            "\nWhy this gate exists: validator scripts that read YAML "
            "fields without paired tests have a recurring failure mode "
            "— the field's contract is tightened for one shape but not "
            "another (e.g., string handled, list crashes). The paired "
            "test forces the operator to enumerate the contract before "
            "the validator ships. Opt out per read-site with "
            "`# coverage-opt-out: <reason>` for fields with existence-"
            "only checks or genuinely no-test cases.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-validator-input-coverage: ok ({n_validators} validators, "
        f"{n_fields_total} YAML fields, all named in paired test files "
        "or explicitly opted out)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())   # pragma: no cover
