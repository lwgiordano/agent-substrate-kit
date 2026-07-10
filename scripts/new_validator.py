#!/usr/bin/env python3
"""Scaffold a new project validator + its adversarial test pair.

The finding-response protocol prescribes "a validator that makes the bug
class impossible" as the lock-down for any real bug. This scaffold turns
that from convention into a one-command workflow:

    ./manage.sh new-validator <name> [--files-regex REGEX] [--desc TEXT]

It generates:
  - scripts/check_<name>.py   (exit-code convention 0 ok / 1 block / 2 env
    error, `python -I` import shim, main(argv) shape)
  - tests/test_validator_<name>.py  (adversarial stub with the non-string
    fixture shapes layer 2 of check_validator_input_coverage requires the
    day the validator starts parsing YAML)

and PRINTS the pre-commit block + follow-up checklist. It never edits
.pre-commit-config.yaml itself: that file is profile-rendered and
drift-tracked (install.json hash) — an auto-edit would trip the upgrade
drift gate and fight the operator's own edits.

Exit codes: 0 scaffolded / 2 bad name, existing files, or usage error.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]+$")


def _safe_desc(desc: str | None) -> str:
    """Neutralize a free-text --desc so it can't break the generated file: it is
    interpolated into a triple-quoted docstring AND a DOUBLE-QUOTED YAML `name:`
    scalar. Collapse to one line, drop triple-quotes/backslashes (docstring +
    YAML escape chars), and fold `"` -> `'` so nothing closes the YAML quotes.
    (v3.8.4 — `--desc 'x \"\"\" y'` broke the Python docstring; v3.8.5 — `--desc
    'x: y'` / `--desc '# h'` broke or nulled the YAML name field.)"""
    if not desc:
        return ""
    d = " ".join(str(desc).split())          # single line, collapse whitespace
    d = d.replace("\\", "").replace('"""', "").replace("'''", '')
    d = d.replace('"', "'")                    # keep YAML/docstring quoting simple
    # Drop C0/C1 control chars (BEL, ESC, …): they survive .split() (not
    # whitespace) and PyYAML rejects them even inside a quoted scalar (v3.8.6).
    d = "".join(c for c in d if c >= " " and c != "\x7f" and not ("\x80" <= c <= "\x9f"))
    return d[:120]


def _safe_regex(rx: str) -> str:
    """Make a --files-regex safe to interpolate into the SINGLE-quoted YAML
    `files:` scalar (v3.8.6): drop control chars/newlines and double any single
    quote (YAML single-quote escaping) so a `'` in the regex cannot close the
    scalar or inject adjacent YAML fields. YAML unescapes `''` -> `'`, so the
    regex pre-commit actually applies is unchanged."""
    rx = "".join(c for c in str(rx) if c >= " " and c != "\x7f" and not ("\x80" <= c <= "\x9f"))
    return rx.replace("'", "''")

_VALIDATOR_TEMPLATE = '''#!/usr/bin/env python3
"""check_{name}: {desc}

Exit codes: 0 ok / 1 findings (block) / 2 environment or usage error.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Import shim: pre-commit runs `python -I scripts/check_{name}.py`, which
# skips sys.path setup — keep this before any sibling-module import.
sys.path.insert(0, str(Path(__file__).resolve().parent))

ROOT = Path.cwd()


def find_issues(root: Path) -> list[str]:
    issues: list[str] = []
    # TODO: implement the check. If it parses YAML config, follow the
    # covered pattern (strict profile meta-validates it):
    #     import yaml
    #     data = yaml.safe_load(path.read_text(encoding="utf-8"))
    #     if not isinstance(data, dict):
    #         return [f"{{path}}: top level must be a mapping"]
    #     field = data.get("field")
    #     if not isinstance(field, str):   # guard EVERY field's shape
    #         issues.append(f"{{path}}: 'field' must be a string")
    # check_validator_input_coverage then requires the paired test to
    # exercise each field with non-string shapes — the generated
    # tests/test_validator_{name}.py already carries those fixtures.
    return issues


def main(argv: list[str] | None = None) -> int:
    issues = find_issues(ROOT)
    for issue in issues:
        print(f"check_{name}: {{issue}}")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''

_TEST_TEMPLATE = '''"""Adversarial tests for scripts/check_{name}.py.

Every fixture a validator reads needs at least one NON-STRING shape
(list/int/null) per field — layer 2 of check_validator_input_coverage
enforces this once the validator parses YAML. Keep and extend these.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_{name}.py"

# Non-string shapes for each YAML field the validator will read:
ADVERSARIAL_FIXTURES = [
    "field: [1, 2]\\n",   # list where a scalar is expected
    "field: 7\\n",        # int
    "field: null\\n",     # null
]


def _run(cwd, *args):
    return subprocess.run(
        [sys.executable, "-I", str(SCRIPT), *args],
        cwd=str(cwd), capture_output=True, text=True, timeout=30,
    )


def test_clean_repo_passes(tmp_path):
    p = _run(tmp_path)
    assert p.returncode == 0, p.stdout + p.stderr


def test_todo_add_a_failing_case(tmp_path):
    # TODO: stage the bug class this validator locks down and assert
    # returncode == 1 with a pointing message. Delete this comment when done.
    p = _run(tmp_path)
    assert p.returncode in (0, 1)
'''

# The `name:` value is a DOUBLE-QUOTED YAML scalar (v3.8.5): an unquoted desc
# containing `:` produced invalid YAML ("mapping values are not allowed here")
# and a leading `#` was parsed as a comment -> null name. _safe_desc already
# strips backslashes and folds `"` -> `'`, so nothing inside the quotes can
# escape the scalar.
_PRECOMMIT_SCOPED = """      - id: check-{dashed}
        name: "{desc}"
        entry: .substrate/venv/bin/python -I scripts/check_{name}.py
        language: system
        files: '{files_regex}'
        pass_filenames: false"""

_PRECOMMIT_REPO_WIDE = """      - id: check-{dashed}
        name: "{desc}"
        entry: .substrate/venv/bin/python -I scripts/check_{name}.py
        language: system
        pass_filenames: false
        always_run: true"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("name", help="validator name, snake_case (generates check_<name>.py)")
    ap.add_argument("--files-regex", default=None,
                    help="pre-commit `files:` scope regex; omit for a repo-wide always_run gate")
    ap.add_argument("--desc", default=None, help="one-line description (pre-commit `name:`)")
    args = ap.parse_args(argv)

    name = args.name
    if not _NAME_RE.match(name):
        print(f"new-validator: invalid name {name!r} (want ^[a-z][a-z0-9_]+$)", file=sys.stderr)
        return 2
    if name.startswith("check_"):
        name = name[len("check_"):]
        if not _NAME_RE.match(name):
            print(f"new-validator: invalid name {args.name!r}", file=sys.stderr)
            return 2
    desc = _safe_desc(args.desc) or f"check_{name} validator"

    validator = ROOT / "scripts" / f"check_{name}.py"
    test = ROOT / "tests" / f"test_validator_{name}.py"
    for path in (validator, test):
        if path.exists():
            print(f"new-validator: refusing to overwrite existing {path.relative_to(ROOT)}",
                  file=sys.stderr)
            return 2

    validator.parent.mkdir(parents=True, exist_ok=True)
    test.parent.mkdir(parents=True, exist_ok=True)
    validator.write_text(_VALIDATOR_TEMPLATE.format(name=name, desc=desc), encoding="utf-8")
    validator.chmod(validator.stat().st_mode | 0o755)
    test.write_text(_TEST_TEMPLATE.format(name=name), encoding="utf-8")

    dashed = name.replace("_", "-")
    if args.files_regex:
        block = _PRECOMMIT_SCOPED.format(dashed=dashed, desc=desc, name=name,
                                         files_regex=_safe_regex(args.files_regex))
    else:
        block = _PRECOMMIT_REPO_WIDE.format(dashed=dashed, desc=desc, name=name)

    print(f"new-validator: wrote scripts/check_{name}.py")
    print(f"new-validator: wrote tests/test_validator_{name}.py")
    print()
    print("Paste this under the local repo hooks in .pre-commit-config.yaml")
    print("(NOT auto-edited: that file is profile-rendered and drift-tracked):")
    print()
    print(block)
    print()
    print("Then:")
    print(f"  1. Implement find_issues() in scripts/check_{name}.py")
    print(f"  2. Make tests/test_validator_{name}.py stage the real bug class")
    print(f"  3. uv run pytest tests/test_validator_{name}.py  (or your runner)")
    print("  4. Add the new script to your knowledge doc's covers: list and run")
    print("     python3 scripts/update_manifest.py --fix  (doc-drift gate)")
    print(f"  5. pre-commit run check-{dashed} --all-files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
