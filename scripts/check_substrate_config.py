#!/usr/bin/env python3
"""Validate .substrate/config as DATA and reject dangerous command values.

Two jobs:
  1. Enforce the same data grammar as the shell parser
     (_substrate_config.sh): KEY=VALUE only, fixed key allowlist, no
     command substitution / backticks. Invalid → exit 2.
  2. Apply the SHARED command policy (command_policy.looks_dangerous_command,
     the exact policy the agent Bash exfil guard uses) to the command
     fields LINT_CMD/TYPECHECK_CMD/TEST_CMD, so a config that encodes a
     local-file upload (`curl --data-binary @AGENTS.md ...`) is blocked
     BEFORE any gate executes it. Dangerous → exit 1.

Run by `manage.sh check` and `release_gate.sh` before the lang gates.

Exit codes: 0 ok | 1 dangerous value | 2 invalid config syntax.
"""
from __future__ import annotations
import re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
import json
# Detection is owned by command_policy.py. FAIL CLOSED: if it cannot import
# (broken/neutered policy module), looks_dangerous_command raises and main()
# converts that to exit 2 — never silently allow a command value.
try:
    from command_policy import CommandPolicyUnavailable, looks_dangerous_command
    _POLICY_IMPORT_ERROR = None
except Exception as _e:  # pragma: no cover - exercised via staged broken module
    _POLICY_IMPORT_ERROR = _e

    class CommandPolicyUnavailable(RuntimeError):
        pass

    def looks_dangerous_command(cmd, profile=None):
        raise CommandPolicyUnavailable(
            f"command_policy.py failed to import: {_POLICY_IMPORT_ERROR}")

_ALLOWED_KEYS = {"SUBSTRATE_PROFILE", "SUBSTRATE_LANG", "SUBSTRATE_RUNNER",
                 "LINT_CMD", "TYPECHECK_CMD", "TEST_CMD", "SUBSTRATE_CODE_SUFFIXES"}
_ENUMS = {
    "SUBSTRATE_PROFILE": {"starter", "standard", "strict"},
    "SUBSTRATE_LANG": {"python", "node", "go", "none"},
    "SUBSTRATE_RUNNER": {"auto", "uv", "python", "poetry"},
}


class HarnessPatternsUnavailable(RuntimeError):
    """harness_patterns.json could not load — callers must fail closed."""


def _shell_danger_patterns():
    """harness_patterns.json shell-danger (curl|bash, rm -rf, bypass flags) —
    complements the exfil policy (uploads), which doesn't cover pipe-to-shell.

    FAIL CLOSED: if the data file is missing/corrupt or the group is gone,
    raise instead of returning [] — otherwise a corrupted policy file would
    silently disable the pipe-to-shell check and let a curl|bash LINT_CMD
    pass validation and run in `check`/CI. (Semantic weakening of an intact
    file is caught earlier by check_harness_patterns.py.)"""
    try:
        p = Path(__file__).resolve().parent / "harness_patterns.json"
        data = json.loads(p.read_text(encoding="utf-8"))
        entries = data["shell_danger"]
        return [(label, re.compile(rx)) for label, rx in entries]
    except Exception as e:
        raise HarnessPatternsUnavailable(
            f"harness_patterns.json unavailable or invalid: {e}"
        ) from e


def _command_is_dangerous(val, profile, shell_danger):
    """Reason if a config command value is dangerous: exfil policy OR
    harness shell-danger. Both, because they cover different threats."""
    reason = looks_dangerous_command(val, profile)
    if reason:
        return reason
    for label, rx in shell_danger:
        if rx.search(val):
            return label
    return None
_COMMAND_KEYS = ("LINT_CMD", "TYPECHECK_CMD", "TEST_CMD")
_KV = re.compile(r"^([A-Za-z][A-Za-z0-9_ ]*?)\s*=(.*)$")


def _required_profile():
    """The pinned minimum profile (.substrate/required_profile), or None.
    Written by bootstrap; frozen by the trusted-base guard + CODEOWNERS."""
    p = ROOT / ".substrate" / "required_profile"
    if not p.is_file():
        return None
    try:
        val = p.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    return val if val in {"starter", "standard", "strict"} else None


def _strip_quotes_checked(raw: str, key: str):
    """Returns (value, error). Rejects unbalanced quotes."""
    v = raw.strip()
    if v[:1] in ('"', "'"):
        q = v[0]
        if len(v) < 2 or v[-1] != q:
            return "", f"unbalanced quotes in {key}"
        return v[1:-1], None
    if v[-1:] in ('"', "'"):
        return "", f"unbalanced quotes in {key}"
    return v, None


def main() -> int:
    cfg = ROOT / ".substrate" / "config"
    if not cfg.is_file():
        return 0
    vals: dict[str, str] = {}
    for raw in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw
        # drop full-line comments / blanks
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        line = line.split("  #", 1)[0].rstrip()
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if not line:
            continue
        # strict KEY=VALUE: uppercase key, no leading `export`, no space before `=`
        if not re.match(r"^[A-Z][A-Z0-9_]*=", line):
            print(f"check-substrate-config: invalid line (only KEY=VALUE allowed): {line}", file=sys.stderr)
            return 2
        key, raw_val = line.split("=", 1)
        if key not in _ALLOWED_KEYS:
            print(f"check-substrate-config: unknown key: {key}", file=sys.stderr)
            return 2
        # command substitution / backticks / ${...} forbidden (data, not code)
        if "$(" in raw_val or "`" in raw_val or "${" in raw_val:
            print(f"check-substrate-config: command substitution forbidden in {key}", file=sys.stderr)
            return 2
        val, err = _strip_quotes_checked(raw_val, key)
        if err:
            print(f"check-substrate-config: {err}", file=sys.stderr)
            return 2
        # enum values must be in their fixed domain (a typo like "stirct"
        # would otherwise silently disable strict governance).
        if key in _ENUMS and val not in _ENUMS[key]:
            print(f"check-substrate-config: invalid {key}: {val}", file=sys.stderr)
            return 2
        vals[key] = val
    profile = vals.get("SUBSTRATE_PROFILE", "standard")
    # PROFILE LOCK: a repo may RAISE its profile but never silently LOWER it.
    # `.substrate/required_profile` (written by bootstrap, CODEOWNED + frozen by
    # the trusted-base guard) pins the minimum. A PR flipping strict→standard
    # to disable strict-only hook behavior is blocked here — the gate, the
    # runtime hook profile, and CI all read this same file. (v3.2.20 finding.)
    req = _required_profile()
    if req is not None:
        order = {"starter": 0, "standard": 1, "strict": 2}
        if order.get(profile, 0) < order.get(req, 0):
            print(f"check-substrate-config: SUBSTRATE_PROFILE={profile!r} is below the "
                  f"required minimum profile {req!r} (.substrate/required_profile)", file=sys.stderr)
            return 2
    findings = []
    shell_danger = None
    for key in _COMMAND_KEYS:
        v = vals.get(key, "")
        if not v:
            continue
        try:
            if shell_danger is None:
                # load lazily so an empty-command config never depends on it,
                # but a command-valued config FAILS CLOSED on a broken policy
                shell_danger = _shell_danger_patterns()
            reason = _command_is_dangerous(v, profile, shell_danger)
        except (CommandPolicyUnavailable, HarnessPatternsUnavailable) as e:
            print(f"check-substrate-config: {e}", file=sys.stderr)
            return 2
        if reason:
            findings.append((key, reason))
    if findings:
        print("check-substrate-config: dangerous command value(s):", file=sys.stderr)
        for key, reason in findings:
            print(f"  - {key}: {reason}", file=sys.stderr)
        return 1
    print("check-substrate-config: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
