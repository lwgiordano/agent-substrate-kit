#!/usr/bin/env python3
"""PreToolUse guard: block secret-read and exfiltration shell commands.

THIN ADAPTER. The detection (regexes + decision logic) lives in
command_policy.py — the single shared source of truth used by both this
hook and the .substrate/config command-value validator. This file only:
parses the host's hook JSON/stdin, extracts the command from the
Claude/Codex/Copilot payload shapes, calls command_policy, and translates
a dangerous verdict into the blocking exit 2. Keeping detection out of the
adapter means editing the adapter cannot silently change config validation
(the v3.2.15 finding).

A TRIPWIRE, NOT A SANDBOX. It catches obvious accidental and naive
exfiltration; a determined attacker can mutate command shape to evade
regex detection. For real containment, run the agent in a sandboxed
environment with no secret access.

Wired as a PreToolUse (matcher: Bash) hook for Claude (.claude/
settings.json) and Codex (.codex/hooks.json); for Copilot the
copilot_hook_adapter translates the verdict into a permissionDecision.
Exit code 2 blocks the tool call and feeds stderr back to the model.

Profile tiers (read from .substrate/config SUBSTRATE_PROFILE):
  starter   — sensitive-path reads/moves + recursive secret grep
  standard  — + env/printenv/set dumps, os.environ reads, git grep
              secrets, archive-to-public, find -exec over secret paths
  strict    — + network upload of a local file (curl -d @ / -T / upload)

Override for legitimate one-offs: set SUBSTRATE_ALLOW_SECRET_CMD to 1
(audited — the marker is grep-able).

Stdlib only. Exit codes: 0 allow | 2 block (reason on stderr).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Detection is owned by command_policy.py. `_looks_dangerous`/`_profile` are
# re-exported (back-compat for in-process tests) but are NOT defined here —
# this file is an adapter, not the policy.
from command_policy import (  # noqa: E402
    CommandPolicyUnavailable,
    looks_dangerous_command as _looks_dangerous,
    profile as _profile,
)


def main() -> int:
    try:
        raw = sys.stdin.read()
        hook = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0  # fail-open on malformed input; never wedge the agent
    # Only guard the shell tool; non-Bash tools are handled by Read-deny
    # rules and other hooks. None (absent) falls through to inspection.
    if hook.get("tool_name") not in (None, "Bash"):
        return 0
    tool_input = hook.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    cmd = str(tool_input.get("command", ""))
    if not cmd:
        return 0
    # Audited override for legitimate one-offs (checked before profile so the
    # explicit escape hatch always works).
    if os.environ.get("SUBSTRATE_ALLOW_SECRET_CMD", "") in ("1", "true", "yes"):
        return 0
    # FAIL CLOSED: an invalid/unreadable profile must BLOCK, not downgrade.
    try:
        profile = _profile()
        reason = _looks_dangerous(cmd, profile)
    except CommandPolicyUnavailable as e:
        print(f"exfil-guard: BLOCKED — command policy unavailable: {e}", file=sys.stderr)
        return 2
    if reason:
        print(
            "exfil-guard: BLOCKED — " + reason + ".\n"
            "This guard is a tripwire for obvious patterns, not a sandbox. "
            "If this is legitimate, run it yourself outside the agent, or "
            "set the SUBSTRATE_ALLOW_SECRET_CMD env var to 1 for this session (audited).",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
