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


def _root() -> Path:
    try:
        from _substrate_root import substrate_root as _sr
        return _sr()
    except Exception:
        return Path.cwd()


def _sandbox_required(root: Path) -> bool:
    """Containment is a REQUIRED minimum (so an UNCONTAINED Bash command must be
    blocked) when .substrate/required_sandbox=1 or SUBSTRATE_SANDBOX="1" in config."""
    rs = root / ".substrate" / "required_sandbox"
    try:
        if rs.is_file() and rs.read_text(encoding="utf-8").strip() == "1":
            return True
        cfg = root / ".substrate" / "config"
        if cfg.is_file():
            for ln in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.split("#", 1)[0].strip()
                if ln.startswith("SUBSTRATE_SANDBOX=") and ln.split("=", 1)[1].strip().strip("\"'") == "1":
                    return True
    except Exception:
        return False
    return False


def _claude_strict_sandbox(root: Path) -> bool:
    """True iff Claude's native sandbox is CONFIGURED to contain every Bash command:
    sandbox.enabled=true AND allowUnsandboxedCommands=false (strict mode). Honest
    detection of the host's enforcement CONFIG (the PreToolUse hook cannot read the
    runtime sandbox state — Claude exposes no sandbox field/env var to hooks)."""
    for p in (root / ".claude" / "settings.json",
              root / ".claude" / "settings.local.json",
              Path.home() / ".claude" / "settings.json"):
        try:
            if not p.is_file():
                continue
            sb = json.loads(p.read_text(encoding="utf-8")).get("sandbox", {})
            if isinstance(sb, dict) and sb.get("enabled") is True and sb.get("allowUnsandboxedCommands") is False:
                return True
        except Exception:
            continue
    return False


def _provably_contained(root: Path) -> bool:
    """A Bash command is provably contained ONLY via a signal we can verify — never
    a guess. Routed through sandbox_exec.sh, Claude strict-sandbox configured, or an
    explicit operator attestation of host containment."""
    if os.environ.get("SUBSTRATE_SANDBOXED") == "1":
        return True   # ran through scripts/sandbox_exec.sh
    if os.environ.get("SUBSTRATE_HOST_SANDBOX") == "1":
        return True   # operator attests host containment (srt-wrapped session, container, …)
    return _claude_strict_sandbox(root)


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
    # SANDBOX CONTAINMENT GATE (v3.5.5). When containment is REQUIRED
    # (required_sandbox=1), an interactive Bash command that is NOT provably
    # contained must be BLOCKED. The PreToolUse hook cannot read the host's runtime
    # sandbox state, so we require PROOF (routed via sandbox_exec.sh, Claude
    # strict-sandbox configured, or an operator attestation) — absent proof we
    # refuse rather than fake it. NOT escapable by SUBSTRATE_ALLOW_SECRET_CMD: that
    # is the exfil-tripwire override, not a containment override.
    _r = _root()
    if _sandbox_required(_r) and not _provably_contained(_r):
        print(
            "exfil-guard: BLOCKED — containment is REQUIRED (.substrate/required_sandbox=1) "
            "but this Bash command is not provably sandboxed.\n"
            "Satisfy it by ONE of: run the agent via `scripts/sandbox_exec.sh` "
            "(sets SUBSTRATE_SANDBOXED=1); enable Claude's strict sandbox "
            "(settings.json sandbox.enabled=true + allowUnsandboxedCommands=false); "
            "or, if the host already contains execution (`npx @anthropic-ai/sandbox-runtime "
            "claude`, a container, …), set SUBSTRATE_HOST_SANDBOX=1.",
            file=sys.stderr,
        )
        return 2
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
