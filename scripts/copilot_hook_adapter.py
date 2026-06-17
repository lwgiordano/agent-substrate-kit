#!/usr/bin/env python3
"""Adapter: GitHub Copilot preToolUse hook -> substrate exfil guard.

Copilot's preToolUse hook approves/denies a tool call by emitting a
`permissionDecision` JSON object on stdout (not by exit code 2, which is
the Claude/Codex contract). This adapter reuses the exfil guard's
detection logic and translates the verdict into Copilot's expected
output shape.

Schema reference: https://docs.github.com/en/copilot/reference/hooks-configuration
Copilot stdin field names vary across versions, so input parsing is
defensive (checks several plausible shapes). Fail-open: on any parse
failure it allows the call (the guard is a tripwire, not a sandbox).

Usage (wired in .github/hooks/exfil-guard.json):
  python3 scripts/copilot_hook_adapter.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from command_policy import CommandPolicyUnavailable
except Exception:  # pragma: no cover
    class CommandPolicyUnavailable(RuntimeError):
        pass
try:
    from check_exfil_guard import (  # type: ignore
        _looks_dangerous,
        _profile,
        _provably_contained,
        _root,
        _sandbox_required,
    )
except Exception:  # pragma: no cover - guard import must never crash the hook
    def _looks_dangerous(_cmd: str, _profile_name: str = "standard"):
        return None

    def _profile() -> str:
        return "standard"

    def _root() -> Path:
        return Path.cwd()

    def _sandbox_required(_root) -> bool:
        return False

    def _provably_contained(_root, _host) -> bool:
        return True


_SHELL_TOOLS = {"bash", "shell", "terminal", "sh", "run", "runinterminal", "exec"}


def _tool_name(data: dict) -> str:
    for key in ("toolName", "tool_name", "tool", "name"):
        v = data.get(key)
        if isinstance(v, str):
            return v.lower()
    return ""


def _coerce_args(v):
    """toolArgs is documented as a JSON STRING; tool_input as an object."""
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{"):
            try:
                return json.loads(s)
            except Exception:
                return {"command": s}
        return {"command": s} if s else {}
    if isinstance(v, dict):
        return v
    return {}


def _extract_command(data: dict) -> str:
    """Pull the shell command out of the documented Copilot shapes.

    GitHub docs: preToolUse sends `toolName` + `toolArgs` (a JSON-encoded
    STRING). The VS Code-compatible shape uses `tool_name` + `tool_input`
    (an object). Also tolerate a few looser forms.
    """
    # Documented arg containers, in priority order.
    for key in ("toolArgs", "tool_input", "toolInput", "input", "arguments", "args"):
        if key in data:
            args = _coerce_args(data[key])
            for ck in ("command", "cmd", "script", "commandLine"):
                if isinstance(args.get(ck), str) and args[ck]:
                    return args[ck]
    # Flat command field.
    if isinstance(data.get("command"), str):
        return data["command"]
    # Nested tool object.
    for key in ("tool", "toolUse", "tool_use"):
        v = data.get(key)
        if isinstance(v, dict):
            return _extract_command(v)
    return ""


def main() -> int:
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        print(json.dumps({"permissionDecision": "allow"}))
        return 0
    if not isinstance(data, dict):
        print(json.dumps({"permissionDecision": "allow"}))
        return 0
    # Only inspect shell-like tools; a non-shell tool (edit/view) is not
    # this guard's concern. If tool name is absent, inspect anyway.
    tname = _tool_name(data)
    if tname and tname not in _SHELL_TOOLS:
        print(json.dumps({"permissionDecision": "allow"}))
        return 0
    cmd = _extract_command(data)
    # CONTAINMENT GATE (v3.5.6), HOST-BOUND to "copilot": when containment is
    # REQUIRED (required_sandbox=1), an uncontained Bash command is DENIED. A Claude
    # settings.json does NOT prove Copilot containment — only routing (SUBSTRATE_SANDBOXED=1)
    # or operator attestation (SUBSTRATE_HOST_SANDBOX=1) count for this host.
    if cmd:
        try:
            root = _root()
            if _sandbox_required(root) and not _provably_contained(root, "copilot"):
                print(json.dumps({
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "substrate: containment REQUIRED "
                    "(.substrate/required_sandbox=1) but this Bash command is not provably "
                    "sandboxed for Copilot — route via scripts/sandbox_exec.sh "
                    "(SUBSTRATE_SANDBOXED=1) or set SUBSTRATE_HOST_SANDBOX=1.",
                }))
                return 0
        except Exception:
            pass  # never crash the hook on the gate; the tripwire below still applies
    # FAIL CLOSED: an invalid/unreadable profile must DENY, not downgrade.
    try:
        reason = _looks_dangerous(cmd, _profile()) if cmd else None
    except CommandPolicyUnavailable as e:
        print(json.dumps({
            "permissionDecision": "deny",
            "permissionDecisionReason": f"substrate command policy unavailable: {e}",
        }))
        return 0
    if reason:
        print(json.dumps({
            "permissionDecision": "deny",
            "permissionDecisionReason": f"substrate exfil-guard: {reason}",
        }))
    else:
        print(json.dumps({"permissionDecision": "allow"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
