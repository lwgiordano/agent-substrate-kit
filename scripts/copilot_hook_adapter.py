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
_GUARD_IMPORT_FAILED = False
_GUARD_IMPORT_ERROR = ""
try:
    from check_exfil_guard import (  # type: ignore
        _looks_dangerous,
        _profile,
        _provably_contained,
        _root,
        _sandbox_required,
    )
except Exception as _e:  # pragma: no cover - guard import must never crash the hook
    # FAIL CLOSED (v3.7.6 audit P2): if the policy/containment guard can't import, we
    # cannot evaluate exfil danger OR containment — so main() DENIES shell tools rather
    # than allowing them. These stubs exist only so the hook process doesn't crash.
    _GUARD_IMPORT_FAILED = True
    _GUARD_IMPORT_ERROR = str(_e)[:160]

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


def _decide(decision: str, reason: str = "") -> int:
    out = {"permissionDecision": decision}
    if reason:
        out["permissionDecisionReason"] = reason
    print(json.dumps(out))
    return 0


def main() -> int:
    # Compute the containment requirement BEFORE parsing, so a malformed/missing
    # shell payload fails CLOSED (deny) under required_sandbox=1 — a payload we
    # can't read can't prove containment (v3.5.6-audit P2). Host is "copilot":
    # a .claude settings.json does NOT prove Copilot containment.
    try:
        root = _root()
        required = _sandbox_required(root)
    except Exception:
        root, required = None, False

    def _deny_if_required(reason: str) -> int:
        # FAIL CLOSED (v3.7.7 audit P2): if the policy/containment guard couldn't import,
        # `required` came from a fallback stub that returns False — so the malformed /
        # non-object / no-command paths would ALLOW under a double fault (broken guard +
        # bad input). When the guard is unavailable we cannot evaluate containment at all,
        # so deny here too. (Non-shell tools already returned `allow` before this point.)
        if _GUARD_IMPORT_FAILED:
            return _decide("deny", f"substrate: policy/containment guard unavailable "
                           f"({_GUARD_IMPORT_ERROR}) — denying fail-closed; {reason}")
        return _decide("deny", reason) if required else _decide("allow")

    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except Exception:
        return _deny_if_required("substrate: containment REQUIRED but Copilot hook input was malformed")
    if not isinstance(data, dict):
        return _deny_if_required("substrate: containment REQUIRED but Copilot hook input was not an object")
    # Non-shell tools (edit/view) are not this guard's concern. Absent name => inspect.
    tname = _tool_name(data)
    if tname and tname not in _SHELL_TOOLS:
        return _decide("allow")
    # FAIL CLOSED (v3.7.6 audit P2): the policy/containment guard failed to import, so we
    # cannot judge this shell command at all — deny it rather than fail open. (Non-shell
    # tools already returned `allow` above.) A broken guard is caught by CI/trusted-base;
    # at the hook boundary, an un-judgeable shell command must not run.
    if _GUARD_IMPORT_FAILED:
        return _decide("deny", f"substrate: policy/containment guard unavailable "
                       f"({_GUARD_IMPORT_ERROR}) — denying shell command fail-closed")
    cmd = _extract_command(data)
    # A shell-shaped call with no extractable command can't prove containment.
    if not cmd:
        return _deny_if_required("substrate: containment REQUIRED but Copilot Bash payload was missing or malformed")
    # CONTAINMENT GATE (host-bound to "copilot"): only routing (SUBSTRATE_SANDBOXED=1)
    # or operator attestation (SUBSTRATE_HOST_SANDBOX=1) count — never a .claude file.
    try:
        if required and root is not None and not _provably_contained(root, "copilot"):
            return _decide("deny", "substrate: containment REQUIRED (.substrate/required_sandbox=1) "
                           "but this Bash command is not provably sandboxed for Copilot — route via "
                           "scripts/sandbox_exec.sh (SUBSTRATE_SANDBOXED=1) or set SUBSTRATE_HOST_SANDBOX=1.")
    except Exception:
        pass  # never crash the hook on the gate; the tripwire below still applies
    # FAIL CLOSED: an invalid/unreadable profile must DENY, not downgrade.
    try:
        reason = _looks_dangerous(cmd, _profile())
    except CommandPolicyUnavailable as e:
        return _decide("deny", f"substrate command policy unavailable: {e}")
    return _decide("deny", f"substrate exfil-guard: {reason}") if reason else _decide("allow")


if __name__ == "__main__":
    sys.exit(main())
