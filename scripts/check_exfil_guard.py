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

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None
# Detection is owned by command_policy.py. `_looks_dangerous`/`_profile` are
# re-exported (back-compat for in-process tests) but are NOT defined here —
# this file is an adapter, not the policy.
from command_policy import (  # noqa: E402
    CommandPolicyUnavailable,
    looks_dangerous_command as _looks_dangerous,
    profile as _profile,
)
from _doc_common import read_lock as _dc_read_lock  # noqa: E402
from _doc_common import safe_read_text as _dc_safe_read_text  # noqa: E402


def _root() -> Path:
    try:
        from _substrate_root import substrate_root as _sr
        return _sr()
    except Exception:
        return Path.cwd()


def _sandbox_required(root: Path) -> bool:
    """Containment is a REQUIRED minimum (so an UNCONTAINED Bash command must be
    blocked) when .substrate/required_sandbox=1 or SUBSTRATE_SANDBOX="1" in config.

    v3.8.33: the LOCK read fails CLOSED. The old single try/except returned
    False on ANY error, so a present-but-unreadable required_sandbox=1 (chmod —
    not content drift, so the freeze never sees it) silently allowed uncontained
    Bash. A lock that EXISTS but cannot be read, or holds a value outside
    {'0','1'}, now counts as REQUIRED. Config stays best-effort: it is the
    agent-writable OPT-IN surface, not the authority — an unreadable config
    simply fails to opt in."""
    # v3.8.36: canonical fail-closed reader. is_file() FOLLOWED SYMLINKS, so a
    # lock symlinked to attacker-controlled '0' lowered the containment floor,
    # and a DIRECTORY lock read as absent (Codex round-19). The canonical
    # reader refuses both: any "bad" state (symlink/dir/unreadable/undecodable/
    # out-of-domain) means containment REQUIRED.
    state, val, _reason = _dc_read_lock(root / ".substrate" / "required_sandbox", {"0", "1"}, root=root)
    if state == "bad":
        return True
    if state == "ok" and val == "1":
        return True
    try:
        cfg = root / ".substrate" / "config"
        # v3.8.43 (round-26 P2): a FIFO .substrate/config hung the guard here —
        # is_file() is True for a FIFO and read_text() then blocks forever.
        # The shared guarded reader refuses linked/non-regular/routed configs and
        # never blocks; None means "no usable config", which leaves the caller on
        # its existing fail-closed default.
        _cfg_text = _dc_safe_read_text(cfg, root, max_bytes=1 << 20)
        if _cfg_text is not None:
            for ln in _cfg_text.splitlines():
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
    # v3.8.47 (round-30 P2, surfaced when loop targets started inheriting their
    # iterable's origin): these were read raw. The two IN-REPO settings files
    # are read with containment against `root`; the user's home settings file
    # is outside any repo, so it gets the leaf guards and no containment root.
    # Split rather than passing a conditional root variable — the wrong-root
    # invariant test rightly rejects that shape, and it is the shape that
    # produced four silent regressions in v3.8.43.
    def _strict(raw):
        if raw is None:
            return False
        try:
            sb = json.loads(raw).get("sandbox", {})
        except Exception:
            return False
        return (isinstance(sb, dict) and sb.get("enabled") is True
                and sb.get("allowUnsandboxedCommands") is False)

    for p in (root / ".claude" / "settings.json",
              root / ".claude" / "settings.local.json"):
        if _strict(_safe_read_text(p, root, max_bytes=8 << 20)):
            return True
    home = Path.home() / ".claude" / "settings.json"
    if _strict(_dc_safe_read_text(home, None, max_bytes=8 << 20)):
        return True
    return False


def _hook_host() -> str:
    """Which host invoked this hook — from SUBSTRATE_HOOK_HOST, set in the generated
    Claude/Codex hook commands (and passed as "copilot" by the Copilot adapter).
    Unknown/empty => host-BOUND proofs (Claude settings) do NOT apply (fail-closed)."""
    return os.environ.get("SUBSTRATE_HOOK_HOST", "").strip().lower()


def _provably_contained(root: Path, host: str) -> bool:
    """Provable containment for THIS host — never a guess. Env-marker proofs are
    host-independent (the command is actually routed/attested-contained); Claude's
    settings.json proves containment ONLY for the Claude host — it says nothing about
    a Codex / Copilot / unknown invocation (the v3.5.5-audit P1 proof-binding gap)."""
    if os.environ.get("SUBSTRATE_SANDBOXED") == "1":
        return True   # ran through scripts/sandbox_exec.sh (any host)
    if os.environ.get("SUBSTRATE_HOST_SANDBOX") == "1":
        return True   # operator attests host containment (srt-wrapped, container, …; any host)
    if host == "claude" and _claude_strict_sandbox(root):
        return True   # Claude strict-sandbox config binds to the Claude host ONLY
    return False


def main() -> int:
    # Compute the containment requirement BEFORE parsing, so a malformed Bash
    # payload fails CLOSED under required_sandbox (a hook that can't read the
    # command can't prove containment) — v3.5.5-audit P2.
    _r = _root()
    required = _sandbox_required(_r)
    host = _hook_host()

    def _block_required(why: str) -> int:
        print(f"exfil-guard: BLOCKED — containment is required ({why}).", file=sys.stderr)
        return 2

    try:
        raw = sys.stdin.read()
        hook = json.loads(raw) if raw.strip() else {}
    except Exception:
        return _block_required("hook input was malformed") if required else 0
    # Only guard the shell tool; non-Bash tools are NOT shell execution (governed
    # by Read/Edit permission rules). None (absent) falls through to inspection.
    if hook.get("tool_name") not in (None, "Bash"):
        return 0
    tool_input = hook.get("tool_input")
    if not isinstance(tool_input, dict):
        return _block_required("the Bash payload was missing or malformed") if required else 0
    cmd = str(tool_input.get("command", ""))
    if not cmd:
        return _block_required("no command was provided") if required else 0
    # SANDBOX CONTAINMENT GATE (v3.5.5/3.5.6, HOST-AWARE). When containment is
    # REQUIRED, an interactive Bash command that is NOT provably contained FOR THIS
    # HOST must be BLOCKED. The hook cannot read the host's runtime sandbox state,
    # so we require PROOF — absent it we refuse rather than fake it. NOT escapable
    # by SUBSTRATE_ALLOW_SECRET_CMD (the exfil-tripwire override, not a containment one).
    if required and not _provably_contained(_r, host):
        hint = "" if host in ("claude", "codex", "copilot") else " (host unknown — set SUBSTRATE_HOOK_HOST)"
        print(
            "exfil-guard: BLOCKED — containment is REQUIRED (.substrate/required_sandbox=1) "
            f"but this Bash command is not provably sandboxed{hint}.\n"
            "Satisfy it by ONE of: run via `scripts/sandbox_exec.sh` (sets SUBSTRATE_SANDBOXED=1); "
            "enable Claude strict sandbox (sandbox.enabled + allowUnsandboxedCommands=false) when "
            "the host is Claude; or set SUBSTRATE_HOST_SANDBOX=1 if the host already contains "
            "execution (`npx @anthropic-ai/sandbox-runtime claude`, a container, …).",
            file=sys.stderr,
        )
        return 2
    # Audited override for legitimate one-offs (exfil tripwire only).
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
