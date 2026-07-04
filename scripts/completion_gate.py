#!/usr/bin/env python3
"""Stop-hook completion gate: nudge when work happened without a self-audit.

DEFAULT OFF (v3.8.3 soft rollout). Enable with SUBSTRATE_COMPLETION_GATE=1
in the environment or COMPLETION_GATE="1" in .substrate/config; the env var
wins in both directions (=0 is the kill-switch even when config enables).

When enabled, on Stop it checks whether PROJECT files changed this session
(HEAD moved from the .substrate/memory/session_start.json baseline, or the
tree is dirty EXCLUDING substrate bookkeeping — the gate must never trigger
on its own side effects) and whether a `skill-run` event for self-audit
exists in the hash-chained memory log TIMESTAMPED AFTER the last project
change (auditing early then editing more does not count). If work happened
un-audited it emits a systemMessage nudge with the exact remediation.

WARNING-ONLY in this release: the decision-block emission for the strict
profile exists below but is disabled by _BLOCK_MODE_ENABLED = False; it
ships (default-on for strict) only in v3.8.4 after the warn mode has been
dogfooded. See docs/OPERATOR_ENABLEMENT.md.

Fail-open by contract: garbage stdin, missing baseline, git errors, any
internal exception, and `stop_hook_active` (loop guard) all exit 0 silently.
A Stop hook must never brick a session.

Exit codes: always 0.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

SESSION_START = ROOT / ".substrate" / "memory" / "session_start.json"
EVENTS = ROOT / ".substrate" / "memory" / "events.jsonl"
_EVENTS_TAIL_LINES = 200

# Substrate bookkeeping the gate must ignore — restore()/capture()/todo-mirror
# and the memory log THIS gate consults are written as a side effect of the
# session existing, and `git status` collapses untracked dirs to ".substrate/".
# All of .substrate/ is substrate state guarded by its own gates
# (check_substrate_config, required_* locks), never project work.
_BOOKKEEPING_PREFIXES = (".substrate/",)
_BOOKKEEPING_FILES = {"docs/.todo_state.json", "docs/CURRENT_SESSION.md"}

# v3.8.4 flips this after the warn mode has been dogfooded; until then the
# strict decision-block path below is written but unreachable.
_BLOCK_MODE_ENABLED = False

_REMEDIATION = (
    "Substrate completion gate: project files changed this session with no "
    "self-audit recorded after the last change. Before finishing: run the "
    "self-audit skill, then record it with "
    "`./manage.sh memory skill-run self-audit --result pass` "
    "(or --result issues-found). Disable this nudge with "
    "SUBSTRATE_COMPLETION_GATE=0."
)


def _git(*args: str) -> str:
    try:
        p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                           text=True, timeout=10)
        return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
        return ""


def _git_lines(*args: str) -> list[str]:
    """Unstripped stdout lines. `git status --porcelain` paths are position-
    encoded (2 status chars + space); a global strip() would eat the leading
    space of the FIRST line and mangle its path."""
    try:
        p = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                           text=True, timeout=10)
        return p.stdout.splitlines() if p.returncode == 0 else []
    except Exception:
        return []


def _enabled() -> bool:
    env = os.environ.get("SUBSTRATE_COMPLETION_GATE")
    if env is not None:
        return env.strip() in ("1", "true", "yes", "warn")
    try:
        for line in (ROOT / ".substrate" / "config").read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("COMPLETION_GATE="):
                return line.split("=", 1)[1].strip().strip('"') == "1"
    except Exception:
        pass
    return False


def _project_dirty_files() -> list[str]:
    out = []
    # -uall: list untracked files individually — a collapsed "?? docs/" would
    # hide bookkeeping files (docs/.todo_state.json) behind a directory path.
    for line in _git_lines("status", "--porcelain", "-uall"):
        path = line[3:].strip().strip('"')
        if not path or path.startswith(_BOOKKEEPING_PREFIXES) or path in _BOOKKEEPING_FILES:
            continue
        # Bytecode is an interpreter side effect, not project work — running
        # any substrate script (including recording the audit!) can drop a
        # fresh .pyc that would otherwise re-arm the gate.
        if "__pycache__" in path or path.endswith((".pyc", ".pyo")):
            continue
        out.append(path)
    return out


def _parse_ts(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _last_project_change() -> datetime | None:
    """Best-effort timestamp of the latest project change: the HEAD commit
    time, or the newest mtime among dirty project files, whichever is later."""
    candidates: list[datetime] = []
    head_time = _parse_ts(_git("log", "-1", "--format=%cI"))
    if head_time is not None:
        candidates.append(head_time)
    for rel in _project_dirty_files()[:100]:
        try:
            mtime = (ROOT / rel).stat().st_mtime
            candidates.append(datetime.fromtimestamp(mtime, tz=UTC))
        except Exception:
            continue
    if not candidates:
        return None
    # Event timestamps are second-resolution (memory_log floors microseconds);
    # floor the cutoff the same way so an audit recorded in the same second as
    # the last change counts as covering it (benign ties go to the audit).
    return max(candidates).replace(microsecond=0)


def _audit_event_after(cutoff: datetime | None) -> bool:
    """True if a self-audit skill-run event exists at/after `cutoff`
    (bounded tail read — the log is append-only and can grow large)."""
    try:
        with EVENTS.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 64 * 1024))
            lines = fh.read().decode("utf-8", errors="replace").splitlines()
    except Exception:
        return False
    for line in lines[-_EVENTS_TAIL_LINES:]:
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get("type") != "skill-run":
            continue
        data = ev.get("data") or {}
        if data.get("skill") != "self-audit":
            continue
        ev_ts = _parse_ts(str(ev.get("ts", "")))
        if ev_ts is None:
            continue
        if cutoff is None or ev_ts >= cutoff:
            return True
    return False


def _work_happened() -> tuple[bool, datetime | None]:
    dirty = _project_dirty_files()
    head_moved = False
    try:
        baseline = json.loads(SESSION_START.read_text(encoding="utf-8"))
        base_head = str(baseline.get("head", ""))
        cur_head = _git("rev-parse", "--short", "HEAD")
        head_moved = bool(base_head) and bool(cur_head) and base_head != cur_head
    except Exception:
        # No baseline (pre-v3.8.0 session or fresh repo): only a dirty
        # PROJECT tree counts; guessing about commits would false-positive.
        pass
    if not dirty and not head_moved:
        return False, None
    return True, _last_project_change()


def main() -> int:
    try:
        try:
            hook = json.loads(sys.stdin.read() or "{}") if not sys.stdin.isatty() else {}
        except Exception:
            return 0
        if not isinstance(hook, dict) or hook.get("stop_hook_active"):
            return 0
        if not _enabled():
            return 0
        changed, cutoff = _work_happened()
        if not changed:
            return 0
        if _audit_event_after(cutoff):
            return 0
        if _BLOCK_MODE_ENABLED and _strict_profile():  # pragma: no cover — v3.8.4
            print(json.dumps({"decision": "block", "reason": _REMEDIATION}))
        else:
            print(json.dumps({"systemMessage": _REMEDIATION}))
        return 0
    except Exception as e:
        print(f"completion-gate: internal error (fail-open): {e}", file=sys.stderr)
        return 0


def _strict_profile() -> bool:  # pragma: no cover — used by the v3.8.4 block path
    try:
        for line in (ROOT / ".substrate" / "config").read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("SUBSTRATE_PROFILE="):
                return line.split("=", 1)[1].strip().strip('"') == "strict"
    except Exception:
        pass
    return False


if __name__ == "__main__":
    sys.exit(main())
