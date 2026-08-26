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
    from _substrate_root import git_lines as _git_lines_impl
    from _substrate_root import git_output as _git_output
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
    def _git_output(root, *args, timeout=10):
        try:
            p = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout)
            return p.stdout.strip() if p.returncode == 0 else ""
        except Exception:
            return ""
    def _git_lines_impl(root, *args, timeout=10):
        try:
            p = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout)
            return p.stdout.splitlines() if p.returncode == 0 else []
        except Exception:
            return []

SESSION_START = ROOT / ".substrate" / "memory" / "session_start.json"
EVENTS = ROOT / ".substrate" / "memory" / "events.jsonl"
CONFIG = ROOT / ".substrate" / "config"
_EVENTS_TAIL_LINES = 200

# v3.8.43 (round-26): import the CANONICAL guarded reader instead of keeping an
# inline mirror. v3.8.42 added one here for events.jsonl; this round needed two
# more readers guarded (session_start.json, .substrate/config), and three
# hand-copies in one file is how the mirrors drift. scripts/ is on sys.path
# above and _doc_common is pure stdlib. The fallback returns None — no evidence
# — which makes the gate NUDGE rather than go quiet, the fail-safe direction.
try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None


def _safe_cfg_text() -> str | None:
    """.substrate/config as text, or None when absent/unsafe. Trust-adjacent:
    a FIFO here hung the Stop hook and a linked one supplied outside config."""
    return _safe_read_text(CONFIG, ROOT, max_bytes=64 * 1024)


def _safe_read_json_text(path) -> str | None:
    """Guarded read of a small JSON state file (None when absent/unsafe)."""
    return _safe_read_text(path, ROOT, max_bytes=1 << 20)

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
    return _git_output(ROOT, *args, timeout=10)


def _git_lines(*args: str) -> list[str]:
    # UNSTRIPPED lines — `git status --porcelain` paths are position-encoded.
    return _git_lines_impl(ROOT, *args, timeout=10)


def _enabled() -> bool:
    env = os.environ.get("SUBSTRATE_COMPLETION_GATE")
    if env is not None:
        return env.strip() in ("1", "true", "yes", "warn")
    try:
        # v3.8.43 (round-26): .substrate/config is a trust-adjacent file; a
        # FIFO here hung the Stop hook and a linked one supplied outside config.
        for line in (_safe_cfg_text() or "").splitlines():
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


def _safe_event_lines() -> list[str] | None:
    """Tail lines of events.jsonl, or None when absent OR unsafe to read.

    v3.8.42 (round-25 P2) added the guard here as a hand-copied inline mirror.
    v3.8.43 collapses it onto the canonical `safe_read_text`: this round had to
    guard two MORE readers in this file, and three hand-copies in one module is
    exactly how mirrors drift out of sync with the original. The guarantees are
    unchanged — containment, O_NOFOLLOW|O_NONBLOCK, S_ISREG, st_nlink == 1, and
    a bounded tail — they are just no longer re-derived here."""
    raw = _safe_read_text(EVENTS, ROOT, tail_bytes=64 * 1024)
    return None if raw is None else raw.splitlines()


def _audit_event_after(cutoff: datetime | None) -> bool:
    """True if a self-audit skill-run event exists at/after `cutoff`
    (bounded tail read — the log is append-only and can grow large).

    v3.8.42 (round-25 P2): this decides whether the Stop nudge fires, so reading
    it through a link is a gate BYPASS — a hard-linked events.jsonl pointing at
    an outside file holding a recent self-audit event silenced the nudge on a
    dirty tree. The read is guarded (containment + O_NOFOLLOW|O_NONBLOCK +
    S_ISREG + st_nlink == 1); anything unsafe returns False, i.e. NO evidence of
    an audit, which nudges rather than staying silent."""
    lines = _safe_event_lines()
    if lines is None:
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
        # v3.8.43 (round-26 P2): events.jsonl was guarded in v3.8.42 but this
        # BASELINE read was not, so a hard-linked session_start.json whose head
        # matched HEAD silenced the nudge, and a FIFO hung the gate. Same guard.
        _base_raw = _safe_read_json_text(SESSION_START)
        if _base_raw is None:
            raise OSError("session_start.json unreadable or unsafe")
        baseline = json.loads(_base_raw)
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
        for line in (_safe_cfg_text() or "").splitlines():
            if line.strip().startswith("SUBSTRATE_PROFILE="):
                return line.split("=", 1)[1].strip().strip('"') == "strict"
    except Exception:
        pass
    return False


if __name__ == "__main__":
    sys.exit(main())
