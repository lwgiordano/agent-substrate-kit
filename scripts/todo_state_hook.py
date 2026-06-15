#!/usr/bin/env python3
"""PostToolUse hook on TodoWrite: persist todo state to disk.

v2 documented that docs/.todo_state.json is "regenerated each turn from
the agent's TodoWrite tool calls" but shipped nothing that does so.
This closes that gap. Wired in .claude/settings.json:

  PostToolUse (matcher: TodoWrite) -> todo_state_hook.py

Reads the hook JSON from stdin, extracts tool_input.todos, writes
docs/.todo_state.json (gitignored). session_handoff.py reads this file
when building the compaction handoff.

Stdlib only. Always exits 0 (fail-open: a broken todo mirror must not
interrupt the agent).
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
TODO_STATE = ROOT / "docs" / ".todo_state.json"

# Bound what a single TodoWrite can persist. The handoff reader caps again
# at 30, but capping at WRITE time keeps docs/.todo_state.json from growing
# unbounded (a 10k-item payload would otherwise be read whole on every
# capture before the read-side cap applies — a tool-state DoS).
_MAX_TODO_ITEMS = 100
_MAX_TODO_CONTENT_CHARS = 500
_MAX_STATUS_CHARS = 32


def main() -> int:
    try:
        raw = sys.stdin.read()
        hook = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0
    tool_input = hook.get("tool_input")
    if not isinstance(tool_input, dict):
        return 0
    todos = tool_input.get("todos")
    if not isinstance(todos, list):
        return 0
    items = []
    for t in todos[:_MAX_TODO_ITEMS]:
        if not isinstance(t, dict):
            continue
        items.append({
            "status": str(t.get("status", "pending"))[:_MAX_STATUS_CHARS],
            "content": str(t.get("content", t.get("subject", "")))[:_MAX_TODO_CONTENT_CHARS],
        })
    state = {
        "version": 1,
        "updated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "items": items,
    }
    try:
        TODO_STATE.parent.mkdir(parents=True, exist_ok=True)
        TODO_STATE.write_text(
            json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except Exception as e:
        print(f"todo-state-hook: write failed: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
