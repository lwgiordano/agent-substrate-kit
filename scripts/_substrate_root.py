#!/usr/bin/env python3
"""Shared repo-root resolver for hook scripts.

Hooks fire from Claude, Codex, Copilot, CI, and plain shells — and a
user may launch the agent from a subdirectory. Relying on Path.cwd()
breaks repo-relative paths in those cases. This resolves the substrate
root deterministically, in priority order:

  1. $SUBSTRATE_PROJECT_DIR   (explicit override)
  2. $CLAUDE_PROJECT_DIR      (Claude Code sets this)
  3. git rev-parse --show-toplevel
  4. nearest ancestor containing .substrate/ or AGENTS.md
  5. Path.cwd() (last resort)

Stdlib only. Never raises — falls through to cwd on any error.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


def substrate_root() -> Path:
    for env in ("SUBSTRATE_PROJECT_DIR", "CLAUDE_PROJECT_DIR"):
        v = os.environ.get(env)
        if v:
            p = Path(v)
            if p.is_dir():
                return p.resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return Path(out.stdout.strip()).resolve()
    except Exception:
        pass
    here = Path.cwd().resolve()
    for cand in [here, *here.parents]:
        if (cand / ".substrate").is_dir() or (cand / "AGENTS.md").is_file():
            return cand
    return here


def git_output(root, *args: str, timeout: int = 15) -> str:
    """Run `git <args>` in `root`, return stripped stdout ("" on any failure).
    Shared by the session-handoff / memory-log / completion-gate hooks so the
    (previously triplicated + timeout-drifted) helper lives in one place."""
    try:
        p = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout
        )
        return p.stdout.strip() if p.returncode == 0 else ""
    except Exception:
        return ""


def git_lines(root, *args: str, timeout: int = 15) -> list[str]:
    """Like git_output but returns UNSTRIPPED stdout lines — `git status
    --porcelain` paths are position-encoded, so a global strip() would mangle
    the first line's leading status field."""
    try:
        p = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=timeout
        )
        return p.stdout.splitlines() if p.returncode == 0 else []
    except Exception:
        return []


if __name__ == "__main__":
    print(substrate_root())
