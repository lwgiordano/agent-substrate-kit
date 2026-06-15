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


if __name__ == "__main__":
    print(substrate_root())
