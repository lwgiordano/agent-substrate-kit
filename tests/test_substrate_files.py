"""Contract tests for an INSTALLED substrate repo.

These assert the shape of a repo after bootstrap. Run from the kit
source root they would all fail (no AGENTS.md/.substrate there), so
they skip unless the install marker is present. The install-matrix
tests (run by maintainers) bootstrap a temp repo and exercise these
for real.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

_INSTALLED = Path("AGENTS.md").exists() and Path(".substrate/config").exists()
pytestmark = pytest.mark.skipif(
    not _INSTALLED,
    reason="contract tests require an installed substrate repo (run after bootstrap)",
)


def test_claude_imports_agents() -> None:
    p = Path("CLAUDE.md")
    if p.exists():
        assert "@AGENTS.md" in p.read_text(encoding="utf-8")


def test_self_audit_skill_exists() -> None:
    assert Path(".agents/skills/self-audit/SKILL.md").exists()


def test_session_recovery_skill_exists() -> None:
    assert Path(".claude/skills/session-recovery/SKILL.md").exists()


def test_hook_scripts_installed() -> None:
    for s in ("session_handoff.py", "todo_state_hook.py", "lint_on_write.py", "check_exfil_guard.py"):
        assert Path("scripts", s).exists(), s


def test_settings_json_wires_lifecycle_and_guard_hooks() -> None:
    p = Path(".claude/settings.json")
    assert p.exists()
    cfg = json.loads(p.read_text(encoding="utf-8"))
    hooks = cfg.get("hooks", {})
    for event in ("PreToolUse", "PreCompact", "SessionEnd", "SessionStart", "PostToolUse"):
        assert event in hooks, f"missing {event} hook"
    flat = json.dumps(hooks)
    for script in ("session_handoff.py", "todo_state_hook.py", "lint_on_write.py", "check_exfil_guard.py"):
        assert script in flat, f"{script} not wired"
    # Hooks must use absolute paths via $CLAUDE_PROJECT_DIR (Claude hook
    # security guidance) and carry explicit timeouts.
    assert "$CLAUDE_PROJECT_DIR" in flat, "hooks should use absolute paths"
    for matchers in hooks.values():
        for m in matchers:
            for h in m.get("hooks", []):
                assert "timeout" in h, f"hook missing timeout: {h.get('command')}"


def test_substrate_config_exists() -> None:
    text = Path(".substrate/config").read_text(encoding="utf-8")
    assert "SUBSTRATE_PROFILE=" in text
    assert "SUBSTRATE_LANG=" in text


def test_skills_have_real_bodies() -> None:
    # v2 shipped 15-line stubs; v3 skills must carry actual workflow content.
    for skill_dir in Path(".claude/skills").iterdir():
        md = skill_dir / "SKILL.md"
        if md.exists():
            assert len(md.read_text(encoding="utf-8").splitlines()) >= 25, (
                f"{md} looks like a stub"
            )
