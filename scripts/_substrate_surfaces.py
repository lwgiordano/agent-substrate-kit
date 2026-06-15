#!/usr/bin/env python3
"""Canonical inventory of substrate-governed surfaces — the SINGLE source
of truth that strict CODEOWNERS coverage (substrate_doctor), harness
scanning (check_agent_harness), and the agent-config-audit workflow
trigger all derive from. Maintaining one list here prevents the drift
where a new surface is owned but not scanned, or scanned but not
triggered.

Surface classes:
  CONTEXT  — files the agent reads AS instructions/knowledge/reference.
             Scanned for secrets + shell-danger + prompt-injection.
  CODE     — files executed by the agent or CI (shell/python/CI/skill
             resources). Scanned for secrets + shell-danger (NO
             injection scan: validator source legitimately contains
             injection-pattern regexes).

Both classes are required-owned by a real CODEOWNER in strict mode.

Stdlib only (imported by hook-time + venv-time scripts).
"""
from __future__ import annotations

# --- CONTEXT surfaces: agent reads these AS instructions/knowledge ---
CONTEXT_GLOBS = [
    "AGENTS.md", "CLAUDE.md", "DESIGN.md",
    ".claude/**/*.md", ".codex/**/*.md", ".codex/**/*.toml", ".agents/**/*.md",
    ".mcp.json",
    ".github/copilot-instructions.md", ".github/instructions/**/*.md",
    ".github/skills/**/*.md",
    "docs/HISTORY.md", "docs/README.md", "docs/ARCHITECTURE.md", "docs/INTENT.md",
    "docs/knowledge/**/*.md", "docs/decisions/**/*.md", "docs/postmortems/**/*.md",
    # auditor-reference material — read by checklist-auditor / ultrareview
    "docs/blind-spot-checklists/**/*.md", "docs/templates/**/*.md",
    # UI design system — AGENTS.md tells agents to read these on UI work.
    "design-system/**/*.md",
]

# --- CODE surfaces: executed by agent or CI ---
_SKILL_RESOURCE_EXTS = ("sh", "py", "js", "ts", "json", "yml", "yaml", "toml")
_SKILL_ROOTS = (".claude/skills", ".agents/skills", ".github/skills")
CODE_GLOBS = [
    "manage.sh", "pytest.ini", ".pre-commit-config.yaml", ".gitattributes", ".gitignore",
    # .substrate/config is read by manage.sh/CI as gate commands — it is
    # an execution surface and MUST be scanned for shell-danger (it is
    # parsed as data, never sourced, but its command values still run).
    ".substrate/config",
    "scripts/**/*.py", "scripts/**/*.sh", "scripts/harness_patterns.json",
    ".github/workflows/*.yml", ".github/workflows/*.yaml",
    ".github/hooks/**/*.json", ".github/dependabot.yml",
    ".claude/**/*.json", ".codex/**/*.json",
    # UI design-system config/tokens.
    "design-system/**/*.json", "design-system/**/*.yml", "design-system/**/*.yaml", "design-system/**/*.toml",
] + [f"{root}/**/*.{ext}" for root in _SKILL_ROOTS for ext in _SKILL_RESOURCE_EXTS]

# NOT harness-scanned: the adversarial test suite legitimately contains
# fake secrets, attack strings, and injection phrases as fixtures.
# tests/ is still required-OWNED (OWNED_DIRS) — just not content-scanned.
HARNESS_SKIP_GLOBS = ["tests/**/*.py"]

# The danger/injection patterns now live in harness_patterns.json (data),
# so the scanner .py is scanned NORMALLY (no bypassable line-allowlist).
# Only the pattern DATA file is secrets-only allowlisted — weakening it is
# caught by CODEOWNERS review + the validator tests.
HARNESS_ALLOWLIST = {"scripts/harness_patterns.json"}

# --- strict CODEOWNERS coverage: required-owned files/dirs ---
# Directories owned recursively (a trailing-slash CODEOWNERS rule covers them).
OWNED_DIRS = [
    "scripts", "tests", ".claude", ".codex", ".agents",
    "docs/knowledge", "docs/decisions", "docs/blind-spot-checklists", "docs/templates",
    ".github/hooks", ".github/instructions", ".github/workflows",
]
OWNED_FILES = [
    "AGENTS.md", "CLAUDE.md", "DESIGN.md", "manage.sh", "pytest.ini", ".pre-commit-config.yaml",
    ".gitattributes", ".gitignore", ".github/copilot-instructions.md",
    ".github/dependabot.yml", ".substrate/config", ".substrate/required_profile",
    "docs/HISTORY.md", "docs/README.md", "docs/ARCHITECTURE.md", "docs/INTENT.md",
]
# Optional agent-control surfaces: required-owned ONLY when present.
OPTIONAL_FILES = [".mcp.json"]
OPTIONAL_DIRS = [".github/skills", "docs/postmortems", "design-system"]
# Generated runtime/toolchain state that is NOT governance source.
COVERAGE_SKIP_PARTS = {"__pycache__", "venv", "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache"}

# --- agent-config-audit workflow trigger paths (CI must watch the same set) ---
def audit_trigger_paths():
    paths = set()
    for g in CONTEXT_GLOBS + CODE_GLOBS:
        # collapse `dir/**/*.ext` -> `dir/**` for the workflow path filter
        if "/**/" in g:
            paths.add(g.split("/**/")[0] + "/**")
        elif g.endswith("/*.yml") or g.endswith("/*.yaml"):
            paths.add(g.rsplit("/", 1)[0] + "/**")
        else:
            paths.add(g)
    for d in OWNED_DIRS + OPTIONAL_DIRS:
        paths.add(d + "/**")
    for f in OWNED_FILES + OPTIONAL_FILES:
        paths.add(f)
    for loc in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
        paths.add(loc)
    return sorted(paths)


if __name__ == "__main__":
    import json
    print(json.dumps(audit_trigger_paths(), indent=2))
