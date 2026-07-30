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
    "docs/HISTORY.md", "docs/REJECTED.md", "docs/README.md", "docs/ARCHITECTURE.md",
    "docs/INTENT.md",
    "docs/knowledge/**/*.md", "docs/decisions/**/*.md", "docs/postmortems/**/*.md",
    # auditor-reference material — read by checklist-auditor / ultrareview
    "docs/blind-spot-checklists/**/*.md", "docs/templates/**/*.md",
    # UI design system — AGENTS.md tells agents to read these on UI work.
    "design-system/**/*.md",
    # templates/ ships VERBATIM to consumer installs, so a poisoned template
    # reaches every downstream repo. Scan the ones that become AGENT-INSTRUCTION
    # surfaces there (what an agent reads as rules) — NOT the human-operator docs
    # (OPERATOR_ENABLEMENT/SECURITY/CONTRIBUTING), which legitimately document the
    # security flags and would false-positive, exactly as their installed twins
    # are not context-scanned either. (v3.8.4)
    "templates/AGENTS.md", "templates/CLAUDE.md", "templates/copilot-instructions.md",
    "templates/github/*.instructions.md", "templates/claude/**/*.md", "templates/codex/**/*.md",
    # v3.8.5: the REMAINING agent-read template sources bootstrap ships verbatim into
    # downstream CONTEXT surfaces — auditor-reference material (finding_response,
    # diy_ultrareview_prompts, blind-spot-checklists) and the ADR/knowledge/postmortem
    # scaffolds (installed under docs/decisions, docs/knowledge, docs/postmortems, all
    # of which ARE context-scanned). A poison planted only in one of these passed
    # check_agent_harness before, then landed as an installed context doc. Human-operator
    # docs (OPERATOR_ENABLEMENT/SECURITY/CONTRIBUTING) stay excluded — they legitimately
    # document the bypass flags and would false-positive, exactly as their installed
    # twins are not context-scanned.
    "templates/finding_response.md", "templates/diy_ultrareview_prompts.md",
    "templates/blind-spot-checklists/**/*.md",
    "templates/0000-adr-template.md", "templates/knowledge_doc_template.md",
    "templates/postmortem_template.md",
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
    # templates/ EXECUTION surfaces shipped to consumers: rendered hook/config
    # templates + the pre-commit template (their installed twins are code-scanned,
    # so scan the source too). The human-doc .template files (pyproject/pytest/
    # CODEOWNERS) are inert scaffolding and excluded. (v3.8.4)
    "templates/claude/**/*.template", "templates/codex/**/*.template",
    "templates/pre-commit-config.yaml.template", "templates/github/*.hook.json",
    "templates/manage.sh.template",
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
# .substrate/trust/* are the release/upgrade TRUST ANCHORS — owned-when-present so a PR can't
# swap a verification key/identity without CODEOWNER review (v3.7.13; sigstore_identity v3.7.20).
# They are ALSO frozen by trusted-base (the release root of trust).
OPTIONAL_FILES = [".mcp.json", ".substrate/trust/minisign.pub",
                  ".substrate/trust/sigstore_identity.json", ".substrate/install.json"]
# templates/ ships verbatim to consumers and now carries context-scanned agent
# sources (above), so it must be required-OWNED when present — closing the v3.8.5
# gap where the scanned template files had no CODEOWNER requirement despite this
# module's contract that both surface classes are required-owned. Owned-when-present
# (not unconditionally) so a consumer that strips templates/ is not falsely failed.
OPTIONAL_DIRS = [".github/skills", "docs/postmortems", "design-system", "templates"]
# NOTE: the substrate-init installer (installer/) carries a COPY of the trust key, but the
# authoritative anchor is .substrate/trust/minisign.pub (OPTIONAL_FILES, owned + frozen). The
# installer copy is guarded against drift by test_installer_vendored_pubkey_matches_kit rather
# than by owning installer/ here — owning it would wrongly demand knowledge-doc coverage of a
# separate package's modules. (v3.7.15)
# Generated runtime/toolchain state that is NOT governance source.
COVERAGE_SKIP_PARTS = {"__pycache__", "venv", "node_modules", ".pytest_cache", ".ruff_cache", ".mypy_cache"}

# --- tests/ classification ---------------------------------------------------
# tests/ is required-OWNED as a dir, but a CONSUMER repo's tests/ is MIXED (the
# kit's self-tests + the project's own tests), so tooling that must tell them
# apart (code_shape shape report, bootstrap install) keys off the kit's own test
# FILENAMES — named here as the single source of truth.
KIT_TEST_FILES = {
    "tests/conftest.py", "tests/test_doc_consistency.py", "tests/test_hook_scripts.py",
    "tests/test_smoke.py", "tests/test_substrate_files.py",
}
# Heavy behavioral self-tests STRIPPED from a consumer install (bootstrap): on
# byte-identical vendored code they re-prove what the kit's OWN CI already proves,
# adding ~2 min to every consumer CI run for ~zero marginal safety (content-pins
# already detect vendored-file tampering more cheaply). KEPT on install is the
# cheap install-integrity smoke — test_substrate_files.py (a contract test that
# only runs in an installed repo), test_smoke.py (always-green so pytest never
# exit-5s before the project adds tests), and conftest.py (the watchdog/hermetic
# fixtures those rely on). The kit's OWN tests/ dir is untouched — the full suite
# still runs here. `bootstrap.sh --dev-tests` vendors the full suite (dogfooding).
# (v3.7.11)
CONSUMER_STRIP_TESTS = {
    "test_hook_scripts.py",
    "test_doc_consistency.py",
}

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
    import sys
    if "--consumer-strip-tests" in sys.argv:
        # Emit the bootstrap strip list (one filename per line) so bootstrap.sh
        # derives it from this single source of truth instead of duplicating it.
        for _n in sorted(CONSUMER_STRIP_TESTS):
            print(_n)
    else:
        print(json.dumps(audit_trigger_paths(), indent=2))
