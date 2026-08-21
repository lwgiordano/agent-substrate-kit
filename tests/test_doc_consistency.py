"""Doc-consistency guard for the KIT SOURCE tree.

Stale docs become bad agent context. This test runs against the kit
source (where this test file lives) and fails on the drift classes an
external audit caught: old product names, dead manage.sh commands,
and version-string mismatches. It locates the kit root by walking up
to the dir containing bootstrap.sh, so it works from source root and
is skipped (no bootstrap.sh) inside an installed repo.
"""
from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest


def _kit_root() -> Path | None:
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "bootstrap.sh").exists() and (parent / "templates").is_dir():
            return parent
    return None


KIT = _kit_root()
pytestmark = pytest.mark.skipif(KIT is None, reason="not in kit source tree")

KNOWLEDGE_DOCS = {
    "00_substrate.md": "Entry point for current substrate contracts and functional knowledge.",
    "01_install_adoption.md": "Installation and adoption across new and existing repositories.",
    "02_upgrade_integrity.md": "Upgrade provenance, authority floors, transactions, and postconditions.",
    "03_memory_sessions.md": "Tamper-evident memory, session restore, completion, and append-only logs.",
    "04_policy_governance.md": "Command policy, hooks, sandboxing, and local or remote governance.",
    "05_evals_assurance.md": "Behavioral evals, deterministic validators, audits, and assurance limits.",
    "06_release_distribution.md": "Release packaging, signing, manifests, and artifact verification.",
    "07_agent_context_governance.md": "Agent context inventory, harness scanning, budgets, and doc drift.",
}

KNOWLEDGE_ASSERTS = {
    "bootstrap.sh::_safe_mkdir_p",
    "bootstrap.sh::wappend",
    "scripts/_doc_common.py::locked_atomic_append",
    "scripts/command_policy.py::looks_dangerous_command",
    "scripts/memory_log.py::_raw_tracked_hash",
    "scripts/memory_log.py::_write_tree_oid",
    "scripts/run_python_gate.sh::_ruff_args",
    "scripts/session_handoff.py::_rejected_block",
    "scripts/session_handoff.py::_safe_history_line",
    "scripts/substrate_upgrade.py::_apply_capability_floor",
    "scripts/substrate_upgrade.py::_exec_module_from_source",
}

ROOT_ENTRYPOINTS = {"bootstrap.sh", "manage.sh", "package_release.sh"}
KNOWLEDGE_TOKEN_BUDGET = 3000


def _front_matter(path: Path) -> dict:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_knowledge_doc_common", KIT / "scripts" / "_doc_common.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    front_matter, _ = module.parse_front_matter(path)
    return front_matter


# Generated toolchain/cache state that is NOT kit source. A leftover .venv
# (e.g. from a prior `manage.sh setup` at the source root) must not be
# scanned — it contains third-party files with old Python pins, stray
# attack-looking strings, etc. that would false-fail these guards.
_SKIP_DIR_PARTS = {
    ".claude", ".agents", "__pycache__", ".substrate",
    ".git", ".venv", "venv", "dist", "build", "node_modules",
    ".pytest_cache", ".ruff_cache", ".mypy_cache",
}


def _is_generated(p: Path) -> bool:
    # Only consider parts BELOW the kit root — the kit itself may live under a
    # path like /tmp/build/... and we must not skip the whole tree on "build".
    try:
        parts = p.relative_to(KIT).parts
    except ValueError:
        parts = p.parts
    return any(d in parts for d in _SKIP_DIR_PARTS)


def _docs() -> list[Path]:
    skip = {"CHANGES_V3.md"}  # legitimately discusses v2->v3 history
    return [
        p for p in KIT.rglob("*.md")
        if p.name not in skip and not _is_generated(p)
    ]


def _scannable() -> list[Path]:
    """All agent-facing text: docs + scripts + templates. Stale strings
    in any of these become bad agent context or broken config."""
    # CHANGES_V3.md = changelog (cites old versions); BENCHMARK.md = generated result
    # report (records the host's runtime Python, which may legitimately be 3.13+).
    skip = {"CHANGES_V3.md", "test_doc_consistency.py", "BENCHMARK.md"}
    out = []
    for ext in ("*.md", "*.py", "*.sh", "*.template", "*.toml.template"):
        for p in KIT.rglob(ext):
            if p.name in skip:
                continue
            if _is_generated(p):
                continue
            out.append(p)
    return out


def test_source_knowledge_is_functionally_partitioned() -> None:
    knowledge = KIT / "docs" / "knowledge"
    docs = {
        path.name: path
        for path in knowledge.glob("*.md")
        if not path.name.startswith("_")
    }
    assert set(docs) == set(KNOWLEDGE_DOCS)

    assertion_counts: dict[str, int] = {}
    covers: set[str] = set()
    purposes: set[str] = set()
    for name, path in docs.items():
        front_matter = _front_matter(path)
        assert front_matter.get("purpose") == KNOWLEDGE_DOCS[name]
        # v3.8.33: a VALID review date on/after the split, not a pinned one —
        # last_human_reviewed exists precisely to be bumped at each review, so
        # equality with a frozen date made every legitimate review a test failure.
        reviewed = date.fromisoformat(str(front_matter.get("last_human_reviewed")))
        assert reviewed >= date(2026, 8, 9), (name, reviewed)
        purposes.add(str(front_matter.get("purpose")))
        covers.update(str(item) for item in front_matter.get("covers", []))
        for assertion in front_matter.get("asserts", []):
            key = str(assertion)
            assertion_counts[key] = assertion_counts.get(key, 0) + 1
        assert round(path.stat().st_size / 4) <= KNOWLEDGE_TOKEN_BUDGET, name

    assert len(purposes) == len(KNOWLEDGE_DOCS)
    assert set(assertion_counts) == KNOWLEDGE_ASSERTS
    assert all(count == 1 for count in assertion_counts.values())
    assert ROOT_ENTRYPOINTS <= covers

    entry = docs["00_substrate.md"].read_text(encoding="utf-8")
    for sibling in sorted(set(KNOWLEDGE_DOCS) - {"00_substrate.md"}):
        assert f"]({sibling})" in entry
    assert "](../../CHANGES_V3.md)" in entry
    assert "](../HISTORY.md)" in entry
    for name, path in docs.items():
        if name != "00_substrate.md":
            assert "](00_substrate.md)" in path.read_text(encoding="utf-8")


def test_source_knowledge_covers_every_discovered_module() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_knowledge_doc_common", KIT / "scripts" / "_doc_common.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    covered = {
        str(item)
        for path in (KIT / "docs" / "knowledge").glob("[0-9][0-9]_*.md")
        for item in _front_matter(path).get("covers", [])
    }
    discovered = {path.as_posix() for path in module.iter_code_modules(KIT)}
    assert discovered <= covered


def test_superpowers_execution_docs_are_governed_context() -> None:
    """Plans/specs drive agent execution and need scanning plus ownership."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_substrate_surfaces", KIT / "scripts" / "_substrate_surfaces.py"
    )
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    assert "docs/superpowers/**/*.md" in inventory.CONTEXT_GLOBS
    assert "docs/knowledge" in inventory.GOVERNED_DIRS
    assert "docs/knowledge" not in inventory.OWNED_DIRS
    assert "docs/superpowers" in inventory.GOVERNED_OPTIONAL_DIRS
    assert "docs/superpowers" not in inventory.OPTIONAL_DIRS
    assert {"docs/knowledge/00_substrate.md", "docs/knowledge/_template.md"} <= set(
        inventory.OWNED_FILES
    )


def test_no_old_product_names() -> None:
    offenders = []
    for p in _scannable():
        text = p.read_text(encoding="utf-8", errors="replace")
        if "META_SYSTEM_KIT" in text or "META_SYSTEM_SPEC" in text:
            offenders.append(f"{p.relative_to(KIT)}: META_SYSTEM reference")
        if re.search(r"\bKit v2\b|agent_substrate_kit_v2", text):
            offenders.append(f"{p.relative_to(KIT)}: v2 reference")
    assert not offenders, "stale product names:\n" + "\n".join(offenders)


def test_no_deprecated_codex_flag() -> None:
    # `codex_hooks` is the deprecated alias; canonical is `hooks`.
    # Allowed only when the line explicitly documents the deprecation.
    ctx = re.compile(r"(?i)deprecat|was\s+`?codex_hooks|alias")
    # \b...\b excludes identifiers like `_codex_hooks_use_...`.
    flag = re.compile(r"\bcodex_hooks\b")
    offenders = []
    for p in _scannable():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if flag.search(line) and not ctx.search(line):
                offenders.append(f"{p.relative_to(KIT)}: {line.strip()[:80]}")
    assert not offenders, "deprecated codex_hooks flag:\n" + "\n".join(offenders)


def test_no_stale_python_version() -> None:
    # The substrate targets 3.11+. A pinned 3.13 in templates is stale.
    offenders = []
    for p in _scannable():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if re.search(r"python[:/ -]?3\.13", line, re.IGNORECASE):
                offenders.append(f"{p.relative_to(KIT)}: {line.strip()[:80]}")
    assert not offenders, "stale Python 3.13 pin:\n" + "\n".join(offenders)


def test_readme_current_status_matches_version() -> None:
    """README '## Current status (vX.Y.Z)' must equal VERSION. The v3.3.5 audit
    found the README frozen at v3.3.2 (and falsely claiming 'No trace/eval
    harness') while VERSION had moved on — stale agent-facing context that no
    gate caught. This makes the staleness a deterministic failure, not a
    discipline (the substrate's own thesis applied to its own docs)."""
    readme = KIT / "README.md"
    version = (KIT / "VERSION").read_text(encoding="utf-8").strip()
    if not readme.exists():
        return
    m = re.search(r"^##\s+Current status\s+\(v([\d.]+)\)", readme.read_text(encoding="utf-8"), re.MULTILINE)
    assert m, "README has no '## Current status (vX.Y.Z)' header"
    assert m.group(1) == version, (
        f"README 'Current status (v{m.group(1)})' != VERSION ({version}) — "
        "update the README status header on every release")


def test_agent_facing_command_lists_include_evals() -> None:
    """`./manage.sh evals` must appear in EVERY fenced command block that
    documents the check+release pair — not merely somewhere in the file. The
    v3.3.9 audit found the file-level check too coarse: a secondary
    `### Build and test commands` block listed only check+release while the test
    passed because evals appeared elsewhere. Block-aware enforcement matches the
    docstring's claim (v3.3.10)."""
    for rel in ("AGENTS.md", "templates/AGENTS.md", "README.md"):
        p = KIT / rel
        if not p.exists():
            continue
        for block in re.findall(r"```(?:bash|sh)?\n(.*?)```", p.read_text(encoding="utf-8"), re.S):
            if "./manage.sh check" in block and "./manage.sh release" in block:
                assert "./manage.sh evals" in block, (
                    f"{rel} has a check+release command block without ./manage.sh evals:\n{block}")


def test_referenced_github_paths_are_generated() -> None:
    # copilot-instructions.md references .github/instructions/; bootstrap
    # must actually generate it (the v3.1 path-mismatch finding).
    bootstrap = (KIT / "bootstrap.sh").read_text(encoding="utf-8")
    copilot = (KIT / "templates" / "copilot-instructions.md").read_text(encoding="utf-8")
    if ".github/instructions" in copilot:
        assert ".github/instructions" in bootstrap, (
            "copilot-instructions.md references .github/instructions/ but bootstrap.sh never creates it"
        )
    if ".github/hooks" in copilot:
        assert ".github/hooks" in bootstrap, (
            "copilot-instructions.md references .github/hooks/ but bootstrap.sh never creates it"
        )


def test_no_references_to_removed_scripts() -> None:
    # A mention is stale only if it's NOT in a removal/changelog context.
    removed = ["snapshot_session.py"]
    removal_ctx = re.compile(r"(?i)remov|deprecat|superseded|no longer|changelog")
    offenders = []
    for p in _docs():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            for r in removed:
                if r in line and not removal_ctx.search(line):
                    offenders.append(f"{p.relative_to(KIT)}: {line.strip()[:80]}")
    assert not offenders, "live references to removed scripts:\n" + "\n".join(offenders)


def test_documented_manage_commands_exist() -> None:
    manage = (KIT / "templates" / "manage.sh.template").read_text(encoding="utf-8")
    # Commands the README/quickstart tell operators to run.
    for cmd in ("setup", "doctor", "check", "audit", "release", "handoff"):
        # case patterns may be piped, e.g. `release|release-gate)`.
        assert re.search(rf"\b{cmd}[)|]", manage), f"manage.sh missing '{cmd}' command"
    # A removed command must not be advertised as usable (changelog
    # mentions of its removal are fine).
    removal_ctx = re.compile(r"(?i)remov|deprecat|superseded|no longer")
    for p in _docs():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if "manage.sh tools" in line and not removal_ctx.search(line):
                raise AssertionError(
                    f"{p.relative_to(KIT)} advertises removed 'manage.sh tools': {line.strip()[:80]}"
                )


def test_docs_do_not_recommend_sourcing_substrate_config() -> None:
    """No agent-facing doc/script should recommend `. .substrate/config`
    or `source .substrate/config` (re-introduces the config-as-shell P0).
    Changelog history is exempt (it documents the fix)."""
    ctx = re.compile(r"(?i)remov|deprecat|no longer|do not source|don't source|history|v3\.2\.1[01]|sourced as shell|was \. \.substrate")
    offenders = []
    for p in _scannable():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if re.search(r"(?<![\w/])\.\s+\.substrate/config|source\s+\.substrate/config", line) and not ctx.search(line):
                offenders.append(f"{p.relative_to(KIT)}: {line.strip()[:80]}")
    assert not offenders, "docs recommend sourcing .substrate/config:\n" + "\n".join(offenders)


def test_pyproject_template_version_current() -> None:
    pp = (KIT / "templates" / "pyproject.toml.template").read_text(encoding="utf-8")
    assert "Kit v2" not in pp and "kit_v2" not in pp


def test_governance_consumers_derive_from_inventory() -> None:
    """CODEOWNERS coverage (doctor), harness scan, and the agent-config
    audit trigger must all reference the canonical surface inventory, so
    a new governed surface propagates to all three (no drift)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_substrate_surfaces", str(KIT / "scripts" / "_substrate_surfaces.py"))
    inv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inv)
    # The auditor-reference + architecture surfaces the reviews kept finding
    # must be in the inventory's owned set.
    owned = set(inv.OWNED_DIRS) | set(inv.OWNED_FILES)
    for surf in ("docs/blind-spot-checklists", "docs/templates", "docs/ARCHITECTURE.md",
                 "docs/INTENT.md", "manage.sh", "docs/HISTORY.md"):
        assert surf in owned, f"{surf} missing from canonical OWNED inventory"
    # The agent-config-audit workflow runs on ALL PRs (no path filter) to
    # avoid trigger-drift; the harness derives the scanned set from the
    # inventory at runtime.
    wf = (KIT / "workflows" / "agent-config-audit.yml.template").read_text(encoding="utf-8")
    assert not re.search(r"(?m)^\s+paths:", wf), "workflow should not have a drift-prone path filter"
    assert "_substrate_surfaces" in (KIT / "scripts" / "check_agent_harness.py").read_text(encoding="utf-8")
    # doctor + harness import the inventory (not their own hardcoded lists).
    doctor = (KIT / "scripts" / "substrate_doctor.py").read_text(encoding="utf-8")
    harness = (KIT / "scripts" / "check_agent_harness.py").read_text(encoding="utf-8")
    assert "_substrate_surfaces" in doctor
    assert "_substrate_surfaces" in harness


# --- v3.2.15: the kit source tree must be self-governed with CURRENT rules ---

def test_source_root_manage_matches_template() -> None:
    """The kit's own root manage.sh must carry the same validator wiring as
    templates/manage.sh.template (the v3.2.14 finding: generated repos were
    wired but the shipped source root was stale)."""
    template = (KIT / "templates" / "manage.sh.template").read_text(encoding="utf-8")
    root_manage = KIT / "manage.sh"
    required = ("scripts/check_python_syntax.py", "scripts/check_harness_patterns.py",
                "scripts/check_policy_code_integrity.py", "scripts/check_harness_smoke.py",
                "scripts/check_hook_smoke.py", "scripts/check_agent_harness.py",
                "scripts/check_substrate_config.py")
    for r in required:
        assert r in template, f"template missing {r}"
    if root_manage.exists():
        rm = root_manage.read_text(encoding="utf-8")
        for r in required:
            assert r in rm, f"source-root manage.sh stale — missing {r}"


def test_source_root_precommit_has_core_validators() -> None:
    pc = KIT / ".pre-commit-config.yaml"
    if not pc.exists():
        return
    text = pc.read_text(encoding="utf-8")
    for hook_id in ("check-python-syntax", "check-harness-patterns",
                    "check-policy-code-integrity", "check-harness-smoke",
                    "check-hook-smoke", "check-substrate-config", "check-agent-harness"):
        assert hook_id in text, f"source-root .pre-commit-config.yaml stale — missing {hook_id}"


def test_source_root_agent_config_audit_matches_template() -> None:
    """The kit's own .github/workflows/agent-config-audit.yml must run the full
    policy chain like the template (v3.2.18: it was stale, harness-only)."""
    root_wf = KIT / ".github" / "workflows" / "agent-config-audit.yml"
    if not root_wf.exists():
        return
    text = root_wf.read_text(encoding="utf-8")
    for token in ("check_python_syntax.py", "check_harness_patterns.py",
                  "check_policy_code_integrity.py", "check_harness_smoke.py",
                  "check_hook_smoke.py", "check_agent_harness.py",
                  "check_substrate_config.py"):
        assert token in text, f"source-root agent-config-audit.yml stale — missing {token}"


def test_source_root_manifest_is_current() -> None:
    """docs/manifest.json must be current in the shipped source tree, else
    source-root `manage.sh check` fails before the policy chain (v3.2.18)."""
    import subprocess, sys
    upd = KIT / "scripts" / "update_manifest.py"
    if not upd.exists():
        return
    p = subprocess.run([sys.executable, str(upd), "--check"], cwd=str(KIT),
                       capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, "manifest stale: " + (p.stdout + p.stderr)


def test_doc_consistency_skips_generated_venv(tmp_path) -> None:
    """A leftover .venv at the source root must not be scanned (it holds
    third-party files with old Python pins / stray strings)."""
    # _is_generated must treat a path under .venv/ as generated.
    fake = KIT / ".venv" / "lib" / "python3.13" / "site-packages" / "foo.py"
    assert _is_generated(fake)
    assert _is_generated(KIT / "dist" / "x.zip")
    assert not _is_generated(KIT / "scripts" / "check_exfil_guard.py")


def test_full_suite_watchdog_has_measured_runtime_margin(monkeypatch) -> None:
    """The session watchdog must not kill a healthy full suite at its measured runtime.

    The exact pre-commit path took 602.85 seconds on the slow supported host. Require
    two complete measured runs of margin while keeping a finite fail-closed deadline.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_substrate_test_conftest", KIT / "tests" / "conftest.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scheduled = {}

    monkeypatch.setattr(module.faulthandler, "enable", lambda: None)
    monkeypatch.setattr(
        module.faulthandler,
        "dump_traceback_later",
        lambda seconds, **kwargs: scheduled.update(seconds=seconds, **kwargs),
    )
    module.pytest_configure(None)

    assert scheduled["seconds"] >= 2 * 603
    assert scheduled["exit"] is True
