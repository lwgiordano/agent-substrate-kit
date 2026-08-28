# Substrate Knowledge Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the oversized source knowledge document with a tested functional map and close the four enforcement gaps that would let the new structure drift or escape governance.

**Architecture:** Keep `00_substrate.md` as the source entry point and generate the same compact consumer-local file as today. Put source detail in seven functional siblings with many-to-many coverage, then make staged review, context budgets, and harness smoke tests enumerate the full governed set instead of relying on suffix or top-ten shortcuts.

**Tech Stack:** Python 3.11+, Bash, Markdown front matter, pytest, Git plumbing, and the existing stdlib-only substrate validators.

## Global Constraints

- Work on `claude/version-identification-7vpc1t`; the release target is v3.8.32 or the next unused patch version if the branch advances again.
- Do not edit `scripts/_doc_common.py`, `scripts/append_history.py`, or `scripts/append_rejected.py`; v3.8.31 already fixed that class.
- Preserve all eleven current `asserts: path::substring` entries exactly once across the source knowledge set.
- Keep `docs/knowledge/00_substrate.md` plus seven source-only siblings named `01_install_adoption.md` through `07_agent_context_governance.md`.
- A fresh consumer install must retain its generated compact `00_substrate.md`
  and installed `_template.md`, but none of the seven source siblings; do not add
  those siblings to bootstrap, upgrade, packaging, or the owned-file baseline.
- Use many-to-many `covers` entries. Cover `bootstrap.sh`, `manage.sh`, and `package_release.sh` wherever their behavior supports a documented contract.
- Set `last_human_reviewed: 2026-08-09` only after comparing each migrated claim with running code.
- Keep every non-template knowledge doc at or below the default 3,000-token estimate (`round(bytes / 4)`).
- Never hand-edit `docs/manifest.json`; run `python scripts/update_manifest.py --fix`.
- Run `./manage.sh evals` because the harness and policy-adjacent checks change.
- Prove the ownership migration by running the new kit's engine against a target
  holding a legacy recursive baseline; the old target engine cannot know this
  future rule, so document the one-time boundary command explicitly.
- Land this plan, its design spec, and the two split-design rejection entries as a reviewed planning commit before Task 1 changes implementation files.
- Create one coherent v3.8.32 code commit after Tasks 1 through 4 pass together. Then append HISTORY with that commit SHA, commit HISTORY, post the bus RELEASE, and push without squashing.

## File Responsibility Map

| File | Responsibility in this release |
|---|---|
| `docs/knowledge/00_substrate.md` | Compact source entry point, trust-boundary summary, chronology links, and functional index |
| `docs/knowledge/01_install_adoption.md` | Installation and adoption contracts |
| `docs/knowledge/02_upgrade_integrity.md` | Upgrade authority, provenance, and postconditions |
| `docs/knowledge/03_memory_sessions.md` | Memory, session restore, completion, and append-only logs |
| `docs/knowledge/04_policy_governance.md` | Hooks, command policy, sandbox, and local/remote governance |
| `docs/knowledge/05_evals_assurance.md` | Behavioral evals, audits, validators, and assurance limits |
| `docs/knowledge/06_release_distribution.md` | Packaging, signing, manifests, and artifact verification |
| `docs/knowledge/07_agent_context_governance.md` | Context inventory, harness scanning, budgets, and documentation drift |
| `docs/decisions/0001-substrate-knowledge-boundaries.md` | Accepted boundary decision and rejected alternatives |
| `docs/README.md` | Human index for the new source documentation shape |
| `scripts/check_doc_drift.py` | Review every staged path already named in `covers`, independent of suffix |
| `scripts/context_report.py` | Enumerate every knowledge doc for per-document budget rows |
| `scripts/check_harness_smoke.py` | Prove each context surface independently, including arbitrary knowledge and execution-plan siblings |
| `scripts/_substrate_surfaces.py` | Separate governed project context from exact install-owned knowledge files |
| `scripts/write_install_json.py` | Baseline only substrate-owned files, excluding project knowledge and plans |
| `scripts/code_shape.py` | Classify governed project context as governance churn without substrate ownership |
| `scripts/substrate_doctor.py` | Preserve governed-directory ownership checks if the canonical inventory import fails |
| `tests/test_doc_consistency.py` | Source knowledge shape, assertion, coverage, link, and size invariants |
| `tests/test_hook_scripts.py` | Behavioral regressions for consumers and the four integration fixes |
| `docs/manifest.json` | Generated knowledge and ADR index |
| `docs/REJECTED.md` | Record why governed project context cannot share directory-wide install ownership |
| `docs/postmortems/2026-08-10-knowledge-ownership-migration.md` | Record the legacy serialized-baseline migration gap and permanent transition gate |
| `VERSION`, `README.md`, `BENCHMARK.md` | Release identity and measured results |

---

### Task 1: Lock the knowledge boundary with tests, then migrate the source document

**Files:**
- Modify: `tests/test_doc_consistency.py`
- Modify: `tests/test_hook_scripts.py`
- Modify: `docs/knowledge/00_substrate.md`
- Create: `docs/knowledge/01_install_adoption.md`
- Create: `docs/knowledge/02_upgrade_integrity.md`
- Create: `docs/knowledge/03_memory_sessions.md`
- Create: `docs/knowledge/04_policy_governance.md`
- Create: `docs/knowledge/05_evals_assurance.md`
- Create: `docs/knowledge/06_release_distribution.md`
- Create: `docs/knowledge/07_agent_context_governance.md`
- Create: `docs/decisions/0001-substrate-knowledge-boundaries.md`
- Modify: `docs/README.md`
- Generate: `docs/manifest.json`

**Interfaces:**
- Consumes: `scripts._doc_common.parse_front_matter`, `scripts._doc_common.iter_code_modules`, current `bootstrap.sh` consumer generation, and the eleven current assertion strings.
- Produces: Eight source knowledge docs with valid front matter, one accepted ADR, a generated manifest, and deterministic source/consumer boundary tests.

- [ ] **Step 1: Add canonical source-shape constants and a front-matter loader**

Add these constants near the top of `tests/test_doc_consistency.py` after `pytestmark`:

```python
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
```

Load the canonical parser without normal import-cache behavior:

```python
def _front_matter(path: Path) -> dict:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_knowledge_doc_common", KIT / "scripts" / "_doc_common.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    front_matter, _ = module.parse_front_matter(path)
    return front_matter
```

- [ ] **Step 2: Add failing source knowledge invariants**

Add one test that checks names, purposes, links, assertions, coverage, and size:

```python
def test_source_knowledge_is_functionally_partitioned() -> None:
    knowledge = KIT / "docs" / "knowledge"
    docs = {
        p.name: p
        for p in knowledge.glob("*.md")
        if not p.name.startswith("_")
    }
    assert set(docs) == set(KNOWLEDGE_DOCS)

    assertion_counts: dict[str, int] = {}
    covers: set[str] = set()
    purposes: set[str] = set()
    for name, path in docs.items():
        fm = _front_matter(path)
        assert fm.get("purpose") == KNOWLEDGE_DOCS[name]
        assert fm.get("last_human_reviewed") == "2026-08-09"
        purposes.add(str(fm.get("purpose")))
        covers.update(str(item) for item in fm.get("covers", []))
        for assertion in fm.get("asserts", []):
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
```

Add a second test that proves every discovered module remains covered:

```python
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
```

- [ ] **Step 3: Add a failing consumer-boundary regression**

Add this beside `test_consumer_install_omits_heavy_selftests` in `tests/test_hook_scripts.py`:

```python
def test_consumer_install_gets_only_compact_substrate_knowledge(tmp_path) -> None:
    if not _bootstrapped(tmp_path):
        return
    knowledge = tmp_path / "docs" / "knowledge"
    installed = {
        p.name for p in knowledge.glob("*.md") if not p.name.startswith("_")
    }
    assert installed == {"00_substrate.md"}
    text = (knowledge / "00_substrate.md").read_text(encoding="utf-8")
    assert "This document covers the installed AI/self-audit substrate scripts." in text
    assert "01_install_adoption.md" not in text
```

- [ ] **Step 4: Run the new tests and confirm the intended failures**

Run:

```bash
uv run pytest \
  tests/test_doc_consistency.py::test_source_knowledge_is_functionally_partitioned \
  tests/test_doc_consistency.py::test_source_knowledge_covers_every_discovered_module \
  tests/test_hook_scripts.py::test_consumer_install_gets_only_compact_substrate_knowledge -vv
```

Expected result: the two source tests fail because only the oversized source `00_substrate.md` exists; the consumer test passes and pins the existing compact-install behavior.

- [ ] **Step 5: Rewrite the source knowledge set by responsibility**

Use the exact purposes from `KNOWLEDGE_DOCS`, `last_human_reviewed: 2026-08-09`, and this assertion allocation:

```yaml
01_install_adoption.md:
  - bootstrap.sh::_safe_mkdir_p
  - bootstrap.sh::wappend
  - scripts/run_python_gate.sh::_ruff_args
02_upgrade_integrity.md:
  - scripts/substrate_upgrade.py::_exec_module_from_source
  - scripts/substrate_upgrade.py::_apply_capability_floor
03_memory_sessions.md:
  - scripts/memory_log.py::_raw_tracked_hash
  - scripts/memory_log.py::_write_tree_oid
  - scripts/_doc_common.py::locked_atomic_append
  - scripts/session_handoff.py::_safe_history_line
  - scripts/session_handoff.py::_rejected_block
04_policy_governance.md:
  - scripts/command_policy.py::looks_dangerous_command
```

Seed `covers` with the following allocation. Duplicates across documents are intentional:

```text
01 install/adoption:
  bootstrap.sh, manage.sh, scripts/_substrate_config.sh,
  scripts/_substrate_root.py, scripts/check_substrate_config.py,
  scripts/lang_gate.sh, scripts/new_validator.py, scripts/run_python_gate.sh,
  scripts/substrate_doctor.py, scripts/substrate_profile.py,
  scripts/update_manifest.py, scripts/write_install_json.py

02 upgrade/integrity:
  bootstrap.sh, manage.sh, scripts/_minisign.py,
  scripts/_substrate_config.sh, scripts/_verify_backends.py,
  scripts/check_substrate_config.py, scripts/substrate_profile.py,
  scripts/substrate_upgrade.py, scripts/update_manifest.py,
  scripts/verify_release.py, scripts/write_install_json.py

03 memory/sessions:
  manage.sh, scripts/_doc_common.py, scripts/append_history.py,
  scripts/append_rejected.py, scripts/completion_gate.py,
  scripts/lint_on_write.py, scripts/memory_log.py,
  scripts/session_handoff.py, scripts/todo_state_hook.py

04 policy/governance:
  manage.sh, scripts/_substrate_config.sh, scripts/_substrate_surfaces.py,
  scripts/_text_safety.py, scripts/check_dep_cooldown.py,
  scripts/check_exfil_guard.py, scripts/check_github_governance.py,
  scripts/check_hook_smoke.py, scripts/check_policy_code_integrity.py,
  scripts/check_substrate_config.py, scripts/check_validator_input_coverage.py,
  scripts/command_policy.py, scripts/copilot_hook_adapter.py,
  scripts/lang_gate.sh, scripts/remote_detect.py, scripts/sandbox_detect.py,
  scripts/sandbox_exec.sh, scripts/setup_branch_protection.sh,
  scripts/substrate_profile.py

05 evals/assurance:
  manage.sh, extras/calibrate_diy_ultrareview.py,
  extras/check_license_headers.py, extras/check_stale_phrases.py,
  scripts/agent_system_audit.sh, scripts/build_review_bundle.py,
  scripts/check_bandit_skip_baseline.py, scripts/check_coverage_floors.py,
  scripts/check_finding_response.py, scripts/check_harness_patterns.py,
  scripts/check_harness_smoke.py, scripts/check_history_sha.py,
  scripts/check_import_shadowing.py, scripts/check_policy_code_integrity.py,
  scripts/check_postmortem_for_bug_fix.py,
  scripts/check_postmortem_gates_resolved.py,
  scripts/check_python_syntax.py, scripts/check_secrets.py,
  scripts/check_validator_input_coverage.py, scripts/code_shape.py,
  scripts/diy_ultrareview.sh, scripts/run_security_scanners.py,
  scripts/run_smoke_verification.py, scripts/run_substrate_evals.py,
  scripts/substrate_audit.py

06 release/distribution:
  manage.sh, package_release.sh, scripts/_minisign.py,
  scripts/_verify_backends.py, scripts/build_review_bundle.py,
  scripts/release_gate.sh, scripts/setup_release_key.sh,
  scripts/update_manifest.py, scripts/verify_release.py,
  scripts/write_install_json.py

07 agent-context/governance:
  manage.sh, scripts/_doc_common.py, scripts/_substrate_root.py,
  scripts/_substrate_surfaces.py, scripts/_text_safety.py,
  scripts/check_agent_harness.py, scripts/check_doc_drift.py,
  scripts/check_harness_patterns.py, scripts/check_harness_smoke.py,
  scripts/context_report.py, scripts/new_validator.py,
  scripts/session_handoff.py, scripts/todo_state_hook.py
```

Write each body as a current contract, not a per-version transcript. Carry forward the code-backed limits from the old document, including sandbox host proof, local versus remote governance, consumer/source layout, trusted-code execution, upgrade race limits, submodule fail-closed behavior, deferred completion blocking, and v3.8.31 append serialization. Link release chronology instead of duplicating it.

- [ ] **Step 6: Add the ADR and documentation index**

Create `docs/decisions/0001-substrate-knowledge-boundaries.md` with:

```markdown
# 0001: Functional boundaries for substrate knowledge

**Status:** Accepted
**Date:** 2026-08-09
**Deciders:** operator, Codex
**Related:** [Design specification](../superpowers/specs/2026-07-30-substrate-knowledge-split-design.md)
```

Its Decision section must record the stable `00` entry point, seven source-only functional siblings, compact consumer generation, many-to-many coverage, and deterministic integration checks. Its Alternatives section must record the chronological split and single-file trimming rejections already present in `docs/REJECTED.md`.

Update `docs/README.md` with links to the entry point, seven siblings, ADR, HISTORY, and `CHANGES_V3.md`.

- [ ] **Step 7: Regenerate the manifest and run the focused green checks**

Run:

```bash
python scripts/update_manifest.py --fix
uv run pytest \
  tests/test_doc_consistency.py::test_source_knowledge_is_functionally_partitioned \
  tests/test_doc_consistency.py::test_source_knowledge_covers_every_discovered_module \
  tests/test_hook_scripts.py::test_consumer_install_gets_only_compact_substrate_knowledge -vv
SUBSTRATE_ENFORCE_DOC_BUDGET=1 python scripts/check_doc_drift.py --strict
python scripts/check_agent_harness.py
```

Expected result: all commands exit `0`; the drift command reports no oversize document; the harness scans all eight source knowledge docs.

---

### Task 2: Make staged documentation review suffix-independent

**Files:**
- Modify: `scripts/check_doc_drift.py:17-20,104-122`
- Modify: `tests/test_hook_scripts.py` near the existing v3.8.29 and v3.8.30 drift tests
- Modify: `docs/knowledge/07_agent_context_governance.md`

**Interfaces:**
- Consumes: `covers` values from every knowledge doc and Git's staged name-status stream.
- Produces: `_staged(root) -> set[str]` containing both sides of renames and a pending-review loop over `staged_paths & covered_paths`.

- [ ] **Step 1: Add a reusable disposable Git fixture for staged drift**

Add this helper beside `_drift_json`:

```python
def _staged_drift_repo(tmp_path: Path, covered: str) -> Path:
    repo = tmp_path
    target = repo / covered
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("version one\n", encoding="utf-8")
    doc = repo / "docs" / "knowledge" / "01_surface.md"
    doc.parent.mkdir(parents=True, exist_ok=True)
    doc.write_text(
        "---\npurpose: staged surface\nlast_human_reviewed: 2000-01-01\n"
        f"covers:\n  - {covered}\n---\n\n# Surface\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "x@x"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "x"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
    return repo
```

- [ ] **Step 2: Add failing staged-path regressions**

Add a parameterized test for shell, YAML, JSON, and extensionless config:

```python
@pytest.mark.parametrize(
    "covered",
    [
        "scripts/tool.sh",
        ".github/workflows/ci.yml",
        "config/policy.json",
        ".substrate/config",
    ],
)
def test_doc_drift_reviews_every_staged_covered_path(tmp_path, covered) -> None:
    repo = _staged_drift_repo(tmp_path, covered)
    target = repo / covered
    target.write_text("version two\n", encoding="utf-8")
    subprocess.run(["git", "add", covered], cwd=repo, check=True)
    pending = _drift_json(repo)["pending_stale_doc"]
    assert any(row[0] == "docs/knowledge/01_surface.md" and row[1] == covered for row in pending)

    doc = repo / "docs" / "knowledge" / "01_surface.md"
    doc.write_text(doc.read_text(encoding="utf-8") + "\nReviewed.\n", encoding="utf-8")
    subprocess.run(["git", "add", str(doc.relative_to(repo))], cwd=repo, check=True)
    assert _drift_json(repo)["pending_stale_doc"] == []
```

Add deletion and rename coverage:

```python
@pytest.mark.parametrize("operation", ["delete", "rename"])
def test_doc_drift_keeps_old_covered_path_for_delete_or_rename(tmp_path, operation) -> None:
    repo = _staged_drift_repo(tmp_path, "scripts/tool.sh")
    if operation == "delete":
        subprocess.run(["git", "rm", "scripts/tool.sh"], cwd=repo, check=True)
    else:
        subprocess.run(
            ["git", "mv", "scripts/tool.sh", "scripts/tool-renamed.sh"],
            cwd=repo,
            check=True,
        )
    pending = _drift_json(repo)["pending_stale_doc"]
    assert any(row[1] == "scripts/tool.sh" for row in pending)
```

Import `pytest` in `tests/test_hook_scripts.py` if it is not already imported.

- [ ] **Step 3: Run the staged tests and confirm they fail**

Run:

```bash
uv run pytest \
  tests/test_hook_scripts.py::test_doc_drift_reviews_every_staged_covered_path \
  tests/test_hook_scripts.py::test_doc_drift_keeps_old_covered_path_for_delete_or_rename -vv
```

Expected result: shell/YAML/JSON/config changes do not appear in `pending_stale_doc`, and deletion or rename loses the old covered path.

- [ ] **Step 4: Parse the NUL-delimited staged name-status stream**

Replace `_staged` with a parser that returns both names for renames and copies:

```python
def _staged(root: Path) -> set[str]:
    try:
        result = subprocess.run(
            [
                "git", "diff", "--cached", "--name-status", "-z",
                "--diff-filter=ACMRTD",
            ],
            cwd=str(root),
            check=True,
            capture_output=True,
            timeout=30,
        )
    except Exception:
        return set()
    fields = result.stdout.decode("utf-8", "surrogateescape").split("\0")
    staged: set[str] = set()
    index = 0
    while index < len(fields) and fields[index]:
        status = fields[index]
        index += 1
        old_or_only = fields[index]
        index += 1
        staged.add(old_or_only)
        if status.startswith(("R", "C")):
            staged.add(fields[index])
            index += 1
    return staged
```

Keep `_staged_code` for module-discovery gaps, but accept a staged set so Git runs once:

```python
def _staged_code(root: Path, staged: set[str] | None = None) -> set[str]:
    paths = _staged(root) if staged is None else staged
    return {
        path
        for path in paths
        if Path(path).suffix in CODE_SUFFIXES
        and not _excluded(path)
        and (root / path).exists()
    }
```

In `detect`, compute `staged = _staged(root)` once. Build pending review from all staged covered paths:

```python
for code_path in sorted(staged & covered):
    for doc in cov_to_docs.get(code_path, []):
        if doc["path"] not in staged_docs and _date(doc.get("last_human_reviewed", "")) != today:
            pending.append(
                (doc["path"], code_path, str(doc.get("last_human_reviewed", "")))
            )
```

Keep `staged_coverage_gap` limited to `_staged_code(root, staged)` so arbitrary product data files do not become required knowledge modules.

- [ ] **Step 5: Run focused tests and update the context-governance contract**

Run:

```bash
uv run pytest \
  tests/test_hook_scripts.py::test_doc_drift_reviews_every_staged_covered_path \
  tests/test_hook_scripts.py::test_doc_drift_keeps_old_covered_path_for_delete_or_rename \
  tests/test_hook_scripts.py::test_doc_drift_asserts_catch_renamed_and_missing \
  tests/test_hook_scripts.py::test_doc_drift_doc_committed_with_code_is_not_stale -vv
```

Expected result: all pass. Update `07_agent_context_governance.md` to state that module discovery remains suffix-based while review of already-covered staged paths is suffix-independent and includes old rename/delete names.

---

### Task 3: Enumerate every knowledge document in the context budget

**Files:**
- Modify: `scripts/context_report.py:279-312`
- Modify: `tests/test_hook_scripts.py` near `test_context_report_budget_names_oversize_knowledge_doc`
- Modify: `docs/knowledge/07_agent_context_governance.md`

**Interfaces:**
- Consumes: `root / docs/knowledge/*.md`, `_size`, `_tok`, and the existing `_BUDGETS` mapping.
- Produces: `_budget(d: dict, root: Path) -> list[dict]` with all legacy rows plus every over-budget non-template knowledge doc.

- [ ] **Step 1: Add a failing twelve-document budget regression**

Add:

```python
def test_context_report_budget_enumerates_all_knowledge_docs(tmp_path) -> None:
    knowledge = tmp_path / "docs" / "knowledge"
    knowledge.mkdir(parents=True)
    expected = set()
    for index in range(12):
        path = knowledge / f"{index:02d}_surface.md"
        path.write_text("# Surface\n" + ("content " * 100), encoding="utf-8")
        expected.add(f"knowledge_doc:docs/knowledge/{path.name}")
    template = knowledge / "_template.md"
    template.write_text("content " * 100, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(SCRIPTS / "context_report.py"),
            "--root",
            str(tmp_path),
            "--budget",
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(os.environ, SUBSTRATE_KNOWLEDGE_DOC_TOKENS="10"),
    )
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout)["budget"]
    actual = {row["item"] for row in rows if row["item"].startswith("knowledge_doc:")}
    assert actual == expected
```

- [ ] **Step 2: Run it and confirm the top-ten failure**

Run:

```bash
uv run pytest tests/test_hook_scripts.py::test_context_report_budget_enumerates_all_knowledge_docs -vv
```

Expected result: only ten of the twelve expected rows appear.

- [ ] **Step 3: Pass the full root into `_budget` and enumerate the source inventory**

Change the signature and knowledge loop:

```python
def _budget(d: dict, root: Path) -> list:
    # Keep the four legacy rows unchanged above this point.
    kb = _BUDGETS["knowledge_doc"]
    knowledge = sorted(
        (
            path
            for path in _glob_files(root, "docs/knowledge/*.md")
            if not path.name.startswith("_")
        ),
        key=lambda path: (-_tok(_size(path)), path.relative_to(root).as_posix()),
    )
    for path in knowledge:
        rel = path.relative_to(root).as_posix()
        tok = _tok(_size(path))
        if tok > kb:
            out.append(
                {
                    "item": f"knowledge_doc:{rel}",
                    "est_tokens": tok,
                    "budget": kb,
                    "status": "warn",
                }
            )
    return out
```

Update `main`:

```python
root = Path(a.root).resolve()
d = build(root)
if a.budget:
    d["budget"] = _budget(d, root)
```

Do not enlarge `largest_contributors`; it remains a concise top-ten display.

- [ ] **Step 4: Run budget contract tests and update the knowledge doc**

Run:

```bash
uv run pytest \
  tests/test_hook_scripts.py::test_context_report_budget_enumerates_all_knowledge_docs \
  tests/test_hook_scripts.py::test_context_report_budget_names_oversize_knowledge_doc \
  tests/test_hook_scripts.py::test_context_report_budget_flags_oversize -vv
```

Expected result: all pass, the four legacy rows stay present, and `_template.md` stays absent. Update `07_agent_context_governance.md` to separate the top-ten contributor display from full budget enumeration.

---

### Task 4: Govern agent plans and prove every context surface independently

**Files:**
- Modify: `scripts/_substrate_surfaces.py:23-58,108-119`
- Modify: `scripts/check_harness_smoke.py:43-92`
- Modify: `tests/test_doc_consistency.py` near `test_governance_consumers_derive_from_inventory`
- Modify: `tests/test_hook_scripts.py` near the existing harness smoke tests
- Modify: `docs/knowledge/05_evals_assurance.md`
- Modify: `docs/knowledge/07_agent_context_governance.md`

**Interfaces:**
- Consumes: the canonical context/ownership inventory, the production scanner's glob discovery, and the existing randomized injection families.
- Produces: governed `docs/superpowers/**/*.md` context plus one scanner subprocess per surface, including random knowledge and plan siblings, so one correctly scanned surface cannot mask another ignored surface.

- [ ] **Step 1: Add failing canonical-inventory and behavioral regressions**

Add this test to `tests/test_doc_consistency.py`:

```python
def test_superpowers_execution_docs_are_governed_context() -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_substrate_surfaces", KIT / "scripts" / "_substrate_surfaces.py"
    )
    inventory = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(inventory)
    assert "docs/superpowers/**/*.md" in inventory.CONTEXT_GLOBS
    assert "docs/superpowers" in inventory.GOVERNED_OPTIONAL_DIRS
    assert "docs/superpowers" not in inventory.OPTIONAL_DIRS
```

Add this regression beside `test_harness_smoke_catches_stubbed_agent_harness`:

```python
@pytest.mark.parametrize("ignored", ("knowledge", "plans"))
def test_harness_smoke_catches_scanner_that_ignores_dynamic_surface(tmp_path, ignored) -> None:
    _stage(
        tmp_path,
        "check_harness_smoke.py",
        "_substrate_root.py",
        "_substrate_surfaces.py",
        "harness_patterns.json",
    )
    (tmp_path / "scripts" / "check_agent_harness.py").write_text(
        """#!/usr/bin/env python3
from pathlib import Path

known = (Path("AGENTS.md"), Path("docs/HISTORY.md"), Path("docs/knowledge/00_substrate.md"))
if any(path.is_file() and len(path.read_text(encoding="utf-8")) > 80 for path in known):
    print("agent-harness: BLOCK prompt injection")
    raise SystemExit(1)
print("agent-harness: ok")
""",
        encoding="utf-8",
    )
    result = _run_staged(tmp_path, "check_harness_smoke.py")
    assert result.returncode == 1
    assert "knowledge" in (result.stdout + result.stderr).lower()
```

- [ ] **Step 2: Run both regressions and prove the inventory plus aggregate-smoke defects**

Run:

```bash
uv run pytest \
  tests/test_doc_consistency.py::test_superpowers_execution_docs_are_governed_context \
  tests/test_hook_scripts.py::test_harness_smoke_catches_scanner_that_ignores_dynamic_surface -vv
```

Expected result: the inventory test fails because both entries are absent. The old smoke passes because injected `AGENTS.md` makes the fake scanner block even though it ignores the sibling, so the behavioral regression fails its `returncode == 1` assertion.

- [ ] **Step 3: Add the plan directory to the canonical inventory**

Add the context glob beside the other documentation surfaces:

```python
"docs/knowledge/**/*.md", "docs/decisions/**/*.md", "docs/postmortems/**/*.md",
"docs/superpowers/**/*.md",
```

Add a distinct optional governance rule so project-authored plans do not enter
the substrate install baseline:

```python
GOVERNED_DIRS = ["docs/knowledge"]
GOVERNED_OPTIONAL_DIRS = ["docs/superpowers"]

# OWNED_FILES retains docs/knowledge/00_substrate.md and
# docs/knowledge/_template.md as the generated/install-supplied artifacts.
```

Keep it optional so a consumer that never creates the directory does not fail strict doctor. The existing `audit_trigger_paths()` derivation will add `docs/superpowers/**` without a workflow-specific duplicate.

- [ ] **Step 4: Run the real scanner once per surface**

Replace the static knowledge-only surface list with a per-run sibling:

```python
_BASE_SURFACES = (
    "AGENTS.md",
    "docs/HISTORY.md",
    "docs/knowledge/00_substrate.md",
)
```

Replace `main` with the complete per-surface loop:

```python
def main() -> int:
    scanner = SCRIPTS / "check_agent_harness.py"
    if not scanner.exists():
        print("check-harness-smoke: ok (no harness to test)")
        return 0

    def _payload(encoded: str) -> str:
        return base64.b64decode(encoded).decode().replace("{T}", uuid.uuid4().hex)

    surfaces = (
        *_BASE_SURFACES,
        f"docs/knowledge/{uuid.uuid4().hex}_smoke.md",
        f"docs/superpowers/plans/{uuid.uuid4().hex}_smoke.md",
    )
    seed = int(uuid.uuid4().hex[:8], 16)
    families_used = []
    for index, injected_surface in enumerate(surfaces):
        family = (seed + index) % len(_INJECTION_FAMILIES)
        families_used.append(family)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            scripts = tmp / "scripts"
            scripts.mkdir()
            for dependency in _DEPS:
                source = SCRIPTS / dependency
                if source.exists():
                    (scripts / dependency).write_text(
                        source.read_text(encoding="utf-8"), encoding="utf-8"
                    )
            substrate = tmp / ".substrate"
            substrate.mkdir()
            (substrate / "config").write_text(
                'SUBSTRATE_PROFILE="standard"\n', encoding="utf-8"
            )
            for surface in surfaces:
                target = tmp / surface
                target.parent.mkdir(parents=True, exist_ok=True)
                body = (
                    _payload(_INJECTION_FAMILIES[family])
                    if surface == injected_surface
                    else "benign"
                )
                target.write_text(
                    f"# governed context\n\n{body}\n", encoding="utf-8"
                )
            result = subprocess.run(
                [PY, "scripts/check_agent_harness.py"],
                cwd=str(tmp),
                capture_output=True,
                text=True,
                timeout=30,
            )
        output = (result.stdout + result.stderr).lower()
        if result.returncode == 0:
            print(
                f"check-harness-smoke: BLOCK: scanner ignored {injected_surface}",
                file=sys.stderr,
            )
            return 1
        if "injection" not in output:
            print(
                f"check-harness-smoke: BLOCK: {injected_surface} failed without the expected finding",
                file=sys.stderr,
            )
            return 1
    print(
        f"check-harness-smoke: ok ({len(surfaces)} surfaces independently, "
        f"families {sorted(set(families_used))} of {len(_INJECTION_FAMILIES)})"
    )
    return 0
```

- [ ] **Step 5: Run focused behavioral checks and update both contracts**

Run:

```bash
uv run pytest \
  tests/test_doc_consistency.py::test_superpowers_execution_docs_are_governed_context \
  tests/test_hook_scripts.py::test_harness_smoke_passes_shipped \
  tests/test_hook_scripts.py::test_harness_smoke_catches_stubbed_agent_harness \
  tests/test_hook_scripts.py::test_harness_smoke_catches_scanner_that_ignores_dynamic_surface -vv
python scripts/check_harness_smoke.py
python scripts/check_agent_harness.py
```

Expected result: all commands exit `0`; the smoke reports five independently tested surfaces. Document the per-surface negative control in `05_evals_assurance.md`, and document both arbitrary sibling discovery and optional plan ownership in `07_agent_context_governance.md`.

---

### Task 5: Integrate, release, audit, and publish v3.8.32

**Files:**
- Modify: `VERSION`
- Modify: `README.md`
- Modify: `BENCHMARK.md`
- Generate: `docs/manifest.json`
- Modify after code commit: `docs/HISTORY.md`
- Append after verification: `AGENT_BUS.md`
- Review: every file changed in Tasks 1 through 4

**Interfaces:**
- Consumes: all green focused tests, the generated knowledge manifest, and the v3.8.31 branch baseline.
- Produces: one coherent v3.8.32 code commit, one append-only HISTORY commit, one bus RELEASE commit, and a pushed branch with no unresolved auditor BLOCK.

- [ ] **Step 1: Update release identity and regenerate measured artifacts**

Set `VERSION` to `3.8.32`. Change the README current-status header and any exact release label from `3.8.31` to `3.8.32`. Regenerate the benchmark instead of editing its result fields:

```bash
./manage.sh evals --report
python scripts/update_manifest.py --fix
```

Expected result: evals report 23/23 malicious blocked and 0/12 benign false positives, `BENCHMARK.md` names v3.8.32, and the manifest lists eight knowledge docs plus ADR 0001.

- [ ] **Step 2: Run all focused regression groups together**

Run:

```bash
uv run pytest \
  tests/test_doc_consistency.py \
  tests/test_hook_scripts.py::test_consumer_install_gets_only_compact_substrate_knowledge \
  tests/test_hook_scripts.py::test_doc_drift_reviews_every_staged_covered_path \
  tests/test_hook_scripts.py::test_doc_drift_keeps_old_covered_path_for_delete_or_rename \
  tests/test_hook_scripts.py::test_context_report_budget_enumerates_all_knowledge_docs \
  tests/test_hook_scripts.py::test_context_report_budget_names_oversize_knowledge_doc \
  tests/test_hook_scripts.py::test_harness_smoke_passes_shipped \
  tests/test_hook_scripts.py::test_harness_smoke_catches_scanner_that_ignores_dynamic_surface -vv
SUBSTRATE_ENFORCE_DOC_BUDGET=1 python scripts/check_doc_drift.py --strict
python scripts/update_manifest.py --check
python scripts/check_agent_harness.py
```

Expected result: every command exits `0`, all eight docs fit the budget, and the manifest has no follow-up diff.

- [ ] **Step 3: Run the required auditors**

Dispatch read-only `architecture-auditor`, `documentation-auditor`, `test-auditor`, `harness-auditor`, and `security-auditor` against the full diff from `84ecc7a`. Require `file:line` evidence and resolve every BLOCK. The security review must focus on NUL-delimited Git parsing, path handling, and whether the smoke test still executes only copied trusted scanner code.

Run the `self-audit` skill after the last project-file edit and record it:

```bash
./manage.sh memory skill-run self-audit
```

- [ ] **Step 4: Run the authoritative release gates**

Run:

```bash
./manage.sh check
./manage.sh evals
./manage.sh release
git diff --check
git status --short
```

Expected result: `check` exits `0`; evals block every malicious case with zero benign false positives; release verifies the built artifact; no generated follow-up or unexpected file remains.

- [ ] **Step 5: Commit the coherent code and documentation unit**

Stage only the claimed v3.8.32 files, inspect the staged diff, and commit with hooks enabled:

```bash
git add \
  VERSION README.md BENCHMARK.md docs/README.md \
  docs/REJECTED.md \
  docs/decisions/0001-substrate-knowledge-boundaries.md \
  docs/knowledge/00_substrate.md \
  docs/knowledge/01_install_adoption.md \
  docs/knowledge/02_upgrade_integrity.md \
  docs/knowledge/03_memory_sessions.md \
  docs/knowledge/04_policy_governance.md \
  docs/knowledge/05_evals_assurance.md \
  docs/knowledge/06_release_distribution.md \
  docs/knowledge/07_agent_context_governance.md \
  docs/postmortems/2026-08-10-knowledge-ownership-migration.md \
  docs/manifest.json \
  docs/superpowers/plans/2026-08-09-substrate-knowledge-split.md \
  docs/superpowers/specs/2026-07-30-substrate-knowledge-split-design.md \
  scripts/_substrate_surfaces.py scripts/check_doc_drift.py \
  scripts/context_report.py scripts/check_harness_smoke.py \
  scripts/substrate_doctor.py scripts/substrate_upgrade.py \
  scripts/write_install_json.py scripts/code_shape.py \
  tests/test_doc_consistency.py tests/test_hook_scripts.py
git diff --cached --check
git commit -m "v3.8.32: split substrate knowledge by function" \
  -m "Postmortem: docs/postmortems/2026-08-10-knowledge-ownership-migration.md"
```

- [ ] **Step 6: Append HISTORY using the landed code SHA**

Run:

```bash
sha=$(git rev-parse --short HEAD)
python scripts/append_history.py \
  --commit-hash "$sha" \
  --summary "v3.8.32: functional substrate knowledge map with complete drift, budget, and harness enforcement" \
  --files "docs/knowledge,docs/decisions/0001-substrate-knowledge-boundaries.md,docs/postmortems/2026-08-10-knowledge-ownership-migration.md,docs/REJECTED.md,docs/superpowers,scripts/_substrate_surfaces.py,scripts/check_doc_drift.py,scripts/context_report.py,scripts/check_harness_smoke.py,scripts/substrate_doctor.py,scripts/substrate_upgrade.py,scripts/write_install_json.py,scripts/code_shape.py,tests/test_doc_consistency.py,tests/test_hook_scripts.py" \
  --intent "Replace the oversized chronological knowledge file with enforceable functional boundaries" \
  --knowledge "Source has eight bounded knowledge docs; consumers keep generated 00 plus the installed knowledge template; staged covered paths are suffix-independent; budgets and harness smoke enumerate every sibling; project knowledge and plans are governed but excluded from install ownership; the first upgrade retires obsolete project-knowledge baseline entries"
git add docs/HISTORY.md
git commit -m "docs: HISTORY for v3.8.32"
```

- [ ] **Step 7: Post the bus RELEASE and publish without rewriting history**

Append one line to `AGENT_BUS.md` with the code SHA, HISTORY SHA, gate results, auditor verdicts, the eight-document source shape, consumer-layout proof, and the four fixed integration defects. Then:

```bash
git add AGENT_BUS.md
git commit -m "bus: release v3.8.32 knowledge split"
git pull --rebase origin claude/version-identification-7vpc1t
git push origin claude/version-identification-7vpc1t
git status --short --branch
```

Expected result: the branch matches origin with a clean tree. Do not squash these published commits when PR #7 merges.

## Plan Self-Review

- **Spec coverage:** Tasks 1 through 4 cover the document map, eleven assertions, many-to-many coverage, consumer boundary, suffix-independent staged review, complete budget enumeration, per-surface smoke, Superpowers plan governance, ADR, links, and size enforcement. Task 5 covers versioning, manifest generation, full gates, auditors, HISTORY, bus, and push.
- **Placeholder scan:** The plan contains no unresolved marker, deferred implementation step, or unnamed error-handling requirement. Every behavior change has a named test, command, expected red result, implementation seam, and green command.
- **Type consistency:** `_staged` returns `set[str]`; `_staged_code` accepts that same set; `_budget` receives a resolved `Path`; knowledge purposes and assertion strings match the source-shape tests; harness surfaces remain repository-relative strings.
