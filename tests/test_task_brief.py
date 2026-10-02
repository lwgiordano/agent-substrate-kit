"""Task brief contracts; self-contained so copied consumer tests can run."""
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts").is_dir() and (p / "manage.sh").is_file())
sys.path.insert(0, str(ROOT / "scripts"))


def api(name="task_brief"):
    assert importlib.util.find_spec(name), f"missing approved command module: {name}"
    return importlib.import_module(name)


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    return subprocess.run(["git", *args], cwd=root, env=env, check=True,
                          capture_output=True, timeout=10).stdout.decode().strip()


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project with spaces"
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    for directory in ("docs/knowledge", "docs/decisions", "tests", "scripts"):
        (root / directory).mkdir(parents=True)
    (root / "docs/INTENT.md").write_text(
        "# Intent\n## Objectives\n1. Preserve evidence.\n2. Reduce retrieval cost.\n")
    (root / "docs/knowledge/storage.md").write_text(
        "# Storage\n## Receipts\nImmutable receipts retain each check observation.\n")
    (root / "docs/decisions/0001-ranking.md").write_text(
        "# Ranking\n## Decision\nRetrieval ranks sections using BM25 offline.\n")
    (root / "tests/test_feature.py").write_text("def test_proof():\n    assert True\n")
    lessons = [
        {"id": "L1", "rule": "Keep every observation.", "status": "test",
         "triggers": ["scripts/storage.py"], "superseded_by": None,
         "evidence": {"test": "tests/test_feature.py::test_proof"}},
        {"id": "L2", "rule": "Keep retrieval bounded.", "status": "test",
         "triggers": ["scripts/retrieval.py"], "superseded_by": None,
         "evidence": {"test": "tests/test_feature.py::test_proof"}},
    ]
    (root / "docs/lessons.jsonl").write_text("\n".join(map(json.dumps, lessons)) + "\n")
    (root / "AGENT_BUS.md").write_text(
        "- [2026-10-02T00:00:00Z] **alice**: CLAIM v9.0.0 scripts/storage.py\n"
        "- [2026-10-02T00:01:00Z] **bob**: FINDING P2 scripts/storage.py:1 — reported only\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "fixture")
    return root


@pytest.mark.parametrize(("task", "path", "lesson", "source"), [
    ("receipt observations", "scripts/storage.py", "L1", "docs/knowledge/storage.md"),
    ("retrieval ranks", "scripts/retrieval.py", "L2", "docs/decisions/0001-ranking.md"),
])
def test_brief_selects_relevant_committed_evidence(project, task, path, lesson, source):
    report = api().build(project, task, [path], 6000)
    assert report["schema_version"] == 1
    assert report["identity"]["head"] == git(project, "rev-parse", "HEAD")
    assert report["identity"]["dirty"] == "clean"
    assert report["identity"]["collected_at"]
    items = report["evidence"]
    assert any(x["kind"] == "objective" and "Preserve" in x["body"] for x in items)
    assert [x["id"] for x in items if x["kind"] == "lesson"] == [lesson]
    hit = next(x for x in items if x["path"] == source)
    assert hit["line"] == 2
    assert hit["content_hash"] == hashlib.sha256((project / source).read_bytes()).hexdigest()
    assert hit["source_state"] == "committed"
    assert hit["source_revision"] == report["identity"]["head"]
    assert hit["reason"] and hit["collected_at"]
    assert any(x["kind"] == "reported-finding" for x in items)
    assert "unresolved_count" not in json.dumps(report)


def test_brief_reads_current_docs_but_only_committed_lessons(project):
    module = api()
    first = module.build(project, "receipts", ["scripts/storage.py"], 6000)
    path = project / "docs/knowledge/storage.md"
    path.write_text("# Storage\n## Receipts\nReceipts now retain status and revision.\n")
    (project / "docs/lessons.jsonl").write_text("not the committed lesson\n")
    second = module.build(project, "receipts", ["scripts/storage.py"], 6000)
    before = next(x for x in first["evidence"] if x["path"] == "docs/knowledge/storage.md")
    after = next(x for x in second["evidence"] if x["path"] == before["path"])
    assert before["content_hash"] != after["content_hash"]
    assert after["source_state"] == "modified"
    assert "now retain" in after["body"]
    assert any(x.get("id") == "L1" for x in second["evidence"])
    assert second["identity"]["dirty"] == "dirty"


@pytest.mark.parametrize("triggers", [None, 42, [None]])
def test_malformed_local_lesson_yields_diagnostic_not_brief_crash(project, triggers):
    malformed = {"id": "L99", "rule": "local draft", "triggers": triggers}
    (project / "docs/lessons.jsonl").write_text(json.dumps(malformed) + "\n")
    report = api().build(project, "receipts", ["scripts/storage.py"], 6000)
    assert any(x.get("id") == "L1" for x in report["evidence"])
    assert any(x["code"] == "malformed-source" and x["path"] == "docs/lessons.jsonl"
               for x in report["diagnostics"])
    assert api("recall").collect(project)  # legacy renderer shares the safe collector


def test_brief_json_sanitizes_all_exported_metadata(project):
    module = api()
    token = "sk-" + "X" * 32  # deliberately fake credential-shaped fixture
    record = {"id": "L3", "rule": "Keep observations.", "status": "test",
              "triggers": ["scripts/storage.py"], "superseded_by": None,
              "evidence": {"test": "tests/test_feature.py::test_proof", "sha": token,
                           "nested": {"directive": "unexpected metadata"}}}
    (project / "docs/lessons.jsonl").write_text(json.dumps(record) + "\n")
    git(project, "add", ".")
    git(project, "commit", "-qm", "malformed lesson")
    git(project, "branch", "-m", token)
    (project / (token + ".txt")).write_text("ordinary bytes")
    report = module.build(project, "observations", ["scripts/storage.py", token + ".txt"], 6000)
    rendered = module.render_json(report)
    assert token not in rendered
    assert "unexpected metadata" not in rendered
    assert any(x["code"] == "malformed-lesson" for x in report["diagnostics"])
    assert report["sanitization"]["changed_fields"] > 0


def test_brief_preserves_valid_null_sha_lesson(project):
    path = project / "docs/lessons.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0]["evidence"]["sha"] = None
    path.write_text("\n".join(map(json.dumps, records)) + "\n")
    git(project, "add", ".")
    git(project, "commit", "-qm", "nullable lesson evidence")
    report = api().build(project, "receipts", ["scripts/storage.py"], 6000)
    assert any(x.get("id") == "L1" for x in report["evidence"])


@pytest.mark.parametrize(("field", "value"), [
    ("id", "wrong"), ("id", "L123456789"), ("id", "L1\n"),
    ("sha", "not-hex"), ("sha", "a" * 6), ("sha", "a" * 65),
])
def test_lesson_metadata_validated_independently(project, field, value):
    path = project / "docs/lessons.jsonl"
    record = json.loads(path.read_text().splitlines()[0])
    if field == "sha":
        record["evidence"][field] = value
    else:
        record[field] = value
    path.write_text(json.dumps(record) + "\n")
    git(project, "add", ".")
    git(project, "commit", "-qm", "one malformed field")
    report = api().build(project, "receipts", ["scripts/storage.py"], 6000)
    assert not [x for x in report["evidence"] if x["kind"] == "lesson"]
    assert any(x["code"] == "malformed-lesson" for x in report["diagnostics"])


def test_brief_lease_has_stable_identity_not_fabricated_line(project):
    report = api().build(project, "receipts", ["scripts/storage.py"], 6000)
    lease = next(x for x in report["evidence"] if x["kind"] == "lease")
    assert lease["id"] == "lease:9.0.0:alice"
    assert lease["line"] is None


def test_brief_text_reports_diagnostics_it_cannot_show(project):
    report = api().build(project, "receipts", [], 6000)
    assert len(report["diagnostics"]) >= 3
    hidden = len(report["diagnostics"]) - 2 + report["truncation"]["diagnostics_omitted"]
    assert f"{hidden} diagnostics not shown" in api().render_text(report)


def test_legacy_recall_does_not_invoke_git_for_unused_provenance(project, monkeypatch):
    import _task_evidence

    def forbidden(*args, **kwargs):
        pytest.fail("legacy recall must not collect unused Git provenance")

    monkeypatch.setattr(_task_evidence, "git", forbidden)
    assert api("recall").collect(project)


def test_recall_refuses_linked_ancestor_before_listing_names(project, tmp_path):
    (project / "docs").rename(project / "docs_saved")
    outside = tmp_path / "outside"
    (outside / "knowledge").mkdir(parents=True)
    (outside / "knowledge/OUTSIDE_NAME.md").write_text("not in scope")
    (project / "docs").symlink_to(outside, target_is_directory=True)
    items, diagnostics = api("recall").collect_with_diagnostics(project)
    assert "OUTSIDE_NAME" not in json.dumps([items, diagnostics])


@pytest.mark.parametrize("shape", ["missing", "symlink", "directory", "undecodable"])
def test_brief_missing_and_unsafe_sources_are_visible(project, tmp_path, shape):
    path = project / "docs/INTENT.md"
    path.unlink()
    if shape == "symlink":
        outside = tmp_path / "outside.md"
        outside.write_text("OUTSIDE OBJECTIVE")
        path.symlink_to(outside)
    elif shape == "directory":
        path.mkdir()
    elif shape == "undecodable":
        path.write_bytes(b"\xff")
    report = api().build(project, "unmatchedterm", [], 800)
    assert any(x["path"] == "docs/INTENT.md" for x in report["diagnostics"])
    assert "OUTSIDE OBJECTIVE" not in json.dumps(report)


def test_brief_reports_off_grammar_claims_without_inventing_clean_bus(project):
    (project / "AGENT_BUS.md").write_text("CLAIM scripts/storage.py -- Alice\n")
    report = api().build(project, "storage", [], 800)
    assert any(x["code"] == "unparsed-claim" for x in report["diagnostics"])


@pytest.mark.parametrize("budget", [200, 800, 6000])
def test_brief_unicode_budget_preserves_identity_and_omission(project, budget):
    module = api()
    (project / "docs/knowledge/storage.md").write_text(
        "# Storage\n## Receipts\n" + "receipts 界 " * 5000)
    report = module.build(project, "receipts 界 " * 500, ["scripts/storage.py"], budget)
    rendered = module.render_text(report)
    assert len(rendered.encode()) <= budget * 4
    assert git(project, "rev-parse", "HEAD") in rendered
    assert "truncat" in rendered.lower() or "omitt" in rendered.lower()
    assert len(module.render_json(report).encode()) <= 65536
    assert report["truncation"]["evidence_omitted"] > 0


def test_brief_minimum_budget_preserves_omissions_with_unicode_identity(project):
    git(project, "branch", "-m", "🧪" * 50)
    report = api().build(project, "界" * 2000, ["scripts/storage.py"], 200)
    rendered = api().render_text(report)
    assert len(rendered.encode()) <= 800
    assert git(project, "rev-parse", "HEAD") in rendered
    assert "diagnostics not shown" in rendered


def test_brief_no_matches_does_not_invent_review(project):
    report = api().build(project, "zyxqwnomatch", ["unrelated.txt"], 6000)
    assert not [x for x in report["evidence"] if x["kind"] in ("knowledge", "decision", "lesson")]
    assert "not a review" in api().render_text(report)


def test_brief_reports_all_ranked_candidates_or_counts_omissions(project):
    text = "# Storage\n" + "\n".join(f"## receipts {i}\nreceipts item" for i in range(31))
    (project / "docs/knowledge/storage.md").write_text(text)
    report = api().build(project, "receipts", ["unrelated.txt"], 6000)
    hits = [x for x in report["evidence"] if x["kind"] == "knowledge"]
    assert len(hits) == 31  # all fit; a hidden top-30 cap is not the byte budget


def test_brief_reports_invalid_grammar_shaped_timestamp(project):
    (project / "AGENT_BUS.md").write_text(
        "- [2026-99-02T00:00:00Z] **alice**: CLAIM v9.0.0 scripts/storage.py\n")
    report = api().build(project, "receipts", [], 6000)
    assert any(x["code"] == "invalid-claim-timestamp" for x in report["diagnostics"])


def test_report_sanitizer_removes_terminal_controls():
    payload = "ordinary " + chr(27) + "[2J" + chr(7) + chr(155)
    clean, changed = api("_task_evidence").sanitize_report({"body": payload})
    assert changed == 1
    assert all(c not in clean["body"] for c in (chr(27), chr(7), chr(155)))


def test_brief_cli_does_not_create_project_bytecode(project):
    shutil.copytree(ROOT / "scripts", project / "scripts", dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    proc = subprocess.run([sys.executable, "-I", "scripts/task_brief.py", "receipts", "--json"],
                          cwd=project, capture_output=True, timeout=45)
    assert proc.returncode == 0, proc.stderr
    assert not (project / "scripts/__pycache__").exists()


def test_brief_essential_identity_failure_is_explicit(tmp_path, monkeypatch, capsys):
    module = api()
    monkeypatch.setattr(module, "__file__", str(tmp_path / "scripts/task_brief.py"))
    assert module.main(["ordinary task", "--json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["identity"]["status"] == "error"
    assert report["identity"]["dirty"] == "unknown"


def test_brief_cli_parity_in_fresh_consumer(tmp_path):
    if not (ROOT / "bootstrap.sh").exists():
        pytest.skip("source-kit bootstrap integration")
    consumer = tmp_path / "consumer with spaces"
    consumer.mkdir()
    git(consumer, "init", "-q")
    git(consumer, "config", "user.name", "Fixture")
    git(consumer, "config", "user.email", "fixture@example.invalid")
    git(consumer, "config", "commit.gpgsign", "false")
    subprocess.run(["bash", str(ROOT / "bootstrap.sh"), "--target", str(consumer),
                    "--profile", "starter", "--lang", "none", "--no-doctor"],
                   check=True, capture_output=True, timeout=90)
    git(consumer, "add", ".")
    git(consumer, "commit", "-qm", "consumer fixture")
    for root in (ROOT, consumer):
        proc = subprocess.run(["bash", "manage.sh", "brief", "evidence retrieval", "--json"],
                              cwd=root, capture_output=True, text=True, timeout=45)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        data = json.loads(proc.stdout)
        assert data["schema_version"] == 1
        assert data["identity"]["head"] == git(root, "rev-parse", "HEAD")
        assert Path(data["identity"]["root"]) == root.resolve()
        assert len(proc.stdout.encode()) <= 65536
        small = subprocess.run(["bash", "manage.sh", "brief", "界" * 1500, "--budget", "200"],
                               cwd=root, capture_output=True, text=True, timeout=45)
        assert small.returncode == 0, small.stderr
        assert len(small.stdout.encode()) <= 800


def test_git_facts_unborn_is_not_clean(tmp_path):
    git(tmp_path, "init", "-q")
    facts = api("_task_evidence").git_facts(tmp_path)
    assert facts["head"] is None
    assert facts["status"] == "unborn"
    assert facts["dirty"] != "clean"


def test_git_facts_never_runs_filter_or_fsmonitor(project):
    module = api("_task_evidence")
    (project / "filter.sh").write_text("#!/bin/sh\ntouch MARKER\ncat\n")
    (project / ".gitattributes").write_text("input.txt filter=audit\n")
    (project / "input.txt").write_text("original\n")
    git(project, "add", ".")
    git(project, "commit", "-qm", "filter fixture")
    git(project, "config", "filter.audit.clean", "sh filter.sh")
    git(project, "config", "core.fsmonitor", "sh filter.sh")
    (project / "input.txt").write_text("changed\n")
    before = sorted(str(x.relative_to(project)) for x in (project / ".git/objects").rglob("*"))
    facts = module.git_facts(project)
    assert facts["dirty"] == "dirty"
    assert not (project / "MARKER").exists()
    after = sorted(str(x.relative_to(project)) for x in (project / ".git/objects").rglob("*"))
    assert after == before


def test_git_facts_owner_execute_change_is_dirty(project):
    module = api("_task_evidence")
    path = project / "helper.sh"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o755)
    git(project, "add", "helper.sh")
    git(project, "commit", "-qm", "executable helper")
    before = module.git_facts(project)
    path.chmod(0o655)
    after = module.git_facts(project)
    assert "helper.sh" in after["changed_paths"]
    assert before["fingerprint"] != after["fingerprint"]


def test_git_facts_fingerprint_covers_raw_permission_bits(project):
    module = api("_task_evidence")
    path = project / "permission.txt"
    path.write_text("unchanged bytes\n")
    path.chmod(0o644)
    git(project, "add", "permission.txt")
    git(project, "commit", "-qm", "permission fixture")
    before = module.git_facts(project)
    path.chmod(0o444)
    assert before["fingerprint"] != module.git_facts(project)["fingerprint"]


def test_report_sanitizer_discards_pem_body_before_truncating():
    module = api("_task_evidence")
    header = "-----BEGIN " + "PRIVATE KEY-----"
    payload = "VISIBLE_BODY_CANARY\n" + header + "\nSYNTHETIC_BODY_CANARY\n"
    assert "CANARY" not in module.safe_text(payload, 65536)
    assert "VISIBLE_BODY" not in module.safe_text(payload, 20)


@pytest.mark.parametrize("separator", ["\u200b ", "\t", "\n"])
def test_report_secret_redaction_runs_after_normalization(separator):
    payload = "-----BEGIN" + separator + "PRIVATE KEY-----\nSYNTHETIC_BODY_CANARY"
    assert "CANARY" not in api("_task_evidence").safe_text(payload)


@pytest.mark.parametrize("prefix", ["", "SYNTHETIC_BODY_CANARY " + "padding " * 35])
def test_brief_discards_already_redacted_objective_body(project, prefix):
    header = "-----BEGIN " + "PRIVATE KEY-----"
    (project / "docs/INTENT.md").write_text(
        "## Objectives\n1. " + prefix + header + "\n   SYNTHETIC_BODY_CANARY\n")
    assert "SYNTHETIC_BODY_CANARY" not in json.dumps(api().build(project, "objective", [], 6000))


def test_lesson_selector_discards_secret_before_clipping(project):
    header = "-----BEGIN " + "PRIVATE KEY-----"
    lesson = {"id": "L1", "rule": "SYNTHETIC_BODY_CANARY " + "padding " * 35 + header,
              "status": "test", "triggers": ["scripts/storage.py"],
              "evidence": {"test": "tests/test_feature.py::test_proof"}}
    selected, _ = api("session_handoff").select_lessons(
        project, json.dumps(lesson), ["scripts/storage.py"])
    assert "CANARY" not in json.dumps(selected)


def test_git_facts_ignores_inherited_routing(project, tmp_path, monkeypatch):
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q")
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    facts = api("_task_evidence").git_facts(project)
    assert facts["head"] == git(project, "rev-parse", "HEAD")
    assert facts["dirty"] == "clean"


def test_git_facts_dangling_linked_parent_is_unknown_not_missing(project, tmp_path):
    (project / "docs").rename(project / "docs_saved")
    (project / "docs").symlink_to(tmp_path / "absent", target_is_directory=True)
    # Hide the new leaf from the untracked list so only tracked descendant
    # inspection can catch the routed ancestor, not a redundant sibling path.
    (project / ".git/info/exclude").write_text("docs\n")
    facts = api("_task_evidence").git_facts(project)
    assert facts["dirty"] == "unknown"
    assert facts["fingerprint"] is None


def test_git_facts_orphan_branch_reports_unborn(project):
    git(project, "switch", "--orphan", "empty")
    facts = api("_task_evidence").git_facts(project)
    assert facts["status"] == "unborn"
    assert facts["head"] is None


def test_collect_diagnostics_retains_legacy_tuple_contract(project):
    module = api("recall")
    assert hasattr(module, "collect_with_diagnostics"), "structured collector is missing"
    items, diagnostics = module.collect_with_diagnostics(project)
    assert any(x["path"] == "docs/knowledge/storage.md" for x in items)
    assert diagnostics  # optional HISTORY/REJECTED sources are absent
    assert all(len(item) == 4 for item in module.collect(project))


def test_read_only_git_never_fetches_missing_promisor_objects(project):
    module = api("_task_evidence")
    oid = git(project, "rev-parse", "HEAD:docs/INTENT.md")
    (project / ".git/objects" / oid[:2] / oid[2:]).unlink()
    (project / "remote.sh").write_text("#!/bin/sh\ntouch FETCH_MARKER\nexit 1\n")
    git(project, "config", "core.repositoryformatversion", "1")
    git(project, "config", "extensions.partialClone", "origin")
    git(project, "config", "remote.origin.promisor", "true")
    git(project, "config", "remote.origin.url", "ext::sh remote.sh")
    git(project, "config", "protocol.ext.allow", "always")
    with pytest.raises(ValueError):
        module.git(project, "cat-file", "blob", oid)
    assert not (project / "FETCH_MARKER").exists()


@pytest.mark.parametrize("budget", [199, 6001])
def test_brief_rejects_invalid_budget(project, budget):
    with pytest.raises(ValueError):
        api().build(project, "task", [], budget)
