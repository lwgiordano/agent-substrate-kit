"""Explicit-root project status contracts; self-contained for consumer copies."""
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts").is_dir() and (p / "manage.sh").is_file())
sys.path.insert(0, str(ROOT / "scripts"))
SETTINGS_HOOK = 'python3 "$CLAUDE_PROJECT_DIR/scripts/check_exfil_guard.py"'


def api(name="project_status"):
    return importlib.import_module(name)


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
    return subprocess.run(["git", *args], cwd=root, env=env, check=True,
                          capture_output=True, timeout=20).stdout.decode().strip()


def init(root):
    root.mkdir(parents=True)
    git(root, "init", "-q")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    return root


def make_project(root, marker_dir):
    """A target that tries to execute itself the moment anything touches it."""
    init(root)
    trap = f'touch "{marker_dir}/ran-$$"'
    (root / "manage.sh").write_text(f"#!/usr/bin/env bash\n{trap}\n")
    (root / "scripts").mkdir()
    for name in ("check_substrate_config.py", "task_receipt.py", "_task_evidence.py",
                 "_doc_common.py"):
        (root / "scripts" / name).write_text(
            f"import pathlib; pathlib.Path(r'{marker_dir}', 'imported-{name}').touch()\n")
    (root / ".substrate").mkdir()
    (root / ".substrate/config").write_text(
        'SUBSTRATE_PROFILE="strict"\nSUBSTRATE_LANG="python"\n')
    (root / ".substrate/required_profile").write_text("strict\n")
    (root / ".substrate/install.json").write_text(json.dumps(
        {"kit_version": "3.9.3", "installed_at": "2026-10-01T00:00:00Z",
         "owned_file_sha256": {"scripts/x.py": "0" * 64}}))
    (root / ".claude").mkdir()
    settings = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command",
                                                      "command": SETTINGS_HOOK}]}]}}
    (root / ".claude/settings.json").write_text(json.dumps(settings))
    (root / ".gitignore").write_text(".substrate/receipts/\n")
    (root / "app.py").write_text("print('ok')\n")
    git(root, "add", ".")
    git(root, "commit", "-qm", "fixture")
    return root


def inventory(root):
    out = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            out[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return out


@pytest.fixture
def markers(tmp_path):
    d = tmp_path / "markers"
    d.mkdir()
    return d


@pytest.fixture
def project(tmp_path, markers):
    return make_project(tmp_path / "project one", markers)


def test_reports_installed_kit_config_hooks_and_unchecked_remote(project, markers):
    rep = api().report([project])
    row = rep["projects"][0]
    assert rep["errors"] == 0 and row["status"] == "ok"
    assert row["kit"] == {"installed": "yes", "version": "3.9.3",
                          "installed_at": "2026-10-01T00:00:00Z",
                          "provenance": "baseline-present"}
    assert row["config"]["status"] == "ok" and row["config"]["profile"] == "strict"
    assert row["config"]["locks"]["required_profile"] == "strict"
    assert row["hooks"]["declared"]["PreToolUse"] == {"scripts/check_exfil_guard.py": "missing"}
    assert set(row["remote"].values()) == {"not checked"}
    assert row["git"]["dirty"] == "clean" and len(row["git"]["head"]) == 40
    assert set(row["hooks"]["git_hooks"].values()) == {"missing"}
    assert row["hooks"]["git_hooks_location"] == "inside-root"
    assert not any(markers.iterdir())


def test_git_hooks_are_reported_by_shape_never_run(project, markers, tmp_path):
    hooks = project / ".git/hooks"
    (hooks / "pre-commit").write_text(f'#!/bin/sh\ntouch "{markers}/hook-ran"\n')
    (hooks / "pre-commit").chmod(0o755)
    (tmp_path / "elsewhere").write_text("#!/bin/sh\n")
    (hooks / "pre-push").symlink_to(tmp_path / "elsewhere")
    (hooks / "commit-msg").write_text("#!/bin/sh\n")
    (hooks / "commit-msg").chmod(0o644)
    row = api().report([project])["projects"][0]
    assert row["hooks"]["git_hooks"] == {"pre-commit": "present-executable", "pre-push": "unsafe",
                                         "commit-msg": "present"}
    assert "not proof" in row["hooks"]["meaning"]
    assert not any(markers.iterdir())


def test_inspection_never_runs_or_imports_target_code_and_writes_nothing(project, markers):
    git(project, "config", "filter.evil.clean", f'touch "{markers}/filter-clean"; cat')
    git(project, "config", "filter.evil.smudge", f'touch "{markers}/filter-smudge"; cat')
    git(project, "config", "core.fsmonitor", f'touch "{markers}/fsmonitor"; echo')
    (project / ".gitattributes").write_text("* filter=evil\n")
    (project / "app.py").write_text("print('dirty')\n")
    before = inventory(project)
    rep = api().report([project])
    assert rep["projects"][0]["git"]["dirty"] == "dirty"
    assert inventory(project) == before
    assert not any(markers.iterdir()), sorted(p.name for p in markers.iterdir())


def test_a_git_planted_on_a_relative_path_entry_never_runs(project, markers, monkeypatch):
    fake = project / "git"
    fake.write_text(f'#!/bin/sh\ntouch "{markers}/planted-git"\nexit 1\n')
    fake.chmod(0o755)
    monkeypatch.chdir(project)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", os.environ["PATH"]]))
    row = api().report([project])["projects"][0]
    assert row["git"]["status"] == "ok" and row["git"]["head"]
    assert not any(markers.iterdir())


def test_missing_root_is_an_error_row_and_the_report_finishes(project, tmp_path):
    rep = api().report([tmp_path / "does not exist", project])
    codes = [d["code"] for d in rep["projects"][0]["diagnostics"]]
    assert rep["errors"] == 1 and codes == ["missing-root"]
    assert rep["projects"][1]["status"] == "ok"


def test_non_git_and_unborn_roots_are_errors_never_clean(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    unborn = init(tmp_path / "unborn")
    rep = api().report([plain, unborn])
    assert rep["errors"] == 2
    for row in rep["projects"]:
        assert row["status"] == "error" and row["git"]["dirty"] != "clean"
    assert "unborn" in {d["code"] for d in rep["projects"][1]["diagnostics"]}


def test_project_without_kit_and_with_unsafe_metadata_is_shown_accurately(tmp_path):
    bare = init(tmp_path / "bare")
    (bare / "a.txt").write_text("a\n")
    git(bare, "add", ".")
    git(bare, "commit", "-qm", "x")
    row = api().report([bare])["projects"][0]
    assert row["kit"]["installed"] == "no" and row["config"]["status"] == "absent"
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"kit_version": "9.9.9"}))
    (bare / ".substrate").mkdir()
    (bare / ".substrate/install.json").symlink_to(outside)
    (bare / ".substrate/config").write_text("SUBSTRATE_PROFILE=$(id)\n")
    (bare / ".substrate/required_profile").write_text("bogus\n")
    row = api().report([bare])["projects"][0]
    codes = {d["code"] for d in row["diagnostics"]}
    assert row["kit"]["installed"] == "unknown" and row["kit"]["version"] is None
    assert row["config"]["status"] == "invalid"
    assert row["config"]["locks"]["required_profile"] == "bad"
    assert {"unsafe-or-unreadable", "invalid-config", "unsafe-lock"} <= codes


def test_hostile_metadata_values_are_bounded_and_sanitized(project):
    (project / ".substrate/install.json").write_text(json.dumps(
        {"kit_version": "3.9.3\x1b[2J", "installed_at": "x" * 41,
         "owned_file_sha256": {}}))
    (project / ".claude/settings.json").write_text(json.dumps({"hooks": {
        "\ud800Evil\x1b]0;t\x07": [{"hooks": [{"command": "python3 a/scripts/\u0000x.py"},
                                             {"command": "python3 a/scripts/../../etc/x.py"},
                                             {"command": "python3 a/scripts/\x1b[2J‮x.py"}]},
                                  {"hooks": "not-a-list"}, 7],
        "Other": "not-a-list"}}))
    rep = api().report([project])
    row = rep["projects"][0]
    assert row["status"] == "ok"
    assert row["kit"]["installed_at"] is None and "\x1b" not in row["kit"]["version"]
    assert row["kit"]["provenance"] == "unavailable"
    [event] = [e for e in row["hooks"]["declared"] if e != "Other"]
    assert "\x1b" not in event and "\ud800" not in event
    refs = row["hooks"]["declared"][event]
    assert len(refs) == 3 and set(refs.values()) <= {"unsafe", "missing"}
    for ref in refs:
        assert "\x1b" not in ref and "‮" not in ref and "\x00" not in ref
    text = api().render_text(rep)
    text.encode("utf-8")
    assert "\x1b" not in text


def test_one_broken_project_never_aborts_or_hides_the_others(project, tmp_path, monkeypatch):
    deep = make_project(tmp_path / "deep", tmp_path / "markers")
    (deep / ".claude/settings.json").write_text("[" * 60000)
    rep = api().report([deep, project])
    assert "malformed-json" in {d["code"] for d in rep["projects"][0]["diagnostics"]}
    ps = api()
    real = ps._hooks

    def explode(root, diags):
        if root == deep.resolve():
            raise RuntimeError("unexpected")
        return real(root, diags)

    monkeypatch.setattr(ps, "_hooks", explode)
    rep = ps.report([deep, project])
    first, second = rep["projects"]
    assert first["status"] == "error" and second["status"] == "ok" and rep["errors"] == 1
    assert "inspection-failed" in {d["code"] for d in first["diagnostics"]}


def test_duplicate_and_symlinked_roots_collapse(project, tmp_path):
    link = tmp_path / "link to project"
    link.symlink_to(project)
    rep = api().report([project, Path(str(project) + "/"), link])
    assert len(rep["projects"]) == 1


def test_linked_worktrees_are_separate_projects_with_their_own_state(project, tmp_path):
    linked = tmp_path / "linked tree"
    git(project, "worktree", "add", "-q", "--detach", str(linked))
    (linked / "app.py").write_text("print('linked edit')\n")
    rep = api().report([project, linked])
    main, other = rep["projects"]
    assert (main["worktree"], other["worktree"]) == ("main", "linked")
    assert main["git"]["dirty"] == "clean" and other["git"]["dirty"] == "dirty"
    assert other["git"]["branch"] == "detached"


def test_latest_receipt_applicability_is_reported_without_running_checks(project, markers):
    receipt = api("task_receipt")
    task_id = receipt.start(project, "status fixture")
    receipt.annotate(project, task_id, "incomplete", note="half done")
    row = api().report([project])["projects"][0]
    assert row["latest_receipt"]["task_id"] == task_id
    assert row["latest_receipt"]["completion"] == "incomplete"
    assert row["latest_receipt"]["checks"] == {}
    assert row["latest_receipt"]["authentication"].startswith("unsigned")
    assert not any(markers.iterdir())


def test_latest_receipt_says_whether_its_check_still_applies(tmp_path):
    clean = init(tmp_path / "clean")
    (clean / "manage.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
    (clean / ".gitignore").write_text(".substrate/receipts/\n")
    (clean / "app.py").write_text("x = 1\n")
    git(clean, "add", ".")
    git(clean, "commit", "-qm", "clean")
    receipt = api("task_receipt")
    task_id = receipt.start(clean, "applicability")
    assert receipt.run_check(clean, task_id, "check", 30)["outcome"] == "passed"
    rep = api().report([clean])
    check = rep["projects"][0]["latest_receipt"]["checks"]["check"]
    assert (check["latest_outcome"], check["applies_to_current_state"]) == ("passed", "current")
    assert "(unsigned, recorded by that project)" in api().render_text(rep)
    (clean / "app.py").write_text("x = 2\n")
    check = api().report([clean])["projects"][0]["latest_receipt"]["checks"]["check"]
    assert check["applies_to_current_state"] == "stale"


def test_a_hooks_path_symlink_loop_is_an_unknown_not_a_crash(project, tmp_path):
    (project / "loop").symlink_to("loop")
    git(project, "config", "core.hooksPath", "loop/hooks")
    other = make_project(tmp_path / "after loop", tmp_path / "markers")
    rep = api().report([project, other])
    first, second = rep["projects"]
    assert set(first["hooks"]["git_hooks"].values()) <= {"unknown", "missing"}
    assert second["status"] == "ok"
    assert "after loop" in api().render_text(rep)


def test_target_text_is_bounded_so_one_project_cannot_crowd_out_the_rest(project, tmp_path):
    big = make_project(tmp_path / "big", tmp_path / "markers")
    (big / ".claude/settings.json").write_text(json.dumps({"hooks": {"E": [{"hooks": [
        {"command": "python3 " + "a" * 600_000 + "/scripts/x.py"}]}]}}))
    for i in range(60):
        (big / f"link{i}").symlink_to(big / "app.py")
    ps = api()
    rep = ps.report([big, project])
    row = rep["projects"][0]
    assert row["hooks"]["declared"]["E"] == {}
    assert len(row["diagnostics"]) == ps.MAX_DIAGNOSTICS and row["diagnostics_omitted"] >= 10
    assert "more diagnostics" in ps.render_text(rep)
    out = json.loads(ps.render_json(rep))
    assert "truncated_projects" not in out and len(out["projects"]) == 2


def test_text_report_names_what_is_and_is_not_checked(project):
    text = api().render_text(api().report([project]))
    assert "[ok]" in text and "kit: installed yes version 3.9.3" in text
    assert "profile strict" in text and "wired, not proven to run" in text
    assert "receipt: none" in text and "not checked" in text


def test_invalid_invocations_and_truncation_return_two(project, monkeypatch, capsys):
    ps = api()
    assert ps.main(["--root", str(project)]) == 0
    with pytest.raises(ValueError):
        ps.report([project] * (ps.MAX_ROOTS + 1))
    with pytest.raises(SystemExit):
        ps.main([])
    assert ps.main(["--root", "/definitely/missing/root"]) == 2
    capsys.readouterr()
    monkeypatch.setattr(ps, "JSON_LIMIT", 600)
    assert ps.main(["--root", str(project), "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["truncated_projects"] == 1 and out["projects"] == []
    monkeypatch.undo()
    proc = subprocess.run([sys.executable, str(ROOT / "scripts/project_status.py"),
                           "--root", str(project), "--json"],
                          capture_output=True, text=True, timeout=120)
    out = json.loads(proc.stdout)
    assert proc.returncode == 0 and out["schema_version"] == 1
    assert out["inspector"]["network"] == "off"
    assert re.fullmatch(r"\d+\.\d+\.\d+", out["inspector"]["kit_version"] or ""), out["inspector"]


def test_config_parser_splits_lines_like_the_shell(tmp_path):
    parse = api("check_substrate_config").parse_config_text
    hidden = "SUBSTRATE_PROFILE=standard\x0bSUBSTRATE_PROFILE=strict\n"
    vals, err = parse(hidden)
    # v3.10.5: refused before any line is read, by both loaders alike.
    assert err and "control character" in err
    cfg = tmp_path / "config"
    cfg.write_bytes(hidden.encode())
    shell = subprocess.run(["bash", "-c", f'source "{ROOT}/scripts/_substrate_config.sh"; '
                            f'load_substrate_config "{cfg}"'],
                           capture_output=True, text=True, timeout=30)
    assert shell.returncode == 2, "shell loader must reject what the Python parser rejects"
    assert "control character" in shell.stderr
    assert parse('SUBSTRATE_PROFILE="strict"  # pinned\nSUBSTRATE_LANG=python\n') == (
        {"SUBSTRATE_PROFILE": "strict", "SUBSTRATE_LANG": "python"}, None)


@pytest.mark.parametrize("profile", ["starter", "strict"])
def test_receipt_projects_and_brief_work_in_a_fresh_consumer(tmp_path, profile):
    if not (ROOT / "bootstrap.sh").exists():
        pytest.skip("source-kit bootstrap integration")
    consumer = init(tmp_path / "consumer with spaces")
    subprocess.run(["bash", str(ROOT / "bootstrap.sh"), "--target", str(consumer),
                    "--profile", profile, "--lang", "none", "--no-doctor"],
                   check=True, capture_output=True, timeout=180)
    assert ".substrate/receipts/" in (consumer / ".gitignore").read_text().splitlines()
    git(consumer, "add", ".")
    git(consumer, "commit", "-qm", "consumer fixture")

    def manage(*args):
        return subprocess.run(["bash", "manage.sh", *args], cwd=consumer,
                              capture_output=True, text=True, timeout=120)

    started = manage("receipt", "start", "--task", "consumer parity")
    assert started.returncode == 0, started.stdout + started.stderr
    task_id = started.stdout.strip()
    assert manage("receipt", "annotate", task_id, "--completion", "incomplete").returncode == 0
    shown = manage("receipt", "show", task_id, "--json")
    assert shown.returncode == 0
    assert json.loads(shown.stdout)["summary"]["completion"] == "incomplete"
    status = manage("projects", "--root", str(consumer), "--json")
    assert status.returncode == 0, status.stdout + status.stderr
    row = json.loads(status.stdout)["projects"][0]
    assert row["kit"]["installed"] == "yes" and row["latest_receipt"]["task_id"] == task_id
    assert row["config"]["profile"] == profile
    assert json.loads(status.stdout)["inspector"]["kit_version"] == row["kit"]["version"]
    assert row["git"]["dirty"] == "clean", "the receipt store must stay out of the working state"
    assert manage("receipt", "check", task_id, "--kind", "deploy").returncode == 2
    # A real known check, end to end in the installed project: evals runs offline
    # without setup and leaves the tree as it found it.
    ran = manage("receipt", "check", task_id, "--kind", "evals", "--timeout", "600")
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert "evals passed (exit 0); state unchanged" in ran.stdout
    evals = json.loads(manage("receipt", "show", task_id, "--json").stdout)["summary"]["checks"]
    assert evals["evals"]["latest_outcome"] == "passed"
    assert evals["evals"]["applies_to_current_state"] == "current"
    brief = manage("brief", "receipts", "--json")
    assert brief.returncode == 0, brief.stdout + brief.stderr
    assert json.loads(brief.stdout)["schema_version"] == 1


def test_release_package_excludes_every_local_state_store():
    """Receipts and execution scratch are local evidence: the source hash, the zip
    and the zip-hygiene check must all leave them out, or a maintainer's receipts
    ship to every consumer."""
    if not (ROOT / "package_release.sh").exists():
        pytest.skip("source-kit packaging")
    text = (ROOT / "package_release.sh").read_text()
    hygiene = next(line for line in text.splitlines() if line.startswith("_JUNK_RE="))
    for store in (".substrate/receipts", ".superpowers", ".substrate/memory",
                  ".substrate/traces"):
        assert f"/{store}/*'" in text, f"source hash includes {store}"
        assert f'"*/{store}/*"' in text, f"zip includes {store}"
        assert "/" + store.replace(".", "\\.") + "/" in hygiene, f"zip hygiene misses {store}"


def test_release_package_really_leaves_out_local_state(tmp_path):
    """v3.10.4: build a real package from a copy of the kit with a receipt and a
    .superpowers note planted in it. Neither may be in the zip, and the recorded
    source hash must equal the hash of a build without them."""
    import shutil
    import zipfile
    if not (ROOT / "package_release.sh").exists():
        pytest.skip("source-kit packaging")
    if shutil.which("zip") is None:
        pytest.skip("zip not installed")
    kit = tmp_path / ROOT.name
    shutil.copytree(ROOT, kit, ignore=shutil.ignore_patterns(
        ".git", ".venv", "venv", "dist", "__pycache__", ".pytest_cache", ".ruff_cache",
        "node_modules", "receipts", ".superpowers"))

    def build():
        proc = subprocess.run(["bash", "package_release.sh", "--smoke"], cwd=kit,
                              capture_output=True, text=True, timeout=600)
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-1000:]
        manifest = json.loads((kit / "dist" / "RELEASE_MANIFEST.json").read_text())
        [zip_path] = (kit / "dist").glob(f"{ROOT.name}-*.zip")
        return manifest["source_tree_sha256"], zipfile.ZipFile(zip_path).namelist()

    clean_hash, _ = build()
    receipt = kit / ".substrate" / "receipts" / "11111111-1111-4111-8111-111111111111"
    receipt.mkdir(parents=True)
    (receipt / "task.json").write_text('{"planted": true}\n')
    (kit / ".superpowers").mkdir()
    (kit / ".superpowers" / "note.md").write_text("planted\n")
    planted_hash, names = build()
    assert not [n for n in names if ".substrate/receipts" in n or ".superpowers" in n]
    assert planted_hash == clean_hash, "local state changed the release source hash"
