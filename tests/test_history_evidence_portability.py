"""Missing cross-clone proof is not invalid proof or permission for a new claim.

Keep this fixture self-contained: consumer installs omit kit-only test helpers.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest


def _record_repo(tmp_path):
    root = tmp_path / "history repo"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "scripts"
    for name in ("_doc_common.py", "_substrate_root.py", "_text_safety.py",
                 "memory_log.py", "append_history.py", "check_history_sha.py"):
        (scripts / name).write_bytes((source / name).read_bytes())
    (root / "docs").mkdir()
    (root / ".substrate").mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k != "CLAUDE_PROJECT_DIR"}
    env["SUBSTRATE_PROJECT_DIR"] = str(root)

    def git(*args):
        return subprocess.run(["git", *args], cwd=root, env=env,
                              capture_output=True, text=True, timeout=20)

    def run(script, *args):
        return subprocess.run([sys.executable, "-I", str(scripts / script), *args],
                              cwd=root, env=env, capture_output=True, text=True, timeout=60)

    for args in (("init", "-q"), ("config", "user.email", "test@example.invalid"),
                 ("config", "user.name", "Test"), ("config", "commit.gpgsign", "false"),
                 ("add", "scripts"), ("commit", "-qm", "init")):
        result = git(*args)
        assert result.returncode == 0, result.stderr
    return root, git, lambda *args: run("memory_log.py", *args), run


def _events_path(root):
    return root / ".substrate" / "memory" / "events.jsonl"


def _hist_args(sha, outcome):
    return ["--commit-hash", sha, "--summary", "a summary long enough", "--files", "f",
            "--intent", "an intent long enough", "--knowledge", "knowledge long enough",
            "--outcome", outcome]


def _entry(sha, token="IMPORT", summary="imported release"):
    return (f"## 2099-01-01T00:00:00Z — {token} — {sha}\n"
            f"**Summary:** {summary}\n**Outcome:** shipped-green\n\n")


def _imported(tmp_path, proof=None):
    root, git, memory, run = _record_repo(tmp_path)
    sha = git("rev-parse", "HEAD").stdout.strip()
    if proof is not None:
        assert memory("release-pass", "--commit", sha,
                      "--clean-start", proof).returncode == 0
    text = "# HISTORY\n\n" + _entry(sha)
    path = root / "docs" / "HISTORY.md"
    path.write_text(text, encoding="utf-8")
    assert git("add", "docs/HISTORY.md").returncode == 0
    assert git("commit", "-qm", "imported history").returncode == 0
    return root, git, memory, run, path, text, sha


@pytest.mark.parametrize("local_note", [False, True])
def test_imported_history_survives_an_unrelated_local_chain(tmp_path, local_note):
    _, _, memory, run, _, _, _ = _imported(tmp_path)
    if local_note:
        assert memory("append", "--type", "note", "--message", "local session").returncode == 0
        assert memory("verify").returncode == 0
    result = run("check_history_sha.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "NOT verifiable in this checkout" in result.stdout
    assert "0 locally-verified" in result.stdout


@pytest.mark.parametrize("mutation", ["edit", "duplicate", "new"])
@pytest.mark.parametrize("local_note", [False, True])
def test_new_or_changed_claim_cannot_borrow_imported_provenance(tmp_path, mutation, local_note):
    _, _, memory, run, path, original, sha = _imported(tmp_path)
    if local_note:
        assert memory("append", "--type", "note", "--message", "local session").returncode == 0
    if mutation == "edit":
        text = original.replace("imported release", "a different release assertion")
    elif mutation == "duplicate":
        text = original + _entry(sha)
    else:
        text = original + _entry(sha, "NEW")
    path.write_text(text, encoding="utf-8")
    result = run("check_history_sha.py")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "new or modified" in result.stderr


@pytest.mark.parametrize("damage", ["broken", "linked", "directory", "bad-bytes"])
def test_imported_claim_does_not_hide_invalid_chain(tmp_path, damage):
    root, _, memory, run, _, _, _ = _imported(tmp_path)
    assert memory("append", "--type", "note", "--message", "local session").returncode == 0
    chain = _events_path(root)
    if damage == "broken":
        chain.write_text('{"seq": 1, "hash": "wrong"}\n', encoding="utf-8")
    elif damage == "bad-bytes":
        chain.write_bytes(b"\xff\xfe")
    else:
        chain.unlink()
        if damage == "linked":
            outside = tmp_path / "outside.jsonl"
            outside.write_text("", encoding="utf-8")
            chain.symlink_to(outside)
        else:
            chain.mkdir()
    result = run("check_history_sha.py")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "memory chain" in result.stderr


@pytest.mark.parametrize("proof, expected", [("no", 1), ("yes", 0)])
def test_matching_release_pass_remains_authoritative(tmp_path, proof, expected):
    _, _, _, run, _, _, _ = _imported(tmp_path, proof)
    result = run("check_history_sha.py")
    assert result.returncode == expected, result.stdout + result.stderr
    if proof == "no":
        assert "DIRTY tree" in result.stderr
    else:
        assert "1 locally-verified" in result.stdout


def test_missing_evidence_is_still_refused_by_writer(tmp_path):
    _, _, _, run, _, _, sha = _imported(tmp_path)
    result = run("append_history.py", *_hist_args(sha, "shipped-green"))
    assert result.returncode == 1 and "release-gate evidence" in result.stderr


def test_other_commits_clean_pass_cannot_verify_this_claim(tmp_path):
    _, git, memory, run, _, _, sha = _imported(tmp_path)
    other = git("rev-parse", "HEAD").stdout.strip()
    assert other != sha
    assert memory("release-pass", "--commit", other, "--clean-start", "yes").returncode == 0
    result = run("check_history_sha.py")
    assert result.returncode == 0 and "0 locally-verified" in result.stdout
    assert "1 imported-unverified" in result.stdout
    result = run("append_history.py", *_hist_args(sha, "shipped-green"))
    assert result.returncode == 1 and "no release-pass event" in result.stderr


def test_union_merge_uses_both_parents_without_double_counting(tmp_path):
    root, git, _, run, path, original, sha = _imported(tmp_path)
    (root / ".gitattributes").write_text("docs/HISTORY.md merge=union\n", encoding="utf-8")
    assert git("add", ".gitattributes").returncode == 0
    assert git("commit", "-qm", "union history").returncode == 0
    assert git("checkout", "-qb", "side").returncode == 0
    path.write_text(original + _entry(sha, "SIDE"), encoding="utf-8")
    assert git("commit", "-qam", "side import").returncode == 0
    assert git("checkout", "-qb", "local", "HEAD~1").returncode == 0
    path.write_text(original + _entry(sha, "LOCAL"), encoding="utf-8")
    assert git("commit", "-qam", "local import").returncode == 0
    assert git("merge", "--no-commit", "--no-ff", "side").returncode == 0
    # Resolve the union as complete entries. Git's line-based union may coalesce
    # these deliberately identical bodies; that is not the gate under test.
    path.write_text(original + _entry(sha, "LOCAL") + _entry(sha, "SIDE"), encoding="utf-8")
    result = run("check_history_sha.py")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "3 imported-unverified" in result.stdout
    # The common parent's entry occurs in BOTH parents, but was only present once.
    path.write_text(path.read_text(encoding="utf-8") + _entry(sha), encoding="utf-8")
    result = run("check_history_sha.py")
    assert result.returncode == 1 and "new or modified" in result.stderr


@pytest.mark.parametrize("failure", ["malformed-parent", "missing-parent", "missing-blob"])
def test_baseline_git_failure_is_not_import_permission(tmp_path, failure):
    root, git, _, run, _, _, _ = _imported(tmp_path)
    # Keep HEAD and all commits readable; a malformed merge head must not be
    # silently treated as 'no merge', permitting an incomplete provenance read.
    if failure == "missing-blob":
        oid = git("rev-parse", "HEAD:docs/HISTORY.md").stdout.strip()
        (root / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
    else:
        ref = "not-a-commit" if failure == "malformed-parent" else "f" * 40
        (root / ".git" / "MERGE_HEAD").write_text(ref + "\n", encoding="utf-8")
    result = run("check_history_sha.py")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "committed HISTORY" in result.stderr
