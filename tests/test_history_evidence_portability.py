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
    # GITHUB_* and SUBSTRATE_HISTORY_BASE choose the HISTORY base; a test that wants
    # CI behaviour sets them itself, so the suite behaves the same under Actions.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "GITHUB_"))
           and k not in ("CLAUDE_PROJECT_DIR", "SUBSTRATE_HISTORY_BASE")}
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


def _branch_with_forged_claim(tmp_path, local_chain):
    """origin/main carries one imported entry; a branch then commits a forged
    shipped-green entry with no release pass, as `git commit --no-verify` would."""
    root, git, memory, run, path, original, sha = _imported(tmp_path)
    assert git("update-ref", "refs/remotes/origin/main", "HEAD").returncode == 0
    assert git("checkout", "-qb", "feature").returncode == 0
    path.write_text(original + _entry(sha, "FORGED", "a release that never ran"), encoding="utf-8")
    assert git("commit", "-qam", "forged claim").returncode == 0
    if local_chain:
        assert memory("append", "--type", "note", "--message", "local session").returncode == 0
    return root, git, run


def test_a_committed_claim_not_on_the_base_needs_local_proof(tmp_path):
    """v3.10.5: imported meant "committed at HEAD", so a forged entry committed with
    --no-verify read as imported-unverified forever."""
    _, _, run = _branch_with_forged_claim(tmp_path, local_chain=True)
    result = run("check_history_sha.py")
    assert result.returncode == 1 and "new or modified" in result.stderr
    assert "1 imported" not in result.stdout


def _clean_env(root, **extra):
    """The caller's GitHub variables never leak in: run under Actions, an inherited
    GITHUB_ACTIONS turned these fixtures into CI runs."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_", "GITHUB_")) and k != "SUBSTRATE_HISTORY_BASE"}
    return {**env, "SUBSTRATE_PROJECT_DIR": str(root), **extra}


@pytest.mark.parametrize("actions", [False, True])
def test_without_a_chain_a_new_claim_is_named_for_review_not_imported(tmp_path, actions):
    """CI has no memory chain, so a release PR's own entry cannot be proven there;
    it passes, but is named as new and unverified instead of counted as imported."""
    root, _, run = _branch_with_forged_claim(tmp_path, local_chain=False)
    extra = {"GITHUB_ACTIONS": "true", "GITHUB_BASE_REF": "main"} if actions else {}
    result = subprocess.run([sys.executable, "-I", str(root / "scripts" / "check_history_sha.py")],
                            cwd=root, capture_output=True, text=True, timeout=60,
                            env=_clean_env(root, **extra))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 imported-unverified" in result.stdout and "1 new-unverified" in result.stdout
    marker = "::warning title=Unverified shipped-green::" if actions else "WARNING"
    assert marker in result.stdout and "not on refs/remotes/origin/main" in result.stdout


def test_history_text_cannot_start_a_workflow_command(tmp_path):
    root, git, _, run, path, original, sha = _imported(tmp_path)
    path.write_text(original + "## ::add-mask::x \u2014 T \u2014 " + sha
                    + "\n**Summary:** s\n**Outcome:** shipped-green\n**Outcome:** wip\n\n",
                    encoding="utf-8")
    result = run("check_history_sha.py")
    assert result.returncode == 1
    assert "::add-mask::" not in result.stderr and "::" not in result.stderr


def test_a_release_pass_on_a_dirty_tree_cannot_claim_a_clean_start(tmp_path):
    """v3.10.5: `memory release-pass --clean-start yes` took the caller's word; run by
    hand on a dirty tree it minted the evidence shipped-green needs."""
    root, git, memory, run = _record_repo(tmp_path)
    sha = git("rev-parse", "HEAD").stdout.strip()
    (root / "scripts" / "memory_log.py").write_text(
        (root / "scripts" / "memory_log.py").read_text(encoding="utf-8") + "\n# dirty\n",
        encoding="utf-8")
    assert memory("release-pass", "--commit", sha, "--clean-start", "yes").returncode == 0
    result = run("append_history.py", *_hist_args(sha, "shipped-green"))
    assert result.returncode == 1 and "DIRTY tree" in result.stderr


def test_a_verified_self_audit_cannot_be_appended_by_hand(tmp_path):
    """v3.10.5 audit: `memory append --type skill-run` wrote a verified self-audit
    and silenced the completion nudge."""
    root, git, memory, run = _record_repo(tmp_path)
    result = memory("append", "--type", "skill-run", "--message", "audited")
    assert result.returncode != 0 and "reserved" in (result.stdout + result.stderr).lower()


def test_an_unrelated_or_missing_base_is_an_error_not_an_import(tmp_path, monkeypatch):
    """v3.10.5 audit: a merge-base failure, or no base in CI, fell back to "everything
    committed at HEAD is imported"."""
    root, git, memory, run, path, original, sha = _imported(tmp_path)
    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    assert git("checkout", "-q", "--orphan", "other").returncode == 0
    assert git("commit", "-qm", "unrelated root").returncode == 0
    assert git("update-ref", "refs/remotes/origin/main", "HEAD").returncode == 0
    assert git("checkout", "-q", branch).returncode == 0
    result = run("check_history_sha.py")
    assert result.returncode == 2 and "shares no history" in result.stderr
    assert git("update-ref", "-d", "refs/remotes/origin/main").returncode == 0
    result = subprocess.run([sys.executable, "-I", str(root / "scripts" / "check_history_sha.py")],
                            cwd=root, capture_output=True, text=True, timeout=60,
                            env=_clean_env(root, GITHUB_ACTIONS="true"))
    assert result.returncode == 2 and "SUBSTRATE_HISTORY_BASE" in result.stderr


def test_editing_an_entry_already_on_the_base_is_a_finding_even_without_a_chain(tmp_path):
    """v3.10.5 audit: an edited OLD shipped-green entry only drew a new-unverified
    warning in CI; HISTORY is append-only."""
    root, git, memory, run, path, original, sha = _imported(tmp_path)
    assert git("update-ref", "refs/remotes/origin/main", "HEAD").returncode == 0
    path.write_text(original.replace("imported release", "a rewritten release"), encoding="utf-8")
    assert git("commit", "-qam", "edit an old entry").returncode == 0
    result = run("check_history_sha.py")
    assert result.returncode == 1 and "never edited" in result.stderr
