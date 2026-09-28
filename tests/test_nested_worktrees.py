"""A linked worktree nested in the checkout is its own tree: the drift and harness checks stop
at it, and only at it.

Ported in v3.9.1 from the consumer that found and fixed it (domain-lookup a350bd4,
where three live sessions produced 369 false coverage gaps). The Claude app checks each session out at .claude/worktrees/<name>/, inside the main checkout
and git-ignored through .git/info/exclude. check-doc-drift and check-agent-harness walk the file
system, so from the main checkout they read every session's copy of the repository: drift
reported each copied module as a COVERAGE GAP, the harness scanner blocked on the copied
scripts/harness_patterns.json, and no commit from the main checkout could pass (2026-09-27).

A nested worktree's files belong to that worktree. Its own hooks check them when it commits, and
a CI checkout never holds one. So the checks skip a directory only when git has registered it as
a linked worktree and its .git file and admin directory name each other. A plain directory beside
it, a copied or swapped .git file, a pruned worktree, a submodule, a nested clone and every file
of the main tree are still checked, and nothing is skipped when git cannot answer. Each test runs
the real hook script against a real repository.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
HARNESS_FILES = (
    "check_agent_harness.py",
    "_substrate_root.py",
    "_substrate_surfaces.py",
    "_doc_common.py",
    "harness_patterns.json",
)
DRIFT_FILES = ("check_doc_drift.py", "_doc_common.py", "_substrate_surfaces.py")
# The harness pattern data outside its one allowlisted path: the file that blocked the main
# checkout, and a real permission-bypass / hook-trust-bypass finding wherever it is copied.
DANGER = (SCRIPTS / "harness_patterns.json").read_text(encoding="utf-8")


def _env() -> dict[str, str]:
    """The environment of a plain shell, whatever the running hook inherited.

    git exports GIT_DIR and GIT_INDEX_FILE to a hook it runs from a linked worktree; left in
    place, every git command below would act on the real repository. SUBSTRATE_PROJECT_DIR and
    CLAUDE_PROJECT_DIR would point the scanners at it.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.pop("SUBSTRATE_PROJECT_DIR", None)
    env.pop("CLAUDE_PROJECT_DIR", None)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.com", *args],
        cwd=cwd,
        env=_env(),
        check=True,
        capture_output=True,
        timeout=30,
    )


def _repo(tmp_path: Path, scripts: tuple[str, ...], files: dict[str, str]) -> Path:
    """A committed repository holding copies of the hook scripts and `files`."""
    root = tmp_path.resolve() / "repo"
    (root / "scripts").mkdir(parents=True)
    for name in scripts:
        shutil.copy2(SCRIPTS / name, root / "scripts" / name)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    _git(root, "init", "-q", "-b", "main")
    exclude = root / ".git" / "info" / "exclude"
    exclude.parent.mkdir(exist_ok=True)
    with exclude.open("a", encoding="utf-8") as handle:
        handle.write(".claude/worktrees/\n")  # as the app leaves it
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "init")
    return root


def _worktree(root: Path, rel: str) -> Path:
    _git(root, "worktree", "add", "-q", rel, "-b", Path(rel).name)
    return root / rel


def _run(
    cwd: Path, script: str, *args: str, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", f"scripts/{script}", *args],
        cwd=cwd,
        env={**_env(), **(extra_env or {})},
        capture_output=True,
        text=True,
        timeout=60,
    )


def _harness_repo(tmp_path: Path) -> Path:
    return _repo(
        tmp_path,
        HARNESS_FILES,
        {
            "AGENTS.md": "# Agent rules\n\n- Run the tests after every edit.\n",
            ".substrate/config": 'SUBSTRATE_PROFILE="standard"\n',
        },
    )


def _plant(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(DANGER, encoding="utf-8")


def test_harness_passes_in_a_main_checkout_holding_a_session_worktree(tmp_path: Path) -> None:
    root = _harness_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "agent-harness: ok" in result.stdout


def test_harness_still_blocks_the_main_trees_own_claude_files(tmp_path: Path) -> None:
    root = _harness_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")
    _plant(root / ".claude" / "settings.local.json")

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 1
    assert "BLOCK: permission bypass: .claude/settings.local.json:" in result.stdout
    assert "BLOCK: hook-trust bypass: .claude/settings.local.json:" in result.stdout
    assert ".claude/worktrees/" not in result.stdout


def test_harness_scans_a_plain_directory_beside_the_worktree(tmp_path: Path) -> None:
    """The path exempts nothing: this directory even shares the worktree's name as a prefix."""
    root = _harness_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")
    _plant(root / ".claude" / "worktrees" / "wt-notes" / "patterns.json")

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 1
    assert "BLOCK: permission bypass: .claude/worktrees/wt-notes/patterns.json:" in result.stdout
    assert ".claude/worktrees/wt/" not in result.stdout


def test_harness_scans_a_directory_holding_a_copied_git_file(tmp_path: Path) -> None:
    """A directory git never registered is not a worktree, whatever .git file it holds."""
    root = _harness_repo(tmp_path)
    worktree = _worktree(root, ".claude/worktrees/wt")
    fake = root / ".claude" / "worktrees" / "fake"
    fake.mkdir()
    shutil.copy2(worktree / ".git", fake / ".git")
    _plant(fake / "patterns.json")

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 1
    assert "BLOCK: permission bypass: .claude/worktrees/fake/patterns.json:" in result.stdout


def test_harness_ignores_a_helper_that_names_directories_it_should_not(tmp_path: Path) -> None:
    """The hash-pinned scanner re-checks each directory the unpinned helper names.

    _substrate_surfaces.py carries no pin. Edited to name an ordinary directory and one holding a
    copy of a real worktree's .git file, the helper must exempt neither: only a .git file whose
    admin directory names it back does, and git never tracks a `.git` path, so nothing committed
    can qualify. The real worktree it also names is still skipped.
    """
    root = _harness_repo(tmp_path)
    worktree = _worktree(root, ".claude/worktrees/wt")
    fake = root / ".claude" / "worktrees" / "fake"
    fake.mkdir()
    shutil.copy2(worktree / ".git", fake / ".git")
    _plant(fake / "patterns.json")
    _plant(root / ".claude" / "hooks" / "patterns.json")
    surfaces = root / "scripts" / "_substrate_surfaces.py"
    surfaces.write_text(
        surfaces.read_text(encoding="utf-8")
        + "\n\ndef nested_worktrees(root):\n"
        + "    return ('.claude/hooks', '.claude/worktrees/fake', '.claude/worktrees/wt')\n",
        encoding="utf-8",
    )

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 1
    assert "BLOCK: permission bypass: .claude/hooks/patterns.json:" in result.stdout
    assert "BLOCK: permission bypass: .claude/worktrees/fake/patterns.json:" in result.stdout
    assert ".claude/worktrees/wt/" not in result.stdout


def test_harness_scans_skills_vendored_as_a_submodule_or_a_clone(tmp_path: Path) -> None:
    """A skill vendored as a submodule or a nested clone is agent context: only a linked
    worktree is another tree."""
    skill = tmp_path.resolve() / "skill"
    skill.mkdir()
    _plant(skill / "patterns.json")
    _git(skill, "init", "-q", "-b", "main")
    _git(skill, "add", "-A")
    _git(skill, "commit", "-q", "-m", "skill")
    root = _harness_repo(tmp_path)
    _git(root, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(skill),
         ".claude/skills/vendored")
    _git(root, "clone", "-q", str(skill), ".claude/skills/cloned")

    result = _run(root, "check_agent_harness.py")

    assert result.returncode == 1
    assert "BLOCK: permission bypass: .claude/skills/vendored/patterns.json:" in result.stdout
    assert "BLOCK: permission bypass: .claude/skills/cloned/patterns.json:" in result.stdout


def test_harness_skips_nothing_when_git_cannot_list_worktrees(tmp_path: Path) -> None:
    """No git on PATH: the nested worktree's copy of the pattern data is scanned and blocks."""
    root = _harness_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")
    no_git = tmp_path / "empty-path"
    no_git.mkdir()

    result = _run(root, "check_agent_harness.py", extra_env={"PATH": str(no_git)})

    assert result.returncode == 1
    assert (
        "BLOCK: permission bypass: .claude/worktrees/wt/scripts/harness_patterns.json:"
        in result.stdout
    )


@pytest.mark.parametrize("in_hook", [False, True], ids=["shell", "commit-hook"])
def test_a_session_worktree_scans_its_own_files(tmp_path: Path, in_hook: bool) -> None:
    """What the main checkout skips, the worktree's own hook catches.

    git runs the hooks of a commit made in a linked worktree with GIT_DIR and GIT_INDEX_FILE
    naming that worktree's admin dir (a main-checkout commit gets GIT_INDEX_FILE only); the
    helper's `git worktree list` inherits them and must answer the same.
    """
    root = _harness_repo(tmp_path)
    worktree = _worktree(root, ".claude/worktrees/wt")
    _plant(worktree / ".claude" / "settings.local.json")
    admin = root / ".git" / "worktrees" / "wt"
    main_hook = {"GIT_INDEX_FILE": str(root / ".git" / "index")} if in_hook else {}
    worktree_hook = (
        {"GIT_DIR": str(admin), "GIT_INDEX_FILE": str(admin / "index")} if in_hook else {}
    )

    assert _run(root, "check_agent_harness.py", extra_env=main_hook).returncode == 0
    inside = _run(worktree, "check_agent_harness.py", extra_env=worktree_hook)

    assert inside.returncode == 1
    assert "BLOCK: permission bypass: .claude/settings.local.json:" in inside.stdout


def _drift_repo(tmp_path: Path) -> Path:
    covers = (
        "scripts/_doc_common.py",
        "scripts/_substrate_surfaces.py",
        "scripts/check_doc_drift.py",
        "src/app.py",
    )
    doc = (
        "---\npurpose: test subsystem\nlast_human_reviewed: 2999-12-31\ncovers:\n"
        + "".join(f"  - {path}\n" for path in covers)
        + "---\n\n# Test subsystem\n"
    )
    manifest = {"knowledge_docs": [{"path": "docs/knowledge/00_test.md"}]}
    return _repo(
        tmp_path,
        DRIFT_FILES,
        {
            "src/app.py": "VALUE = 1\n",
            "docs/knowledge/00_test.md": doc,
            "docs/manifest.json": json.dumps(manifest),
        },
    )


def _coverage_gaps(cwd: Path) -> list[str]:
    result = _run(cwd, "check_doc_drift.py", "--json")
    assert result.returncode == 0, result.stderr
    gaps: list[str] = json.loads(result.stdout)["coverage_gap"]
    return gaps


def test_drift_passes_in_a_main_checkout_holding_nested_worktrees(tmp_path: Path) -> None:
    root = _drift_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")
    _worktree(root, ".worktrees/other")  # any linked worktree, not only the app's layout

    result = _run(root, "check_doc_drift.py", "--strict")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "doc-drift: no drift detected." in result.stdout


def test_drift_still_reports_uncovered_modules_outside_the_worktree(tmp_path: Path) -> None:
    root = _drift_repo(tmp_path)
    _worktree(root, ".claude/worktrees/wt")
    (root / "src" / "new.py").write_text("VALUE = 2\n", encoding="utf-8")
    plain = root / ".claude" / "worktrees" / "wt-notes"
    plain.mkdir()
    (plain / "tool.py").write_text("VALUE = 3\n", encoding="utf-8")

    assert _coverage_gaps(root) == [".claude/worktrees/wt-notes/tool.py", "src/new.py"]


def test_drift_checks_a_pruned_worktrees_leftover_files(tmp_path: Path) -> None:
    """git still lists a worktree whose .git file is gone, as prunable: it is a plain directory."""
    root = _drift_repo(tmp_path)
    worktree = _worktree(root, ".claude/worktrees/wt")
    (worktree / ".git").unlink()

    assert _coverage_gaps(root) == [
        ".claude/worktrees/wt/scripts/_doc_common.py",
        ".claude/worktrees/wt/scripts/_substrate_surfaces.py",
        ".claude/worktrees/wt/scripts/check_doc_drift.py",
        ".claude/worktrees/wt/src/app.py",
    ]


def test_drift_checks_a_worktree_whose_git_file_names_another(tmp_path: Path) -> None:
    """git still lists wt2, but its .git file now names wt's admin dir, which names wt back."""
    root = _drift_repo(tmp_path)
    first = _worktree(root, ".claude/worktrees/wt")
    second = _worktree(root, ".claude/worktrees/wt2")
    shutil.copy2(first / ".git", second / ".git")

    assert _coverage_gaps(root) == [
        ".claude/worktrees/wt2/scripts/_doc_common.py",
        ".claude/worktrees/wt2/scripts/_substrate_surfaces.py",
        ".claude/worktrees/wt2/scripts/check_doc_drift.py",
        ".claude/worktrees/wt2/src/app.py",
    ]


def test_drift_inside_a_session_worktree_checks_its_own_modules(tmp_path: Path) -> None:
    root = _drift_repo(tmp_path)
    worktree = _worktree(root, ".claude/worktrees/wt")
    (worktree / "src" / "new.py").write_text("VALUE = 2\n", encoding="utf-8")

    assert _coverage_gaps(worktree) == ["src/new.py"]


# --- v3.9.1: the kit's other walkers, which the consumer fix did not reach ---------

LEAK_FILES = ("check_leaks.py", "_substrate_surfaces.py", "_doc_common.py")
# Built at runtime so this source file never holds the shape it plants.
_FAKE_KEY = "AKIA" + "QX7" * 5 + "Z"


def test_leak_scan_skips_a_session_worktree_but_not_a_plain_directory(tmp_path: Path) -> None:
    """The leak scanner walks the whole tree; a session worktree's files are that
    tree's, while a plain directory beside it is still this tree's and still scanned."""
    root = _repo(tmp_path, LEAK_FILES, {"README.md": "clean\n"})
    wt = _worktree(root, ".claude/worktrees/wt")
    (wt / "notes.md").write_text(f"key = {_FAKE_KEY}\n", encoding="utf-8")
    result = _run(root, "check_leaks.py")
    assert result.returncode == 0, result.stdout + result.stderr

    plain = root / ".claude" / "scratch" / "notes.md"
    plain.parent.mkdir(parents=True, exist_ok=True)
    plain.write_text(f"key = {_FAKE_KEY}\n", encoding="utf-8")
    result = _run(root, "check_leaks.py")
    assert result.returncode == 1 and ".claude/scratch/notes.md" in result.stderr


def test_install_baseline_does_not_vouch_for_a_session_worktree(tmp_path: Path) -> None:
    """write_install_json hashed every file under .claude/, including each session's
    worktree copy — one consumer's baseline was 288/470 entries of scratch trees."""
    root = _repo(tmp_path, ("write_install_json.py", "_substrate_surfaces.py", "_doc_common.py"),
                 {".claude/settings.json": "{}\n", "AGENTS.md": "# a\n"})
    _worktree(root, ".claude/worktrees/wt")
    probe = (
        "import sys; sys.path.insert(0, 'scripts')\n"
        "import write_install_json as w\n"
        "print('\\n'.join(w.owned_files(__import__('pathlib').Path('.').resolve())))\n"
    )
    out = subprocess.run([sys.executable, "-c", probe], cwd=root, env=_env(),
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    owned = out.stdout.split()
    assert ".claude/settings.json" in owned
    assert not [p for p in owned if p.startswith(".claude/worktrees/")], owned


def test_under_needs_a_path_boundary() -> None:
    """`.claude/worktrees/wt` must not cover `.claude/worktrees/wt2` or `wtx.md`."""
    sys.path.insert(0, str(SCRIPTS))
    from _substrate_surfaces import under
    trees = (".claude/worktrees/wt",)
    assert under(".claude/worktrees/wt/AGENTS.md", trees)
    assert under(".claude/worktrees/wt", trees)
    assert not under(".claude/worktrees/wt2/AGENTS.md", trees)
    assert not under(".claude/worktrees/wtx.md", trees)
