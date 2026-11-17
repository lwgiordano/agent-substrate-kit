"""Edit presence: two sessions in one checkout learn of each other at the file
they are both writing, without a person carrying notes between them.
Self-contained so copied consumer tests can run."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts").is_dir() and (p / "manage.sh").is_file())
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
ep = pytest.importorskip("edit_presence")

ALICE = "session-alice-0001"
BOB = "session-bob-0002"
CAROL = "session-carol-0003"
DOC = "docs/a.md"


def _tag(session: str) -> str:
    """The six characters a note shows for a session."""
    return ep.session_key(session)[:6]


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "docs").mkdir(parents=True)
    (root / ".substrate").mkdir()
    for name in ("a.md", "b.md"):
        (root / "docs" / name).write_text("text\n", encoding="utf-8")
    return root


def _env(root: Path, **extra) -> dict:
    env = {k: v for k, v in os.environ.items()
           if k != "CLAUDE_PROJECT_DIR" and not k.startswith("SUBSTRATE_EDIT_PRESENCE")}
    env.update(SUBSTRATE_PROJECT_DIR=str(root), SUBSTRATE_USAGE_LOG="0")
    env.update(extra)
    return env


def _hook(root: Path, when: str, session: str | None, rel: str = DOC, tool_input=None, **extra):
    payload = {"tool_name": "Edit", "tool_input": tool_input or {"file_path": str(root / rel)}}
    if session is not None:
        payload["session_id"] = session
    return subprocess.run([sys.executable, str(SCRIPTS / "edit_presence.py"), when],
                          input=json.dumps(payload), cwd=str(root), env=_env(root, **extra),
                          capture_output=True, text=True, timeout=30)


def _marker(root: Path, session: str, rel: str = DOC) -> Path:
    return (root / ".substrate" / "usage" / "presence" / ep.path_key(rel)
            / f"{ep.session_key(session)}.json")


def _age(root: Path, session: str, seconds: float, rel: str = DOC) -> None:
    """Make `session`'s last write to `rel` look `seconds` older."""
    marker = _marker(root, session, rel)
    data = json.loads(marker.read_text(encoding="utf-8"))
    data["at"] -= seconds
    marker.write_text(json.dumps(data), encoding="utf-8")


def test_the_first_writer_hears_nothing_and_leaves_a_marker(tmp_path) -> None:
    root = _repo(tmp_path)
    p = _hook(root, "after", ALICE)
    assert (p.returncode, p.stderr) == (0, ""), p.stderr
    data = json.loads(_marker(root, ALICE).read_text(encoding="utf-8"))
    assert data["path"] == DOC and abs(data["at"] - time.time()) < 60, data


def test_a_second_session_is_told_once_for_each_write_by_the_other(tmp_path) -> None:
    """The whole point. Each side learns of the other at its own next write to
    the shared file, once, and again only when the other writes again."""
    root = _repo(tmp_path)
    assert _hook(root, "after", ALICE).returncode == 0
    told = _hook(root, "after", BOB)
    assert told.returncode == 2, told.stderr
    assert "another session" in told.stderr and DOC in told.stderr
    assert _tag(ALICE) in told.stderr and _tag(BOB) not in told.stderr
    assert "docs/b.md" not in told.stderr
    # The write went through, so the note has to say so or the agent redoes it.
    assert "was applied" in told.stderr
    assert _hook(root, "after", BOB).returncode == 0          # nothing new since
    back = _hook(root, "after", ALICE)                         # and Alice hears of Bob
    assert back.returncode == 2 and DOC in back.stderr
    assert _tag(BOB) in back.stderr and _tag(ALICE) not in back.stderr
    assert _hook(root, "after", ALICE).returncode == 0
    again = _hook(root, "after", BOB)                          # Alice wrote twice since
    assert again.returncode == 2, again.stderr


def test_with_two_others_on_the_file_the_note_counts_them_and_names_the_latest(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _age(root, ALICE, 300)
    _hook(root, "after", BOB)
    _age(root, BOB, 60)
    told = _hook(root, "after", CAROL)
    assert told.returncode == 2, told.stderr
    assert "2 other sessions" in told.stderr
    assert _tag(BOB) in told.stderr and _tag(ALICE) not in told.stderr
    assert _hook(root, "after", CAROL).returncode == 0


def test_hold_still_records_and_still_says_who_else_is_here(tmp_path) -> None:
    """`before` can pass and the other session write a moment later, so `after`
    behaves the same in every setting but `off`."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE, SUBSTRATE_EDIT_PRESENCE="hold")
    told = _hook(root, "after", BOB, SUBSTRATE_EDIT_PRESENCE="hold")
    assert told.returncode == 2 and _tag(ALICE) in told.stderr, told.stderr
    assert _marker(root, BOB).exists()


@pytest.mark.parametrize("seen", ["x", True, None, -1, 9e18])
def test_a_damaged_marker_costs_one_repeated_note_and_no_error(tmp_path, seen) -> None:
    """What a session has already been told lives in its own marker. If that
    is lost or nonsense the session is told again, once, and the marker heals."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    assert _hook(root, "after", BOB).returncode == 2
    data = json.loads(_marker(root, BOB).read_text(encoding="utf-8"))
    data["seen"] = seen
    _marker(root, BOB).write_text(json.dumps(data), encoding="utf-8")
    again = _hook(root, "after", BOB)
    assert again.returncode == 2, again.stderr
    assert "Traceback" not in again.stderr
    assert _hook(root, "after", BOB).returncode == 0


def test_the_note_never_carries_a_session_id(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    told = _hook(root, "after", BOB)
    assert ALICE not in told.stderr and BOB not in told.stderr
    assert ep.session_key(ALICE)[:6] in told.stderr           # a tag, to tell two others apart


def test_the_same_session_and_other_files_are_silent(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    assert _hook(root, "after", ALICE).returncode == 0
    assert _hook(root, "after", BOB, rel="docs/b.md").returncode == 0


def test_a_write_outside_the_window_is_not_news(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _age(root, ALICE, 11 * 60)
    assert _hook(root, "after", BOB).returncode == 0           # default window: 10 minutes
    _hook(root, "after", ALICE)
    _age(root, ALICE, 11 * 60)
    wide = _hook(root, "after", BOB, SUBSTRATE_EDIT_PRESENCE_MINUTES="30")
    assert wide.returncode == 2, wide.stderr


def test_hold_refuses_before_the_write_until_the_file_is_quiet(tmp_path) -> None:
    """`hold` is the strict setting: while another session's window is live,
    this session's write is refused before it happens. The default never
    refuses a write."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    assert _hook(root, "before", BOB).returncode == 0          # notice mode: never refuses
    held = _hook(root, "before", BOB, SUBSTRATE_EDIT_PRESENCE="hold")
    assert held.returncode == 2, held.stderr
    assert DOC in held.stderr and "not applied" in held.stderr
    hold = {"SUBSTRATE_EDIT_PRESENCE": "hold"}
    assert _hook(root, "before", ALICE, **hold).returncode == 0
    assert _hook(root, "before", BOB, rel="docs/b.md", **hold).returncode == 0
    _age(root, ALICE, 11 * 60)
    assert _hook(root, "before", BOB, **hold).returncode == 0


def test_a_refused_write_leaves_no_marker(tmp_path) -> None:
    """`before` only looks. A refused session must not appear to have written,
    or the two would hold each other."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _hook(root, "before", BOB, SUBSTRATE_EDIT_PRESENCE="hold")
    assert not _marker(root, BOB).exists()
    assert _hook(root, "before", ALICE, SUBSTRATE_EDIT_PRESENCE="hold").returncode == 0


def test_off_records_nothing_and_says_nothing(tmp_path) -> None:
    root = _repo(tmp_path)
    for session in (ALICE, BOB):
        p = _hook(root, "after", session, SUBSTRATE_EDIT_PRESENCE="off")
        assert (p.returncode, p.stderr) == (0, "")
    assert not (root / ".substrate" / "usage").exists()


def test_an_unknown_setting_falls_back_to_the_default(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE, SUBSTRATE_EDIT_PRESENCE="banana")
    told = _hook(root, "after", BOB, SUBSTRATE_EDIT_PRESENCE="banana",
                 SUBSTRATE_EDIT_PRESENCE_MINUTES="soon")
    assert told.returncode == 2, told.stderr
    assert _hook(root, "before", ALICE, SUBSTRATE_EDIT_PRESENCE="banana").returncode == 0


@pytest.mark.parametrize("value, minutes", [("0", 10), ("1", 1), ("1440", 1440), ("1441", 10),
                                            ("-5", 10), (" 15 ", 15), ("1.5", 10), ("", 10)])
def test_the_window_is_whole_minutes_from_one_to_a_day(monkeypatch, value, minutes) -> None:
    monkeypatch.setenv("SUBSTRATE_EDIT_PRESENCE_MINUTES", value)
    assert ep._window() == minutes * 60


def test_ages_read_as_seconds_then_whole_minutes() -> None:
    assert [ep._ago(s) for s in (-5, 0, 89, 90, 600)] == ["0 s", "0 s", "89 s", "1 min", "10 min"]


def test_notebooks_relative_paths_and_links_name_the_same_file(tmp_path) -> None:
    """One file is one file however the tool names it: a notebook path, a path
    relative to the project, or a link that resolves to it."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE, tool_input={"notebook_path": str(root / DOC)})
    assert _marker(root, ALICE).exists()
    relative = _hook(root, "after", BOB, tool_input={"file_path": DOC})
    assert relative.returncode == 2 and _tag(ALICE) in relative.stderr, relative.stderr
    try:
        (root / "docs" / "link.md").symlink_to("a.md")
    except OSError:
        pytest.skip("symlinks unavailable")
    linked = _hook(root, "after", CAROL, rel="docs/link.md")
    assert linked.returncode == 2 and DOC in linked.stderr, linked.stderr


def test_without_the_guarded_helpers_nothing_is_read_or_written(tmp_path, monkeypatch) -> None:
    """A stripped install has no guarded IO. The hook then does nothing; it does
    not fall back to plain file calls."""
    root = _repo(tmp_path)
    monkeypatch.setattr(ep, "ROOT", root)
    for name in ("open_dir_chain", "safe_atomic_write", "safe_read_text"):
        monkeypatch.setattr(ep, name, None)
    monkeypatch.setenv("SUBSTRATE_EDIT_PRESENCE", "hold")
    hook = {"session_id": ALICE, "tool_input": {"file_path": str(root / DOC)}}
    assert (ep.after(hook), ep.before(hook), ep.listing()) == (0, 0, 0)
    assert not (root / ".substrate" / "usage").exists()


@pytest.mark.parametrize("stdin", ["", "not json", "[]", json.dumps({"tool_input": {}}),
                                   json.dumps({"session_id": 7, "tool_input": {"file_path": "x"}})])
@pytest.mark.parametrize("when", ["before", "after"])
def test_garbage_input_is_a_silent_pass(tmp_path, stdin, when) -> None:
    """This hook runs on every edit. Whatever it is handed, it must not turn an
    edit into an error."""
    root = _repo(tmp_path)
    p = subprocess.run([sys.executable, str(SCRIPTS / "edit_presence.py"), when], input=stdin,
                       cwd=str(root), env=_env(root, SUBSTRATE_EDIT_PRESENCE="hold"),
                       capture_output=True, text=True, timeout=30)
    assert (p.returncode, p.stderr) == (0, ""), p.stderr


def test_without_a_session_id_nothing_is_recorded(tmp_path) -> None:
    """A host that does not say which session is writing cannot be told apart
    from itself, so it is neither recorded nor warned."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    p = _hook(root, "after", None)
    assert (p.returncode, p.stderr) == (0, "")
    assert len(list((root / ".substrate" / "usage" / "presence").rglob("*.json"))) == 1


@pytest.mark.parametrize("rel", [".substrate/config", ".git/config", "../outside.md"])
def test_runtime_git_and_outside_paths_are_not_tracked(tmp_path, rel) -> None:
    root = _repo(tmp_path)
    (root / ".git").mkdir()
    for session in (ALICE, BOB):
        p = _hook(root, "after", session, rel=rel)
        assert (p.returncode, p.stderr) == (0, "")
    assert not (root / ".substrate" / "usage").exists()


def test_markers_sit_in_ignored_runtime_state_and_hold_no_session_id(tmp_path) -> None:
    """Under .substrate/usage/, which bootstrap gitignores and the verification
    fingerprint leaves out: recording a write must not read as a change to the
    repository. The session id is hashed, in the name and in the content."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    files = [p for p in (root / ".substrate").rglob("*") if p.is_file()]
    assert [p.relative_to(root).parts[:3] for p in files] == [(".substrate", "usage", "presence")]
    assert ALICE not in files[0].name and ALICE not in files[0].read_text(encoding="utf-8")


def test_markers_older_than_a_day_are_cleared_by_the_next_writer(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _age(root, ALICE, 25 * 3600)
    assert _hook(root, "after", BOB).returncode == 0
    assert not _marker(root, ALICE).exists() and _marker(root, BOB).exists()


def test_folders_of_files_idle_for_a_day_go_when_a_new_file_is_first_written(tmp_path) -> None:
    """One folder per file ever edited would grow without end. The walk that
    clears idle ones runs when a file gets its first marker, not on every edit,
    and a folder with one fresh marker stays whole."""
    root = _repo(tmp_path)
    (root / "docs" / "c.md").write_text("text\n", encoding="utf-8")
    _hook(root, "after", ALICE)                                # docs/a.md
    _hook(root, "after", ALICE, rel="docs/b.md")
    _hook(root, "after", BOB, rel="docs/b.md")
    old = time.time() - 2 * 24 * 3600
    os.utime(_marker(root, ALICE), (old, old))                 # a.md: idle for two days
    os.utime(_marker(root, ALICE, "docs/b.md"), (old, old))    # b.md: Bob's marker is fresh
    _hook(root, "after", BOB, rel="docs/b.md")                 # not a first marker: no walk
    assert _marker(root, ALICE).exists()
    _hook(root, "after", BOB, rel="docs/c.md")                 # first marker for c.md
    assert not _marker(root, ALICE).parent.exists()
    assert _marker(root, ALICE, "docs/b.md").exists() and _marker(root, BOB, "docs/b.md").exists()


def _stuff(root: Path, count: int) -> Path:
    """Fill docs/a.md's marker folder with `count` fresh markers no session wrote."""
    _hook(root, "after", ALICE)
    folder = _marker(root, ALICE).parent
    body = _marker(root, ALICE).read_text(encoding="utf-8")
    _marker(root, ALICE).unlink()
    for i in range(count):
        (folder / f"{i:016x}.json").write_text(body, encoding="utf-8")
    return folder


def test_a_folder_stuffed_with_markers_is_not_read_and_not_believed(tmp_path) -> None:
    """The runtime directory is agent-writable. A folder holding more markers
    than any file has sessions would make every edit of that file read them
    all, so none of it is read: no note, and `hold` sees nobody."""
    root = _repo(tmp_path)
    _stuff(root, ep.MAX_MARKERS + 1)
    assert _hook(root, "before", BOB, SUBSTRATE_EDIT_PRESENCE="hold").returncode == 0
    told = _hook(root, "after", BOB)
    assert (told.returncode, told.stderr) == (0, ""), told.stderr


def test_a_stuffed_folder_is_emptied_by_the_next_writer_and_watched_again(tmp_path) -> None:
    """Ignoring a stuffed folder for good would leave that one file unwatched
    until someone deleted the folder by hand. The next writer clears it, and
    the file is watched again from that write on."""
    root = _repo(tmp_path)
    folder = _stuff(root, ep.MAX_MARKERS + 1)
    assert _hook(root, "after", BOB).returncode == 0
    assert [p.name for p in folder.iterdir()] == [_marker(root, BOB).name]
    told = _hook(root, "after", ALICE)
    assert told.returncode == 2 and _tag(BOB) in told.stderr, told.stderr


def test_a_very_large_stuffed_folder_is_emptied_a_batch_at_a_time(tmp_path) -> None:
    """One edit must not pay for deleting a hundred thousand files, so each
    write removes a bounded batch and records nothing until the folder is small."""
    root = _repo(tmp_path)
    total = ep.CLEAR_BATCH + ep.MAX_MARKERS + 1
    folder = _stuff(root, total)
    assert _hook(root, "after", BOB).returncode == 0
    assert len(list(folder.iterdir())) == total - ep.CLEAR_BATCH and not _marker(root, BOB).exists()
    assert _hook(root, "after", BOB).returncode == 0
    assert [p.name for p in folder.iterdir()] == [_marker(root, BOB).name]


def test_the_idle_walk_removes_markers_and_nothing_else(tmp_path) -> None:
    root = _repo(tmp_path)
    (root / "docs" / "c.md").write_text("text\n", encoding="utf-8")
    _hook(root, "after", ALICE)
    old = time.time() - 2 * 24 * 3600
    os.utime(_marker(root, ALICE), (old, old))
    planted = _marker(root, ALICE).parent / "not-a-marker"
    planted.mkdir()
    _hook(root, "after", BOB, rel="docs/c.md")
    assert not _marker(root, ALICE).exists() and planted.is_dir()


def test_a_marker_dated_in_the_future_is_not_believed(tmp_path) -> None:
    """The runtime directory is agent-writable. A marker that claims a write far
    ahead of the clock would hold a file for as long as it said."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _age(root, ALICE, -3600)
    assert _hook(root, "before", BOB, SUBSTRATE_EDIT_PRESENCE="hold").returncode == 0
    assert _hook(root, "after", BOB).returncode == 0


def test_a_linked_presence_directory_is_refused_and_the_edit_still_passes(tmp_path) -> None:
    """The runtime directory is agent-writable. A symlink there must not send
    the marker outside the repository, and must not break the edit either."""
    root = _repo(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / ".substrate" / "usage").mkdir()
    try:
        (root / ".substrate" / "usage" / "presence").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    for when in ("before", "after"):
        p = _hook(root, when, ALICE, SUBSTRATE_EDIT_PRESENCE="hold")
        assert p.returncode == 0, p.stderr
    assert list(outside.iterdir()) == []


def test_list_shows_who_wrote_what_lately(tmp_path) -> None:
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _hook(root, "after", BOB, rel="docs/b.md")
    _age(root, BOB, 2 * 3600, rel="docs/b.md")
    p = subprocess.run([sys.executable, str(SCRIPTS / "edit_presence.py"), "list"],
                       cwd=str(root), env=_env(root), capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    lines = [ln for ln in p.stdout.splitlines() if "docs/" in ln]
    assert len(lines) == 1 and DOC in lines[0] and _tag(ALICE) in lines[0], p.stdout


def test_list_prints_marker_text_as_plain_single_lines(tmp_path) -> None:
    """Markers are agent-writable and `list` is read by agents. A path with a
    terminal escape or a line break in it must come out as one harmless line,
    and a marker with no usable path as none."""
    root = _repo(tmp_path)
    _hook(root, "after", ALICE)
    _hook(root, "after", BOB, rel="docs/b.md")
    data = json.loads(_marker(root, ALICE).read_text(encoding="utf-8"))
    data["path"] = "docs/a.md\n   0 s ago  session ffffff  \x1b[31mforged"
    _marker(root, ALICE).write_text(json.dumps(data), encoding="utf-8")
    other = json.loads(_marker(root, BOB, "docs/b.md").read_text(encoding="utf-8"))
    other["path"] = ["docs/b.md"]
    _marker(root, BOB, "docs/b.md").write_text(json.dumps(other), encoding="utf-8")
    p = subprocess.run([sys.executable, str(SCRIPTS / "edit_presence.py"), "list"],
                       cwd=str(root), env=_env(root), capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert "\x1b" not in p.stdout and len(p.stdout.splitlines()) == 1, repr(p.stdout)


def test_doctor_blocks_an_install_that_does_not_run_the_hook() -> None:
    import importlib.util
    spec = importlib.util.spec_from_file_location("_doctor_ep", SCRIPTS / "substrate_doctor.py")
    doctor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(doctor)
    settings = next((ROOT / rel for rel in (".claude/settings.json",
                                            "templates/claude/settings.json.template")
                     if (ROOT / rel).is_file()), None)
    assert settings is not None, "no settings file to check"
    text = settings.read_text(encoding="utf-8")
    assert "hook not wired: edit_presence.py" not in doctor._hook_findings(json.loads(text))[0]
    unwired = json.loads(text.replace("edit_presence.py", "something_else.py"))
    assert "hook not wired: edit_presence.py" in doctor._hook_findings(unwired)[0]


def test_both_hooks_are_wired_for_every_edit_tool() -> None:
    checked = [ROOT / rel for rel in (".claude/settings.json",
                                      "templates/claude/settings.json.template")
               if (ROOT / rel).is_file()]
    assert checked, "no settings file to check"
    for path in checked:
        rel = path.relative_to(ROOT).as_posix()
        hooks = json.loads(path.read_text(encoding="utf-8"))["hooks"]
        for event, when in (("PreToolUse", "before"), ("PostToolUse", "after")):
            wired = [entry for entry in hooks.get(event, [])
                     if any(f"edit_presence.py\" {when}" in h.get("command", "")
                            for h in entry.get("hooks", []))]
            assert len(wired) == 1, f"{rel}: {event} is not wired once to edit_presence.py {when}"
            tools = set(wired[0]["matcher"].split("|"))
            assert tools == {"Edit", "Write", "MultiEdit", "NotebookEdit"}, (rel, event, tools)
