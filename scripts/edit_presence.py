#!/usr/bin/env python3
"""Edit presence: a session learns that another session is writing the same file.

Two agent sessions can share one checkout. Each reads a file, plans a change
and writes it, and neither knows the other is there: one trims a doc while the
other is adding to it, and a person ends up carrying notes between them. The
host stops a write over content the session has not read, so nothing is lost
byte for byte. What is lost is the work, redone each time the other side moves.

Wired in .claude/settings.json for Edit, Write, MultiEdit and NotebookEdit:

  PostToolUse -> edit_presence.py after    record this write; say who else is here
  PreToolUse  -> edit_presence.py before   only in `hold`: refuse while another
                                           session's window on the file is live

  edit_presence.py list                    who wrote what in the last hour

`after` leaves one marker per file and session, and when a DIFFERENT session
wrote the same file inside the window it says so once on stderr with exit 2,
which the host shows to the agent beside the result of its write. It is said
again only when that other session writes again.

SUBSTRATE_EDIT_PRESENCE          off | notice (default) | hold
SUBSTRATE_EDIT_PRESENCE_MINUTES  the window, 1 to 1440 (default 10)

Markers live under .substrate/usage/presence/, which bootstrap gitignores and
the verification fingerprint leaves out, so recording a write never reads as a
change to the repository. Each session writes only its own marker, so there is
no file two sessions update at once. Names and contents carry a hash of the
session id, never the id. That directory is agent-writable: this is a way for
cooperating sessions to see each other, not access control. Anything that can
write a file there can make a note appear or, under `hold`, keep a file held,
so `hold` is for a checkout whose sessions cooperate.

It needs a host that names the session (`session_id` on stdin). Without one a
write is neither recorded nor answered, because the writer could not be told
apart from everyone else. A file changed by a shell command is not seen here;
check_doc_drift's working-tree advisory covers the doc that falls behind.

Exit codes: 0 pass | 2 a note (after) or a refusal (before), reason on stderr.
This hook runs on every edit, so any input it cannot use is a silent pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Guarded file IO only. Without the helpers nothing is read or recorded.
try:
    from _doc_common import open_dir_chain, safe_atomic_write, safe_read_text
except Exception:  # pragma: no cover - stripped install
    open_dir_chain = safe_atomic_write = safe_read_text = None
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()

PRESENCE = (".substrate", "usage", "presence")
UNTRACKED_TOPS = (".substrate", ".git")
MODES = ("off", "notice", "hold")
DEFAULT_MODE = "notice"
DEFAULT_MINUTES = 10
MAX_MINUTES = 1440
KEEP_SECONDS = 24 * 3600      # a marker older than this is cleared by the next writer
LIST_SECONDS = 3600
MAX_MARKERS = 64              # sessions believed on one file; a fuller folder is ignored
CLEAR_BATCH = 512             # markers one write removes from a folder that is too full
WALK_SECONDS = 1.0            # budget for a walk over every marker folder
_FUTURE_SLACK = 60            # a marker dated further ahead than this is not believed


def path_key(rel: str) -> str:
    return hashlib.sha256(rel.encode("utf-8", "replace")).hexdigest()[:32]


def session_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8", "replace")).hexdigest()[:16]


def _mode() -> str:
    value = os.environ.get("SUBSTRATE_EDIT_PRESENCE", "").strip().lower()
    return value if value in MODES else DEFAULT_MODE


def _window() -> int:
    try:
        minutes = int(os.environ.get("SUBSTRATE_EDIT_PRESENCE_MINUTES", "").strip())
    except ValueError:
        minutes = DEFAULT_MINUTES
    if not 1 <= minutes <= MAX_MINUTES:
        minutes = DEFAULT_MINUTES
    return minutes * 60


def _shown(text: str) -> str:
    """Text safe to print: one line, no control characters, bounded."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))[:200]


def _is_hex(name: str, length: int) -> bool:
    return len(name) == length and all(ch in "0123456789abcdef" for ch in name)


def _target(hook) -> tuple[str, str] | None:
    """(repo-relative path, session key) for a write this hook tracks, else None."""
    if not isinstance(hook, dict):
        return None
    tool_input = hook.get("tool_input")
    session = hook.get("session_id")
    if not isinstance(tool_input, dict) or not isinstance(session, str) or not session.strip():
        return None
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not isinstance(file_path, str) or not file_path:
        return None
    try:
        rel = Path(file_path).resolve().relative_to(ROOT.resolve())
    except (ValueError, OSError):
        return None  # outside the project: not ours
    if not rel.parts or rel.parts[0] in UNTRACKED_TOPS:
        return None
    return rel.as_posix(), session_key(session)


def _marker_dir(rel: str) -> Path:
    return ROOT.joinpath(*PRESENCE, path_key(rel))


def _read_marker(path: Path) -> dict | None:
    try:
        data = json.loads(safe_read_text(path, ROOT, max_bytes=4096) or "null")
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _when(data, now: float) -> float | None:
    """A marker's write time, or None when it has none or claims the future."""
    at = data.get("at") if data else None
    if isinstance(at, bool) or not isinstance(at, (int, float)) or at > now + _FUTURE_SLACK:
        return None
    return float(at)


def _writers(rel: str, now: float, clear: bool = False) -> dict | None:
    """{session key: write time} for every session with a marker on `rel` that is
    less than a day old. With `clear`, markers older than that are removed.
    None when the folder holds more markers than any file has sessions: it is
    then not read and not believed, and with `clear` it is emptied."""
    if open_dir_chain is None:
        return {}
    folder = _marker_dir(rel)
    try:
        fd = open_dir_chain(ROOT, folder, create=False)
    except Exception:
        return {}  # nobody has written it, or the directory is not safe to read
    out = {}
    try:
        names = [n for n in os.listdir(fd) if n.endswith(".json") and _is_hex(n[:-5], 16)]
        if len(names) > MAX_MARKERS:
            # Nobody has this many sessions on one file. Reading them all would
            # stall every edit of the file, so the folder is not believed at all.
            # A writer empties it, a bounded batch per write, or the file would
            # stay unwatched until someone removed the folder by hand. Once the
            # last batch is gone the folder is an empty one and this write counts.
            if clear:
                for name in names[:CLEAR_BATCH]:
                    try:
                        os.unlink(name, dir_fd=fd)
                    except OSError:
                        pass
                if len(names) <= CLEAR_BATCH:
                    return {}
            return None
        for name in names:
            at = _when(_read_marker(folder / name), now)
            if at is None:
                continue
            if now - at > KEEP_SECONDS:
                if clear:
                    try:
                        os.unlink(name, dir_fd=fd)
                    except OSError:
                        pass
                continue
            out[name[:-5]] = at
    except OSError:
        return {}
    finally:
        os.close(fd)
    return out


def _others(writers: dict, me: str, now: float) -> list:
    """Other sessions' writes inside the window, newest first, from `_writers`."""
    window = _window()
    return sorted(((at, key) for key, at in writers.items()
                   if key != me and now - at <= window), reverse=True)


def _clear_idle_folders(now: float) -> None:
    """Remove the marker folders of files nobody has written for a day. Run when
    a file gets its first marker, so the directory is walked once per newly
    edited file and not once per edit. Ages come from file times here: nothing
    is parsed for a folder that is only being judged for removal.

    Bounded: the walk stops after WALK_SECONDS, and a folder with more entries
    than MAX_MARKERS is left alone (it is already ignored when read). Only
    regular files are removed; anything else in a folder stays, and so does
    the folder."""
    deadline = time.monotonic() + WALK_SECONDS
    try:
        top = open_dir_chain(ROOT, ROOT.joinpath(*PRESENCE), create=False)
    except Exception:
        return
    try:
        for name in os.listdir(top):
            if time.monotonic() > deadline:
                break
            if not _is_hex(name, 32):
                continue
            try:
                sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                              dir_fd=top)
            except OSError:
                continue
            try:
                files = os.listdir(sub)
                if len(files) > MAX_MARKERS:
                    continue
                regular = [f for f in files
                           if stat.S_ISREG(os.stat(f, dir_fd=sub, follow_symlinks=False).st_mode)]
                if any(now - os.stat(f, dir_fd=sub, follow_symlinks=False).st_mtime <= KEEP_SECONDS
                       for f in regular):
                    continue
                for f in regular:
                    os.unlink(f, dir_fd=sub)
            except OSError:
                continue
            finally:
                os.close(sub)
            try:
                os.rmdir(name, dir_fd=top)
            except OSError:
                pass
    except OSError:
        pass
    finally:
        os.close(top)


def _ago(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds} s" if seconds < 90 else f"{seconds // 60} min"


def after(hook) -> int:
    """PostToolUse: record this write and say once if another session is on the file."""
    mode = _mode()
    target = _target(hook)
    if mode == "off" or target is None or safe_atomic_write is None:
        return 0
    rel, me = target
    now = time.time()
    writers = _writers(rel, now, clear=True)
    if writers is None:
        return 0
    others = _others(writers, me, now)
    mine = _marker_dir(rel) / f"{me}.json"
    first_marker = not writers
    previous = _read_marker(mine) or {}
    seen = previous.get("seen")
    seen = float(seen) if isinstance(seen, (int, float)) and not isinstance(seen, bool) else 0.0
    if seen > now + _FUTURE_SLACK:
        seen = 0.0  # "already told about writes that have not happened" is not believed
    newest = others[0] if others else None
    told = newest is not None and newest[0] > seen
    try:
        safe_atomic_write(mine, json.dumps({"v": 1, "path": rel, "at": now,
                                            "seen": max(seen, newest[0]) if newest else seen}),
                          ROOT, tmp_prefix=".ep-", make_parents=True)
    except Exception:
        return 0  # an unsafe or read-only runtime directory: record nothing, say nothing
    if first_marker:
        _clear_idle_folders(now)
    if not told:
        return 0
    who = "another session" if len(others) == 1 else f"{len(others)} other sessions"
    latest = "" if len(others) == 1 else "the latest "
    print(
        f"edit-presence: {who} wrote {_shown(rel)}, {latest}{_ago(now - newest[0])} ago "
        f"(session {newest[1][:6]}). Your edit was applied.\n"
        "Two sessions writing one file undo each other's work. Before your next change to "
        "it, re-read the file and keep what the other session added. If you are about to "
        "make a large change, tell that session or the user first, or leave the file until "
        f"it has been quiet for {_window() // 60} minutes.\n"
        "This is said again only when that session writes the file again. "
        "Setting: SUBSTRATE_EDIT_PRESENCE=off|notice|hold.",
        file=sys.stderr,
    )
    return 2


def before(hook) -> int:
    """PreToolUse: in `hold`, refuse while another session's window on the file is live."""
    target = _target(hook)
    if _mode() != "hold" or target is None:
        return 0
    rel, me = target
    now = time.time()
    others = _others(_writers(rel, now) or {}, me, now)
    if not others:
        return 0
    wait = _window() - (now - others[0][0])
    print(
        f"edit-presence: {_shown(rel)} is held. Another session wrote it "
        f"{_ago(now - others[0][0])} ago (session {others[0][1][:6]}), and "
        "SUBSTRATE_EDIT_PRESENCE=hold keeps other sessions off a file until it has been "
        f"quiet for {_window() // 60} minutes. Your edit was not applied.\n"
        f"It is free in about {_ago(wait)} if that session does not write it again. "
        "Work on something else, or tell the user the file is in use.",
        file=sys.stderr,
    )
    return 2


def listing() -> int:
    """Print who wrote which file in the last hour, newest first."""
    now = time.time()
    deadline = time.monotonic() + 5 * WALK_SECONDS
    rows = []
    if open_dir_chain is not None:
        try:
            top = open_dir_chain(ROOT, ROOT.joinpath(*PRESENCE), create=False)
        except Exception:
            top = None
        if top is not None:
            try:
                names = [n for n in os.listdir(top) if _is_hex(n, 32)]
            except OSError:
                names = []
            finally:
                os.close(top)
            for name in names:
                if time.monotonic() > deadline:
                    break
                folder = ROOT.joinpath(*PRESENCE, name)
                try:
                    fd = open_dir_chain(ROOT, folder, create=False)
                except Exception:
                    continue
                try:
                    files = [f for f in os.listdir(fd)
                             if f.endswith(".json") and _is_hex(f[:-5], 16)]
                except OSError:
                    files = []
                finally:
                    os.close(fd)
                if len(files) > MAX_MARKERS:
                    continue
                for f in files:
                    data = _read_marker(folder / f)
                    at = _when(data, now)
                    if at is None or now - at > LIST_SECONDS or not isinstance(data.get("path"), str):
                        continue
                    rows.append((at, f[:6], data["path"]))
    if not rows:
        print("edit-presence: no file written through the edit tools in the last hour")
        return 0
    for at, tag, path in sorted(rows, reverse=True):
        print(f"{_ago(now - at):>7} ago  session {tag}  {_shown(path)}")
    return 0


def main(argv: list | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    when = argv[0] if argv else ""
    if when == "list":
        return listing()
    if when not in ("before", "after"):
        return 0
    try:
        raw = sys.stdin.read()
        hook = json.loads(raw) if raw.strip() else {}
        return before(hook) if when == "before" else after(hook)
    except Exception:  # noqa: BLE001 - this hook must never turn an edit into an error
        return 0


if __name__ == "__main__":
    sys.exit(main())
