#!/usr/bin/env python3
"""Structured work receipts: what was asked, which known check ran, what it returned,
and whether the tree it ran on is still the tree you have. Local, unsigned evidence.

A receipt never certifies more than it observed:
- each attempt is two immutable records, `running` before the process starts and
  `result` after it ends; a `running` record with no `result` reads as incomplete;
- exit 0 is `passed` only for the input state captured before the run; a check that
  changed the tree while running reads `state-changed-during-check`;
- an attempt whose own gate (manage.sh, scripts/, .substrate/, the pre-commit
  config) was modified when it ran lists those paths as `harness_changed`;
- inner test coverage is `unknown` unless the producer reports it (none do yet);
- a completion assertion is a separate, self-reported record and never alters a
  measured result; release verification stays with the release gate.
Only `check`, `evals` and `prove` can run; no other command is accepted. Output is
digested, not stored, unless an excerpt is explicitly requested; the excerpt drops
credential-shaped lines and private-key blocks and sanitizes the rest line by line.
Environment variables are never stored. Redaction covers known credential shapes,
not every possible secret. A child that starts its own session escapes the
process-group kill; the check commands this runs do not do that.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import GuardRefusal, open_dir_chain, safe_atomic_write, safe_read_bytes
from _task_evidence import (clip_bytes, git, git_facts, harden_path, json_text, now, safe_fact,
                            safe_text, trusted_executable)
from session_handoff import _INVISIBLE_CHARS, _strip_html
from session_handoff import _STRIPPED_HISTORY as _STRIPPED

SCHEMA = 1
STORE = Path(".substrate") / "receipts"
CHECKS = ("check", "evals", "prove")
COMPLETIONS = ("complete", "incomplete")
RECORD_LIMIT = 64 << 10
EXCERPT_JSON_LIMIT = 40 << 10
MAX_RECORDS = 1000
MAX_SCAN = 2000
TASK_CHARS, NOTE_CHARS, AUTHOR_CHARS, REF_CHARS = 2000, 2000, 100, 500
DEFAULT_TIMEOUT, MAX_TIMEOUT, KILL_GRACE = 1800, 7200, 5
_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_RECORD = re.compile(r"(\d{19})-([0-9a-f-]{36})-(running|result|assertion)\.json")
_HEX = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_STATE_KEYS = ("status", "head", "branch", "dirty", "fingerprint")
OUTCOMES = ("passed", "failed", "timeout", "interrupted", "spawn-failed")
STATES = ("unchanged", "state-changed-during-check", "unknown")
_HARNESS = ("manage.sh", ".pre-commit-config.yaml")
_HARNESS_DIRS = ("scripts/", ".substrate/")
# Excerpt lines withheld whole, before the general sanitizer: assignments whose
# NAME (bare or quoted) carries a credential word (PREFIX_API_KEY=...,
# "db_password": ..., Cookie: ...), flags such as --password VALUE, URLs with a
# user:password part, HTTP authorization values, and everything inside a PEM
# block. `::` is not an assignment, so pytest node ids stay visible.
# Quantifiers are bounded and each line is matched on its first CREDENTIAL_SCAN
# characters AS DISPLAYED (v3.10.5): invisible characters and markup removed and
# whitespace collapsed, exactly as the sanitizer that shows it does, so padding
# cannot push a value past the scanned prefix. Unbounded `[a-z0-9_.-]*` runs were
# quadratic: a 64 KB minified line stalled `--excerpt` for minutes. The excerpt
# shows at most 500 characters of a line.
CREDENTIAL_SCAN = 1000
_CREDENTIAL_LINE = re.compile(
    r"(?i)([\"']?[a-z0-9_.-]{0,64}(key|secret|token|passw(or)?d|passwd|pwd|credential|auth|cookie)"
    r"[a-z0-9_.-]{0,64}[\"']?\s{0,16}(=|:(?!:)))"
    r"|--?[a-z0-9-]{0,64}(passw(or)?d|passwd|pwd|token|secret|api-?key)[a-z0-9-]{0,64}([ =]|$)"
    r"|[a-z][a-z0-9+.-]{0,64}://[^/\s:@]{1,256}:[^/\s@]{1,256}@"
    r"|\bbearer\s+\S|\bauthorization\s*:")
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]+-----")


class ReceiptError(ValueError):
    """Invalid invocation or invalid stored receipt: reported, never an empty pass."""


def _check_id(task_id: str) -> str:
    if not isinstance(task_id, str) or not _ID.fullmatch(task_id):
        raise ReceiptError("task id must be a lowercase UUID4")
    return task_id


def _text(value, limit: int, field: str, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise ReceiptError(f"{field} must be text")
    if len(value) > limit:
        raise ReceiptError(f"{field} exceeds {limit} characters")
    clean = safe_text(value, limit) if value.strip() else ""
    if required and not clean:
        raise ReceiptError(f"{field} is required")
    if clean == _STRIPPED:
        # Refuse rather than store the placeholder: a receipt whose task reads
        # "[history line stripped ...]" records nothing (v3.10.5).
        raise ReceiptError(
            f"{field} reads as a command or an instruction to the context filter (for example "
            "a shell tool name such as node or python3 standing as a word of its own); "
            "rephrase it")
    return clean


def _state(facts: dict) -> dict:
    return {k: facts.get(k) for k in _STATE_KEYS} | {
        "diagnostics": [d.get("code") for d in facts.get("diagnostics", [])][:20]}


def _is_harness(path: str) -> bool:
    return path in _HARNESS or path.startswith(_HARNESS_DIRS)


def _harness_changed(facts: dict, since: str | None = None, root: Path | None = None) -> list[str]:
    """Gate files that differ from HEAD, and (v3.10.5) gate files committed since
    the task started: committing a weakened gate first used to clear the warning."""
    paths = {p for p in facts.get("changed_paths", []) if _is_harness(p)}
    head = facts.get("head")
    if since and head and since != head and root is not None:
        try:
            out = git(root, "diff", "--name-only", "-z", "--no-renames", since, head, "--")
            paths.update(p for p in (os.fsdecode(x) for x in out.split(b"\0") if x)
                         if _is_harness(p))
        except (OSError, ValueError, subprocess.SubprocessError):
            paths.add("(gate changes since the task started could not be read)")
    return [safe_fact(p, 200) for p in sorted(paths)[:50]]


def _task_dir(root: Path, task_id: str) -> Path:
    return root / STORE / _check_id(task_id)


def _names(root: Path, directory: Path, cap: int | None = None) -> list[str]:
    """Entry names, read through the guarded walk and never more than cap + 1 of
    them, so an oversized directory is detected without being listed whole."""
    cap = MAX_RECORDS + 2 if cap is None else cap
    try:
        fd = open_dir_chain(root, directory)
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ReceiptError(f"receipt store is unsafe or unreadable ({type(exc).__name__})") from exc
    names: list[str] = []
    try:
        with os.scandir(fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > cap:
                    break
    finally:
        os.close(fd)
    return sorted(names)


def _write(root: Path, rel: Path, record: dict) -> None:
    text = json_text(record)
    if len(text.encode()) > RECORD_LIMIT:
        raise ReceiptError("record exceeds the 64 KiB limit")
    if rel.name in _names(root, root / rel.parent):
        raise ReceiptError("refusing to overwrite an existing receipt record")
    try:
        safe_atomic_write(root / rel, text + "\n", root=root, make_parents=True, mode=0o600)
    except GuardRefusal as exc:
        raise ReceiptError(f"receipt store is unsafe ({safe_text(str(exc), 200)})") from exc


def _record_name(kind: str, record_id: str) -> str:
    return f"{time.time_ns():019d}-{record_id}-{kind}.json"


def _append(root: Path, task_id: str, kind: str, record_id: str, record: dict) -> None:
    directory = _task_dir(root, task_id)
    names = _names(root, directory)
    if "task.json" not in names:
        raise ReceiptError("unknown task id")
    if len(names) > MAX_RECORDS:
        raise ReceiptError(f"task already holds {MAX_RECORDS} records; start a new task")
    _write(root, directory.relative_to(root) / _record_name(kind, record_id), record)


def start(root: Path, task: str) -> str:
    harden_path()
    root = Path(root).resolve()
    text = _text(task, TASK_CHARS, "task", required=True)
    task_id = str(uuid.uuid4())
    facts = git_facts(root)
    record = dict(schema_version=SCHEMA, kind="task", task_id=task_id, task=text,
                  created_at=now(), created_ns=time.time_ns(), root=safe_fact(str(root), 1000),
                  start_state=_state(facts))
    _write(root, STORE / task_id / "task.json", record)
    return task_id


def _drain(proc, deadline: float, keep_tail: bool) -> tuple[str, int, str, bytes]:
    """(how it ended, byte count, sha256, retained tail). Output is always fully
    drained so a chatty child cannot block; only the tail is ever retained."""
    digest, size, tail = hashlib.sha256(), 0, b""
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                return "timeout", size, digest.hexdigest(), tail
            for key, _ in selector.select(min(left, 1)):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                digest.update(chunk)
                size += len(chunk)
                if keep_tail:
                    tail = (tail + chunk)[-(64 << 10):]
    return "exited", size, digest.hexdigest(), tail


def _stop(proc) -> None:
    """TERM the whole process group, give the leader the grace period, then KILL
    the whole group regardless: members that ignore TERM must not outlive it."""
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=KILL_GRACE)
    except subprocess.TimeoutExpired:
        pass


def _excerpt(tail: bytes) -> str:
    """Last lines of output, never a credential-shaped line or a key block, each
    line sanitized, and small enough that the JSON record stays under its cap
    even when every character escapes to six bytes."""
    raw = tail.decode("utf-8", "replace").splitlines()[-400:]
    # The window may start inside a key block whose BEGIN line fell off: when
    # the first marker seen is an END, everything before it is block body.
    first = None
    for line in raw:
        first = _PEM_BEGIN.search(line) or _PEM_END.search(line)
        if first:
            break
    lines, withheld = [], 0
    in_pem = first is not None and first.group().startswith("-----END")
    for line in raw:
        if in_pem or _PEM_BEGIN.search(line):
            in_pem = not _PEM_END.search(line)
            withheld += 1
            continue
        shown = " ".join(_strip_html(_INVISIBLE_CHARS.sub("", line)).split())
        if _CREDENTIAL_LINE.search(shown[:CREDENTIAL_SCAN]):
            withheld += 1
            continue
        clean = safe_text(line, 500) if line.strip() else ""
        if clean:
            lines.append(clean)
    while lines and len(json.dumps("\n".join(lines))) > EXCERPT_JSON_LIMIT:
        lines.pop(0)
    head = [f"[{withheld} credential-shaped line(s) withheld]"] if withheld else []
    return "\n".join(head + lines)


class _Interrupted(Exception):
    pass


# Variables that choose which hooks or tests a check runs (v3.10.5): with SKIP
# exported, pre-commit skipped the failing hook and the receipt read `passed`;
# PYTEST_ADDOPTS can deselect a failing test the same way. The check runs as
# written, never as the caller's environment trims it.
_CHECK_SELECTION_ENV = frozenset({"SKIP", "PRE_COMMIT_ALLOW_NO_CONFIG", "PYTEST_ADDOPTS",
                                  "PYTEST_PLUGINS"})


def _spawn(argv: list[str], root: Path):
    # Inherited GIT_DIR/GIT_INDEX_FILE/... would point the check at a different
    # repository than the one the fingerprints describe.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in _CHECK_SELECTION_ENV}
    return subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True)


def _exited(proc, deadline: float) -> bool:
    """Wait for the leader to exit WITHOUT reaping it where the platform allows,
    so its process-group id cannot be reused while leftover members are swept."""
    if not hasattr(os, "waitid"):
        try:
            proc.wait(timeout=max(0.01, deadline - time.monotonic()))
            return True
        except subprocess.TimeoutExpired:
            return False
    while os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)
    return True


def _sweep(proc) -> None:
    """KILL members that outlived a leader which exited on its own, then reap."""
    if hasattr(os, "waitid"):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    proc.wait()


def run_check(root: Path, task_id: str, kind: str, timeout: int = DEFAULT_TIMEOUT,
              excerpt: bool = False) -> dict:
    harden_path()
    root = Path(root).resolve()
    _check_id(task_id)
    if kind not in CHECKS:
        raise ReceiptError(f"check must be one of {', '.join(CHECKS)}")
    if not 1 <= int(timeout) <= MAX_TIMEOUT:
        raise ReceiptError(f"timeout must be 1..{MAX_TIMEOUT} seconds")
    if os.name != "posix" or not hasattr(os, "killpg"):
        raise ReceiptError("process-group control is unavailable here; refusing to run unbounded")
    if "task.json" not in _names(root, _task_dir(root, task_id)):
        raise ReceiptError("unknown task id")
    bash = trusted_executable("bash")
    argv = [bash or "bash", "./manage.sh", kind]
    attempt = str(uuid.uuid4())
    start_head = _valid_state(_load(root, STORE / task_id / "task.json").get("start_state")).get("head")
    before = git_facts(root)
    harness = _harness_changed(before, since=start_head, root=root)
    _append(root, task_id, "running", attempt, dict(
        schema_version=SCHEMA, kind="running", task_id=task_id, attempt_id=attempt,
        check=kind, argv=argv, timeout_seconds=int(timeout), started_at=now(),
        before=_state(before), harness_changed=harness))
    outcome, code, sig, size, digest, tail = "spawn-failed", None, None, 0, None, b""
    started = time.monotonic()

    def _on_signal(signum, frame):
        raise _Interrupted

    previous = {s: signal.signal(s, _on_signal) for s in (signal.SIGTERM, signal.SIGHUP)}
    proc = None
    try:
        if bash is None:
            raise FileNotFoundError("bash is not on an absolute PATH entry")
        proc = _spawn(argv, root)
        how, size, digest, tail = _drain(proc, started + int(timeout), excerpt)
        if how == "exited":
            if _exited(proc, started + int(timeout)):
                _sweep(proc)
            else:
                how = "timeout"
        if how == "timeout":
            _stop(proc)
            outcome = "timeout"
        else:
            code = proc.returncode
            if code < 0:
                sig, code, outcome = -code, None, "interrupted"
            else:
                outcome = "passed" if code == 0 else "failed"
    except OSError:
        outcome = "spawn-failed"
    except (KeyboardInterrupt, _Interrupted):
        if proc is not None:
            _stop(proc)
        outcome = "interrupted"
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)
        if proc is not None and proc.poll() is None:
            _stop(proc)
    after = git_facts(root)
    state = _derive_state(before.get("fingerprint"), after.get("fingerprint"))
    output = {"bytes": size, "sha256": digest, "stored": "excerpt" if excerpt else "digest-only"}
    if excerpt:
        output["excerpt"] = _excerpt(tail)
    result = dict(schema_version=SCHEMA, kind="result", task_id=task_id, attempt_id=attempt,
                  check=kind, outcome=outcome, exit_code=code, signal=sig,
                  duration_seconds=round(time.monotonic() - started, 3), finished_at=now(),
                  output=output, before=_state(before), after=_state(after),
                  state=state, coverage="unknown", harness_changed=harness)
    _append(root, task_id, "result", attempt, result)
    return result


def annotate(root: Path, task_id: str, completion: str, note: str = "",
             author: str = "", review_ref: str = "") -> dict:
    harden_path()
    root = Path(root).resolve()
    _check_id(task_id)
    if completion not in COMPLETIONS:
        raise ReceiptError(f"completion must be one of {', '.join(COMPLETIONS)}")
    ref = _text(review_ref, REF_CHARS, "review reference")
    if ref and (Path(ref).is_absolute() or ".." in Path(ref).parts):
        raise ReceiptError("review reference must be repository-relative")
    record = dict(schema_version=SCHEMA, kind="assertion", task_id=task_id,
                  assertion_id=str(uuid.uuid4()), completion=completion,
                  note=_text(note, NOTE_CHARS, "note"),
                  author=_text(author, AUTHOR_CHARS, "author") or "unspecified",
                  author_verified=False, review_ref=ref or None, recorded_at=now())
    _append(root, task_id, "assertion", record["assertion_id"], record)
    return record


def _load(root: Path, rel: Path) -> dict:
    raw = safe_read_bytes(root / rel, root, max_bytes=RECORD_LIMIT)
    if raw is None:
        raise ReceiptError(f"unreadable, unsafe or oversized record: {safe_text(rel.name, 120)}")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ReceiptError(f"malformed record: {safe_text(rel.name, 120)}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA:
        raise ReceiptError(f"unknown receipt schema: {safe_text(rel.name, 120)}")
    return data


def _resanitize(value, limit: int) -> str | None:
    """Stored text is read back through the same sanitizer: a hand-edited record
    cannot smuggle terminal controls or a credential into a report."""
    return None if value is None else safe_text(str(value), limit)


def _valid_state(value) -> dict:
    """Stored state, re-validated: hashes must be hashes, text is re-sanitized."""
    if not isinstance(value, dict):
        raise ReceiptError("record state is malformed")
    out = {}
    for key in _STATE_KEYS:
        item = value.get(key)
        if key in ("head", "fingerprint"):
            out[key] = item if isinstance(item, str) and _HEX.fullmatch(item) else None
        else:
            clean = safe_fact if key == "branch" else safe_text
            out[key] = clean(item, 200) if isinstance(item, str) else None
    return out


def _derive_state(before_fp, after_fp) -> str:
    """Exit 0 certifies only the input it started from: a changed fingerprint is
    `state-changed-during-check`, a missing one `unknown`, never `unchanged`."""
    if not (before_fp and after_fp):
        return "unknown"
    return "unchanged" if before_fp == after_fp else "state-changed-during-check"


def _consistent(outcome, code, sig) -> bool:
    if outcome == "passed":
        return code == 0
    if outcome == "failed":
        return isinstance(code, int) and code > 0
    if outcome == "interrupted":
        return code is None and (sig is None or isinstance(sig, int))
    return code is None


def show(root: Path, task_id: str, current: dict | None = None) -> dict:
    harden_path()
    root = Path(root).resolve()
    directory = _task_dir(root, task_id)
    names = _names(root, directory)
    if "task.json" not in names:
        raise ReceiptError("unknown task id")
    if len(names) > MAX_RECORDS + 1:
        raise ReceiptError("task holds more records than a receipt may")
    rel = directory.relative_to(root)
    task = _load(root, rel / "task.json")
    if task.get("kind") != "task" or task.get("task_id") != task_id:
        raise ReceiptError("task record does not match its directory")
    running, results, assertions, diagnostics = {}, {}, [], []
    for name in names:
        if name == "task.json":
            continue
        m = _RECORD.fullmatch(name)
        if not m:
            raise ReceiptError(f"unexpected file in receipt: {safe_text(name, 120)}")
        record = _load(root, rel / name)
        if record.get("task_id") != task_id or record.get("kind") != m.group(3):
            raise ReceiptError(f"record does not match its name: {safe_text(name, 120)}")
        if m.group(3) == "assertion":
            if record.get("assertion_id") != m.group(2) or record.get("completion") not in COMPLETIONS:
                raise ReceiptError(f"malformed assertion: {safe_text(name, 120)}")
            assertions.append(dict(
                completion=record["completion"], note=_resanitize(record.get("note"), NOTE_CHARS),
                author=_resanitize(record.get("author"), AUTHOR_CHARS), author_verified=False,
                review_ref=_resanitize(record.get("review_ref"), REF_CHARS),
                recorded_at=_resanitize(record.get("recorded_at"), 40)))
            continue
        if record.get("attempt_id") != m.group(2) or record.get("check") not in CHECKS:
            raise ReceiptError(f"malformed attempt record: {safe_text(name, 120)}")
        target = running if m.group(3) == "running" else results
        if m.group(2) in target:
            raise ReceiptError(f"duplicate attempt record: {safe_text(name, 120)}")
        target[m.group(2)] = (int(m.group(1)), record)
    attempts = []
    for attempt_id, (_, start_rec) in sorted(running.items(), key=lambda kv: kv[1][0]):
        before = _valid_state(start_rec.get("before"))
        harness = start_rec.get("harness_changed")
        harness = [safe_fact(str(p), 200) for p in harness[:50]] if isinstance(harness, list) else []
        entry = dict(attempt_id=attempt_id, check=start_rec["check"],
                     started_at=_resanitize(start_rec.get("started_at"), 40), before=before,
                     harness_changed=harness)
        if attempt_id not in results:
            entry.update(outcome="incomplete", state="unknown", coverage="unknown")
        else:
            _, res = results.pop(attempt_id)
            code, sig = res.get("exit_code"), res.get("signal")
            if res.get("check") != start_rec["check"] or res.get("outcome") not in OUTCOMES \
                    or _valid_state(res.get("before")) != before \
                    or not _consistent(res["outcome"], code, sig):
                raise ReceiptError(f"result record does not match its start: {attempt_id}")
            after = _valid_state(res.get("after"))
            state = _derive_state(before.get("fingerprint"), after.get("fingerprint"))
            if res.get("state") != state:
                raise ReceiptError(f"result state does not match its fingerprints: {attempt_id}")
            output = res.get("output") if isinstance(res.get("output"), dict) else {}
            digest = output.get("sha256")
            entry.update(outcome=res["outcome"], exit_code=code, state=state,
                         coverage="unknown", after=after,
                         finished_at=_resanitize(res.get("finished_at"), 40),
                         output={"bytes": output.get("bytes") if isinstance(output.get("bytes"), int) else None,
                                 "sha256": digest if isinstance(digest, str) and _HEX.fullmatch(digest) else None,
                                 "stored": "excerpt" if "excerpt" in output else "digest-only"})
            if "excerpt" in output:
                entry["output"]["excerpt"] = "\n".join(
                    _resanitize(x, 500) or "" for x in str(output["excerpt"]).splitlines())
        attempts.append(entry)
    for attempt_id in results:
        diagnostics.append({"code": "result-without-start", "attempt_id": attempt_id})
    current = current if current is not None else git_facts(root)
    now_fp = current.get("fingerprint")
    checks = {}
    for kind in CHECKS:
        mine = [a for a in attempts if a["check"] == kind]
        if not mine:
            continue
        latest = mine[-1]
        fp = latest["before"].get("fingerprint")
        applies = ("unknown" if latest["outcome"] == "incomplete" or not (fp and now_fp)
                   else "current" if fp == now_fp else "stale")
        checks[kind] = dict(latest_outcome=latest["outcome"], latest_state=latest["state"],
                            applies_to_current_state=applies, attempts=len(mine),
                            passed_attempts=sum(a["outcome"] == "passed" for a in mine),
                            harness_modified=bool(latest["harness_changed"]))
    return dict(schema_version=SCHEMA, task_id=task_id,
                task=_resanitize(task.get("task"), TASK_CHARS),
                created_at=_resanitize(task.get("created_at"), 40),
                start_state=_valid_state(task.get("start_state")),
                current_state=_state(current),
                summary=dict(
                    completion=assertions[-1]["completion"] if assertions else "not-recorded",
                    checks=checks,
                    release_verification="not part of receipts; use ./manage.sh release",
                    authentication="unsigned local evidence; author is self-reported"),
                attempts=attempts, assertions=assertions, diagnostics=diagnostics)


def latest_tasks(root: Path, limit: int = 5,
                 current: dict | None = None) -> tuple[list[dict], list[dict]]:
    """Newest receipts (by task.json creation time) for status reports. Read-only;
    scans at most MAX_SCAN task directories and says so when it stops."""
    harden_path()
    root = Path(root).resolve()
    shown, problems = [], []
    names = _names(root, root / STORE, cap=MAX_SCAN)
    if len(names) > MAX_SCAN:
        problems.append({"code": "receipt-scan-capped", "task_id": "*",
                         "reason": f"more than {MAX_SCAN} entries"})
    dated = []
    for task_id in (n for n in names[:MAX_SCAN] if _ID.fullmatch(n)):
        try:
            task = _load(root, STORE / task_id / "task.json")
        except ReceiptError as exc:
            problems.append({"code": "invalid-receipt", "task_id": task_id,
                             "reason": str(exc)[:200]})
            continue
        ns = task.get("created_ns")
        dated.append((str(task.get("created_at")), ns if isinstance(ns, int) else 0, task_id))
    for *_, task_id in sorted(dated, reverse=True)[:limit]:
        try:
            shown.append(show(root, task_id, current))
        except ReceiptError as exc:
            problems.append({"code": "invalid-receipt", "task_id": task_id,
                             "reason": str(exc)[:200]})
    return shown, problems


def render(report: dict) -> str:
    s = report["summary"]
    lines = [f"Receipt {report['task_id']}  (created {report['created_at']})",
             f"Task: {report['task']}",
             f"Completion (self-reported): {s['completion']}",
             f"Release verification: {s['release_verification']}"]
    if not s["checks"]:
        lines.append("Checks: none run")
    for kind, c in s["checks"].items():
        lines.append(f"Check {kind}: latest {c['latest_outcome']} ({c['latest_state']}); "
                     f"applies to current state: {c['applies_to_current_state']}; "
                     f"{c['passed_attempts']}/{c['attempts']} attempts passed; inner coverage unknown"
                     + ("; WARNING: its own gate files were modified when it ran"
                        if c["harness_modified"] else ""))
    for a in report["assertions"]:
        lines.append(f"Assertion {a['completion']} by {a['author']} (unverified) "
                     f"at {a['recorded_at']}: {a['note'] or ''}")
    for d in report["diagnostics"]:
        lines.append(f"Diagnostic: {d['code']} {d.get('attempt_id', '')}")
    lines.append(f"Note: {s['authentication']}")
    return "\n".join(lines)


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="./manage.sh receipt", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("start", help="record a new task")
    p.add_argument("--task", required=True)
    p = sub.add_parser("check", help="run one known check and record it")
    p.add_argument("task_id")
    p.add_argument("--kind", required=True, choices=CHECKS)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--excerpt", action="store_true", help="also store a redacted output excerpt")
    p = sub.add_parser("annotate", help="record a self-reported completion assertion")
    p.add_argument("task_id")
    p.add_argument("--completion", required=True, choices=COMPLETIONS)
    p.add_argument("--note", default="")
    p.add_argument("--author", default="")
    p.add_argument("--review-ref", default="")
    p = sub.add_parser("show", help="summarize a receipt")
    p.add_argument("task_id")
    p.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = _root()
    try:
        if args.cmd == "start":
            print(start(root, args.task))
            return 0
        if args.cmd == "check":
            result = run_check(root, args.task_id, args.kind, args.timeout, args.excerpt)
            warn = "; WARNING: gate files modified" if result["harness_changed"] else ""
            print(f"receipt: {args.kind} {result['outcome']} (exit {result['exit_code']}); "
                  f"state {result['state']}; coverage unknown{warn}")
            return 0 if result["outcome"] == "passed" and result["state"] == "unchanged" else 1
        if args.cmd == "annotate":
            annotate(root, args.task_id, args.completion, args.note, args.author, args.review_ref)
            print(f"receipt: recorded self-reported completion '{args.completion}'")
            return 0
        report = show(root, args.task_id)
        print(json_text(report) if args.json else render(report))
        return 0
    except ReceiptError as exc:
        # Built only from fixed text and already-sanitized fragments; sanitizing
        # again would swallow the whole message around a redaction marker.
        print(f"receipt: {str(exc)[:300]}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"receipt: {safe_text(str(exc), 300)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
