#!/usr/bin/env python3
"""Prove every registered guard is load-bearing — `./manage.sh prove`.

    ./manage.sh prove                 # every guard in tests/guards.json
    ./manage.sh prove --only ID ...   # a subset
    ./manage.sh prove --list

A regression test that still passes with its guard removed proves nothing, and
it looks identical to proof. Four audit rounds running (v3.8.54–57) the probes
that were supposed to show a guard mattered did not: a redundant guard that a
single revert could not pin, a whole-line check that a sibling kept green, a
string search satisfied by an import. Each time the check was a person
remembering to revert the guard by hand. This makes it a gate.

Each registry entry names a guard by an EXACT source snippet (`find`), the
neutralized form (`replace`), and the pytest node ids that must catch it:

    {"id": "record-verify", "file": "scripts/memory_log.py",
     "find": "...", "replace": "...", "tests": ["tests/x.py::test_y"],
     "why": "one line: what an attacker gets if this guard goes"}

A REDUNDANT guard — two checks that each block the attack alone — cannot be
pinned by reverting one (carry-forward 22), so an entry may give `edits`, a list
of {file, find, replace} reverted together, and must say so in `why`.

For each guard, in a PRIVATE COPY of the working tree (never the live one — an
interrupted run must not leave a guard neutralized in place):
  1. every `find` must occur EXACTLY once. Zero means the registry is stale (a
     refactor moved the guard); more than one means the snippet does not
     identify one guard. Either is a failure, not a skip.
  2. The mapped tests must PASS unmodified (one baseline run for all guards):
     a test that already fails proves nothing when it fails again.
  3. With the snippet neutralized they must FAIL — pytest rc 1 with a failed
     test. rc 2/3/4/5 (collection error, internal error, usage, nothing
     collected) is NOT proof: a nonzero exit is not evidence of the failure you
     meant, and a typo'd node id is the most common way to get one.

Exit codes: 0 every guard proven | 1 a guard survived its removal, a snippet
is stale/ambiguous, or the baseline failed | 2 usage / environment error.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root, safe_read_bytes, safe_read_text  # noqa: E402

REGISTRY = "tests/guards.json"
_TIMEOUT = int(os.environ.get("SUBSTRATE_PROVE_TIMEOUT", "600"))
_REQUIRED = ("id", "tests", "why")


def _edits(gd: dict) -> list[dict] | None:
    """A guard's neutralization as a list of {file, find, replace}, or None if
    malformed."""
    raw = gd.get("edits") if "edits" in gd else [
        {k: gd.get(k) for k in ("file", "find", "replace")}]
    if not isinstance(raw, list) or not raw:
        return None
    for e in raw:
        if not isinstance(e, dict) or not all(isinstance(e.get(k), str)
                                              for k in ("file", "find", "replace")):
            return None
        if not e["file"] or not e["find"] or e["find"] == e["replace"]:
            return None
        if Path(e["file"]).is_absolute() or ".." in Path(e["file"]).parts:
            return None
    return raw


def load_registry(root: Path, rel: str) -> tuple[list[dict] | None, str]:
    text = safe_read_text(root / rel, root, max_bytes=4 << 20)
    if text is None:
        return None, f"{rel} is absent or not a private regular file"
    try:
        data = json.loads(text)
    except ValueError as e:
        return None, f"{rel} is not valid JSON: {e}"
    guards = data.get("guards") if isinstance(data, dict) else None
    if not isinstance(guards, list):
        return None, f'{rel} must be an object with a "guards" list'
    seen: set[str] = set()
    for i, gd in enumerate(guards):
        if not isinstance(gd, dict) or any(k not in gd for k in _REQUIRED):
            return None, f"{rel}: guard #{i} lacks one of {', '.join(_REQUIRED)}"
        if not all(isinstance(gd[k], str) and gd[k] for k in ("id", "why")) or _edits(gd) is None:
            return None, (f"{rel}: guard {gd.get('id', i)!r} needs a non-empty, repo-relative "
                          "file/find/replace (or an `edits` list of them) that changes something")
        if not isinstance(gd["tests"], list) or not gd["tests"] or \
                not all(isinstance(t, str) and "::" in t for t in gd["tests"]):
            return None, f"{rel}: guard {gd['id']!r} needs pytest node ids (file::test)"
        if gd["id"] in seen:
            return None, f"{rel}: duplicate guard id {gd['id']!r}"
        seen.add(gd["id"])
    return guards, ""


def _tracked(root: Path) -> list[str]:
    p = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                       cwd=root, capture_output=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("git ls-files failed: " + p.stderr.decode(errors="replace").strip())
    return [f for f in p.stdout.decode().split("\0") if f]


def make_copy(root: Path, dest: Path) -> None:
    """The working tree's tracked + unignored files, as a fresh git repo (some
    tests ask git about the tree they run in). Links are copied AS links and
    never followed, so a planted symlink cannot pull an outside file in."""
    for rel in _tracked(root):
        src, dst = root / rel, dest / rel
        if not os.path.lexists(src):
            continue                                  # deleted in the work tree
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            os.symlink(os.readlink(src), dst)
            continue
        if src.is_dir():
            continue                                  # a submodule/gitlink
        # The guarded reader: a hard-linked or special tracked file is refused,
        # loudly — a copy missing a file would fail the baseline for the wrong
        # reason, and an outside inode must not be read in.
        data = safe_read_bytes(src, root, max_bytes=64 << 20)
        if data is None:
            raise RuntimeError(f"refusing to copy {rel}: linked, special, or over 64 MiB")
        dst.write_bytes(data)
        os.chmod(dst, os.lstat(src).st_mode & 0o755)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=prove@substrate.invalid", "-c", "user.name=prove",
                  "commit", "-qm", "prove baseline", "--no-verify"]):
        subprocess.run(["git", *args], cwd=dest, capture_output=True, timeout=120,
                       env=env, check=True)


def run_tests(copy: Path, nodes: list[str]) -> tuple[int, str]:
    # Strip, never set: a project-dir variable naming the live repo would point
    # the copy's tests back at it, and setting it to the copy overrides the
    # temp-repo fixtures the tests build for themselves.
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PROJECT_DIR", "SUBSTRATE_PROJECT_DIR", "PYTEST_ADDOPTS")}
    # NO BYTECODE CACHE. A .pyc is validated by source mtime (1s resolution) and
    # size, and a neutralization is often the same length as the guard
    # (`if x < 0:` / `if False:`). Within one second the cache then served the
    # ORIGINAL code to the mutated run — a false SURVIVED — or, worse, the
    # previous guard's MUTATED code to the next run, a failure credited to the
    # wrong guard: a false "proven". Found by this file's own test flaking.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:randomly",
                            "-p", "no:cacheprovider", *nodes], cwd=copy, env=env,
                           capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return p.returncode, p.stdout + p.stderr


def _tail(out: str, n: int = 6) -> str:
    return "\n".join("      " + ln for ln in out.strip().splitlines()[-n:])


def prove(root: Path, guards: list[dict]) -> int:
    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="substrate-prove.") as td:
        copy = Path(td) / "repo"
        copy.mkdir()
        make_copy(root, copy)
        problems: list[str] = []
        originals: dict[str, str] = {}
        for gd in guards:
            for e in _edits(gd) or []:
                path = copy / e["file"]
                if path.is_symlink() or not path.is_file():
                    problems.append(f"{gd['id']}: {e['file']} is missing or not a regular file")
                    continue
                text = originals.setdefault(e["file"], path.read_text(encoding="utf-8"))
                n = text.count(e["find"])
                if n != 1:
                    problems.append(f"{gd['id']}: snippet occurs {n} times in {e['file']} — "
                                    + ("the registry is STALE (was the guard moved or renamed?)"
                                       if n == 0 else "it does not identify one guard"))
        if problems:
            for p in problems:
                print(f"prove: FAIL {p}", file=sys.stderr)
            return 1
        nodes = sorted({t for gd in guards for t in gd["tests"]})
        rc, out = run_tests(copy, nodes)
        if rc != 0:
            print(f"prove: FAIL baseline — the mapped tests do not pass on the unmodified "
                  f"tree (pytest rc {rc}), so their failing later would prove nothing:\n"
                  + _tail(out, 12), file=sys.stderr)
            return 1
        proven, survived = 0, []
        for gd in guards:
            mutated: dict[str, str] = {}
            for e in _edits(gd) or []:
                cur = mutated.get(e["file"], originals[e["file"]])
                mutated[e["file"]] = cur.replace(e["find"], e["replace"], 1)
            try:
                for f, txt in mutated.items():
                    (copy / f).write_text(txt, encoding="utf-8")
                rc, out = run_tests(copy, gd["tests"])
            finally:
                for f in mutated:
                    (copy / f).write_text(originals[f], encoding="utf-8")
            if rc == 1 and ("failed" in out or "FAILED" in out):
                proven += 1
                print(f"  proven   {gd['id']}")
            else:
                why = ("its tests still PASS without it" if rc == 0 else
                       f"pytest rc {rc} is not a test failure (collection/usage/timeout)")
                survived.append(gd["id"])
                print(f"  SURVIVED {gd['id']} — {why}\n      guards against: {gd['why']}"
                      + ("\n" + _tail(out) if rc not in (0, 1) else ""), file=sys.stderr)
    dt = time.time() - t0
    if survived:
        print(f"prove: FAIL — {len(survived)}/{len(guards)} guard(s) survived their own "
              f"removal: {', '.join(survived)}. A test that passes without its guard is "
              f"not evidence for it. ({dt:.0f}s)", file=sys.stderr)
        return 1
    print(f"prove: {proven}/{len(guards)} guards proven — removing each one made its "
          f"tests fail ({dt:.0f}s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="prove", description=__doc__.split("\n", 1)[0])
    ap.add_argument("--registry", default=REGISTRY)
    ap.add_argument("--only", nargs="+", metavar="ID")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    root = repo_root()
    guards, err = load_registry(root, a.registry)
    if guards is None:
        print(f"prove: {err}", file=sys.stderr)
        return 2
    if a.only:
        unknown = sorted(set(a.only) - {g["id"] for g in guards})
        if unknown:
            print(f"prove: unknown guard id(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        guards = [g for g in guards if g["id"] in set(a.only)]
    if a.list:
        for g in guards:
            files = ", ".join(sorted({e["file"] for e in _edits(g) or []}))
            print(f"{g['id']:<34} {files}  — {g['why']}")
        return 0
    if not guards:
        print("prove: the registry lists no guards", file=sys.stderr)
        return 2
    try:
        return prove(root, guards)
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        print(f"prove: environment error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
