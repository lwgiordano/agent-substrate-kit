#!/usr/bin/env python3
"""Validate docs/lessons.jsonl — lessons must carry evidence that still exists.

A lesson is a rule a past failure taught (the carry-forward rules). Written
down as prose, rule 22 recurred three times in one session; what stopped each
recurrence was a test. So a lesson here is structured and bound to evidence:

  {"id": "L27", "rule": "<=200 chars", "triggers": ["scripts/*.py"],
   "evidence": {"sha": "<commit>|null", "test": "<ref>|null"},
   "status": "prose|test|gate", "added": "3.8.55", "last_confirmed": "3.9.0",
   "superseded_by": null}

  evidence.test is one of
    tests/<file>.py::<test_name>   a pytest test that must exist
    evals::<t_function>            an eval task in scripts/run_substrate_evals.py
    gate::scripts/<validator>      a deterministic validator that must exist

FAILS (rc 1): malformed line or field; duplicate id; status test/gate whose
evidence does not exist (the `asserts:` rule for knowledge docs, applied to
lessons — a lesson whose test was deleted is a belief nobody re-checks);
superseded_by naming no lesson; an evidence sha that does not resolve.
WARNS (rc 0): status `prose` — a rule nothing enforces is itself a finding,
the promotion path is prose -> test -> gate; last_confirmed three or more
releases behind VERSION; a lesson not yet recorded in the memory chain
(`./manage.sh memory record docs/lessons.jsonl`), which SessionStart will not
inject.

An absent docs/lessons.jsonl is valid (a fresh install has no lessons yet).
Exit codes: 0 ok (warnings allowed) | 1 finding | 2 environment error.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root, safe_read_text  # noqa: E402

LESSONS = "docs/lessons.jsonl"
STATUSES = ("prose", "test", "gate")
_ID = re.compile(r"^L\d{2,4}$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_KEYS = ("id", "rule", "triggers", "evidence", "status", "added", "last_confirmed",
         "superseded_by")


def evidence_exists(root: Path, ref: str) -> bool:
    """Whether an evidence.test reference names something that exists NOW."""
    if ref.startswith("gate::"):
        p = root / ref[6:]
        return p.is_file() and not p.is_symlink() and ref[6:].startswith("scripts/")
    if ref.startswith("evals::"):
        src = safe_read_text(root / "scripts" / "run_substrate_evals.py", root,
                             max_bytes=16 << 20) or ""
        return bool(re.search(rf"^def {re.escape(ref[7:])}\(", src, re.M))
    if "::" in ref:
        f, name = ref.split("::", 1)
        if not f.startswith("tests/") or ".." in Path(f).parts:
            return False
        src = safe_read_text(root / f, root, max_bytes=16 << 20) or ""
        return bool(re.search(rf"^def {re.escape(name)}\(", src, re.M))
    return False


def _vtuple(v: str) -> tuple[int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c


def _releases_behind(current: str, confirmed: str) -> int:
    """Releases between two versions. Within a minor line, the patch distance;
    across ONE minor step (3.8.57 -> 3.9.x), the x.y.0 release plus its patches
    (3.9.0 is one release after 3.8.57, not three); anything further is stale."""
    c, k = _vtuple(current), _vtuple(confirmed)
    if k >= c:
        return 0
    if c[:2] == k[:2]:
        return c[2] - k[2]
    if c[0] == k[0] and c[1] == k[1] + 1:
        return c[2] + 1
    return 3


def parse(text: str) -> tuple[list[dict], list[str]]:
    lessons, findings = [], []
    for n, ln in enumerate(text.splitlines(), 1):
        if not ln.strip():
            continue
        try:
            d = json.loads(ln)
        except ValueError as e:
            findings.append(f"line {n}: not valid JSON ({e})")
            continue
        if not isinstance(d, dict) or tuple(k for k in _KEYS if k not in d):
            findings.append(f"line {n}: needs keys {', '.join(_KEYS)}")
            continue
        d["_line"] = n
        lessons.append(d)
    return lessons, findings


def check(root: Path, current_version: str) -> tuple[list[str], list[str], list[dict]]:
    text = safe_read_text(root / LESSONS, root, max_bytes=4 << 20)
    lessons, findings = parse(text or "")
    warns: list[str] = []
    ids = [d["id"] for d in lessons]
    for d in lessons:
        at = f"{LESSONS}:{d['_line']} ({d.get('id')})"
        if not isinstance(d["id"], str) or not _ID.match(d["id"]):
            findings.append(f"{at}: id must look like L07")
        elif ids.count(d["id"]) > 1:
            findings.append(f"{at}: duplicate id")
        rule = d["rule"]
        if not isinstance(rule, str) or not (20 <= len(rule) <= 200) or "\n" in rule:
            findings.append(f"{at}: rule must be one line of 20-200 characters")
        trig = d["triggers"]
        if not isinstance(trig, list) or not trig \
                or not all(isinstance(t, str) and t for t in trig):
            findings.append(f"{at}: triggers must be a non-empty list of path globs")
        ev = d["evidence"]
        if not isinstance(ev, dict) or set(ev) != {"sha", "test"}:
            findings.append(f"{at}: evidence must be {{sha, test}}")
            continue
        status = d["status"]
        if status not in STATUSES:
            findings.append(f"{at}: status must be one of {', '.join(STATUSES)}")
            continue
        test = ev["test"]
        if status == "prose":
            if test is not None:
                findings.append(f"{at}: status prose but evidence.test is set — promote it")
            warns.append(f"{at}: status PROSE — nothing enforces this rule; promote it to a "
                         "test or a gate (rule 22 recurred three times as prose)")
        elif not isinstance(test, str) or not evidence_exists(root, test):
            findings.append(f"{at}: status {status} but evidence.test {test!r} does not exist "
                            "— the lesson's proof was deleted or renamed")
        elif status == "gate" and not test.startswith("gate::"):
            findings.append(f"{at}: status gate needs gate::scripts/<validator> evidence")
        sha = ev["sha"]
        if sha is not None:
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{7,40}", sha):
                findings.append(f"{at}: evidence.sha must be a hex sha or null")
            elif subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=root,
                                capture_output=True, timeout=30).returncode != 0 \
                    and not _shallow(root):
                findings.append(f"{at}: evidence.sha {sha} does not resolve")
        for key in ("added", "last_confirmed"):
            if not isinstance(d[key], str) or not _VERSION.match(d[key]):
                findings.append(f"{at}: {key} must be a version like 3.9.0")
        sup = d["superseded_by"]
        if sup is not None and sup not in ids:
            findings.append(f"{at}: superseded_by {sup!r} names no lesson")
        if (_VERSION.match(current_version) and isinstance(d["last_confirmed"], str)
                and _VERSION.match(d["last_confirmed"]) and sup is None
                and _releases_behind(current_version, d["last_confirmed"]) >= 3):
            warns.append(f"{at}: last_confirmed {d['last_confirmed']} is 3+ releases behind "
                         f"{current_version} — re-run its evidence and bump it, or supersede it")
    return findings, warns, lessons


def _shallow(root: Path) -> bool:
    p = subprocess.run(["git", "rev-parse", "--is-shallow-repository"], cwd=root,
                       capture_output=True, text=True, timeout=30)
    return p.stdout.strip() == "true"


def _unrecorded(root: Path, lessons: list[dict]) -> list[str]:
    try:
        import memory_log as ml
    except Exception:
        return []
    recorded = ml.recorded_hashes(root, LESSONS)
    if recorded is None:
        return []          # no verifying chain: `memory verify` reports that, not us
    return [d["id"] for d in lessons if isinstance(d.get("id"), str)
            and isinstance(d.get("rule"), str)
            and ml.lesson_unit_hash(d["id"], d["rule"]) not in recorded]


def main() -> int:
    root = repo_root()
    path = root / LESSONS
    if not path.exists() and not path.is_symlink():
        print("check-lessons: no docs/lessons.jsonl (nothing to validate)")
        return 0
    if safe_read_text(path, root, max_bytes=4 << 20) is None:
        print(f"check-lessons: {LESSONS} is linked, special, or too large — refusing",
              file=sys.stderr)
        return 1
    version = (safe_read_text(root / "VERSION", root, max_bytes=64) or "").strip()
    findings, warns, lessons = check(root, version)
    unrec = _unrecorded(root, lessons)
    if unrec:
        warns.append(f"{len(unrec)} lesson(s) not recorded in the memory chain "
                     f"({', '.join(unrec[:5])}{'…' if len(unrec) > 5 else ''}) — SessionStart "
                     "injects only recorded lessons: "
                     "`./manage.sh memory record docs/lessons.jsonl`")
    for w in warns:
        print(f"check-lessons: WARN {w}")
    if findings:
        for f in findings:
            print(f"check-lessons: {f}", file=sys.stderr)
        return 1
    counts = {s: sum(1 for d in lessons if d["status"] == s) for s in STATUSES}
    print(f"check-lessons: {len(lessons)} lessons ({counts['gate']} gate / {counts['test']} "
          f"test / {counts['prose']} prose), evidence present; {len(warns)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
