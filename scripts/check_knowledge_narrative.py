#!/usr/bin/env python3
"""Warn when knowledge docs narrate history instead of stating the contract.

    python scripts/check_knowledge_narrative.py [--strict] [--list]

docs/knowledge/ is read to learn how the substrate works NOW. Release narrative
("it once demanded equality", "v3.8.54 fixed…", "round-37 found…") belongs in
HISTORY, postmortems, and ADRs, where it is append-only and dated. In a
knowledge doc it costs budget on every read and ages into contradiction: two
docs were split this arc after repeated trimming, most of what was trimmed was
narrative, and a reader cannot tell a superseded sentence from a live one.

This is WARN-ONLY by design (rc 0): the existing docs carry narrative, and a
new advisory signal is dogfooded before it blocks (INTENT.md). `--strict`
returns 1 when anything is flagged, for a later ratchet.

Flags, per line, outside front matter and code fences:
  - history verbs: "used to", "formerly", "(it|this|…) once <verb>"
    ("previously anchored" and "no longer in the chain" are contract language,
    so they are deliberately not flagged: a warn-only signal must be precise)
  - release narrative: "(v3.8.54 …", "v3.8.54: …", "round-37", "Codex round"

Exit codes: 0 (warnings allowed) | 1 --strict and something flagged.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root, safe_read_text  # noqa: E402

_PATTERNS = [
    ("history verb", re.compile(
        r"\b(?:used to|formerly)\b"
        r"|\b(?:it|this|that|which|the gate|the check) once\b", re.I)),
    ("release narrative", re.compile(
        r"\(v\d+\.\d+\.\d+\b|\bv\d+\.\d+\.\d+\s*[:(]|\bround-\d+\b|\bCodex round\b")),
]


def scan(text: str) -> list[tuple[int, str, str]]:
    hits: list[tuple[int, str, str]] = []
    lines = text.splitlines()
    start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                start = i + 1
                break
    fence = False
    for i in range(start, len(lines)):
        ln = lines[i]
        if ln.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        for label, rx in _PATTERNS:
            m = rx.search(ln)
            if m:
                hits.append((i + 1, label, m.group(0)))
                break
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--list", action="store_true", help="print every flagged line")
    a = ap.parse_args(argv)
    root = repo_root()
    base = root / "docs" / "knowledge"
    total, per_doc = 0, []
    for p in sorted(base.glob("*.md")) if base.is_dir() else []:
        if p.name.startswith("_"):
            continue
        text = safe_read_text(p, root, max_bytes=1 << 20)
        if text is None:
            continue
        hits = scan(text)
        if hits:
            total += len(hits)
            per_doc.append((p.name, hits))
    if not total:
        print("knowledge-narrative: ok (no release narrative in docs/knowledge)")
        return 0
    for name, hits in per_doc:
        print(f"knowledge-narrative: WARN {name}: {len(hits)} narrative line(s)")
        for line, label, frag in hits if a.list else hits[:2]:
            print(f"    docs/knowledge/{name}:{line}  {label}: {frag!r}")
    print(f"knowledge-narrative: {total} line(s) narrate history — move them to HISTORY, a "
          "postmortem, or an ADR and state the current contract (warn-only; --list for all)")
    return 1 if a.strict else 0


if __name__ == "__main__":
    sys.exit(main())
