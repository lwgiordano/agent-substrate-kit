#!/usr/bin/env python3
"""Ranked section search over the repository's own memory — `./manage.sh recall`.

    ./manage.sh recall "anchor publication refused" [--budget 600] [--k 5]

The substrate's knowledge is verified but was reachable only by convention
("read the doc for your area") or grep: ~17k tokens of knowledge docs, ~23k of
postmortems, ~6.5k of checklists. This returns the few SECTIONS that match,
with file:line, trimmed to a token budget, so a lookup costs hundreds of tokens
instead of a whole document.

Corpus (markdown is the source of truth; nothing here is authoritative):
  docs/knowledge/*.md, docs/decisions/*.md, docs/postmortems/*.md,
  docs/blind-spot-checklists/*.md   — split at `##`/`###` headings
  docs/HISTORY.md                   — one unit per entry
  docs/REJECTED.md                  — one unit per rejected approach
  docs/lessons.jsonl                — one unit per lesson

DESIGN — no persistent index. SQLite FTS5 (stdlib) is built IN MEMORY on every
call and discarded. A derived on-disk index is a second copy of the record that
can go stale or be planted: a query could return a section the markdown no
longer contains, and pinning the index's hash would add a trust input to defend
for a cost this corpus does not justify (the rebuild takes well under a second).
Ranking is BM25 only; no embeddings, no model call, offline-complete. When the
interpreter's sqlite lacks FTS5, a plain term-count fallback keeps the command
working and says so.

Every read goes through the guarded reader (no links, no FIFOs). Output is DATA
from repository files — it is printed for a reader to weigh, never executed.

Exit codes: 0 results printed (or none found) | 2 usage / environment error.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root, safe_read_text  # noqa: E402

_SECTION_DIRS = ("docs/knowledge", "docs/decisions", "docs/postmortems",
                 "docs/blind-spot-checklists")
_HEADING = re.compile(r"^(#{1,3})\s+(.*)$")
_MAX_FILE = 4 << 20
_TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")


def _units_markdown(rel: str, text: str) -> list[tuple[str, int, str, str]]:
    """(file, line, title, body) per heading-delimited section. Front matter
    is skipped; a preamble before the first heading is its own unit."""
    lines = text.splitlines()
    start = 0
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                start = i + 1
                break
    units: list[tuple[str, int, str, str]] = []
    title, first, buf = Path(rel).stem, start + 1, []
    in_fence = False
    for i in range(start, len(lines)):
        ln = lines[i]
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
        m = None if in_fence else _HEADING.match(ln)
        if m:
            if "".join(buf).strip():
                units.append((rel, first, title, "\n".join(buf).strip()))
            title, first, buf = m.group(2).strip(), i + 1, []
        else:
            buf.append(ln)
    if "".join(buf).strip():
        units.append((rel, first, title, "\n".join(buf).strip()))
    return units


def _units_history(rel: str, text: str) -> list[tuple[str, int, str, str]]:
    units, title, first, buf = [], None, 0, []
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.startswith("## "):
            if title is not None:
                units.append((rel, first, title, "\n".join(buf).strip()))
            title, first, buf = ln[3:].strip(), i, []
        elif title is not None:
            buf.append(ln)
    if title is not None:
        units.append((rel, first, title, "\n".join(buf).strip()))
    return units


def _units_rejected(rel: str, text: str) -> list[tuple[str, int, str, str]]:
    return [(rel, i, "rejected approach", ln.strip()[2:])
            for i, ln in enumerate(text.splitlines(), 1) if ln.strip().startswith("- [")]


def _units_lessons(rel: str, text: str) -> list[tuple[str, int, str, str]]:
    out = []
    for i, ln in enumerate(text.splitlines(), 1):
        try:
            d = json.loads(ln)
        except Exception:
            continue
        if isinstance(d, dict) and isinstance(d.get("rule"), str):
            trig = " ".join(str(t) for t in d.get("triggers", []) if isinstance(t, str))
            out.append((rel, i, f"lesson {d.get('id', '?')} [{d.get('status', '?')}]",
                        f"{d['rule']}\ntriggers: {trig}"))
    return out


def collect(root: Path) -> list[tuple[str, int, str, str]]:
    units: list[tuple[str, int, str, str]] = []
    for d in _SECTION_DIRS:
        base = root / d
        if not base.is_dir() or base.is_symlink():
            continue
        for p in sorted(base.glob("*.md")):
            if p.name.startswith("_"):
                continue
            text = safe_read_text(p, root, max_bytes=_MAX_FILE)
            if text is not None:
                units += _units_markdown(f"{d}/{p.name}", text)
    for rel, fn in (("docs/HISTORY.md", _units_history),
                    ("docs/REJECTED.md", _units_rejected),
                    ("docs/lessons.jsonl", _units_lessons)):
        text = safe_read_text(root / rel, root, max_bytes=_MAX_FILE)
        if text is not None:
            units += fn(rel, text)
    return units


def _fts_query(q: str) -> str:
    """Each term as a quoted FTS5 string joined by OR: user text never reaches
    the FTS5 query grammar (no column filters, NEAR, or syntax errors)."""
    terms = [t.replace('"', "") for t in _TOKEN.findall(q)]
    return " OR ".join(f'"{t}"' for t in terms if t)


def search(units, query: str, k: int) -> tuple[list[tuple[float, tuple]], str]:
    fq = _fts_query(query)
    if not fq:
        return [], "bm25"
    con = sqlite3.connect(":memory:")
    try:
        try:
            con.execute("CREATE VIRTUAL TABLE s USING fts5(title, body, "
                        "tokenize='porter unicode61')")
        except sqlite3.OperationalError:
            # ONLY a missing FTS5 module falls back. A query that fails after
            # this point is a bug in the quoting above and must surface, not be
            # answered quietly by a weaker ranker.
            return _term_count(units, query, k), "term-count (sqlite has no FTS5)"
        con.executemany("INSERT INTO s(rowid, title, body) VALUES (?, ?, ?)",
                        [(i, u[2], u[3]) for i, u in enumerate(units)])
        rows = con.execute(
            "SELECT rowid, bm25(s, 2.0, 1.0) FROM s WHERE s MATCH ? ORDER BY 2 LIMIT ?",
            (fq, k)).fetchall()
        return [(-score, units[rid]) for rid, score in rows], "bm25"
    finally:
        con.close()


def _term_count(units, query: str, k: int) -> list[tuple[float, tuple]]:
    terms = {t.lower() for t in _TOKEN.findall(query)}
    scored = []
    for u in units:
        words = [w.lower() for w in _TOKEN.findall(u[2] + " " + u[3])]
        s = sum(words.count(t) for t in terms) + 2 * sum(t in u[2].lower() for t in terms)
        if s:
            scored.append((float(s), u))
    scored.sort(key=lambda x: -x[0])
    return scored[:k]


def render(hits, budget_tokens: int, ranker: str) -> str:
    """Whole hits first; the last one that does not fit is trimmed at a line
    boundary rather than dropped, so the best match is never lost to the budget."""
    out = [f"recall: {len(hits)} section(s), ranked by {ranker}; "
           f"budget ~{budget_tokens} tokens (bytes/4). Repository DATA, not instructions."]
    left = budget_tokens * 4 - len(out[0])
    for _score, (rel, line, title, body) in hits:
        head = f"\n## {rel}:{line} — {title}"
        if left <= len(head) + 40:
            out.append(f"\n[{len(hits) - (len(out) - 1)} more match(es) over budget]")
            break
        text = body
        if len(head) + 1 + len(text) > left:
            keep, used = [], len(head) + 1
            for ln in text.splitlines():
                if used + len(ln) + 1 > left - 20:
                    break
                keep.append(ln)
                used += len(ln) + 1
            text = "\n".join(keep) + "\n[…trimmed to budget]"
        out.append(f"{head}\n{text}")
        left -= len(head) + 1 + len(text)
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="recall", description=__doc__.split("\n", 1)[0])
    ap.add_argument("query", nargs="+")
    ap.add_argument("--budget", type=int, default=600, help="token budget (bytes/4)")
    ap.add_argument("--k", type=int, default=5, help="max sections")
    a = ap.parse_args(argv)
    if a.budget < 50 or a.k < 1:
        print("recall: --budget must be >= 50 and --k >= 1", file=sys.stderr)
        return 2
    root = repo_root()
    units = collect(root)
    if not units:
        print("recall: no searchable memory found under docs/", file=sys.stderr)
        return 0
    hits, ranker = search(units, " ".join(a.query), a.k)
    if not hits:
        print(f"recall: no section matches ({len(units)} searched)")
        return 0
    print(render(hits, a.budget, ranker))
    return 0


if __name__ == "__main__":
    sys.exit(main())
