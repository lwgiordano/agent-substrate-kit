#!/usr/bin/env python3
"""Measure the repo's agent CONTEXT footprint — LOCAL, READ-ONLY. (v3.6.2)

Token efficiency is the remaining "optimize memory + tokens" goal. This reports
what an agent actually loads, split by WHEN it loads:

  ALWAYS-LOADED   read every turn (the real per-turn cost): CLAUDE.md, AGENTS.md,
                  .claude/settings.json, and the skill INDEX (each SKILL.md's
                  name+description — what a host loads to decide whether to trigger
                  a skill; the body is NOT loaded until the skill is invoked).
  SESSION         re-injected after compaction: CURRENT_SESSION.md, todo state.
  MEMORY          the durable event log.
  ON-DEMAND       progressive disclosure — loaded only when invoked: skill BODIES,
                  subagent defs, knowledge docs, ADRs, postmortems.
  OTHER-AGENT     always-loaded for non-Claude hosts (Gemini/Copilot pointers).

Plus the CACHE-PREFIX hash (CLAUDE.md+AGENTS.md): a byte-stable prefix earns the
~10x cached-read discount (break-even ~2nd hit), so a changing hash = lost caching.

NO network, NO token, NO venv creation, NO writes. Token counts are a rough
estimate (~bytes/4) for RELATIVE comparison, not billing.

Usage: context_report.py [--root PATH] [--json]
Exit: 0 always (informational).
"""
from __future__ import annotations
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()

# Heuristics. ~4 bytes/token is the standard rough rule for English+code; good
# enough for relative comparison (which file dominates), not for billing.
def _tok(nbytes: int) -> int:
    return round(nbytes / 4)


def _size(p: Path) -> int:
    try:
        return p.stat().st_size if p.is_file() else 0
    except Exception:
        return 0


def _frontmatter_bytes(p: Path) -> int:
    """Bytes of a SKILL.md's leading `--- ... ---` frontmatter (name+description) —
    the part a host loads ALWAYS to match triggers. Body is on-demand."""
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0
    if not txt.startswith("---"):
        return 0
    end = txt.find("\n---", 3)
    if end == -1:
        return len(txt.encode("utf-8", "replace"))
    return len(txt[: end + 4].encode("utf-8", "replace"))


def _glob_files(root: Path, *globs: str):
    out = []
    for g in globs:
        for p in root.glob(g):
            if p.is_file():
                out.append(p)
    return out


def build(root: Path) -> dict:
    contributors = []  # (bytes, rel, tier)

    def note(p: Path, tier: str, nbytes=None):
        if not p.is_file():
            return 0
        b = nbytes if nbytes is not None else _size(p)
        contributors.append((b, p.relative_to(root).as_posix(), tier))
        return b

    # --- always-loaded (Claude per-turn) ---
    always = {}
    for rel in ("CLAUDE.md", "AGENTS.md", ".claude/settings.json"):
        always[rel] = note(root / rel, "always")
    # skill INDEX = sum of frontmatter (name+description) across skills; bodies are on-demand
    skill_mds = _glob_files(root, ".claude/skills/*/SKILL.md")
    skill_index = sum(_frontmatter_bytes(p) for p in skill_mds)
    skill_body = sum(_size(p) - _frontmatter_bytes(p) for p in skill_mds)
    # Register each skill BODY as an on-demand contributor (the body loads only on
    # invocation), so a heavy skill shows up in the largest-contributors ranking.
    for p in skill_mds:
        note(p, "on-demand", nbytes=_size(p) - _frontmatter_bytes(p))
    # All non-SKILL.md files under any skill dir (references/, nested) — on-demand.
    # Single recursive glob (no overlapping globs → no double-count).
    ref_files = [p for p in root.glob(".claude/skills/*/**/*") if p.is_file() and p.name != "SKILL.md"]
    for p in ref_files:
        note(p, "on-demand")
    skill_refs = sum(_size(p) for p in ref_files)
    always["skill index (%d skills)" % len(skill_mds)] = skill_index
    always_total = sum(always.values())

    # --- session / compaction (re-injected) ---
    session = {rel: _size(root / rel) for rel in ("docs/CURRENT_SESSION.md", "docs/.todo_state.json")}
    for rel in session:
        note(root / rel, "session")
    # --- memory ---
    mem_files = _glob_files(root, ".substrate/memory/**/*")
    memory_total = sum(_size(p) for p in mem_files)

    # --- on-demand (progressive disclosure) ---
    agents = _glob_files(root, ".claude/agents/*.md", ".codex/agents/*")
    knowledge = [p for p in _glob_files(root, "docs/knowledge/*.md") if not p.name.startswith("_")]
    adrs = [p for p in _glob_files(root, "docs/decisions/*.md") if not p.name.startswith("_")]
    postmortems = [p for p in _glob_files(root, "docs/postmortems/*.md") if not p.name.startswith("_")]
    for p in agents + knowledge + adrs + postmortems:
        note(p, "on-demand")
    on_demand = {
        "skill bodies (%d)" % len(skill_mds): skill_body + skill_refs,
        "subagent defs (%d)" % len(agents): sum(_size(p) for p in agents),
        "knowledge docs (%d)" % len(knowledge): sum(_size(p) for p in knowledge),
        "ADRs (%d)" % len(adrs): sum(_size(p) for p in adrs),
        "postmortems (%d)" % len(postmortems): sum(_size(p) for p in postmortems),
    }
    on_demand_total = sum(on_demand.values())

    # --- other-agent always-loaded (informational) ---
    other = {}
    for rel in ("GEMINI.md", ".github/copilot-instructions.md"):
        if (root / rel).is_file():
            other[rel] = note(root / rel, "other-agent")
    inst = _glob_files(root, ".github/instructions/*.instructions.md")
    if inst:
        for p in inst:
            note(p, "other-agent")
        other[".github/instructions (%d)" % len(inst)] = sum(_size(p) for p in inst)

    # --- cache prefix (the stable instruction prefix) ---
    h = hashlib.sha256()
    prefix_bytes = 0
    for rel in ("CLAUDE.md", "AGENTS.md"):
        p = root / rel
        if p.is_file():
            data = p.read_bytes()
            h.update(data)
            prefix_bytes += len(data)
    cache_prefix = h.hexdigest()

    contributors.sort(reverse=True)
    recs = []
    if _tok(always_total) > 3000:
        recs.append(f"Always-loaded context is ~{_tok(always_total)} tok/turn — trim AGENTS.md and move "
                    "detail into docs/knowledge/ (read on demand, not every turn).")
    if always.get("AGENTS.md", 0) > 6000:
        recs.append(f"AGENTS.md is {always['AGENTS.md']}B — keep the keystone lean AND byte-stable so it "
                    "stays at the top of the cached prompt prefix.")
    if session.get("docs/CURRENT_SESSION.md", 0) > 8000:
        recs.append("docs/CURRENT_SESSION.md is large — compaction RE-INJECTS it every recovery; keep handoffs terse.")
    if memory_total > 2_000_000:
        recs.append(f"Memory log is {memory_total // 1000}KB — consider compaction/anchoring (it is not loaded into "
                    "context, but grows the repo).")
    recs.append("Keep CLAUDE.md/AGENTS.md byte-stable across runs — a stable cached prefix earns a ~10x cached-read "
                "discount (break-even ~2nd hit). The cache-prefix hash above changes whenever they do.")
    if _tok(always_total) <= 3000 and always.get("AGENTS.md", 0) <= 6000:
        recs.insert(0, "Always-loaded footprint is lean — most context (skills bodies, knowledge, agents) is on-demand. Good.")

    return {
        "always_loaded": {"files": always, "total_bytes": always_total, "est_tokens": _tok(always_total)},
        "session": {"files": session, "total_bytes": sum(session.values()), "est_tokens": _tok(sum(session.values()))},
        "memory": {"total_bytes": memory_total, "files": len(mem_files)},
        "on_demand": {"groups": on_demand, "total_bytes": on_demand_total, "est_tokens": _tok(on_demand_total)},
        "other_agent": {"files": other, "total_bytes": sum(other.values())},
        "cache_prefix": {"files": ["CLAUDE.md", "AGENTS.md"], "bytes": prefix_bytes, "sha256": cache_prefix},
        "largest_contributors": [{"bytes": b, "path": r, "tier": t} for b, r, t in contributors[:10]],
        "recommendations": recs,
    }


def _print(d: dict) -> None:
    def line(label, nbytes, indent=2):
        print(f"{' ' * indent}{nbytes:>9}  ~{_tok(nbytes):>6} tok  {label}")
    print("CONTEXT REPORT  (rough est ~bytes/4; for relative comparison, not billing)")
    print("=" * 66)
    al = d["always_loaded"]
    print(f"\nALWAYS-LOADED (every turn) — {al['total_bytes']}B ~{al['est_tokens']} tok")
    for k, v in al["files"].items():
        line(k, v)
    s = d["session"]
    print(f"\nSESSION / compaction (re-injected) — {s['total_bytes']}B")
    for k, v in s["files"].items():
        line(k if v else f"{k} (absent)", v)
    m = d["memory"]
    print(f"\nMEMORY — {m['total_bytes']}B across {m['files']} file(s) (durable log; not loaded into context)")
    od = d["on_demand"]
    print(f"\nON-DEMAND (progressive disclosure — loaded only when invoked) — {od['total_bytes']}B ~{od['est_tokens']} tok")
    for k, v in od["groups"].items():
        line(k, v)
    if d["other_agent"]["files"]:
        print(f"\nOTHER-AGENT always-loaded (per host) — {d['other_agent']['total_bytes']}B")
        for k, v in d["other_agent"]["files"].items():
            line(k, v)
    cp = d["cache_prefix"]
    print(f"\nCACHE PREFIX (CLAUDE.md+AGENTS.md): {cp['bytes']}B  sha256={cp['sha256'][:16]}…")
    print("  byte-stable prefix → ~10x cached-read discount; this hash changes whenever those files do.")
    print("\nLARGEST CONTRIBUTORS:")
    for c in d["largest_contributors"]:
        print(f"  {c['bytes']:>9}  [{c['tier']}]  {c['path']}")
    print("\nRECOMMENDATIONS:")
    for r in d["recommendations"]:
        print("  - " + r)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    d = build(Path(a.root))
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        _print(d)
    return 0


if __name__ == "__main__":
    sys.exit(main())
