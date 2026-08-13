#!/usr/bin/env python3
"""Measure the repo's agent CONTEXT footprint — LOCAL, READ-ONLY. (v3.6.2; semantics corrected v3.6.3)

Token efficiency is the remaining "optimize memory + tokens" goal. This reports
what an agent actually loads, classified by HOW/WHEN it loads — measuring the
ACTUAL sources of truth, not human-facing derivations:

  ALWAYS-LOADED (prompt)  injected into the model prompt every turn: CLAUDE.md,
                          AGENTS.md, and the skill INDEX (each SKILL.md's
                          name+description — what a host loads to decide whether to
                          trigger a skill; the body is NOT loaded until invoked).
  SESSION restore         re-injected at SessionStart / after compaction. The SOURCE
                          OF TRUTH is .substrate/memory/tasks/current.json (structured;
                          session_handoff.py restore reads THIS, never the Markdown).
                          docs/.todo_state.json is capture input (the TodoWrite mirror).
  DERIVED (human-only)    docs/CURRENT_SESSION.md — a generated VIEW, NEVER re-injected
                          (no Markdown fallback; a stale/planted file can't re-enter context).
  RUNTIME CONFIG          .claude/settings.json, .codex/hooks.json, .github/hooks/* —
                          read by the HARNESS (permissions/hooks/env), NOT injected as
                          model prompt tokens. Counted as footprint, not prompt cost.
  MEMORY                  the durable hash-chained log (.substrate/memory/**, minus the
                          session restore file) — not loaded into context.
  ON-DEMAND               progressive disclosure — loaded only when invoked: skill
                          bodies, subagent defs, knowledge docs, ADRs, postmortems.
  OTHER-AGENT             always-loaded for non-Claude hosts (Gemini/Copilot pointers).

Plus the KEYSTONE CACHE PREFIX (CLAUDE.md+AGENTS.md) hash — the stable keystone prefix
(NOT a full host-prompt hash); a byte-stable prefix earns the ~10x cached-read discount.

NO network, NO token, NO venv creation, NO writes (bytecode disabled so an import of a
sibling module cannot drop a __pycache__). Token counts are a rough estimate (~bytes/4)
for RELATIVE comparison, not billing.

Usage: context_report.py [--root PATH] [--json]
Exit: 0 always (informational).
"""
from __future__ import annotations
import argparse, hashlib, json, os, sys
# READ-ONLY contract: importing a sibling (_substrate_root) would otherwise write
# scripts/__pycache__/*.pyc. Disable bytecode BEFORE the local import. (v3.6.3)
sys.dont_write_bytecode = True
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    _DEFAULT_ROOT = _sr()
except Exception:
    _DEFAULT_ROOT = Path.cwd()


def _tok(nbytes: int) -> int:
    return round(nbytes / 4)


def _size(p: Path) -> int:
    try:
        return p.stat().st_size if p.is_file() else 0
    except Exception:
        return 0


def _frontmatter_bytes(p: Path) -> int:
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


# The structured SESSION restore source of truth (what session_handoff.py restore reads).
_SESSION_SOT = (".substrate", "memory", "tasks", "current.json")


def build(root: Path) -> dict:
    contributors = []  # (bytes, rel, tier)

    def note(p: Path, tier: str, nbytes=None):
        if not p.is_file():
            return 0
        b = nbytes if nbytes is not None else _size(p)
        contributors.append((b, p.relative_to(root).as_posix(), tier))
        return b

    # --- always-loaded PROMPT context (Claude per-turn) ---
    always = {}
    for rel in ("CLAUDE.md", "AGENTS.md"):
        always[rel] = note(root / rel, "always")
    skill_mds = _glob_files(root, ".claude/skills/*/SKILL.md")
    skill_index = sum(_frontmatter_bytes(p) for p in skill_mds)
    skill_body = sum(_size(p) - _frontmatter_bytes(p) for p in skill_mds)
    for p in skill_mds:  # bodies are on-demand contributors
        note(p, "on-demand", nbytes=_size(p) - _frontmatter_bytes(p))
    ref_files = [p for p in root.glob(".claude/skills/*/**/*") if p.is_file() and p.name != "SKILL.md"]
    for p in ref_files:
        note(p, "on-demand")
    skill_refs = sum(_size(p) for p in ref_files)
    always["skill index (%d skills)" % len(skill_mds)] = skill_index
    always_total = sum(always.values())

    # --- session restore (re-injected) — the STRUCTURED source of truth ---
    sot = root.joinpath(*_SESSION_SOT)
    todo = root / "docs" / ".todo_state.json"
    note(sot, "session"); note(todo, "session")
    session = {
        ".substrate/memory/tasks/current.json": _size(sot),
        "docs/.todo_state.json": _size(todo),
    }
    session_total = sum(session.values())

    # --- derived / human-only (NEVER re-injected) ---
    cur = root / "docs" / "CURRENT_SESSION.md"
    note(cur, "derived")
    derived = {"docs/CURRENT_SESSION.md": _size(cur)}

    # --- runtime config (read by the harness; NOT prompt tokens) ---
    runtime = {}
    for rel in (".claude/settings.json", ".codex/hooks.json"):
        if (root / rel).is_file():
            runtime[rel] = note(root / rel, "runtime")
    hookjson = _glob_files(root, ".github/hooks/*.json")
    if hookjson:
        for p in hookjson:
            note(p, "runtime")
        runtime[".github/hooks (%d)" % len(hookjson)] = sum(_size(p) for p in hookjson)
    runtime_total = sum(runtime.values())

    # --- memory (durable log; NOT loaded into context). Exclude the session SOT,
    #     which is counted under SESSION (it IS re-injected). ---
    mem_files = [p for p in _glob_files(root, ".substrate/memory/**/*") if p.resolve() != sot.resolve()]
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

    # --- keystone cache prefix (the stable instruction keystone, NOT a full prompt hash) ---
    h = hashlib.sha256()
    prefix_bytes = 0
    for rel in ("CLAUDE.md", "AGENTS.md"):
        p = root / rel
        if p.is_file():
            data = p.read_bytes()
            h.update(data)
            prefix_bytes += len(data)
    keystone = h.hexdigest()

    contributors.sort(reverse=True)
    recs = []
    if _tok(always_total) > 3000:
        recs.append(f"Always-loaded prompt context is ~{_tok(always_total)} tok/turn — trim AGENTS.md and "
                    "move detail into docs/knowledge/ (read on demand, not every turn).")
    if always.get("AGENTS.md", 0) > 6000:
        recs.append(f"AGENTS.md is {always['AGENTS.md']}B — keep the keystone lean AND byte-stable so it stays "
                    "at the top of the cached prompt prefix.")
    if session[".substrate/memory/tasks/current.json"] > 8000:
        recs.append("`.substrate/memory/tasks/current.json` is large — SessionStart restores structured state "
                    "from THIS file (re-injected); keep handoffs terse.")
    if memory_total > 2_000_000:
        recs.append(f"Memory log is {memory_total // 1000}KB — consider compaction/anchoring (not loaded into "
                    "context, but grows the repo).")
    recs.append("Keep CLAUDE.md/AGENTS.md byte-stable across runs — a stable keystone prefix earns a ~10x "
                "cached-read discount (break-even ~2nd hit). The keystone hash changes whenever they do.")
    if _tok(always_total) <= 3000 and always.get("AGENTS.md", 0) <= 6000:
        recs.insert(0, "Always-loaded prompt footprint is lean — most context (skill bodies, knowledge, agents) "
                    "is on-demand. Good.")

    return {
        "always_loaded": {"note": "injected into the model prompt every turn",
                          "files": always, "total_bytes": always_total, "est_tokens": _tok(always_total)},
        "session": {"note": "re-injected at SessionStart; current.json is the structured source of truth",
                    "files": session, "total_bytes": session_total, "est_tokens": _tok(session_total)},
        "derived": {"note": "human view only; NEVER restored/re-injected",
                    "files": derived, "total_bytes": sum(derived.values())},
        "runtime_config": {"note": "read by the harness (permissions/hooks/env); NOT prompt token context",
                          "files": runtime, "total_bytes": runtime_total},
        "memory": {"note": "durable hash-chained log; not loaded into context",
                   "total_bytes": memory_total, "files": len(mem_files)},
        "on_demand": {"note": "progressive disclosure — loaded only when invoked",
                      "groups": on_demand, "total_bytes": on_demand_total, "est_tokens": _tok(on_demand_total)},
        "other_agent": {"files": other, "total_bytes": sum(other.values())},
        "keystone_cache_prefix": {"files": ["CLAUDE.md", "AGENTS.md"], "bytes": prefix_bytes, "sha256": keystone,
                                  "note": "keystone prefix only — NOT a full host-prompt hash"},
        "largest_contributors": [{"bytes": b, "path": r, "tier": t} for b, r, t in contributors[:10]],
        "recommendations": recs,
    }


def _print(d: dict) -> None:
    def line(label, nbytes, indent=2):
        print(f"{' ' * indent}{nbytes:>9}  ~{_tok(nbytes):>6} tok  {label}")
    print("CONTEXT REPORT  (rough est ~bytes/4; for relative comparison, not billing)")
    print("=" * 66)
    al = d["always_loaded"]
    print(f"\nALWAYS-LOADED PROMPT CONTEXT (every turn) — {al['total_bytes']}B ~{al['est_tokens']} tok")
    for k, v in al["files"].items():
        line(k, v)
    s = d["session"]
    print(f"\nSESSION RESTORE (re-injected at SessionStart) — {s['total_bytes']}B")
    for k, v in s["files"].items():
        line(k if v else f"{k} (absent)", v)
    dv = d["derived"]
    print("\nDERIVED / human-only (NEVER re-injected)")
    for k, v in dv["files"].items():
        line(k if v else f"{k} (absent)", v)
    rc = d["runtime_config"]
    print(f"\nRUNTIME CONFIG (harness reads; NOT prompt tokens) — {rc['total_bytes']}B")
    for k, v in rc["files"].items():
        line(k, v)
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
    cp = d["keystone_cache_prefix"]
    print(f"\nKEYSTONE CACHE PREFIX (CLAUDE.md+AGENTS.md): {cp['bytes']}B  sha256={cp['sha256'][:16]}…")
    print("  keystone prefix only (NOT a full host-prompt hash); byte-stable → ~10x cached-read discount.")
    print("\nLARGEST CONTRIBUTORS:")
    for c in d["largest_contributors"]:
        print(f"  {c['bytes']:>9}  [{c['tier']}]  {c['path']}")
    print("\nRECOMMENDATIONS:")
    for r in d["recommendations"]:
        print("  - " + r)


# Warn-only token budgets (v3.7.8) — defaults; surfaced by `--budget`, never a gate.
# knowledge_doc (v3.8.30) is PER-DOC, not an aggregate: the kit's own
# 00_substrate.md reached ~17.8k tok — 75% of all on-demand context and the #1
# contributor by 15x — because context-report MEASURED but nothing flagged it.
# The knowledge-doc template prescribes "one doc per coherent subsystem"
# (contract/organization/scope); a doc many times this budget has usually become
# a changelog, which is what docs/HISTORY.md is for. Env-overridable.
_BUDGETS = {"always_loaded_prompt": 2500, "AGENTS.md": 1500,
            "skill_index": 1500, "session_current_json": 2000,
            "knowledge_doc": int(os.environ.get("SUBSTRATE_KNOWLEDGE_DOC_TOKENS") or 3000)}


def _budget(d: dict, root: Path) -> list:
    files = d["always_loaded"]["files"]
    agents = next((v for k, v in files.items() if k == "AGENTS.md"), 0)
    skill = next((v for k, v in files.items() if k.startswith("skill index")), 0)
    cur = d["session"]["files"].get(".substrate/memory/tasks/current.json", 0)
    rows = [("always_loaded_prompt", d["always_loaded"]["est_tokens"]),
            ("AGENTS.md", _tok(agents)), ("skill_index", _tok(skill)),
            ("session_current_json", _tok(cur))]
    out = [{"item": item, "est_tokens": tok, "budget": _BUDGETS[item],
            "status": "warn" if tok > _BUDGETS[item] else "pass"} for item, tok in rows]
    # One row per OVER-budget knowledge doc, named, so the warning is actionable
    # rather than an aggregate nobody can act on. Enumerate the source directory
    # directly: largest_contributors is intentionally a top-ten display and must
    # never become an accidental completeness boundary for budget enforcement.
    kb = _BUDGETS["knowledge_doc"]
    knowledge = root / "docs" / "knowledge"
    docs = []
    if knowledge.is_dir():
        for path in knowledge.glob("*.md"):
            if path.is_file() and not path.name.startswith("_"):
                rel = path.relative_to(root).as_posix()
                docs.append((_tok(_size(path)), rel))
    for tok, rel in sorted(docs, key=lambda row: (-row[0], row[1])):
        if tok > kb:
            out.append({"item": f"knowledge_doc:{rel}", "est_tokens": tok,
                        "budget": kb, "status": "warn"})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(_DEFAULT_ROOT))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--budget", action="store_true", help="evaluate warn-only token budgets")
    a = ap.parse_args()
    root = Path(a.root).resolve()
    d = build(root)
    if a.budget:
        d["budget"] = _budget(d, root)
    if a.json:
        print(json.dumps(d, indent=2))
    else:
        _print(d)
        if a.budget:
            print("\nTOKEN BUDGETS (warn-only; defaults):")
            for r in d["budget"]:
                tag = "WARN " if r["status"] == "warn" else "pass "
                print(f"  {tag} {r['item']:22} {r['est_tokens']:>6} tok  (budget {r['budget']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
