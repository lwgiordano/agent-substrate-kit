#!/usr/bin/env python3
"""Safety check for agent instructions, skills, hooks, configs, and the
agent-facing docs/auditor-reference material the substrate governs.

Surfaces come from the CANONICAL inventory in `_substrate_surfaces.py`
(shared with strict CODEOWNERS coverage and the agent-config-audit
workflow trigger), so the three can't drift apart.

The danger/secret/injection PATTERNS live in `harness_patterns.json`
(data), so this .py contains no pattern source and is scanned normally
— there is no bypassable line-allowlist. The JSON is scanned
secrets-only (weakening it is governed by CODEOWNERS + tests).

Two scan classes:
  CONTEXT  (markdown/docs/instructions/auditor-reference read AS context):
            SECRET + SHELL_DANGER + INJECTION
  CODE     (shell/python/CI/skill-resource/config that EXECUTE):
            SECRET + SHELL_DANGER  (no injection-phrase scan)
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from _substrate_root import substrate_root as _sr
    ROOT = _sr()
except Exception:
    ROOT = Path.cwd()
from _substrate_surfaces import (CONTEXT_GLOBS, CODE_GLOBS, HARNESS_SKIP_GLOBS, HARNESS_ALLOWLIST,
                                 OWNED_DIRS, OPTIONAL_DIRS, GOVERNED_DIRS, GOVERNED_OPTIONAL_DIRS,
                                 _SKILL_ROOTS)
def _load_patterns():
    p=Path(__file__).resolve().parent/'harness_patterns.json'
    data=json.loads(p.read_text(encoding='utf-8'))
    def comp(key): return [(label,re.compile(rx)) for label,rx in data.get(key,[])]
    return comp('secret'), comp('shell_danger'), comp('injection')
SECRET, SHELL_DANGER, INJECTION = _load_patterns()
def _glob(pats):
    # v3.8.38 (round-21 P2): discover surfaces WITHOUT following symlinks. A
    # symlinked surface either redirects the scan to outside bytes (a symlinked
    # package_release.sh scanned a clean outside script) or — when broken —
    # silently drops out of the inventory (is_file() is False), shrinking the
    # count. Real regular files go to `out`; any symlink match (broken or not)
    # goes to `links` so main() can BLOCK it rather than scan/skip it.
    # v3.8.42 (round-25 P2): a NON-REGULAR governed surface (FIFO/socket/device)
    # is neither a symlink nor is_file(), so it silently DROPPED out of the
    # inventory — the scan returned ok with a quietly lower count, which is the
    # same false-green a broken symlink used to produce. Non-regular existing
    # surfaces go to `bad` so main() BLOCKs them instead of skipping them.
    out=set(); links=set(); bad=set()
    for pat in pats:
        cands = ROOT.glob(pat) if '*' in pat else ([ROOT/pat] if (ROOT/pat).is_symlink() or (ROOT/pat).exists() else [])
        for p in cands:
            if p.is_symlink(): links.add(p)
            elif p.is_file(): out.add(p)
            elif p.exists(): bad.add(p)
    return out, links, bad
def main():
    skip,_,_=_glob(HARNESS_SKIP_GLOBS)
    context,ctx_links,ctx_bad=_glob(CONTEXT_GLOBS); context-=skip
    code,code_links,code_bad=_glob(CODE_GLOBS); code-=skip
    findings=[]
    for p in sorted((ctx_links|code_links)):
        if p in skip: continue
        rel=p.relative_to(ROOT).as_posix()
        findings.append(("governed surface is a symlink (redirects/hides the scan)", rel, 0))
    for p in sorted((ctx_bad|code_bad)):
        if p in skip: continue
        rel=p.relative_to(ROOT).as_posix()
        findings.append(("governed surface is not a regular file (fifo/socket/device) "
                         "— refusing to skip it", rel, 0))
    # v3.8.39/40 (round-22/23): a symlinked governed DIRECTORY — or ANY ancestor
    # of one — redirects or shrinks the glob under it while the per-file scan
    # stays green. v3.8.39 checked only the exact listed path; `docs ->
    # /outside` (an ancestor of governed `docs/knowledge`) slipped through. Walk
    # every path component of each governed dir and flag the first that is a
    # symlink. Skill roots are governed dirs, so they are covered by the lists.
    # v3.8.41 (round-24 P2): _SKILL_ROOTS (.claude/skills, .agents/skills,
    # .github/skills) are GLOB ROOTS in _substrate_surfaces (CODE_GLOBS builds
    # `<root>/**/*.<ext>` from them) but are NOT all in the dir lists above —
    # only .github/skills is (OPTIONAL_DIRS). A direct symlink AT a skill root
    # (`.agents/skills -> /outside`) is neither scanned (glob does not follow it)
    # nor flagged (its parent `.agents` is the only listed component). Walk the
    # skill roots too so a linked skill root BLOCKs instead of silently shrinking
    # the scan. list(_SKILL_ROOTS) is deduped against the dir lists by _seen_link.
    _seen_link = set()
    for d in OWNED_DIRS + OPTIONAL_DIRS + GOVERNED_DIRS + GOVERNED_OPTIONAL_DIRS + list(_SKILL_ROOTS):
        parts = d.split("/")
        for i in range(1, len(parts) + 1):
            comp = "/".join(parts[:i])
            cp = ROOT / comp
            if comp not in _seen_link and cp.is_symlink():
                _seen_link.add(comp)
                findings.append(("governed directory (or an ancestor) is a symlink "
                                 "(redirects/shrinks the scan)", comp, 0))
                break  # deeper components are under the link; one finding per chain
    for p in sorted(context|code):
        text=p.read_text(encoding='utf-8', errors='replace'); rel=p.relative_to(ROOT).as_posix()
        if rel in HARNESS_ALLOWLIST:
            pats=list(SECRET)  # the pattern DATA file: secrets only
        else:
            pats=list(SECRET)+list(SHELL_DANGER)
            if p in context: pats+=list(INJECTION)
        for label,rx in pats:
            for m in rx.finditer(text): findings.append((label,rel,text.count('\n',0,m.start())+1))
    # v3.8.42 (round-25 P3): this script imports _substrate_root — which it
    # cannot itself verify — BEFORE discovering surfaces, so a poisoned helper
    # returning an empty directory made a standalone run print "ok (0 files
    # scanned)". Pinning the helper would only move the trust; the honest,
    # self-contained tell is the RESULT: a real install always has governed
    # surfaces, so finding NONE means the scan root is wrong or the inventory
    # was redirected — never a clean bill of health. (Asserting that this file
    # lives under ROOT was rejected: running the scanner from outside the tree
    # it scans is a legitimate, tested pattern.)
    if not (context | code):
        findings.append(("no governed surfaces found — scan root is wrong or the "
                         "inventory was redirected (refusing to report ok)", '.', 0))
    if findings:
        print('agent-harness: BLOCK findings')
        for label,rel,line in findings: print(f'  - BLOCK: {label}: {rel}:{line}')
        return 1
    print(f'agent-harness: ok ({len(context|code)} files scanned)'); return 0
if __name__=='__main__': sys.exit(main())
