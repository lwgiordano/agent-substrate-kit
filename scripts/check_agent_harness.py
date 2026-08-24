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
from _substrate_surfaces import CONTEXT_GLOBS, CODE_GLOBS, HARNESS_SKIP_GLOBS, HARNESS_ALLOWLIST
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
    out=set(); links=set()
    for pat in pats:
        cands = ROOT.glob(pat) if '*' in pat else ([ROOT/pat] if (ROOT/pat).is_symlink() or (ROOT/pat).exists() else [])
        for p in cands:
            if p.is_symlink(): links.add(p)
            elif p.is_file(): out.add(p)
    return out, links
def main():
    skip,_=_glob(HARNESS_SKIP_GLOBS)
    context,ctx_links=_glob(CONTEXT_GLOBS); context-=skip
    code,code_links=_glob(CODE_GLOBS); code-=skip
    findings=[]
    for p in sorted((ctx_links|code_links)):
        if p in skip: continue
        rel=p.relative_to(ROOT).as_posix()
        findings.append(("governed surface is a symlink (redirects/hides the scan)", rel, 0))
    for p in sorted(context|code):
        text=p.read_text(encoding='utf-8', errors='replace'); rel=p.relative_to(ROOT).as_posix()
        if rel in HARNESS_ALLOWLIST:
            pats=list(SECRET)  # the pattern DATA file: secrets only
        else:
            pats=list(SECRET)+list(SHELL_DANGER)
            if p in context: pats+=list(INJECTION)
        for label,rx in pats:
            for m in rx.finditer(text): findings.append((label,rel,text.count('\n',0,m.start())+1))
    if findings:
        print('agent-harness: BLOCK findings')
        for label,rel,line in findings: print(f'  - BLOCK: {label}: {rel}:{line}')
        return 1
    print(f'agent-harness: ok ({len(context|code)} files scanned)'); return 0
if __name__=='__main__': sys.exit(main())
