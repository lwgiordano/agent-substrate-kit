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
import json
import os, stat, re, sys
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
def _guarded_json_bytes(p):
    """Read a governed JSON data file WITHOUT following a link or blocking.

    v3.8.47 (round-30 P2): this ran a raw read_text() at MODULE IMPORT, so a
    FIFO harness_patterns.json HUNG the scanner instead of failing it — the
    fifth time a component of this system carried the class it polices. Kept
    inline and dependency-free because this module is AST-pinned and must not
    grow an import.
    """
    fd = os.open(str(p), os.O_RDONLY
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink > 1:
            raise OSError(f"pattern source is not a private regular file: {p}")
        chunks = []
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            chunks.append(b)
    finally:
        os.close(fd)
    return b"".join(chunks)


# Surfaces where inline-code spans are quoted EVIDENCE rather than
# instructions. Deliberately a one-element set: the coordination bus.
EVIDENCE_QUOTING_SURFACES = {'AGENT_BUS.md'}


def _load_patterns():
    p=Path(__file__).resolve().parent/'harness_patterns.json'
    data=json.loads(_guarded_json_bytes(p).decode('utf-8'))
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
    # v3.8.46 (round-29 P3): a HARD LINK is a regular file — is_symlink() is
    # False and is_file() is True — so a governed prompt surface hard-linked to
    # an outside file scanned as ordinary and returned ok, leaving AGENTS.md
    # writable through an alias the scan never sees. This is the oldest reader
    # in the kit and it predates refuse_linked_leaf; every newer reader refuses
    # st_nlink > 1 and this one still did not. Grouped with the non-regular
    # surfaces so main() BLOCKs rather than silently trusting it.
    out=set(); links=set(); bad=set()
    for pat in pats:
        cands = ROOT.glob(pat) if '*' in pat else ([ROOT/pat] if (ROOT/pat).is_symlink() or (ROOT/pat).exists() else [])
        for p in cands:
            if p.is_symlink(): links.add(p)
            elif p.is_file():
                try:
                    linked = p.lstat().st_nlink > 1
                except OSError:
                    linked = True     # cannot prove it is private: fail closed
                (bad if linked else out).add(p)
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
        findings.append(("governed surface is not a private regular file "
                         "(fifo/socket/device, or a hard link sharing an outside inode) "
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
        # v3.8.47 (round-30 P3): the bus is an agent-read surface AND the audit
        # channel. Scanning it verbatim BLOCKS on an auditor accurately quoting
        # the string they tested — verified: adding it to CONTEXT_GLOBS failed
        # immediately on the round-30 finding that reported this very gap, whose
        # repro names the phrase in backticks. A gate that punishes accurate
        # reporting is worse than the hole. Inline-code spans are EVIDENCE, so
        # they are blanked (length-preserving, to keep line numbers honest)
        # before matching — on this surface only. An UNQUOTED injection line on
        # the bus still blocks, and no other governed surface gets the carve-out.
        # v3.8.47 in-release (auditor BLOCK): the first cut blanked the text
        # ONCE, before all three pattern classes ran, so the carve-out also
        # exempted quoted credentials and quoted shell-danger commands. The
        # justification only ever applied to the INJECTION class — an auditor
        # quoting the phrase they tested. A live credential or a pipe-to-shell
        # command in backticks is not evidence of anything and must still
        # block, so the blanked copy feeds the injection class ALONE.
        evidence_text=text
        if rel in EVIDENCE_QUOTING_SURFACES:
            evidence_text=re.sub(r'`[^`\n]*`', lambda m: ' '*len(m.group(0)), text)
        if rel in HARNESS_ALLOWLIST:
            pats=list(SECRET)  # the pattern DATA file: secrets only
        else:
            pats=list(SECRET)+list(SHELL_DANGER)
            if p in context: pats+=list(INJECTION)
        _inj_ids={id(rx) for _l,rx in INJECTION}
        for label,rx in pats:
            src=evidence_text if id(rx) in _inj_ids else text
            for m in rx.finditer(src): findings.append((label,rel,src.count('\n',0,m.start())+1))
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
    # v3.8.43 (round-26 P3): a poisoned _substrate_root can still aim a STANDALONE
    # run at a clean nonempty outside tree, and the empty-scan BLOCK above only
    # catches the zero-surface case. There is no false-positive-free way to
    # self-detect this here — running the scanner from OUTSIDE the tree it scans
    # is a legitimate, tested pattern, so "my file must live under ROOT" would
    # fail valid runs. What is honest is to stop reporting an unqualified "ok":
    # print the ROOT that was actually scanned, so a redirected scan is visible
    # in the output rather than indistinguishable from a real pass. The full
    # `manage.sh check` remains the authority — check_harness_smoke re-runs this
    # scanner against known-bad payloads and catches a redirected root.
    print(f'agent-harness: ok ({len(context|code)} files scanned under {ROOT})'); return 0
if __name__=='__main__': sys.exit(main())
