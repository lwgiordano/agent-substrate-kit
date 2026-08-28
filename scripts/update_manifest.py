#!/usr/bin/env python3
"""Generate or check docs/manifest.json from knowledge docs and ADRs."""
from __future__ import annotations
import argparse, json, re, sys
from pathlib import Path
# Explicit local import path so this works under `python -I` (isolated mode
# does NOT auto-prepend the script dir). Stdlib imports above resolve first.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.

try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None

try:
    from _doc_common import safe_atomic_write as _safe_atomic_write
except Exception:  # pragma: no cover - stripped install
    def _safe_atomic_write(*a, **k):
        raise OSError("safe_atomic_write unavailable — refusing an unguarded write")
from _doc_common import parse_front_matter, repo_root
TITLE_RE=re.compile(r'^#\s+(.+?)\s*$', re.M); STATUS_RE=re.compile(r'^\*\*Status:\*\*\s+(.+?)\s*$', re.M)
def knowledge(root):
    out=[]; d=root/'docs'/'knowledge'
    if not d.is_dir(): return out
    for md in sorted(d.glob('*.md')):
        if md.name.startswith('_'): continue
        fm,_=parse_front_matter(md); out.append({'path':md.relative_to(root).as_posix(),'covers':list(fm.get('covers',[])),'last_human_reviewed':fm.get('last_human_reviewed',''),'purpose':fm.get('purpose','')})
    return out
def decisions(root):
    out=[]; d=root/'docs'/'decisions'
    if not d.is_dir(): return out
    for md in sorted(d.glob('*.md')):
        if md.name=='0000-template.md' or md.name.startswith('_'): continue
        text=md.read_text(encoding='utf-8'); out.append({'path':md.relative_to(root).as_posix(),'status':(STATUS_RE.search(text).group(1).strip() if STATUS_RE.search(text) else 'Unknown'),'title':(TITLE_RE.search(text).group(1).strip() if TITLE_RE.search(text) else md.stem)})
    return out
def render(payload): return json.dumps(payload, indent=2, sort_keys=True)+'\n'
def write_atomic(path,text,root):
    # v3.8.44 (round-27, surfaced by the gate's new interprocedural pass): this
    # was the round-26 parent-swap defect verbatim — path-based mkdir/mkstemp/
    # replace on a governed destination — hidden from the gate only because the
    # governed path arrived as a PARAMETER. docs/manifest.json is a trust anchor
    # (the doc/code coverage map), so it goes through the shared writer.
    # `root` is REQUIRED, not defaulted: an `or _repo_root()` fallback is a guard
    # pointed at a root that need not contain `path`, which the wrong-root
    # invariant test rightly rejects (four such regressions escaped in v3.8.43).
    _safe_atomic_write(path, text, root=root, tmp_prefix='.manifest.',
                       make_parents=True)
def main():
    ap=argparse.ArgumentParser(); g=ap.add_mutually_exclusive_group(); g.add_argument('--check', action='store_true'); g.add_argument('--fix', action='store_true'); a=ap.parse_args()
    root=repo_root(); target=root/'docs'/'manifest.json'; payload={'knowledge_docs':knowledge(root),'decisions':decisions(root)}; expected=render(payload)
    if a.check:
        if not target.exists() or (_safe_read_text(target, root, max_bytes=16 << 20) or '')!=expected:
            print('update_manifest: docs/manifest.json is stale or missing; run `python scripts/update_manifest.py --fix`.'); return 1
        print(f"update_manifest: manifest is current ({len(payload['knowledge_docs'])} knowledge, {len(payload['decisions'])} decisions)"); return 0
    write_atomic(target, expected, root); print(f"update_manifest: wrote {target.relative_to(root)} ({len(payload['knowledge_docs'])} knowledge, {len(payload['decisions'])} decisions)"); return 0
if __name__=='__main__': sys.exit(main())
