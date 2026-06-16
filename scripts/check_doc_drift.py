#!/usr/bin/env python3
"""Docs/code drift detector with staged-edit awareness."""
from __future__ import annotations
import argparse, json, subprocess, sys
from datetime import date
from pathlib import Path
# Explicit local import path so this works under `python -I` (isolated mode
# does NOT auto-prepend the script dir). Stdlib imports above resolve first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import CODE_SUFFIXES, DEFAULT_EXCLUDES, git_file_last_modified, iter_code_modules, parse_front_matter, repo_root
KNOWLEDGE_DIR='docs/knowledge'; MANIFEST_PATH='docs/manifest.json'
def _git(args, cwd):
    try: return subprocess.run(['git',*args], cwd=str(cwd), check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception: return ''
def _excluded(rel):
    parts=rel.split('/'); bare={d for d in DEFAULT_EXCLUDES if '/' not in d}; paths=[d.strip('/') for d in DEFAULT_EXCLUDES if '/' in d]
    return any(p in bare for p in parts) or any(rel==x or rel.startswith(x+'/') for x in paths)
def _staged(root): return {x.strip() for x in _git(['diff','--cached','--name-only','--diff-filter=ACMRT'], root).splitlines() if x.strip()}
def _staged_code(root): return {p for p in _staged(root) if Path(p).suffix in CODE_SUFFIXES and not _excluded(p) and (root/p).exists()}
def _load_docs(root):
    out=[]; d=root/KNOWLEDGE_DIR
    if not d.is_dir(): return out
    for md in sorted(d.glob('*.md')):
        if md.name.startswith('_'): continue
        fm,_=parse_front_matter(md)
        out.append({'path':md.relative_to(root).as_posix(),'covers':list(fm.get('covers',[])),'last_human_reviewed':fm.get('last_human_reviewed','')})
    return out
def _manifest_paths(root):
    p=root/MANIFEST_PATH
    if not p.exists(): return None
    try: data=json.loads(p.read_text(encoding='utf-8'))
    except Exception: return None
    return {e['path'] for e in data.get('knowledge_docs',[])}
def _date(s):
    try: return date.fromisoformat(str(s))
    except Exception: return None
def _doc_stale(doc, cov, root):
    """A covered file makes the doc stale ONLY if it was committed AFTER the doc's
    last_human_reviewed date AND after the doc's OWN last commit. Committing the
    doc together with (or after) the code IS the review — so an all-in-one commit
    (and the kit's own source, where docs ride with code) is never falsely stale.
    Without this, a frozen review date drifted stale on EVERY later whole-tree
    commit / fresh clone (CI failed on the published repo). User-repo protection
    is preserved: a script changed in a LATER commit than its doc still flags."""
    rv = _date(doc.get('last_human_reviewed', ''))
    if rv is None:
        return None
    fd = git_file_last_modified(Path(cov), cwd=root)
    if not fd or fd <= rv:
        return None
    dd = git_file_last_modified(Path(doc['path']), cwd=root)
    if dd is not None and fd <= dd:
        return None  # doc committed with/after the code -> reviewed in that change
    return (doc['path'], cov, fd.isoformat(), rv.isoformat())
def detect(root:Path):
    docs=_load_docs(root); cov_to_docs={}
    for doc in docs:
        for cov in doc['covers']: cov_to_docs.setdefault(cov,[]).append(doc)
    covered=set(cov_to_docs); code={p.as_posix() for p in iter_code_modules(root)}
    staged=_staged(root); staged_docs={p for p in staged if p.startswith(KNOWLEDGE_DIR+'/') and p.endswith('.md')}; today=date.today()
    pending=[]
    for code_path in sorted(_staged_code(root)):
        for doc in cov_to_docs.get(code_path,[]):
            if doc['path'] not in staged_docs and _date(doc.get('last_human_reviewed','')) != today:
                pending.append((doc['path'], code_path, str(doc.get('last_human_reviewed',''))))
    manifest=_manifest_paths(root); on_disk={d['path'] for d in docs}
    return {
      'coverage_gap':sorted(code-covered),
      'staged_coverage_gap':sorted(p for p in _staged_code(root) if p not in cov_to_docs),
      'pending_stale_doc':pending,
      'phantom_doc':[(d['path'],c) for d in docs for c in d['covers'] if not (root/c).exists()],
      'stale_doc':[r for d in docs for c in d['covers'] if (r:=_doc_stale(d,c,root)) is not None],
      'orphan_doc':sorted(on_disk-(manifest or set())),
      'missing_manifest':manifest is None,
    }
def report(d,file=sys.stdout):
    found=False
    def section(name, items, fix):
        nonlocal found
        if items:
            found=True; print(f'\n{name}:', file=file)
            for item in items: print('  - '+(' -> '.join(map(str,item)) if isinstance(item,tuple) else str(item)), file=file)
            print('  Fix: '+fix, file=file)
    if d['missing_manifest']:
        found=True; print('MISSING_MANIFEST: run `python scripts/update_manifest.py --fix`.', file=file)
    section('COVERAGE GAP — source modules with no knowledge-doc coverage', d['coverage_gap'], 'add covers: entries and bump last_human_reviewed.')
    section('STAGED COVERAGE GAP — staged source files lack coverage', d['staged_coverage_gap'], 'cover staged files, run update_manifest --fix, and stage docs/manifest.')
    section('PENDING STALE DOC — staged source changed but covering doc was not reviewed/staged', d['pending_stale_doc'], 'review code+doc, bump last_human_reviewed to today, and stage the doc.')
    section('PHANTOM DOC — covers entries point at missing files', d['phantom_doc'], 'remove missing path or fix typo.')
    section('STALE DOC — committed file newer than review date', d['stale_doc'], 'review and bump last_human_reviewed.')
    section('ORPHAN DOC — docs not registered in manifest', d['orphan_doc'], 'run update_manifest --fix.')
    if not found: print('doc-drift: no drift detected.', file=file)
    return found
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--strict', action='store_true', default=True); ap.add_argument('--report-only', action='store_true'); ap.add_argument('--json', action='store_true')
    a=ap.parse_args(); d=detect(repo_root())
    if a.json: print(json.dumps(d, indent=2, sort_keys=True)); return 0
    found=report(d); return 0 if a.report_only or not found else 1
if __name__=='__main__': sys.exit(main())
