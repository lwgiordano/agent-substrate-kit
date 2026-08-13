#!/usr/bin/env python3
"""Docs/code drift detector with staged-edit awareness."""
from __future__ import annotations
import argparse, json, os, subprocess, sys
from datetime import date
from pathlib import Path
# Explicit local import path so this works under `python -I` (isolated mode
# does NOT auto-prepend the script dir). Stdlib imports above resolve first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import CODE_SUFFIXES, DEFAULT_EXCLUDES, git_file_last_modified, iter_code_modules, parse_front_matter, repo_root
KNOWLEDGE_DIR='docs/knowledge'; MANIFEST_PATH='docs/manifest.json'
def _git(args, cwd):
    try:
        return subprocess.run(
            ['git', *args], cwd=str(cwd), check=True, capture_output=True,
            text=False, timeout=30,
        ).stdout
    except Exception as exc:
        raise RuntimeError(f"cannot read staged git state: {type(exc).__name__}") from exc
def _excluded(rel):
    parts=rel.split('/'); bare={d for d in DEFAULT_EXCLUDES if '/' not in d}; paths=[d.strip('/') for d in DEFAULT_EXCLUDES if '/' in d]
    return any(p in bare for p in parts) or any(rel==x or rel.startswith(x+'/') for x in paths)
def _staged(root):
    """Return every staged path, retaining both sides of renames/copies.

    NUL framing preserves unusual pathnames. Deletions and rename sources matter
    because a knowledge doc may cover the old path even when it no longer exists.
    """
    raw = _git([
        'diff', '--cached', '--name-status', '-z', '--diff-filter=ACMRTD',
        '--find-renames', '--find-copies',
    ], root)
    fields = raw.split(b'\0')
    out = set()
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        i += 1
        count = 2 if status[:1] in {b'R', b'C'} else 1
        for _ in range(count):
            if i >= len(fields) or not fields[i]:
                return out
            out.add(os.fsdecode(fields[i]))
            i += 1
    return out


def _staged_code(root, staged=None):
    staged = _staged(root) if staged is None else staged
    return {p for p in staged if Path(p).suffix in CODE_SUFFIXES and not _excluded(p) and (root/p).exists()}
def _load_docs(root):
    out=[]; d=root/KNOWLEDGE_DIR
    if not d.is_dir(): return out
    for md in sorted(d.glob('*.md')):
        if md.name.startswith('_'): continue
        fm,_=parse_front_matter(md)
        out.append({'path':md.relative_to(root).as_posix(),'covers':list(fm.get('covers',[])),'last_human_reviewed':fm.get('last_human_reviewed',''),'asserts':_assert_specs(fm)})
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
_ASSERT_MAX_PER_DOC = 50      # bound the work a single doc can demand of the gate
_ASSERT_MAX_NEEDLE = 300      # a "claim" is a symbol/phrase, not a file
_ASSERT_MAX_READ = 4_000_000  # never read an unbounded file into memory


def _assert_specs(fm) -> list:
    """Normalize the optional `asserts:` front-matter key to a list of strings.

    A bare scalar (`asserts: a::b`) is accepted as one entry — `list()` on a str
    would otherwise iterate CHARACTERS and produce nonsense failures."""
    raw = fm.get('asserts')
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = [raw]
    try:
        items = [str(x).strip() for x in raw]
    except TypeError:
        return []
    return [i for i in items if i][:_ASSERT_MAX_PER_DOC]


def _assert_failures(doc, root:Path) -> list:
    """Check each `path::substring` claim the doc makes about the code.

    DECLARATIVE ONLY — nothing here executes doc content. Running commands
    declared in an agent-writable markdown file would make repo prose
    executable, which this threat model refuses (see docs/REJECTED.md).

    A MALFORMED entry is REPORTED, never silently skipped: an assertion that
    quietly does not run is false assurance, which is worse than no assertion
    (the v3.8.25 lesson — a silent guard turns a missing case into a wrong
    ANSWER rather than an error)."""
    out=[]
    for spec in _assert_specs(doc):
        path, sep, needle = spec.partition('::')
        path=path.strip(); needle=needle.strip()
        if not sep or not path or not needle:
            out.append((doc['path'], spec, 'malformed — expected path::substring')); continue
        if len(needle) > _ASSERT_MAX_NEEDLE:
            out.append((doc['path'], path, f'substring longer than {_ASSERT_MAX_NEEDLE} chars')); continue
        target=root/path
        if not target.is_file():
            out.append((doc['path'], path, 'asserted file does not exist')); continue
        try:
            text=target.read_text(encoding='utf-8', errors='replace')[:_ASSERT_MAX_READ]
        except OSError as e:
            out.append((doc['path'], path, f'unreadable: {e}')); continue
        if needle not in text:
            out.append((doc['path'], path, f'no longer contains "{needle[:80]}"'))
    return out


_DOC_TOKEN_BUDGET = int(os.environ.get('SUBSTRATE_KNOWLEDGE_DOC_TOKENS') or 3000)


def _oversize_docs(docs, root:Path) -> list:
    """Knowledge docs over the per-doc token budget (~bytes/4, the same estimate
    context_report uses). ADVISORY: reported by report() but deliberately EXCLUDED
    from its failure boolean — see the comment there."""
    out=[]
    for d in docs:
        p=root/d['path']
        try: nbytes=p.stat().st_size
        except OSError: continue
        tok=round(nbytes/4)
        if tok > _DOC_TOKEN_BUDGET:
            out.append((d['path'], f'~{tok} tok', f'budget {_DOC_TOKEN_BUDGET}'))
    return out


def detect(root:Path):
    docs=_load_docs(root); cov_to_docs={}
    for doc in docs:
        for cov in doc['covers']: cov_to_docs.setdefault(cov,[]).append(doc)
    covered=set(cov_to_docs); code={p.as_posix() for p in iter_code_modules(root)}
    staged_error = None
    try:
        staged = _staged(root)
    except RuntimeError as exc:
        staged = set()
        staged_error = str(exc)
    staged_docs={p for p in staged if p.startswith(KNOWLEDGE_DIR+'/') and p.endswith('.md')}
    pending=[]
    for code_path in sorted(staged & covered):
        for doc in cov_to_docs.get(code_path,[]):
            if doc['path'] not in staged_docs:
                pending.append((doc['path'], code_path, str(doc.get('last_human_reviewed',''))))
    manifest=_manifest_paths(root); on_disk={d['path'] for d in docs}
    return {
      'coverage_gap':sorted(code-covered),
      'staged_coverage_gap':sorted(p for p in _staged_code(root, staged) if p not in cov_to_docs),
      'pending_stale_doc':pending,
      'phantom_doc':[(d['path'],c) for d in docs for c in d['covers'] if not (root/c).exists()],
      'stale_doc':[r for d in docs for c in d['covers'] if (r:=_doc_stale(d,c,root)) is not None],
      'orphan_doc':sorted(on_disk-(manifest or set())),
      'assert_failed':[f for d in docs for f in _assert_failures(d, root)],
      'oversize_doc':_oversize_docs(docs, root),
      'missing_manifest':manifest is None,
      'staged_read_error':staged_error,
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
    if d.get('staged_read_error'):
        found=True; print(f"STAGED READ ERROR: {d['staged_read_error']}", file=file)
    section('COVERAGE GAP — source modules with no knowledge-doc coverage', d['coverage_gap'], 'add covers: entries and bump last_human_reviewed.')
    section('STAGED COVERAGE GAP — staged source files lack coverage', d['staged_coverage_gap'], 'cover staged files, run update_manifest --fix, and stage docs/manifest.')
    section('PENDING STALE DOC — staged source changed but covering doc was not reviewed/staged', d['pending_stale_doc'], 'review code+doc, bump last_human_reviewed to today, and stage the doc.')
    section('PHANTOM DOC — covers entries point at missing files', d['phantom_doc'], 'remove missing path or fix typo.')
    section('STALE DOC — committed file newer than review date', d['stale_doc'], 'review and bump last_human_reviewed.')
    section('ORPHAN DOC — docs not registered in manifest', d['orphan_doc'], 'run update_manifest --fix.')
    section('BROKEN CLAIM — doc asserts something the code no longer contains', d.get('assert_failed') or [], 'update the doc to match the code (or fix the asserts: entry), then bump last_human_reviewed.')
    # ADVISORY, NOT A GATE (v3.8.30). Every category above is OR'd into `found`,
    # which becomes the process exit code. Size is deliberately NOT: a doc growing
    # past its budget is a shape problem to fix deliberately, not a reason to block
    # a commit, and the kit's own 00_substrate.md is already ~6x over. This follows
    # the precedent the completion gate set (shipped warning-only; blocking deferred
    # until after dogfooding). Opt in to hard enforcement with
    # SUBSTRATE_ENFORCE_DOC_BUDGET=1. The numeric view is `context-report --budget`.
    over = d.get('oversize_doc') or []
    if over:
        print('\nOVERSIZE DOC (advisory — does not fail the gate):', file=file)
        for item in over: print('  - '+' -> '.join(map(str,item)), file=file)
        print('  Fix: knowledge docs describe ONE subsystem (contract/organization/scope); '
              'per-release narrative belongs in docs/HISTORY.md. Split or trim.', file=file)
        if os.environ.get('SUBSTRATE_ENFORCE_DOC_BUDGET') == '1':
            found=True
    if not found: print('doc-drift: no drift detected.', file=file)
    return found
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--strict', action='store_true', default=True); ap.add_argument('--report-only', action='store_true'); ap.add_argument('--json', action='store_true')
    a=ap.parse_args(); d=detect(repo_root())
    if a.json: print(json.dumps(d, indent=2, sort_keys=True)); return 0
    found=report(d); return 0 if a.report_only or not found else 1
if __name__=='__main__': sys.exit(main())
