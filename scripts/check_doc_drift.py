#!/usr/bin/env python3
"""Docs/code drift detector with staged-edit awareness."""
from __future__ import annotations
import argparse, hashlib, json, os, stat, subprocess, sys
from datetime import date
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
    from _doc_common import safe_read_bytes as _safe_read_bytes
except Exception:  # pragma: no cover - stripped install
    def _safe_read_bytes(path, root=None, max_bytes=None, tail_bytes=None):
        return None
from _doc_common import CODE_SUFFIXES, DEFAULT_EXCLUDES, git_file_last_modified, iter_code_modules, knowledge_prose, knowledge_prose_bytes, parse_front_matter, repo_root
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
    try: data=json.loads(_safe_read_text(p, root, max_bytes=8 << 20) or 'null')
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
            text=(_safe_read_text(target, root, max_bytes=64 << 20) or '')[:_ASSERT_MAX_READ]
        except OSError as e:
            out.append((doc['path'], path, f'unreadable: {e}')); continue
        if needle not in text:
            out.append((doc['path'], path, f'no longer contains "{needle[:80]}"'))
    return out


_DOC_TOKEN_BUDGET = int(os.environ.get('SUBSTRATE_KNOWLEDGE_DOC_TOKENS') or 3000)


def _heaviest_section(prose:str):
    """(title, bytes) of the largest `## ` section of a doc's prose, or None when
    it has no such heading. Text before the first heading is its own part, and a
    `## ` line inside a code fence is not a heading."""
    parts={}; title='(before the first ## heading)'; fence=False
    for ln in prose.splitlines(keepends=True):
        if ln.lstrip().startswith(('```', '~~~')): fence=not fence
        elif not fence and ln.startswith('## '): title=ln[3:].strip()
        parts[title]=parts.get(title,0)+len(ln.encode('utf-8','replace'))
    if len(parts) < 2: return None
    return max(parts.items(), key=lambda kv: kv[1])


def _oversize_docs(docs, root:Path) -> list:
    """Knowledge docs whose PROSE is over the per-doc token budget (~bytes/4 of
    the text after the front matter: `knowledge_prose_bytes`, the measure
    context_report uses too). `covers:` and `asserts:` are read by this gate and
    are not priced, so adding a guard line never costs a doc its prose. ADVISORY:
    reported by report() but deliberately EXCLUDED from its failure boolean — see
    the comment there. Each row names the heaviest section, which is where a
    split or a trim pays most."""
    out=[]
    for d in docs:
        p=root/d['path']
        nbytes=knowledge_prose_bytes(p, root)
        if nbytes is None:
            try: nbytes=p.stat().st_size
            except OSError: continue
        tok=round(nbytes/4)
        if tok > _DOC_TOKEN_BUDGET:
            row=[d['path'], f'~{tok} tok', f'budget {_DOC_TOKEN_BUDGET}']
            top=_heaviest_section(knowledge_prose(_safe_read_text(p, root, max_bytes=8 << 20) or ''))
            if top: row.append(f'heaviest section "{top[0][:60]}" ~{round(top[1]/4)} tok')
            out.append(tuple(row))
    return out


INSTALL_RECORD='.substrate/install.json'


def _plain_rel(rel:str) -> bool:
    """A covers entry that can be handed to git as a path inside this repo."""
    return bool(rel) and '\0' not in rel and not rel.startswith('/') and '..' not in rel.split('/')


_STATUS_BATCH = 200


def _status_paths(root:Path, paths) -> set:
    """Paths among `paths` that git reports as modified, staged or untracked.
    NUL framing; a rename or copy contributes both of its names.

    `--no-optional-locks`: a plain `git status` refreshes the index's stat cache
    and writes it back. This gate is run as a CHECK, and a check that rewrites
    .git/index changes the repository identity that verified skill evidence
    signs, so its own run would read as stale."""
    raw=_git(['--no-optional-locks','--literal-pathspecs','status','--porcelain','-z','--untracked-files=all','--',*paths], root)
    out=set(); fields=raw.split(b'\0'); j=0
    while j < len(fields):
        entry=fields[j]; j+=1
        if len(entry) < 4: continue
        out.add(os.fsdecode(entry[3:]))
        if entry[:1] in (b'R', b'C') or entry[1:2] in (b'R', b'C'):
            if j < len(fields) and fields[j]: out.add(os.fsdecode(fields[j]))
            j+=1
    return out


def _dirty_covered(root:Path, covered) -> set:
    """The covered paths git calls changed or untracked. Git is asked about
    covered paths only (literal pathspecs, after `--`), in batches, so an
    untracked tree no doc covers is never walked. A covers entry git cannot be
    given (absolute, `..`, a NUL) is left out. Raises RuntimeError when git does
    not answer; the caller reports that and compares nothing."""
    dirty=set(); paths=sorted(p for p in covered if _plain_rel(p))
    for i in range(0, len(paths), _STATUS_BATCH):
        dirty |= _status_paths(root, paths[i:i+_STATUS_BATCH])
    return dirty


def _install_hashes(root:Path) -> dict:
    """sha256 by path of the kit files an install wrote here, from the install
    record. Empty when there is none (the kit's own repo) or it cannot be read."""
    try: data=json.loads(_safe_read_text(root/INSTALL_RECORD, root, max_bytes=8 << 20) or 'null')
    except Exception: return {}
    owned=data.get('owned_file_sha256') if isinstance(data, dict) else None
    return {str(k): str(v) for k, v in owned.items()} if isinstance(owned, dict) else {}


def _as_installed(root:Path, rel:str, want:str) -> bool:
    """True when `rel` still has the bytes the install record names. Unreadable
    is not a match: the advisory then reports the file, which is the safe side."""
    data=_safe_read_bytes(root/rel, root, max_bytes=64 << 20)
    return data is not None and hashlib.sha256(data).hexdigest() == want


def _worktree_stale(docs, root:Path, pending) -> list:
    """(doc, covered file) pairs where the file has uncommitted changes AND was
    saved after the doc. This is the window `stale_doc` (commit dates) and
    `pending_stale_doc` (the index) cannot see: code edited, nothing staged,
    the doc still describing the old rule, every gate green. A repo with no
    commit lives in that window permanently.

    Only files git calls changed are compared, so a clean checkout never flags
    whatever its mtimes are (a clone or a branch switch sets them arbitrarily).
    A kit file that still matches its install record is not changed either: an
    install or upgrade writes files in no promised order, and nobody edited it.
    A pair the gate already reports as PENDING is not repeated here. ADVISORY,
    like size: a save order is evidence that a doc may be behind, not proof."""
    covered={c for d in docs for c in d['covers']}
    dirty=_dirty_covered(root, covered)
    if not dirty: return []
    installed=_install_hashes(root); seen={(p[0], p[1]) for p in pending}; unchanged={}
    out=[]
    for d in docs:
        try: doc_saved=(root/d['path']).stat().st_mtime_ns
        except OSError: continue
        for cov in d['covers']:
            if cov not in dirty or (d['path'], cov) in seen: continue
            try: st=(root/cov).stat()
            except OSError: continue
            if not stat.S_ISREG(st.st_mode) or st.st_mtime_ns <= doc_saved: continue
            if cov in installed:
                if cov not in unchanged: unchanged[cov]=_as_installed(root, cov, installed[cov])
                if unchanged[cov]: continue
            out.append((d['path'], cov))
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
    pending=[]; today=date.today()
    for code_path in sorted(staged & covered):
        for doc in cov_to_docs.get(code_path,[]):
            if doc['path'] in staged_docs:
                continue
            # SAME-DAY REVIEW EXEMPTION (v3.8.35). The v3.8.32 rewrite required
            # the covering doc to be STAGED, full stop — but an unmodified doc
            # cannot be staged, so a second same-day commit to a file covered
            # by every doc (manage.sh) became unsatisfiable without artificial
            # edits (the "commits never converge" class). The v3.4.1 date-only
            # exemption was too loose the other way: a date proves nothing by
            # itself. Reconciled: exempt only when the review date is today AND
            # the doc's last COMMIT is today — a demonstrable same-day review,
            # not a bare date bump on a stale doc.
            if (_date(doc.get('last_human_reviewed','')) == today
                    and git_file_last_modified(Path(doc['path']), cwd=root) == today):
                continue
            pending.append((doc['path'], code_path, str(doc.get('last_human_reviewed',''))))
    manifest=_manifest_paths(root); on_disk={d['path'] for d in docs}
    # The working-tree advisory needs git too. With the index unreadable the gate
    # is already failing on that, and there is nothing further to ask git for.
    worktree_stale = []; worktree_error = None
    if staged_error:
        worktree_error = 'git state is unreadable (see STAGED READ ERROR)'
    else:
        try:
            worktree_stale = _worktree_stale(docs, root, pending)
        except RuntimeError as exc:
            worktree_error = str(exc).replace('staged git state', 'working tree state')
    return {
      'coverage_gap':sorted(code-covered),
      'staged_coverage_gap':sorted(p for p in _staged_code(root, staged) if p not in cov_to_docs),
      'pending_stale_doc':pending,
      'phantom_doc':[(d['path'],c) for d in docs for c in d['covers'] if not (root/c).exists()],
      'stale_doc':[r for d in docs for c in d['covers'] if (r:=_doc_stale(d,c,root)) is not None],
      'orphan_doc':sorted(on_disk-(manifest or set())),
      'assert_failed':[f for d in docs for f in _assert_failures(d, root)],
      'oversize_doc':_oversize_docs(docs, root),
      'worktree_stale_doc':worktree_stale,
      'worktree_read_error':worktree_error,
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
              'per-release narrative belongs in docs/HISTORY.md. Split or trim. The size is '
              'the prose only: covers: and asserts: lines are not counted, so keep them.', file=file)
        if os.environ.get('SUBSTRATE_ENFORCE_DOC_BUDGET') == '1':
            found=True
    # ALSO ADVISORY: a save order says a doc MAY be behind its code; it does not
    # prove it, and an edit in progress is the normal state of a working tree.
    stale = d.get('worktree_stale_doc') or []
    if stale or d.get('worktree_read_error'):
        print('\nWORKING-TREE STALE DOC (advisory — does not fail the gate):', file=file)
        if d.get('worktree_read_error'):
            print(f"  - not checked: {d['worktree_read_error']}", file=file)
        by_doc={}
        for doc, cov in stale: by_doc.setdefault(doc, []).append(cov)
        for doc, covs in by_doc.items():
            more=f' (+{len(covs)-5} more)' if len(covs) > 5 else ''
            print(f"  - {doc} -> {len(covs)} covered file(s) with uncommitted changes saved after the doc: "
                  + ', '.join(covs[:5]) + more, file=file)
        print('  Fix: read each file against the doc, correct what no longer holds, then save the doc '
              'and bump last_human_reviewed. The commit-date and staged checks above cannot see an '
              'edit that is neither committed nor staged.', file=file)
    if not found: print('doc-drift: no drift detected.', file=file)
    return found
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--strict', action='store_true', default=True); ap.add_argument('--report-only', action='store_true'); ap.add_argument('--json', action='store_true')
    a=ap.parse_args(); d=detect(repo_root())
    if a.json: print(json.dumps(d, indent=2, sort_keys=True)); return 0
    found=report(d); return 0 if a.report_only or not found else 1
if __name__=='__main__': sys.exit(main())
