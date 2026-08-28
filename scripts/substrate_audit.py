#!/usr/bin/env python3
"""Run substrate checks and optionally write a report under ai/audits/."""
from __future__ import annotations
import argparse, json, subprocess, sys
from datetime import UTC, datetime
from pathlib import Path

# v3.8.43 (round-26): shared guarded file-IO helpers. Fallbacks fail CLOSED —
# a reader yields None (no usable content) and a writer RAISES; neither
# degrades to an unguarded operation.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from _doc_common import safe_atomic_write as _safe_atomic_write
except Exception:  # pragma: no cover - stripped install
    def _safe_atomic_write(*a, **k):
        raise OSError("safe_atomic_write unavailable — refusing an unguarded write")

# v3.8.46 (round-29 P2): guarded mkdir. A raw mkdir(parents=True) BEFORE a
# guarded write creates the directory through a symlinked ancestor and only
# then gets refused — the mutation has already happened outside the repo.
try:
    from _doc_common import safe_mkdir as _safe_mkdir
except Exception:  # pragma: no cover - stripped install
    def _safe_mkdir(*a, **k):
        raise OSError("safe_mkdir unavailable — refusing an unguarded mkdir")

ROOT=Path.cwd()
def run(cmd):
    start=datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z')
    try:
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=300); rc=p.returncode; out=(p.stdout+p.stderr).strip()
    except Exception as e: rc=1; out=str(e)
    end=datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z')
    return {'cmd':cmd,'returncode':rc,'output':out,'started':start,'finished':end}
def _subvenv_bin(name):
    # Substrate-venv tool path, or None if absent. NEVER falls back to
    # ambient PATH (the v3.2.2 "full-audit uses ambient pytest" finding) —
    # callers skip the gate instead of running an environment-dependent tool.
    p=ROOT/'.substrate'/'venv'/'bin'/name
    return str(p) if p.exists() else None
def plan(mode):
    # Validators run with the substrate-venv python if present, else this
    # interpreter — consistent with manage.sh / release_gate tool resolution.
    subpy=ROOT/'.substrate'/'venv'/'bin'/'python'
    py=str(subpy) if subpy.exists() else sys.executable
    quick=[[py,'scripts/substrate_doctor.py'],[py,'scripts/update_manifest.py','--check'],[py,'scripts/check_doc_drift.py','--strict'],[py,'scripts/check_agent_harness.py'],[py,'scripts/check_secrets.py'],[py,'scripts/check_history_sha.py']]
    if mode=='quick': return quick
    full=list(quick)
    pt=_subvenv_bin('pytest'); pc=_subvenv_bin('pre-commit')
    if pt: full.append([pt,'tests/','-q'])
    else: full.append(['__skip__','pytest not in .substrate/venv — run ./manage.sh setup'])
    if pc: full.append([pc,'run','--all-files','--show-diff-on-failure'])
    else: full.append(['__skip__','pre-commit not in .substrate/venv — run ./manage.sh setup'])
    return full
def write_report(report):
    stamp=datetime.now(UTC).strftime('%Y-%m-%dT%H%M%SZ'); outdir=ROOT/'ai'/'audits'/stamp; _safe_mkdir(outdir, ROOT)
    _safe_atomic_write(outdir/'audit-report.json', json.dumps(report,indent=2,sort_keys=True)+'\n', root=ROOT)
    lines=[f'# Audit report — {stamp}','',f"Mode: `{report['mode']}`",f"Final: **{report['final']}**",'', '## Checks','']
    for c in report['checks']:
        status='PASS' if c['returncode']==0 else 'BLOCK'; lines.append(f"### {status}: `{' '.join(c['cmd'])}`")
        if c['output']: lines+=['','```text',c['output'][-4000:],'```','']
    _safe_atomic_write(outdir/'audit-report.md', '\n'.join(lines)+'\n', root=ROOT)
    return outdir/'audit-report.json'
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--mode',choices=['quick','full'],default='quick'); ap.add_argument('--write-report',action='store_true'); ap.add_argument('--json',action='store_true'); a=ap.parse_args()
    checks=[]
    for cmd in plan(a.mode):
        if cmd and cmd[0]=='__skip__':
            print('SKIP: '+cmd[1]); checks.append({'cmd':['skip'],'returncode':0,'output':'skipped: '+cmd[1],'started':'','finished':''}); continue
        r=run(cmd); checks.append(r); print(('PASS' if r['returncode']==0 else 'BLOCK')+': '+' '.join(cmd))
        if r['returncode'] and r['output']: print(r['output'][-2000:])
    final='PASS' if all(c['returncode']==0 for c in checks) else 'BLOCK'; report={'mode':a.mode,'final':final,'generated_at':datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z'),'checks':checks}
    if a.write_report:
        # v3.8.46 (round-29 P2): the report directory is created through the
        # guarded descent now, so a symlinked ai/ is REFUSED before anything is
        # created outside. Report that as an audit failure with a readable
        # message rather than a traceback — an audit that cannot record itself
        # has not passed.
        try:
            print('substrate-audit: wrote '+str(write_report(report).relative_to(ROOT)))
        except OSError as e:
            print(f'substrate-audit: BLOCK: cannot write the report: {e}', file=sys.stderr)
            return 1
    if a.json: print(json.dumps(report,indent=2,sort_keys=True))
    return 0 if final=='PASS' else 1
if __name__=='__main__': sys.exit(main())
