#!/usr/bin/env python3
"""Run substrate checks and optionally write a report under ai/audits/."""
from __future__ import annotations
import argparse, json, os, subprocess, sys
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
# Every check gets a bounded run. The full pytest suite runs close to five minutes
# on a hosted runner, so a fixed 300 s cap turned ordinary runner variance into
# intermittent failures (v3.10.2). Its limit is separate and configurable.
QUICK_TIMEOUT=300
PYTEST_TIMEOUT_ENV='SUBSTRATE_AUDIT_PYTEST_TIMEOUT'
PYTEST_TIMEOUT_DEFAULT=1200
PYTEST_TIMEOUT_RANGE=(60,1800)
def pytest_timeout():
    """The pytest limit in seconds. An invalid value is an error, never a silent default."""
    raw=os.environ.get(PYTEST_TIMEOUT_ENV,'').strip()
    if not raw: return PYTEST_TIMEOUT_DEFAULT
    lo,hi=PYTEST_TIMEOUT_RANGE
    if not (raw.isascii() and raw.isdigit() and lo<=int(raw)<=hi):
        raise ValueError(f'{PYTEST_TIMEOUT_ENV} must be whole seconds in {lo}..{hi}, got {raw[:20]!r}')
    return int(raw)
def _text(data):
    return data.decode('utf-8','replace') if isinstance(data,bytes) else (data or '')
def run(cmd,timeout=QUICK_TIMEOUT):
    """One check. TIMEOUT is its own status: the check neither passed nor failed,
    it did not finish, and the partial output shows how far it got."""
    start=datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z')
    try:
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=timeout); rc=p.returncode; out=(p.stdout+p.stderr).strip()
        status='PASS' if rc==0 else 'BLOCK'
    except subprocess.TimeoutExpired as e:
        rc=124; status='TIMEOUT'
        partial=(_text(e.stdout)+_text(e.stderr)).strip()
        out=f'did not finish within {timeout} s; partial output follows\n{partial}'.strip()
    except Exception as e: rc=1; status='BLOCK'; out=str(e)
    end=datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z')
    return {'cmd':cmd,'returncode':rc,'status':status,'timeout_seconds':timeout,'output':out,'started':start,'finished':end}
def final_status(checks):
    """PASS only when every check ran and passed. A check that timed out or could not
    run (its tool is missing) is not verified, so it never reads as a pass."""
    statuses=[c.get('status','PASS' if c['returncode']==0 else 'BLOCK') for c in checks]
    if all(s=='PASS' for s in statuses): return 'PASS'
    for s in ('BLOCK','TIMEOUT','NOT-RUN'):
        if s in statuses: return s
    return 'BLOCK'
def _durations(output):
    """The slowest-tests block pytest prints, so every report says whether one
    test or the whole suite is slow."""
    lines=output.splitlines()
    for i,line in enumerate(lines):
        if 'slowest' in line and 'durations' in line:
            return '\n'.join(lines[i:i+16])
    return ''
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
    quick=[[py,'scripts/substrate_doctor.py'],[py,'scripts/update_manifest.py','--check'],[py,'scripts/check_doc_drift.py','--strict'],[py,'scripts/check_agent_harness.py'],[py,'scripts/check_leaks.py'],[py,'scripts/check_history_sha.py']]
    if mode=='quick': return quick
    full=list(quick)
    pt=_subvenv_bin('pytest'); pc=_subvenv_bin('pre-commit')
    if pt: full.append([pt,'tests/','-q','--durations=15'])
    else: full.append(['__not_run__','pytest not in .substrate/venv — run ./manage.sh setup'])
    if pc: full.append([pc,'run','--all-files','--show-diff-on-failure'])
    else: full.append(['__not_run__','pre-commit not in .substrate/venv — run ./manage.sh setup'])
    return full
def write_report(report):
    stamp=datetime.now(UTC).strftime('%Y-%m-%dT%H%M%SZ'); outdir=ROOT/'ai'/'audits'/stamp; _safe_mkdir(outdir, ROOT)
    _safe_atomic_write(outdir/'audit-report.json', json.dumps(report,indent=2,sort_keys=True)+'\n', root=ROOT)
    lines=[f'# Audit report — {stamp}','',f"Mode: `{report['mode']}`",f"Final: **{report['final']}**",'', '## Checks','']
    for c in report['checks']:
        status=c.get('status','PASS' if c['returncode']==0 else 'BLOCK'); lines.append(f"### {status}: `{' '.join(c['cmd'])}`")
        if c['output']: lines+=['','```text',c['output'][-4000:],'```','']
    _safe_atomic_write(outdir/'audit-report.md', '\n'.join(lines)+'\n', root=ROOT)
    return outdir/'audit-report.json'
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--mode',choices=['quick','full'],default='quick'); ap.add_argument('--write-report',action='store_true'); ap.add_argument('--json',action='store_true'); a=ap.parse_args()
    try:
        limit=pytest_timeout() if a.mode=='full' else QUICK_TIMEOUT
    except ValueError as e:
        print(f'substrate-audit: {e}', file=sys.stderr); return 2
    checks=[]
    for cmd in plan(a.mode):
        if cmd and cmd[0]=='__not_run__':
            # A full audit without its test tools has verified nothing about tests:
            # NOT-RUN, never a pass (it used to be SKIP with returncode 0).
            print('NOT-RUN: '+cmd[1]); checks.append({'cmd':['not-run'],'returncode':127,'status':'NOT-RUN','output':'not run: '+cmd[1],'started':'','finished':''}); continue
        is_pytest=Path(cmd[0]).name=='pytest'
        r=run(cmd,limit if is_pytest else QUICK_TIMEOUT); checks.append(r); print(r['status']+': '+' '.join(cmd))
        if r['returncode'] and r['output']: print(r['output'][-2000:])
        elif is_pytest and _durations(r['output']): print(_durations(r['output']))
    final=final_status(checks); report={'mode':a.mode,'final':final,'generated_at':datetime.now(UTC).replace(microsecond=0).isoformat().replace('+00:00','Z'),'checks':checks}
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
