#!/usr/bin/env python3
"""Fast lightweight secrets scanner for common credential shapes."""
from __future__ import annotations
import re, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
EXCLUDE={'.git','.venv','venv','node_modules','__pycache__','.pytest_cache','.ruff_cache','.mypy_cache','data','dist','build'}
EXTS={'.py','.sql','.yaml','.yml','.md','.toml','.ts','.tsx','.json','.txt','.sh','.css','.html','.js','.env','.cfg','.ini'}
# Scripts that legitimately contain secret-SHAPED regex patterns (the
# redaction/guard layer), not real secrets.
ALLOW={'scripts/check_secrets.py','scripts/check_agent_harness.py','scripts/check_exfil_guard.py','scripts/session_handoff.py','scripts/memory_log.py','scripts/copilot_hook_adapter.py','tests/test_validator_secrets.py','tests/test_hook_scripts.py'}
PATS=[
 ('aws_access_key', re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
 ('github_token', re.compile(r'\bgh[pousr]_[A-Za-z0-9]{20,}\b')),
 ('slack_token', re.compile(r'\bxox[bpars]-[A-Za-z0-9-]{10,}\b')),
 ('stripe_live_key', re.compile(r'\b[sp]k_live_[A-Za-z0-9]{20,}\b')),
 ('google_api_key', re.compile(r'\bAIza[0-9A-Za-z_\-]{35}\b')),
 ('private_key', re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----')),
]
GENERIC=re.compile(r'''(?ix)\b(api[_-]?key|secret|password|passwd|token|access[_-]?token)\b\s*[:=]\s*['"]([^'"]{12,})['"]''')
OK=re.compile(r'(example|placeholder|fixture|TODO|YOUR[_-]?KEY|<.*?>|\$\{[A-Z_]+\}|test|dummy|fake)', re.I)
def false_positive(line,value): return bool(OK.search(line) or OK.search(value) or len(set(value))<=2)
def main():
    findings=[]; count=0
    for p in ROOT.rglob('*'):
        if not p.is_file(): continue
        rel=p.relative_to(ROOT)
        if any(part in EXCLUDE for part in rel.parts): continue
        if p.suffix.lower() not in EXTS: continue
        if rel.as_posix() in ALLOW: continue
        try: lines=p.read_text(encoding='utf-8', errors='ignore').splitlines()
        except OSError: continue
        count+=1
        for n,line in enumerate(lines,1):
            if '# secrets-ok:' in line: continue
            for name,rx in PATS:
                if rx.search(line): findings.append((rel,n,name,line.strip()[:120]))
            m=GENERIC.search(line)
            if m and not false_positive(line,m.group(2)): findings.append((rel,n,'generic_assignment',line.strip()[:120]))
    if findings:
        print('check-secrets: POTENTIAL SECRETS FOUND', file=sys.stderr)
        for rel,n,name,line in findings:
            print(f'  {rel}:{n} -> {name}\n    {line}', file=sys.stderr)
        return 1
    print(f'check-secrets: scanned {count} files, 0 secret-pattern hits.'); return 0
if __name__=='__main__': sys.exit(main())
