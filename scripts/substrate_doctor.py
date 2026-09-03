#!/usr/bin/env python3
"""Verify that the agent substrate is installed and wired correctly.

Readiness levels (default runs quick+security+subprocess checks):
  --quick        file presence + hook wiring only (fast, no subprocesses)
  --security     adds exfil-guard + secret-deny + absolute-path checks
  --operational  adds "can it actually RUN?" — substrate venv + pre-commit
                 present, validators import, configured lang commands
                 resolve. A pass means setup/check will work, not just
                 that files exist.
"""
from __future__ import annotations
import argparse, json, shutil, subprocess, sys
from pathlib import Path
# Use the shared root resolver (env override / git toplevel / ancestor) like
# every other validator+hook, so `doctor` is correct when launched from a
# subdirectory instead of silently checking the wrong tree. Falls back to cwd.
sys.path.insert(0, str(Path(__file__).resolve().parent))

# v3.8.43 (round-26 P2): every .substrate/config read in the doctor goes through
# the canonical guarded reader — a FIFO config used to hang the doctor at
# _remote_governance() before any check ran. None means "no usable config",
# which leaves each helper on its existing default.
try:
    from _doc_common import safe_read_text as _safe_read_text
except Exception:  # pragma: no cover - stripped install
    def _safe_read_text(path, root=None, max_bytes=None, tail_bytes=None):
        return None

try:
    from _substrate_root import substrate_root as _sr
    ROOT=_sr()
except Exception:
    ROOT=Path.cwd()
REQ=['AGENTS.md','CLAUDE.md','.codex/config.toml','.codex/hooks.json','.substrate/config','.agents/skills/self-audit/SKILL.md','.claude/skills/self-audit/SKILL.md','.claude/skills/session-recovery/SKILL.md','.claude/agents/security-auditor.md','.claude/agents/checklist-auditor.md','.codex/agents/security-auditor.toml','.claude/settings.json','.github/copilot-instructions.md','.github/hooks/exfil-guard.json','.github/instructions/substrate.instructions.md','scripts/check_doc_drift.py','scripts/check_agent_harness.py','scripts/check_exfil_guard.py','scripts/copilot_hook_adapter.py','scripts/session_handoff.py','scripts/todo_state_hook.py','scripts/lint_on_write.py','scripts/memory_log.py','scripts/lang_gate.sh','scripts/run_python_gate.sh','scripts/_substrate_config.sh','scripts/check_substrate_config.py','scripts/command_policy.py','scripts/harness_patterns.json','scripts/_substrate_root.py','scripts/_substrate_surfaces.py','scripts/substrate_audit.py','scripts/release_gate.sh','scripts/update_manifest.py','docs/HISTORY.md','docs/knowledge/00_substrate.md','docs/manifest.json','.pre-commit-config.yaml','.github/workflows/ci.yml','.github/workflows/scheduled-audit.yml','.github/workflows/agent-config-audit.yml','manage.sh']
WARN=['docs/ARCHITECTURE.md','docs/INTENT.md']
def _codex_hooks_use_canonical_flag():
    p=ROOT/'.codex/config.toml'
    if not p.exists(): return True
    txt=_safe_read_text(p, ROOT, max_bytes=16 << 20) or ''
    # canonical is `hooks = true`; deprecated alias is `codex_hooks`.
    import re as _re
    return bool(_re.search(r'(?m)^\s*hooks\s*=\s*true', txt))
def _settings():
    p=ROOT/'.claude/settings.json'
    if not p.exists(): return None
    try: return json.loads(_safe_read_text(p, ROOT, max_bytes=16 << 20) or 'null')
    except Exception: return None
def _hooks_wired(cfg):
    if not cfg: return False
    hooks=cfg.get('hooks',{})
    return all(k in hooks for k in ('PreToolUse','PreCompact','SessionStart','PostToolUse'))
def _hook_findings(cfg):
    """Returns (blocks, warns) for hook security posture."""
    b=[]; w=[]
    if not cfg: return (['settings.json unreadable'], [])
    hooks=cfg.get('hooks',{}); flat=json.dumps(hooks)
    for script in ('session_handoff.py','todo_state_hook.py','lint_on_write.py','check_exfil_guard.py'):
        if script not in flat: b.append(f'hook not wired: {script}')
    if '$CLAUDE_PROJECT_DIR' not in flat: w.append('hooks should use absolute paths ($CLAUDE_PROJECT_DIR)')
    missing_timeout=[h.get('command','?') for ms in hooks.values() for m in ms for h in m.get('hooks',[]) if 'timeout' not in h]
    if missing_timeout: w.append(f'{len(missing_timeout)} hook(s) missing explicit timeout')
    deny=cfg.get('permissions',{}).get('deny',[])
    if not any('.env' in d for d in deny): w.append('settings.json permissions.deny does not cover .env')
    return (b,w)
def _profile():
    cfg=ROOT/'.substrate/config'
    if True:
        for line in (_safe_read_text(cfg, ROOT, max_bytes=1 << 20) or '').splitlines():
            if line.strip().startswith('SUBSTRATE_PROFILE='):
                return line.split('=',1)[1].strip().strip('"\'')
    return 'standard'
def _remote_governance():
    """SUBSTRATE_REMOTE_GOVERNANCE from .substrate/config ('0'/'1'). v3.6.0:
    remote governance (CODEOWNERS coverage, trusted-base authority) is an
    ORTHOGONAL tier, decoupled from the strict profile — a repo can be
    strict-LOCAL or standard+remote."""
    cfg=ROOT/'.substrate/config'
    if True:
        for line in (_safe_read_text(cfg, ROOT, max_bytes=1 << 20) or '').splitlines():
            if line.split('#',1)[0].strip().startswith('SUBSTRATE_REMOTE_GOVERNANCE='):
                return line.split('=',1)[1].split('#',1)[0].strip().strip('"\'')
    return '0'
def _dep_cooldown_days():
    """SUBSTRATE_DEP_COOLDOWN (int days, 0=off) from .substrate/config. v3.7.2 — the
    cooldown deep tier. go-live reports it OFFLINE (never runs the networked check)."""
    cfg=ROOT/'.substrate/config'
    if True:
        for line in (_safe_read_text(cfg, ROOT, max_bytes=1 << 20) or '').splitlines():
            if line.split('#',1)[0].strip().startswith('SUBSTRATE_DEP_COOLDOWN='):
                v=line.split('=',1)[1].split('#',1)[0].strip().strip('"\'')
                return int(v) if v.isdigit() else 0
    return 0
def _required_remote_governance():
    """.substrate/required_remote_governance ('0'/'1' or None) — the pinned remote-
    governance minimum, frozen by the trusted-base audit. v3.6.1.
    v3.8.33/36: any PRESENT-but-malformed lock (unreadable, garbage, symlink,
    directory — the canonical reader decides) reads as '1' — doctor then reports
    the remote tier as required-but-unproven instead of silently dropping it
    (fail toward requiring; the gate itself refuses in check_substrate_config)."""
    from _doc_common import read_lock as _dc_read_lock
    state, val, _r = _dc_read_lock(ROOT/'.substrate'/'required_remote_governance', {'0','1'}, root=ROOT)
    if state == 'absent': return None
    return val if state == 'ok' else '1'
def _codeowners_path():
    for loc in ('.github/CODEOWNERS','CODEOWNERS','docs/CODEOWNERS'):
        if (ROOT/loc).exists(): return ROOT/loc
    return None
def _codeowners_active():
    return _codeowners_path() is not None
# Placeholder owners that GitHub would silently ignore (no real team).
import re as _re_co
_PLACEHOLDER_OWNER=_re_co.compile(r'(?i)@(?:your-org|your-team|org|example|team-or-user|changeme|change-me|todo)\b|<[^>]+>')
def _codeowners_placeholder_owners():
    """Returns list of placeholder owner tokens in the ACTIVE file.
    GitHub assigns no owner for nonexistent teams, so a file full of
    @your-org/* placeholders is a governance false-green."""
    p=_codeowners_path()
    if p is None: return []
    bad=set()
    try:
        for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
            line=line.split('#',1)[0].strip()
            if not line: continue
            for tok in line.split()[1:]:  # owners follow the pattern
                if _PLACEHOLDER_OWNER.search(tok): bad.add(tok)
    except Exception: return []
    return sorted(bad)
def _codeowners_warn():
    gh=ROOT/'.github'
    if (gh/'CODEOWNERS.suggested').exists() and not _codeowners_active():
        return 'CODEOWNERS.suggested present but no active .github/CODEOWNERS (fill in real teams, then rename)'
    return None
# Strict CODEOWNERS coverage derives from the CANONICAL surface inventory
# (_substrate_surfaces.py), shared with the harness scanner and the
# agent-config-audit trigger so the three cannot drift.
try:
    sys.path.insert(0, str((ROOT/'scripts')))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _substrate_surfaces import (OWNED_DIRS as _SENSITIVE_DIRS,
        OWNED_FILES as _SENSITIVE_FILES, OPTIONAL_FILES as _SENSITIVE_OPTIONAL_FILES,
        OPTIONAL_DIRS as _SENSITIVE_OPTIONAL_DIRS,
        GOVERNED_DIRS as _SENSITIVE_GOVERNED_DIRS,
        GOVERNED_OPTIONAL_DIRS as _SENSITIVE_GOVERNED_OPTIONAL_DIRS,
        COVERAGE_SKIP_PARTS as _COVERAGE_SKIP_PARTS)
except Exception:  # pragma: no cover - fall back if inventory unreadable
    # This fallback MUST mirror _substrate_surfaces EXACTLY — test_doctor_fallback_
    # matches_canonical_inventory fails CI if it drifts. (v3.8.6: the fallback was
    # stale — missing DESIGN.md/.substrate/required_profile/docs/README.md and the
    # design-system/templates optional dirs + trust-anchor optional files — so an
    # import failure would silently DROP those coverage requirements and overstate
    # remote-governance coverage.)
    _SENSITIVE_DIRS=['scripts','tests','.claude','.codex','.agents','docs/decisions','docs/blind-spot-checklists','docs/templates','.github/hooks','.github/instructions','.github/workflows']
    _SENSITIVE_FILES=['AGENTS.md','CLAUDE.md','DESIGN.md','AGENT_BUS.md','manage.sh','bootstrap.sh','agentsync.sh','package_release.sh','pytest.ini','.pre-commit-config.yaml','.gitattributes','.gitignore','.github/copilot-instructions.md','.github/dependabot.yml','.substrate/config','.substrate/required_profile','docs/HISTORY.md','docs/REJECTED.md','docs/README.md','docs/ARCHITECTURE.md','docs/INTENT.md','docs/knowledge/00_substrate.md','docs/knowledge/_template.md']
    _SENSITIVE_OPTIONAL_FILES=['.mcp.json','.substrate/trust/minisign.pub','.substrate/trust/sigstore_identity.json','.substrate/install.json']
    _SENSITIVE_OPTIONAL_DIRS=['.github/skills','docs/postmortems','design-system','templates']
    _SENSITIVE_GOVERNED_DIRS=['docs/knowledge']
    _SENSITIVE_GOVERNED_OPTIONAL_DIRS=['docs/superpowers']
    _COVERAGE_SKIP_PARTS={'__pycache__','venv','node_modules','.pytest_cache','.ruff_cache','.mypy_cache'}
def _sensitive_files_on_disk():
    """Enumerate the actual privileged files that must be owned, plus the
    ACTIVE CODEOWNERS file itself (wherever GitHub loads it from)."""
    out=[]
    for f in _SENSITIVE_FILES+_SENSITIVE_OPTIONAL_FILES:
        if (ROOT/f).is_file(): out.append(f)
    # The active CODEOWNERS file must own itself — and it may live at
    # .github/, repo root, or docs/ (GitHub searches those in order).
    co=_codeowners_path()
    if co is not None: out.append(co.relative_to(ROOT).as_posix())
    for d in (_SENSITIVE_DIRS+_SENSITIVE_OPTIONAL_DIRS+_SENSITIVE_GOVERNED_DIRS
              +_SENSITIVE_GOVERNED_OPTIONAL_DIRS):
        base=ROOT/d
        if not base.is_dir(): continue
        for p in base.rglob('*'):
            if not p.is_file(): continue
            rel=p.relative_to(ROOT)
            if any(part in _COVERAGE_SKIP_PARTS for part in rel.parts): continue
            out.append(rel.as_posix())
    return sorted(set(out))
# A "real" owner is a syntactically valid GitHub handle/team or email —
# `@` alone or `x@` (no domain) is not a valid owner GitHub would honor.
_VALID_OWNER=_re_co.compile(
    r'^(?:@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?'
    r'|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})$'
)
def _is_real_owner(tok):
    return bool(_VALID_OWNER.match(tok)) and not _PLACEHOLDER_OWNER.search(tok)
CODEOWNERS_MAX_BYTES=3_000_000  # GitHub will not load a CODEOWNERS file over 3 MB
def _codeowners_too_large():
    p=_codeowners_path()
    try:
        return p is not None and p.stat().st_size>CODEOWNERS_MAX_BYTES
    except Exception:
        return False
def _co_pattern_to_regex(pat):
    """Translate a CODEOWNERS pattern to a regex over a posix repo path,
    matching GitHub's documented semantics:
      - `*` matches a single path segment (does NOT cross `/`). So
        `docs/*` covers `docs/a.md` but NOT `docs/sub/b.md`.
      - a pattern ending in `/` covers that directory RECURSIVELY.
      - `**` matches across `/` (recursive).
      - a non-recursive pattern matches the file EXACTLY (no implicit
        descendant coverage) — the conservative choice for a governance
        gate (a false-red is safe; a false-green is not)."""
    anchored=pat.startswith('/'); p=pat.lstrip('/'); dir_only=p.endswith('/'); p=p.rstrip('/')
    out=[]; i=0
    while i<len(p):
        if p[i:i+2]=='**': out.append('.*'); i+=2; continue
        c=p[i]
        if c=='*': out.append('[^/]*')
        elif c=='?': out.append('[^/]')
        else: out.append(_re_co.escape(c))
        i+=1
    body=''.join(out)+('/.*' if dir_only else '')  # only `/`-terminated patterns recurse
    rx=('^'+body+'$') if (anchored or '/' in p) else ('(^|.*/)'+body+'$')
    try: return _re_co.compile(rx)
    except Exception: return None
def _codeowners_all_rules():
    """[(pattern, [owners])] in file order — owners may be empty or placeholder."""
    p=_codeowners_path()
    if p is None: return []
    rules=[]
    for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
        line=line.split('#',1)[0].strip()
        if not line: continue
        parts=line.split()
        if len(parts)<1: continue
        rules.append((parts[0],parts[1:]))
    return rules
def _codeowners_owner_for(path, rules):
    """GitHub last-match semantics: the LAST matching rule wins, even if
    it has no owners (which leaves the path unowned)."""
    last=None
    for pat,owners in rules:
        rx=_co_pattern_to_regex(pat)
        if rx and rx.match(path): last=owners
    return last  # None=no match | []=matched ownerless | [owners]
def _codeowners_coverage_gaps():
    """ACTUAL privileged files whose LAST matching rule has no real owner.
    An owner is real if it is a GitHub handle (@user/@org/team) or an
    email address, and not a placeholder."""
    files=_sensitive_files_on_disk()
    rules=_codeowners_all_rules()
    if not rules: return files
    gaps=[]
    for s in files:
        owners=_codeowners_owner_for(s,rules)
        real=[o for o in (owners or []) if _is_real_owner(o)]
        if not real: gaps.append(s)
    # Cap the reported list; the count is what matters.
    return gaps
def _config_tool_warns():
    cfg=ROOT/'.substrate/config'
    if not cfg.exists(): return []
    vals={}
    for line in (_safe_read_text(cfg, ROOT, max_bytes=1 << 20) or '').splitlines():
        line=line.split('#',1)[0].strip()
        if '=' in line:
            k,v=line.split('=',1); vals[k.strip()]=v.strip().strip('"\'')
    w=[]
    for key in ('LINT_CMD','TYPECHECK_CMD','TEST_CMD'):
        cmd=vals.get(key,'')
        if not cmd: continue
        tool=cmd.replace('npx --no-install ','').split()[0]
        if tool and tool not in ('uv','python','python3') and not shutil.which(tool):
            w.append(f'{key} references "{tool}" which is not on PATH')
    return w
def run(cmd):
    try:
        p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=60); return p.returncode,(p.stdout+p.stderr).strip()
    except Exception as e: return 1,str(e)
def _operational_findings():
    """Can the substrate actually RUN? Returns (blocks, warns)."""
    b=[]; w=[]
    subpy=ROOT/'.substrate/venv/bin/python'
    if not subpy.exists():
        b.append('.substrate/venv missing — run `./manage.sh setup` (validators cannot run without it)')
        return (b,w)
    rc,out=run([str(subpy),'-c','import yaml'])
    if rc: b.append('substrate venv cannot import PyYAML (validators will fail): '+out[:120])
    if not (ROOT/'.substrate/venv/bin/pre-commit').exists():
        b.append('pre-commit not installed in substrate venv — run `./manage.sh setup`')
    # Configured language commands must resolve (empty is fine = gate skipped).
    cfg=ROOT/'.substrate/config'; vals={}
    if cfg.exists():
        for line in (_safe_read_text(cfg, ROOT, max_bytes=1 << 20) or '').splitlines():
            line=line.split('#',1)[0].strip()
            if '=' in line:
                k,v=line.split('=',1); vals[k.strip()]=v.strip().strip('"\'')
    for key in ('LINT_CMD','TYPECHECK_CMD','TEST_CMD'):
        cmd=vals.get(key,'')
        if not cmd: continue
        first=cmd.split()[0]
        # adapter scripts and shell builtins are fine; check real binaries
        if first in ('bash','sh','npm','npx','go','uv','python','python3'): continue
        if not shutil.which(first) and not (ROOT/first).exists():
            b.append(f'{key} entrypoint "{first}" not runnable')
    # Explicit runner must be available (no silent fallback to a
    # different env than setup used — the v3.2.1 runner-mismatch finding).
    runner=vals.get('SUBSTRATE_RUNNER','auto')
    if runner=='uv' and not shutil.which('uv'):
        b.append('SUBSTRATE_RUNNER=uv but uv is not on PATH')
    if runner=='poetry' and not shutil.which('poetry'):
        b.append('SUBSTRATE_RUNNER=poetry but poetry is not on PATH')
    # Durable memory chain integrity (if a log exists).
    if (ROOT/'.substrate/memory/events.jsonl').exists():
        rc,out=run([str(subpy),'scripts/memory_log.py','verify'])
        if rc: b.append('memory chain broken: '+out.strip()[:160])
    return (b,w)
def _go_live(blocks, warns, as_json=False):
    """Aggregate GO-LIVE readiness: repo-local PASS/FAIL + a production-hardening
    posture (sandbox, governance, anchor) a repo CANNOT prove on its own.
    Anti-overclaim: never reports production-hardened while the sandbox tier is
    absent. `as_json` emits a STABLE machine-readable contract — the single
    integration point future layers (sandbox, governance, installers, agents)
    add rows to (v3.3.12)."""
    repo_ok = not blocks
    eval_ok = None
    ev = ROOT / 'scripts' / 'run_substrate_evals.py'
    if ev.is_file():
        rc, _ = run([sys.executable, '-I', str(ev), '--fast', '--no-trace'])
        eval_ok = (rc == 0)
    tb = (ROOT / '.github' / 'workflows' / 'trusted-base-audit.yml').exists()
    # Memory posture. v3.7.6 (audit P1): a present anchor NOTE is not a verified anchor —
    # the row must check the anchor against the chain, not merely that a note exists, or
    # it overclaims `pass`. v3.8.51 (self-audit P1): this row used to REIMPLEMENT the
    # rule (anchored_head == current_head) alongside memory_log.verify — two definitions
    # of "anchor valid", and the one here reported ordinary growth as STALE. One
    # definition now: delegate to `memory_log.py verify --anchor` (nearest annotated
    # ancestor; anchored hash must be a MEMBER of the link-verified chain) and map its
    # outcome. 4-state: no-log → warn | chain-broken → fail | anchor verified → pass |
    # no anchor in ancestry → warn | anchor not in chain (replaced/truncated) → fail.
    mem_events = ROOT / '.substrate' / 'memory' / 'events.jsonl'
    if not mem_events.exists():
        mem_status, mem_reason = 'warn', 'no memory log yet (events.jsonl absent)'
    else:
        rc_mem, _ = run([sys.executable, '-I', 'scripts/memory_log.py', 'verify'])
        if rc_mem != 0:
            mem_status, mem_reason = 'fail', 'memory hash-chain BROKEN (tamper evidence) — run `./manage.sh memory verify`'
        else:
            rc_anc, out_anc = run([sys.executable, '-I', 'scripts/memory_log.py', 'verify', '--anchor'])
            # v3.8.52 (round-34 P1): rc==0 no longer means one thing. A note that
            # exists only in this clone lives in the same writable state as the log,
            # so reporting it as "verified" was the overclaim this row was written to
            # avoid. Published and local-only are now separate rows.
            #
            # v3.8.54 (in-release security-auditor BLOCK, my own defect): the
            # strongest verdict used to be the CATCH-ALL — "none of the known
            # local tiers matched, so it must be remote-verified". Adding a
            # fifth rc==0 tier (LOCAL AHEAD) therefore made this row claim
            # "verified against the remote" for an anchor that is not published
            # at all, from state a local writer controls. A positive claim must
            # rest on positive evidence, never on the absence of known
            # negatives, so the remote row now requires the verifier to have
            # SAID so and an unrecognised tier degrades to warn.
            if rc_anc == 0 and 'verified against origin' in out_anc:
                mem_status, mem_reason = 'pass', 'hash-chain ok + anchor verified against the remote'
            elif rc_anc == 0 and 'LOCAL (no remote)' in out_anc:
                mem_status, mem_reason = 'pass', ('hash-chain ok + anchor verified locally (no remote exists, so '
                                                  'local is the strongest anchor this repo can hold)')
            elif rc_anc == 0 and 'LOCAL-ONLY' in out_anc:
                mem_status, mem_reason = 'warn', ('hash-chain ok + anchor present but LOCAL-ONLY — not published to '
                                                  'the remote, so it bounds accident and a single re-anchor, not an '
                                                  'adversary with write access to refs/notes/; push it FROM THIS '
                                                  'CLONE with `git push origin refs/notes/substrate-memory`')
            elif rc_anc == 0 and 'LOCAL AHEAD' in out_anc:
                mem_status, mem_reason = 'warn', ('hash-chain ok but the local anchor has ADVANCED PAST the '
                                                  'published one — the chain still descends from what the remote '
                                                  'publishes, but the newer note was never pushed; push it FROM '
                                                  'THIS CLONE with `git push origin refs/notes/substrate-memory`')
            elif rc_anc == 0:
                mem_status, mem_reason = 'warn', ('hash-chain ok but the anchor tier was not recognised — treat as '
                                                  'UNVERIFIED and read the verifier output: '
                                                  + (out_anc.strip().splitlines() or [''])[0][:160])
            elif 'NO ANCHOR' in out_anc:
                mem_status, mem_reason = 'warn', 'hash-chain ok but not anchored — run `./manage.sh memory anchor`'
            elif 'ANCHOR NOT PUBLISHED' in out_anc:
                mem_status, mem_reason = 'fail', ('strict requires a PUBLISHED anchor — the note exists only locally; '
                                                  'push it FROM THIS CLONE with `git push origin '
                                                  'refs/notes/substrate-memory` (a normal push/clone does not carry '
                                                  'refs/notes/*, so no other clone can publish it for you)')
            elif 'ANCHOR CONFLICT' in out_anc:
                mem_status, mem_reason = 'fail', ('memory anchor CONFLICT — the local note disagrees with the one the '
                                                  'remote publishes: the local note was rewritten; run '
                                                  '`./manage.sh memory verify --anchor`')
            else:
                mem_status, mem_reason = 'fail', ('memory anchor MISMATCH — the anchored head is not in the current '
                                                  'chain (history replaced or truncated past the anchor); run '
                                                  '`./manage.sh memory verify --anchor`')
    # Remote tier (v3.6.0): OFFLINE detection only — is there a GitHub remote? Drives
    # the remote-expansion section. remote_detect.py reads .git/config (no network, no
    # token), so go-live stays side-effect-light. LIVE branch-protection state needs an
    # API call and lives behind `enable remote --check`, NOT this default report.
    has_remote, provider = False, 'none'
    rd = ROOT / 'scripts' / 'remote_detect.py'
    if rd.is_file():
        try:
            import json as _jr, subprocess as _spr, sys as _sysr
            pr = _spr.run([_sysr.executable, '-I', str(rd), '--root', str(ROOT), '--json'],
                          capture_output=True, text=True, timeout=15)
            dr = _jr.loads(pr.stdout)
            has_remote, provider = bool(dr.get('has_remote')), dr.get('provider', 'none')
        except Exception:
            has_remote, provider = False, 'none'
    # Remote-governance tier (config flag, decoupled from the strict profile).
    remote_gov = _remote_governance() == '1'
    # sandbox tier (egress containment): enabled in config AND an OS sandbox present.
    sb_cfg = ''
    cfgp = ROOT / '.substrate' / 'config'
    if cfgp.exists():
        for ln in (_safe_read_text(cfgp, ROOT, max_bytes=1 << 20) or '').splitlines():
            ln = ln.split('#', 1)[0].strip()
            if ln.startswith('SUBSTRATE_SANDBOX='):
                sb_cfg = ln.split('=', 1)[1].strip().strip('"\'')
    # Resolve the backend + its HONEST capabilities (srt = network+fs+allowlist;
    # bwrap/seatbelt = network containment only) so go-live never overclaims.
    det = ROOT / 'scripts' / 'sandbox_detect.py'
    sbx = ROOT / 'scripts' / 'sandbox_exec.sh'
    sb_backend, sb_caps, sb_avail, sb_warns = 'none', {}, False, []
    if det.exists():
        try:
            import json as _json
            import subprocess as _sp
            import sys as _sys
            p = _sp.run([_sys.executable, '-I', str(det), '--root', str(ROOT), '--json'],
                        capture_output=True, text=True, timeout=20)
            d = _json.loads(p.stdout)
            sb_backend, sb_caps = d.get('backend', 'none'), d.get('capabilities', {})
            sb_avail, sb_warns = bool(d.get('available')), d.get('warnings', [])
        except Exception:
            sb_avail = sbx.exists() and run(['bash', str(sbx), '--available'])[0] == 0
    _cap = ('network+fs+egress-allowlist' if sb_caps.get('egress_allowlist')
            else 'network containment only' if sb_caps.get('network') else 'no containment')
    # CONSUME the detector's warnings (v3.5.1 audit fix): a backend that can't
    # deliver the requested policy (e.g. allowlist/fs-scope on seatbelt) must
    # DEGRADE pass->warn — go-live never claims more containment than the backend gives.
    if sb_cfg == '1' and sb_avail and not sb_warns:
        sb_status, sb_reason = 'pass', f'backend={sb_backend} ({_cap})'
    elif sb_cfg == '1' and sb_avail:
        sb_status, sb_reason = 'warn', f'backend={sb_backend} ({_cap}); policy not fully enforceable here: {"; ".join(sb_warns)}'
    elif sb_cfg == '1':
        sb_status, sb_reason = 'warn', 'SUBSTRATE_SANDBOX=1 but no backend available (install @anthropic-ai/sandbox-runtime, or bubblewrap on Linux / sandbox-exec on macOS)'
    else:
        sb_status, sb_reason = 'warn', f'not enabled — set SUBSTRATE_SANDBOX=1 to contain egress (resolved backend={sb_backend}); else exfil stays a tripwire'
    # Each row carries a `tier` (local|remote|deep) so go-live reads as a MAP across
    # the scaling model, not a flat pass/fail. LOCAL is offline-complete; REMOTE
    # unlocks when a GitHub remote exists; DEEP rungs are optional/on-demand. v3.6.0.
    checks = [{'id': 'validators', 'tier': 'local', 'status': 'pass' if repo_ok else 'fail',
               'reason': '' if repo_ok else f'{len(blocks)} repo-local blocker(s)'}]
    if eval_ok is not None:
        checks.append({'id': 'evals', 'tier': 'local', 'status': 'pass' if eval_ok else 'fail',
                       'reason': '' if eval_ok else 'fast eval suite failed'})
    checks.append({'id': 'sandbox', 'tier': 'local', 'status': sb_status, 'reason': sb_reason})
    checks.append({'id': 'memory_anchor', 'tier': 'local', 'status': mem_status, 'reason': mem_reason})
    # Release trust anchor (v3.7.13, installer/upgrade Phase 1a): the minisign public key
    # is what makes a release artifact's authenticity VERIFIABLE before an upgrade is
    # applied (scripts/verify_release.py, or `minisign -Vm`). Offline-honest: report
    # whether the anchor is present — pass if so, warn if absent (upgrades unverifiable).
    _pub = ROOT / '.substrate' / 'trust' / 'minisign.pub'
    if _pub.is_file():
        rs_status, rs_reason = 'pass', 'minisign trust anchor present — release artifacts are verifiable (./manage.sh verify-release <zip>)'
    else:
        rs_status, rs_reason = 'warn', 'no .substrate/trust/minisign.pub — release/upgrade authenticity cannot be verified'
    checks.append({'id': 'release_signature', 'tier': 'local', 'status': rs_status, 'reason': rs_reason})
    # Install provenance / upgrade baseline (v3.7.14, Phase 1b): .substrate/install.json records
    # the kit version this repo was installed/upgraded from + a drift baseline for `manage.sh
    # upgrade`. Offline-honest: present → pass (with version), absent → warn (upgrade needs --force).
    _ij = ROOT / '.substrate' / 'install.json'
    if _ij.is_file():
        try:
            _ijv = json.loads(_safe_read_text(_ij, ROOT, max_bytes=8 << 20) or '{}').get('kit_version', '?')
        except Exception:
            _ijv = '?'
        ip_status, ip_reason = 'pass', f'installed from kit {_ijv}; `./manage.sh upgrade --from <signed-zip> --plan` to preview an upgrade'
    else:
        ip_status, ip_reason = 'warn', 'no .substrate/install.json — provenance/drift baseline absent (pre-1b install); upgrades need --force'
    checks.append({'id': 'install_provenance', 'tier': 'local', 'status': ip_status, 'reason': ip_reason})
    # --- remote expansion ---
    checks.append({'id': 'remote_connected', 'tier': 'remote',
                   'status': 'pass' if (has_remote and provider == 'github') else 'warn',
                   'reason': f'github remote present (provider={provider})' if (has_remote and provider == 'github')
                             else (f'remote present but provider={provider} (remote governance targets GitHub)' if has_remote
                                   else 'no git remote — add a GitHub remote to unlock remote governance')})
    if remote_gov and tb:
        rg_status, rg_reason = 'pass', 'enabled (SUBSTRATE_REMOTE_GOVERNANCE=1); trusted-base workflow present'
    elif remote_gov:
        rg_status, rg_reason = 'warn', 'enabled but trusted-base workflow missing — re-run bootstrap --profile strict+remote (or `enable remote`)'
    else:
        rg_status, rg_reason = 'warn', 'not enabled — run `./manage.sh enable remote --plan`'
    checks.append({'id': 'remote_governance', 'tier': 'remote', 'status': rg_status, 'reason': rg_reason})
    checks.append({'id': 'github_governance', 'tier': 'remote', 'status': 'warn',
                   'reason': 'live branch protection not verifiable offline; run `./manage.sh enable remote --check` (needs an admin-readable token in CI)'})
    # --- deep options (optional rungs; never block hardening) ---
    _dc = _dep_cooldown_days()
    # 'warn' not 'pass' when enabled: go-live is OFFLINE and does NOT run the networked
    # cooldown check, so it cannot claim the deps actually passed (v3.7.4 audit P2 — no overclaim).
    checks.append({'id': 'dep_cooldown', 'tier': 'deep',
                   'status': 'warn' if _dc > 0 else 'available',
                   'reason': (f'enabled ({_dc}d) — runs in `manage.sh check` (networked), not by offline go-live'
                              if _dc > 0 else
                              'not enabled — set SUBSTRATE_DEP_COOLDOWN=N to flag direct deps published < N days ago')})
    # Security-scanner tier (v3.7.17): composed gitleaks/trivy/osv, opt-in + skip-honest.
    # Offline go-live reports the flag + which scanner binaries are present, but (like
    # dep_cooldown) does NOT run the networked scan, so 'warn' not 'pass' when enabled.
    _ss_cfg = "0"
    _cfgp = ROOT / '.substrate' / 'config'
    if _cfgp.is_file():
        for _ln in (_safe_read_text(_cfgp, ROOT, max_bytes=1 << 20) or '').splitlines():
            _ln = _ln.split('#', 1)[0].strip()
            if _ln.startswith('SUBSTRATE_SECURITY_SCANNERS='):
                _ss_cfg = _ln.split('=', 1)[1].strip().strip('"\'')
    _present = [b for b in ('gitleaks', 'trivy', 'osv-scanner') if shutil.which(b)]
    if _ss_cfg == '1':
        _ss_reason = (f"enabled — runs in `manage.sh check` (networked), not by offline go-live; "
                      f"installed: {', '.join(_present) if _present else 'none (all skip-honest)'}")
        checks.append({'id': 'security_scanners', 'tier': 'deep', 'status': 'warn', 'reason': _ss_reason})
    else:
        checks.append({'id': 'security_scanners', 'tier': 'deep', 'status': 'available',
                       'reason': 'not enabled — `./manage.sh enable security` composes gitleaks/trivy/osv-scanner'})
    checks.append({'id': 'deep_audit', 'tier': 'deep', 'status': 'available',
                   'reason': 'DeepSec/AgentDojo deep audit available as a manual/scheduled tier'})
    # Distribution ladder (v3.7.18): the release/signing posture + the consume-side auto-upgrade
    # rung. Informational map (never blocks) — the "scale by one command" pathway made visible.
    # Consumers verify ANY tier out of the box via scripts/verify_release.py (multi-backend).
    _rb = "local"
    if _cfgp.is_file():
        for _ln in (_safe_read_text(_cfgp, ROOT, max_bytes=1 << 20) or '').splitlines():
            _ln = _ln.split('#', 1)[0].strip()
            if _ln.startswith('SUBSTRATE_RELEASE_BACKEND='):
                _rb = _ln.split('=', 1)[1].strip().strip('"\'')
    _rb_next = {
        "local": "next rung: `./manage.sh enable release ci` (CI minisign) or `keyless` (Sigstore, no stored key)",
        "ci-minisign": "next rung: `./manage.sh enable release keyless` — zero key custody (Sigstore/OIDC)",
        "keyless": "top rung — keyless Sigstore signing, no key stored",
    }.get(_rb, "")
    checks.append({'id': 'release_backend', 'tier': 'remote',
                   'status': 'pass' if _rb == 'keyless' else 'available',
                   'reason': f'signing posture: {_rb}. {_rb_next}'})
    _au = (ROOT / '.github' / 'workflows' / 'substrate-auto-upgrade.yml').is_file()
    checks.append({'id': 'auto_upgrade', 'tier': 'remote',
                   'status': 'pass' if _au else 'available',
                   'reason': ('scheduled verify+upgrade-PR workflow installed'
                              if _au else
                              'not enabled — `./manage.sh enable auto-upgrade` for hands-off verified upgrades')})
    repo_pass = repo_ok and eval_ok is not False
    def _st(cid):
        return next((c['status'] for c in checks if c['id'] == cid), None)
    # Production-hardened requires the LOCAL containment tier AND enforced REMOTE
    # governance — and the latter's LIVE state is unverifiable offline, so go-live
    # can NEVER assert hardened from local files alone (anti-overclaim, v3.6.0).
    hardened = (repo_pass and _st('sandbox') == 'pass'
                and _st('remote_governance') == 'pass' and _st('github_governance') == 'pass')
    missing = []
    if _st('sandbox') != 'pass': missing.append('sandbox containment')
    if not remote_gov: missing.append('remote governance')
    missing.append('verified GitHub enforcement')  # never confirmable offline
    ph_reason = '' if hardened else ('cannot confirm offline — ' + ', '.join(missing)
                + ' still required; run `./manage.sh enable remote --check`')
    if not repo_pass: next_hint = 'fix the repo-local blocker(s) above'
    elif not has_remote: next_hint = 'add a GitHub remote, then `./manage.sh enable remote --plan`'
    elif not remote_gov: next_hint = '`./manage.sh enable remote --plan`'
    elif _st('github_governance') != 'pass': next_hint = '`./manage.sh enable remote --check` to verify live GitHub enforcement'
    else: next_hint = 'production-hardened — no further rungs'
    if as_json:
        print(json.dumps({'repo_local': 'pass' if repo_pass else 'fail',
                          'production_hardened': hardened,
                          'production_hardened_reason': ph_reason,
                          'remote': {'has_remote': has_remote, 'provider': provider},
                          'next': next_hint,
                          'checks': checks, 'blockers': blocks}, indent=2))
        return 0 if repo_pass else 1
    print('GO-LIVE REPORT'); print('=' * 48)
    tagmap = {'pass': 'PASS ', 'fail': 'FAIL ', 'warn': 'WARN ', 'available': 'AVAIL'}
    for title, tier in (('Repo-local readiness', 'local'),
                        ('Remote expansion', 'remote'),
                        ('Deep options', 'deep')):
        rows = [c for c in checks if c.get('tier') == tier]
        if not rows: continue
        print('\n' + title)
        for c in rows:
            tag = tagmap.get(c['status'], '?    ')
            print('  ' + tag + ' ' + c['id'] + ('' if not c['reason'] else ' — ' + c['reason']))
    if blocks:
        print('\nrepo-local BLOCKERS:')
        for b in blocks:
            print('  - ' + b)
    print()
    if not repo_pass:
        print('go-live: NOT READY — repo-local checks are failing'); return 1
    print(f'repo_local: pass   production_hardened: {"yes" if hardened else "no (" + ph_reason + ")"}')
    print('next: ' + next_hint)
    if hardened:
        print('\ngo-live: PASS (production-hardened)'); return 0
    print('\ngo-live: PASS (repo-local) / NOT PRODUCTION-HARDENED')
    return 0


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--quick',action='store_true'); ap.add_argument('--security',action='store_true'); ap.add_argument('--operational',action='store_true'); ap.add_argument('--strict',action='store_true'); ap.add_argument('--strict-governance',dest='strict_governance',action='store_true'); ap.add_argument('--go-live',dest='go_live',action='store_true'); ap.add_argument('--json',action='store_true'); a=ap.parse_args()
    # --strict = operational + security + governance (the coherent
    # high-stakes contract). full (no flag) = everything.
    # --strict-governance = the STATIC strict checks ONLY (CODEOWNERS coverage,
    #   placeholders, 3MB, owner syntax, policy integrity) WITHOUT the
    #   operational venv checks — for the trusted-base CI job, which has no
    #   .substrate/venv. It enforces strict governance regardless of profile.
    if a.strict: a.operational=True; a.security=True
    if a.strict_governance: a.security=True
    # --go-live is the FAST readiness MAP, not the gate — it must NOT pull the full
    # doctor chain (integrity subprocesses, operational venv probe, manifest, harness
    # scan) before rendering, or it hangs/times out in a fresh no-venv repo (v3.6.1
    # audit P1). It runs only the cheap base checks (required files + hook wiring),
    # then _go_live adds fast evals + offline remote/sandbox detection. The real gate
    # stays `manage.sh check` / `doctor --strict`.
    full=not (a.quick or a.security or a.operational or a.strict or a.strict_governance or a.go_live)
    blocks=[]; warns=[]
    for r in REQ:
        if not (ROOT/r).exists(): blocks.append(f'missing required file: {r}')
    for r in WARN:
        if not (ROOT/r).exists(): warns.append(f'optional/recommended file missing: {r}')
    if (ROOT/'CLAUDE.md').exists() and '@AGENTS.md' not in (_safe_read_text(ROOT/'CLAUDE.md', ROOT, max_bytes=8 << 20) or ''): blocks.append('CLAUDE.md does not import AGENTS.md')
    cfg=_settings()
    if not _hooks_wired(cfg): blocks.append('.claude/settings.json missing lifecycle hooks (PreToolUse/PreCompact/SessionStart/PostToolUse)')
    if a.security or full:
        hb,hw=_hook_findings(cfg); blocks+=hb; warns+=hw
        co=_codeowners_warn()
        # CODEOWNERS coverage is REMOTE governance (a GitHub feature), so v3.6.0
        # gates it on the remote tier — NOT the strict profile. A strict-LOCAL repo
        # (no remote) is no longer told it is "broken" for lacking CODEOWNERS. The
        # explicit high-stakes flags (`--strict`, `--strict-governance`) still enforce
        # it (the CI trusted-base job + on-demand audit), and config
        # SUBSTRATE_REMOTE_GOVERNANCE=1 turns it on for `manage.sh check`.
        strict_gov = (_remote_governance()=='1' or a.strict or a.strict_governance)
        # Remote-governance AUTHORITY completeness (v3.6.1 audit P1): the tier is
        # "CODEOWNERS coverage + trusted-base authority". If remote governance is
        # enabled (flag) or LOCKED (.substrate/required_remote_governance=1) but the
        # trusted-base workflow is ABSENT, the repo claims an authority tier it does
        # not actually have — a false-green. The gate must BLOCK (go-live only warns).
        if (_remote_governance()=='1' or _required_remote_governance()=='1') and \
                not (ROOT/'.github'/'workflows'/'trusted-base-audit.yml').exists():
            blocks.append('SUBSTRATE_REMOTE_GOVERNANCE=1 but .github/workflows/trusted-base-audit.yml '
                          'is missing — remote governance has no trusted-base authority '
                          '(run `./manage.sh enable remote --write`, or re-bootstrap with --profile strict+remote)')
        if co:
            # remote-governance tier OR --strict mode requires an ACTIVE CODEOWNERS.
            (blocks if strict_gov else warns).append(co)
        # An ACTIVE CODEOWNERS full of placeholder owners is a false-green:
        # GitHub assigns no owner for nonexistent teams.
        ph=_codeowners_placeholder_owners()
        if ph:
            msg=f'CODEOWNERS has placeholder owners GitHub will ignore: {", ".join(ph[:5])}'
            (blocks if strict_gov else warns).append(msg)
        # GitHub will not load a CODEOWNERS file over 3 MB — owners go
        # unrequested. A large file is a governance false-green.
        if _codeowners_too_large():
            (blocks if strict_gov else warns).append('CODEOWNERS exceeds GitHub 3 MB load limit (file would not be honored)')
        # Strict requires real-owner COVERAGE of the ACTUAL privileged files,
        # not merely "a non-placeholder file exists".
        if strict_gov and _codeowners_active():
            gaps=_codeowners_coverage_gaps()
            if gaps:
                blocks.append(f'CODEOWNERS leaves {len(gaps)} privileged file(s) unowned: {", ".join(gaps[:6])}'+(' …' if len(gaps)>6 else ''))
        warns+=_config_tool_warns()
        if not _codex_hooks_use_canonical_flag(): warns.append('.codex/config.toml uses deprecated codex_hooks flag (use `hooks = true`)')
        # Safety-policy integrity: governed Python must compile (a broken
        # security hook fails-open as rc1, not blocking rc2), and the
        # harness pattern DATA must be intact (weakening it disables the
        # harness AND the config command check at once).
        for script,msg in [('scripts/check_import_shadowing.py','a repo-local file shadows a stdlib module (can subvert the hash validators)'),
                           ('scripts/check_python_syntax.py','governed Python failed to compile (a broken security hook would fail-open, not block)'),
                           ('scripts/check_harness_patterns.py','harness safety-policy data invalid or weakened'),
                           ('scripts/check_policy_code_integrity.py','policy/scanner logic altered/redefined (AST pin mismatch)'),
                           ('scripts/check_harness_smoke.py','agent-harness scanner does not block injected context (stubbed?)'),
                           ('scripts/check_hook_smoke.py','a security hook is not enforcing (compile-clean but neutered)')]:
            if (ROOT/script).exists():
                rc,out=run([sys.executable,'-I',script])  # isolated: no repo-local stdlib shadow
                if rc: blocks.append(msg); warns.append(out)
    if a.operational or full:
        ob,ow=_operational_findings(); blocks+=ob; warns+=ow
    if full:
        for cmd,msg in [([sys.executable,'scripts/update_manifest.py','--check'],'manifest stale'),([sys.executable,'scripts/check_agent_harness.py'],'agent harness failed')]:
            rc,out=run(cmd)
            if rc: blocks.append(msg); warns.append(out)
    if a.go_live:
        return _go_live(blocks, warns, as_json=a.json)
    if blocks:
        print('substrate-doctor: BLOCK'); [print('  - '+b) for b in blocks]
        if warns: print('\nwarnings/details:'); [print('  - '+w) for w in warns if w]
        return 1
    if warns:
        print('substrate-doctor: PASS with warnings'); [print('  - '+w) for w in warns if w]
    else: print('substrate-doctor: PASS')
    return 0
if __name__=='__main__': sys.exit(main())
