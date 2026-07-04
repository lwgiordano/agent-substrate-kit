#!/usr/bin/env bash
set -euo pipefail
cmd="${1:-help}"; shift || true

# --- substrate config (written by bootstrap.sh; polyglot indirection) ---
SUBSTRATE_PROFILE="standard"; SUBSTRATE_LANG="python"
LINT_CMD=""; TYPECHECK_CMD=""; TEST_CMD=""
. scripts/_substrate_config.sh; load_substrate_config || { echo "substrate-config: refusing to run with invalid .substrate/config" >&2; exit 2; }

# The substrate's validators + pre-commit ALWAYS run from a dedicated
# Python venv, regardless of the project language. This is what makes
# `setup`/`check` work in node/go/none repos (they have no Python deps
# of their own). Project-language toolchains are separate (uv/.venv for
# python; npm/go for the others).
SUBVENV=".substrate/venv"
SUBPY="$SUBVENV/bin/python"
have_uv=false; [ "$SUBSTRATE_LANG" = python ] && command -v uv >/dev/null 2>&1 && [ -f pyproject.toml ] && have_uv=true

# Run a substrate VALIDATOR script (always via the substrate venv if it
# exists; else uv for python projects; else system python3). ALWAYS with
# `-I` (isolated): the repo's scripts/ dir is not auto-prepended to sys.path,
# so a repo-local stdlib shadow (scripts/hashlib.py etc) cannot hijack a
# validator's imports and defeat the hash pins. check_import_shadowing.py
# (run first) is the belt to this `-I` suspenders.
run_py(){ if [ -x "$SUBPY" ]; then "$SUBPY" -I "$@"; elif $have_uv; then uv run python -I "$@"; else python3 -I "$@"; fi; }
# Side-effect-light runner: substrate venv if present, else system python3 — NO
# `uv run` fallback, so read-only inspection commands (doctor, go-live, context-report)
# never create a project .venv or print installer noise (v3.3.13 reviewer). NOTE: `-I`
# (isolated) ignores PYTHON* env vars, so PYTHONDONTWRITEBYTECODE here would be a no-op —
# the no-__pycache__ guarantee is set IN-SCRIPT via sys.dont_write_bytecode (context_report.py).
run_py_system(){ if [ -x "$SUBPY" ]; then "$SUBPY" -I "$@"; else python3 -I "$@"; fi; }
# Run a substrate TOOL (pre-commit). Always the substrate venv.
subtool(){ local t="$1"; shift || true; if [ -x "$SUBVENV/bin/$t" ]; then "$SUBVENV/bin/$t" "$@"; elif $have_uv; then uv run "$t" "$@"; else "$t" "$@"; fi; }
# Route configured LINT_CMD/TYPECHECK_CMD/TEST_CMD through the sandbox when the tier
# is enabled (v3.5.3): these are executable PROJECT code, so containment must cover
# them too — fail-closed (exit 3) if a required backend is absent.
run_lang(){ local label="$1" cmd="$2"; [ -z "$cmd" ] && return 0; echo "==> $label: $cmd"
  if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ]; then scripts/sandbox_exec.sh bash -c "$cmd"; else bash -c "$cmd"; fi; }

setup(){
  # 1. Substrate validator venv (all languages). pytest is included for
  #    every language because the kit ships its own tests/ to every repo;
  #    full-audit must run them from the substrate venv, never ambient.
  [ -x "$SUBPY" ] || { echo "==> Creating substrate venv ($SUBVENV)"; python3 -m venv "$SUBVENV"; "$SUBPY" -m pip install --quiet --upgrade pip; }
  # Self-healing: a partial/interrupted install can leave the venv python
  # present but pre-commit/PyYAML/pytest missing. Verify and (re)install so
  # `setup` is idempotent and repairs a half-initialized environment
  # instead of failing later at pre-commit install.
  need_repair=no
  # cryptography is required by scripts/_minisign.py (release/upgrade signature
  # verification, v3.7.13); include it so the trust check is actually runnable.
  "$SUBPY" -c 'import yaml, pytest, pre_commit, cryptography' >/dev/null 2>&1 || need_repair=yes
  [ -x "$SUBVENV/bin/pre-commit" ] || need_repair=yes
  if [ "$need_repair" = yes ]; then
    echo "==> Installing/repairing substrate tools"
    "$SUBPY" -m pip install --quiet --upgrade pre-commit PyYAML pytest cryptography
    # If the import is fine but the console script is missing (e.g. a
    # truncated install), force-recreate it.
    [ -x "$SUBVENV/bin/pre-commit" ] || "$SUBPY" -m pip install --quiet --force-reinstall --no-deps pre-commit
  fi
  # 2. Python projects: install project + dev toolchain too. --all-extras covers BOTH
  #    dev-declaration styles (optional-dependencies + PEP 735 dependency-groups); the
  #    old `--group dev` silently installed nothing for optional-dependencies (trial #1).
  if [ "$SUBSTRATE_LANG" = python ]; then
    if command -v uv >/dev/null 2>&1; then uv sync --all-extras || true
    else "$SUBPY" -m pip install --quiet pytest pytest-cov pytest-randomly pytest-rerunfailures hypothesis ruff mypy bandit pip-audit types-PyYAML cryptography; fi
  fi
  subtool pre-commit install
  if [ "$SUBSTRATE_PROFILE" = "strict" ]; then subtool pre-commit install --hook-type commit-msg; fi
  run_py scripts/update_manifest.py --fix
  # Operational (not full) doctor: setup proves "can it run", not
  # governance. Strict CODEOWNERS is enforced by `doctor --strict` / CI,
  # so setup never blocks on a not-yet-activated CODEOWNERS.
  run_py scripts/substrate_doctor.py --operational
}
# enable_remote: turn ON the remote-governance tier (v3.6.0). Orthogonal to the
# governance profile — decoupled from strict. --plan (default) prints what it does
# with NO mutation; --write makes the LOCAL config edits (no network, no GitHub
# mutation); --check delegates the LIVE GitHub enforcement check to the operator helper.
enable_remote(){
  local mode="${1:---plan}"
  case "$mode" in
    --check) exec bash scripts/setup_branch_protection.sh --check ;;
    --plan)
      cat <<'PLAN'
`enable remote` turns on the REMOTE-GOVERNANCE tier (decoupled from the strict profile):
  - sets SUBSTRATE_REMOTE_GOVERNANCE="1" in .substrate/config
  - writes .substrate/required_remote_governance=1 (frozen minimum; a PR may not disable it)
  - CODEOWNERS coverage + trusted-base authority become REQUIRED in `check`

It does NOT configure GitHub branch protection (that stays an explicit operator action):
  - ensure a GitHub remote exists and a real-owner .github/CODEOWNERS covers scripts/, workflows, .substrate/required_*
  - the trusted-base workflow ships with `bootstrap --profile *+remote`; if .github/workflows/trusted-base-audit.yml is absent, re-bootstrap with --profile strict+remote
  - then verify live enforcement:  ./manage.sh enable remote --check

Apply the local config changes with:  ./manage.sh enable remote --write
PLAN
      ;;
    --write)
      local cfg=".substrate/config"
      [ -f "$cfg" ] || { echo "no $cfg — run bootstrap first" >&2; exit 2; }
      if grep -q '^SUBSTRATE_REMOTE_GOVERNANCE=' "$cfg"; then
        local tmp; tmp="$(mktemp)"
        awk '/^SUBSTRATE_REMOTE_GOVERNANCE=/{print "SUBSTRATE_REMOTE_GOVERNANCE=\"1\""; next}{print}' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
      else
        printf 'SUBSTRATE_REMOTE_GOVERNANCE="1"\n' >> "$cfg"
      fi
      echo "1" > .substrate/required_remote_governance
      # Install the trusted-base workflow if absent — the tier requires it and `check`
      # now BLOCKS without it (v3.6.1). Render from a staged template; if none is
      # findable, say so plainly (the gate will refuse until it is restored).
      local wf=".github/workflows/trusted-base-audit.yml" tpl=""
      if [ ! -f "$wf" ]; then
        for cand in ".substrate/trusted-base-audit.yml.template" "workflows/trusted-base-audit.yml.template"; do
          [ -f "$cand" ] && { tpl="$cand"; break; }
        done
        if [ -n "$tpl" ]; then mkdir -p .github/workflows && cp "$tpl" "$wf"; echo "installed $wf (from $tpl)"
        else echo "WARNING: $wf is missing and no template was found — \`check\` will BLOCK until you restore it (re-bootstrap with --profile strict+remote)." >&2; fi
      fi
      echo "remote governance ENABLED (SUBSTRATE_REMOTE_GOVERNANCE=1, required_remote_governance=1)."
      echo "next: ensure a real .github/CODEOWNERS covers privileged files, then ./manage.sh enable remote --check"
      ;;
    *) echo "usage: ./manage.sh enable remote [--plan|--write|--check]" >&2; exit 2 ;;
  esac
}
enable_security(){
  local mode="${1:---plan}"
  case "$mode" in
    --check) exec run_py_system scripts/run_security_scanners.py --scan ;;
    --plan)
      cat <<'PLAN'
`enable security` turns on the DEEP SCANNER tier (composed, opt-in, skip-honest):
  - sets SUBSTRATE_SECURITY_SCANNERS="1" in .substrate/config
  - writes .substrate/required_security_scanners=1 (frozen minimum; a PR may not disable it)
  - `check` then runs scripts/run_security_scanners.py (gitleaks / trivy / osv-scanner)

The substrate is the JUDGE, scanners are INPUTS: a scanner FINDING blocks; a MISSING scanner
is SKIPPED honestly (and, because the tier is required once enabled, a skip BLOCKS — install
the tool or it fails). Networked (trivy/osv vuln DBs) → never part of the offline base.
Install the tools you want first (e.g. `brew install gitleaks trivy osv-scanner`).

Apply the local config changes with:  ./manage.sh enable security --write
Run a scan any time with:             ./manage.sh security scan
PLAN
      ;;
    --write)
      local cfg=".substrate/config"
      [ -f "$cfg" ] || { echo "no $cfg — run bootstrap first" >&2; exit 2; }
      if grep -q '^SUBSTRATE_SECURITY_SCANNERS=' "$cfg"; then
        local tmp; tmp="$(mktemp)"
        awk '/^SUBSTRATE_SECURITY_SCANNERS=/{print "SUBSTRATE_SECURITY_SCANNERS=\"1\""; next}{print}' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
      else
        printf 'SUBSTRATE_SECURITY_SCANNERS="1"\n' >> "$cfg"
      fi
      echo "1" > .substrate/required_security_scanners
      echo "security-scanner tier ENABLED (SUBSTRATE_SECURITY_SCANNERS=1, required_security_scanners=1)."
      echo "next: install gitleaks/trivy/osv-scanner, then ./manage.sh security scan"
      ;;
    *) echo "usage: ./manage.sh enable security [--plan|--write|--check]" >&2; exit 2 ;;
  esac
}
enable_profile(){  # $1=target $2=mode [$3=--force] — in-place RAISE-only profile ratchet
  local target="${1:-}"; shift || true
  local mode="${1:---plan}"; shift || true
  case "$target" in standard|strict) ;; *)
    echo "usage: ./manage.sh enable profile <standard|strict> [--plan|--write|--check] [--force]" >&2; exit 2 ;;
  esac
  case "$mode" in
    --plan)  run_py_system scripts/substrate_profile.py --plan "$target" ;;
    --check) run_py_system scripts/substrate_profile.py --check "$target" ;;
    --write)
      run_py scripts/substrate_profile.py --write "$target" "$@"
      subtool pre-commit install
      if [ "$target" = "strict" ]; then subtool pre-commit install --hook-type commit-msg; fi
      run_py_system scripts/substrate_doctor.py --operational ;;
    *) echo "usage: ./manage.sh enable profile <standard|strict> [--plan|--write|--check] [--force]" >&2; exit 2 ;;
  esac
}
_set_cfg_flag(){  # $1=key $2=value — set-or-append in .substrate/config
  local cfg=".substrate/config"; [ -f "$cfg" ] || { echo "no $cfg — run bootstrap first" >&2; exit 2; }
  if grep -q "^$1=" "$cfg"; then local tmp; tmp="$(mktemp)"
    awk -v k="$1" -v v="$2" '$0 ~ "^"k"=" {print k"=\""v"\""; next} {print}' "$cfg" > "$tmp" && mv "$tmp" "$cfg"
  else printf '%s="%s"\n' "$1" "$2" >> "$cfg"; fi
}
_install_workflow(){  # $1=staged-template-name $2=dest-workflow-filename — activate a dormant template
  local tpl=".substrate/$1" dest=".github/workflows/$2"
  [ -f "$tpl" ] || { echo "staged template $tpl not found — re-bootstrap to stage it" >&2; return 1; }
  mkdir -p .github/workflows && cp "$tpl" "$dest" && echo "installed $dest (from $tpl) — REVIEW before it runs"
}
enable_release(){
  case "${1:---plan}" in
    --plan|"") cat <<'PLAN'
`enable release <tier>` sets the release/signing posture (SUBSTRATE_RELEASE_BACKEND). Consumers
verify ANY tier out of the box (scripts/verify_release.py); go-live maps the ladder + next rung.
  local    — sign on your laptop (package_release + gh release create); key never leaves it (default)
  ci       — tag-triggered CI release, signed with a minisign key in a GH Actions secret
  keyless  — tag-triggered CI release, signed KEYLESS via Sigstore/cosign OIDC (no key stored)
Apply:  ./manage.sh enable release local|ci|keyless
PLAN
      ;;
    local) _set_cfg_flag SUBSTRATE_RELEASE_BACKEND local
      echo "release backend = local (laptop signing; publish: ./package_release.sh --full then gh release create)";;
    ci) _set_cfg_flag SUBSTRATE_RELEASE_BACKEND ci-minisign
      _install_workflow release-ci-minisign.yml.template release.yml
      echo "next: add repo secret SUBSTRATE_RELEASE_SECKEY (your minisign secret key), then push a v* tag";;
    keyless) _set_cfg_flag SUBSTRATE_RELEASE_BACKEND keyless
      _install_workflow release-keyless.yml.template release.yml
      echo "next: add .substrate/trust/sigstore_identity.json (trusted workflow identity + issuer); then push a v* tag";;
    *) echo "usage: ./manage.sh enable release [local|ci|keyless]" >&2; exit 2;;
  esac
}
enable_auto_upgrade(){
  case "${1:---plan}" in
    --plan|"") cat <<'PLAN'
`enable auto-upgrade` installs a SCHEDULED workflow that fetches the latest signed kit release,
VERIFIES it (fail-closed), applies `manage.sh upgrade`, and opens a PR. No key/secret — it only
verifies + proposes; a human/branch-protection merge applies it.
Apply:  ./manage.sh enable auto-upgrade --write   (then set KIT_REPO in the installed workflow)
PLAN
      ;;
    --write) _install_workflow auto-upgrade.yml.template substrate-auto-upgrade.yml
      echo "next: set KIT_REPO in .github/workflows/substrate-auto-upgrade.yml + adjust the cron";;
    *) echo "usage: ./manage.sh enable auto-upgrade [--plan|--write]" >&2; exit 2;;
  esac
}
case "$cmd" in
  setup) setup ;;
  doctor) run_py_system scripts/substrate_doctor.py "$@" ;;
  go-live) run_py_system scripts/substrate_doctor.py --go-live "$@" ;;
  context-report) run_py_system scripts/context_report.py "$@" ;;
  code-shape) run_py_system scripts/code_shape.py "$@" ;;
  verify-release) run_py_system scripts/verify_release.py "$@" ;;
  upgrade) run_py_system scripts/substrate_upgrade.py "$@" ;;
  enable)
    what="${1:-}"; shift || true
    case "$what" in
      remote) enable_remote "${1:---plan}" ;;
      security) enable_security "${1:---plan}" ;;
      release) enable_release "${1:---plan}" ;;
      auto-upgrade) enable_auto_upgrade "${1:---plan}" ;;
      profile) enable_profile "$@" ;;
      *) echo "usage: ./manage.sh enable remote|security|release|auto-upgrade|profile [...]" >&2; exit 2 ;;
    esac ;;
  security)
    what="${1:-scan}"; shift || true
    case "$what" in
      scan) run_py_system scripts/run_security_scanners.py --scan "$@" ;;
      *) echo "usage: ./manage.sh security scan" >&2; exit 2 ;;
    esac ;;
  check)
    # Remote governance (CODEOWNERS coverage + trusted-base authority) is enforced as
    # part of check only when the remote tier is ON (v3.6.0 — decoupled from the strict
    # profile, so a strict-LOCAL repo is not told it is "broken" for lacking a
    # GitHub-only CODEOWNERS). strict profile still gets operational+security checks.
    if [ "${SUBSTRATE_REMOTE_GOVERNANCE:-0}" = "1" ]; then run_py scripts/substrate_doctor.py --strict
    elif [ "$SUBSTRATE_PROFILE" = "strict" ]; then run_py scripts/substrate_doctor.py --operational --security; fi
    run_py scripts/check_import_shadowing.py          # no repo-local stdlib shadow can subvert the hash validators
    run_py scripts/update_manifest.py --check
    run_py scripts/check_doc_drift.py --strict
    run_py scripts/check_python_syntax.py             # a broken security hook must not fail-open (rc1, not blocking rc2)
    run_py scripts/check_harness_patterns.py          # safety-policy data intact (regexes hash-pinned)
    run_py scripts/check_policy_code_integrity.py     # policy + scanner LOGIC intact (AST-pinned: funcs AND helper regexes)
    run_py scripts/check_harness_smoke.py             # the harness scanner actually blocks injected context (multi-family)
    run_py scripts/check_hook_smoke.py                # hooks actually DENY (compile-clean but neutered hook)
    run_py scripts/check_agent_harness.py
    run_py scripts/check_substrate_config.py   # reject dangerous LINT/TEST values before they run
    # Dependency-cooldown tier (v3.7.2): opt-in fresh-version risk signal. Networked +
    # skip-honest; only runs when SUBSTRATE_DEP_COOLDOWN>0, so the base check stays offline.
    if [ "${SUBSTRATE_DEP_COOLDOWN:-0}" != "0" ]; then run_py scripts/check_dep_cooldown.py; fi
    # Security-scanner tier (v3.7.17): opt-in composed gitleaks/trivy/osv. Networked +
    # skip-honest; only runs when SUBSTRATE_SECURITY_SCANNERS=1, so the base check stays offline.
    if [ "${SUBSTRATE_SECURITY_SCANNERS:-0}" = "1" ]; then run_py scripts/run_security_scanners.py; fi
    run_lang "lint" "$LINT_CMD"
    run_lang "typecheck" "$TYPECHECK_CMD"
    run_lang "test" "$TEST_CMD"
    subtool pre-commit run --all-files --show-diff-on-failure ;;
  evals) run_py scripts/run_substrate_evals.py "$@" ;;
  audit) run_py scripts/substrate_audit.py --mode quick --write-report ;;
  full-audit) run_py scripts/substrate_audit.py --mode full --write-report ;;
  release|release-gate)
    case "${1:-}" in
      --setup-key) shift || true; bash scripts/setup_release_key.sh "$@" ;;
      *) bash scripts/release_gate.sh ;;
    esac ;;
  manifest) run_py scripts/update_manifest.py --fix ;;
  agent-system-audit) bash scripts/agent_system_audit.sh ;;
  handoff) run_py scripts/session_handoff.py capture ;;
  memory) run_py scripts/memory_log.py "$@" ;;
  new-validator) run_py scripts/new_validator.py "$@" ;;
  design-init) mkdir -p design-system/pages design-system/tokens; echo "design-system/ scaffolded" ;;
  *) cat <<'HELP'
Usage: ./manage.sh setup|doctor|go-live|context-report|code-shape|verify-release|upgrade|enable|security|check|evals|audit|full-audit|release|manifest|agent-system-audit|handoff|memory|design-init|new-validator
  evals                                       adversarial behavior evals (block-rate / FP-rate, writes a trace)
  doctor [--quick|--security|--operational]   readiness levels
  go-live [--json]                            local/remote/deep readiness map (offline, side-effect-light)
  context-report [--json] [--budget]          token/context footprint: always-loaded vs on-demand, cache prefix; --budget = warn-only token thresholds
  code-shape [--json]                         engineering-shape report (warn-only): large files, long fns, diff size, source-without-tests
  enable remote [--plan|--write|--check]      turn on the remote-governance tier (CODEOWNERS + trusted-base)
  memory [verify|tail|tasks]                  append-only event log
Config: .substrate/config (profile, language, LINT_CMD/TYPECHECK_CMD/TEST_CMD indirection)
Substrate validators + pre-commit run from .substrate/venv (works in any language).
HELP
  ;;
esac
