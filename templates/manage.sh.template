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
      *) echo "usage: ./manage.sh enable remote [--plan|--write|--check]" >&2; exit 2 ;;
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
    run_lang "lint" "$LINT_CMD"
    run_lang "typecheck" "$TYPECHECK_CMD"
    run_lang "test" "$TEST_CMD"
    subtool pre-commit run --all-files --show-diff-on-failure ;;
  evals) run_py scripts/run_substrate_evals.py "$@" ;;
  audit) run_py scripts/substrate_audit.py --mode quick --write-report ;;
  full-audit) run_py scripts/substrate_audit.py --mode full --write-report ;;
  release|release-gate) bash scripts/release_gate.sh ;;
  manifest) run_py scripts/update_manifest.py --fix ;;
  agent-system-audit) bash scripts/agent_system_audit.sh ;;
  handoff) run_py scripts/session_handoff.py capture ;;
  memory) run_py scripts/memory_log.py "$@" ;;
  design-init) mkdir -p design-system/pages design-system/tokens; echo "design-system/ scaffolded" ;;
  *) cat <<'HELP'
Usage: ./manage.sh setup|doctor|go-live|context-report|code-shape|verify-release|upgrade|enable|check|evals|audit|full-audit|release|manifest|agent-system-audit|handoff|memory|design-init
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
