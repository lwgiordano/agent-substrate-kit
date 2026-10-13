#!/usr/bin/env bash
# Language-native gate adapter with graceful skips.
#
# Usage: scripts/lang_gate.sh <lint|typecheck|test>
#
# Reads SUBSTRATE_LANG from .substrate/config. Each gate detects whether
# the repo has actually opted into it (a package script, a config file,
# at least one Go package) and SKIPS with a clear message otherwise —
# so a fresh/empty repo never fails a gate it never opted into. `strict`
# profile can be made to require gates by editing .substrate/config.
set -euo pipefail
SUBSTRATE_LANG="none"
. scripts/_substrate_config.sh; load_substrate_config || { echo "substrate-config: refusing to run with invalid .substrate/config" >&2; exit 2; }
gate="${1:?usage: lang_gate.sh <lint|typecheck|test>}"

skip(){ echo "lang-gate: $gate skipped ($1)"; exit 0; }

# Route the native gate command through the sandbox when containment is enabled
# (v3.5.2): lint/test execution runs PROJECT code, so it is the path that must be
# contained. SUBSTRATE_SANDBOX comes from the config loaded above; if a backend is
# required but unavailable, sandbox_exec.sh fails closed (exit 3).
_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
maybe_sandbox(){ if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ]; then "$_SCRIPTS_DIR/sandbox_exec.sh" "$@"; else "$@"; fi; }

npm_script(){ # has a given npm script?
  [ -f package.json ] || return 1
  node -e "process.exit(((require('./package.json').scripts||{})['$1'])?0:1)" 2>/dev/null
}

case "$SUBSTRATE_LANG" in
  node)
    case "$gate" in
      lint)      npm_script lint      && maybe_sandbox npm run lint      || skip "no 'lint' npm script" ;;
      typecheck) npm_script typecheck && maybe_sandbox npm run typecheck || skip "no 'typecheck' npm script" ;;
      test)      npm_script test      && maybe_sandbox npm test          || skip "no 'test' npm script" ;;
    esac ;;
  go)
    command -v go >/dev/null 2>&1 || skip "go not installed"
    pkgs="$(go list ./... 2>/dev/null || true)"
    case "$gate" in
      lint)      out="$(gofmt -l . 2>/dev/null || true)"; [ -z "$out" ] && echo "gofmt: clean" || { echo "gofmt: needs formatting:"; echo "$out"; exit 1; } ;;
      typecheck) [ -n "$pkgs" ] && maybe_sandbox go vet ./...  || skip "no go packages" ;;
      test)      [ -n "$pkgs" ] && maybe_sandbox go test ./... || skip "no go packages" ;;
    esac ;;
  *) skip "no language-native $gate for lang=$SUBSTRATE_LANG" ;;
esac
