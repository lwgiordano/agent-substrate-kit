#!/usr/bin/env bash
# Language-native gate adapter with graceful skips.
#
# Usage: scripts/lang_gate.sh <lint|typecheck|test>
#
# Reads SUBSTRATE_LANG from .substrate/config. Each gate detects whether
# the repo has actually opted into it (a package script, a config file,
# at least one Go source file) and SKIPS with a clear message otherwise —
# so a fresh/empty repo never fails a gate it never opted into. `strict`
# profile can be made to require gates by editing .substrate/config.
#
# Once a gate applies, ITS EXIT STATUS IS THE GATE'S. A skip is only ever "this
# repo has nothing for this gate"; a failing lint/test, a toolchain that is
# missing although the repo needs it, and a package.json that cannot be read
# all fail. (v3.10.5: `probe && run || skip` turned a failing `npm test` or
# `go test` into "skipped" with exit 0, and a broken Go package into "no go
# packages".)
set -euo pipefail
SUBSTRATE_LANG="none"
. scripts/_substrate_config.sh; load_substrate_config || { echo "substrate-config: refusing to run with invalid .substrate/config" >&2; exit 2; }
gate="${1:?usage: lang_gate.sh <lint|typecheck|test>}"
case "$gate" in
  lint|typecheck|test) ;;
  *) echo "lang-gate: unknown gate '$gate' (want lint, typecheck or test)" >&2; exit 2;;
esac

skip(){ echo "lang-gate: $gate skipped ($1)"; exit 0; }
fail(){ echo "lang-gate: $gate FAILED: $1" >&2; exit 1; }

# Route the native gate command through the sandbox when containment is enabled
# (v3.5.2): lint/test execution runs PROJECT code, so it is the path that must be
# contained. SUBSTRATE_SANDBOX comes from the config loaded above; if a backend is
# required but unavailable, sandbox_exec.sh fails closed (exit 3).
_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
maybe_sandbox(){ if [ "${SUBSTRATE_SANDBOX:-0}" = "1" ]; then "$_SCRIPTS_DIR/sandbox_exec.sh" "$@"; else "$@"; fi; }
# Run the gate's command and exit with its status.
run_gate(){
  local rc=0
  maybe_sandbox "$@" || rc=$?
  [ "$rc" -eq 0 ] || echo "lang-gate: $gate failed (exit $rc): $*" >&2
  exit "$rc"
}

# 0 = the npm script is defined, 1 = it is not, 2 = cannot tell (node missing or
# package.json unreadable). Only 1 may skip.
npm_script(){
  [ -f package.json ] || return 1
  command -v node >/dev/null 2>&1 || return 2
  node -e 'let s;try{s=require(process.cwd()+"/package.json").scripts||{}}catch(e){process.exit(2)}
process.exit(Object.prototype.hasOwnProperty.call(s,process.argv[1])&&s[process.argv[1]]?0:1)' "$1" 2>/dev/null
}

# Go source files the go tool builds: vendor/, testdata/, node_modules/ and
# directories starting with '.' or '_' are ignored, as `go list ./...` ignores them.
go_files(){
  find . -type d \( -name vendor -o -name testdata -o -name node_modules -o -name '.?*' -o -name '_*' \) -prune \
    -o -type f -name '*.go' -print0
}

case "$SUBSTRATE_LANG" in
  node)
    case "$gate" in
      lint)      script=lint;      cmd=(npm run lint) ;;
      typecheck) script=typecheck; cmd=(npm run typecheck) ;;
      test)      script=test;      cmd=(npm test) ;;
    esac
    probe=0; npm_script "$script" || probe=$?
    case "$probe" in
      0) run_gate "${cmd[@]}" ;;
      1) skip "no '$script' npm script" ;;
      *) fail "package.json is present but its scripts cannot be read (is node installed and package.json valid JSON?)" ;;
    esac ;;
  go)
    [ "$(go_files | head -c 1 | wc -c | tr -d " ")" -gt 0 ] || skip "no Go source files"
    command -v go >/dev/null 2>&1 || fail "Go source files are present but go is not installed"
    case "$gate" in
      lint)
        out=""; rc=0
        out="$(go_files | xargs -0 gofmt -l 2>&1)" || rc=$?
        [ "$rc" -eq 0 ] || { echo "gofmt: failed (exit $rc):"; printf '%s\n' "$out"; exit 1; }
        [ -z "$out" ] || { echo "gofmt: needs formatting:"; printf '%s\n' "$out"; exit 1; }
        echo "gofmt: clean" ;;
      typecheck) run_gate go vet ./... ;;
      test)      run_gate go test ./... ;;
    esac ;;
  *) skip "no language-native $gate for lang=$SUBSTRATE_LANG" ;;
esac
