#!/usr/bin/env bash
# Compose an OS sandbox BACKEND to CONTAIN egress/filesystem (not merely detect it).
#
# The exfil guard (command_policy) is a TRIPWIRE — pattern matching a determined
# attacker can mutate around. This wrapper is CONTAINMENT: it runs the command
# under a real OS sandbox, with a SECRETLESS environment. We do NOT hand-roll
# isolation — we select a backend (resolved by scripts/sandbox_detect.py from
# .substrate/sandbox.json):
#   anthropic-srt : @anthropic-ai/sandbox-runtime `srt` — whole-process, network
#                   deny+allowlist, filesystem write-scope (needs Node/npm; used
#                   ONLY if already present — never a forced dependency)
#   bubblewrap    : Linux bwrap, private unconnected netns (NETWORK containment)
#   seatbelt      : macOS sandbox-exec (deny network*)   (NETWORK containment)
#
# SECRETLESS ENV (v3.5.2): the command runs under `env -i` with only the allow-listed
# vars from .substrate/sandbox.json `env` policy — a network-denied command still
# cannot read tokens/keys from the ambient env and write them into allowed files.
# It is also marked SUBSTRATE_SANDBOXED=1 (lets the agent-Bash guard verify routing).
#
# FAIL CLOSED: if no usable backend is available, REFUSE (exit 3) rather than run
# unsandboxed — asking for containment and silently getting none is the failure
# mode this exists to prevent.
#
# Usage:  scripts/sandbox_exec.sh <command> [args...]
#         scripts/sandbox_exec.sh --available   # probe: 0 if a backend exists, 3 if not
# Exit:   the command's own exit code | 3 no backend | 2 usage.
set -euo pipefail

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
_ROOT="$(cd "$_SCRIPT_DIR/.." && pwd)"
_PY="python3"
[ -x "$_ROOT/.substrate/venv/bin/python" ] && _PY="$_ROOT/.substrate/venv/bin/python"

_MAC_PROFILE='(version 1)(allow default)(deny network*)'

# Resolve the backend via the (validated, fail-closed) detector. Non-zero exit =
# "no usable backend" (3) or "invalid sandbox.json" (2) — both fail closed. We
# capture the REAL rc with `|| rc=$?` (an `if ! cmd` block would record !'s status,
# i.e. 0, in the message — the v3.5.1-audit P2).
_resolve_backend() { "$_PY" -I "$_ROOT/scripts/sandbox_detect.py" --root "$_ROOT" --backend; }

# Build the SECRETLESS env prefix into the global _ENVP array: `env -i` + allow-listed
# vars + the sandbox marker. mode=inherit → no scrub, just mark.
_build_env() {
  _ENVP=()
  local names n v
  names="$("$_PY" -I "$_ROOT/scripts/sandbox_detect.py" --root "$_ROOT" --emit-env-names 2>/dev/null || echo "__INHERIT__")"
  if [ "$names" = "__INHERIT__" ]; then
    _ENVP=(env "SUBSTRATE_SANDBOXED=1")
  else
    _ENVP=(env -i "SUBSTRATE_SANDBOXED=1")
    for n in $names; do
      v="$(printenv "$n" 2>/dev/null || true)"
      _ENVP+=("$n=$v")
    done
  fi
}

if [ "${1:-}" = "--available" ]; then
  rc=0; backend="$(_resolve_backend)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "sandbox-exec: available (backend=$backend, $(uname -s))"; exit 0
  else
    echo "sandbox-exec: NO usable sandbox backend on $(uname -s) (rc=$rc)" >&2; exit 3
  fi
fi
[ "$#" -ge 1 ] || { echo "usage: $0 <command> [args...] | --available" >&2; exit 2; }

rc=0; backend="$(_resolve_backend)" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "sandbox-exec: refusing to run — no usable sandbox backend / invalid policy (rc=$rc)" >&2
  exit 3
fi

_build_env

case "$backend" in
  anthropic-srt)
    command -v srt >/dev/null 2>&1 || {
      echo "sandbox-exec: backend anthropic-srt resolved but \`srt\` not on PATH — refusing" >&2; exit 3; }
    _srt_settings="$(mktemp)"; trap 'rm -f "$_srt_settings"' EXIT
    "$_PY" -I "$_ROOT/scripts/sandbox_detect.py" --root "$_ROOT" --emit-srt-settings "$_srt_settings"
    exec "${_ENVP[@]}" srt --settings "$_srt_settings" "$@"
    ;;
  bubblewrap)
    command -v bwrap >/dev/null 2>&1 || {
      echo "sandbox-exec: bubblewrap (bwrap) not found — refusing to run unsandboxed" >&2; exit 3; }
    # --unshare-net: private network namespace, no connectivity (default-deny egress).
    # --dev-bind / / keeps the filesystem (this backend contains NETWORK; fine-grained
    # fs write-scope is an anthropic-srt-only capability today — reported by go-live).
    exec "${_ENVP[@]}" bwrap --unshare-net --dev-bind / / "$@"
    ;;
  seatbelt)
    command -v sandbox-exec >/dev/null 2>&1 || {
      echo "sandbox-exec: macOS sandbox-exec not found — refusing to run unsandboxed" >&2; exit 3; }
    exec "${_ENVP[@]}" sandbox-exec -p "$_MAC_PROFILE" "$@"
    ;;
  *)
    echo "sandbox-exec: no usable backend ($backend) — refusing to run unsandboxed" >&2
    exit 3
    ;;
esac
