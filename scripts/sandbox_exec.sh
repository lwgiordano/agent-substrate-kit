#!/usr/bin/env bash
# Compose an OS sandbox BACKEND to CONTAIN egress/filesystem (not merely detect it).
#
# The exfil guard (command_policy) is a TRIPWIRE — pattern matching a determined
# attacker can mutate around. This wrapper is CONTAINMENT: it runs the command
# under a real OS sandbox. We do NOT hand-roll isolation (the one wheel never to
# reinvent) — we select a backend (resolved by scripts/sandbox_detect.py from
# .substrate/sandbox.json):
#   anthropic-srt : @anthropic-ai/sandbox-runtime `srt` — whole-process, network
#                   deny+allowlist, filesystem write-scope (needs Node/npm; used
#                   ONLY if already present — never a forced dependency)
#   bubblewrap    : Linux bwrap, private unconnected netns (NETWORK containment)
#   seatbelt      : macOS sandbox-exec (deny network*)   (NETWORK containment)
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

# Resolve the backend via the (validated, fail-closed) detector. A non-zero exit
# means "no usable backend" (3) or "invalid sandbox.json" (2) — both fail closed.
_resolve_backend() {
  "$_PY" -I "$_ROOT/scripts/sandbox_detect.py" --root "$_ROOT" --backend
}

if [ "${1:-}" = "--available" ]; then
  if backend="$(_resolve_backend)"; then
    echo "sandbox-exec: available (backend=$backend, $(uname -s))"; exit 0
  else
    rc=$?
    echo "sandbox-exec: NO usable sandbox backend on $(uname -s) (rc=$rc)" >&2; exit 3
  fi
fi
[ "$#" -ge 1 ] || { echo "usage: $0 <command> [args...] | --available" >&2; exit 2; }

# Fail closed if the detector rejects the config (exit 2) or finds no backend (exit 3).
if ! backend="$(_resolve_backend)"; then
  rc=$?
  echo "sandbox-exec: refusing to run — no usable sandbox backend / invalid policy (rc=$rc)" >&2
  exit 3
fi

case "$backend" in
  anthropic-srt)
    command -v srt >/dev/null 2>&1 || {
      echo "sandbox-exec: backend anthropic-srt resolved but \`srt\` not on PATH — refusing" >&2; exit 3; }
    _srt_settings="$(mktemp)"; trap 'rm -f "$_srt_settings"' EXIT
    "$_PY" -I "$_ROOT/scripts/sandbox_detect.py" --root "$_ROOT" --emit-srt-settings "$_srt_settings"
    exec srt --settings "$_srt_settings" "$@"
    ;;
  bubblewrap)
    command -v bwrap >/dev/null 2>&1 || {
      echo "sandbox-exec: bubblewrap (bwrap) not found — refusing to run unsandboxed" >&2; exit 3; }
    # --unshare-net: private network namespace, no connectivity (default-deny egress).
    # --dev-bind / / keeps the filesystem (this backend contains NETWORK; fine-grained
    # fs write-scope is an anthropic-srt-only capability today — reported by go-live).
    exec bwrap --unshare-net --dev-bind / / "$@"
    ;;
  seatbelt)
    command -v sandbox-exec >/dev/null 2>&1 || {
      echo "sandbox-exec: macOS sandbox-exec not found — refusing to run unsandboxed" >&2; exit 3; }
    exec sandbox-exec -p "$_MAC_PROFILE" "$@"
    ;;
  *)
    echo "sandbox-exec: no usable backend ($backend) — refusing to run unsandboxed" >&2
    exit 3
    ;;
esac
