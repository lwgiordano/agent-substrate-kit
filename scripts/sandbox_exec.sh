#!/usr/bin/env bash
# Compose the OS network sandbox to CONTAIN egress (not merely detect it).
#
# The exfil guard (command_policy) is a TRIPWIRE — pattern matching that a
# determined attacker can mutate around. This wrapper is CONTAINMENT: it runs
# the given command with network egress DENIED by the kernel, using the
# OS-provided primitive — we do NOT hand-roll isolation (the one wheel never to
# reinvent):
#   macOS : sandbox-exec (Seatbelt) with a deny-network profile
#   Linux : bubblewrap (bwrap) with a private, unconnected network namespace
#
# FAIL CLOSED: if no OS sandbox is available, REFUSE (exit 3) rather than run the
# command unsandboxed — asking for containment and silently getting none is the
# failure mode this exists to prevent.
#
# Usage:  scripts/sandbox_exec.sh <command> [args...]
#         scripts/sandbox_exec.sh --available   # probe only: 0 if a sandbox exists, 3 if not
# Exit:   the command's own exit code | 3 no sandbox available | 2 usage.
set -euo pipefail

# macOS Seatbelt: allow everything EXCEPT network. (deny network*) blocks
# outbound/inbound sockets at the kernel; everything else (fs, exec) is allowed
# so normal build/test work proceeds — only egress is contained.
_MAC_PROFILE='(version 1)(allow default)(deny network*)'

_have_sandbox() {
  case "$(uname -s)" in
    Darwin) command -v sandbox-exec >/dev/null 2>&1 ;;
    Linux)  command -v bwrap >/dev/null 2>&1 ;;
    *)      return 1 ;;
  esac
}

if [ "${1:-}" = "--available" ]; then
  _have_sandbox && { echo "sandbox-exec: available ($(uname -s))"; exit 0; } \
                || { echo "sandbox-exec: NO OS sandbox on $(uname -s)" >&2; exit 3; }
fi
[ "$#" -ge 1 ] || { echo "usage: $0 <command> [args...] | --available" >&2; exit 2; }

case "$(uname -s)" in
  Darwin)
    command -v sandbox-exec >/dev/null 2>&1 || {
      echo "sandbox-exec: macOS sandbox-exec not found — refusing to run unsandboxed" >&2; exit 3; }
    exec sandbox-exec -p "$_MAC_PROFILE" "$@"
    ;;
  Linux)
    command -v bwrap >/dev/null 2>&1 || {
      echo "sandbox-exec: bubblewrap (bwrap) not found — refusing to run unsandboxed" >&2; exit 3; }
    # --unshare-net gives the command a private network namespace with no
    # connectivity (default-deny egress). --dev-bind / / keeps the filesystem
    # (this tier contains NETWORK; working-dir write-scoping is a later tier).
    exec bwrap --unshare-net --dev-bind / / "$@"
    ;;
  *)
    echo "sandbox-exec: no OS sandbox available on $(uname -s) — refusing to run unsandboxed" >&2
    exit 3
    ;;
esac
