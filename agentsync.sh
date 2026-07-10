#!/usr/bin/env bash
# agentsync — bidirectional git sync + append-only message bus so two agent
# checkouts of the SAME branch (this Claude container and your local Codex
# folder) can share work and talk. Transport is git; there is no shared disk
# between machines, so sync is turn-based (pull then push), not real-time.
#
# Setup (run in EACH checkout, once):
#   export AGENT_NAME=claude     # or: export AGENT_NAME=codex
#   chmod +x agentsync.sh
# The message bus is conflict-free because '.gitattributes' carries
#   AGENT_BUS.md merge=union
# (already committed on this branch).
#
# Usage:
#   ./agentsync.sh              # pull the other side's changes, push yours
#   ./agentsync.sh msg "text"   # post a message to the bus + sync
#   ./agentsync.sh read [N]     # pull, then show the last N bus lines (default 20)
#   ./agentsync.sh watch [secs] # keep pulling every N secs (run in a spare tab)
set -euo pipefail
BUS="AGENT_BUS.md"
BR="$(git rev-parse --abbrev-ref HEAD)"
who="${AGENT_NAME:-$(whoami)}"

_sync() {
  # pull the remote branch (merge, keep both sides), then push. Never hard-fail
  # on a transient network/push race — the next run reconciles.
  git pull --no-edit --no-rebase origin "$BR" || echo "agentsync: pull had issues (resolve conflicts, re-run)"
  git push origin "$BR" || echo "agentsync: push deferred (pull first, re-run)"
}

case "${1:-sync}" in
  sync) _sync ;;
  msg)
    shift || true
    [ -n "${*:-}" ] || { echo "usage: ./agentsync.sh msg <text>"; exit 2; }
    [ -f "$BUS" ] || printf '# Agent bus (append-only, merge=union)\n' > "$BUS"
    printf '\n- [%s] **%s**: %s\n' "$(date -u +%FT%TZ)" "$who" "$*" >> "$BUS"
    git add "$BUS"
    git commit -q -m "bus: $who" || true
    if ! git check-attr merge -- "$BUS" | grep -q union; then
      echo "HINT: add 'AGENT_BUS.md merge=union' to .gitattributes and commit it,"
      echo "      or concurrent messages from both agents will conflict."
    fi
    _sync
    echo "sent + synced as '$who'."
    ;;
  read)
    git pull --no-edit --no-rebase origin "$BR" >/dev/null 2>&1 || true
    tail -n "${2:-20}" "$BUS" 2>/dev/null || echo "(no bus yet — send one with: ./agentsync.sh msg \"hi\")"
    ;;
  watch)
    secs="${2:-15}"
    echo "watching branch '$BR' (pull every ${secs}s; Ctrl-C to stop)"
    while true; do
      git pull --no-edit --no-rebase origin "$BR" >/dev/null 2>&1 || true
      sleep "$secs"
    done
    ;;
  *) echo "usage: ./agentsync.sh [sync | msg <text> | read [N] | watch [secs]]"; exit 2 ;;
esac
