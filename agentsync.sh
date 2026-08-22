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
# Optional auto-backup (opt-in, generic — no machine-specific path in this file):
#   export SUBSTRATE_BACKUP_DIR="/path/to/some/backup/folder"
# When set, every sync/msg drops a fresh zip of the repo (minus .git) there —
# e.g. point it at a Google Drive folder to snapshot into the cloud on each sync.
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

_backup() {
  # If SUBSTRATE_BACKUP_DIR is set, refresh a single zip snapshot there (repo
  # minus .git). Never hard-fail — a backup problem must not break the sync.
  local dir="${SUBSTRATE_BACKUP_DIR:-}"
  [ -n "$dir" ] || return 0
  command -v zip >/dev/null 2>&1 || { echo "agentsync: 'zip' not found, skipping backup"; return 0; }
  [ -d "$dir" ] || { echo "agentsync: SUBSTRATE_BACKUP_DIR '$dir' not found, skipping backup"; return 0; }
  local top repo
  top="$(git rev-parse --show-toplevel)" || return 0
  repo="$(basename "$top")"
  ( cd "$top/.." && rm -f "$dir/$repo-backup.zip" \
      && zip -rq "$dir/$repo-backup.zip" "$repo" -x "*/.git/*" ) \
    && echo "agentsync: backed up to $dir/$repo-backup.zip" \
    || echo "agentsync: backup failed (sync still OK)"
}

_sync() {
  # pull the remote branch (merge, keep both sides), then push. v3.8.36
  # (Codex round-19): failures are still non-fatal to the WORK (the next run
  # reconciles) but the return code is HONEST — a caller must never be told
  # the bus is synced when the push was rejected, or a CLAIM can look
  # published while it exists only locally.
  local rc=0
  git pull --no-edit --no-rebase origin "$BR" \
    || { echo "agentsync: pull FAILED (resolve conflicts, re-run)"; rc=1; }
  git push origin "$BR" \
    || { echo "agentsync: push FAILED — local commits are NOT on the bus remote"; rc=1; }
  _backup
  return $rc
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
    if _sync; then
      echo "sent + synced as '$who'."
    else
      echo "agentsync: message committed LOCALLY as '$who' but NOT synced —"
      echo "           the other agent cannot see it. Re-run './agentsync.sh sync'."
      exit 1
    fi
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
