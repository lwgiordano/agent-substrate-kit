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
    # v3.8.37 (round-20 P1 + audit WARN): append ATOMICALLY through an
    # O_NOFOLLOW|O_APPEND|O_CREAT open, not a `[ -L ]` test-then-`>>`. A
    # symlinked AGENT_BUS.md turns `msg` into an arbitrary external-write
    # primitive; the earlier test-then-act closed the static case but left a
    # TOCTOU window a concurrent local swap could exploit. The kernel refuses
    # to follow a symlink on open, so there is no window. python3 is a hard
    # substrate dependency (every hook is python3), so relying on it here is safe.
    AGENT_BUS_WHO="$who" AGENT_BUS_MSG="$*" python3 - "$BUS" <<'PY' || exit $?
import datetime, os, stat, sys
bus = sys.argv[1]
who = os.environ["AGENT_BUS_WHO"]
msg = os.environ["AGENT_BUS_MSG"]
# v3.8.38 (round-21 P2): the bus is line-oriented, so a message containing a
# newline could forge additional top-level lease entries. Collapse ALL
# whitespace/control to single spaces — the entry stays exactly one line.
msg = " ".join(msg.split())
who = " ".join(str(who).split()) or "unknown"
try:
    # O_NOFOLLOW: never open a symlinked bus. O_NONBLOCK: a FIFO bus fails fast
    # instead of hanging on open (round-21 P2). O_CREAT so first-run still works.
    fd = os.open(bus, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                 | getattr(os, "O_NONBLOCK", 0), 0o644)
except OSError as e:
    sys.stderr.write("agentsync: refusing to write %s (%s) — the bus must be a "
                     "regular file, never a symlink\n" % (bus, e.__class__.__name__))
    sys.exit(2)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        sys.stderr.write("agentsync: refusing — %s is not a regular file "
                         "(fifo/directory/special)\n" % bus)
        sys.exit(2)
    # v3.8.38 (round-21 P1): a HARD-LINKED bus (st_nlink > 1) writes through to
    # an outside inode — invisible to the symlink check, the v3.8.25 lesson.
    if st.st_nlink > 1:
        sys.stderr.write("agentsync: refusing — %s has %d hard links; a shared "
                         "inode is an external-write primitive\n" % (bus, st.st_nlink))
        sys.exit(2)
    if st.st_size == 0:
        os.write(fd, b"# Agent bus (append-only, merge=union)\n")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    os.write(fd, ("\n- [%s] **%s**: %s\n" % (ts, who, msg)).encode("utf-8"))
finally:
    os.close(fd)
PY
    git add "$BUS"
    # v3.8.37 (round-20 P1): commit failure must PROPAGATE — the old `|| true`
    # let `msg` print success while no bus commit existed (a rejecting
    # pre-commit hook, an empty diff after a prior identical stage, etc.).
    if ! git commit -q -m "bus: $who"; then
      echo "agentsync: git commit FAILED — the message is staged but NOT committed;" >&2
      echo "           nothing was synced. Resolve the commit failure and re-run." >&2
      exit 1
    fi
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
    # v3.8.40 (round-23): validate AFTER the pull, not before — a remote commit
    # can replace AGENT_BUS.md with a symlink between an early check and the read
    # (TOCTOU). Also reject HARD links (nlink>1), which follow no symlink check
    # but share an outside inode. Refuse before printing anything.
    git pull --no-edit --no-rebase origin "$BR" >/dev/null 2>&1 || true
    if [ -e "$BUS" ]; then
      AGENT_BUS_PATH="$BUS" python3 - <<'PY' || exit $?
import os, stat, sys
b = os.environ["AGENT_BUS_PATH"]
try:
    st = os.lstat(b)
except OSError:
    sys.exit(0)  # absent — handled below
if stat.S_ISLNK(st.st_mode):
    sys.stderr.write("agentsync: refusing — %s is a symlink\n" % b); sys.exit(2)
if not stat.S_ISREG(st.st_mode):
    sys.stderr.write("agentsync: refusing — %s is not a regular file\n" % b); sys.exit(2)
if st.st_nlink > 1:
    sys.stderr.write("agentsync: refusing — %s has %d hard links (shared inode)\n"
                     % (b, st.st_nlink)); sys.exit(2)
PY
    fi
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
