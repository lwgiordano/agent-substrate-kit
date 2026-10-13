#!/usr/bin/env bash
# Generate a DURABLE minisign release keypair for local (`SUBSTRATE_RELEASE_BACKEND=local`)
# signing and print the PUBLIC key to commit. The SECRET key lives OUTSIDE the repo (never
# committed, mode 600); point SUBSTRATE_RELEASE_SECKEY at it when packaging. (v3.7.21)
#
# Key custody scales with the release backend — you rarely stay on a local key:
#   local        → this durable secret file (below); passphrase optional (see note)
#   ci-minisign  → the secret is a GitHub Actions secret; no local key
#   keyless      → NO key exists anywhere (Sigstore/OIDC)  ← the end state; see KEY_ROTATION.md
set -euo pipefail
DEST="${1:-$HOME/.config/agent-substrate}"
# The key is NAMED after the repo (basename of the repo root), so require running from a
# substrate repo root — from anywhere else the name (and the existing-key check) would silently
# target the wrong key (v3.7.22 review #3).
if [ ! -f manage.sh ] || [ ! -d .substrate ]; then
  echo "setup_release_key: run from the substrate repo root (manage.sh + .substrate/ not found here)" >&2
  exit 2
fi
NAME="$(basename "$(pwd)")"
KEY="$DEST/${NAME}-release.key"
PUB="$DEST/${NAME}-release.pub"
command -v minisign >/dev/null 2>&1 || { echo "minisign not installed — 'brew install minisign' (or cargo/apt)" >&2; exit 2; }
mkdir -p "$DEST"; chmod 700 "$DEST"
if [ -f "$KEY" ]; then
  echo "release key already exists: $KEY"
  echo "use it with:  export SUBSTRATE_RELEASE_SECKEY='$KEY'"
  [ -f "$PUB" ] || echo "WARNING: its public key ($PUB) is missing — if .substrate/trust/minisign.pub is also gone, rotate: see KEY_ROTATION.md" >&2
  exit 0
fi
# -W = no passphrase, so automated signing (package_release) is non-interactive. For stronger
# custody, drop -W (adds a passphrase — but then signing prompts), or scale to ci-minisign /
# keyless where no local key exists.
minisign -G -W -p "$PUB" -s "$KEY"
chmod 600 "$KEY"
echo "generated durable release key: $KEY (mode 600)"
echo
echo "1. commit the PUBLIC key as the repo trust anchor:"
echo "     mkdir -p .substrate/trust && cp '$PUB' .substrate/trust/minisign.pub"
echo "     [ -d installer/substrate-init ] && cp .substrate/trust/minisign.pub installer/substrate-init/src/substrate_init/trust/minisign.pub"
echo "2. sign releases with the durable secret (never commit it):"
echo "     export SUBSTRATE_RELEASE_SECKEY='$KEY'"
echo "     ./package_release.sh --full"
echo "3. to scale off local key custody later:  ./manage.sh enable release ci   (or keyless)"
