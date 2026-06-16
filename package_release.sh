#!/usr/bin/env bash
# Content-hash-recorded kit packaging + artifact self-test (maintainer tool).
#
# Builds a VERSIONED zip with provenance (artifact sha256 + a CONTENT
# `source_tree_sha256` in RELEASE_MANIFEST.json), then verifies it FROM THE
# EXTRACTED ARTIFACT — never the working tree. NOTE: the zip is content-
# reproducible (the source_tree hash is stable) but NOT bit-for-bit
# deterministic — archive metadata (mtimes, order, attrs) varies. Trust the
# `source_tree_sha256`, not a byte-identical zip, to compare two builds.
#
# Modes:
#   --smoke   FAST verification (~6-15s): version/sha, zip hygiene, a fresh
#             standard-none bootstrap running the FULL LOCAL validator chain
#             DIRECTLY (python -I; no setup/pre-commit), and a strict
#             profile-lock check. Per-validator name + timeout. Completes
#             reliably in constrained containers.
#   --full    --smoke PLUS the complete pytest suite from the artifact
#             (default). Subprocess-heavy; use --smoke where time is tight.
#
# Output (dist/):
#   <name>-<version>.zip  + .sha256  (canonical, versioned)
#   <name>.zip                       (unversioned compat copy)
#   RELEASE_MANIFEST.json            (version, commit, shas, test summary)
#
# Exit: 0 packaged AND the selected verification passed | non-zero otherwise.
set -euo pipefail

MODE="full"
case "${1:-}" in
  --smoke) MODE="smoke" ;;
  --smoke-install) MODE="smoke-install" ;;
  --full|"") MODE="full" ;;
  *) echo "usage: $0 [--smoke|--smoke-install|--full]" >&2; exit 2 ;;
esac

KITROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="$(basename "$KITROOT")"
PARENT="$(dirname "$KITROOT")"
DIST="$KITROOT/dist"
VER="$(tr -d '[:space:]' < "$KITROOT/VERSION" 2>/dev/null || echo '0.0.0')"
ZIP_VER="$DIST/${NAME}-${VER}.zip"
ZIP_PLAIN="$DIST/${NAME}.zip"

echo "==> Cleaning generated caches"
find "$KITROOT" \( -name '__pycache__' -o -name '.pytest_cache' -o -name '.ruff_cache' \
  -o -name '.mypy_cache' \) -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$KITROOT" -name '*.pyc' -delete 2>/dev/null || true
find "$KITROOT" -name '.DS_Store' -delete 2>/dev/null || true
# Disposable runtime state + local toolchain roots (.venv, .substrate/venv,
# node_modules, .substrate/traces, .substrate/memory/tasks) must not ship — but
# they are EXCLUDED from both the source-tree hash (find ! -path, below) and the
# artifact (zip -x, below) and re-checked by the hygiene gate, so they never need
# to be deleted from the working tree. package_release is NON-DESTRUCTIVE to the
# source root: deleting $KITROOT/.venv + $KITROOT/.substrate/venv in place used to
# wipe an ACTIVE dev/CI toolchain mid-run (v3.4.3 — surfaced as flaky
# FileNotFoundError under pytest-randomly when a packaging test ran before the
# venv-dependent eval/smoke tests). Cache dirs/.DS_Store are pruned above only
# because they regenerate for free; no toolchain or runtime state is removed.

# Source-tree hash: stable hash of all tracked source files (order-independent).
echo "==> Hashing source tree"
SRC_HASH="$(cd "$KITROOT" && find . -type f \
    ! -path './.git/*' ! -path './dist/*' ! -path '*/__pycache__/*' \
    ! -path './.venv/*' ! -path '*/.substrate/venv/*' ! -path './node_modules/*' \
    ! -path '*/.substrate/traces/*' ! -path '*/.substrate/memory/tasks/*' \
    ! -path '*/.pytest_cache/*' ! -path '*/.ruff_cache/*' ! -path '*/.mypy_cache/*' \
    ! -name '*.pyc' ! -name '.DS_Store' \
    -exec shasum -a 256 {} + | awk '{print $1}' | sort | shasum -a 256 | awk '{print $1}')"
GIT_COMMIT="$(cd "$KITROOT" && git rev-parse --short HEAD 2>/dev/null || echo 'none')"

echo "==> Building $ZIP_VER"
mkdir -p "$DIST"
rm -f "$ZIP_VER" "$ZIP_PLAIN"
( cd "$PARENT" && zip -rq "$ZIP_VER" "$NAME" \
    -x "$NAME/.git/*" "$NAME/dist/*" "$NAME/.venv/*" "$NAME/node_modules/*" \
       "*/__pycache__/*" "*/.pytest_cache/*" "*/.ruff_cache/*" "*/.mypy_cache/*" \
       "*/.substrate/venv/*" "*/.substrate/traces/*" "*/.substrate/memory/tasks/*" )
cp "$ZIP_VER" "$ZIP_PLAIN"
NFILES="$(cd "$PARENT" && unzip -l "$ZIP_VER" | tail -1 | awk '{print $2}')"
ART_SHA="$(shasum -a 256 "$ZIP_VER" | awk '{print $1}')"
echo "$ART_SHA  ${NAME}-${VER}.zip" > "$ZIP_VER.sha256"
echo "    $NFILES files, sha256 ${ART_SHA:0:16}…"

# Zip hygiene: no generated/toolchain junk must ride along. Write the listing to
# a FILE first — piping `unzip -l` straight into `grep -q` is BROKEN under
# `set -o pipefail`: grep -q closes the pipe on its first match, unzip dies with
# SIGPIPE (141), pipefail makes the whole pipeline non-zero, so the `if` was
# FALSE even when junk WAS present — the gate silently passed a dirty zip
# (v3.3.9 reviewer). With a temp file, grep's own exit status is authoritative.
echo "==> Zip hygiene"
_LISTING="$(mktemp)"
( cd "$PARENT" && unzip -l "$ZIP_VER" ) > "$_LISTING"
_JUNK_RE='(/\.venv/|/\.substrate/venv/|/__pycache__/|/\.pytest_cache/|/\.ruff_cache/|/\.mypy_cache/|/node_modules/|\.DS_Store|\.pyc$)'
if grep -Eq "$_JUNK_RE" "$_LISTING"; then
  echo "release: BLOCK — packaging junk in artifact:" >&2
  grep -E "$_JUNK_RE" "$_LISTING" | head -30 >&2
  rm -f "$_LISTING"; exit 1
fi
rm -f "$_LISTING"
echo "    clean"

echo "==> Extracting and verifying FROM THE ARTIFACT (mode: $MODE)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
unzip -q "$ZIP_VER" -d "$WORK"
APP="$WORK/$NAME"
rm -rf "$APP/.venv" "$APP/.substrate/venv" "$APP/.pytest_cache" \
       "$APP/.ruff_cache" "$APP/.mypy_cache" 2>/dev/null || true
ver="$(tr -d '[:space:]' < "$APP/VERSION" 2>/dev/null || echo '?')"
echo "    artifact VERSION = $ver"
[ "$ver" = "$VER" ] || { echo "release: BLOCK — VERSION mismatch ($ver != $VER)" >&2; exit 1; }

TEST_SUMMARY=""

# --- SMOKE: the FULL local validator chain in a freshly bootstrapped
# standard-none repo. Honest scope: this runs the validators DIRECTLY with
# `python -I` (no `manage.sh setup`, no `.substrate/venv`, no pre-commit) so
# it is fast and deterministic in any environment. It proves "bootstrap +
# the full local policy chain pass", NOT "manage.sh check/pre-commit pass"
# (that needs setup and is covered by --full + the CI matrix). No `|| true`:
# any validator failure fails the release.
_LOCAL_CHAIN="check_import_shadowing check_python_syntax check_harness_patterns \
              check_policy_code_integrity check_harness_smoke check_hook_smoke \
              check_agent_harness check_substrate_config"

# Per-validator timeout so a wedged validator is ATTRIBUTABLE (the v3.2.23
# reviewer hit a hung hook subprocess). Prefer GNU timeout / gtimeout; else
# run bare (each validator's own subprocess timeouts still apply).
_TO=""
if command -v timeout >/dev/null 2>&1; then _TO="timeout --kill-after=5s ${SUBSTRATE_SMOKE_VALIDATOR_TIMEOUT:-45s}"
elif command -v gtimeout >/dev/null 2>&1; then _TO="gtimeout --kill-after=5s ${SUBSTRATE_SMOKE_VALIDATOR_TIMEOUT:-45s}"; fi

echo "==> Smoke: bootstrap standard-none + ONE-PROCESS static chain"
SREPO="$(mktemp -d)"
( cd "$SREPO" && git init -q
  $_TO bash "$APP/bootstrap.sh" --profile standard --lang none --no-doctor >/dev/null 2>&1
  # ONE python process runs the static validator chain + behavioral spot-checks
  # in-process (the v3.3.1 reviewer's slow-startup timeout: ~10 separate
  # `python -I` launches cost too much; this is a single interpreter startup).
  $_TO python3 -I scripts/run_smoke_verification.py )
echo "    standard-none bootstrap + one-process static chain ok"
rm -rf "$SREPO"

# Strict profile-lock check WITHOUT a second full bootstrap (that second
# bootstrap was the v3.3.0 reviewer's remaining --smoke timeout in a slow
# container). The lock is independent of HOW required_profile got written, so
# stage it minimally: required_profile=strict + a downgraded config must make
# check_substrate_config refuse. Per-step echo + $_TO so a hang is attributable.
echo "==> Smoke: strict profile-lock blocks a downgrade (minimal stage)"
TREPO="$(mktemp -d)"
echo "    strict smoke step: stage"
mkdir -p "$TREPO/scripts" "$TREPO/.substrate"
for f in check_substrate_config.py command_policy.py harness_patterns.json _substrate_root.py; do
  cp "$APP/scripts/$f" "$TREPO/scripts/$f"
done
printf 'strict\n' > "$TREPO/.substrate/required_profile"
printf 'SUBSTRATE_PROFILE="starter"\n' > "$TREPO/.substrate/config"
echo "    strict smoke step: downgrade check"
if ( cd "$TREPO" && $_TO python3 -I scripts/check_substrate_config.py >/dev/null 2>&1 ); then
  echo "release: BLOCK — strict profile lock did not block a downgrade" >&2; rm -rf "$TREPO"; exit 1
fi
rm -rf "$TREPO"
echo "    strict profile-lock ok"
TEST_SUMMARY="smoke: standard-none bootstrap+full-local-chain + strict-profile-lock PASS"

# --- SMOKE-INSTALL (optional, explicit): the OPERATIONAL path the fast --smoke
# deliberately skips — a full bootstrap + `manage.sh setup` (creates the
# substrate venv, installs pre-commit) + `manage.sh check` (venv-backed chain +
# pre-commit). Needs network (pip) and is slow; run it when you want end-to-end
# setup proof. Not part of --smoke/--full defaults.
if [ "$MODE" = "smoke-install" ]; then
  echo "==> Smoke-install: bootstrap standard-none + manage.sh setup + manage.sh check"
  IREPO="$(mktemp -d)"; ir=0
  ( cd "$IREPO" && git init -q
    bash "$APP/bootstrap.sh" --profile standard --lang none --no-doctor >/dev/null 2>&1
    ./manage.sh setup
    ./manage.sh check ) || ir=$?
  rm -rf "$IREPO"
  [ "$ir" -eq 0 ] || { echo "release: BLOCK — smoke-install (setup+check) failed (rc=$ir)" >&2; exit "$ir"; }
  echo "    smoke-install: setup + check ok"
  TEST_SUMMARY="smoke-install: standard-none bootstrap+setup+check PASS ; $TEST_SUMMARY"
fi

if [ "$MODE" = "full" ]; then
  echo "==> Full: complete pytest suite from the artifact"
  EARLY_DUMP="${SUBSTRATE_ARTIFACT_EARLY_DUMP:-30}"
  DUMP_AFTER="${SUBSTRATE_ARTIFACT_DUMP_AFTER:-90}"
  HARD_CAP="${SUBSTRATE_ARTIFACT_HARD_CAP:-300}"
  PLOG="$WORK/pytest.log"
  ( cd "$APP" && exec env PYTHONNOUSERSITE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
      python3 -m pytest -v -p no:randomly -p no:cacheprovider > "$PLOG" 2>&1 ) &
  PYTEST_PID=$!
  _dump() {  # $1 = label
    echo "==> artifact-test watchdog: still running after $1 — current/last test + tree:" >&2
    tail -3 "$PLOG" 2>/dev/null | sed 's/^/    /' >&2 || true
    pgrep -af "python|pytest|check_" 2>/dev/null >&2 || true
  }
  ( sleep "$EARLY_DUMP"; kill -0 "$PYTEST_PID" 2>/dev/null && _dump "${EARLY_DUMP}s" ) & EARLY_PID=$!
  ( sleep "$DUMP_AFTER"; kill -0 "$PYTEST_PID" 2>/dev/null && _dump "${DUMP_AFTER}s" ) & DUMP_PID=$!
  ( sleep "$HARD_CAP"; kill -0 "$PYTEST_PID" 2>/dev/null && { echo "==> HARD CAP ${HARD_CAP}s — killing" >&2; kill -KILL "$PYTEST_PID" 2>/dev/null; } ) & CAP_PID=$!
  rc=0; wait "$PYTEST_PID" || rc=$?
  kill "$EARLY_PID" "$DUMP_PID" "$CAP_PID" 2>/dev/null || true
  wait "$EARLY_PID" "$DUMP_PID" "$CAP_PID" 2>/dev/null || true
  if [ "$rc" -ne 0 ]; then
    echo "release-artifact-test: FAILED (rc=$rc) — tail:" >&2; tail -15 "$PLOG" >&2
    exit "$rc"
  fi
  TEST_SUMMARY="full: $(grep -Eo '[0-9]+ passed[^$]*' "$PLOG" | tail -1) ; $TEST_SUMMARY"
fi

# --- provenance manifest ---
cat > "$DIST/RELEASE_MANIFEST.json" <<JSON
{
  "name": "$NAME",
  "version": "$VER",
  "git_commit": "$GIT_COMMIT",
  "artifact": "${NAME}-${VER}.zip",
  "review_bundle": "${NAME}-${VER}-review-bundle.tar.gz",
  "artifact_sha256": "$ART_SHA",
  "source_tree_sha256": "$SRC_HASH",
  "file_count": $NFILES,
  "verification_mode": "$MODE",
  "test_summary": "$TEST_SUMMARY",
  "built_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

# --- Review bundle: ONE place (and one tarball) carrying zip + sha + manifest +
# instructions, so a reviewer who can move only ONE file still gets verifiable
# provenance. Recurring audit friction: zip+sha arrived, the manifest didn't,
# and the renamed-on-upload zip broke `shasum -c`. The tarball solves both —
# extract it and the names line up.
echo "==> Review bundle"
REVIEW="$DIST/review"; rm -rf "$REVIEW"; mkdir -p "$REVIEW"
cp "$ZIP_VER" "$ZIP_VER.sha256" "$DIST/RELEASE_MANIFEST.json" "$REVIEW/"
cat > "$REVIEW/README_REVIEW.md" <<MD
# Review bundle — ${NAME} ${VER}

Three files, verifiable provenance:

1. Verify the checksum (run in this directory):
       shasum -a 256 -c ${NAME}-${VER}.zip.sha256
2. Confirm the printed SHA equals artifact_sha256 in RELEASE_MANIFEST.json.
3. Extract and audit ${NAME}-${VER}.zip.

If your audit environment accepts only ONE upload, upload
${NAME}-${VER}-review-bundle.tar.gz (it contains all of the above, with names
that line up so \`shasum -c\` works after extraction).
MD
BUNDLE="$DIST/${NAME}-${VER}-review-bundle.tar.gz"
# Build the review bundle with Python tarfile, NOT platform tar. macOS bsdtar
# embeds com.apple.provenance as a LIBARCHIVE.xattr PAX header even after
# `xattr -cr`/COPYFILE_DISABLE (provenance is a sticky Gatekeeper xattr that
# `xattr -c` does not reliably clear), so the tarball warns on extraction
# elsewhere. tarfile never reads xattrs, and we normalize every TarInfo
# (mtime/mode/uid/gid/uname/gname) in USTAR format, so the bundle is
# deterministic + metadata-clean on every platform (v3.3.11 reviewer).
python3 - "$REVIEW" "$BUNDLE" "$NAME" "$VER" <<'PY'
import io, sys, tarfile
from pathlib import Path
review, bundle, name, ver = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4]
files = [f"{name}-{ver}.zip", f"{name}-{ver}.zip.sha256",
         "RELEASE_MANIFEST.json", "README_REVIEW.md"]
with tarfile.open(bundle, "w:gz", format=tarfile.USTAR_FORMAT) as tf:
    for rel in files:
        data = (review / rel).read_bytes()
        info = tarfile.TarInfo(rel)
        info.size = len(data); info.mtime = 0; info.mode = 0o644
        info.uid = info.gid = 0; info.uname = info.gname = ""
        tf.addfile(info, io.BytesIO(data))
PY
# Bundle hygiene (pipefail-safe): listing must SUCCEED, emit NO warnings (a stray
# xattr/metadata header prints a tar warning), contain no ._*/.DS_Store, and be
# EXACTLY the four review files. Listings go to files so grep/diff status is
# authoritative (the v3.3.9 SIGPIPE lesson).
_BLIST="$(mktemp)"; _BERR="$(mktemp)"
if ! tar -tzf "$BUNDLE" > "$_BLIST" 2>"$_BERR"; then
  echo "release: BLOCK — review bundle cannot be listed" >&2; cat "$_BERR" >&2
  rm -f "$_BLIST" "$_BERR"; exit 1
fi
if [ -s "$_BERR" ]; then
  echo "release: BLOCK — review bundle emits tar warnings (stray metadata):" >&2; cat "$_BERR" >&2
  rm -f "$_BLIST" "$_BERR"; exit 1
fi
if grep -Eq '(^|/)\._|(^|/)\.DS_Store$' "$_BLIST"; then
  echo "release: BLOCK — review bundle contains macOS metadata files:" >&2
  grep -E '(^|/)\._|(^|/)\.DS_Store$' "$_BLIST" >&2; rm -f "$_BLIST" "$_BERR"; exit 1
fi
_EXP="$(mktemp)"; _ACT="$(mktemp)"
printf '%s\n' "${NAME}-${VER}.zip" "${NAME}-${VER}.zip.sha256" \
  RELEASE_MANIFEST.json README_REVIEW.md | LC_ALL=C sort > "$_EXP"
LC_ALL=C sort "$_BLIST" > "$_ACT"
if ! diff -q "$_EXP" "$_ACT" >/dev/null; then
  echo "release: BLOCK — review bundle is not exactly the four review files:" >&2
  cat "$_BLIST" >&2; rm -f "$_BLIST" "$_BERR" "$_EXP" "$_ACT"; exit 1
fi
rm -f "$_BLIST" "$_BERR" "$_EXP" "$_ACT"

# Clean up the extraction BEFORE the final success line and disarm the EXIT
# trap, so "passed" is printed POST-cleanup — an operator/reviewer sees the
# script reached completion, not just pre-trap success (v3.2.24 polish).
rm -rf "$WORK"; trap - EXIT
echo "release-artifact-test: passed (artifact $ver, mode $MODE) — workspace cleaned"
echo "    zip:      $ZIP_VER"
echo "    sha256:   $ZIP_VER.sha256"
echo "    manifest: $DIST/RELEASE_MANIFEST.json"
echo "    review:   $REVIEW/ (+ $BUNDLE)"
