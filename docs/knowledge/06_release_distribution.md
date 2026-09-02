---
purpose: Release packaging, signing, manifests, and artifact verification.
last_human_reviewed: 2026-09-02
covers:
  - manage.sh
  - package_release.sh
  - scripts/_minisign.py
  - scripts/_verify_backends.py
  - scripts/build_review_bundle.py
  - scripts/release_gate.sh
  - scripts/setup_release_key.sh
  - scripts/update_manifest.py
  - scripts/verify_release.py
  - scripts/write_install_json.py
---

# Release and distribution

[Back to the substrate map](00_substrate.md).

The release path packages the current source tree, records exact provenance, and
verifies the built artifact rather than trusting an in-place checkout. The root
`package_release.sh` and `manage.sh release` route through the same release gate.

## Artifact contents

The package includes substrate-owned scripts, templates, trust configuration,
workflows, and compact install assets. Consumer-heavy self-tests and source-only
knowledge siblings are not installed by default. Cheap installed-file and smoke
tests remain in consumer repositories; `--dev-tests` opts into the full source
self-test suite.

`docs/manifest.json` is generated from source knowledge docs and ADRs. It is not
hand-edited. `.substrate/install.json` is generated after render and records the
installed answers, owned-file hashes, version, and source tree used by later
drift checks.
Its stripped-install inventory fallback mirrors the canonical install-owned
surface lists exactly while deliberately excluding governed project-authored
knowledge directories from provenance, so a missing helper import does not
silently shrink the upgrade drift baseline.

## Verification

Release verification supports the configured signature backends and pins their
trusted material. The verifier executes the source bytes it checks and includes
the local dependency closure. A missing or malformed pin refuses verification;
the operator must choose the explicit unverified path for local development.

The release manifest binds the commit, source-tree identity, and artifact
SHA-256. `BENCHMARK.md` carries measured behavior but delegates exact artifact
provenance to that manifest. Review bundles include the evidence required for a
human or another agent to reproduce the decision.

The gate also verifies the tamper-evident memory chain, and in the strict
profile requires its git-note anchor unconditionally — an absent anchor is a
named failure, never a silent downgrade to the unanchored check (that hedge was
the v3.8.50 self-audit's P1: a trust anchor failing open on absence). Once the
whole gate has passed, every profile's release writes a fresh anchor for that
commit, so each release re-ties the chain to a known-good state; the first
strict release in a repo needs a one-time `./manage.sh memory anchor`.

The release gate runs deterministic validators, project tests, policy evals, and
artifact verification in sequence. A finalizer or verifier failure is a release
failure. Published HISTORY entries refer to real immutable commit objects, so
published release commits must merge without squash rewriting.

Signature strength depends on protection of the configured key or identity and
the remote trusted-base boundary. A local agent-writable install manifest is not
a substitute for the signed release. Hosts without a verification backend must
report that limitation instead of labeling an artifact verified.


`manage.sh check` runs `check_raw_file_io.py` alongside the other structural
pins: it fails the chain when raw file I/O targets a repo-derived path, which is
the mechanized form of the link/TOCTOU class the earlier rounds fixed by hand.
