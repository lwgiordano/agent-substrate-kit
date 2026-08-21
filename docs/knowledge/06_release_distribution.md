---
purpose: Release packaging, signing, manifests, and artifact verification.
last_human_reviewed: 2026-08-21
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

## Verification

Release verification supports the configured signature backends and pins their
trusted material. The verifier executes the source bytes it checks and includes
the local dependency closure. A missing or malformed pin refuses verification;
the operator must choose the explicit unverified path for local development.

The release manifest binds the commit, source-tree identity, and artifact
SHA-256. `BENCHMARK.md` carries measured behavior but delegates exact artifact
provenance to that manifest. Review bundles include the evidence required for a
human or another agent to reproduce the decision.

The release gate runs deterministic validators, project tests, policy evals, and
artifact verification in sequence. A finalizer or verifier failure is a release
failure. Published HISTORY entries refer to real immutable commit objects, so
published release commits must merge without squash rewriting.

Signature strength depends on protection of the configured key or identity and
the remote trusted-base boundary. A local agent-writable install manifest is not
a substitute for the signed release. Hosts without a verification backend must
report that limitation instead of labeling an artifact verified.
