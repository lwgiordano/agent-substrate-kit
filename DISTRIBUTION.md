# Distribution & release tiers

The substrate treats distribution as a **tiered capability** (like sandbox / remote / scanners):
the same machinery runs at every scale, and you climb by flipping a flag / running `enable` —
never a rewrite. **Consumers verify any tier out of the box** (`scripts/verify_release.py` is
multi-backend), so you can change *how* releases are signed without breaking anyone downstream.

`./manage.sh go-live` maps where you are on each axis + the exact command for the next rung.

## The three axes

### Sign — `SUBSTRATE_RELEASE_BACKEND`
| Rung | Command | Trust model | When |
|---|---|---|---|
| `local` (default) | `enable release local` | minisign key on your laptop; never leaves it | solo / private |
| `ci-minisign` | `enable release ci` | minisign key in a GH Actions secret; tag → auto release | team, want hands-off |
| `keyless` | `enable release keyless` | Sigstore/cosign OIDC — **no key stored anywhere** | public / high-value |

The honest tradeoff: automation moves the signer off your laptop into CI. Either CI holds a
secret (`ci-minisign`) or there's no key at all (`keyless`). There is no "fully automated **and**
key-only-on-laptop" — that's what `local` is, and it's a manual maintainer step by design.

### Publish
`local zip` → **GitHub Release** (`gh release create`, or automatic in the CI tiers) → **PyPI**
for `substrate-init` (tokenless via OIDC Trusted Publishing; only needed when strangers install).

### Consume — how repos get upgrades
`manual` (`./manage.sh upgrade --from <signed-zip>`) → **`enable auto-upgrade`** (a scheduled
workflow that verifies the latest release + opens an upgrade PR; no key/secret, verify+PR only)
→ fleet push (a loop / org job over many repos — not built; it's the same per-repo verified
upgrade fanned out).

## Out-of-the-box vs scale
- **Out of the box (`local`):** sign on your laptop, `gh release create`, install via the
  release URL or a local signed zip. Complete for you + a private team.
- **Scale by one command:** `enable release ci|keyless` installs the matching (pre-staged) release
  workflow; `enable auto-upgrade` installs the consumer upgrade-PR workflow. The dormant templates
  ship with every install (`.substrate/*.yml.template`) — activating is a copy, not authoring.
- **The one thing to plan before scaling past yourself:** key management — see
  [KEY_ROTATION.md](KEY_ROTATION.md). The design already supports **signed key rotation through
  `upgrade`**, so it's a procedure, not a rebuild.

## Verifying a release (any tier, any consumer)
```
scripts/verify_release.py <artifact>          # auto-detects .minisig (minisign) or .sigstore (cosign)
minisign -Vm <artifact> -p minisign.pub       # reference-tool cross-check (minisign tier)
```
Fail-closed: a bad signature, a missing trust anchor, or a required verifier that isn't installed
is a non-zero exit — never a silent pass.
