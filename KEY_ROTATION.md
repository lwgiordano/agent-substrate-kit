# Key rotation & signing-key protection

The release trust root is one minisign keypair (`local` / `ci-minisign` tiers). This is the one
thing to have a plan for before you scale past yourself. The `keyless` tier removes the problem
entirely (no key), so "rotation" below applies to the minisign tiers.

## Where the signing key lives (resolves to YOUR setup — key custody shrinks as you scale)
Signing is `SUBSTRATE_RELEASE_SECKEY` + the release backend; there is no hardcoded location:

| Backend (`enable release …`) | Where the secret is | Custody |
|---|---|---|
| `local` | a **durable file** you own (default `~/.config/agent-substrate/<repo>-release.key`, mode 600) | you |
| `ci-minisign` | a **GitHub Actions secret** | GitHub |
| `keyless` | **nowhere** — Sigstore/OIDC, no key exists | none |

- **Never keep the key in a scratch/temp dir** — it can vanish, and losing it forces a rotation.
- One-command setup: `./manage.sh release --setup-key` generates the durable key + prints the
  public key to commit. Then `export SUBSTRATE_RELEASE_SECKEY=<that path>` before packaging.
- The higher you climb the ladder, the less local key custody you carry — that's the intended
  scaling: solo keeps a durable file; a team moves it to a CI secret; public/high-value goes
  keyless and holds no key at all.

## Protect the secret key
- **Never commit it.** Only `.substrate/trust/minisign.pub` (the PUBLIC key) is in the repo.
- **Password-protect it** for anything beyond solo use: `minisign -G` (without `-W`) encrypts the
  secret with a passphrase. The current bootstrap key uses `-W` (no passphrase) for automation —
  fine solo, weak shared. For real custody, use a passphrase or a KMS/hardware-backed signer.
- **`ci-minisign` tier:** the key lives in a GH Actions secret — a repo/org compromise is a key
  compromise. Prefer `keyless` (Sigstore) once the blast radius matters.

## Rotate — signed rotation through `upgrade` (no rebuild)
The design already carries this: `.substrate/trust/minisign.pub` is **machinery** (overwritten
by a verified upgrade), so a new key propagates to consumers via a normal signed release chain:

1. Generate the new keypair; keep the OLD secret until step 3 is shipped.
2. Put the NEW public key in the kit (`.substrate/trust/minisign.pub`) and in the installer
   (`installer/substrate-init/src/substrate_init/trust/minisign.pub` — the drift test enforces
   the match).
3. Cut a release **signed with the OLD key** that ships the NEW public key. Consumers verify it
   with the OLD key they still trust, then `upgrade` overwrites their anchor with the NEW key.
   This is the valid rotation chain: old-key-signed → adopt new key.
4. From the next release, sign with the NEW key. Republish `substrate-init` (embeds the new key).
5. Retire the OLD secret.

If the old key is **lost or compromised** (can't sign step 3): rotation can't be self-served —
consumers must re-anchor out-of-band (fetch the new `substrate-init` from PyPI, or re-bootstrap
from a freshly-cloned trusted kit). This break-glass gap is the reason to (a) back up the secret
and (b) move to `keyless` before the project is high-value.

## When to move to keyless
`./manage.sh enable release keyless` — Sigstore/cosign OIDC signing, no key to store, lose, or
rotate. Verification anchors on the workflow identity + a public transparency log
(`.substrate/trust/sigstore_identity.json`). This is the recommended end state for public or
high-value distribution; see [DISTRIBUTION.md](DISTRIBUTION.md).
