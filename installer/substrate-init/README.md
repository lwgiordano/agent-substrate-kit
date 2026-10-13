# substrate-init

Verify-then-install bootstrapper for the [Agent Substrate Kit](https://github.com/lwgiordano/agent-substrate-kit).

**Why this package exists:** the minisign public key used to verify a kit release is
**embedded in this package**, out-of-band from the repository being bootstrapped. A forked
or tampered kit repo therefore cannot substitute its own key — first-install authenticity
is anchored on this package's integrity (PyPI), not trust-on-first-use of a cloned repo.
This is the fork-proof property that makes minisign worth choosing over repo-local signing.

## Use

```bash
# from a published release URL (fetches the .zip and its .minisig, verifies, bootstraps):
uvx substrate-init --url https://github.com/lwgiordano/agent-substrate-kit/releases/download/vX.Y.Z/agent_substrate_kit_v3-X.Y.Z.zip --target .

# from a local signed artifact (expects agent_substrate_kit_v3-X.Y.Z.zip.minisig alongside):
uvx substrate-init --from ./agent_substrate_kit_v3-X.Y.Z.zip --target . -- --profile strict
```

Everything after `--` is passed through to the kit's `bootstrap.sh`.

**Fail-closed:** a `.zip` whose signature does not verify against the embedded key is never
extracted or run. `--allow-unverified` (a local directory or a deliberately unsigned build,
dev only) is the sole escape and warns.

## Maintainer: publish

The embedded key (`src/substrate_init/trust/minisign.pub`) must match the key the kit's
`package_release.sh` signs with (`.substrate/trust/minisign.pub`); a kit test enforces the
match. To publish:

```bash
cd installer/substrate-init
uv build          # or: python -m build   → dist/substrate_init-*.whl + .tar.gz
uv publish        # or: twine upload dist/*   (needs a PyPI token)
```

Bump `version` in `pyproject.toml` (and `__init__.py`) whenever the verifier logic or the
embedded key changes (e.g. a key rotation → republish so consumers get the new anchor).
