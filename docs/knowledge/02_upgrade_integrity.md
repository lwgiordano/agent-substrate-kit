---
purpose: Upgrade provenance, authority floors, transactions, and postconditions.
asserts:
  - scripts/substrate_upgrade.py::_exec_module_from_source
  - scripts/substrate_upgrade.py::_apply_capability_floor
last_human_reviewed: 2026-08-28
covers:
  - bootstrap.sh
  - manage.sh
  - scripts/_minisign.py
  - scripts/_substrate_config.sh
  - scripts/_verify_backends.py
  - scripts/check_substrate_config.py
  - scripts/substrate_profile.py
  - scripts/substrate_upgrade.py
  - scripts/update_manifest.py
  - scripts/verify_release.py
  - scripts/write_install_json.py
---

# Upgrade integrity

[Back to the substrate map](00_substrate.md).

Upgrade separates source verification, target drift, frozen authority, rendering,
and final postconditions. `--plan` resolves and validates the same source and
authority inputs as `--write` without mutating the target.

## Verified source execution

File release sources require a supported signature unless the operator supplies
the explicit unverified-source override. Directory kits are local development
inputs and require the corresponding opt-in. The verifier wrapper and its local
dependency closure are pinned before use.

Private loaders read, compile, and execute the verified source bytes directly.
They do not use normal import bytecode lookup, so ignored unchecked `.pyc` files
cannot substitute different executable code for a hashed source file. That read
is itself guarded (v3.8.47): it is the highest-value read in the kit, because
the bytes it returns are compiled and RUN, so a symlinked or hard-linked engine
module would execute outside code with the upgrader's privileges. An unsafe or
unreadable source refuses rather than executing. Temporary module bindings and
import paths are restored after verification.

Finalizers and canonical-config validation run the kit's copies against the
target root. Target-controlled helper replacements therefore remain data being
audited rather than code the upgrade executes.

## Drift and overwrite coverage

The installed provenance contains hashes for owned files. Upgrade derives its
overwrite set from the selected kit and intersects that set with the surface the
baseline is allowed to vouch for. Missing, malformed, or incomplete drift maps
are untrusted: a write requires `--force` rather than treating absent entries as
proof of no drift.

Replaced directory roots and owned destinations are checked for escaping
symlinks. Drift is computed against the live target state and covers the root
entrypoints and generated files the render may overwrite.

Ownership migrations retire obsolete serialized entries before they make drift
or destination-safety decisions. In v3.8.32, pre-existing baseline entries for
project-authored `docs/knowledge/*.md` siblings stop being machinery; the
generated `00_substrate.md` and installed `_template.md` remain fully protected.

The boundary-crossing command must run the verified new kit's engine against the
old target, for example from the trusted or already-verified extracted kit:

```bash
./manage.sh upgrade --root /path/to/old-consumer --from . --allow-unverified --write
```

The old target's `./manage.sh upgrade` necessarily dispatches its old engine and
cannot apply a future baseline rule. After the crossing, the installed engine
supports ordinary target-local upgrades. The directory-source opt-out above is
valid only because the operator already established trust in that extracted kit.
If the selected kit cannot execute its canonical provenance writer to enumerate
baseline coverage, upgrade aborts before the render even with `--force`; it does
not downgrade that missing oracle to a late finalizer failure. The canonical
surface inventory must also load independently, and the writer's exported
ownership constants must match it; a self-consistent fallback is not authority.
The writer's own stripped-install fallback is tested against the canonical
install-owned and optional inventories so an import failure cannot silently
shrink the provenance baseline.

The drift map in `.substrate/install.json` is agent-writable. It detects
accidental or ordinary local changes but is not a local cryptographic integrity
anchor. A process that edits both a target engine and its baseline is already
inside the code-execution boundary. Signed artifacts and remote trusted-base
enforcement provide the independent anchors.

## Frozen authority and transactions

The engine snapshots live config and every required capability before deriving
answers. Render values come from that snapshot, not from agent-writable install
provenance. Profile, sandbox, and remote-governance floors never move downward;
language and runner come from validated live config.

Authority is re-read before mutation and after restore. A concurrent raise is
preserved and makes the upgrade fail so the operator can rerun with a consistent
render. `_apply_capability_floor` reconciles only upward.

Upgrade renders through a backup/restore transaction. The backup carries the
authority snapshot used for the render, and the target receives kit-owned files
only after validation. The final success decision comes from the resulting
on-disk state: provenance must name the intended version and tree, manifest
generation must succeed, frozen floors must hold, and canonical config must pass
the kit validator.

No user-space check can eliminate the final instruction-scale interval against a
non-cooperating process that already has concurrent write and execute access.
The postcondition converts detected changes into failure and leaves raised locks
intact instead of claiming a consistent apply.

Render authority reads of the frozen locks refuse the upgrade when a lock is
present but unreadable or invalid; only a genuinely absent lock yields the
documented default. A reader that fell back to the lowest tier on error would
let an unreadable lock silently drop a required tier.


Every `.substrate/config` read in the doctor, the profile resolver, and the
config gate goes through the shared guarded reader, so a linked or non-regular
config can neither supply outside values nor block a gate on open.
