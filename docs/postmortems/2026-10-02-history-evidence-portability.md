---
date: 2026-10-02
severity: medium
caught_by: runtime
related_commits:
  - 24c2316 (receiving-clone baseline)
gates_added:
  - tests/test_history_evidence_portability.py
  - tests/guards.json
---

# HISTORY evidence portability

## What happened

The v3.9.3 HISTORY gate passed a fresh clone with four imported success labels,
then failed the same file after the clone recorded one benign local memory
event. The receiving clone had no release-pass evidence from the producing
clone. This blocked normal checked commits without a permitted HISTORY edit.

## Why it happened

The reader reused the writer's proof requirement with one special case: no
local chain. A healthy unrelated chain was treated as a complete record of all
releases. Evidence availability and evidence validity were conflated. The
no-chain exception also permitted newly inserted unproven success claims.

## Why our tooling didn't catch it

Tests separately covered no-chain and bad-chain states, but never imported
unchanged history followed by a receiving clone's first local event. The
existing test encoded the overly broad no-chain exception as expected behavior.

## Preventative gate added

The reader classifies verified, unavailable, and invalid proof. Unavailable
proof only permits a reported, unverified historical claim matching a whole
committed entry and its multiplicity. HEAD and merge-parent provenance is not
release proof. The writer still requires matching clean-start local proof.

Disposable-repo tests cover the original transition, edited and duplicate
claims, damaged chains, wrong-commit and dirty-start proof, merge multiplicity,
and failed Git reads. Registered guard-removal probes must make their mapped
tests fail. Tests shipped to consumers use their own minimal fixture rather
than importing a kit-only helper that bootstrap omits.

The full suite also exposed two copied tests absent from the shape classifier's
kit-test inventory. A discovery regression compares that inventory with the
actual top-level test files, while checking that an arbitrary consumer test
remains project code. This prevents automatic shipping and manual classification
from silently diverging when a test is added.

## Carry-forward rule

Test evidence readers against absent, unrelated valid, matching valid, and
invalid evidence, and separately test creation of a new success claim in each
state; imported provenance must never be counted as local verification.
