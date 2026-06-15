---
name: release-gate
description: Run the full release gate and summarize results without hiding unresolved risk. Use before tagging a release, merging to main, or any "is this shippable?" question.
---

# release-gate

```bash
./manage.sh release        # runs scripts/release_gate.sh
```

Runs the full battery: doctor, manifest, drift, harness, secrets,
HISTORY SHA, tests, pre-commit all-files.

## Reporting contract

- Report every failure verbatim — exact command, exact error tail.
- Never summarize a red gate as "minor" or "mostly passing". The
  release is PASS or BLOCK; there is no "pass with unresolved BLOCK".
- For each failure: classify (real bug / environment / stale config),
  state the fix, and rerun until green or explicitly waived by the
  operator with a recorded reason.

## After green

1. Append a HISTORY entry for the release.
2. Tag/release per the project's playbook.
3. If anything was waived, the waiver + reason goes in the HISTORY
   entry — auditable, greppable.
