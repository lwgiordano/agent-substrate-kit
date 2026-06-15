<!-- Agent Substrate Kit pull-request template. The substrate handles
     bug-fix discipline via the commit-msg hook (four required
     fields). This PR template covers the broader review context. -->

## Summary

<!-- 1-2 sentences. What changed and why. -->

## Type of change

<!-- Check all that apply -->

- [ ] Bug fix (substrate's commit-msg hook will require the
      four-field protocol on bug-fix commits)
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Documentation
- [ ] Performance improvement
- [ ] Breaking change

## Substrate checklist

<!-- The substrate enforces these mechanically; tick off here for
     reviewer confidence. -->

- [ ] **Pre-commit passes locally** (`pre-commit run --all-files`)
- [ ] **Knowledge doc** updated if new modules were added or behavior
      changed (covers: list refreshed, last_human_reviewed bumped)
- [ ] **ADR written** if this picks one approach over alternatives
      (`docs/decisions/NNNN-<slug>.md` with all four sections)
- [ ] **Postmortem written** if this is a bug fix
      (`docs/postmortems/YYYY-MM-DD-<slug>.md` with five required
      sections + carry-forward rule) OR `[no-postmortem: <reason>]`
      opt-out for typo/rename/refactor
- [ ] **HISTORY appended** with --commit-hash after the fix lands

## Test plan

<!-- How did you verify this works? Concrete: commands, expected
     output, edge cases tested. -->

- [ ] <test 1>
- [ ] <test 2>

## Reviewer notes

<!-- Anything the reviewer should pay extra attention to:
     - Tricky edge cases
     - Decisions you considered but rejected
     - Dependencies on other PRs / issues
     - Migration steps if breaking -->

## Related

<!-- Closes #123, Refs #456, etc. -->

---

<!-- The substrate auto-routes review via .github/CODEOWNERS.
     If your change touches AGENTS.md or scripts/check_*.py, expect
     substrate-maintainers to be auto-requested. -->
