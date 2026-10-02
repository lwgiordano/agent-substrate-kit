---
purpose: Lessons with evidence, the record the chain attests, outcome labels, and recall.
last_human_reviewed: 2026-10-02
covers:
  - scripts/check_lessons.py
  - scripts/recall.py
  - scripts/check_knowledge_narrative.py
  - scripts/memory_log.py
  - scripts/append_history.py
  - scripts/check_history_sha.py
  - scripts/session_handoff.py
asserts:
  - scripts/memory_log.py::record_units
  - scripts/memory_log.py::release_pass
  - scripts/_doc_common.py::history_outcome_problem
  - scripts/_doc_common.py::release_evidence_status
  - scripts/check_lessons.py::evidence_exists
---

# Lessons, records, and recall

[Back to the substrate map](00_substrate.md). The chain these records live in
is described in [memory and sessions](03_memory_sessions.md); why its anchor
stops where it does is [ADR 0002](../decisions/0002-anchor-threat-model-boundary.md).

## Lessons carry evidence

`docs/lessons.jsonl` holds the rules past failures taught, one JSON object per
line: `id`, `rule` (one line, ≤200 characters), `triggers` (path globs),
`evidence {sha, test}`, `status` (`prose`, `test`, `gate`), `added`,
`last_confirmed`, `superseded_by`. `evidence.test` names a pytest node
(`tests/x.py::test_y`), an eval (`evals::t_name`), or a validator
(`gate::scripts/check_x.py`).

`check_lessons.py` fails when a `test` or `gate` lesson's evidence no longer
exists: a lesson whose proof was deleted is a belief nobody re-checks. It warns
on `prose` (nothing enforces the rule; promote it), on `last_confirmed` three or
more releases behind, and on lessons not yet recorded in the chain. The
promotion path is prose → test → gate, because a rule written down as prose
recurred three times in one session and stopped only when it became a test.

## Only lessons that clear every bar reach a session

At session start `session_handoff` injects lessons whose triggers match the
paths changed in the working tree and the last five commits, exact-path
triggers outranking globs, within their own budget. Lessons are read from
HEAD's COMMITTED `docs/lessons.jsonl`, so a line appended to the working tree
is never injected and a committed one went through git review. The memory
chain is not the binding here: `.substrate/memory/` is gitignored, so a fresh
clone has no chain and would otherwise never see a lesson. A lesson is shown
only if its status is `test` or `gate`, it is not superseded, and its evidence
exists; the text then passes the same sanitizer as every injected line, and an
instruction-shaped rule is dropped. The binding proves EXISTENCE, not
relevance: nothing deterministic can tell that a named test actually exercises
the rule it is attached to, so a misleading committed lesson pointing at an
unrelated real test is caught by review of the commit, not by this check.

## The chain attests the record

`memory_log.py record <file>` appends a `record` event holding the sha256 of
each not-yet-recorded entry of `docs/HISTORY.md`, `docs/REJECTED.md`, or
`docs/lessons.jsonl`. `append_history` and `append_rejected` call it after
every append, through `_doc_common.record_in_chain`, pinned to the repository
they wrote. `verify` then requires every recorded entry to be present, so
editing or deleting one is a `RECORD MISMATCH`. Entries are hashed one by one,
whitespace-normalized, because HISTORY and REJECTED are `merge=union` and a
whole-file hash would break on every legitimate merge. A lesson's unit is its
id and rule text: `status` and `last_confirmed` may move, while a reworded
rule is a mismatch. Change a rule by superseding it. An unrecorded insertion is
not detected by the chain; git history shows it.

`record`, `release-pass`, and `anchor-forced` are reserved event types: the
generic `append` command refuses them, because other gates trust them.

## Outcome labels

Every HISTORY entry written with `append_history` carries `**Outcome:**`:
`shipped-green`, `unverified` (the default), `wip`, `abandoned`,
`reverts:<sha>`, or `supersedes:<sha>`. A revert or supersede must name a sha an
earlier entry documents. `shipped-green` is the only label that claims success
and the only one that needs evidence: a `release-pass` event for that commit, in
a chain that verifies, recorded by a release gate that started on a clean
tracked tree.

The release gate records `release-pass` after every check, re-verifying first
that `.substrate/config` is unchanged, and before it writes the anchor, so the
anchor covers the evidence. `memory_log` re-derives HEAD and refuses if it
moved during the run. The event says the gates passed on that commit;
publication of the anchor is reported separately.

`append_history` requires verified local proof before writing `shipped-green`.
`check_history_sha.py` distinguishes verified proof, unavailable proof, and
invalid proof through `_doc_common.release_evidence_status`. A new or changed
success entry without proof is drift, and so is an entry with two labels.
It polices claims, not silence: an entry with no label claims
nothing and reads as `unverified` through `_doc_common.history_entry_outcome`,
the one reader of outcomes, and the gate reports it without failing. A line that
looks like a label but is not one (`**outcome:** shipped-green`, a list marker, a
Cyrillic `О`, checked on the confusable-folded line) is drift in any entry, since a
human would read a claim the gate reads as silence. v3.9.0
failed every unlabelled entry after the first labelled one, and that could not
survive a union merge: a branch forked before an upgrade appends old-tool entries
below the first labelled one, entries are never edited, and nothing appended
could clear it (domain-lookup, 2026-09-28). Leaving a label off gains nothing,
since only a label can claim success; `append_history` still writes one on every
entry. The order-bound rules (`reverts:`/`supersedes:` and `Correction-of-`
name only an entry their author already had) survive the same merge, because a
union merge keeps each side's own order; a test merges two branches to show it.
The chain is gitignored: a receiving clone may have no chain, or a healthy
unrelated chain without the producing clone's release-pass. An unchanged
committed entry then reports **NOT verifiable in this checkout**, never verified.
The comparison covers the whole entry and its multiplicity, ignoring only
separator newlines. It uses HEAD and, during a merge, resolved MERGE_HEAD
parents; shared entries cannot authorize extra duplicates. Git failures refuse
the comparison. This is provenance for a reported historical claim, not proof
that the claim was true or reviewed. New/edited success entries require local
proof even in a fresh clone. Broken, linked, or unreadable chains and matching
dirty-start-only passes remain invalid. Reader output separates imported
unverified, locally verified, and invalid outcomes.

## Recall and the narrative lint

`./manage.sh recall "<question>" [--budget N]` ranks sections of the knowledge
docs, ADRs, postmortems, checklists, HISTORY entries, rejected approaches, and
lessons with SQLite FTS5 BM25 and prints the top matches with `file:line`,
trimmed to a token budget. The index is built in memory on every call and
discarded, so no stale or planted index can answer for the markdown. Query
terms are quoted before they reach FTS5. Without FTS5 a term-count fallback
runs and says so.

`check_knowledge_narrative.py` warns (it never blocks) when a knowledge doc
narrates release history — past-tense change verbs, version stamps, audit-round
references — instead of stating the current contract. Narrative belongs in
HISTORY, postmortems, and ADRs.
