# Plan: memory retrieval and lesson delivery (proposed v3.9 scope)

Status: PROPOSAL — for Codex review before anything is built. Not claimed.
Operator asked for this critique and for Codex to run it before implementation.
Companion operator doc (annotatable): Claude Docs "Substrate Memory & Retrieval Plan".

## Verdict

The substrate is unusually strong on verification and unusually weak on
retrieval. It has the property every memory product is now chasing — memory
bound to evidence, checkable against running code — and almost none of the
machinery those products treat as table stakes: search, ranking, bounded
briefs, outcome labels, decay.

The proof is rounds 34–39. Carry-forward rule 22 ("a redundant guard cannot be
pinned by a single-line revert") recurred as rules 27, 29 and 30. Writing a
lesson down did nothing. The only thing that stopped a recurrence, every time,
was turning it into a test.

## Where it beats the field

- Memory bound to code: `covers:` / `asserts:` on every knowledge doc, a drift
  gate that blocks a script change without a doc review, a test that fails
  when an asserted symbol disappears. No surveyed product does this; the
  closest is a Cline feature REQUEST (cline/cline#14260) for "verified memory".
- Lessons become gates (`check_raw_file_io.py` after twelve recurrences).
- Append-only, SHA-bound HISTORY; tamper-evident chain; anchor.
- Zero LLM calls, zero infrastructure, offline-complete. Mem0's April 2026
  rewrite dropped LLM-driven update/delete; the substrate never carried it.

## Where it is behind — measured on this checkout at 156ef96

| gap | measured | consequence |
| --- | --- | --- |
| retrieval | none: no index, no ranking; lookup is "read the doc for your area" | 16,984 tok of knowledge docs, 22,687 of postmortems, 6,525 of checklists reachable only by convention or grep |
| lesson delivery at start | HISTORY *Summary* injected, cut to ~200 chars mid-word; the *Knowledge* field is never injected | the field designed to carry lessons has no path into context |
| carry-forward rules | 31, prose, in a 19k-tok postmortem opened only by a skill | rule 22 recurred three times in one session |
| tamper-evident chain | 44 events: 43 handoffs, 1 skill-run | attests heartbeats; HISTORY/postmortems/lessons are outside it |
| outcome labels | REJECTED.md has 1 entry; HISTORY has no outcome field | "what happened" is recorded, "what worked vs failed" is not |
| provenance on lessons | no sha, test, or last_confirmed on any rule | confabulation risk: agent-written belief, trusted forever, never re-tested |
| knowledge docs | narrative accretes; two docs split this arc after repeated trimming | 3,000-tok read to find one paragraph |
| architecture lookup | grep | no structural map |
| goals/intent | INTENT.md (828 tok) not in the startup path | operator goals unrecoverable after compaction |

Fixed per-session spend ≈ 3,000 tok (AGENTS.md 1,313; handoff ≤1,000;
HISTORY/REJECTED ≤500). That is fine. The waste is after start.

## Landscape (pages actually opened; reddit/arxiv/mem0.ai were egress-blocked)

| project | steal | avoid |
| --- | --- | --- |
| akitaonrails/ai-memory | markdown source of truth + derived rebuildable SQLite FTS5 index; zero-LLM default; audit log of every mutation | LLM prose consolidation; no tie to code |
| rohitg00/agentmemory | bounded brief (~1.9k tok top-k vs 22k loading everything); provenance origin channel; superseded kept but excluded from search | decay by access frequency |
| Claude Code memory docs | index in context (MEMORY.md ≤200 lines), detail on demand; "skip anything derivable from the codebase" | unverified free-form notes |
| getzep/graphiti | invalidate-never-delete with validity window + superseded_by; facts trace to episodes | Neo4j; per-ingest LLM calls |
| vectorize-io/hindsight | beliefs with evidence quotes + proof counts, refined not overwritten; trimmed to a token limit | 4-strategy retrieval + cross-encoder |
| cline/cline#14260 | lifecycle observed→verified→promoted; evidence = command + exit code + output hash; trust decay for unreferenced items | it is unshipped — this substrate can ship it |
| Aider repo map | PageRank over symbol refs under a 1k-tok budget | nothing |
| VectorSpaceLab/general-agentic-memory | just-in-time: store lightly, compute at read time | LLM segmentation at write |
| Mem0 / Cognee / MemoryLake | Mem0's retreat from LLM update/delete; Cognee's code-graph idea | vector DB, graph DB, hosted memory |

## Plan, priority order (every item keeps existing gates, formats, offline-complete)

1. **Last mile for lessons.** Inject HISTORY *Knowledge* (not *Summary*) at
   session start: whole sentences, one entry per line, ~600 tok. Add a
   ~150-tok digest of INTENT.md. One file: `scripts/session_handoff.py`.
2. **Structured, targeted, provenanced lessons.** Extract the 31 carry-forward
   rules to `docs/lessons.jsonl`: `id, rule(≤200 chars), triggers(globs |
   domains), evidence{sha, test}, status(prose|test|gate), added,
   last_confirmed, superseded_by`.
   - SessionStart/UserPromptSubmit hook injects only rules whose triggers match
     `git status` / the task — ≤500 tok, not a 19k-tok postmortem.
   - Validator fails when `evidence.test` no longer exists (the `asserts:` rule
     applied to lessons). `last_confirmed` older than 3 releases → surfaced for
     review, never silently trusted. Superseded rules keep `superseded_by`.
   - Promotion is the point: status must move prose→test→gate; a rule stuck at
     prose for 3 releases is itself a finding.
3. **Retrieval, no LLM, no infra.** SQLite FTS5 (stdlib). Derived, gitignored
   index over knowledge-doc SECTIONS, postmortem sections, HISTORY entries,
   checklists, lessons; rebuildable from markdown. `./manage.sh recall "<q>"
   --budget 600` → top-k sections with file:line, trimmed to budget. Skills
   that say "read the doc for your area" read a section instead. BM25 only.
4. **Knowledge inside the chain.** Appending HISTORY/REJECTED/lessons appends a
   `record` event with the file's content hash; `verify` cross-checks. The
   chain then attests the record, not 43 heartbeats.
5. **Outcome labels; use REJECTED.** HISTORY gets `outcome` (shipped-green |
   reverted | superseded-by <sha>) set by the release gate. A hook prompts for
   a REJECTED entry when a branch is abandoned or a fix replaced within N
   commits. Retrieval returns worked AND failed for the same area.
6. **No narrative in knowledge docs.** Lint flags past-tense narrative ("used
   to", "once", "before v3.8.x") under docs/knowledge/. Generate a
   section-level index into 00_substrate.md. Budget can likely drop 3000→2000.
7. **Repo map.** `./manage.sh map`: Python `ast` over scripts/, symbols ranked
   by reference count, ≤1k tok, on demand.

| # | files touched | new tok at start | effort |
| --- | --- | --- | --- |
| 1 | session_handoff.py | +750 | hours |
| 2 | new lessons.jsonl, one hook, one validator, postmortem extraction | ≤500 when triggered | days |
| 3 | new script, manage.sh, skills | 0 (on demand) | days |
| 4 | memory_log.py, append_history.py, append_rejected.py | 0 | hours |
| 5 | append_history.py, release_gate.sh, one hook | 0 | hours |
| 6 | one validator, 00_substrate.md generator | 0 | days |
| 7 | new script, manage.sh | 0 (on demand) | days |

## Not adopting

Vector DBs, graph DBs, hosted memory, LLM-written consolidation as a default:
each is a writable trust surface (the class rounds 34–39 attacked), each
breaks offline-complete. Embeddings only as an opt-in tier after BM25 is shown
to miss. Decay by access frequency is out; decay by unconfirmed age tied to a
re-confirming test is in.

## Questions for Codex round 40 — attack the design, not the code (there is none yet)

1. Item 2 creates a new agent-writable trust input (`lessons.jsonl`) that a
   hook injects into context. What is the minimum evidence binding that stops
   a forged lesson from becoming an instruction? Is `evidence.test` existing
   enough, or must the test have PASSED at `evidence.sha`?
2. Item 3's index is derived and gitignored. Name the attack where a stale or
   planted index returns a section the markdown no longer contains, and say
   whether "rebuild before every recall" is an acceptable cost or the index
   needs its own hash pin in the chain.
3. Item 4 puts content hashes of HISTORY/REJECTED/lessons in the chain. Does
   that change the threat model of the anchor in any way you can name — in
   particular, does a suffix rewrite of HISTORY now become detectable, or does
   it just move the undetectable window?
4. Item 5's `outcome` field is set by the release gate. Which of the six gate
   findings from rounds 36–39 (pre-state certified as post-state, stale rule,
   A-B-A, -f vs -e, unattested helper, unpinned load) applies to it, and how
   should it be written so none do?
5. Is there a legitimate workflow where injecting matched lessons at
   UserPromptSubmit is a false positive (wrong lesson, wrong moment)? If so,
   should injection be SessionStart-only?
6. Which items would you drop, reorder, or merge, and why?

Nothing here is claimed. No implementation file is touched by this plan.
