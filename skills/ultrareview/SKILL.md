---
name: ultrareview
description: Run a 7-lens multi-agent review of a commit cluster (6 parallel specialist lenses + 1 synthesizer). Use for non-trivial commit clusters before merge, or when the operator asks for a deep review without leaving the session.
---

# ultrareview

The closest in-session substitute for a cloud multi-agent review.
Costs real tokens (6 parallel subagents + 1 synthesizer) — reserve
for non-trivial clusters.

## Steps

1. Get the diff and prompt block:

```bash
scripts/diy_ultrareview.sh HEAD~3..HEAD   # or main..HEAD, or a SHA
```

2. Spawn lenses 1–6 IN PARALLEL (one message, six subagent calls).
   Full prompt text lives in `docs/templates/diy_ultrareview_prompts.md`
   — the script references it; subagents read it themselves, the main
   context never loads it:

   - lens-1 adversarial-input
   - lens-2 sibling-cluster
   - lens-3 doc-drift
   - lens-4 verbatim-shape
   - lens-5 forcing-function-gameability
   - lens-6 external-CWE-corpus (needs web access)

3. After all six return, spawn lens-7 (synthesizer) sequentially with
   the six reports as input.

4. Treat the synthesizer output as a pre-merge review: every real
   finding gets fixed or explicitly dispositioned before merge.

## Token rule

Each lens returns ≤500 tokens of findings. The main context receives
seven compact reports, never the raw prompt corpus or full re-reads
of the diff.
