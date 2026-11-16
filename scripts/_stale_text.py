#!/usr/bin/env python3
"""Stale-text scans: one list for the doc-consistency suite and the record writers.

The doc-consistency suite reads the whole tree for strings that are stale as
agent context: an old product name, a removed command, a config idiom the kit
dropped. It also reads the append-only records (docs/HISTORY.md,
docs/REJECTED.md, AGENT_BUS.md), and an entry there can never be reworded. So
the suite and the writers of those records share this list, and a writer refuses
an entry BEFORE it is recorded when the suite would fail on it afterwards.

Found releasing v3.11.2: a HISTORY entry named the interpreter the release gate
ran on, the pin scan rejected it once it was recorded, and the entry could only
be abandoned along with the gate run behind it. Two things were wrong. The
writer could not know what the scans would say. And the pin scan read a record
of what ran as if it were a pin: a record states which interpreter a gate ran
on, which is a fact about that run, the same reason BENCHMARK.md is not scanned.

This file names the stale strings, so the suite does not scan it.

Stdlib only (the record writers run outside the project venv).
"""
from __future__ import annotations

import re
from typing import NamedTuple

# Append-only records of what happened, relative to the repository root.
RUN_RECORDS = ("docs/HISTORY.md", "docs/REJECTED.md", "AGENT_BUS.md")
# The suite that applies these scans. A repository without it (a consumer
# install strips it) has nothing that would read an entry afterwards.
SUITE = "tests/test_doc_consistency.py"


class Scan(NamedTuple):
    finding: str                    # what a hit is called
    pattern: re.Pattern             # the stale string
    excused_by: re.Pattern | None   # a line that says the thing is gone is not stale
    in_run_records: bool            # False: a record of what ran may state it


SCANS = {
    "old-product-name": Scan(
        "an old product name",
        re.compile(r"META_SYSTEM_(?:KIT|SPEC)|\bKit v2\b|agent_substrate_kit_v2"),
        None, True),
    # `codex_hooks` is the deprecated alias; canonical is `hooks`. \b...\b leaves
    # out identifiers that only contain it.
    "deprecated-codex-flag": Scan(
        "the deprecated codex_hooks flag",
        re.compile(r"\bcodex_hooks\b"),
        re.compile(r"(?i)deprecat|was\s+`?codex_hooks|alias"), True),
    # The substrate targets 3.11+, so a 3.13 pin in a template or script is stale.
    "python-pin": Scan(
        "a Python 3.13 pin",
        re.compile(r"(?i)python[:/ -]?3\.13"),
        None, False),
    # Re-introduces the config-as-shell defect.
    "sources-config": Scan(
        "a recommendation to source .substrate/config",
        re.compile(r"(?<![\w/])\.\s+\.substrate/config|source\s+\.substrate/config"),
        re.compile(r"(?i)remov|deprecat|no longer|do not source|don't source|history"
                   r"|v3\.2\.1[01]|sourced as shell|was \. \.substrate"), True),
    "removed-script": Scan(
        "a reference to a removed script",
        re.compile(r"snapshot_session\.py"),
        re.compile(r"(?i)remov|deprecat|superseded|no longer|changelog"), True),
    "removed-manage-command": Scan(
        "the removed 'manage.sh tools' command",
        re.compile(r"manage\.sh tools"),
        re.compile(r"(?i)remov|deprecat|superseded|no longer"), True),
}


def is_stale(key: str, line: str) -> bool:
    """Does this one line trip the named scan?"""
    scan = SCANS[key]
    if not scan.pattern.search(line):
        return False
    return not (scan.excused_by and scan.excused_by.search(line))


def record_findings(text: str) -> list[str]:
    """Which scans the suite would fail if `text` were appended to a run record,
    as scan keys in scan order. Empty means the entry clears every scan."""
    return [key for key, scan in SCANS.items()
            if scan.in_run_records and any(is_stale(key, line) for line in text.splitlines())]


def refusal(text: str, root) -> str | None:
    """The message a record writer prints instead of recording `text`, or None.
    Only where the suite is present: elsewhere nothing would fail afterwards, and
    refusing would be friction with no check behind it."""
    from pathlib import Path
    if not (Path(root) / SUITE).is_file():
        return None
    found = record_findings(text)
    if not found:
        return None
    parts = [SCANS[key].finding
             + (" (a line that says it was removed or deprecated passes)"
                if SCANS[key].excused_by else "")
             for key in found]
    return ("the entry holds " + "; and ".join(parts) + ". The doc-consistency suite ("
            + SUITE + ") reads this file and would fail on it, and a recorded entry is "
            "never edited, so reword it now.")
