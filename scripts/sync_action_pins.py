#!/usr/bin/env python3
"""Copy the kit's GitHub Action pins into the workflow templates consumers receive.

Dependabot bumps the actions in `.github/workflows/*.yml` and cannot see
`workflows/*.yml.template`, so every bump arrived red: a test requires both to pin
the same commit (v3.10.6). This rewrites each template `uses:` line whose action
the kit also uses to the kit's exact `action@<sha> # <version>`; nothing else in a
template changes. `--check` reports drift and exits 1 without writing.

An action the kit pins to two different commits is an error (exit 2): there is
no single pin to copy. Templates for actions the kit never runs (cosign-installer)
are left alone. A consumer install has no templates, so this does nothing there.

Usage: scripts/sync_action_pins.py [--check] [--root DIR]
Exit codes: 0 in sync (or synced) | 1 drift found with --check | 2 error.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import safe_atomic_write, safe_read_text  # noqa: E402

# `uses: owner/action[/path]@ref [# comment]`, as a step key or a list item.
USES = re.compile(r"^(?P<lead>[ \t]*(?:-[ \t]+)?uses:[ \t]*)"
                  r"(?P<action>[\w.-]+/[\w./-]+)@(?P<ref>[^\s#]+)"
                  r"(?P<comment>[ \t]*#[^\n]*)?$")
PINNED = re.compile(r"[0-9a-f]{40}")
MAX_BYTES = 1 << 20


def kit_pins(root: Path) -> tuple[dict[str, str], list[str]]:
    """{action: "action@sha # version"} from the kit's own workflows, and errors."""
    seen: dict[str, set[str]] = {}
    for path in sorted((root / ".github" / "workflows").glob("*.yml")):
        text = safe_read_text(path, root, max_bytes=MAX_BYTES)
        if text is None:
            return {}, [f"{path.relative_to(root)}: unreadable or unsafe"]
        for line in text.split("\n"):
            m = USES.match(line)
            if m and PINNED.fullmatch(m["ref"]):
                comment = (m["comment"] or "").strip()
                seen.setdefault(m["action"], set()).add(f"{m['action']}@{m['ref']} {comment}".strip())
    errors = [f"{action}: the kit's own workflows pin it {len(pins)} ways: {sorted(pins)}"
              for action, pins in sorted(seen.items()) if len(pins) != 1]
    return {action: next(iter(pins)) for action, pins in seen.items() if len(pins) == 1}, errors


def sync_text(text: str, pins: dict[str, str]) -> tuple[str, list[str]]:
    """The template text with each kit-known action re-pinned, and what changed."""
    out, changes = [], []
    for line in text.split("\n"):
        m = USES.match(line)
        if m and m["action"] in pins:
            new = m["lead"] + pins[m["action"]]
            if new != line:
                changes.append(f"{m['action']}@{m['ref'][:12]} -> {pins[m['action']].split('@', 1)[1][:12]}")
            line = new
        out.append(line)
    return "\n".join(out), changes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="report drift and exit 1; write nothing")
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    templates = sorted((root / "workflows").glob("*.yml.template"))
    if not templates:
        print("sync-pins: no workflows/*.yml.template here (a consumer install); nothing to do")
        return 0
    pins, errors = kit_pins(root)
    if errors:
        for e in errors:
            print(f"sync-pins: {e}", file=sys.stderr)
        return 2
    drift = 0
    for path in templates:
        text = safe_read_text(path, root, max_bytes=MAX_BYTES)
        if text is None:
            print(f"sync-pins: {path.relative_to(root)}: unreadable or unsafe", file=sys.stderr)
            return 2
        new, changes = sync_text(text, pins)
        if not changes:
            continue
        drift += len(changes)
        for c in changes:
            print(f"{'drift' if args.check else 'synced'}: {path.relative_to(root)}: {c}")
        if not args.check:
            safe_atomic_write(path, new, root=root)
    if args.check and drift:
        print(f"sync-pins: {drift} template pin(s) differ from the kit; run ./manage.sh sync-pins",
              file=sys.stderr)
        return 1
    print(f"sync-pins: {'in sync' if not drift else f'{drift} pin(s) synced'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
