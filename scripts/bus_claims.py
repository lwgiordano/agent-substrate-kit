#!/usr/bin/env python3
"""Deterministic claim-state reader for AGENT_BUS.md — leases, not vibes.

WHY (v3.8.35). The bus is the human-readable coordination channel between
agents, but a bare CLAIM has no lifetime: a claimant that goes silent holds
its files forever, and only operator intervention can break the stall (the
motivating incident: a claim sat unstarted for 9 days). This tool gives
claims LEASE semantics without any new infrastructure — the bus file stays
the single source of truth, carried by git, and this parser derives claim
state deterministically from it.

Grammar (one entry per `- [<ISO-8601>Z] **<agent>**: <VERB> ...` line):
  CLAIM / RECLAIM            -> lease starts (agent, timestamp)
  CLAIM EXPANSION / HEARTBEAT -> lease timestamp refreshes (same agent)
  RELEASE                    -> lease closed
Keys: the first version token (vX.Y.Z) within 80 chars after the verb.
A claim with no version token is UNKEYED and is considered released by the
same agent's next later RELEASE (the historical area-claim convention).

A lease older than the TTL (default 72h, SUBSTRATE_CLAIM_TTL_HOURS to
override) is EXPIRED: per the bus protocol any agent may RECLAIM it by
posting a RECLAIM entry — no operator needed.

ADVISORY ONLY — never wired into any gate. Coordination state must not be
able to block a commit. Exit 0 always; `--strict` exits 1 when expired
claims exist (for agents that want a hard signal in their own loop).
Missing or malformed bus file: reports and exits 0 (fail open — this is a
reader of coordination prose, not a trust anchor).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root

_BUS_MAX_READ = 4_000_000  # bounded read; the bus grows unboundedly
_ENTRY = re.compile(
    r"^- \[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|\+00:00))\] "
    r"\*\*(?P<agent>[A-Za-z0-9_-]+)\*\*: "
    r"(?P<verb>CLAIM EXPANSION|CLAIM|RECLAIM|HEARTBEAT|RELEASE)\b(?P<rest>.*)$")
_VERSION_NEAR_VERB = re.compile(r"^.{0,80}?v?(\d+\.\d+\.\d+)")
_DEFAULT_TTL_HOURS = 72.0


def _ttl() -> timedelta:
    try:
        hours = float(os.environ.get("SUBSTRATE_CLAIM_TTL_HOURS") or _DEFAULT_TTL_HOURS)
    except ValueError:
        hours = _DEFAULT_TTL_HOURS
    return timedelta(hours=hours)


def _parse_ts(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_claims(text: str, now: datetime) -> list[dict]:
    """Chronological state machine over bus entries -> list of claim states."""
    keyed: dict[str, dict] = {}
    unkeyed: list[dict] = []
    for line in text.splitlines():
        m = _ENTRY.match(line)
        if not m:
            continue
        ts = _parse_ts(m.group("ts"))
        if ts is None:
            continue  # malformed timestamp: not an entry this reader can use
        agent, verb, rest = m.group("agent"), m.group("verb"), m.group("rest")
        vm = _VERSION_NEAR_VERB.match(rest)
        key = vm.group(1) if vm else None
        if key is None:
            if verb in ("CLAIM", "RECLAIM"):
                unkeyed.append({"key": None, "agent": agent, "since": ts,
                                "text": rest.strip()[:80], "state": "active"})
            elif verb == "RELEASE":
                for c in unkeyed:  # same-agent later RELEASE closes area claims
                    if c["agent"] == agent and c["state"] == "active" and ts > c["since"]:
                        c["state"] = "released"
            continue
        cur = keyed.get(key)
        if verb in ("CLAIM", "RECLAIM"):
            keyed[key] = {"key": key, "agent": agent, "since": ts,
                          "text": rest.strip()[:80], "state": "active"}
        elif verb in ("CLAIM EXPANSION", "HEARTBEAT"):
            if cur is not None and cur["state"] == "active":
                cur["since"] = ts  # refresh the lease
            else:  # expansion without a base claim still claims
                keyed[key] = {"key": key, "agent": agent, "since": ts,
                              "text": rest.strip()[:80], "state": "active"}
        elif verb == "RELEASE":
            if cur is not None:
                cur["state"] = "released"
            else:  # release without recorded claim — key is simply closed
                keyed[key] = {"key": key, "agent": agent, "since": ts,
                              "text": rest.strip()[:80], "state": "released"}
    out = list(keyed.values()) + unkeyed
    ttl = _ttl()
    for c in out:
        if c["state"] == "active" and now - c["since"] > ttl:
            c["state"] = "expired"
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Report AGENT_BUS.md claim leases.")
    ap.add_argument("--all", action="store_true",
                    help="include released claims (default: active/expired only)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when any claim lease is expired")
    a = ap.parse_args(argv)
    bus = repo_root() / "AGENT_BUS.md"
    if not bus.is_file():
        print("bus-claims: no AGENT_BUS.md — nothing to report.")
        return 0
    try:
        text = bus.read_text(encoding="utf-8", errors="replace")[:_BUS_MAX_READ]
    except OSError as e:
        print(f"bus-claims: cannot read AGENT_BUS.md ({e}) — advisory reader, not failing.")
        return 0
    now = datetime.now(UTC)
    claims = parse_claims(text, now)
    ttl_h = _ttl().total_seconds() / 3600
    shown = [c for c in claims if a.all or c["state"] != "released"]
    if not shown:
        print(f"bus-claims: no open claims (TTL {ttl_h:g}h).")
        return 0
    expired = 0
    for c in sorted(shown, key=lambda c: c["since"]):
        age_h = (now - c["since"]).total_seconds() / 3600
        label = c["key"] and f"v{c['key']}" or "(unkeyed)"
        print(f"  {c['state'].upper():8} {label:12} {c['agent']:8} "
              f"age {age_h:6.1f}h  {c['text']}")
        if c["state"] == "expired":
            expired += 1
    if expired:
        print(f"bus-claims: {expired} EXPIRED lease(s) (TTL {ttl_h:g}h) — per the bus "
              "protocol any agent may RECLAIM them now.")
    return 1 if (a.strict and expired) else 0


if __name__ == "__main__":
    sys.exit(main())
