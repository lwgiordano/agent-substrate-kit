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


def read_bus_tail(bus: Path) -> str:
    """Last _BUS_MAX_READ bytes of the bus. v3.8.36 (Codex round-19): the bus
    is APPEND-ONLY, so the newest — authoritative — state lives at the BOTTOM;
    the old head-slice (`read_text()[:N]`) kept the OLDEST bytes and reported
    a long-released lease as ACTIVE once the file outgrew the bound. A partial
    first line after seeking is dropped."""
    with bus.open("rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        start = max(0, size - _BUS_MAX_READ)
        fh.seek(start)
        raw = fh.read()
    text = raw.decode("utf-8", errors="replace")
    if start > 0:
        nl = text.find("\n")
        text = text[nl + 1:] if nl >= 0 else ""
    return text


def _expired_at(lease: dict, ts: datetime, ttl: timedelta) -> bool:
    return ts - lease["since"] > ttl


def parse_claims(text: str, now: datetime) -> tuple[list[dict], list[str]]:
    """Chronological state machine over bus entries.

    Returns (claims, violations). v3.8.36 corrections (Codex round-19):
    - Events are SORTED BY TIMESTAMP (file order only as tie-break) before
      folding: the bus is merge=union, so physical order is not chronology —
      a stale branch's 09:00 RELEASE merged after a 10:00 CLAIM must not roll
      the lease backward.
    - Transitions validate OWNER and EXPIRY: HEARTBEAT/EXPANSION refresh and
      RELEASE close only the OWNER's lease; RECLAIM takes a lease only when
      it is already released or EXPIRED AS OF the reclaim entry's timestamp.
      An invalid transition changes nothing and is reported as a violation —
      a foreign RELEASE or premature RECLAIM must not silently end a fresh
      lease. (TTL for historical expiry checks is the configured TTL; the
      protocol does not model TTL changes over time.)
    """
    events = []
    for seq, line in enumerate(text.splitlines()):
        m = _ENTRY.match(line)
        if not m:
            continue
        ts = _parse_ts(m.group("ts"))
        if ts is None:
            continue  # malformed timestamp: not an entry this reader can use
        vm = _VERSION_NEAR_VERB.match(m.group("rest"))
        events.append((ts, seq, m.group("agent"), m.group("verb"),
                       vm.group(1) if vm else None, m.group("rest").strip()[:80]))
    events.sort(key=lambda e: (e[0], e[1]))
    ttl = _ttl()
    keyed: dict[str, dict] = {}
    unkeyed: list[dict] = []
    violations: list[str] = []
    for ts, _seq, agent, verb, key, txt in events:
        if key is None:
            if verb in ("CLAIM", "RECLAIM"):
                unkeyed.append({"key": None, "agent": agent, "since": ts,
                                "text": txt, "state": "active"})
            elif verb == "RELEASE":
                for c in unkeyed:  # same-agent later RELEASE closes area claims
                    if c["agent"] == agent and c["state"] == "active" and ts > c["since"]:
                        c["state"] = "released"
            continue
        cur = keyed.get(key)
        holds = (cur is not None and cur["state"] == "active"
                 and not _expired_at(cur, ts, ttl))
        if verb == "CLAIM":
            if holds and cur["agent"] != agent:
                violations.append(f"v{key}: CLAIM by {agent} at {ts.isoformat()} ignored — "
                                  f"{cur['agent']}'s lease is still fresh")
                continue
            keyed[key] = {"key": key, "agent": agent, "since": ts,
                          "text": txt, "state": "active"}
        elif verb == "RECLAIM":
            if holds:
                violations.append(f"v{key}: RECLAIM by {agent} at {ts.isoformat()} ignored — "
                                  f"{cur['agent']}'s lease is not expired (protocol: "
                                  "reclaim only past TTL)")
                continue
            keyed[key] = {"key": key, "agent": agent, "since": ts,
                          "text": txt, "state": "active"}
        elif verb in ("CLAIM EXPANSION", "HEARTBEAT"):
            if holds and cur["agent"] == agent:
                cur["since"] = ts  # refresh the OWNER's lease
            elif holds:
                violations.append(f"v{key}: {verb} by {agent} at {ts.isoformat()} ignored — "
                                  f"lease belongs to {cur['agent']}")
            else:  # expansion onto a free/expired key still claims it
                keyed[key] = {"key": key, "agent": agent, "since": ts,
                              "text": txt, "state": "active"}
        elif verb == "RELEASE":
            if cur is None:
                keyed[key] = {"key": key, "agent": agent, "since": ts,
                              "text": txt, "state": "released"}
            elif holds and cur["agent"] != agent:
                violations.append(f"v{key}: RELEASE by {agent} at {ts.isoformat()} ignored — "
                                  f"only the owner ({cur['agent']}) may release a fresh lease")
            else:
                cur["state"] = "released"
    out = list(keyed.values()) + unkeyed
    for c in out:
        if c["state"] == "active" and now - c["since"] > ttl:
            c["state"] = "expired"
    return out, violations


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
        text = read_bus_tail(bus)
    except OSError as e:
        print(f"bus-claims: cannot read AGENT_BUS.md ({e}) — advisory reader, not failing.")
        return 0
    now = datetime.now(UTC)
    claims, violations = parse_claims(text, now)
    ttl_h = _ttl().total_seconds() / 3600
    for v in violations:
        print(f"  PROTOCOL VIOLATION (ignored): {v}")
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
