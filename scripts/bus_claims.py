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

UNPARSEABLE CLAIMS ARE REPORTED (v3.9.1). A consumer wrote claims as
`CLAIM <paths> — why — agent — date`, which this grammar does not match, and the
reader printed "no open claims" while four were open. A claim-shaped line the
grammar cannot read is now counted and shown, and "no open claims" is never
printed while such lines exist.

DIGEST (v3.9.1): `--digest` prints the open claims, then the last N entries
(`--n`, default 15), each capped — what an agent needs before starting work,
instead of reading a bus that had grown to ~450k tokens in one consumer.

ADVISORY ONLY — never wired into any gate. Coordination state must not be
able to block a commit. Exit 0 always; `--strict` exits 1 when expired
claims exist (for agents that want a hard signal in their own loop).
Missing or malformed bus file: reports and exits 0 (fail open — this is a
reader of coordination prose, not a trust anchor).
"""
from __future__ import annotations

import argparse
import math
import os
import re
import sys
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _doc_common import repo_root

# Bus text is written by agents and shown to terminals and other agents' context:
# a C0/C1 control (terminal escapes), a bidi override or an invisible character is
# shown as `?` rather than passed through (v3.9.1).
_UNPRINTABLE = re.compile("[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e"
                          "\u2060-\u2064\u2066-\u2069\ufeff]")


def _shown(s: str) -> str:
    return _UNPRINTABLE.sub("?", s)

# v3.8.44 (round-27, surfaced by the gate's new interprocedural pass): the bus
# is agent-writable and this reader opened it raw, so a symlinked/hard-linked
# AGENT_BUS.md fed OUTSIDE claim prose to every agent reading lease state, and
# a FIFO would hang the reader. Advisory output is still input to agents.
try:
    from _doc_common import safe_read_bytes as _safe_read_bytes
except Exception:  # pragma: no cover - stripped install
    def _safe_read_bytes(path, root=None, max_bytes=None, tail_bytes=None):
        return None

_MAX_ENTRIES = 10_000       # keep the newest N entry lines (filler is skipped, not counted)
_BUS_HARD_CAP = 64_000_000  # absolute byte ceiling for a pathological bus (then tail-fallback)
_ENTRY = re.compile(
    r"^- \[(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|\+00:00))\] "
    r"\*\*(?P<agent>[A-Za-z0-9_-]+)\*\*: "
    r"(?P<verb>CLAIM EXPANSION|CLAIM|RECLAIM|HEARTBEAT|RELEASE)\b(?P<rest>.*)$")
_VERSION_NEAR_VERB = re.compile(r"^.{0,80}?v?(\d+\.\d+\.\d+)")
# A line that is trying to be a claim-protocol entry: the verb near the start, after
# an optional list marker, timestamp, and/or bold agent name.
_CLAIM_LIKE = re.compile(
    r"^\s*(?:[-*]\s+)?(?:\[[^\]]{0,40}\]\s*)?(?:\*\*[^*]{1,40}\*\*:?\s*)?"
    r"(?:CLAIM EXPANSION|CLAIM|RECLAIM|HEARTBEAT|RELEASE)\b")
_ANY_ENTRY = re.compile(r"^- \[\d{4}-\d{2}-\d{2}T[^\]]{0,30}\] \*\*[A-Za-z0-9_-]+\*\*:")
_DEFAULT_TTL_HOURS = 72.0


def _ttl() -> timedelta:
    # v3.8.37 (round-20 P3): a garbage override must fall back to the default,
    # never crash or invert the meaning. nan/inf make every comparison nonsense
    # (nan → nothing ever expires; -1 → everything is instantly expired), so
    # only a finite POSITIVE value is honored.
    try:
        hours = float(os.environ.get("SUBSTRATE_CLAIM_TTL_HOURS") or _DEFAULT_TTL_HOURS)
    except ValueError:
        hours = _DEFAULT_TTL_HOURS
    if not math.isfinite(hours) or hours <= 0:
        hours = _DEFAULT_TTL_HOURS
    return timedelta(hours=hours)


def _parse_ts(raw: str) -> datetime | None:
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_bus_tail(bus: Path, root: Path | None = None) -> str:
    """The last _MAX_ENTRIES *entry* lines of the bus, newest-preserving.

    v3.8.36 (round-19) made this keep the file's TAIL so a released lease past
    the byte bound stopped reading as ACTIVE. But a pure byte tail had the
    inverse flaw (round-20 P2): a single fresh CLAIM at the TOP followed by
    megabytes of non-entry filler fell out of the window and the reader saw NO
    open claims. The fix streams the whole file (bounded by a generous hard
    byte ceiling) and keeps only ENTRY lines in a bounded deque — filler is
    free to skip and can never displace a real claim, while the deque still
    keeps the NEWEST entries when a bus genuinely accumulates that many."""
    entries: deque = deque(maxlen=_MAX_ENTRIES)
    # v3.8.44 (round-27): both reads went through bus.open(), which follows a
    # symlinked leaf and BLOCKS on a FIFO. The guarded reader enforces
    # O_NOFOLLOW|O_NONBLOCK + S_ISREG + st_nlink==1, and its max_bytes/tail_bytes
    # split maps exactly onto the two branches this function already had:
    # whole file under the hard cap, else a byte tail of the end.
    raw = _safe_read_bytes(bus, root, max_bytes=_BUS_HARD_CAP)
    truncated = raw is None
    if truncated:
        # Pathological bus beyond the hard cap: fall back to a byte tail of the
        # end so we still report the newest state rather than nothing.
        raw = _safe_read_bytes(bus, root, tail_bytes=_BUS_HARD_CAP)
    if raw is None:
        return ""      # absent or an unsafe leaf — advisory reader, no state
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        nl = text.find("\n")
        text = text[nl + 1:] if nl >= 0 else text
    for line in text.splitlines():
        if _ENTRY.match(line):
            entries.append(line)
    return "\n".join(entries)


def unparsed_claim_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every claim-shaped line the entry grammar rejects."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        if _CLAIM_LIKE.match(line) and not _ENTRY.match(line):
            out.append((n, line))
    return out


def recent_entries(text: str, n: int, width: int = 300) -> list[str]:
    """The last `n` bus entries (any verb), newest last, each capped at `width`."""
    lines = [ln for ln in text.splitlines() if _ANY_ENTRY.match(ln)]
    return [ln if len(ln) <= width else ln[:width - 1] + "\u2026" for ln in lines[-n:]]


def _read_whole(bus: Path, root: Path) -> str:
    raw = _safe_read_bytes(bus, root, max_bytes=_BUS_HARD_CAP)
    if raw is None:
        raw = _safe_read_bytes(bus, root, tail_bytes=_BUS_HARD_CAP) or b""
    return raw.decode("utf-8", errors="replace")


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
    violations: list[str] = []
    # v3.8.37 (round-20 P2): a FUTURE-dated entry is malformed — it would never
    # expire (now - since is negative) and would block a legitimate reclaim
    # forever. Reject anything past a small clock-skew tolerance.
    future_cutoff = now + timedelta(minutes=5)
    for seq, line in enumerate(text.splitlines()):
        m = _ENTRY.match(line)
        if not m:
            continue
        ts = _parse_ts(m.group("ts"))
        if ts is None:
            continue  # malformed timestamp: not an entry this reader can use
        if ts > future_cutoff:
            vm0 = _VERSION_NEAR_VERB.match(m.group("rest"))
            k0 = vm0.group(1) if vm0 else "(unkeyed)"
            violations.append(f"v{k0}: {m.group('verb')} by {m.group('agent')} dated "
                              f"{ts.isoformat()} ignored — timestamp is in the future")
            continue
        vm = _VERSION_NEAR_VERB.match(m.group("rest"))
        events.append((ts, seq, m.group("agent"), m.group("verb"),
                       vm.group(1) if vm else None, m.group("rest").strip()[:80]))
    events.sort(key=lambda e: (e[0], e[1]))
    ttl = _ttl()
    keyed: dict[str, dict] = {}
    unkeyed: list[dict] = []
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
            # v3.8.39 (round-22): a plain CLAIM may only take a FREE/never-owned
            # key. If ANOTHER agent already owns it — fresh OR expired — the
            # taker must post an explicit RECLAIM; a plain foreign CLAIM is a
            # reported no-op. Round-21 fixed HEARTBEAT/EXPANSION/RELEASE but left
            # this path, so an expired lease still changed hands via CLAIM.
            if cur is not None and cur["agent"] != agent and cur["state"] != "released":
                why = "still fresh" if holds else "expired — post an explicit RECLAIM to take it"
                violations.append(f"v{key}: CLAIM by {agent} at {ts.isoformat()} ignored — "
                                  f"{cur['agent']}'s lease is {why}")
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
            # v3.8.37 (round-20 P2): a refresh only ever extends a lease that
            # HOLDS and is owned by the actor. It must NOT silently claim an
            # EXPIRED or free key — that path let a foreign HEARTBEAT take over
            # a lapsed lease with no RECLAIM. An expired/free key requires an
            # explicit CLAIM/RECLAIM; anything else is a reported no-op.
            if holds and cur["agent"] == agent:
                cur["since"] = ts  # refresh the OWNER's lease
            elif holds:
                violations.append(f"v{key}: {verb} by {agent} at {ts.isoformat()} ignored — "
                                  f"lease belongs to {cur['agent']}")
            elif cur is not None:
                violations.append(f"v{key}: {verb} by {agent} at {ts.isoformat()} ignored — "
                                  "the lease is expired/closed; post an explicit RECLAIM to take it")
            else:
                violations.append(f"v{key}: {verb} by {agent} at {ts.isoformat()} ignored — "
                                  "no lease to refresh; post an explicit CLAIM")
        elif verb == "RELEASE":
            # v3.8.37 (round-20 P2): only the OWNER may release, and only a lease
            # that still exists. A foreign RELEASE — fresh OR expired — is a
            # violation, not a silent close (the expired case must be RECLAIMed,
            # not released out from under its owner).
            if cur is None:
                keyed[key] = {"key": key, "agent": agent, "since": ts,
                              "text": txt, "state": "released"}
            elif cur["agent"] != agent:
                violations.append(f"v{key}: RELEASE by {agent} at {ts.isoformat()} ignored — "
                                  f"only the owner ({cur['agent']}) may release this lease")
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
    ap.add_argument("--digest", action="store_true",
                    help="open claims + the last N entries: read this, not the whole bus")
    ap.add_argument("--n", type=int, default=15, help="entries shown by --digest")
    a = ap.parse_args(argv)
    bus = repo_root() / "AGENT_BUS.md"
    # v3.8.39/40 (round-22/23): a symlinked, non-regular, OR HARD-LINKED
    # AGENT_BUS.md must not be read — coordination state would be derived from an
    # outside inode. A hard link (st_nlink>1) shares the same bytes as an outside
    # file while passing every is_symlink/is_file check (the v3.8.25 class), so
    # check it explicitly via lstat. Advisory reader → reported no-op.
    if bus.is_symlink() or (bus.exists() and not bus.is_file()):
        print("bus-claims: refusing — AGENT_BUS.md is a symlink or non-regular file; "
              "not reading coordination state from outside the repo.")
        return 0
    try:
        if bus.exists() and bus.lstat().st_nlink > 1:
            print("bus-claims: refusing — AGENT_BUS.md has multiple hard links; "
                  "not reading coordination state from a shared inode.")
            return 0
    except OSError:
        return 0
    if not bus.is_file():
        print("bus-claims: no AGENT_BUS.md — nothing to report.")
        return 0
    try:
        text = read_bus_tail(bus, repo_root())
    except OSError as e:
        print(f"bus-claims: cannot read AGENT_BUS.md ({e}) — advisory reader, not failing.")
        return 0
    now = datetime.now(UTC)
    claims, violations = parse_claims(text, now)
    ttl_h = _ttl().total_seconds() / 3600
    whole = _read_whole(bus, repo_root())
    unparsed = unparsed_claim_lines(whole)
    for v in violations:
        print(f"  PROTOCOL VIOLATION (ignored): {_shown(v)}")
    if unparsed:
        print(f"bus-claims: WARNING — {len(unparsed)} claim-like line(s) do not match the "
              "grammar `- [<ISO-8601>Z] **<agent>**: CLAIM ...` and are NOT counted below:")
        for n, line in unparsed[-5:]:
            print(f"    AGENT_BUS.md:{n}: {_shown(line[:160])}")
    shown = [c for c in claims if a.all or c["state"] != "released"]
    if a.digest:
        size = len(whole.encode("utf-8"))
        print(f"bus digest: {size // 1024} KiB (~{size // 4000}k tokens) — read this, "
              "not the whole file")
    if not shown:
        if unparsed:
            print(f"bus-claims: no open claims IN THE PARSED GRAMMAR (TTL {ttl_h:g}h) — "
                  f"{len(unparsed)} unparsed claim-like line(s) above may be open.")
        else:
            print(f"bus-claims: no open claims (TTL {ttl_h:g}h).")
        if a.digest:
            _print_recent(whole, a.n)
        return 0
    expired = 0
    for c in sorted(shown, key=lambda c: c["since"]):
        age_h = (now - c["since"]).total_seconds() / 3600
        label = c["key"] and f"v{c['key']}" or "(unkeyed)"
        print(f"  {c['state'].upper():8} {_shown(label):12} {_shown(c['agent']):8} "
              f"age {age_h:6.1f}h  {_shown(c['text'])}")
        if c["state"] == "expired":
            expired += 1
    if expired:
        print(f"bus-claims: {expired} EXPIRED lease(s) (TTL {ttl_h:g}h) — per the bus "
              "protocol any agent may RECLAIM them now.")
    if a.digest:
        _print_recent(whole, a.n)
    return 1 if (a.strict and expired) else 0


def _print_recent(whole: str, n: int) -> None:
    rec = recent_entries(whole, max(1, n))
    print(f"last {len(rec)} entr{'y' if len(rec) == 1 else 'ies'} (newest last):")
    for ln in rec:
        print(f"  {_shown(ln)}")


if __name__ == "__main__":
    sys.exit(main())
