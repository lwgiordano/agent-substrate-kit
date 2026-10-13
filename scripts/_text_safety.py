#!/usr/bin/env python3
"""Shared text-normalization helpers for the untrusted-context sanitizers.

The session-handoff and memory-log sanitizers strip instruction-like /
command-like directives from agent-authored text before it can be re-injected
into a future session. Those checks are literal-ASCII regexes, so an attacker
can evade them with Unicode look-alikes (" ignоre " with a Cyrillic о),
full-width forms, zero-width joiners, or leetspeak ("1gn0re"). This module
produces a NORMALIZED VIEW of a string purely for the DANGER SCAN — the caller
still emits the original text; only the *match decision* is made against the
folded view.

Design notes / why it is shaped this way:
  - NFKC folds full-width and other compatibility forms to ASCII, but it does
    NOT fold cross-script confusables (Cyrillic о U+043E stays U+043E). So the
    mixed-script map below is the load-bearing part; NFKC is the full-width half.
  - We fold KNOWN confusables to Latin and then run the SAME keyword patterns.
    We deliberately do NOT flag "any residual non-ASCII letter" as dangerous —
    that would strip benign accented text (café, résumé). A homoglyph attack
    folds to a real keyword; a benign accented word does not.
  - Leetspeak digits/symbols are folded to letters for the scan only. Because we
    also scan the un-folded variant, tokens that legitimately contain digits
    (base64) are still matched on the raw side.
  - Kit command vocabulary (manage.sh) is neutralized so a filename suffix does
    not read as a bare `sh` shell invocation (the v3.8.1 false-positive).

Stdlib only (hook scripts run outside the project venv).
"""
from __future__ import annotations

import unicodedata

# Cross-script Latin look-alikes → Latin. High-frequency Cyrillic/Greek homoglyphs
# that spell English attack keywords (ignore/previous/instructions/disable/rules/
# system/bypass/jailbreak/curl/bash/...). Not exhaustive TR39 — the practical set.
_CONFUSABLE_PAIRS = [
    # Cyrillic lower
    ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"), ("с", "c"), ("у", "y"),
    ("х", "x"), ("і", "i"), ("ј", "j"), ("ѕ", "s"), ("ԁ", "d"), ("һ", "h"),
    ("к", "k"), ("м", "m"), ("т", "t"), ("в", "b"), ("ո", "n"),
    # Cyrillic upper (folded to lower Latin; final .lower() would anyway)
    ("А", "a"), ("Е", "e"), ("О", "o"), ("Р", "p"), ("С", "c"), ("У", "y"),
    ("Х", "x"), ("В", "b"), ("К", "k"), ("М", "m"), ("Т", "t"), ("Н", "h"),
    # Greek lower
    ("ο", "o"), ("α", "a"), ("ε", "e"), ("ρ", "p"), ("ν", "v"), ("ι", "i"),
    ("κ", "k"), ("ς", "s"), ("σ", "s"), ("τ", "t"), ("υ", "u"), ("β", "b"),
]
_CONFUSABLE_MAP = {ord(a): b for a, b in _CONFUSABLE_PAIRS}

# Leetspeak → letter, for the danger scan only.
_LEET_MAP = {ord(k): v for k, v in {
    "1": "i", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
}.items()}

# Zero-width / bidi / invisible characters an attacker can splice inside a keyword.
_INVISIBLE = dict.fromkeys(
    [0x00AD] + list(range(0x200B, 0x2010)) + list(range(0x2028, 0x202F))
    + list(range(0x2060, 0x2065)) + list(range(0x2066, 0x206A)) + [0xFEFF],
    None,
)

# The kit's own command vocabulary. Neutralized before the shell-danger scan so a
# filename suffix (manage.sh) is not read as a bare `sh` shell command. Every other
# shell-danger token (curl, | bash, rm -rf, $(), backticks) stays fully active.
_KIT_TOKENS = ("./manage.sh", "manage.sh")


def neutralize_kit_tokens(s: str) -> str:
    for tok in _KIT_TOKENS:
        s = s.replace(tok, "manage_sh")
    return s


def confusables_fold(s: str) -> str:
    """Normalized view for danger detection: drop invisibles, NFKC-fold
    compatibility forms, LOWERCASE (so upper/lower Cyrillic/Greek collapse via
    str.lower first), then map cross-script confusables + leetspeak to Latin.
    NEVER use the result as emitted text — detection only."""
    s = s.translate(_INVISIBLE)
    s = unicodedata.normalize("NFKC", s)
    s = s.lower()  # lower FIRST: str.lower folds Ѕ->ѕ, О->о, etc. so the map needs only lowercase keys
    s = s.translate(_CONFUSABLE_MAP)
    s = s.translate(_LEET_MAP)
    return s


def scan_variants(text: str) -> list[str]:
    """The strings a directive-detector should run its patterns against: the
    kit-token-neutralized original (catches raw + digit-bearing tokens like
    base64) and its confusable/leet-folded form (catches homoglyph/leet evasion).
    A match in EITHER means the text is directive-like."""
    raw = neutralize_kit_tokens(text)
    return [raw, confusables_fold(raw)]
