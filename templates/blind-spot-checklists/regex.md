# Blind-spot checklist: Regex authoring

Read before adding or modifying a regex. Each class is a recurring
real-world bug. The "smell" is what to look for in the diff; the
"fix" is what to do instead.

## When to consult

- Adding a `re.compile`, `re.match`, `re.search`, `re.fullmatch`,
  `re.sub`, or `re.findall` call.
- Tightening a stale-phrase entry.
- Authoring a commit-msg hook regex (also read `commit-msg-hooks.md`).
- Reviewing a PR that touches `*.py` files matching the above.

---

## 1. Greedy vs lazy quantifier

**Smell**: `.*` or `.+` between two literals — matches more than you'd
expect because `.` is greedy by default.

**Example bug**:
```python
re.search(r'<.*>', '<a><b>')  # matches '<a><b>', not '<a>'
```

**Fix**: use lazy `.*?` or a character class that excludes the
terminator.
```python
re.search(r'<.*?>', '<a><b>')   # → '<a>'
re.search(r'<[^>]*>', '<a><b>') # → '<a>' (preferred — no backtracking)
```

---

## 2. Unanchored when you meant anchored

**Smell**: regex matches a phrase but doesn't have `^` or `$`. A
contributor can satisfy the gate with mid-paragraph text.

**Example bug**:
```python
re.search(r'\[no-postmortem:\s*([^\]]+)\]', body)
# This fires on any inline mention of [no-postmortem: ...] in
# narrative, not just opt-out tags on their own line.
```

**Fix**: line-anchor with `re.MULTILINE`:
```python
re.compile(r'^\s*\[no-postmortem:\s*([^\]]+)\]\s*$', re.MULTILINE)
```

---

## 3. Word boundary doesn't include `(`

**Smell**: `\bre\.compile\b` — `\b` is the boundary between word/
non-word characters. After `compile` (word char) comes `(` (non-
word), so `\b` matches BEFORE the `(`. But you might want to match
ONLY when `(` follows.

**Example bug**:
```python
re.compile(r'\bre\.compile\b')
# Matches "re.compile" in COMMENTS (e.g., "// re.compile is...")
# because the prose uses the function name without the call.
```

**Fix**: anchor on `\(`:
```python
re.compile(r'\bre\.compile\(')
```

---

## 4. Character class range surprise

**Smell**: `[a-Z]` or `[A-z]` looks like it covers all letters but
includes punctuation `[\\]^_` between `Z` and `a` in ASCII.

**Fix**: use `[a-zA-Z]` (two ranges) or `\w` if word chars are
acceptable.

---

## 5. Forgotten `re.escape` for user input

**Smell**: dynamic regex built with f-string + user-supplied string:
```python
re.compile(rf'^{user_field}:')
# If user_field is `foo.bar`, the `.` matches anything.
# If user_field is `(`, the regex is invalid.
```

**Fix**: `re.escape(user_field)`.

---

## 6. Alternation with no group

**Smell**: `r'cat|dog food'` — alternation has the LOWEST precedence.
This matches `cat` or `dog food`, not `cat food` or `dog food`.

**Fix**: parenthesize: `r'(cat|dog) food'`.

---

## 7. Newline blindness in `.`

**Smell**: regex spans multiple lines but `.` doesn't match newlines
by default. A multi-line bug shape is missed.

**Example bug**:
```python
# Real bug: a docstring claims "X" then code does "Y" 5 lines later.
re.search(r'docstring.*code does Y', text)  # MISSES across lines
```

**Fix**: `re.DOTALL` flag or use `[\s\S]*` instead of `.*`.

---

## 8. Empty-match infinite loop in sub/findall

**Smell**: a regex that can match empty string (`r'\w*'`, `r'(?:x)?'`,
etc.) used with `re.sub` or `re.findall` — creates infinite empty
matches.

**Fix**: require at least one char (`\w+` not `\w*`) or use the
positive lookahead form.

---

## 9. Capture-group numbering after edit

**Smell**: code uses `m.group(1)` but the regex was edited to add a
new group earlier in the pattern. Group numbers shift silently.

**Fix**: switch to NAMED groups:
```python
re.compile(r'(?P<sha>\w{7,40})')
m.group('sha')  # immune to re-numbering
```

---

## 10. Verbatim-shape gap in tests

**Smell**: regex is tested with a stylized minimal example that
doesn't match the real bug shape (different unicode quotes,
column-wrapped lines, em-dashes vs hyphens, etc.).

**Fix**: copy the actual buggy text VERBATIM into the test fixture.
Don't paraphrase. The substrate's commit-msg hook calls this
"verbatim-shape verified".

---

## 11. Backslash-escape escaping

**Smell**: `r'\d+'` works but `r'\\d+'` doesn't. Or non-raw string
`'\d+'` works in Python (because `\d` is not a recognized escape) but
`'\n'` is a newline, not a literal backslash-n.

**Fix**: ALWAYS use raw strings (`r'...'`) for regex.

---

## 12. Anchor-collision in MULTILINE

**Smell**: `^` and `$` change meaning under `re.MULTILINE`. Without
the flag, `^` is start-of-string and `$` is end-of-string. With the
flag, they're start/end of EACH line.

**Fix**: pick one and be explicit. If you mean "start of each line",
use `re.MULTILINE`. If you mean "start of input", use `\A` and `\Z`
(which ignore the flag).

---

## 13. Lookahead/lookbehind variable-width restriction

**Smell**: `(?<=foo|barbar)` — fixed-width lookbehind in stdlib `re`
module errors on variable-width alternation.

**Fix**: use `regex` module (3rd party) for variable-width
lookbehind, OR refactor to lookahead, OR enumerate fixed-width forms.

---

## How to use this checklist

When you author or modify a regex:

1. Read the diff.
2. For each regex change, check the 13 classes above.
3. If any apply, either fix the bug OR add a comment explaining
   why the class doesn't apply here.
4. Add a test that plants the bug shape verbatim (per class #10).
5. Reference this checklist in the commit message's
   `Cluster searched:` field per the substrate's four-field protocol.
