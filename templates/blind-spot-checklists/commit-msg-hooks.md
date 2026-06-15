# Blind-spot checklist: commit-msg hooks

Read before adding or modifying a commit-msg-stage pre-commit hook.
Each class is a recurring real-world bug.

## When to consult

- Adding a hook with `stages: [commit-msg]`.
- Modifying `check_finding_response.py` or `check_postmortem_for_bug_fix.py`.
- Authoring a forcing-function gate that requires specific commit-
  message content.

---

## 1. Unanchored opt-out tag

**Smell**: `re.search(r'\[no-postmortem:\s*([^\]]+)\]')` — fires on
any inline mention of the tag, including narrative text describing
the opt-out in commit-body documentation.

**Fix**: line-anchored with MULTILINE:
```python
re.compile(r'^[ \t]*\[no-postmortem:\s*([^\]]+)\]\s*$', re.MULTILINE)
```

---

## 2. Placeholder values satisfy non-empty checks

**Smell**: hook checks `value not in ("", None)` — but a copy-pasted
template placeholder like `<reason>` is non-empty and passes.

**Fix**: also reject placeholder shapes:
```python
_PLACEHOLDER_RE = re.compile(r'^\s*[<\[{].*[>\]}]\s*$')
_PLACEHOLDER_PHRASES = ("TODO", "FIXME", "XXX", "TBD", "N/A")
def is_placeholder(s):
    return bool(_PLACEHOLDER_RE.match(s)) or s.strip().upper() in _PLACEHOLDER_PHRASES
```

---

## 3. Comment-stripping eats valid content

**Smell**: hook strips `#` lines from the message — but Git's
default commit-msg template uses `#` for instruction comments, which
is correct to strip. However, if the operator writes
`Bug class: # comment-style narrative` in the field value, the
comment-strip removes content.

**Fix**: only strip `^#` (line-leading) lines, not `#` mid-line:
```python
"\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
```

---

## 4. Subject-line regex misses informal bug-fix shapes

**Smell**: regex requires `^fix:` prefix but operators write
informal subjects like `correct empty array case`.

**Fix**: layered detection — conventional-commit prefix + phase-fix
shape + loose-token detection within the first 60 chars. See
`check_finding_response.py::_BUG_FIX_SUBJECT_PATTERNS`.

Counter: too-loose detection produces false positives ("fixate the
config" → fires the four-field gate). Find the balance via
calibration tests against historical commits.

---

## 5. Merge / revert false positives

**Smell**: bug-fix detection fires on `Merge branch 'fix-foo'` or
`Revert "fix: bug"` — neither is a new fix.

**Fix**: skip merge / revert subjects:
```python
if message.startswith(("Merge ", "Revert ")):
    return 0  # not a bug-fix, skip
```

---

## 6. Domain-detection misses staged-only changes

**Smell**: domain detection (e.g., "this commit touches regex")
walks `git diff HEAD` instead of `git diff --cached`. The
commit-msg hook runs BEFORE the commit lands, so HEAD doesn't have
the new content.

**Fix**: use `git diff --cached --name-only` and `git show :0:<file>`
to read STAGED content, not HEAD content.

---

## 7. Cross-line opt-out collision

**Smell**: opt-out tag spans two lines because the operator wrapped
manually:
```
[meta-fix-not-applicable: trivial typo
in a comment]
```
Regex with `[^\]]+` matches across newlines IF `re.DOTALL` is set,
but most opt-out regexes use `[^\]\n]+` (no newline) — so the
two-line form fails.

**Fix**: document that opt-out tags must fit on one line, OR allow
wrapping with explicit `\n` handling.

---

## 8. Empty commit-message file

**Smell**: hook reads `args.commit_msg_file` and processes — but
git allows empty messages with `--allow-empty-message` or via aborted
commits. Reading an empty file should be a no-op, not a crash.

**Fix**:
```python
if not raw_text.strip():
    return 0  # empty message — git itself rejects, hook is no-op
```

---

## 9. Detection regex that hits comment narration

**Smell**: regex `\b\w+\.compile\(` is meant to detect production
regex usage but also fires on comments that document the function
name with parens.

**Fix**: AST-based detection (parse the file as Python, walk Call
nodes) instead of regex on raw text. See
`check_finding_response.py::_detect_python_uses`.

---

## 10. Field-value extraction across lines

**Smell**: `^Bug class:\s*(.+)$` with the wrong flag. Without
MULTILINE, `^` and `$` are start/end of input. With MULTILINE, they
work per-line. With DOTALL, `.` matches newlines and the value
spills into the next field.

**Fix**: explicit `[ \t]` (space/tab only) instead of `\s` (which
includes newlines):
```python
re.compile(r'^[ \t]*Bug class[ \t]*:[ \t]*(\S.*\S|\S)[ \t]*$', re.MULTILINE)
```

---

## 11. Hook accepts message but git rejects later

**Smell**: hook returns 0, but git's commit-msg validation rejects
the message anyway (e.g., trailing whitespace + commit.cleanup
config).

**Fix**: hooks that MODIFY the commit message must rewrite the file
in-place; hooks that VALIDATE just return non-zero. Don't mix.

---

## 12. Regex compiles but never matches due to encoding

**Smell**: hook reads commit-msg file with default encoding;
operator's git commit message contains UTF-8 BOM or Windows
line-endings. Regex pattern uses LF assumptions and silently fails
to match.

**Fix**: read with `encoding="utf-8"`, normalize line endings:
```python
raw = msg_path.read_text(encoding="utf-8").replace("\r\n", "\n")
```

---

## 13. Forcing-function gameability

**Smell**: hook requires four fields like
`Bug class: <text>`. A contributor satisfies the gate by typing
`Bug class: x` (single character). Letter-of-the-law passes, but the
spirit (force class-of-bug thinking) doesn't.

**Fix**: layered gates — non-empty AND non-placeholder AND
domain-checklist-referenced AND verbatim-shape verified. Multiple
weak gates compose into a strong one.

---

## 14. Hook hangs on slow filesystem

**Smell**: hook shells out to `git` or `subprocess.run` without
timeout. Google Drive cloud-sync filesystems can take 10+ seconds
per spawn; without timeout, the hook hangs the commit forever.

**Fix**: always pass `timeout=30` to `subprocess.run`. Catch
`subprocess.TimeoutExpired` and degrade gracefully.

---

## 15. Calibration drift

**Smell**: hook detection logic changes; the calibration regression
test (which validates detection against known-bug commits) isn't
re-run, so silent precision/recall drift lands.

**Fix**: any change to detection logic must include calibration
re-run. The substrate ships `calibrate_diy_ultrareview.py` for this;
it runs as a pre-commit hook on detection-code changes.

---

## How to use this checklist

When you author or modify a commit-msg hook:

1. Read the diff.
2. For each regex / detection change, check the 15 classes above.
3. Add tests that plant the bug shapes verbatim.
4. Run the calibration suite (if applicable) to verify no
   precision/recall regression.
5. Reference this checklist in the commit message's
   `Cluster searched:` field per the substrate's four-field protocol.
