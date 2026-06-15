# Blind-spot checklist: Python AST parsing

Read before adding or modifying code that uses Python's `ast` module
to parse or analyze source files.

## When to consult

- Adding any `ast.parse`, `ast.walk`, `ast.NodeVisitor` call.
- Authoring a static-analysis validator (e.g., `check_finding_response`'s
  domain detection).
- Reviewing a PR with `import ast` in the diff.

---

## 1. SyntaxError on the file you're parsing

**Smell**: `ast.parse(content)` — if `content` has a Python syntax
error (which is common during mid-edit pre-commit runs), parse
raises `SyntaxError`.

**Fix**: catch and degrade to regex fallback OR skip:
```python
try:
    tree = ast.parse(content)
except SyntaxError:
    return regex_fallback(content)  # or: skip with a warning
```

---

## 2. RecursionError on deeply nested input

**Smell**: `ast.parse` and `ast.walk` recurse into the AST tree.
Pathologically nested input (e.g., 1000-deep parens) hits Python's
default recursion limit (1000).

**Fix**: catch RecursionError + MemoryError. Don't bump
sys.setrecursionlimit globally (causes other surprises).

---

## 3. Source-file-twice mypy collision

**Smell**: when running `mypy .` on a repo with `scripts/` AND
`scripts.foo` import paths, mypy classifies the same file under two
module names, raising "Source file found twice under different
module names".

**Fix**: set `explicit_package_bases = true` in
`pyproject.toml [tool.mypy]`.

---

## 4. Aliased imports break attribute walk

**Smell**: `import re as r; r.compile(...)` — your AST walk for
`Call(func=Attribute(value=Name(id='re')))` misses this because the
local name is `r`, not `re`.

**Fix**: build an alias_map by walking `Import` and `ImportFrom`
nodes first, then resolve local names through the map:
```python
alias_map: dict[str, str] = {}
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        for alias in node.names:
            alias_map[alias.asname or alias.name] = alias.name
```

---

## 5. `from X import Y` bypasses Attribute access

**Smell**: `from re import compile; compile(r'...')` — there's no
`Attribute` node at the call site, just a bare `Name`. Your
attribute-based detector misses it.

**Fix**: also walk `ImportFrom` to track which names came from which
modules. Treat the imported names as local references to the source
module's calls.

---

## 6. Scope-unaware alias_map

**Smell**: `import re; def f(): import yaml as re` — your alias_map
collects whichever Import `ast.walk` visits LAST. So `re.compile`
elsewhere gets misclassified as yaml.

**Fix**: scope-aware walk via `ast.NodeVisitor` with a scope stack.
Or document the limitation and accept the false positive (low
real-world frequency).

---

## 7. String literal containing call shape

**Smell**: regex-based detection for `re.compile\(` matches inside
string literals like `'re.compile is the function'`.

**Fix**: AST-based detection (Constant nodes don't match Call).
Regex fallback only when AST parse fails.

---

## 8. Comment that looks like code

**Smell**: a docstring or comment mentions function names with
parens: `# Use re.compile(pattern) for ...`. Regex-based detection
fires; AST-based doesn't.

**Fix**: AST-based detection. Don't run regex on raw text for
purposes that should be syntax-aware.

---

## 9. ast.iter_child_nodes vs ast.walk

**Smell**: `ast.walk` recurses into ALL descendants, including
inside nested functions/classes. If you only want top-level
declarations, you need `ast.iter_child_nodes` on the module node.

**Fix**: be explicit about scope:
- Top-level: `ast.iter_child_nodes(tree)` on the Module node.
- Everywhere: `ast.walk(tree)`.

---

## 10. `ast.literal_eval` for untrusted input

**Smell**: parsing user-supplied data with `eval()` or `compile() +
eval()` — code-injection risk.

**Fix**: `ast.literal_eval` for parsing JSON-like literals safely:
```python
ast.literal_eval("[1, 2, 3]")  # safe
```

---

## 11. ast.unparse loses comments

**Smell**: round-tripping code via `ast.unparse(ast.parse(text))`
loses ALL comments (which are not part of the AST).

**Fix**: if you need to preserve comments, use `libcst` or `redbaron`
(third-party AST libraries that preserve formatting + comments).

---

## 12. ast module version drift

**Smell**: AST node names and structure change between Python
versions. `ast.Constant` replaced `ast.Num`/`ast.Str`/`ast.NameConstant`
in 3.8. `ast.MatchAs` is new in 3.10. Code that targets multiple
Python versions hits these.

**Fix**: target the lowest supported Python version + use the
modern node names. Add explicit version checks if you must support
older Python.

---

## How to use this checklist

When you author or modify code that uses `ast`:

1. Read the diff.
2. For each `ast.*` call, check the 12 classes above.
3. Add try/except for SyntaxError + RecursionError + MemoryError +
   TypeError around `ast.parse` and `ast.walk`.
4. Add tests with adversarial input (deeply nested, syntax errors,
   aliased imports, from-imports).
5. Reference this checklist in the commit message's
   `Cluster searched:` field per the substrate's four-field protocol.
