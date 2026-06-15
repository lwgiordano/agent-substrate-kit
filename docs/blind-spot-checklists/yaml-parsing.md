# Blind-spot checklist: YAML / dict input handling

Read before adding or modifying code that reads YAML config or dict
input. Each class is a recurring real-world bug.

## When to consult

- Adding a `yaml.safe_load` or `yaml.load` call.
- Adding a `cfg.get("FIELD")` or `entry["FIELD"]` access on
  user-supplied data.
- Authoring a validator that reads a YAML schema.
- Reviewing a PR that touches `*.yaml`/`*.yml` or `*.py` with the
  above shapes.

---

## 1. Missing-key returns None

**Smell**: `cfg.get("FIELD") in {"a", "b"}` — if the key is missing,
`.get()` returns None, and `None in {"a", "b"}` is False (silently).

**Example bug**: `if cfg.get("status") in {"active"}:` — silently
treats absent status as "not active". The bug surfaces only when a
config without `status:` ships.

**Fix**: use a default:
```python
cfg.get("status", "missing") in {"active"}
```
OR raise on missing required fields:
```python
if "status" not in cfg:
    raise KeyError("required field 'status' missing")
```

---

## 2. Wrong type — list vs scalar

**Smell**: `for x in cfg["items"]:` — if `items` is a string
(YAML scalar), iteration yields characters. If `items` is None
(empty list `items:` line), it raises TypeError.

**Fix**: isinstance check:
```python
items = cfg.get("items") or []
if not isinstance(items, list):
    raise TypeError(f"'items' must be a list, got {type(items).__name__}")
for x in items:
    ...
```

---

## 3. Empty list `items: []` vs missing `items:`

**Smell**: `if cfg["items"]:` treats `items: []` (empty list, defined)
the same as missing `items` key. But the operator's intent differs:
empty list = "I declare none"; missing = "I forgot to declare".

**Fix**: distinguish via `in`:
```python
if "items" not in cfg:
    raise KeyError("'items' required (use 'items: []' if intentionally empty)")
items = cfg["items"]
```

---

## 4. YAML 1.1 vs 1.2 boolean coercion

**Smell**: PyYAML uses YAML 1.1 by default. Strings `yes`, `no`,
`on`, `off`, `True`, `False` are coerced to booleans. So a config
field `country: NO` becomes `country: False`.

**Fix**: quote string values that could collide:
```yaml
country: "NO"   # explicitly string
```
OR use `ruamel.yaml` with YAML 1.2 (no implicit boolean coercion
beyond `true`/`false`).

---

## 5. Numbers vs strings

**Smell**: `cfg["version"] == "1.0"` — but YAML parsed `1.0` as a
float, so the equality fails. Same for `port: 080` (octal in YAML 1.1).

**Fix**: quote in YAML or coerce in Python:
```yaml
version: "1.0"
port: "080"
```

---

## 6. Unintended deep merge

**Smell**: when YAML supports anchors (`&` and `*`) or merge keys
(`<<`), a config inheriting from a base may have surprising
overrides.

**Fix**: prefer flat configs without anchors. If you need
inheritance, use a Python-side merge function with explicit
precedence rules.

---

## 7. Duplicate keys silently overwrite

**Smell**: PyYAML's `safe_load` accepts duplicate keys without
warning — the LAST one wins.

**Example**:
```yaml
threshold: 100
# ... later in the file ...
threshold: 200
# Result: threshold = 200, no warning
```

**Fix**: use `ruamel.yaml` with strict mode, OR write a custom loader
that errors on duplicates, OR enforce one-key-per-config in CI.

---

## 8. None vs missing for nested keys

**Smell**: `cfg["a"]["b"]` raises KeyError if `a` is missing. Worse,
`cfg.get("a", {})["b"]` works but `cfg.get("a", {}).get("b")`
returns None — collapsing "a missing" and "a present but b missing"
into the same value.

**Fix**: explicit walk:
```python
a = cfg.get("a")
if a is None:
    raise KeyError("'a' missing")
b = a.get("b")
if b is None:
    raise KeyError("'a.b' missing")
```

---

## 9. Adversarial-input grid

For every YAML-field read, ask:
- What if the field is empty string?
- What if it's whitespace-only?
- What if it's a wrong type (int, list, None, bool, dict)?
- What if it's a bracket-wrapped placeholder (`<...>`, `[...]`)?
- What if it contains path traversal (`..`)?
- What if it's unicode/surprising whitespace?
- What if it's extremely long?
- What if it's all-punctuation?

The substrate's `check_validator_input_coverage` enforces that every
YAML-field read in a `scripts/check_*.py` has a paired test that
exercises wrong-type and adversarial inputs.

---

## 10. PyYAML `safe_load` is the only safe choice

**Smell**: `yaml.load(text)` (without `Loader=yaml.SafeLoader`) can
deserialize arbitrary Python objects via `!!python/object`.

**Fix**: ALWAYS use `yaml.safe_load`. Lint rule (bandit B506)
catches unsafe `yaml.load` calls.

---

## 11. Key-as-list, value-as-string surprise

**Smell**: YAML allows complex keys (lists, dicts as keys with `?`
syntax). If a config writer accidentally produces one, dict access
raises TypeError.

**Fix**: validate keys are strings:
```python
for k in cfg:
    if not isinstance(k, str):
        raise TypeError(f"non-string key: {k!r}")
```

---

## 12. Encoding mismatch on read

**Smell**: `open(path).read()` without specifying encoding. Default
is locale-dependent (UTF-8 on macOS/Linux, often cp1252 on Windows).
A YAML file with non-ASCII chars fails on some platforms.

**Fix**: always specify `encoding="utf-8"`.

---

## 13. Schema vs runtime drift

**Smell**: code reads a field that's not in the documented schema, or
the schema documents a field the code never reads. Both forms of
drift surface as bugs months later.

**Fix**: write a paired test that exercises every schema field. The
substrate's `check_validator_input_coverage` uses test-mention as a
proxy for "field is exercised".

---

## 14. Default merge vs override

**Smell**: code does `defaults.update(user_cfg)` — but user_cfg's
nested dict completely replaces defaults' nested dict (no recursive
merge).

**Fix**: explicit deep-merge function, OR document the override
semantics clearly.

---

## 15. NULL vs missing in DuckDB/SQL boundary

**Smell**: YAML's `null` → Python's `None` → SQL's `NULL`. But
`NULL IN (...)` evaluates to `NULL` (not `FALSE`) in most SQL
dialects, breaking expected boolean logic.

**Fix**: COALESCE or `IS NULL` checks at the SQL boundary:
```sql
COALESCE(field IN ('a', 'b'), FALSE)
```

---

## How to use this checklist

When you author or modify YAML-reading code:

1. Read the diff.
2. For each YAML field access, check the 15 classes above.
3. Add isinstance + missing-key guards as needed.
4. Add a paired test that plants wrong-type / adversarial inputs.
5. Reference this checklist in the commit message's
   `Cluster searched:` field per the substrate's four-field protocol.
