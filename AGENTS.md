# AGENTS.md — hermes-custom-dangerous-patterns-plugin

## Project overview

Hermes Agent plugin that injects user-defined regex patterns (from `~/.hermes/custom-dangerous-patterns.yaml`) into the built-in `DANGEROUS_PATTERNS` list. Custom patterns get the same once/session/always/deny approval flow as built-in ones.

## Entry point

- `__init__.py:register(ctx)` — called by Hermes at plugin startup.
- The plugin must be installed at `~/.hermes/plugins/custom-dangerous-patterns/` (note trailing `s`).
- Enable: `hermes plugins enable custom-dangerous-patterns`

## Critical gotchas

### Relative imports must be used everywhere

```python
from .config import load_config   # correct
from config import load_config    # fails — Python can't find top-level module
```

Hermes loads plugins as `hermes_plugins.<slug>` packages. Absolute imports against plugin-local modules will raise `ModuleNotFoundError`.

### Config is cached at startup, never re-read

`config.py` has a module-level `_config_cache`. Calling `load_config()` a second time returns the cached dict. The `force=True` parameter exists **only** for testing — mid-session config edits are silently ignored.

### No tests exist

The repo has zero tests. SPEC.md describes test categories but nothing is implemented. Any test work starts from scratch under `tests/` with `pytest`.

### Pattern injection must happen before `tools.approval` is imported

The `register()` function appends to `DANGEROUS_PATTERNS` / `DANGEROUS_PATTERNS_COMPILED` directly. If `tools.approval` is imported before the plugin registers, the injected patterns won't appear in the compiled list. Hermes's normal load order (plugins before tools) makes this work, but it's not verified at runtime.

## Evaluation order (for understanding behavior)

```
1. Hardline (unconditional block — rm -rf /, mkfs, etc.)
2. Sudo stdin guard (unconditional block)
3. Yolo / mode=off (bypass all)
4. Allow patterns (custom)  ← agent can modify this
5. Block patterns (custom)  ← agent can modify this
6. Built-in DANGEROUS_PATTERNS
7. Tirith security scan
```

Allow wins over block. If a command matches both, no prompt.

## Testing safety

- **Never use real dangerous commands** (`rm -rf /`, `DROP DATABASE`, `git push --force`) when testing approval/blocking logic.
- Test patterns from `examples/test-patterns.yaml` are `enabled: false` by default and scoped to safe targets (`/tmp/`, `test_` prefixes). Use them.
- Prefix custom test descriptions with `[TEST]` for clarity.

## Self-modification risk

The agent can read/write `~/.hermes/custom-dangerous-patterns.yaml`. It can add `allow_patterns: [{pattern: '.*'}]` to bypass all approval (except hardline). This is by design — the plugin detects and logs changes but does not prevent them. The `_config_cache` freeze means mid-session edits are ignored, but changes take effect after restart.

## Ad-hoc pattern testing

Verify pattern matching without restarting Hermes:

```bash
python3 -c "
from config import load_config
from patterns import compile_all, get_block_patterns, is_allow_pattern
config = load_config(force=True)
compile_all(config)
print('Block patterns:', len(get_block_patterns()))
print('Allow match:', is_allow_pattern('vultr instance list'))
"
```

Run from the plugin directory (`~/.hermes/plugins/custom-dangerous-patterns/`).

## Runtime dependencies

- Python 3.9+
- PyYAML (`pip install pyyaml`)
- Hermes Agent

## Config path resolution

1. `$HERMES_CUSTOM_PATTERNS_PATH` env var
2. `~/.hermes/custom-dangerous-patterns.yaml`
