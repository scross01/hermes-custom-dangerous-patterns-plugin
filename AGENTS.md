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
- ALWAYS use the provided test patterns from `examples/test-patterns.yaml` (all `enabled: false` by default)
- Test patterns are named `[TEST]` and are safe by design:
  - File operations are scoped to `/tmp/` (ephemeral, no data loss)
  - Database operations target `test_` prefixed tables only
  - Network operations use nonexistent or test endpoints
- If adding custom test commands, validate they cannot cause real damage before running
- Validate that test patterns actually trigger approval before relying on them
- Prefix custom test descriptions with `[TEST]` for clarity.

## Self-modification risk

> The plugin's stance on self-modification is: **allow it, detect it, log it.**

The agent can read/write `~/.hermes/custom-dangerous-patterns.yaml`. It can add `allow_patterns: [{pattern: '.*'}]` to bypass all approval (except hardline). This is by design — the plugin detects and logs changes but does not prevent them. The `_config_cache` freeze means mid-session edits are ignored, but changes take effect after restart.

**Risks the plugin CANNOT prevent:**
- The agent could add `allow_patterns: [{pattern: '.*'}]` to exempt itself from all dangerous-pattern checks (hardline commands are still blocked)
- The agent could modify protected patterns by also changing the `protected` flag
- Config modifications via Python I/O or tool calls are invisible to pattern matching — only literal command-line path references are potentially caught

**Defenses the plugin DOES provide:**
- `protected: true` patterns: critical patterns have their hashes tracked in `~/.hermes/.custom-patterns-hash`. If a protected pattern is modified or removed, a CRITICAL security warning is logged at startup.
- Config hash tracking: the full config SHA-256 is stored between sessions. Any change triggers a security warning on next load with details of what changed.
- New-allow shadowing detection: if a new allow pattern appears to bypass a built-in dangerous-pattern check, a WARNING is logged.

**Bypass vectors through custom patterns:**

| Command | Why pattern matching doesn't see it |
|---------|-----------------------------------|
| `python -c "open('~/.hermes/custom-dangerous-patterns.yaml').write('...')"` | filename is in a Python string, not shell-visible |
| File-write tool call | tool handles I/O; filename not in command string |
| `sed -i 's/block/allow/' ~/.hermes/custom-dangerous-patterns.yaml` | filename visible but not in `_SENSITIVE_WRITE_TARGET` (out of scope) |
| `tee ~/.hermes/custom-dangerous-patterns.yaml << 'EOF'` | same: not in `_SENSITIVE_WRITE_TARGET` (out of scope) |

**User-level hardening options (optional, NOT the default):**
- Run the agent and Hermes under separate OS users so the agent cannot write to `~/.hermes/custom-dangerous-patterns.yaml` or `~/.hermes/config.yaml`
- Set config file permissions to `0444` (read-only) for the agent's user
- Mount the config directory read-only in containerized setups
- Use `command_allowlist` only for patterns the user personally approved

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
