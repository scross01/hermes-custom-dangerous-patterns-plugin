# AGENTS.md — Developer Guide

Developer-focused documentation for the custom-dangerous-patterns plugin.

> **User-facing docs:** See [README.md](./README.md) for installation, configuration, CLI reference, glob syntax, and security/risk information.

---

## Critical Gotchas

### Relative imports must be used everywhere

```python
from .config import load_config   # correct
from config import load_config    # fails — Python can't find top-level module
```

Hermes loads plugins as `hermes_plugins.<slug>` packages. Absolute imports against plugin-local modules will raise `ModuleNotFoundError`.

### Config is cached at startup, never re-read

`config.py` has a module-level `_config_cache`. Calling `load_config()` a second time returns the cached dict. The `force=True` parameter exists **only** for testing — mid-session config edits are silently ignored.

### Pattern injection must happen before `tools.approval` is imported

The `register()` function appends to `DANGEROUS_PATTERNS` / `DANGEROUS_PATTERNS_COMPILED` directly. If `tools.approval` is imported before the plugin registers, the injected patterns won't appear in the compiled list. Hermes's normal load order (plugins before tools) makes this work, but it's not verified at runtime.

### Tests exist under tests/

The repo has a comprehensive test suite under `tests/` using pytest. Tests cover config loading/validation, pattern compilation/matching, and plugin registration logic. See the test files for coverage details.

---

## Testing Safety

- **Never use real dangerous commands** (`rm -rf /`, `DROP DATABASE`, `git push --force`) when testing approval/blocking logic.
- ALWAYS use the provided test patterns from `examples/00-test.yaml` (all `enabled: false` by default)
- Test patterns are named `[TEST]` and are safe by design:
  - File operations are scoped to `/tmp/` (ephemeral, no data loss)
  - Database operations target `test_` prefixed tables only
  - Network operations use nonexistent or test endpoints
- If adding custom test commands, validate they cannot cause real damage before running
- Validate that test patterns actually trigger approval before relying on them
- Prefix custom test descriptions with `[TEST]` for clarity.

---

## CLI Architecture

The plugin exposes a `hermes custom-dangerous-patterns` CLI command group via Hermes's plugin CLI system. CLI commands run **outside** the Hermes agent runtime — they are standalone config management and introspection tools. No monkey-patching, no approval flow involvement.

### Registration flow

Registration happens at Hermes startup via `__init__.py:_register_cli(ctx)`, which makes **one** call to `ctx.register_cli_command()` with the `setup_fn` parameter:

```python
# __init__.py
import cli

ctx.register_cli_command(
    name="custom-dangerous-patterns",
    help="Manage custom dangerous command patterns",
    setup_fn=cli.register_cli,    # ← builds the argparse subcommand tree
    handler_fn=None,
    description="Add, list, test, enable, disable, and remove custom dangerous patterns...",
)
```

Inside `register_cli(subparser)`, the argparse tree is built using `add_subparsers()` for each subcommand. Every subparser gets `set_defaults(func=_handle_*)` to wire dispatch:

```python
# cli.py — register_cli()
subs = subparser.add_subparsers(dest="cdp_command")

list_p = subs.add_parser("list", help="List custom patterns")
list_p.add_argument("-t", "--type", choices=["block", "allow", "deny"], ...)
list_p.set_defaults(func=_handle_list)

test_p = subs.add_parser("test", help="Test a command against patterns")
test_p.add_argument("command", help="Command string to test")
test_p.add_argument("-v", "--verbose", action="store_true", ...)
test_p.set_defaults(func=_handle_test)
# … more subcommands follow the same pattern
```

**Key detail:** The first arg to `ctx.register_cli_command()` is the `name` parameter, NOT the handler. The handler is passed indirectly via `setup_fn`, which receives the subparser and registers sub-subcommands with `set_defaults(func=...)`.

### Modules

| Module | Role |
|--------|------|
| `cli.py` | Defines `register_cli(subparser)` to build the argparse tree, plus all `cmd_*` handlers and their `_handle_*` adapters |
| `logs.py` | Log extraction and filtering from `~/.hermes/logs/hermes.log`. Supports level/date filtering, limit, and follow (tail) mode. |
| `__init__.py` | Calls `ctx.register_cli_command(name=..., setup_fn=cli.register_cli)` during plugin startup |
| `config.py` | Exposes `save_config()` for config write-back and `resolve_config_path()` for CLI path display |

### CLI vs Runtime

- CLI commands load config fresh each invocation (`load_config(force=True, integrity_check=False)`). They bypass the module-level cache.
- Write commands (`enable`, `disable`, `add`, `remove`) modify the YAML config on disk and remind the user to restart Hermes.
- **Directory mode delta writes.** When the config path is a directory, most write commands (`enable`, `disable`, `add` without `--target`) never touch user-created files. Instead, `save_config()` computes a delta and writes only changed entries to `99-custom.yaml`.
- **`add --target <filename>`** writes directly to the specified file (skips `save_config` delta). The file must have a `.yaml` extension; path separators are not allowed.
- **`remove` always edits source files directly.** Unlike other write commands, `remove` uses `remove_entry_from_file()` to scan all YAML files and delete matching pattern entries at the YAML level. No `disabled: true` remnant is written.
- CLI commands are invoked by Hermes's plugin CLI system but still use the same relative import convention as the rest of the plugin (`from .config import ...`, `from .patterns import ...`).

> **User-facing CLI behavior:** See [README.md — CLI Reference](./README.md#cli-reference) for all commands, flags, and usage examples.

---

## Adding a New Subcommand

1. Add the `cmd_*` handler in `cli.py` (returns `tuple[str, int]`)
2. Add the `_handle_*` adapter in `cli.py` (calls `cmd_*`, calls `_emit()`)
3. Add the subparser + arguments in `register_cli()` in `cli.py`
4. No changes needed in `__init__.py` — the single `setup_fn` call already delegates everything to `register_cli()`
