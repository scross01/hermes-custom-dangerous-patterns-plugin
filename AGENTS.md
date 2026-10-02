# AGENTS

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

### Never write to Hermes core — including its tables

The plugin extends Hermes **only** through `pre_tool_call`, a `register_*` API, and
its CLI. Two things are forbidden:

1. **Rebinding** any `tools.*` / `hermes_cli.*` / `agent.*` attribute or function.
2. **Writing** to any Hermes module-level table — `DANGEROUS_PATTERNS` and
   `DANGEROUS_PATTERNS_COMPILED` included.

`hermes plugins validate` detects (1) but **not** (2): a probe plugin doing
`DANGEROUS_PATTERNS.append(...)` produces zero findings. Passing the official
lint is therefore necessary, not sufficient. That blind spot is exactly how the
0.4.x violation survived review. `tests/test_core_surface.py` is the real gate,
and it carries meta-tests that assert the scanner itself fires on known-bad
snippets. Verify it still bites before trusting it:

```sh
# append a real violation to register(), confirm the suite fails, then revert
env -u HERMES_CUSTOM_PATTERNS_PATH PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  python3.14 -m pytest -p no:cacheprovider -o addopts= -q
```

Read-only access is fine and is used deliberately: `cli.py` imports
`DANGEROUS_PATTERNS` to *display* built-ins, and `patterns.py` reads it to warn
about overlap. Neither writes.

### Match commands the way Hermes does, not over raw text

Custom block/deny rules used to be appended to `DANGEROUS_PATTERNS_COMPILED`, so
Hermes matched them with its own normalizer. Matching now happens inside the
plugin, so `find_block_match` / `find_deny_match` must run against
`_normalized_variants()` — which delegates to Hermes's
`_command_detection_variants`. Matching the raw string instead silently
downgrades every user rule: `rm \-rf /`, `r\m -rf /`, `rm${IFS}-rf /`, and
line continuations all evade a plain regex while the built-in gate catches them.

`custom-dangerous-patterns test` uses the same matcher on purpose, so it cannot
report "no match" for a command that will actually gate. If you add a matcher,
add it to both, or the CLI starts lying.

### `rule_key` must be derived from the regex

Block patterns escalate with `{"action": "approve", "rule_key": <stable>}`, and
`rule_key` sets the `[a]lways` allowlist grain. Two traps, both load-bearing:

- Omitting it collapses **every** custom rule on the `terminal` tool into
  `plugin_rule:terminal` — one `always` allowlists all of them. Hermes passes
  `details.rule_key or tool_name`.
- Deriving it from the description means editing a label in YAML silently resets
  the user's permanent approval, because `request_tool_approval` falls back to
  hashing the *description* when no key is given.

`_rule_key_for()` hashes the **regex**, which is the rule's identity. Keep it
that way. It is also the dedup key in `config._pattern_key`.

### Never raise out of the hook

Hermes **fails closed** on `pre_tool_call` exceptions. A raise does not skip one
command — it blocks every terminal call until the plugin is fixed. Hence the
blanket `except` in `_log_match` (a logging failure must never gate), the
`isinstance(command, str)` guard, and the fail-soft `try/except` in
`builtin_overlaps` and `_normalized_variants`. Preserve that posture when adding
code to the hook path.

### Tests exist under tests/

The repo has a comprehensive test suite under `tests/` using pytest. Tests cover config loading/validation, pattern compilation/matching, and plugin registration logic. See the test files for coverage details.

---

## Testing Safety

- **Never run a real command matching a block or deny pattern to exercise the hook.**
  Deny patterns return `{"action": "block"}` and block patterns escalate to a *live* human
  approval gate. A test that answers that gate is testing the user's real configuration and
  can persist a permanent allowlist entry. Use the `[TEST]` patterns in
  `examples/00-test.yaml`, and exercise the hook by calling the returned dict directly rather
  than going through Hermes's gate.
- **Never use real destructive commands** (e.g. recursive forced removal at filesystem root, dropping production databases, force-pushing shared branches) when testing approval/blocking logic.
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
| `cli.py` | Defines `register_cli(subparser)` to build the argparse tree, plus all `cmd_*` handlers and their `_handle_*` adapters. `_get_builtin_patterns()` returns `list | None`, where `None` means Hermes's table was unreadable — **not** the same as "no built-ins". Callers must distinguish them or they will report "Hermes exposes no dangerous patterns" when the truth is "we could not ask". |
| `logs.py` | Log extraction and filtering from `~/.hermes/logs/hermes.log`. Supports level/date filtering, limit, and follow (tail) mode. |
| `__init__.py` | Calls `ctx.register_cli_command(name=..., setup_fn=cli.register_cli)` during plugin startup. Imports **no** Hermes module at module scope — everything Hermes is imported lazily inside functions, which `tests/test_core_surface.py` enforces. |
| `patterns.py` | Matcher and config compiler. Reads `tools.approval_detection` read-only (`_command_detection_variants` for parity, `DANGEROUS_PATTERNS` for the overlap report, `detect_dangerous_command` for the runtime overlap probe). Never writes. |
| `config.py` | Exposes `save_config()` for config write-back and `resolve_config_path()` for CLI path display |

### CLI vs Runtime

- CLI commands load config fresh each invocation (`load_config(force=True, integrity_check=False)`). They bypass the module-level cache.
- Write commands (`enable`, `disable`, `add`, `remove`) modify the YAML config on disk and remind the user to restart Hermes.
- **Directory mode delta writes.** When the config path is a directory, most write commands (`enable`, `disable`, `add` without `--target`) never touch user-created files. Instead, `save_config()` computes a delta and writes only changed entries to `99-custom.yaml`.
- **`add --target <filename>`** writes directly to the specified file (skips `save_config` delta). The file must have a `.yaml` extension; path separators are not allowed.
- **`remove`** behavior depends on config mode:
  - **Single-file mode:** edits the source YAML file directly using `remove_entry_from_file()`. The entry is deleted from the file — no `disabled: true` remnant is written.
  - **Directory mode:** removes the entry from the in-memory config and `save_config()` writes `enabled: false` to `99-custom.yaml` (delta). Source files are not modified.
- CLI commands are invoked by Hermes's plugin CLI system but still use the same relative import convention as the rest of the plugin (`from .config import ...`, `from .patterns import ...`).

> **User-facing CLI behavior:** See [README.md — CLI Reference](./README.md#cli-reference) for all commands, flags, and usage examples.

---

## Adding a New Subcommand

1. Add the `cmd_*` handler in `cli.py` (returns `tuple[str, int]`)
2. Add the `_handle_*` adapter in `cli.py` (calls `cmd_*`, calls `_emit()`)
3. Add the subparser + arguments in `register_cli()` in `cli.py`
4. No changes needed in `__init__.py` — the single `setup_fn` call already delegates everything to `register_cli()`
