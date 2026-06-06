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

### Tests exist under tests/

The repo has a comprehensive test suite under `tests/` using pytest. Tests cover config loading/validation, pattern compilation/matching, and plugin registration logic. See the test files for coverage details.

### Pattern injection must happen before `tools.approval` is imported

The `register()` function appends to `DANGEROUS_PATTERNS` / `DANGEROUS_PATTERNS_COMPILED` directly. If `tools.approval` is imported before the plugin registers, the injected patterns won't appear in the compiled list. Hermes's normal load order (plugins before tools) makes this work, but it's not verified at runtime.

## Evaluation order (runtime, for understanding behavior)

Deny patterns are checked by a wrapper around `check_all_command_guards()` that runs BEFORE the original function. This means deny patterns cannot be bypassed by `--yolo` or `mode=off`.

Each check is tagged with its source:
- `[Plugin]` — this plugin's custom checks
- `[Hermes]` — Hermes Agent's built-in checks

```
 1. [Plugin]  Deny patterns (custom)        → BLOCKED immediately, no prompt
               (wraps original check_all_command_guards)
 2. [Hermes]  Hardline check                → blocked unconditionally
 3. [Hermes]  Sudo stdin guard              → blocked unconditionally
 4. [Hermes]  Yolo / mode=off               → bypasses steps 5-7
 5. [Plugin]  Allow patterns (custom)       → command runs, no prompt (allow wins)
 6. detect_dangerous_command():             — same approval prompt for both —
    a. [Plugin]  Block patterns (custom)    → [o]nce/[s]ession/[a]lways/[d]eny
    b. [Hermes]  Built-in patterns          → [o]nce/[s]ession/[a]lways/[d]eny
 7. [Hermes]  Tirith security scan          → approval prompt if findings
```

**Key rules:**
- **Allow wins over block.** If a command matches both an allow pattern and a block pattern, allow wins and no prompt is shown.
- **Deny wins over allow.** Deny patterns are checked before allow patterns. If a command matches a deny pattern, it is blocked before allow patterns are even evaluated.
- **Deny is immediate-block; block is approval-prompt.** Block patterns and built-in patterns both go through the same `detect_dangerous_command()` approval flow. Deny patterns skip it entirely.
- **Deny bypasses yolo.** Deny patterns are evaluated outside the original guard function, so `--yolo` does not bypass them. Deny patterns are evaluated outside the original guard function, so `--yolo` does not bypass them.

## Testing safety

- **Never use real dangerous commands** (`rm -rf /`, `DROP DATABASE`, `git push --force`) when testing approval/blocking logic.
- ALWAYS use the provided test patterns from `examples/00-test.yaml` (all `enabled: false` by default)
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

**Preferred:** Use the CLI:

```bash
hermes custom-dangerous-patterns test "vultr instance list"
hermes custom-dangerous-patterns list
```

**Fallback:** Verify pattern matching without restarting Hermes (from the plugin directory `~/.hermes/plugins/custom-dangerous-patterns/`):

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

## Runtime dependencies

- Python 3.9+
- ruamel.yaml (declared in `plugin.yaml`; Hermes installs automatically)
- Hermes Agent

## Config path resolution

1. `$HERMES_CUSTOM_PATTERNS_PATH` env var
2. `~/.hermes/custom-dangerous-patterns/` (directory of YAML files — **preferred**)
3. `~/.hermes/custom-dangerous-patterns.yaml` (single file, fallback)

### Combined mode

When **both** the single file (`custom-dangerous-patterns.yaml`) and the directory
(`custom-dangerous-patterns/`) exist, the plugin automatically enters
*combined mode*:

- **Loading:** `_load_yaml()` loads the sibling `.yaml` file first as a
  baseline, then loads all `.yaml` files from the directory on top. Dedup
  ensures directory files take precedence (last occurrence wins).
- **Writes:** `_resolve_config_path()` returns the directory, so CLI write
  operations (`add`, `remove`, `enable`, `disable`) go to `99-custom.yaml`
  inside the directory. The sibling `.yaml` file is included in the user
  baseline for delta computation — changes are tracked correctly across
  both locations.

This allows a gradual migration from single-file mode to directory mode:
leave `custom-dangerous-patterns.yaml` in place and create
`custom-dangerous-patterns/` alongside it. Both are merged automatically.

## CLI architecture

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
# … 8 more subcommands follow the same pattern
```

**Key detail:** The first arg to `ctx.register_cli_command()` is the `name` parameter, NOT the handler. The handler is passed indirectly via `setup_fn`, which receives the subparser and registers sub-subcommands with `set_defaults(func=...)`.

### Modules

| Module | Role |
|--------|------|
| `cli.py` | Defines `register_cli(subparser)` to build the argparse tree, plus all 10 `cmd_*` handlers and their `_handle_*` adapters |
| `logs.py` | Log extraction and filtering from `~/.hermes/logs/hermes.log`. Supports level/date filtering, limit, and follow (tail) mode. |
| `__init__.py` | Calls `ctx.register_cli_command(name=..., setup_fn=cli.register_cli)` during plugin startup |
| `config.py` | Exposes `save_config()` for config write-back and `resolve_config_path()` for CLI path display |

### CLI vs Runtime

- CLI commands load config fresh each invocation (`load_config(force=True, integrity_check=False)`). They bypass the module-level cache.
- Write commands (`enable`, `disable`, `add`, `remove`) modify the YAML config on disk and remind the user to restart Hermes.
- **Directory mode delta writes.** When the config path is a directory, most write commands (`enable`, `disable`, `add` without `--target`) never touch user-created files. Instead, `save_config()` computes a delta and writes only changed entries to `99-custom.yaml`, which sorts last in the merge order.
- **`add --target <filename>`** writes directly to the specified file in the config directory (skips `save_config` delta). The file must have a `.yaml` extension; path separators are not allowed.
- **`remove` always edits source files directly.** Unlike other write commands, `remove` uses `remove_entry_from_file()` to scan all YAML files and delete matching pattern entries at the YAML level. No `disabled: true` remnant is written.
- The `test` command uses the same `patterns.py` matching functions as the runtime monkey-patches, guaranteeing consistent results.
- CLI commands are invoked by Hermes's plugin CLI system but still use the same relative import convention as the rest of the plugin (`from .config import ...`, `from .patterns import ...`).

### Directory Mode Writes

When the config path is a directory, CLI write commands (`add`, `remove`, `enable`, `disable`) behave differently:

1. **Never touch user-created files (except `remove` and `add --target`).** Files like `10-cloud.yaml` and `20-database.yaml` are read-only as far as `enable`, `disable`, and `add` (without `--target`) are concerned. `remove` always edits source files directly to delete entries.
2. **Delta-only writes.** `save_config()` computes a delta between the merged config and the user file baseline. Only entries that differ — new, modified, or removed — are written to `99-custom.yaml`.
3. **Removal as true deletion.** When a pattern is removed via CLI, `remove_entry_from_file()` scans all YAML files (including the sibling `.yaml` in combined mode) and deletes matching pattern entries using ruamel.yaml round-trip editing. The lines are gone — no disabled remnant or `_removed` flag is written.
4. **`add --target <filename>` writes directly.** When `--target` is specified, `append_to_yaml_file()` writes the entry directly to the specified file (creating it if needed), skipping `save_config` entirely.
5. **Deduplication on reload.** During directory loading, `_load_yaml()` deduplicates pattern entries by regex key, keeping the last occurrence (later files win). This ensures `99-custom.yaml`'s `enabled: False` correctly overrides the user file's `enabled: True` without duplication.
6. **To reset CLI-managed patterns**, delete `99-custom.yaml`.

### `remove --force` and confirmation

The `remove` command requests a confirmation prompt before deleting:

| Usage | Behavior |
|-------|----------|
| `remove 3` | Shows matched pattern, asks `Remove this pattern? [y/N]`, deletes on `y` |
| `remove 3 --force` | Skips confirmation, deletes immediately |
| `remove 3 --dry-run` | Shows what would be removed without executing |
| `remove 3 --force --dry-run` | `dry-run` takes precedence, shows would-remove message |

Protected patterns cannot be removed via CLI regardless of `--force` — edit the config file directly.

### `init` command — config directory creation

The `init` command creates a config directory at
`~/.hermes/custom-dangerous-patterns/` (directory mode is the **preferred
setup**). The directory is created with starter files:

- `00-test.yaml` — safe `[TEST]` patterns (all disabled)
- `01-examples.yaml` — example patterns (only with `--with-examples`)

CLI write operations:
- `enable` / `disable`: write delta entries to `99-custom.yaml`
- `add` (without `--target`): writes delta entries to `99-custom.yaml`
- `add --target <filename>`: writes directly to the specified file (must have `.yaml` extension)
- `remove`: edits source files directly via ruamel.yaml round-trip deletion

User-created files like `10-cloud.yaml` are never modified by `enable`, `disable`, or `add` (without `--target`).

### Glob-to-Regex Pattern Entry (`add --interactive` and `add --glob`)

The `add` command supports glob-style pattern entry so users don't need to write raw regex.

**Conversion rules** (in `patterns.py:glob_to_regex()`):
- Whitespace runs → `\\s+`
- `*` → `\\S+`  (one non-whitespace word — **positional**)
- `**` → `.*`    (match anything including whitespace — **super wildcard**)
- `?` → `.`      (match exactly one char)
- `{a,b}` → `(?:a|b)`  (**brace expansion** — each alt includes the prefix)
- Regex meta-chars (`. ^ $ + [ ] \\ | ( )`) → escaped
- `\\b` word boundaries added at alphanumeric starts/ends

**Examples:**

| Glob | Generated regex | Behavior |
|---|---|---|
| `echo hello` | `\\becho\\s+hello\\b` | Match exactly two words |
| `rm -rf /tmp/*` | `\\brm\\s+-rf\\s+/tmp/\\S+` | Trailing `*` matches one path component |
| `docker ** rm` | `\\bdocker\\s+.*\\s+rm\\b` | `**` matches any arguments between `docker` and `rm` |
| `docker * rm` | `\\bdocker\\s+\\S+\\s+rm\\b` | `*` matches exactly ONE argument between `docker` and `rm` |
| `mycli * delete *` | `\\bmycli\\s+\\S+\\s+delete\\s+\\S+` | Positional: `delete` must be the second argument |
| `ls *.{env,bak}` | `\\bls\\s+(?:\\S+\\.env|\\S+\\.bak)` | Brace expansion: match `.env` or `.bak` extensions |
| `deploy {prod,staging}` | `\\bdeploy\\s+(?:prod|staging)` | Match `deploy prod` or `deploy staging` |

**Interactive flow:**
1. Type `echo hello` → regex `\\becho\\s+hello\\b` is generated and shown
2. Confirm with Y (accept), n (try another glob), edit (write raw regex), or Enter (skip glob, write regex)
3. Optionally enter a single example command to test against the generated regex
4. If the example fails, a warning is shown and the user can edit the glob and re-test
5. Description prompt shows the glob as a default (e.g. `Enter description [echo hello]:`). Press Enter to accept the glob as the description, or type a custom one. Empty input re-prompts.

**Config field:** The original glob is saved in an optional `glob` field alongside `pattern` in the YAML config for reference.

**YAML field order:** `_clean_for_serialization` emits fields in this canonical order:
```
description: echo hello       # always
enabled: false                 # only if disabled (omitted when true)
protected: true                # only if protected (omitted when false)
group: test                    # only if set
glob: echo hello               # only if regex was generated from glob
pattern: \\becho\\s+hello\\b   # always (the actual regex)
examples:                      # only if provided
  - echo hello world
```

**Non-interactive:** Use `--glob` instead of `--pattern`. Mutually exclusive — cannot specify both.

### `*` vs `**` — positional vs super wildcard

- `*` between tokens matches **exactly one argument** (non-whitespace word). Use it when you know the command structure — e.g., `mycli * delete *` matches `mycli instance delete instance1` but NOT `mycli instance interface delete interface1` (too many args before `delete`).
- `**` between tokens matches **any number of arguments** (including zero). Use it when the argument count is unknown — e.g., `docker ** rm` matches `docker container rm` AND `docker container network rm`.

### Brace expansion `{a,b}`

Shell-compatible brace expansion: the prefix before `{` is shared by all alternatives.

- `{prod,staging}` → matches `prod` or `staging`
- `*.{env,bak}` → matches `*.env` or `*.bak` (prefix `*.` shared)
- `{hello}{a,b}` → skips single-alt `{hello}`, expands `{a,b}` as `(?:{hello}a|{hello}b)`

A single alternative (`{hello}`) or empty braces (`{}`) are treated as literal text, not expansion.

### `add --target` — writing to a specific file

The `add` command supports a `--target <filename>` flag to write the new
pattern entry directly to a named file in the config directory, bypassing
the `save_config` delta system.

**Rules:**
- Requires directory mode (config path must be a directory)
- File name must end with `.yaml`
- File name must not contain path separators (no `/`)
- If the file doesn't exist, it is created
- The entry is cleaned via `_clean_for_serialization` for proper YAML field order

**Use case:** Organize patterns by tool or team:

```bash
hermes custom-dangerous-patterns add --target 10-cloud.yaml --type block \
    --pattern '\\bvultr\\b' --description 'Vultr CLI' --group cloud

hermes custom-dangerous-patterns add --target 20-database.yaml --type block \
    --pattern '\\bDROP\\s+DATABASE\\b' --description 'SQL DROP' --group database
```

### Adding a new subcommand

1. Add the `cmd_*` handler in `cli.py` (returns `tuple[str, int]`)
2. Add the `_handle_*` adapter in `cli.py` (calls `cmd_*`, calls `_emit()`)
3. Add the subparser + arguments in `register_cli()` in `cli.py`
4. No changes needed in `__init__.py` — the single `setup_fn` call already delegates everything to `register_cli()`
