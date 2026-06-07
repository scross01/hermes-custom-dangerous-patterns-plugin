# Change Log


## 0.3.3

- `init --with-examples` now copies all new bundled example files.
- Update glob to regex conversion to prevent command name matching directory components.
- Handle missing rich dependency, prevent potential ImportErrors when rendering output.
- Fix error in help for logs subcommand.
- Fix `ValueError` on Ctrl-C when exiting `logs --follow` mode.

## 0.3.2

- **Security fix:** Replaced `tempfile.mktemp()` with `tempfile.NamedTemporaryFile()` in `_write_yaml()` to eliminate a TOCTOU race condition (CodeQL `py/insecure-temporary-file`). The atomic write pattern is preserved; the temp file is now created securely and cleaned up on all failure paths.

## 0.3.1

- **`logs` command** now extracts the plugins logs corectly. 
- **Glob auto-conversion on config load.** When a pattern entry has `glob` but no `pattern`, the regex is automatically generated from the glob
- **`validate` glob mismatch warning.** If both `glob` and `pattern` are defined and the stored pattern differs from the pattern generated from the glob, `validate` now emits a warning highlighting the discrepancy.

## 0.3.0

- **BREAKING:** Config directory renamed from `custom-dangerous-patterns.d/` to `custom-dangerous-patterns/`. If you have an existing `.d/` directory, rename it manually:
  ```bash
  mv ~/.hermes/custom-dangerous-patterns.d ~/.hermes/custom-dangerous-patterns
  ```
- Added — `hermes custom-dangerous-patterns` CLI
    - **`list`** — List all custom patterns with filtering by type, group, search, status
    - **`test <command>`** — Test a command against all pattern types (deny, allow, block, built-in)
    - **`init`** — Create a starter config with first-run guidance
    - **`enable / disable`** — Toggle patterns by index, description, or group
    - **`validate`** — Validate config syntax and regexes (supports `--quiet` for CI)
    - **`info`** — Dashboard showing plugin state, integrity, groups, protected patterns
    - **`logs`** — Extract plugin-specific log entries from Hermes logs
    - **`add`** — Add patterns interactively or via CLI flags
    - **`remove`** — Remove patterns interactively or by index/description
    - `--dry-run` flag on all write commands for previewing changes
    - `list --builtins` for viewing Hermes built-in patterns
    - `test --skip-builtins` to focus on custom patterns only
    - `add --glob` for glob-style pattern entry (converted to regex automatically)
    - `add --target <filename>` to write directly to a specific `.yaml` file in the config directory
    - `remove --force` to skip the confirmation prompt

## 0.2.0

- **Deny patterns** — block commands immediately without an approval prompt.
- **`enabled` / `group` / `protected` fields** — per-pattern control over activation, categorization, and integrity tracking.
- **Config integrity tracking** — SHA-256 hash of config persisted across sessions; changes trigger warnings.
- **Protected pattern tier** — critical patterns (`protected: true`) have regex hashes tracked; removal/modification logs a `CRITICAL` warning.
- **Allow shadowing detection** — warns when an allow pattern could bypass a built-in dangerous pattern.
- **Directory config loading** — set config path to a directory to load and merge all `*.yaml` files.
- **Comprehensive test suite** — ~665 lines of tests covering all new features.

## 0.1.0

- **Initial release**.