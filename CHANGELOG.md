# Change Log

## 0.3.0

- Added — `hermes custom-dangerous-patterns` CLI
    - **`list`** — List all custom patterns with filtering by type, group, search, status
    - **`test <command>`** — Test a command against all pattern types (deny, allow, block, built-in)
    - **`init`** — Create a starter config with first-run guidance
    - **`enable / disable`** — Toggle patterns by index, description, or group
    - **`validate`** — Validate config syntax and regexes (supports `--quiet` for CI)
    - **`info`** — Dashboard showing plugin state, integrity, groups, protected patterns
    - **`logs`** — Extract plugin-specific log entries from Hermes logs
    - **`add / remove`** — Add/remove patterns interactively or via CLI flags
    - `--dry-run` flag on all write commands for previewing changes
    - `list --builtins` for viewing Hermes built-in patterns
    - `test --skip-builtins` to focus on custom patterns only

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