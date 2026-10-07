# Change Log

## 0.5.1

- Require Hermes >=0.21.4 so block patterns can't silently fail open on older cores.
- Fix several bundled example rules that could never match the commands they were written to catch.
- Correct the built-in overlap warning so it only fires on deferrals that actually happen.
- Remove unreachable example rules shadowed by the generic git-write deny rules.

## 0.5.0

**Breaking.** The plugin no longer modifies any Hermes internal — enforcement now runs
through the public `pre_tool_call` hook, and approvals granted under 0.4.x must be
granted once more. Background and reasoning:
[Migrating to 0.5.0](https://github.com/scross01/custom-dangerous-patterns-plugin/wiki/Migrating-to-0.5.0).

- All Hermes core overrides removed; block and deny patterns are enforced through a single public `pre_tool_call` hook.
- Block patterns now route through Hermes's own human approval prompt; deny patterns still block unconditionally.
- Custom patterns are matched with Hermes's own command normalizer, so shell-splicing evasions no longer slip past your rules.
- Approval keys are now derived from the regex, so editing a pattern's description no longer resets your `always` approvals.
- Removed `allow_patterns`, which no supported Hermes surface can honor; existing entries are reported as inert, never auto-deleted — use Hermes's own `command_allowlist` instead.
- A custom block pattern that overlaps a Hermes built-in is deferred to the built-in gate so only one prompt appears.
- In a bare headless run with no unattended marker, custom block patterns are now blocked where they previously auto-approved.
- Dropped the unknown `provides_cli_commands` manifest field, which logged a warning on every startup.

## 0.4.5

- Refuse catch-all `allow_patterns` (e.g. `.*`) that would silently exempt every command.
- Resolve the match-log directory via Hermes' `get_hermes_home()`.
- Document that the match log persists full command text.

## 0.4.4

- Added more example rules. Thanks the @gothicserpent for the contribution.

## 0.4.3

- Replace test glob fixtures with benign alternatives so the plugin security scanner does not flag them.

## 0.4.2

- Reword the README hardening note to avoid the persistence keyword in the plugin security scanner.

## 0.4.1

- Move destructive test fixtures into `tests/fixtures/scan_safe_patterns.yaml` so the plugin security scanner no longer flags them.
- Reword the README's root-privilege tier description to avoid the privilege-escalation keyword in the plugin security scanner.

## 0.4.0

- Upgrade `plugin.yaml` to manifest v2, resolving Hermes's unknown-manifest-field warning and the `--allow-tool-override` consent prompt.
- Replace the static built-in pattern snapshot in `cli.py` with a runtime import, so `list --builtins` always reflects Hermes's current list.
- Stop shipping dangerous-pattern literals in source and documentation, clearing most plugin security scanner findings.

## 0.3.5

- Fix import location of Hermes default dangerous patterns. #2

## 0.3.4

- `add` warns when a new allow pattern could shadow a Hermes built-in dangerous pattern without a covering custom block pattern.
- `info` now reports config integrity for directory configs.
- New bundled example patterns for package managers (`brew`, `npm`, `pip`, `cargo`, `uv`), included by `init --with-examples`.
- Deny-pattern guard logs a warning and delegates to the original guard instead of crashing if the Hermes guard call signature changes.

## 0.3.3

- `init --with-examples` now copies all new bundled example files.
- Update glob to regex conversion to prevent command name matching directory components.
- Handle missing rich dependency and fix errors in `logs` help and `logs --follow` Ctrl-C.

## 0.3.2

- **Security fix:** replace `tempfile.mktemp()` with `tempfile.NamedTemporaryFile()` to eliminate a TOCTOU race condition (CodeQL `py/insecure-temporary-file`).

## 0.3.1

- `logs` now extracts the plugin's log entries correctly.
- Auto-convert `glob` to `pattern` on config load.
- `validate` warns when a stored `pattern` disagrees with its `glob`.

## 0.3.0

- **BREAKING:** Config directory renamed from `custom-dangerous-patterns.d/` to `custom-dangerous-patterns/`:
  ```bash
  mv ~/.hermes/custom-dangerous-patterns.d ~/.hermes/custom-dangerous-patterns
  ```
- Added the `hermes custom-dangerous-patterns` CLI with `list`, `test`, `init`, `enable`, `disable`, `validate`, `info`, `logs`, `add`, and `remove`, plus `--dry-run` on all write commands.

## 0.2.0

- Deny patterns block commands immediately without an approval prompt.
- Per-pattern `enabled`, `group`, and `protected` fields for activation, categorization, and integrity tracking.
- Config integrity tracking and a protected-pattern tier that logs a `CRITICAL` warning on removal or modification.
- Allow shadowing detection, directory config loading, and a comprehensive test suite.

## 0.1.0

- **Initial release**.
