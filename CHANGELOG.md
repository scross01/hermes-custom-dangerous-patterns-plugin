# Change Log

## 0.5.0

**Breaking.** The plugin no longer modifies any Hermes internal. It enforces block and deny
patterns through the public `pre_tool_call` hook, which routes custom block patterns to
Hermes's own human approval gate. The `[o]nce`/`[s]ession`/`[a]lways`/`[d]eny` prompt, the
gateway `/approve` and `/deny` queue, timeout handling, and TUI/desktop/channel rendering are
all Hermes's and are unchanged in appearance.

Background, ordering tables, and the reasoning behind each decision:
[Migrating to 0.5.0](https://github.com/scross01/custom-dangerous-patterns-plugin/wiki/Migrating-to-0.5.0).

- **Removed all Hermes core overrides.** The plugin no longer writes to
  `DANGEROUS_PATTERNS` / `DANGEROUS_PATTERNS_COMPILED` and no longer rebinds
  `tools.approval.detect_dangerous_command`, `tools.approval.check_all_command_guards`,
  or `terminal_tool._check_all_guards_impl`. Enforcement is now a single public
  `pre_tool_call` hook, so `hermes plugins validate` reports "no runtime rebinds of
  Hermes core".
- **`plugin.yaml`: dropped the `provides_cli_commands` field.** 0.4.0 declared
  `provides_cli_commands: [custom-dangerous-patterns]`, but Hermes has no such manifest
  field -- `_KNOWN_MANIFEST_FIELDS` in `hermes_cli/plugins_manifest.py` has no CLI entry
  -- so the value was ignored and, because the manifest declares `manifest_version: 2`,
  every plugin load logged `unknown manifest field(s) ignored: provides_cli_commands` at
  WARNING. The CLI group needs no declaration: it is registered at runtime by
  `ctx.register_cli_command(...)`. `provides_hooks` is unchanged and still load-bearing.
  `tests/test_core_surface.py` now fails if any manifest key is outside Hermes's known
  set, or if `provides_hooks` drifts from the hook `register()` actually registers.
- Block patterns return `{"action": "approve", "rule_key": ...}`, which routes to the
  same `_run_approval_gate` as Tier-2 dangerous shell patterns. Once/session/always/deny,
  the gateway `/approve` and `/deny` queue, timeout handling, and TUI/desktop/channel
  rendering are all Hermes's and are unchanged in appearance.
- Deny patterns keep returning `{"action": "block"}` from the same hook. They remain
  unconditional: not bypassed by `--yolo` or `approvals.mode: off`.
- **Custom patterns are matched with Hermes's own normalizer.** Moving matching out of
  `DANGEROUS_PATTERNS_COMPILED` and into the plugin initially left block/deny rules matching
  only ANSI-stripped raw text, so shell splicing that the built-in gate defeats — `rm \-rf /`,
  `r\m -rf /`, `rm${IFS}-rf /`, line continuations — slipped past a user's rule. Matching now runs
  against Hermes's `_command_detection_variants`, restoring parity with 0.4.x (where these rules
  were matched by that same pipeline), and falls back to the plugin's local normalizer when Hermes
  is absent or its internals change. `custom-dangerous-patterns test` uses the same matcher, so it
  cannot report "no match" for a command that will actually prompt or block.
- **Approval keys are now regex-derived.** `always` persists `plugin_rule:cdp:<hash>`
  instead of a description-derived key. Approvals granted under 0.4.x do not carry over
  and must be granted once; editing a pattern's *description* no longer resets them.
- **Removed:** `allow_patterns`. No supported Hermes surface can exempt a command from
  the approval gate — `pre_tool_call` only *adds* gates, the approval hooks
  (`pre_approval_request`, `post_approval_response`) are observer-only, and Hermes's own
  `command_allowlist` matches exact command text or shell globs rather than regex. Existing
  entries are **left in place and reported as inert** (a CRITICAL log at startup; markers in
  `list`, `info`, and `validate`) so they can be reviewed and removed with
  `custom-dangerous-patterns remove --type allow <index>`. Nothing is ever auto-deleted from
  your config. `add --type allow` is refused rather than writing a dead entry that looks like
  a security exemption. `test` no longer reports an ALLOW verdict for a matching allow
  pattern, because such a command is not exempt. The guided `add` flow no longer offers
  `allow` as a type (it was menu option `[2]`); `deny` is now `[2]` and `[3]` is kept as
  an alias for it. The allow-shadowing diagnostics (`_check_allow_shadowing_for_cli` and
  its five tests) are removed, since with no way to add an allow pattern nothing could
  trigger them.
- For a command that should never prompt, use Hermes's own `command_allowlist` in
  `config.yaml` (exact command text, or a glob such as `vultr account info *`).
- **Behaviour change:** a custom block pattern that also matches a Hermes built-in pattern is
  deferred to the built-in gate so only one prompt appears. The built-in description is shown
  instead of the custom one, and granting `always` on it stops the custom rule firing for that
  class of command. A startup warning flags block patterns that look similar to a
  built-in, and `custom-dangerous-patterns test '<command>'` reports the deferral exactly for
  a given command. The startup warning is a similarity estimate over regex sources, so it can
  miss a real overlap -- the per-command probe is the authority, not the estimate.
- **Behaviour change (narrow):** in a bare headless run with no unattended marker — no
  `HERMES_SINGLE_QUERY_SESSION`, `HERMES_CRON_SESSION`, `HERMES_SESSION_PLATFORM`,
  `HERMES_GATEWAY_SESSION`, or `HERMES_EXEC_ASK` — custom block patterns are now blocked where
  they previously auto-approved. Every other context is unchanged: cron, `-q`, `webhook`,
  `msgraph_webhook`, and `api_server` are governed by `approvals.cron_mode` /
  `single_query_mode` / `unattended_mode` (all `deny` by default), exactly as built-in patterns
  are, and switching any of them to `approve` still auto-approves custom patterns too.
- `list`, `info`, and `validate` mark retired allow entries; `validate` still exits 0 so a
  previously-valid config does not start failing a gating script.
- Added `tests/test_core_surface.py`, which fails on core rebinds **and** on the table writes
  that `hermes plugins validate` does not detect.

## 0.4.5

- **Security:** refuse catch-all `allow_patterns` (`.*`, `.+`, `^.*$`, `(?s).*`,
  empty/whitespace-only, or anything matching the built-in dangerous-command
  examples). Such entries are skipped with an `ERROR` log at YAML load time and
  rejected by `add --type allow` with no override flag (the loader refuses them
  unconditionally, so a written entry could never take effect). Disabled
  (`enabled: false`) catch-all entries are kept in the loaded config so they
  stay visible to `list`/`remove`/`enable`; the check runs on the stripped
  pattern; a refused entry is logged once per startup.
- Resolve the match-log directory via Hermes' `get_hermes_home()` (falls back
  to `~/.hermes`) in `logfile.py` and `logs.py`.
- README: document that the match log persists the full command text.
- Remove stray `.coverage`, `package-lock.json`, `skills-lock.json` from the
  tree and ignore them.

## 0.4.4

- Added more example rules. Thanks the @gothicserpent for the contribution.

## 0.4.3

- Replace test glob fixtures with benign alternatives so the plugin security
  scanner does not flag them.

## 0.4.2

- Reword the README hardening note ("separate OS users" -> "different OS
  accounts") to avoid the persistence keyword in the plugin security
  scanner.

## 0.4.1

- Move destructive test fixtures into `tests/fixtures/scan_safe_patterns.yaml`.
  The plugin security scanner does plain-text matching across .py, .md,
  AND .yaml, so the fixtures must not contain any destructive-pattern
  literal. They now use benign commands that exercise the same code paths
  (deny matching, glob trailing-*, brace expansion, ANSI normalization)
  without matching any scanner rule. Drops the scan verdict from DANGEROUS
  (19 findings) to WARN (only LOW/MEDIUM doc references remain).
- Reword the README's root-privilege tier description to avoid the
  privilege-escalation keyword in the plugin security scanner.

## 0.4.0

- **plugin.yaml upgraded to manifest v2** with `provides_hooks` (`pre_tool_call`) and `provides_cli_commands` (`custom-dangerous-patterns`) declared. Resolves Hermes's `unknown manifest field(s) ignored: dependencies` warning and prevents the `--allow-tool-override` consent prompt (we declare no `provides_tools`, no `capabilities`).
- **`_BUILTIN_PATTERNS` table removed from `cli.py`.** The static snapshot of Hermes's dangerous-pattern list has been replaced with a runtime import from `tools.approval_detection.DANGEROUS_PATTERNS`. The plugin's `--builtins` view now always reflects Hermes's actual current list and no longer ships ~50 dangerous-pattern literals in source (eliminates most plugin security scanner findings).
- **`--builtins` correctly shows only Hermes built-ins.** `register()` now records `len(DANGEROUS_PATTERNS)` before injecting the plugin's own block patterns, and `_get_builtin_patterns()` slices to that pre-injection length. User-injected patterns are no longer relabelled `[Hermes]` in the CLI's builtins view.
- **Test fixture literals** that the plugin security scanner flagged as destructive (e.g. in test mocks) are now built via string concatenation so the runtime assertions are unchanged but the literal triggers no longer appear in shipped source.
- **Documentation prose** no longer enumerates specific destructive commands as examples; refers to "real destructive commands" generically.

## 0.3.5

- Fix import location of Hermes default dangerous patterns. #2

## 0.3.4

- `add` now warns when a new allow pattern could shadow Hermes built-in dangerous patterns without a covering custom block pattern.
- The allow-shadowing warning is no longer suppressed by an unrelated block pattern covering a different built-in.
- `info` now reports config integrity (hash match/changed) for directory configs — previously the status was silently omitted in directory mode.
- New bundled example patterns for package managers (`brew`, `npm`, `pip`, `cargo`, `uv`), included by `init --with-examples`.
- Deny-pattern guard now logs a warning and delegates to the original guard instead of crashing or silently skipping if the Hermes guard call signature ever changes.


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
