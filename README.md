# Custom Dangerous Patterns plugin for Hermes Agent

> **⚠️ USE AT YOUR OWN RISK**
>
> This plugin is in **early development** and has not been rigorously tested
> across all Hermes environments, versions, or edge cases. There is **no
> guarantee** that all destructive commands will be caught or blocked. Pattern
> matching is best-effort — creative command obfuscation, shell expansions,
> piped commands, or edge cases in the approval flow may bypass detection.
> **Do not rely on this plugin as your sole safety net for critical operations.**

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that adds custom dangerous command patterns to Hermes's built-in approval system.

## What It Does

Hermes ships with ~47 hardcoded dangerous command patterns (`rm -rf`, `git reset --hard`, `docker stop`, etc.). When a command matches, you get an interactive approval prompt: `[o]nce`, `[s]ession`, `[a]lways`, or `[d]eny`.

This plugin lets you define **your own patterns** in a YAML config file. They get the exact same approval flow — same prompts, same session persistence, same permanent allowlist, same gateway `/approve` and `/deny` support.

**Use cases:**
- Guard cloud CLI tools (`vultr`, `gcloud`, `aws`, `az`)
- Protect deployment scripts (`cap deploy`, `fab deploy`)
- Block dangerous database operations (`DROP TABLE`, `mongodump --drop`)
- Gate any command that should require explicit human approval

## Installation

### Recommended: Install via Hermes CLI

```bash
hermes plugins install scross01/hermes-custom-dangerous-patterns-plugin
hermes plugins enable custom-dangerous-patterns
```

The `install` command clones the repo into `~/.hermes/plugins/custom-dangerous-patterns/`
and prompts to enable it. Use `--enable` to skip the prompt:

```bash
hermes plugins install scross01/hermes-custom-dangerous-patterns-plugin --enable
```

### Updating

```bash
hermes plugins update custom-dangerous-patterns
```

Then restart Hermes for the changes to take effect.

### Alternative: Manual clone or symlink

```bash
git clone https://github.com/scross01/hermes-custom-dangerous-patterns-plugin.git \
    ~/.hermes/plugins/custom-dangerous-patterns
```

Or if you already have the source elsewhere:

```bash
ln -s /path/to/hermes-custom-dangerous-patterns-plugin \
      ~/.hermes/plugins/custom-dangerous-patterns
```

**Important:** The directory inside `~/.hermes/plugins/` must be named `custom-dangerous-patterns`
(with the trailing `s`).

Then enable:

```bash
hermes plugins enable custom-dangerous-patterns
```

### Step 2: Create the config

Easiest — use the interactive bootstrap:

```bash
hermes custom-dangerous-patterns init --with-examples
```

This creates `~/.hermes/custom-dangerous-patterns/` (a directory) with:
- `00-test.yaml` — safe `[TEST]` patterns (all disabled)
- All bundled example files copied individually (`01-cloud.yaml`, `02-infra.yaml`, `03-tools.yaml`, `04-package-managers.yaml`) — fully-enabled example patterns (only with `--with-examples`)

Without `--with-examples`, creates a minimal config directory with safe test patterns (all disabled).

Or create `~/.hermes/custom-dangerous-patterns/` manually — see [Configuration](#configuration).

> **Note:** Directory mode is the **preferred** configuration setup.
> The plugin also supports a single `custom-dangerous-patterns.yaml` file
> or *combined mode* where both the directory and sibling `.yaml` file are
> loaded and merged together.

### Step 3: Restart Hermes

The plugin loads at startup. Restart the gateway or start a new CLI session:

```bash
hermes gateway restart    # if using the gateway
# or just start a new `hermes` CLI session
```

### Step 4: Test it

Test your patterns without running real commands:

```bash
hermes custom-dangerous-patterns test "vultr instance delete --instance-id cb670a12"
```

Then try it live:

```
> vultr instance delete --instance-id cb670a12-e4f5-6d78-ab90-1234567890ab

⚠️ Dangerous command detected: Vultr destructive instance/snapshot command
    vultr instance delete --instance-id cb670a12-e4f5-6d78-ab90-1234567890ab

  [o]nce    — allow this one time
  [s]ession — allow for this session
  [a]lways  — always allow this pattern
  [d]eny    — block (default)
```

## Configuration

### Config Location

**Directory (preferred):**

```
~/.hermes/custom-dangerous-patterns/
```

All `*.yaml` files in the directory are loaded and merged alphabetically.
Most CLI write commands (`enable`, `disable`, `add` without `--target`)
write delta entries to `99-custom.yaml` — user-created files are never
modified.

Two exceptions:
- **`remove`** behavior depends on config mode:
  - **Single-file mode:** edits the source YAML file directly using `remove_entry_from_file()`, which scans all YAML files and deletes matching pattern entries at the YAML level — no `disabled: true` remnant is written.
  - **Directory mode:** removes the entry from the in-memory config and `save_config()` writes `enabled: false` to `99-custom.yaml` (delta). Source files are not modified.
- **`add --target <filename>`** writes to the specified file

**Single file (fallback):**

```
~/.hermes/custom-dangerous-patterns.yaml
```

**Combined mode:** When both the directory and the sibling `.yaml` file
exist, both are loaded and merged (directory files take precedence via
dedup).

Override with env var:

```bash
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/config.yaml

# Or point to a directory:
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/config-directory/
```

### Block Patterns

These commands trigger the approval prompt:

```yaml
patterns:
  - pattern: '\bvultr\b'
    description: 'Vultr CLI command'
    enabled: true
    group: cloud
    protected: false
    examples:
      - 'vultr account info'
      - 'vultr instance list'
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes* | Python regex (matched with `re.IGNORECASE \| re.DOTALL`). Can be omitted if `glob` is provided — the regex is auto-generated from the glob on config load. |
| `description` | Yes | Human-readable label shown in the approval prompt |
| `examples` | No | Documentation-only list of example commands |
| `enabled` | No | Boolean (default `true`). Set `false` to temporarily disable a pattern |
| `group` | No | Optional string tag for categorization (e.g., `cloud`, `database`, `testing`) |
| `protected` | No | Boolean (default `false`). If `true`, the pattern's regex is integrity-checked across sessions |
| `glob` | No | Original glob string saved when pattern was created via `--glob`. If `pattern` is not present, the glob is auto-converted to regex on config load. |

> **\* `pattern` or `glob` required.** At least one must be present. If both are provided, `pattern` is used as-is. If only `glob` is present, the regex is auto-generated during config validation.

### Deny Patterns

Commands matching deny patterns are **blocked immediately without an approval prompt**. They are checked **before** allow and block patterns — deny wraps the original guard function and intercepts first. Useful for commands that should *never* be run without manual config changes.

```yaml
deny_patterns:
  - pattern: '\bgit\s+push\s+--force\b'
    description: 'Force git push'
    enabled: true
    group: git
    examples:
      - 'git push --force origin main'
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes* | Python regex (same flags as block patterns). Can be omitted if `glob` is provided — auto-generated from glob. |
| `description` | Yes | Human-readable label shown in the block message |
| `examples` | No | Documentation-only list of example commands |
| `enabled` | No | Boolean (default `true`). Set `false` to temporarily disable |
| `group` | No | Optional string tag for categorization |
| `protected` | No | Boolean (default `false`). If `true`, integrity-checked across sessions |
| `glob` | No | Original glob string. If `pattern` is absent, auto-converted to regex on load. |

> **\* `pattern` or `glob` required.** At least one must be present. If both are provided, `pattern` is used as-is.

**Behavior note:** Deny patterns are checked by a wrapper around `check_all_command_guards()` that runs before `--yolo`/`mode=off` are evaluated. This means `--yolo` does **not** bypass deny patterns — an intentional safeguard that ensures deny-gated commands are always blocked regardless of mode. A future Hermes core integration (v0.5.0) may add native deny-pattern support upstream, at which point this workaround can be removed.

### Allow Patterns

Exempt specific commands from approval, even if they match a block pattern:

```yaml
allow_patterns:
  - pattern: '\bvultr\s+(account\s+info|instance\s+list)\b'
    description: 'Read-only Vultr commands'
    enabled: true
    group: cloud
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes* | Python regex (same flags as block patterns). Can be omitted if `glob` is provided — auto-generated from glob. |
| `description` | No | Documentation-only label |
| `enabled` | No | Boolean (default `true`). Set `false` to temporarily disable |
| `group` | No | Optional string tag for categorization |
| `protected` | No | Boolean (default `false`). If `true`, integrity-checked across sessions |
| `glob` | No | Original glob string. If `pattern` is absent, auto-converted to regex on load. |

> **\* `pattern` or `glob` required.** At least one must be present. If both are provided, `pattern` is used as-is.

### A Note on `\b` (Word Boundaries)

Patterns use `\b` to match whole words only. This prevents false positives where a command name appears as a substring:

| Pattern | Matches | Doesn't match |
|---------|---------|---------------|
| `\bvultr\b` | `vultr instance list` | `echo vultr_test`, `my-vultr-server` |
| `\baws\s+ec2\b` | `aws ec2 describe-instances` | `aws-ec2-tool`, `paws ec2` |
| `\bterraform destroy\b` | `terraform destroy -auto-approve` | `echo "terraform destroy"` in a script |

Without `\b`, `\bvultr` would match any string containing "vultr" — including hostnames, variable names, or unrelated commands. The `\b` anchor ensures the pattern only triggers on the actual CLI tool name.

**Tip:** Use single-quoted YAML strings for patterns — backslashes pass through literally (`'\bvultr\b'`), avoiding the double-escaping needed with double quotes (`"\\bvultr\\b"`).

### Evaluation Order

> **Note:** The runtime evaluation order differs from the logical order because the deny-pattern wrapper runs *before* the original `check_all_command_guards()` function that contains the yolo/mode=off check. This means deny patterns intercept `--yolo` and `mode=off`.

Each check is tagged with its source:
- `[Plugin]` — this plugin's custom checks
- `[Hermes]` — Hermes Agent's built-in checks

```
 1. [Plugin]  Deny patterns (custom)        → BLOCKED immediately, no prompt
 2. [Hermes]  Hardline check                → blocked unconditionally
 3. [Hermes]  Sudo stdin guard              → blocked unconditionally
 4. [Hermes]  Yolo / mode=off               → bypasses steps 5-7
 5. [Plugin]  Allow patterns (custom)       → command runs, no prompt (allow wins)
 6. detect_dangerous_command():             — same approval prompt for both —
    a. [Plugin]  Block patterns (custom)    → [o]nce/[s]ession/[a]lways/[d]eny
    b. [Hermes]  Built-in patterns          → [o]nce/[s]ession/[a]lways/[d]eny
 7. [Hermes]  Tirith security scan          → approval prompt if findings
```

**What each tier means:**

| Tier | Source | Behavior | Prompt? | Bypassed by `--yolo`? |
|------|--------|----------|---------|----------------------|
| Deny patterns | Plugin | **Immediate block** — command is rejected before any approval logic runs | ❌ No | ❌ No |
| Hardline / Sudo | Hermes | **Unconditional block** — catastrophic or dangerous-by-design commands | ❌ No | ❌ No |
| Allow patterns | Plugin | **Silent pass** — command runs without any check (allow wins over block) | ❌ No | N/A |
| Block patterns | Plugin | **Approval prompt** — same as built-in DANGEROUS_PATTERNS | ✅ Yes | ✅ Yes |
| Built-in patterns | Hermes | **Approval prompt** — Hermes's ~47 hardcoded dangerous command patterns | ✅ Yes | ✅ Yes |
| Tirith scan | Hermes | **Approval prompt** — security scan of command content | ✅ Yes | ✅ Yes |

**Key rules:**
- **Allow wins over block.** If a command matches both an allow pattern and a block pattern, allow wins and no prompt is shown.
- **Deny wins over allow.** Deny patterns are checked before allow patterns. If a command matches a deny pattern, it is blocked before allow patterns are even evaluated.
- **Deny is immediate-block; block is approval-prompt.** Block patterns and built-in patterns both go through the same `detect_dangerous_command()` approval flow. Deny patterns skip it entirely.
- **Deny bypasses yolo.** Deny patterns are evaluated outside the original guard function, so `--yolo` does not bypass them.

### Config Integrity & Protected Patterns

The plugin tracks the integrity of your configuration across sessions:

- **Config hash tracking:** A SHA-256 hash of your full config YAML is stored in `~/.hermes/.custom-patterns-hash`. If the config changes between sessions, a `WARNING` is logged with the old and new pattern counts.
- **Protected patterns:** Patterns with `protected: true` have their individual regex SHA-256 hashed and tracked. If a protected pattern is **modified** or **removed**, a `CRITICAL` security warning is logged at startup.
- **Allow shadowing detection:** When an allow pattern could bypass a built-in dangerous pattern without a corresponding custom block pattern, a `WARNING` is logged with the details.

These integrity checks provide defense-in-depth against unauthorized config tampering, but they are **detective, not preventive** — the plugin detects and logs changes but does not prevent them. See [Security & Risks](#security--risks) for more on the trust model.

### Directory Config Loading

Instead of a single file, you can use a **directory**. The plugin loads all `*.yaml` files in alphabetical order and merges them:

- Lists (`patterns`, `allow_patterns`, `deny_patterns`) are **extended** (appended)
- Scalars override previous values

This is useful for splitting configs by tool or team:

```bash
~/.hermes/custom-dangerous-patterns/
├── 10-cloud.yaml       # cloud CLI patterns
├── 20-database.yaml     # database patterns
└── 30-deployment.yaml   # deploy tool patterns
```

Use `hermes custom-dangerous-patterns init` to create a config directory
with starter files, or set the directory path via `$HERMES_CUSTOM_PATTERNS_PATH`.

### Full Example

```yaml
# ~/.hermes/custom-dangerous-patterns.yaml
#
# TIP: Use single-quoted strings for patterns — backslashes pass through
# literally:  '\bvultr\b'  not  "\\bvultr\\b"

patterns:
  # ── Cloud CLI tools (destructive) ────────────────────────────────
  - pattern: '\bvultr\s+(instance\s+create|instance\s+delete|snapshot\s+create|snapshot\s+delete)\b'
    description: 'Vultr destructive instance/snapshot command'
    examples:
      - 'vultr instance delete --instance-id cb670a12-e4f5-6d78-ab90-1234567890ab'
      - 'vultr snapshot delete --snapshot-id 5a3b2c1d'

  - pattern: '\bterraform\s+(destroy|apply)\b'
    description: 'Terraform destroy/apply (infrastructure mutation)'
    examples:
      - 'terraform destroy -auto-approve'
      - 'terraform apply -auto-approve'

  - pattern: '\baws\s+(ec2|s3|rds|iam|lambda|cloudformation)\b'
    description: 'AWS CLI mutating service command'
    examples:
      - 'aws ec2 terminate-instances --instance-ids i-12345'
      - 'aws s3 rb s://my-bucket --force'
      - 'aws rds delete-db-instance --db-instance-identifier mydb'

  - pattern: '\bgcloud\s+(compute\s+instances\s+delete|projects\s+delete)\b'
    description: 'GCP destructive command'
    examples:
      - 'gcloud compute instances delete my-vm --zone=us-central1-a'

  - pattern: '\boci\s+(compute\s+instance\s+terminate|database\s+db\s+system\s+delete|network\s+vcn\s+delete)\b'
    description: 'Oracle Cloud destructive command'
    examples:
      - 'oci compute instance terminate --instance-id ocid1.instance.oc1..aaaaaaaa'
      - 'oci database db-system delete --db-system-id ocid1.dbsystem.oc1..aaaaaaaa'

  - pattern: '\bdoctl\s+(compute\s+droplet\s+delete|kubernetes\s+cluster\s+delete|databases\s+delete)\b'
    description: 'DigitalOcean destructive command'
    examples:
      - 'doctl compute droplet delete 12345678'
      - 'doctl kubernetes cluster delete my-cluster'

  - pattern: '\bkubectl\s+delete\s+namespace\b'
    description: 'Kubernetes namespace deletion'
    examples:
      - 'kubectl delete namespace staging'

  # ── Deployment tools ─────────────────────────────────────────────
  - pattern: '\bcap\s+\w+\s+deploy\b'
    description: 'Capistrano production deploy'
    examples:
      - 'cap production deploy'

  - pattern: '\bfab\s+\w*\s*deploy\b'
    description: 'Fabric deploy'
    examples:
      - 'fab deploy production'

  # ── Database operations ──────────────────────────────────────────
  - pattern: '\bDROP\s+(TABLE|DATABASE)\b'
    description: 'SQL DROP statement'
    examples:
      - 'DROP TABLE users'
      - 'DROP DATABASE production'

  - pattern: '\bmongodump\b.*--drop\b'
    description: 'MongoDB dump with --drop (overwrites existing data)'
    examples:
      - 'mongodump --drop --db production'

# ── Allow patterns ────────────────────────────────────────────────
# Commands matching these are EXEMPT from approval, even if they
# also match a blocked pattern. Evaluated BEFORE block patterns.
# Allow wins over block.

allow_patterns:
  # ── Read-only cloud commands (safe) ─────────────────────────────
  - pattern: '\bvultr\s+(account\s+info|instance\s+list|dns\s+list|plan\s+list)\b'
    description: 'Read-only Vultr commands'

  - pattern: '\baws\s+(ec2\s+describe|s3\s+ls|s3\s+cp.*--dry-run|iam\s+list)\b'
    description: 'AWS read-only commands'

  - pattern: '\bterraform\s+(plan|state\s+list|output)\b'
    description: 'Terraform read-only commands'

  - pattern: '\boci\s+(compute\s+instance\s+list|network\s+vcn\s+list|database\s+db\s+system\s+list)\b'
    description: 'Oracle Cloud read-only commands'

  - pattern: '\bdoctl\s+(compute\s+droplet\s+list|kubernetes\s+cluster\s+list|databases\s+list)\b'
    description: 'DigitalOcean read-only commands'

  # ── Help and utility (safe) ─────────────────────────────────────
  - pattern: '\b(vultr|gcloud|aws|terraform|kubectl|oci|doctl)\s+(-h|--help|help)\b'
    description: 'Help flags are safe'

  - pattern: '\b(vultr|gcloud|aws|terraform|oci|doctl)\s+completion\b'
    description: 'Shell completion scripts are safe'
```

## CLI Reference

All commands follow the `hermes custom-dangerous-patterns <verb>` pattern, consistent with other Hermes subcommands like `hermes plugins`.

### `list` — Show your patterns

```bash
hermes custom-dangerous-patterns list                    # all patterns
hermes custom-dangerous-patterns list --type block       # block patterns only
hermes custom-dangerous-patterns list --type allow       # allow patterns only
hermes custom-dangerous-patterns list --type deny        # deny patterns only
hermes custom-dangerous-patterns list --group cloud      # patterns in a group
hermes custom-dangerous-patterns list --disabled         # only disabled patterns
hermes custom-dangerous-patterns list --enabled          # only active patterns
hermes custom-dangerous-patterns list --search aws       # search descriptions and patterns
hermes custom-dangerous-patterns list --builtins         # include Hermes built-in patterns (snapshot)
```

> **Note:** `--builtins` uses a static snapshot of Hermes's built-in patterns
> bundled at plugin install time. These may drift from Hermes core updates.

### `test <command>` — Verify patterns before running

Test a command against all patterns to see what would happen **without running it**.

```bash
hermes custom-dangerous-patterns test "vultr instance delete"
hermes custom-dangerous-patterns test "vultr account info" --verbose
hermes custom-dangerous-patterns test "git push --force" --skip-builtins
```

Shows which patterns match and the result: **DENY** (blocked immediately), **ALLOW** (runs freely), **APPROVAL PROMPT** (interactive prompt), or **PASS** (no patterns matched).

`--verbose` shows full pattern regex and built-in matches. `--skip-builtins` omits Hermes's ~47 built-in patterns to focus on custom patterns.

### `init` — First-run bootstrap

```bash
hermes custom-dangerous-patterns init                    # minimal config with safe [TEST] patterns (all disabled)
hermes custom-dangerous-patterns init --with-examples    # full example config (all enabled for demonstration)
hermes custom-dangerous-patterns init --force            # overwrite existing config without prompting
```

### `enable / disable` — Toggle patterns

Toggle patterns on/off without editing YAML. Target by index, description substring, or group.

```bash
hermes custom-dangerous-patterns enable 1                          # by index (from list output)
hermes custom-dangerous-patterns disable "Vultr"                    # by description substring
hermes custom-dangerous-patterns enable --group cloud               # all patterns in a group
hermes custom-dangerous-patterns enable --group testing --dry-run   # preview without saving
```

With no target or group specified, `enable` and `disable` launch
interactive selection automatically.

After any write command, the CLI reminds you to restart Hermes for changes to take effect.

### `validate` — Check config syntax

```bash
hermes custom-dangerous-patterns validate                    # validate default config
hermes custom-dangerous-patterns validate --path /tmp/cfg.yaml  # validate a specific file
hermes custom-dangerous-patterns validate --quiet            # exit code only (CI/CD)
```

Validates YAML syntax, regex compilation, and pattern consistency. In
addition to basic validation, if a pattern defines both `glob` and
`pattern` and the stored regex differs from what the glob would generate,
a warning is emitted to flag the discrepancy.

Exit code 0 = valid, 1 = errors found, 2 = file not found.

### `info` — State dashboard

Shows config path, pattern counts by type, integrity status, protected patterns, and group breakdown.

```bash
hermes custom-dangerous-patterns info
```

### `logs` — Extract plugin log entries

```bash
hermes custom-dangerous-patterns logs                          # all plugin log entries
hermes custom-dangerous-patterns logs --level WARNING          # filter by minimum level
hermes custom-dangerous-patterns logs --limit 20               # last 20 entries
hermes custom-dangerous-patterns logs --since 2026-06-01       # entries since a date
hermes custom-dangerous-patterns logs --follow                 # tail the log (Ctrl+C to exit)
```

### `add` — Add a pattern

Interactive guided prompts or CLI flags for scripting.

```bash
# Interactive (guided prompts for each field, with glob-to-regex support)
hermes custom-dangerous-patterns add

# Write to a specific file in the config directory
hermes custom-dangerous-patterns add --target 02-mycloud.yaml --type block \
    --pattern '\bheroku\s+(apps:destroy|pg:reset)\b' \
    --description 'Heroku destructive commands' \
    --group cloud

# Glob-style pattern entry (converted to regex automatically).
# * matches ONE word, ** matches ANYTHING, {a,b} for alternatives.
hermes custom-dangerous-patterns add --type block \
    --glob 'heroku *destroy*' \
    --description 'Heroku destructive commands'

# Non-interactive (full CLI flags)
hermes custom-dangerous-patterns add --type block \
    --pattern '\bheroku\s+(apps:destroy|pg:reset)\b' \
    --description 'Heroku destructive commands' \
    --group cloud
```

| Flag | Description |
|------|-------------|
| `-t` / `--type` | Pattern type: `block`, `allow`, or `deny` (required non-interactive) |
| `-p` / `--pattern` | Raw regex pattern (required non-interactive; mutually exclusive with `--glob`) |
| `--glob` | Glob-style pattern like `echo hello` — converted to regex automatically |
| `-d` / `--description` | Human-readable description |
| `-g` / `--group` | Optional group tag for categorization |
| `--examples` | One or more example commands |
| `--disabled` | Add as disabled (default: enabled) |
| `--protected` | Mark as protected (integrity tracked across sessions) |
| `--dry-run` | Preview without saving |
| `--target FILENAME` | Write to a specific `.yaml` file in the config directory (requires directory mode) |

> **Note:** `--pattern` and `--glob` are mutually exclusive. Without any
> flags, `add` launches interactive mode with guided prompts and
> glob-to-regex conversion.

### `remove` — Remove a pattern

```bash
# Interactive (shows numbered list)
hermes custom-dangerous-patterns remove

# By index (from `list` output)
hermes custom-dangerous-patterns remove 3

# By description substring
hermes custom-dangerous-patterns remove "Heroku"

# Force removal without confirmation prompt
hermes custom-dangerous-patterns remove 3 --force

# Preview without deleting
hermes custom-dangerous-patterns remove 7 --dry-run
```

| Flag | Description |
|------|-------------|
| `target` | Pattern index (from `list`) or description substring |
| `-t` / `--type` | Filter by type: `block`, `allow`, or `deny` |
| `--force` | Skip confirmation prompt |
| `--dry-run` | Preview without deleting |

Unlike `enable`/`disable` (which write delta entries to `99-custom.yaml`),
**`remove`** deletes the pattern from the active config:

- **Single-file mode:** edits the source YAML file directly using
  `remove_entry_from_file()`. The entry is deleted from the file — no
  `disabled: true` remnant is written.
- **Directory mode:** removes the entry from the in-memory config and
  `save_config()` writes `enabled: false` to `99-custom.yaml` (delta).
  User-created source files are not modified.

Protected patterns cannot be removed via CLI; edit the config file
directly to remove them.

---

## How It Works

The plugin injects your custom patterns into Hermes's `DANGEROUS_PATTERNS` list at startup via pattern injection + two monkey-patches:

1. **`detect_dangerous_command()`** — patched for allow-pattern support (allow patterns bypass all detection)
2. **`check_all_command_guards()`** — patched for deny-pattern support (deny patterns block immediately, no prompt)

```
Hermes startup:
  1. Plugin discovery → register(ctx) runs
  2. Resolves config path (env var → ~/.hermes/custom-dangerous-patterns/ directory or single .yaml file)
  3. Loads YAML (supports directory mode: all *.yaml files merged)
  4. Runs integrity checks (config SHA-256 hash, protected pattern verification)
  5. Compiles regex patterns (block, allow, deny)
  6. Appends block patterns to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED
  7. Monkey-patches detect_dangerous_command() for allow-pattern support
  8. Monkey-patches check_all_command_guards() for deny-pattern support
  9. Checks for allow shadowing (allow patterns that may bypass built-in patterns)
  10. Agent runs → allow/deny/block patterns checked in order → approval flow
```

The built-in approval system then handles everything automatically:

| Context | Behavior |
|---------|----------|
| **CLI** | Interactive `[o]nce`/`[s]ession`/`[a]lways`/`[d]eny` prompt |
| **Gateway** (Telegram/Discord/etc.) | `/approve` and `/deny` commands, async approval queue |
| **Session persistence** | "Session" choice survives for the session duration |
| **Permanent allowlist** | "Always" choice persists to `command_allowlist` in `config.yaml` |
| **Smart mode** | If `approvals.mode: smart`, auxiliary LLM assesses custom patterns |
| **Cron** | Respects `approvals.cron_mode` (deny by default) |
| **`--yolo`** | Block patterns (custom + built-in) are bypassed. **Deny patterns still block** — they intercept before the yolo check. |

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Config file missing | Plugin loads silently, no patterns injected |
| Config file invalid YAML | Log WARNING, plugin loads with empty pattern list |
| Invalid regex in pattern | Log WARNING for that pattern, skip it, load valid ones |
| Block pattern matches but allow also matches | Allow wins — no prompt (allow wins over block) |
| Deny pattern matches (and allow also matches) | Deny wins — blocked immediately (deny checked before allow) |
| Deny pattern match | Blocked immediately, no prompt |
| `--yolo` mode | Block patterns (custom + built-in) bypassed. Deny patterns still block — checked outside the original guard function. |
| `approvals.mode: off` | Block patterns bypassed. Deny patterns still block — checked outside the original guard function. |
| `approvals.mode: smart` | Custom patterns assessed by auxiliary LLM |
| Cron session + `cron_mode: deny` | Custom patterns blocked in cron |
| Container backend (docker, etc.) | All approval checks skipped (sandboxed) |
| `command_allowlist` "always" choice | Persisted to config.yaml — survives restarts |
| Config changed since last session | WARNING logged with old/new pattern counts |
| Protected pattern missing/modified | CRITICAL warning logged at startup |
| Allow pattern shadows built-in pattern | WARNING logged with details |

## Security & Risks

> The plugin's stance on self-modification is: **allow it, detect it, log it.**

The agent running Hermes can read and write `~/.hermes/custom-dangerous-patterns.yaml`. This means an agent could add `allow_patterns: [{pattern: '.*'}]` to bypass all approval checks (except hardline commands, which are always blocked). This is by design — the plugin is a safety net, not a jail.

The `_config_cache` freeze means mid-session edits are ignored, but changes take effect after the next Hermes restart.

### Risks the plugin cannot prevent

- An agent could add `allow_patterns: [{pattern: '.*'}]` to exempt itself from all dangerous-pattern checks
- An agent could modify protected patterns — changing both the pattern and its `protected` flag
- Config modifications via Python I/O or AI tool calls are invisible to pattern matching. Only literal command-line path references to the config file are potentially caught by patterns

### Defenses the plugin does provide

- **Protected patterns:** Patterns with `protected: true` have their regex SHA-256 hashed and tracked in `~/.hermes/.custom-patterns-hash`. If a protected pattern is modified or removed, a **CRITICAL** security warning is logged at startup.
- **Config hash tracking:** The full config SHA-256 is stored between sessions. Any change triggers a `WARNING` on next load with details of what changed (old vs new pattern counts).
- **New-allow shadowing detection:** If a new allow pattern could bypass a built-in dangerous-pattern check without a corresponding custom block pattern, a `WARNING` is logged with details.

### Example bypass vectors

| Command | Why pattern matching doesn't see it |
|---------|-----------------------------------|
| `python -c "open('~/.hermes/custom-dangerous-patterns.yaml').write('...')"` | Filename is in a Python string, not shell-visible |
| AI file-write tool call | Tool handles I/O; filename not in command string |
| `sed -i 's/block/allow/' ~/.hermes/custom-dangerous-patterns.yaml` | Filename visible but not in `_SENSITIVE_WRITE_TARGET` (out of scope) |
| `tee ~/.hermes/custom-dangerous-patterns.yaml << 'EOF'` | Same: not in `_SENSITIVE_WRITE_TARGET` (out of scope) |

### User-level hardening options (optional, not default)

- Run the agent and Hermes under **separate OS users** so the agent cannot write to `~/.hermes/custom-dangerous-patterns.yaml` or `~/.hermes/config.yaml`
- Set config file permissions to `0444` (read-only) for the agent's user
- Mount the config directory read-only in containerized setups
- Use `command_allowlist` only for patterns the user personally approved

## Troubleshooting

### Plugin not loading

Check that the plugin is enabled:

```bash
hermes plugins list | grep custom-dangerous-patterns
```

If not listed, enable it:

```bash
hermes plugins enable custom-dangerous-patterns
```

### Patterns not triggering approval

1. Verify the plugin loaded and see active patterns:
   ```bash
   hermes custom-dangerous-patterns list
   ```

2. Test a command against your patterns:
   ```bash
   hermes custom-dangerous-patterns test "vultr instance delete"
   ```

3. Check the plugin logs for errors:
   ```bash
   hermes custom-dangerous-patterns logs
   ```

4. Ensure you restarted Hermes after enabling the plugin or changing config.

5. Validate your config syntax:
   ```bash
   hermes custom-dangerous-patterns validate
   ```

### Allow patterns not working

Allow patterns are checked **before** block patterns. If a command matches both, the allow wins. Test your pattern matching:

```bash
hermes custom-dangerous-patterns test "vultr account info" --verbose
```

The `--verbose` output shows which patterns matched and the result.

### Deny patterns not blocking

If deny patterns are not blocking commands, verify:

1. The pattern is enabled — `hermes custom-dangerous-patterns list --enabled --type deny`
2. No allow pattern is intercepting the command before the deny check (allow is checked after deny, so if both match, deny wins)
3. Restart Hermes after config changes (mid-session edits are silently ignored)

Test deny pattern matching:

```bash
hermes custom-dangerous-patterns test "git push --force origin main"
```

### Integrity warnings on startup

If you see `CONFIG CHANGED` or `PROTECTED PATTERN MISSING/MODIFIED` warnings on startup:

1. Review the recent changes to `~/.hermes/custom-dangerous-patterns.yaml`
2. If the changes were intentional, the warning is informational — no action needed
3. If the changes were unexpected, investigate who/what modified the config

The integrity hash file is stored at `~/.hermes/.custom-patterns-hash`. Deleting it will clear the stored hash and suppress warnings until the next config change.

### Config file not found

The plugin looks for `~/.hermes/custom-dangerous-patterns/` (directory)
or `~/.hermes/custom-dangerous-patterns.yaml` (single file). Override with:

```bash
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/config.yaml

# Or point to a directory:
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/config-directory/
```

See [Directory Config Loading](#directory-config-loading) for details.

## Project Structure

```
hermes-custom-dangerous-patterns-plugin/
├── plugin.yaml          # Hermes plugin manifest
├── __init__.py          # register(ctx) — injects patterns, monkey-patches detection
├── config.py            # YAML loading, validation, caching, integrity checks, save_config()
├── patterns.py          # Pattern compilation and matching (block, allow, deny)
├── cli.py               # CLI command handlers (hermes custom-dangerous-patterns ...)
├── logs.py              # Log extraction and filtering for hermes custom-dangerous-patterns logs
├── AGENTS.md            # Developer guide: gotchas, testing safety, CLI architecture
├── examples/
│   ├── 00-test.yaml                     # Safe, disabled-by-default test patterns
│   ├── 01-cloud.yaml                    # Cloud CLI tools (aws, az, gcloud, vultr)
│   ├── 02-infra.yaml                    # Infrastructure as Code (opentofu, docker, podman)
│   ├── 03-tools.yaml                    # Backup, sync, network scanning, secrets
│   └── 04-package-managers.yaml         # Package managers (brew, npm, pip, cargo, uv)
├── tests/
│   ├── conftest.py       # Test fixtures, mocks, helpers
│   ├── test_config.py    # Config loading, validation, integrity tests
│   ├── test_patterns.py  # Pattern compilation and matching tests
│   ├── test_init.py      # Plugin registration and monkey-patch tests
│   └── test_cli.py       # CLI command handler tests
├── README.md            # This file
├── LICENSE              # MIT
└── .gitignore
```

## Requirements

- Python 3.11+
- [Hermes Agent](https://github.com/NousResearch/hermes-agent) (tested with 0.15.1)
- ruamel.yaml — for config loading and write-back (declared in `plugin.yaml`; Hermes installs it automatically)

### Development

```bash
git clone https://github.com/scross01/hermes-custom-dangerous-patterns-plugin.git
cd hermes-custom-dangerous-patterns-plugin
uv venv --python 3.11 .venv
uv sync --extra dev
```

## License

MIT — see [LICENSE](LICENSE).
