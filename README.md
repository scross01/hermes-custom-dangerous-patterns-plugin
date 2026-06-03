# hermes-custom-dangerous-patterns

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

### Step 1: Clone or download the plugin

```bash
git clone https://github.com/stephencross/hermes-custom-dangerous-patterns-plugin.git \
    ~/.hermes/plugins/custom-dangerous-patterns
```

Or if you already have the source elsewhere:

```bash
ln -s /path/to/hermes-custom-dangerous-patterns-plugin \
      ~/.hermes/plugins/custom-dangerous-patterns
```

**Important:** The directory inside `~/.hermes/plugins/` must be named `custom-dangerous-patterns` (with the trailing `s`).

### Step 2: Enable the plugin

```bash
hermes plugins enable custom-dangerous-patterns
```

### Step 3: Create the config file

```bash
cp ~/.hermes/plugins/custom-dangerous-patterns/examples/custom-dangerous-patterns.yaml \
   ~/.hermes/custom-dangerous-patterns.yaml
```

Or create `~/.hermes/custom-dangerous-patterns.yaml` manually (see [Configuration](#configuration)).

### Step 4: Restart Hermes

The plugin loads at startup. Restart the gateway or start a new CLI session:

```bash
hermes gateway restart    # if using the gateway
# or just start a new `hermes` CLI session
```

### Step 5: Test it

```
> vultr instance list

⚠️ Dangerous command detected: Vultr CLI command
    vultr instance list

  [o]nce    — allow this one time
  [s]ession — allow for this session
  [a]lways  — always allow this pattern
  [d]eny    — block (default)
```

## Configuration

### Config File Location

```
~/.hermes/custom-dangerous-patterns.yaml
```

Override with env var:

```bash
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/custom-dangerous-patterns.yaml
```

### Block Patterns

These commands trigger the approval prompt:

```yaml
patterns:
  - pattern: "\\bvultr\\b"
    description: "Vultr CLI command"
    examples:
      - "vultr account info"
      - "vultr instance list"
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Python regex (matched with `re.IGNORECASE \| re.DOTALL`) |
| `description` | Yes | Human-readable label shown in the approval prompt |
| `examples` | No | Documentation-only list of example commands |

### Allow Patterns

Exempt specific commands from approval, even if they match a block pattern:

```yaml
allow_patterns:
  - pattern: "\\bvultr\\s+(account\\s+info|instance\\s+list)\\b"
    description: "Read-only Vultr commands"
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Python regex (same flags as block patterns) |
| `description` | No | Documentation-only label |

### Evaluation Order

```
1. Hardline check        → unconditional block (rm -rf /, mkfs, etc.)
2. Sudo stdin guard      → unconditional block
3. Yolo / mode=off       → bypass all approval
4. Allow patterns        → if match → command runs immediately (no prompt)
5. Block patterns        → if match → approval prompt
6. Built-in patterns     → if match → approval prompt
7. Tirith security scan  → if findings → approval prompt
```

**Allow wins over block.** If a command matches both a block pattern and an allow pattern, the allow wins and the command runs without a prompt.

### Full Example

```yaml
# ~/.hermes/custom-dangerous-patterns.yaml

patterns:
  # ── Cloud CLI tools ──────────────────────────────────────────────
  - pattern: "\\bvultr\\b"
    description: "Vultr CLI command"
    examples:
      - "vultr account info"
      - "vultr instance list"
      - "sudo vultr dns list"

  - pattern: "\\bgcloud\\b"
    description: "Google Cloud CLI command"
    examples:
      - "gcloud compute instances delete my-vm"

  - pattern: "\\baws\\s+(ec2|s3|rds|iam|lambda|cloudformation)\\b"
    description: "AWS CLI mutating service command"
    examples:
      - "aws ec2 terminate-instances --instance-ids i-12345"

  # ── Deployment tools ─────────────────────────────────────────────
  - pattern: "\\bcapistrano\\b.*\\bdeploy\\b"
    description: "Capistrano deployment"

  - pattern: "\\bfab\\b.*\\bdeploy\\b"
    description: "Fabric deployment"

  # ── Database operations ──────────────────────────────────────────
  - pattern: "\\bpg_dump\\b.*--clean\\b"
    description: "PostgreSQL dump with --clean (drops objects)"

  - pattern: "\\bmongodump\\b.*--drop\\b"
    description: "MongoDB dump with --drop"

# ── Allow patterns ────────────────────────────────────────────────
# Commands matching these are EXEMPT from approval, even if they
# also match a blocked pattern. Evaluated BEFORE block patterns.
# Allow wins over block.

allow_patterns:
  # Read-only Vultr commands
  - pattern: "\\bvultr\\s+(account\\s+info|instance\\s+list|dns\\s+list|plan\\s+list)\\b"
    description: "Read-only Vultr commands"

  # Dry-run modes
  - pattern: "\\bmy-company-deploy\\s+--dry-run\\b"
    description: "Dry-run mode is safe"

  # Help and version flags
  - pattern: "\\b(vultr|gcloud|aws)\\s+(-h|--help|help)\\b"
    description: "Help flags are safe"

  # Shell completion
  - pattern: "\\b(vultr|gcloud|aws)\\s+completion\\b"
    description: "Shell completion scripts are safe"
```

## How It Works

The plugin injects your custom patterns into Hermes's `DANGEROUS_PATTERNS` list at startup via pattern injection + a monkey-patch of `detect_dangerous_command()` for allow-pattern support.

```
Hermes startup:
  1. Plugin discovery → register(ctx) runs
  2. Reads ~/.hermes/custom-dangerous-patterns.yaml
  3. Compiles regex patterns
  4. Appends to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED
  5. Monkey-patches detect_dangerous_command() for allow-pattern support
  6. Agent runs → detect_dangerous_command() matches custom patterns
  7. Built-in approval flow handles once/session/always/deny
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
| **`--yolo`** | Custom patterns are bypassed (they're `DANGEROUS_PATTERNS`, not `HARDLINE`) |

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| Config file missing | Plugin loads silently, no patterns injected |
| Config file invalid YAML | Log WARNING, plugin loads with empty pattern list |
| Invalid regex in pattern | Log WARNING for that pattern, skip it, load valid ones |
| Pattern matches but allow also matches | Allow wins — no prompt |
| `--yolo` mode | Custom patterns bypassed |
| `approvals.mode: off` | Custom patterns bypassed |
| `approvals.mode: smart` | Custom patterns assessed by auxiliary LLM |
| Cron session + `cron_mode: deny` | Custom patterns blocked in cron |
| Container backend (docker, etc.) | All approval checks skipped (sandboxed) |
| `command_allowlist` "always" choice | Persisted to config.yaml — survives restarts |

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

1. Verify the plugin loaded successfully:
   ```bash
   grep "custom-dangerous-patterns" ~/.hermes/logs/agent.log | tail -5
   ```

2. Check for import errors:
   ```bash
   grep "Failed to load plugin.*custom-dangerous-patterns" ~/.hermes/logs/errors.log
   ```

3. Ensure you restarted Hermes after enabling the plugin.

4. Test pattern matching directly:
   ```bash
   cd ~/.hermes/plugins/custom-dangerous-patterns
   python3 -c "
   from .config import load_config
   from .patterns import compile_all, get_block_patterns
   config = load_config(force=True)
   compile_all(config)
   patterns = get_block_patterns()
   print(f'{len(patterns)} block patterns loaded')
   for regex, desc in patterns:
       print(f'  {regex.pattern} — {desc}')
   "
   ```

### Allow patterns not working

Allow patterns are checked **before** block patterns. If a command matches both, the allow wins. Verify your allow pattern matches the exact command string:

```bash
cd ~/.hermes/plugins/custom-dangerous-patterns
python3 -c "
from .config import load_config
from .patterns import compile_all, is_allow_pattern
config = load_config(force=True)
compile_all(config)
result = is_allow_pattern('vultr account info')
print(f'Match: {result}')  # Should print the description
"
```

### Config file not found

The plugin looks for `~/.hermes/custom-dangerous-patterns.yaml`. Override with:

```bash
export HERMES_CUSTOM_PATTERNS_PATH=/path/to/file.yaml
```

## Project Structure

```
hermes-custom-dangerous-patterns-plugin/
├── plugin.yaml          # Hermes plugin manifest
├── __init__.py          # register(ctx) — injects patterns, monkey-patches detection
├── config.py            # YAML loading, validation, caching
├── patterns.py          # Pattern compilation and allow-pattern matching
├── examples/
│   └── custom-dangerous-patterns.yaml   # Example config with cloud/deployment patterns
├── README.md            # This file
├── SPEC.md              # Design spec and architecture
├── LICENSE              # MIT
└── .gitignore
```

## Requirements

- Python 3.9+
- [Hermes Agent](https://github.com/NousResearch/hermes-agent) (tested with 0.9.x+)
- PyYAML (`pip install pyyaml`) — for config loading

## License

MIT — see [LICENSE](LICENSE).
