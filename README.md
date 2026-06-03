# hermes-custom-dangerous-patterns

> **⚠️ EXPERIMENTAL — USE AT YOUR OWN RISK**
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

### Step 1: Clone or download the plugin

```bash
git clone https://github.com/scross01/hermes-custom-dangerous-patterns-plugin.git \
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
> vultr instance create --region ewr --plan vc2-1c-1gb

⚠️ Dangerous command detected: Vultr mutating instance/snapshot command
    vultr instance create --region ewr --plan vc2-1c-1gb

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
  - pattern: '\bvultr\b'
    description: 'Vultr CLI command'
    examples:
      - 'vultr account info'
      - 'vultr instance list'
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
  - pattern: '\bvultr\s+(account\s+info|instance\s+list)\b'
    description: 'Read-only Vultr commands'
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Python regex (same flags as block patterns) |
| `description` | No | Documentation-only label |

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
#
# TIP: Use single-quoted strings for patterns — backslashes pass through
# literally:  '\bvultr\b'  not  "\\bvultr\\b"

patterns:
  # ── Cloud CLI tools (destructive) ────────────────────────────────
  - pattern: '\bvultr\s+(instance\s+create|instance\s+delete|snapshot\s+create|snapshot\s+delete)\b'
    description: 'Vultr mutating instance/snapshot command'
    examples:
      - 'vultr instance create --region ewr --plan vc2-1c-1gb'
      - 'vultr instance delete --instance-id cb670a12-e4f5-6d78-ab90-1234567890ab'

  - pattern: '\bterraform\s+(destroy|apply)\b'
    description: 'Terraform destroy/apply (mutates infrastructure)'
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
