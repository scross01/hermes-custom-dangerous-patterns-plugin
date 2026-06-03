# hermes-custom-dangerous-patterns

A [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin that lets you add custom dangerous command patterns to Hermes's built-in approval system.

## What It Does

Hermes ships with 47 hardcoded dangerous command patterns (like `rm -rf`, `git reset --hard`, `docker stop`). When a command matches, you get an approval prompt: `[o]nce`, `[s]ession`, `[a]lways`, or `[d]eny`.

This plugin lets you add your own patterns to that system. Define regex patterns in a YAML file, and they get the same approval flow — same prompts, same session persistence, same permanent allowlist.

## Quick Start

1. **Install the plugin:**
   ```bash
   ln -s /path/to/hermes-custom-dangerous-patterns-plugin \
         ~/.hermes/plugins/custom-dangerous-patterns
   ```

2. **Create your config:**
   ```bash
   cp examples/custom-dangerous-patterns.yaml \
      ~/.hermes/custom-dangerous-patterns.yaml
   ```

3. **Edit the config** to add your patterns (see [Configuration](#configuration) below).

4. **Restart Hermes** (or start a new session).

5. **Test it:**
   ```
   > Run vultr account info
   
   ⚠ Dangerous command detected: Vultr CLI command
       vultr account info
   
     [o]nce  [s]ession  [a]lways  [d]eny
   ```

## Configuration

### Config File

Default location: `~/.hermes/custom-dangerous-patterns.yaml`

Override with: `HERMES_CUSTOM_PATTERNS_PATH=/path/to/file.yaml`

### Block Patterns

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
| `pattern` | Yes | Python regex (case-insensitive, dotall) |
| `description` | Yes | Shown in the approval prompt |
| `examples` | No | Documentation only |

### Allow Patterns

Exempt specific commands from approval, even if they match a block pattern:

```yaml
allow_patterns:
  - pattern: "\\bvultr\\s+(account\\s+info|instance\\s+list)\\b"
    description: "Read-only Vultr commands"
```

| Field | Required | Description |
|-------|----------|-------------|
| `pattern` | Yes | Python regex (case-insensitive, dotall) |
| `description` | No | Documentation only |

### Evaluation Order

1. Allow patterns checked first — if command matches, **no prompt**
2. Block patterns checked next — if command matches, **approval prompt**
3. Built-in dangerous patterns checked last

**Allow wins over block.** If a command matches both, it runs without a prompt.

## Examples

### Block all AWS mutating commands, allow read-only

```yaml
patterns:
  - pattern: "\\baws\\s+(ec2|s3|rds|iam|lambda|cloudformation)\\b"
    description: "AWS CLI mutating service command"

allow_patterns:
  - pattern: "\\baws\\s+(ec2\\s+describe|s3\\s+ls|s3\\s+cp.*--dry-run|iam\\s+list)\\b"
    description: "AWS read-only commands"
```

### Block deployments, allow dry-run

```yaml
patterns:
  - pattern: "\\bcap\\s+\\w+\\s+deploy\\b"
    description: "Capistrano deployment"

allow_patterns:
  - pattern: "\\bcap\\s+\\w+\\s+deploy\\s+--dry-run\\b"
    description: "Capistrano dry-run"
```

### Block database drops, allow dumps

```yaml
patterns:
  - pattern: "\\bDROP\\s+(TABLE|DATABASE)\\b"
    description: "SQL DROP statement"

allow_patterns:
  - pattern: "\\bpg_dump\\b"
    description: "PostgreSQL dump (read-only)"
```

## How It Works

The plugin injects your custom patterns into Hermes's `DANGEROUS_PATTERNS` list at startup. The built-in approval system then handles everything automatically:

- **CLI:** Interactive approval prompt
- **Gateway (Telegram/Discord/etc.):** `/approve` and `/deny` commands
- **Session persistence:** "Session" choice survives for the session
- **Permanent allowlist:** "Always" choice persists across restarts
- **Smart mode:** LLM risk assessment for custom patterns
- **Cron:** Respects `approvals.cron_mode`

No custom approval logic — it's all built-in.

## Development

```bash
# Run tests
cd tests/
python -m pytest -v

# Test pattern matching
python -c "
from patterns import match_command
print(match_command('vultr account info', config_path='~/.hermes/custom-dangerous-patterns.yaml'))
"
```

## License

MIT
