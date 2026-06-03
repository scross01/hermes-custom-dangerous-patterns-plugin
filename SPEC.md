# hermes-custom-dangerous-patterns — Design Spec

**Version:** 0.1.0
**Date:** 2026-06-02
**Status:** Implemented

---

## 1. Summary

A Hermes Agent plugin that lets users define **custom dangerous command patterns** and **allow-list exemptions** via a YAML config file. Custom patterns are injected into Hermes's `DANGEROUS_PATTERNS` list at startup, giving them first-class treatment in the approval flow — the same once/session/always/deny prompt, session persistence, permanent allowlist, and gateway `/approve`/`/deny` that built-in patterns enjoy.

This fills a gap: Hermes ships ~47 hardcoded dangerous patterns with no config-level extension point. Users who want to guard additional commands (cloud CLI tools, deployment scripts, domain-specific destructive operations) currently have no clean way to do so.

## 2. How It Works

### Mechanism

The plugin registers on Hermes startup via `register(ctx)`. During registration, it:

1. Reads `~/.hermes/custom-dangerous-patterns.yaml` (configurable path)
2. Compiles each user-defined regex pattern
3. Appends `(pattern, description)` tuples to `tools.approval.DANGEROUS_PATTERNS`
4. Appends compiled regexes to `tools.approval.DANGEROUS_PATTERNS_COMPILED`
5. Monkey-patches `detect_dangerous_command()` to check allow patterns first

### Why This Works

```
Hermes startup sequence:
  1. cli.py / run_agent.py starts
  2. Plugin discovery → register(ctx) runs
     → reads config, compiles patterns
     → appends to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED
     → monkey-patches detect_dangerous_command() for allow patterns
  3. Tool discovery → terminal_tool.py imports approval.py
  4. approval.py builds DANGEROUS_PATTERNS_COMPILED from DANGEROUS_PATTERNS
     (our patterns are already in the list)
  5. Agent runs → detect_dangerous_command() matches our patterns
  6. Built-in approval flow handles once/session/always/deny
```

### What Users Get (For Free)

- **CLI:** Interactive approval prompt with `[o]nce`, `[s]ession`, `[a]lways`, `[d]eny`
- **Gateway (Telegram/Discord/etc.):** `/approve` and `/deny` commands, async approval queue
- **Session persistence:** "Session" choice survives for the session duration
- **Permanent allowlist:** "Always" choice persists to `command_allowlist` in `config.yaml`
- **Smart mode:** If `approvals.mode: smart`, the auxiliary LLM assesses custom patterns too
- **Cron handling:** Respects `approvals.cron_mode` (deny by default)
- **Hardline bypass immunity:** Custom patterns are `DANGEROUS_PATTERNS` (not `HARDLINE_PATTERNS`), so `--yolo` can bypass them — matching user intent

## 3. Configuration

### Config File Location

```
~/.hermes/custom-dangerous-patterns.yaml
```

Override with env var: `HERMES_CUSTOM_PATTERNS_PATH=/path/to/file.yaml`

### Config Schema

```yaml
# ~/.hermes/custom-dangerous-patterns.yaml
#
# Custom dangerous command patterns for Hermes Agent.
# Each pattern triggers the approval prompt (once/session/always/deny).
#
# Patterns are Python regexes matched case-insensitively against the
# full command string (after ANSI stripping and Unicode normalization).
#
# TIP: Use single-quoted YAML strings for patterns — backslashes pass
# through literally:  '\bvultr\b'  not  "\\bvultr\\b"
#
# See: https://docs.python.org/3/library/re.html#regular-expression-syntax

patterns:
  - pattern: '\bvultr\b'
    description: 'Vultr CLI command'
    examples:
      - 'vultr account info'
      - 'vultr instance list'

  - pattern: '\baws\s+(ec2|s3|rds|iam|lambda|cloudformation)\b'
    description: 'AWS CLI mutating service command'
    examples:
      - 'aws ec2 terminate-instances --instance-ids i-12345'

# Allow patterns — exempt commands from approval, even if they match
# a block pattern. Evaluated BEFORE block patterns. Allow wins over block.
allow_patterns:
  - pattern: '\bvultr\s+(account\s+info|instance\s+list)\b'
    description: 'Read-only Vultr commands'
```

### Pattern Rules

| Property | Requirement |
|----------|-------------|
| **`pattern`** | Python regex syntax, matched with `re.IGNORECASE \| re.DOTALL` |
| **`description`** | Human-readable string shown in the approval prompt |
| **`examples`** | Optional list of example commands (documentation only, not enforced) |

### Allow Pattern Rules

| Property | Requirement |
|----------|-------------|
| **`pattern`** | Python regex syntax, same flags as block patterns |
| **`description`** | Optional human-readable reason (documentation only) |

### Evaluation Order

```
1. Hardline check (unconditional block — rm -rf /, mkfs, etc.)
2. Sudo stdin guard (unconditional block)
3. Yolo / mode=off check (bypass all)
4. Allow pattern check → if command matches ANY allow_pattern → ALLOW
5. Block pattern check → if command matches ANY pattern → APPROVAL PROMPT
6. Built-in DANGEROUS_PATTERNS check → if matches → APPROVAL PROMPT
7. Tirith security scan → if findings → APPROVAL PROMPT
```

**Key:** Allow patterns are checked **before** block patterns. If a command matches both a block pattern and an allow pattern, the allow wins. This lets you block `vultr` broadly but exempt `vultr account info`.

### Config Validation

On load, the plugin validates:
- YAML parses correctly
- `patterns` is a list of dicts with required `pattern` and `description` keys
- `allow_patterns` is a list of dicts with required `pattern` key
- Each `pattern` compiles as valid Python regex
- Logs warnings for invalid entries (never crashes the agent)

## 4. Plugin Structure

```
hermes-custom-dangerous-patterns-plugin/
├── plugin.yaml          # Hermes plugin manifest
├── __init__.py          # register(ctx) — injects patterns, monkey-patches detection
├── config.py            # YAML loading, validation, caching
├── patterns.py          # Pattern compilation and allow-pattern matching
├── examples/
│   └── custom-dangerous-patterns.yaml   # Example config
├── README.md            # User-facing documentation
├── SPEC.md              # This file
├── LICENSE              # MIT
└── .gitignore
```

### Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `__init__.py` | Plugin entry point. Calls `register(ctx)` to inject patterns and monkey-patch detection. |
| `config.py` | Loads and validates `~/.hermes/custom-dangerous-patterns.yaml`. Caches result per-process. |
| `patterns.py` | Compiles raw config patterns into `(compiled_regex, description)` tuples. Provides `is_allow_pattern()` for the monkey-patch. |

### Key Design Decisions

1. **Relative imports** (`from .config import load_config`) — Required because Hermes loads plugins as `hermes_plugins.<slug>` packages. Absolute imports (`from config import load_config`) fail because Python can't find a top-level `config` module.

2. **Monkey-patch for allow patterns** — The built-in `detect_dangerous_command()` doesn't know about allow patterns. We wrap it to check allow patterns first. If a command matches any allow pattern, we return `(False, None, None)` to skip all detection.

3. **No hooks used** — The plugin doesn't register any `pre_tool_call` or `post_tool_call` hooks. All work happens at startup via pattern injection and monkey-patching. This is simpler and avoids the hook allowlisting ceremony.

4. **Graceful degradation** — `patterns.py` tries to import `tools.ansi_strip.strip_ansi` for ANSI normalization, falling back to a regex if running outside Hermes. `config.py` tries `hermes_constants.get_hermes_home()`, falling back to `Path.home() / ".hermes"`.

## 5. User-Facing Behavior

### CLI Example

```
$ hermes chat
> List my Vultr instances

⚠️ Dangerous command detected: Vultr CLI command
    vultr instance list

  [o]nce    — allow this one time
  [s]ession — allow for this session
  [a]lways  — always allow this pattern
  [d]eny    — block (default)

> s
✓ Approved for this session.
```

### Gateway Example (Telegram)

```
User: List my Vultr instances

🤖 This command requires approval:
⚠️ Vultr CLI command

Command:
vultr instance list

Reply with /approve or /deny

User: /approve
✓ Approved for this session.
```

### Allow Pattern Example

```
$ hermes chat
> Show my Vultr account info

(vultr account info — runs immediately, no prompt)
```

## 6. Edge Cases

| Scenario | Behavior |
|----------|----------|
| Config file missing | Plugin loads silently, no patterns injected, log message at INFO |
| Config file invalid YAML | Log WARNING, plugin loads with empty pattern list |
| Invalid regex in pattern | Log WARNING for that pattern, skip it, load valid ones |
| Pattern matches but allow also matches | Allow wins — no prompt |
| `--yolo` mode | Custom patterns bypassed (they're `DANGEROUS_PATTERNS`, not `HARDLINE`) |
| `approvals.mode: off` | Custom patterns bypassed |
| `approvals.mode: smart` | Custom patterns assessed by auxiliary LLM |
| Cron session + `cron_mode: deny` | Custom patterns blocked in cron |
| Container backend (docker, etc.) | All approval checks skipped (container is sandboxed) |
| `command_allowlist` "always" choice | Persisted to config.yaml — survives restarts |
| Plugin loads after approval.py | Patterns not injected (import order dependency — plugins load before tools) |

## 7. Installation

See [README.md](README.md#installation) for step-by-step instructions.

## 8. Testing

### Unit Tests

- Config loading (valid, invalid, missing file)
- Pattern compilation (valid regex, invalid regex, edge cases)
- Allow pattern matching (match, no match, overlapping with block patterns)
- Monkey-patch correctness (allow pattern exempts, block pattern triggers)

### Integration Tests

- Mock `DANGEROUS_PATTERNS` list, verify patterns appended
- Mock `detect_dangerous_command`, verify allow patterns suppress detection
- Verify approval flow triggers for unmatched commands

### Manual Tests

1. Install plugin, create config with `vultr` pattern
2. Run `hermes chat` → ask to run `vultr account info` → should run without prompt (allow pattern)
3. Run `hermes chat` → ask to run `vultr instance delete` → should prompt for approval
4. Approve with "session" → run again → should be auto-approved
5. Test gateway: send command via Telegram → should get `/approve` prompt

## 9. Future Considerations

- **GUI config editor:** `hermes custom-patterns add "vultr" "Vultr CLI"` CLI command
- **Pattern groups:** Pre-defined pattern sets (e.g., `cloud: [aws, gcp, azure]`)
- **Pattern testing:** `hermes custom-patterns test "vultr account info"` → shows which patterns match
- **Community patterns:** Share pattern sets via GitHub (e.g., "common cloud CLI patterns")
