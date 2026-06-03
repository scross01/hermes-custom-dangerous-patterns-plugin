# hermes-custom-dangerous-patterns — Plugin Spec

**Version:** 0.1.0 (draft)
**Date:** 2026-06-02
**Status:** Design

---

## 1. Summary

A Hermes Agent plugin that lets users define **custom dangerous command patterns** and **allow-list exemptions** via a YAML config file. Custom patterns are injected into Hermes's built-in `DANGEROUS_PATTERNS` list at startup, giving them first-class treatment in the approval flow — the same once/session/always/deny prompt, session persistence, permanent allowlist, and gateway `/approve`/`/deny` that built-in patterns enjoy.

This fills a gap: Hermes ships 47 hardcoded dangerous patterns with no config-level extension point. Users who want to guard additional commands (cloud CLI tools, deployment scripts, domain-specific destructive operations) currently have no clean way to do so.

## 2. How It Works

### Mechanism

The plugin registers on Hermes startup via `register(ctx)`. During registration, it:

1. Reads `~/.hermes/custom-dangerous-patterns.yaml` (configurable path)
2. Compiles each user-defined regex pattern
3. Appends `(pattern, description)` tuples to `tools.approval.DANGEROUS_PATTERNS`
4. Appends compiled regexes to `tools.approval.DANGEROUS_PATTERNS_COMPILED`

Because plugins load **before** tools are imported, the custom patterns are present by the time `detect_dangerous_command()` first runs. The built-in approval flow then handles everything automatically.

### Why This Works

```
Hermes startup sequence:
  1. cli.py / run_agent.py starts
  2. Plugin discovery → register(ctx) runs → we append to DANGEROUS_PATTERNS
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
# See: https://docs.python.org/3/library/re.html#regular-expression-syntax

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
      - "aws s3 rb s://my-bucket --force"

  # ── Deployment tools ─────────────────────────────────────────────
  - pattern: "\\bcapistrano\\b.*\\bdeploy\\b"
    description: "Capistrano deployment"
    examples:
      - "cap production deploy"

  - pattern: "\\bfab\\b.*\\bdeploy\\b"
    description: "Fabric deployment"
    examples:
      - "fab deploy production"

  # ── Database operations ──────────────────────────────────────────
  - pattern: "\\bpg_dump\\b.*--clean\\b"
    description: "PostgreSQL dump with --clean (drops objects)"
    examples:
      - "pg_dump --clean mydb > dump.sql"

  - pattern: "\\bmongodump\\b.*--drop\\b"
    description: "MongoDB dump with --drop"
    examples:
      - "mongodump --drop --db mydb"

  # ── Custom domain-specific ───────────────────────────────────────
  - pattern: "\\bmy-company-deploy\\b"
    description: "Internal deployment tool"
    examples:
      - "my-company-deploy --env staging"

# ── Allow patterns ──────────────────────────────────────────────────
# Commands matching these patterns are EXEMPT from approval, even if
# they also match a blocked pattern. Evaluated after block patterns.
#
# Use cases:
#   - Read-only subcommands (e.g., "vultr account info" is safe)
#   - Specific scripts you trust
#   - Patterns that are false positives in your workflow
#
# These are also Python regexes, matched against the full command.

allow_patterns:
  # Allow read-only Vultr commands
  - pattern: "\\bvultr\\s+(account\\s+info|instance\\s+list|dns\\s+list|plan\\s+list)\\b"
    description: "Read-only Vultr commands"

  # Allow specific safe scripts
  - pattern: "\\bmy-company-deploy\\s+--dry-run\\b"
    description: "Dry-run mode is safe"

  # Allow help/version flags
  - pattern: "\\b(vultr|gcloud|aws)\\s+(-h|--help|help)\\b"
    description: "Help flags are safe"

  # Allow completion scripts
  - pattern: "\\b(vultr|gcloud|aws)\\s+completion\\b"
    description: "Shell completion scripts are safe"
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
~/.hermes/plugins/custom-dangerous-patterns/
├── plugin.yaml          # Manifest
├── __init__.py          # register(ctx) — injects patterns
├── config.py            # YAML loading, validation, caching
├── patterns.py          # Pattern compilation and matching logic
├── README.md            # User-facing documentation
├── LICENSE              # MIT
└── tests/
    ├── test_config.py
    ├── test_patterns.py
    └── test_integration.py
```

### `plugin.yaml`

```yaml
name: custom-dangerous-patterns
version: "0.1.0"
description: >
  Add custom dangerous command patterns to Hermes's approval system.
  Users define regex patterns in ~/.hermes/custom-dangerous-patterns.yaml;
  the plugin injects them into the built-in DANGEROUS_PATTERNS list so
  they get the same once/session/always/deny approval flow.
author: Stephen Cross
hooks:
  - pre_tool_call
```

### `__init__.py` (pseudocode)

```python
"""custom-dangerous-patterns plugin — inject user-defined patterns into Hermes's approval system."""

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def _load_config() -> dict:
    """Load and validate the custom patterns config."""
    from config import load_custom_patterns_config
    return load_custom_patterns_config()


def _compile_patterns(raw_patterns: list) -> list:
    """Compile raw pattern dicts into (compiled_re, description) tuples."""
    compiled = []
    for entry in raw_patterns:
        pattern_str = entry["pattern"]
        description = entry["description"]
        try:
            compiled.append((re.compile(pattern_str, re.IGNORECASE | re.DOTALL), description))
        except re.error as e:
            logger.warning("custom-dangerous-patterns: invalid regex %r: %s", pattern_str, e)
    return compiled


def _compile_allow_patterns(raw_patterns: list) -> list:
    """Compile allow patterns into (compiled_re, description) tuples."""
    compiled = []
    for entry in raw_patterns:
        pattern_str = entry["pattern"]
        description = entry.get("description", "")
        try:
            compiled.append((re.compile(pattern_str, re.IGNORECASE | re.DOTALL), description))
        except re.error as e:
            logger.warning("custom-dangerous-patterns: invalid allow regex %r: %s", pattern_str, e)
    return compiled


def register(ctx) -> None:
    """Inject custom patterns into DANGEROUS_PATTERNS at startup."""
    from tools.approval import (
        DANGEROUS_PATTERNS,
        DANGEROUS_PATTERNS_COMPILED,
    )

    config = _load_config()
    raw_patterns = config.get("patterns", [])
    raw_allow = config.get("allow_patterns", [])

    if not raw_patterns:
        logger.info("custom-dangerous-patterns: no patterns configured")
        return

    # Compile and inject block patterns
    compiled = _compile_patterns(raw_patterns)
    for regex, desc in compiled:
        DANGEROUS_PATTERNS.append((regex.pattern, desc))
        DANGEROUS_PATTERNS_COMPILED.append((regex, desc))

    # Compile and store allow patterns (used by pre_tool_call hook)
    allow_compiled = _compile_allow_patterns(raw_allow)
    ctx._custom_allow_patterns = allow_compiled  # stash for the hook

    # Register the allow-pattern interceptor
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)

    logger.info(
        "custom-dangerous-patterns: injected %d block patterns, %d allow patterns",
        len(compiled),
        len(allow_compiled),
    )


def _on_pre_tool_call(tool_name: str = "", args: dict = None, **_) -> dict | None:
    """Check allow patterns BEFORE the approval system runs.

    If a command matches an allow pattern, we need to prevent the
    approval system from triggering on our injected patterns.

    Unfortunately, the pre_tool_call hook fires BEFORE
    check_all_command_guards(), so we can't "pre-approve" here.
    Instead, we rely on the allow patterns being checked inside
    check_all_command_guards() via a monkey-patch of
    detect_dangerous_command().

    This hook is a no-op — the real work happens in the pattern
    injection + allow pattern integration described below.
    """
    return None
```

### Allow Pattern Integration

The tricky part: the built-in `detect_dangerous_command()` doesn't know about allow patterns. We need to intercept it. Two options:

**Option A: Monkey-patch `detect_dangerous_command`** (simple, slightly fragile)

```python
def _patch_detection(allow_patterns):
    """Wrap detect_dangerous_command to skip allow-patterned commands."""
    from tools import approval

    _original = approval.detect_dangerous_command

    def _patched(command: str):
        # Check allow patterns first
        cmd_lower = approval._normalize_command_for_detection(command).lower()
        for allow_re, _desc in allow_patterns:
            if allow_re.search(cmd_lower):
                return (False, None, None)  # exempt — skip all detection
        return _original(command)

    approval.detect_dangerous_command = _patched
```

**Option B: Use `pre_approval_request` hook** (cleaner, observer-only)

The `pre_approval_request` hook fires when the approval system is about to prompt. We could use it to auto-approve allow-patterned commands. But this hook is observer-only — it can't veto the approval.

**Verdict: Option A** is the practical choice. The monkey-patch is small, well-scoped, and runs in a trusted plugin context.

## 5. User-Facing Behavior

### CLI Example

```
$ hermes chat
> List my Vultr instances

⚠ Dangerous command detected: Vultr CLI command
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
| Plugin loads after approval.py | Patterns not injected (import order dependency) |

## 7. Installation

### Option 1: Symlink (recommended for development)

```bash
ln -s ~/Development/hermes-custom-dangerous-patterns-plugin \
      ~/.hermes/plugins/custom-dangerous-patterns
```

### Option 2: Copy

```bash
cp -r ~/Development/hermes-custom-dangerous-patterns-plugin \
      ~/.hermes/plugins/custom-dangerous-patterns
```

### Option 3: pip install (future)

```bash
pip install hermes-custom-dangerous-patterns
# Plugin installer copies to ~/.hermes/plugins/
```

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
2. Run `hermes chat` → ask to run `vultr account info` → should prompt
3. Approve with "session" → run again → should be auto-approved
4. Test gateway: send command via Telegram → should get `/approve` prompt
5. Test allow pattern: `vultr account info` → should run without prompt

## 9. Future Considerations

- **GUI config editor:** `hermes custom-patterns add "vultr" "Vultr CLI"` CLI command
- **Pattern groups:** Pre-defined pattern sets (e.g., `cloud: [aws, gcp, azure]`)
- **Inverted allow patterns:** Block everything EXCEPT patterns in allow list
- **Pattern testing:** `hermes custom-patterns test "vultr account info"` → shows which patterns match
- **Community patterns:** Share pattern sets via GitHub (e.g., "common cloud CLI patterns")

## 10. Open Questions

1. **Should we also inject into `HARDLINE_PATTERNS`?** — No. Hardline patterns can't be bypassed even with `--yolo`. Custom patterns should be bypassable.

2. **Should we support `pattern` as a list (multiple patterns per entry)?** — Could be useful but adds complexity. Keep it simple: one pattern per entry.

3. **Should we cache the compiled patterns?** — They're compiled once at startup. No runtime caching needed.

4. **What about `pre_tool_call` hook for allow patterns?** — The monkey-patch approach is simpler. The `pre_tool_call` hook fires too late (after the approval system is already triggered). We'd need to intercept `detect_dangerous_command` directly.

5. **Should the config support comments?** — YAML natively supports `#` comments. No extra work needed.
