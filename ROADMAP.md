# ROADMAP

## Plugin Evaluation

### From the User Perspective

**Value:** High. Hermes ships ~47 hardcoded patterns with no user extension point. This plugin fills that gap cleanly — it uses the existing approval flow (once/session/always/deny), so users don't need to learn anything new.

**Ease of use:** Good. Single YAML file, regex patterns, clear examples. The `HERMES_CUSTOM_PATTERNS_PATH` env var override is a nice touch for testing.

**Adding/removing patterns:** Trivial — edit a YAML file, restart. No CLI tooling yet, but the mental model is simple.

### From the Agent Perspective

The plugin works *with* the agent, not *for* the agent. It's a passive gate — the agent has no awareness of which patterns are custom vs. built-in, and no API to interact with them. That's correct for v0.1.0, but it creates a specific problem:

---

## Critical Risk: Agent Self-Modification of Safety Config

**This is the most important issue in the current design.** The agent can read and write files. If it has write access to `~/.hermes/custom-dangerous-patterns.yaml`, it can:

1. **Remove block patterns** it finds inconvenient
2. **Add allow patterns** that exempt itself from dangerous commands
3. **Widen existing patterns** to be less restrictive
4. **Replace the entire config** with a permissive version

The allow pattern evaluation happens *before* all built-in checks (except hardline). So a self-added allow pattern like `.*` would exempt the agent from custom AND built-in dangerous patterns, though hardline (`rm -rf /`, `mkfs`, etc.) would still trigger.

### Bypass Vectors Through Custom Patterns

**Allow patterns can override built-in protections.** The evaluation order is:

```
1. Hardline (unconditional, not bypassable)
2. Sudo stdin guard (unconditional)
3. Yolo / mode=off
4. Custom allow patterns  ← agent can add arbitrary patterns here
5. Custom block patterns
6. Builtin DANGEROUS_PATTERNS
7. Tirith scan
```

If the agent adds an allow pattern that matches what Hermes would otherwise flag (e.g., `\baws\b.*`), the allow wins before the built-in check runs — **the command runs without any prompt at all.**

**Concrete bypass scenarios:**
- Agent adds `allow_patterns: [{pattern: '.*'}]` → all dangerous commands bypass
- Agent adds `allow_patterns: [{pattern: '\baws\s+ec2\s+terminate-instances\b'}]` → specific destructive commands exempt
- Agent removes a block pattern by editing config → pattern no longer triggers

**Hardline patterns cannot be bypassed.** `rm -rf /`, `mkfs`, `dd to raw device`, fork bombs, and similar catastrophic commands are checked first with no allow-pattern escape. This is the only structural defense against self-modification.

**Agent has multiple paths to modify the config, all invisible to pattern matching:**

| Command | Why pattern matching doesn't see it |
|---------|-----------------------------------|
| `python -c "open('~/.hermes/custom-dangerous-patterns.yaml').write('...')"` | filename is in a Python string, not shell-visible |
| File-write tool call | tool handles I/O; filename not in command string |
| `sed -i 's/block/allow/' ~/.hermes/custom-dangerous-patterns.yaml` | sed's `-i` makes the filename visible, but Hermes's `_SENSITIVE_WRITE_TARGET` only covers `~/.hermes/config.yaml` — NOT this plugin's config (out of scope to fix) |
| `tee ~/.hermes/custom-dangerous-patterns.yaml << 'EOF'` | same: not in `_SENSITIVE_WRITE_TARGET` (out of scope to fix) |

**Plugins cannot gate these vectors from within.** The plugin has no hook before file I/O or terminal command execution that would let it intercept writes to its own config. The only defense is the agent choosing not to — or the user placing the config somewhere the agent cannot write.

**Would including the config filename in a block pattern help?** Marginally. It would catch literal command-line references to the file path in shell form. It does NOT catch:
- Python file I/O (filename in string/expression, not literal path in command)
- Tool-call file writes (filename never appears in the command string)
- `sed` with path via variable: `sed -i 's/.../' "$CFILE"` where `$CFILE` is set earlier

It would only catch direct, hardcoded path references on the command line — a small fraction of possible modification vectors.

**Root cause:** The agent has the same filesystem access as the user. There's no integrity boundary between the agent's operational capabilities and the safety configuration. This is a fundamental trade-off of the local-agent model.

### Design Decision: Agent Self-Management, Not Enforcement

> The plugin's stance on self-modification is: **allow it, detect it, log it.**

The plugin will NOT:
- Fail to load if the config is writable by the agent's process user
- Enforce OS-level ownership or permission checks
- Block the agent from editing the config via tool calls or Python I/O

The plugin WILL:
- Track the previous config hash and log a security warning when the config changes between sessions
- Validate `protected: true` patterns at load and CRITICAL-log if they are missing or modified
- Warn when a newly-added allow pattern appears to bypass built-in dangerous patterns — and ASK the user to confirm before applying (in interactive mode)
- Document the risk and the optional OS-user separation approach for users who need it

This matches the feedback: the agent is trusted to self-manage; the plugin's role is to surface changes loudly, not to police them.

### In-Plugin Mitigations (v0.2.0)

| Mitigation | Mechanism | Coverage |
|------------|-----------|----------|
| **`_config_cache` (existing, v0.1.0)** | `load_config()` is called once at `register()` startup. All patterns are compiled into the live `DANGEROUS_PATTERNS_COMPILED` list; allow patterns are baked into the monkey-patch closure capturing `_allow_compiled`. File is never re-read during a session — `_config_cache` short-circuits all subsequent calls and `force=True` is test-only. | **Mid-session edits are silently ignored.** Agent modifies YAML or adds/deletes patterns → current session unaffected. Does **not** protect across restarts. |
| **Protected pattern tier** | At load: `protected: true` patterns must be present and their regex hash must match stored hash in `~/.hermes/.custom-patterns-hash`. Missing/changed → CRITICAL log with details. | **Cross-session detection.** Catches accidental or automatic config rewrites that drop or modify critical patterns on a fresh startup. Does not prevent deliberate user/agent edits in the same session or across restarts. |
| **Config hash tracking** | SHA-256 of config at load, persisted in `~/.hermes/.custom-patterns-hash`. On next startup, compare. If changed since last session, log a security warning listing the delta (patterns added/removed/modified). Opt-out via `integrity_check: false`. | **Cross-session detection only.** Surfaces *any* config change between sessions with a full diff so the user can review. Mid-session edits invisible (cache wins). |
| **New-allow shadowing warning** | When a newly-loaded allow pattern matches a built-in `DANGEROUS_PATTERNS` entry with no corresponding custom block pattern, log WARN explaining the built-in bypass. In CLI interactive mode, present a confirmation prompt: "This allow pattern bypasses a built-in dangerous-pattern check. Apply anyway? [y/N]". | **Cross-session only** (fires at load time, before patterns are injected). Mid-session adds are invisible (cache). |
| **Config path outside agent sandbox** (optional) | Documented as an *optional* hardening step for users who want it. Not the default, not enforced. See "Optional: Config Path Outside Agent Sandbox" section below. | **OS-level.** Prevents agent from writing to config file at all. Independent of plugin state. |

### What Is Out of Scope (By Design)

| Item | Reason |
|------|--------|
| Config file ownership check | Rejected. Would break agent self-management and fail for users running agent and Hermes as the same user (the common case). |
| Config path in Hermes's `_SENSITIVE_WRITE_TARGET` | Rejected. Cannot modify Hermes core from a plugin. |
| Hard-enforced OS permissions | Out of scope. Documented as optional user hardening. |
| Agent sandboxing | Out of scope. The plugin operates within the same process. |
| Cross-session config tampering prevention | Out of scope. `_config_cache` already freezes config for the current session. Cross-session detection (hash tracking, protected patterns, shadowing warnings) is the appropriate plugin-level response — detection, not prevention. |

---

## How the Plugin Handles Session, Always, and Other Approval Choices

### Approval Mechanism (code-level detail from `tools/approval.py`)

The plugin's injected patterns participate in Hermes's existing approval system. There is no custom persistence logic — it's all handled by `tools/approval.py`:

**Session storage (`_session_approved: dict[str, set]`):**
- Keyed by `session_key` (derived from gateway session or CLI process)
- Each key maps to a `set` of `pattern_key` strings (the human-readable description)
- Populated by `approve_session()` when user chooses `[s]ession`
- Lives only in process memory — cleared when the session ends (gateway disconnect, CLI exit)
- Thread-safe via `_lock`

**Permanent allowlist (`_permanent_approved: set`):**
- Process-global `set` of `pattern_key` strings
- Populated by `approve_permanent()` when user chooses `[a]lways`
- Persisted to `~/.hermes/config.yaml` under `command_allowlist: [...]` via `save_permanent_allowlist()`
- Reloaded at startup by `load_permanent_allowlist()` (called at module level, line 1645)
- Survives restarts; entries are keyed by `pattern_key` (description string)

**Pattern key mechanics:**
```python
# When user approves "vultr instance delete":
# pattern_key = "Vultr destructive instance/snapshot command"  (the description)
# This key is stored in _session_approved[session_key] and/or _permanent_approved
# Future calls to detect_dangerous_command for the same pattern return the same key
```

**The plugin's integration point:**
- The plugin appends `(compiled_regex, description)` to `DANGEROUS_PATTERNS_COMPILED` — the live list
- When `detect_dangerous_command()` matches a custom pattern, it returns `description` as the `pattern_key`
- `is_approved()` checks `_session_approved` and `_permanent_approved` using this key
- If the pattern was "always" approved previously, future calls return early with `approved=True`

**Plugin hooks the approval system also exposes:**
- `pre_approval_request(command, description, pattern_key, pattern_keys, session_key, surface)` — fired when an approval is first requested
- `post_approval_response(..., choice)` — fired after user responds with `once/session/always/deny/timeout`
- These are observer-only — return values are ignored; plugins cannot veto

---

## Can Custom Patterns Circumvent Default Checks?

Yes, in bounded ways:

- **Allow patterns run before built-in patterns.** If a user (or agent) adds an allow pattern like `\baws\b.*` while `aws` is in a built-in block pattern, the allow wins and all AWS commands bypass approval.
- **Built-in patterns with no customization** are unaffected — they still trigger normally if no allow pattern matches.
- **Hardline checks** (`rm -rf /`, `mkfs`, `dd`, etc.) run *before* everything. These cannot be bypassed by any allow pattern.

**The plugin's terminal-write gate gap is acknowledged but out of scope.** `custom-dangerous-patterns.yaml` is not in Hermes's `_SENSITIVE_WRITE_TARGET`, so `sed -i`, `tee`, and `>` redirections targeting it are not gated by terminal-side security. This requires a Hermes core change, which is outside the plugin's scope. The plugin documents this gap and provides the in-plugin hash-tracking mitigation to detect changes after they happen.

**This is primarily a user-education problem, not a bug.** The README has a "Safety Warning" section explaining that allow patterns are powerful and self-added allow patterns = self-removed safety. The protected pattern tier and hash tracking (v0.2.0) address this structurally within plugin scope.

---

## Multi-File Config Support

Single YAML file works for MVP but doesn't scale beyond ~20 patterns. A directory-based approach is the right solution:

### Proposed: `custom-dangerous-patterns.d/` Directory

```
~/.hermes/custom-dangerous-patterns.d/
├── 00-cloud-aws.yaml          # load order via prefix
├── 10-cloud-gcp.yaml
├── 20-database.yaml
├── 30-deployment.yaml
├── 40-allow-readonly.yaml     # allow patterns separate from block patterns
└── 99-local-overrides.yaml    # user's personal additions (loaded last, highest priority)
```

**Benefits:**
- Patterns organized by domain (cloud, database, deployment)
- Team-shared configs can be version-controlled separately
- Easy to `git clone` a community pattern pack into the directory
- Load order controlled by filename prefix for predictable precedence
- `allow_patterns` and `patterns` can live in separate files — no merging required

**Implementation:** In `_load_yaml()`, check if path is a directory. If so, `glob("*.yaml")`, sort alphabetically, and merge all dicts (append `patterns` and `allow_patterns` lists).

**Env var override already supports this:** `HERMES_CUSTOM_PATTERNS_PATH=~/.hermes/custom-dangerous-patterns.d/` would seamlessly enable directory mode.

---

## Expanded Config Format (v0.2.0)

### Proposed schema additions

```yaml
patterns:
  - pattern: '\brm\s+-rf\b'
    description: 'Recursive delete'
    enabled: true          # NEW: optional, default true. Disabled patterns are skipped at load.
    protected: false       # NEW: optional, default false. See "Protected Pattern Tier" below.
    guidance: 'Use `rm -rf` only after confirming with `ls` first. Consider archiving to ~/.Trash instead.'  # NEW: optional

  - pattern: '\becho\s+["\']this\s+is\s+dangerous["\']'
    description: '[TEST] Echo with danger text'
    enabled: false         # Example: shipped but off by default
    group: testing         # NEW: optional tag for grouping

allow_patterns:
  - pattern: '\bvultr\s+account\s+info\b'
    description: 'Read-only Vultr commands'
    enabled: true

deny_patterns:             # NEW: top-level list, like patterns but with action: deny (no prompt)
  - pattern: '\bruby\s+-e\s+.*system\b'
    description: 'Ruby system() exec via -e'
    enabled: true          # optional
    guidance: 'Use `subprocess.run()` or the shell tool instead of inline Ruby system calls.'  # optional
    # No prompt — deny immediately, below hardline but before block patterns
```

**Semantics for `enabled: false`:**
- Pattern is loaded and validated (regex compiled, description stored)
- Tracking it enables "pause" semantics: user can disable a pattern they find noisy without deleting it
- Disabled patterns don't appear in `DANGEROUS_PATTERNS_COMPILED`
- The `pattern_key` (description) for a disabled pattern won't be in `_session_approved` or `_permanent_approved`, so re-enabling it will start a fresh approval lifecycle
- Pattern groups (`group: testing`) allow bulk enable/disable via the future CLI

**Semantics for `deny_patterns`:**
- Matched commands are blocked immediately, no prompt, message reads "deny-pattern block"
- Distinguished from hardline: deny patterns are user-managed and removable; hardline is not
- Does NOT run when `--yolo` or `approvals.mode=off` (respects user intent, unlike hardline)
- Useful for team/org policies where the config owner wants a "no prompt" tier above standard dangerous patterns, without requiring OS-level enforcement

**Evaluation order with new fields:**

```
1. Hardline (unconditional, immutable)
2. Sudo stdin guard (unconditional)
3. Yolo / mode=off / cron_mode
4. Allow patterns (enabled only)
5. Deny patterns (enabled only) → immediate block, no prompt (respects --yolo)
6. Custom block patterns (enabled only) → approval prompt
7. Built-in DANGEROUS_PATTERNS → approval prompt
8. Tirith scan
```

**Guidance field on patterns:**

Each pattern entry can carry an optional `guidance` string. When the command is blocked or denied (by block pattern, deny pattern, or user denial), the guidance text is surfaced to the agent in the tool result.

**Mechanism:**
- Hermes passes the approval result dict (`{"approved": False, "message": "..."}`) back to the agent as the tool result. The agent reads this and adjusts its next reasoning step.
- The plugin cannot modify the already-returned `message` dict via hooks (`post_approval_response` is observer-only). The insertion point is the `description` field that flows into `pattern_key` and into the deny result message, or — more cleanly — the `_patched` monkey-patch function in `__init__.py` can look up `guidance` from the pattern metadata after `allow_checker()` runs and the command falls through to the original `_original()` call.
- For `deny_patterns` (no prompt), the plugin builds the block result itself, so `guidance` can be appended directly to the `message`.

**Two-tier guidance:**

| Tier | Scope | Example |
|------|-------|---------|
| **Plugin default deny guidance** | Appended to *all* custom-pattern denials (block, deny-pattern, user-denied) | `"[custom-dangerous-patterns] This command was blocked by a custom safety pattern. To proceed, request user approval or disable the pattern in the config."` |
| **Per-pattern guidance** | Appended only when the specific pattern has a `guidance` field | `"[guidance for 'recursive delete'] Use `rm -rf` only after confirming with `ls` first. Consider archiving to ~/.Trash instead."` |
| **Per-group guidance** | Appended when the matched pattern has a `group` field and a group-level guidance map is defined at the config top level | See proposed config format below |

**Proposed config format with guidance:**

```yaml
# Top-level guidance defaults
guidance:
  default: >
    [custom-dangerous-patterns] This command was blocked by a custom safety pattern.
    To proceed, request explicit user approval or disable the pattern in
    ~/.hermes/custom-dangerous-patterns.yaml.
  groups:
    testing: >
      [TEST pattern] This is a safety test pattern. Enable the testing group
      (enabled: true) or run `hermes custom-patterns enable --group testing`
      to use it.

patterns:
  - pattern: '\brm\s+-rf\b'
    description: 'Recursive delete'
    guidance: 'Use `rm -rf` only after confirming with `ls` first. Consider archiving to ~/.Trash.'
    group: filesystem

  - pattern: '\bvultr\s+instance\s+create\b'
    description: 'Vultr instance creation'
    guidance: 'Use the Vultr web UI (https://my.vultr.com) or Terraform for auditable provisioning.'
    examples:
      - 'vultr instance delete --instance-id cb670a12-e4f5-6d78-ab90-1234567890ab'

  - pattern: '\becho\s+["\']this\s+is\s+dangerous["\']'
    description: '[TEST] Echo with danger text'
    enabled: false
    group: testing
```

**Message assembly order when a command is denied:**

```
1. Hermes base message:        "BLOCKED: User denied this potentially dangerous command
                                 (matched 'Vultr instance creation' pattern).
                                 Do NOT retry this command - the user has explicitly rejected it."
2. Plugin default guidance:    "[custom-dangerous-patterns] This command was blocked by a
                                 custom safety pattern. To proceed, request explicit user
                                 approval or disable the pattern in config."
3. Per-pattern guidance:       "[guidance for 'Vultr instance creation'] Use the Vultr web UI
                                 (https://my.vultr.com) or Terraform for auditable provisioning."
4. Per-group guidance (if any): "[TEST pattern] ..."  (only for patterns with `group: testing`)

Final result message = [1] + "\n\n" + [2] + "\n\n" + [3]
(Each tier is deduplicated and the agent sees the full composite as `result["message"]`)
```

**Implementation constraints:**

- No Hermes core changes required. `guidance` is stored in the plugin's own pattern metadata and appended to the `message` in the monkey-patch wrapper before delegating to `_original()` and in the deny-pattern block result.
- The `post_approval_response` hook cannot modify the result dict (observer-only per Hermes contract), so guidance must be injected *before* `check_dangerous_command` / `check_all_command_guards` returns — i.e. in the `_patched` wrapper and in the `_check_deny_patterns` function that builds the deny result.
- The `guidance` field does not need to be a `pattern_key` in `_session_approved` — it's display-only, not an approval key. It can be a plain field on the validated pattern dict, alongside `pattern`, `description`, `enabled`, `protected`, `group`, `examples`.

**Protected pattern tier:**

A `protected: true` pattern:
- Must be present in the config at load time (cannot be absent or disabled)
- Cannot have its `pattern` regex modified (detected by hash comparison against last-known-good stored in `~/.hermes/.custom-patterns-hash`)
- Validation failure: log a CRITICAL security warning listing changed/removed protected patterns with their old and new values
- Does NOT affect `allow_patterns` or `deny_patterns` (those are user-controlled by design)
- Protects against accidental removal and against automatic config rewrites from other tools
- Does NOT prevent a deliberate user or agent action: if the user wants to change a protected pattern, they can — they just get a CRITICAL warning and must confirm (in interactive mode)

---

## Sample / Out-of-Box Pattern Library

### Category 1: Cloud CLI — Mutating Operations (block)
- `\bvultr\s+(instance\s+(create|delete|rebuild)|snapshot\s+(create|delete|restore))\b`
- `\baws\s+(ec2|s3|rds|iam|lambda|cloudformation)\b` (broad block, allow patterns for reads)
- `\bgcloud\s+(compute\s+instances\s+delete|projects\s+delete|sql\s+instances\s+delete)\b`
- `\baz\s+(vm\s+delete|storage\s+account\s+delete|sql\s+db\s+delete)\b`
- `\boci\s+(compute\s+instance\s+terminate|database\s+db\s+system\s+delete|network\vcn\s+delete)\b`
- `\bdoctl\s+(compute\s+droplet\s+delete|kubernetes\s+cluster\s+delete|databases\s+delete)\b`

### Category 2: Cloud CLI — Read Operations (allow)
- `\b(vultr|aws|gcloud|oci|doctl)\s+(account\s+info|list|get|describe|show)\b`
- `\bterraform\s+(plan|output|state\s+list|show)\b`

### Category 3: Infrastructure (block)
- `\bterraform\s+(destroy|apply)\b`
- `\bpulumi\s+(up|destroy)\b`
- `\bcdk\s+deploy\b`
- `\bcap\s+\w+\s+deploy\b`
- `\bfab\s+\w*\s*deploy\b`
- `\bhelm\s+delete\b`
- `\bkubectl\s+delete\b`
- `\bk9s\b` (interactive, dangerous by nature)

### Category 4: Database (block)
- `\bDROP\s+(TABLE|DATABASE|SCHEMA)\b`
- `\bTRUNCATE\s+TABLE\b`
- `\bmongodump\b.*--drop\b`
- `\bmongorestore\b.*--drop\b`
- `\bpsql\b.*--command=DROP\b`
- `\bmysql\b.*-e\s+["\']?DROP\b`

### Category 5: File System (block, scoped)
- `\brm\s+-rf\s+/` (catastrophic)
- `\bdd\b.*of=/dev/[sh]d` (disk overwrite)
- `\bmkfs\b` (filesystem format)
- `\b>?\s*/dev/sd[a-z]` (writing to block device)

### Category 6: Network / Exfiltration (block)
- `\bcurl\b.*\|\s*(sh|bash|python)\b` (curl-pipe-exec)
- `\bcurl\b.*\|\s*wget\b.*\|\s*sh\b` (chained download-exec)
- `\bpython\b.*<\s*\(curl\b` (curl-pipe-python)
- `\bwget\b.*\|\s*(sh|bash)\b` (wget-pipe-exec)
- `\bnc\b.*-e\b` (netcat reverse shell)
- `\bpython\b.*-c\s+["\']?import\s+socket\b` (Python socket reverse shell pattern)

### Category 7: CI/CD (block)
- `\bgithub\s+run\b.*\s+delete\b`
- `\bgh\s+run\b.*\s+cancel\b`
- `\bcircleci\b.*\s+purge\b`

### Category 8: Shell Meta-Commands (block)
- `\beval\s+\$\(` (eval with command substitution)
- `\bsource\s+/dev/stdin\b` (source untrusted input)
- `\bsudo\s+\w*\s*-[iI]\b` (sudo to interactive shell)
- `\bsudo\s+-s\b`
- `\bset\s+-o\s+errexit\b` (dangerous shell options)

### Test / Non-Dangerous Patterns (shipped disabled)

```yaml
patterns:
  - pattern: '\becho\s+["\']this\s+is\s+dangerous["\']'
    description: '[TEST] Echo with danger text — use to test approval prompt'
    enabled: false           # shipped but off by default; user opts in
    group: testing
    examples:
      - "echo 'this is dangerous'"
      - 'echo "this is dangerous"'

  - pattern: '\bping\s+-c\s+99999\b'
    description: '[TEST] Excessive ping — use to test approval prompt'
    enabled: false
    group: testing
    examples:
      - 'ping -c 99999 8.8.8.8'

  - pattern: '\bsleep\s+99999\b'
    description: '[TEST] Long sleep — use to test approval prompt'
    enabled: false
    group: testing
    examples:
      - 'sleep 99999'

  - pattern: '\brm\s+-rf\s+/tmp/test_\w+\b'
    description: '[TEST] Scoped rm in /tmp — safe to test blocking logic'
    enabled: false
    group: testing
    examples:
      - 'rm -rf /tmp/test_myapp'
      - 'rm -rf /tmp/test_data'

  - pattern: '\bDROP\s+TABLE\s+test_\w+\b'
    description: '[TEST] Scoped DROP on test tables — safe to test blocking logic'
    enabled: false
    group: testing
    examples:
      - 'DROP TABLE test_users'
      - 'DROP TABLE test_data'

  - pattern: '\bcp\s+/tmp/source_test\s+/tmp/dest_test\b'
    description: '[TEST] Scoped copy in /tmp — safe to test blocking logic'
    enabled: false
    group: testing
    examples:
      - 'cp /tmp/source_test /tmp/dest_test'

allow_patterns:
  - pattern: '\becho\s+["\'](this\s+is\s+safe|hello\s+world)["\']'
    description: '[TEST] Safe echo — demonstrate allow pattern behavior'
    enabled: false
    group: testing
```

These test patterns are deliberately safe:
- File operations scoped to `/tmp/` (ephemeral, no recovery needed)
- Database operations on `test_` prefixed tables only
- Network ops to nonexistent targets (`ping -c 99999 8.8.8.8`)
- The `[TEST]` prefix and `group: testing` tag make them easy to identify and bulk-manage
- All disabled by default (`enabled: false`) — user must opt in to use them, or run `hermes custom-patterns enable --group testing`

This is critical for CI/CD testing the plugin itself and for users who want a safe way to exercise the approval prompt without using real dangerous commands.

---

## Product Roadmap

### v0.2.0 — Safety Hardening (next release)

| Item | Priority | Description |
|------|----------|-------------|
| `enabled` field on patterns | High | `enabled: false` skips pattern at load; re-enable without rewriting regex |
| `group` tag on patterns | High | Optional label for bulk filtering; supports `--group testing` and future bulk enable/disable |
| `deny_patterns` top-level list | High | New action tier: matched commands blocked immediately, no prompt (below hardline, above block patterns). Respects `--yolo`/`mode=off`. |
| Protected pattern tier (`protected: true`) | High | At load: protected patterns must be present and their regex must match the stored hash. Missing/changed → CRITICAL log with details. Protects against accidental/automatic config rewrites. |
| Config hash tracking | High | SHA-256 of config at load, persisted in `~/.hermes/.custom-patterns-hash`. Changed → security warning with delta. Configurable opt-out via `integrity_check: false`. |
| New-allow shadowing warning | Medium | When a new allow pattern matches a built-in dangerous pattern with no overlapping custom block pattern, log WARN. In interactive mode, ask user to confirm before applying. |
| Directory config support | High | `*.d/` directory loading with alphabetic precedence |
| AGENTS.md safety guard | High | Add this document's "Testing Safety" and "Self-Modification Risk" sections to project AGENTS.md |
| Test pattern collection | Medium | Ship the `[TEST]` patterns above as `examples/test-patterns.yaml`, all `enabled: false`, `group: testing` |

### v0.3.0 — Usability

> **Note:** Hermes plugins **can** register CLI subcommands via `ctx.register_cli_command()` (confirmed in `hermes_cli/plugins.py:386`). These v0.3.0 items are architecturally feasible and do not require Hermes core changes.

| Item | Priority | Description |
|------|----------|-------------|
| `hermes custom-patterns` CLI | High | `add`, `remove`, `list`, `test`, `enable`, `disable`, `enable --group testing` subcommands, registered via `ctx.register_cli_command()` |
| Pattern test runner | High | `hermes custom-patterns test "vultr instance delete"` → shows which patterns match, outcome (block/allow/pass/deny), and whether the prompt would appear |
| Config syntax validation | Medium | `hermes custom-patterns validate` — check YAML + regex validity without running |
| Built-in pattern reference | Medium | `hermes custom-patterns builtins` — list Hermes's ~47 hardcoded patterns so users know what's already covered |
| Pattern description search | Low | `hermes custom-patterns search "terraform"` — find all patterns matching a keyword |

### v0.4.0 — Power Features

| Item | Priority | Description |
|------|----------|-------------|
| Pattern profiles | Medium | Named config sets: `profiles/work.yaml` (strict), `profiles/personal.yaml` (relaxed), switchable via env var `HERMES_CUSTOM_PATTERNS_PROFILE=work` |
| Include/import directive | Medium | `patterns: ["#include: community/cloud-aws.yaml"]` for YAML-level composition within the `*.d/` directory |
| Community pattern packs | Low | Curated sets published as GitHub repos, installable via `hermes custom-patterns install scross01/cloud-patterns` |
| Pattern audit log | Low | Record which patterns triggered, how often, user's decision — helps users refine their config |

### v0.5.0 — Hermes Core Integration (recognized as out of scope for plugin code)

> **Note:** Items in this milestone require Hermes core changes and cannot be implemented within the plugin. They are tracked here as upstream requests.

| Item | Notes |
|------|-------|
| Sensitive-write gate for plugin config | Requires Hermes core change: add `custom-dangerous-patterns.yaml` and `custom-dangerous-patterns.d/` to `_SENSITIVE_WRITE_TARGET` in `tools/approval.py`. Plugin will document the gap; Hermes core team would need to pick this up. |
| Marketplace listing | Official Hermes plugin marketplace entry |
| Gateway-native config editor | Edit patterns via Telegram/Discord bot commands |
| Pattern suggestion engine | After each denied command, suggest "Add pattern?" to the user |
| Cross-session analytics | Which custom patterns fire most often, allow/deny ratios |

---

## AGENTS.md Additions

### Section 1: Testing Safety for Approval-Check Plugins

```
## Testing Safety for Approval-Check Plugins

When writing or running tests that verify approval/blocking behavior:

- NEVER use real dangerous commands (e.g., `rm -rf /`, `DROP DATABASE production`, `git push --force`)
- ALWAYS use the provided test patterns from `examples/test-patterns.yaml` (all `enabled: false` by default)
- Test patterns are named `[TEST]` and are safe by design:
  - File operations are scoped to `/tmp/` (ephemeral, no data loss)
  - Database operations target `test_` prefixed tables only
  - Network operations use nonexistent or test endpoints
- If adding custom test commands, validate they cannot cause real damage before running
- Validate that test patterns actually trigger approval before relying on them
```

### Section 2: Self-Modification Risk Warning

```
## Safety Warning: Configuration Integrity

This plugin controls which commands the agent is allowed to execute. The agent
itself has full filesystem access and can modify the plugin's configuration file
(`~/.hermes/custom-dangerous-patterns.yaml`) to remove block patterns or add
allow patterns that bypass safety checks.

This is by design — the plugin does NOT enforce config immutability. It detects
and logs changes, but does not prevent them.

Risks the plugin CANNOT prevent:
- The agent could add `allow_patterns: [{pattern: '.*'}]` to exempt itself
  from all dangerous-pattern checks (hardline commands are still blocked)
- The agent could modify protected patterns by also changing the `protected` flag
- Config modifications via Python I/O or tool calls are invisible to
  pattern matching — only literal command-line path references are potentially caught

Defenses the plugin DOES provide:
- `protected: true` patterns: critical patterns have their hashes tracked.
  If a protected pattern is modified or removed, a CRITICAL security warning
  is logged at startup.
- Config hash tracking: the full config SHA-256 is stored between sessions.
  Any change (additions, removals, edits) triggers a security warning on next
  load, with details of what changed.
- New-allow shadowing detection: if a new allow pattern appears to bypass
  a built-in dangerous-pattern check, a WARNING is logged and the user is
  asked to confirm in interactive mode.

User-level hardening options (optional, NOT the default):
- Run the agent and Hermes under separate OS users so the agent cannot write
  to `~/.hermes/custom-dangerous-patterns.yaml` or `~/.hermes/config.yaml`
- Set config file permissions to `0444` (read-only) for the agent's user
- Mount the config directory read-only in containerized setups
- Use `command_allowlist` only for patterns the user personally approved
  (agent additions to allow_patterns are not persisted there automatically)
```

---

## Optional: Config Path Outside Agent Sandbox (Advanced Users Only)

This section documents an optional hardening step for users who want to prevent
the agent from modifying the plugin's config. It is **not the default, not
enforced, and not recommended for most users** — it requires separate OS user
management and breaks the common case where the agent runs as the same user as
Hermes.

If you want this hardening:

1. Create a separate OS user for the agent (e.g., `hermes-agent`)
2. Place `custom-dangerous-patterns.yaml` in a directory owned by your user (e.g., `~/.hermes/`)
3. Set permissions so the agent user can read but not write:
   ```bash
   chown $USER:$USER ~/.hermes/custom-dangerous-patterns.yaml
   chmod 644 ~/.hermes/custom-dangerous-patterns.yaml
   # Or for the directory:
   chown $USER:$USER ~/.hermes/custom-dangerous-patterns.d/
   chmod 755 ~/.hermes/custom-dangerous-patterns.d/
   ```
4. Run the Hermes agent process as the `hermes-agent` OS user, and the
   interactive Hermes CLI as your personal user (or use `sudo -u hermes-agent`)

**Caveats:**
- This breaks the common case where agent and CLI share a user account
- The agent can still attempt writes — they'll fail with a permission error
- Protected patterns and hash tracking still operate normally (reads are
  unaffected by write restrictions)
- This is fundamentally a workaround for the local-agent trust model; it does
  not change the plugin's architecture

---

## Broader Integration Ideas

1. **Hermes plugin system as a pattern registry** — other plugins could register patterns programmatically (e.g., a `docker` plugin registers Docker-specific patterns), making the pattern system composable beyond YAML. This would require a new `register_pattern(pattern, description, action="block")` API exposed via `ctx`.

2. **Dynamic pattern adaptation** — log which patterns the user consistently "always" approves, and suggest removing them (trust-on-first-use model, inverse of the current always-block approach).

3. **Multi-user team configs** — teams could version-control a shared `custom-dangerous-patterns.d/` directory, deployed via config management (Ansible, etc.), with per-user overrides in `99-local-overrides.yaml`.

4. **Approval policy as code** — treat the patterns config like a policy file that can be linted, tested, and code-reviewed in CI before deployment to production agents.

5. **Tirith integration** — if Hermes uses Tirith for security scanning, custom patterns could feed into Tirith as a rule source, giving a unified policy view across command approval and code security.

6. **Container isolation as a safety layer** — for environments where config tampering risk is unacceptable, running Hermes in a container with a read-only bind mount for `~/.hermes/custom-dangerous-patterns.yaml` makes config filesystem writes impossible at the OS level. This is the recommended container approach (no OS user split needed). Container backends already skip all approval checks, so this must be paired with a non-container backend for approval to take effect.

7. **Pattern convergence with Hermes core** — long-term, the plugin's config format should become Hermes's native `approvals.custom_patterns` field in `config.yaml`, eliminating the separate YAML file and the agent's ability to "reach outside" the config system to modify safety rules. The file-based plugin format is a stepping stone.

---
