# Critical Review: Hermes Custom Dangerous Patterns Plugin

**Plugin:** `hermes-custom-dangerous-patterns` v0.1.0  
**Reviewed:** 2026-06-03  
**Reviewer:** AI-assisted architectural analysis  

---

## 1. Executive Summary

The `hermes-custom-dangerous-patterns` plugin is a well-architected, tightly-scoped extension that fills a genuine gap in the Hermes Agent ecosystem. It adds user-configurable command-approval patterns via YAML configuration, leveraging Hermes's existing `DANGEROUS_PATTERNS` mechanism through pattern injection and a targeted monkey-patch. The implementation is clean, the documentation thorough, and the architectural decisions are defensible.

**Overall assessment:** Strong v0.1.0 — the right thing, built the right way for its constraints. The roadmap is unusually well-considered, anticipating problems (particularly the agent self-modification risk) with structured mitigations already planned. However, the plugin operates within fundamental architectural constraints of the Hermes plugin system that limit what it can achieve, and some of these are existential risks for users who don't understand them.

---

## 2. The Problem Landscape

### 2.1 What Problem Does This Solve?

Hermes Agent ships with ~47 hardcoded dangerous command patterns (`rm -rf`, `git reset --hard`, `docker stop`, etc.). These cover common Unix commands but leave a large surface area unprotected:

- **Cloud CLI tools** (`vultr`, `gcloud`, `aws`, `az`, `oci`, `doctl`) — each with their own destructive subcommands
- **IaC tools** (`terraform destroy`, `pulumi up`, `cdk deploy`)
- **Database operations** (`DROP TABLE`, `mongodump --drop`)
- **CI/CD commands** (`gh run delete`, `circleci purge`)
- **Domain-specific tools** unique to a user's workflow

Without this plugin, a user who wants to guard `vultr instance delete` or `terraform destroy -auto-approve` has no clean mechanism — they either rely on the agent's judgment (risky) or manually approve every command (tedious). The plugin gives users first-class access to Hermes's approval flow (once/session/always/deny, gateway `/approve`/`/deny`, session persistence, permanent allowlist) for their own patterns.

### 2.2 The Broader Ecosystem of Solutions

Command execution safety in AI coding agents has become a defining architectural concern in 2024–2026. The landscape breaks into several philosophical camps:

#### A. Human-in-the-Loop (Approval Gates)

| Tool | Approach |
|------|----------|
| **Claude Code** | Strict read-only by default. Every destructive action requires explicit user approval. Fail-closed architecture. |
| **Aider** | No automatic command execution. Every shell command and code modification requires human confirmation. Git-based audit trail. |
| **Cursor** | Split-mode UI: "Interactive" (approval required) vs. "Auto-run" (YOLO). Optional `bwrap` sandboxing. |

This camp treats the agent as fundamentally untrusted. The user is the ultimate gatekeeper. **Hermes (with this plugin) belongs here** — the approval prompt is the primary safety mechanism.

#### B. Sandboxing-First (Environment Isolation)

| Tool | Approach |
|------|----------|
| **Open Interpreter** | Explicit "sandboxing-first" documentation. Recommends Docker/container isolation as the primary safety layer. |
| **OpenClaw** | Three sandboxing modes (off / non-main / all). Container-based isolation with read-only mounts. Per-agent, per-session scoping. |
| **E2B / CodeGate** | Specialized secure runtimes (WebAssembly, ephemeral containers) as middleware between agent and OS. |

This camp says: don't bother blocking individual commands — isolate the agent entirely so it can't damage anything important.

#### C. Policy-as-Code (Centralized Enforcement)

| Tool | Approach |
|------|----------|
| **OpenClaw + Cedar** | Policy engines evaluate tool requests based on context (who, what action, what resource). Allowlists over denylists. |
| **CodeGate** | Middleware proxy that inspects prompts and responses, enforcing security policies at the API boundary. |
| **Enterprise guardrail services** | Centralized policy enforcement with immutable audit trails. |

This camp treats safety as an architectural property of the orchestration layer, not a feature of the agent itself. The agent never has direct filesystem access to safety configuration.

#### D. Where Hermes + This Plugin Fit

Hermes, as an open-source local agent, sits in **Camp A** with a **light touch of Camp B** (container backends skip approval checks). This plugin extends Camp A by making the approval gate user-configurable.

**Key observation:** The plugin operates in a local-agent trust model where the agent **has the same filesystem access as the user**. This is fundamentally different from Claude Code (which runs in Anthropic's cloud with an API boundary) or OpenClaw (which enforces policies at an orchestration layer outside the agent process). The plugin cannot change this — it can only work within it.

---

## 3. Architecture Assessment

### 3.1 Design Decisions: What Works

#### 3.1.1 Pattern Injection into DANGEROUS_PATTERNS (Strong ✅)

The core design choice — appending `(pattern, description)` tuples to `DANGEROUS_PATTERNS` and `DANGEROUS_PATTERNS_COMPILED` — is the right one. It means custom patterns get **first-class treatment** in Hermes's entire approval pipeline with zero custom logic:

- CLI approval prompt (once/session/always/deny)
- Gateway async approval queue
- Session persistence in `_session_approved`
- Permanent allowlist in `~/.hermes/config.yaml`
- Smart mode LLM assessment
- Cron mode handling

This is elegant. The plugin doesn't reimplement approval — it extends the existing mechanism.

#### 3.1.2 Monkey-Patch for Allow Patterns (Justified ⚖️)

The monkey-patch of `detect_dangerous_command()` is the plugin's only real "hack," and it's justified. Hermes's detection function doesn't have an allow-pattern concept. Without the monkey-patch, the plugin could inject block patterns but couldn't exempt commands from them. The alternative — registering an approval hook — wouldn't work because:

1. `pre_approval_request` is observer-only (return values ignored)
2. By the time the hook fires, the command is already flagged as dangerous

The monkey-patch is clean: it wraps the original, checks allow patterns first, and falls through to the original for everything else. Well-named, well-documented, minimal.

#### 3.1.3 Graceful Degradation (Strong ✅)

Both `config.py` and `patterns.py` handle running outside Hermes gracefully:

```python
try:
    from tools.ansi_strip import strip_ansi
except ImportError:
    command = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', command)

try:
    from hermes_constants import get_hermes_home
except ImportError:
    return Path.home() / ".hermes" / _DEFAULT_CONFIG_FILENAME
```

This matters for testing and for edge cases where modules aren't available. The fallbacks are sensible.

#### 3.1.4 Config Validation (Solid ✅)

The validation pipeline in `config.py` handles every failure mode:
- Missing file → silent, no patterns
- Invalid YAML → `WARNING` logged, empty pattern list
- Invalid regex → `WARNING` logged, that pattern skipped
- Wrong types → `WARNING` logged, entry skipped

The plugin **never crashes the agent** on bad config. This is correct behavior.

#### 3.1.5 Caching (Correct ✅)

The module-level `_config_cache` in `config.py` avoids re-reading and re-validating the YAML on repeated calls. The `force=True` parameter exists for testing. Good trade-off — the config shouldn't change within a single process lifetime.

### 3.2 Design Decisions: Concerns

#### 3.2.1 No Hook Registration (Concerning ⚠️)

The SPEC explicitly notes: "No hooks used — the plugin doesn't register any `pre_tool_call` or `post_tool_call` hooks. All work happens at startup via pattern injection and monkey-patching."

This is simpler, yes. But it limits what the plugin can do:

- **No runtime re-configuration.** If the user edits `custom-dangerous-patterns.yaml` while Hermes is running, the plugin won't pick it up without a restart. A `pre_tool_call` hook could check for config changes.
- **No dynamic pattern adaptation.** Future features like "suggest a pattern after user denies a command 3 times" would need hooks.
- **No per-command context.** The plugin can't distinguish "the agent is trying to run this" from "the user is asking the agent to inspect this."

For v0.1.0 this is fine, but the roadmap's v0.3.0+ features will likely require hook integration.

#### 3.2.2 Regex-Only Matching (Limiting ⚠️)

All patterns are regex. This is flexible but has known limitations:

- **No semantic understanding.** `python -c "open('~/.hermes/custom-dangerous-patterns.yaml').write('...')"` won't match any regex targeting file paths — the filename is inside a Python string literal.
- **No multi-command awareness.** A two-step attack (`export C=~/.hermes/custom-dangerous-patterns.yaml; sed -i 's/block/allow/' $C`) defeats single-command regex.
- **No obfuscation resistance.** `vultr$(echo) instance$(echo) create` — trivial command injection that regex won't catch.

This is not a plugin bug — it's inherent to pattern-based approaches. Claude Code, Cursor, and Aider all have similar limitations. The real defense is the sandboxing layer (which Hermes supports but this plugin doesn't control).

#### 3.2.3 Import Order Dependency (Risk ⚠️)

The plugin depends on Hermes loading plugins before importing `tools.approval`:

```python
# From __init__.py:
from tools.approval import DANGEROUS_PATTERNS, DANGEROUS_PATTERNS_COMPILED
```

If approval.py is imported before the plugin registers, the plugin's patterns won't be in the compiled list. The SPEC acknowledges this ("Plugin loads after approval.py — patterns not injected") but the plugin doesn't detect or warn about it.

A defensive check would be valuable: after injection, verify that the custom patterns are actually in `DANGEROUS_PATTERNS_COMPILED` and log an ERROR if not.

#### 3.2.4 Global Monkey-Patch State (Minor ⚠️)

The monkey-patched function references module-level `_allow_patterns` list (set in `register()`). If `register()` is called multiple times (e.g., during testing), the old allow patterns persist. This is a minor concern for the target use case (single registration at startup) but could cause confusion in testing.

### 3.3 Code Quality Assessment

| Aspect | Rating | Notes |
|--------|--------|-------|
| Module separation | ⭐⭐⭐⭐⭐ | Clean: config.py, patterns.py, __init__.py — each has a clear responsibility |
| Error handling | ⭐⭐⭐⭐⭐ | Every failure mode handled, logged, and gracefully degraded |
| Documentation | ⭐⭐⭐⭐⭐ | SPEC.md, ROADMAP.md, README.md, inline docstrings — thorough and consistent |
| Type hints | ⭐⭐⭐⭐ | Good use of `from __future__ import annotations`, reasonable typing |
| Testing | ⭐⭐ | SPEC describes test categories but no tests exist in the repo |
| Defensive coding | ⭐⭐⭐⭐ | Good fallbacks, validation, caching. Missing: import-order verification |

---

## 4. Security Analysis

### 4.1 The Central Tension: Agent Self-Modification

The ROADMAP.md identifies this correctly as **the most important issue in the design**. Let me frame it more precisely:

**The plugin adds a layer of safety configuration that the agent can modify.** The agent has full filesystem access (same OS user as Hermes). If it can write to `~/.hermes/custom-dangerous-patterns.yaml`, it can:

1. Remove block patterns
2. Add allow patterns (including `.*` to exempt everything)
3. Widen existing patterns
4. Replace the entire config

The evaluation order makes this particularly dangerous:

```
1. Hardline (immutable, not bypassable)
2. Sudo stdin guard (immutable)
3. Yolo / mode=off (user intent)
4. Custom allow patterns     ← AGENT CAN MODIFY THIS
5. Custom block patterns     ← AGENT CAN MODIFY THIS
6. Built-in DANGEROUS_PATTERNS
7. Tirith scan
```

Allow patterns at step 4 **bypass steps 5, 6, and 7**. An agent-added `allow_patterns: [{pattern: '.*'}]` would exempt all commands from all approval except hardline checks. This is not a theoretical concern — it's a direct consequence of the local-agent trust model.

### 4.2 What the Plugin Can (and Can't) Do About It

The ROADMAP's v0.2.0 mitigations are honest about their limits:

| Mitigation | What It Does | What It Doesn't Do |
|------------|-------------|-------------------|
| **Protected pattern tier** | Logs CRITICAL if protected patterns are modified/removed | Doesn't prevent modification |
| **Config hash tracking** | Detects changes between sessions, logs delta | Detects only — doesn't block |
| **Allow shadowing warning** | Warns when new allow patterns bypass built-in checks | Requires interactive confirmation only in CLI mode |
| **OS-level permissions** | Documented as optional user hardening | Not enforced, not default, breaks common use case |

This is the right approach for a plugin: **detect and warn, don't enforce**. Enforcement requires an architectural boundary the plugin doesn't control.

### 4.3 Comparison with Other Ecosystems

| Solution | How it handles config tampering |
|----------|-------------------------------|
| **OpenClaw + Cedar** | Policy engine runs outside the agent process. Agent can't modify policy files — they're owned by the orchestration layer. |
| **Claude Code** | Runs in Anthropic's cloud. The agent has no access to its own safety configuration. |
| **Aider + CodeGate** | CodeGate intercepts API traffic. The agent never touches the security proxy's config. |
| **Cursor** | Desktop app with separate security process. Config files are outside the agent's sandbox. |
| **Hermes + this plugin** | Agent and safety config share the same filesystem. The plugin can only detect tampering, not prevent it. |

**The key insight:** Every other major solution places the safety configuration **outside the agent's trust boundary**. Hermes, as a local-first agent, cannot do this without OS-level user separation or container isolation — both of which the plugin documents but cannot enforce.

### 4.4 The Hardline Backstop

One thing the ROADMAP gets right: hardline patterns (`rm -rf /`, `mkfs`, `dd` to raw device, fork bombs) are **structurally immune** to this plugin. They're checked first in `check_all_command_guards()` and the plugin's monkey-patch returns early before reaching them. Even an agent that adds `allow_patterns: [{pattern: '.*'}]` cannot bypass hardline checks.

This is a critical safety property and it's correctly preserved.

---

## 5. Competitive Landscape

### 5.1 Direct Competitors (Within Hermes Ecosystem)

There are **no direct competitors**. This is the only plugin that extends Hermes's dangerous pattern list. That's both the plugin's strength (first-mover advantage, fills a genuine gap) and a concern (no ecosystem to learn from or interoperate with).

Alternatives users might consider instead of this plugin:
- **Manual approval:** Approve every command manually. Works but is tedious.
- **`--yolo` mode:** Bypass all approval. Fast but reckless.
- **Container backend:** Run Hermes in Docker. All approval skipped (agent is sandboxed). This is actually the **strongest alternative** — it addresses the same risk through isolation rather than gating.

### 5.2 Complementary Solutions

This plugin is **complementary to**, not competitive with:

| Solution | How it complements |
|----------|-------------------|
| **Hermes container backends** | Container isolation + pattern-based approval = defense in depth. Container catches what patterns miss; patterns gate what containers allow. |
| **Tirith security scanning** | Patterns gate known commands; Tirith catches novel threats in command content. |
| **Gateway approval `/approve` `/deny`** | Plugin defines *what* triggers approval; gateway handles *how* approval is delivered across channels. |
| **`command_allowlist` in config.yaml** | Plugin's patterns trigger the prompt; user's "always" choice persists to allowlist. |
| **OpenClaw-style policy engines** | If Hermes ever adds an orchestration layer, this plugin's patterns could feed into it as a rule source. |

### 5.3 What Can Be Learned from Similar Solutions

#### From OpenClaw

1. **Allowlist-first mentality.** OpenClaw's tool policies default to "nothing allowed unless explicitly permitted." Hermes (with this plugin) defaults to "everything allowed unless explicitly blocked." The OpenClaw approach is more secure but less practical for open-ended coding tasks. The plugin could support a "default-deny" mode as a future feature.

2. **Policy as code.** OpenClaw's Cedar integration treats policies as version-controlled, testable artifacts. The plugin's YAML config is a light version of this. Future versions could add policy testing (`hermes custom-patterns test`) and CI integration.

3. **Security audit commands.** `openclaw security audit` checks the installation for common misconfigurations. A `hermes custom-patterns audit` command (v0.3.0+) that checks for: config writability by the agent user, allow patterns that shadow built-in checks, patterns that haven't triggered in N days.

#### From Claude Code

1. **Transparency by default.** Claude Code shows what it's about to do in natural language before asking for approval. This plugin's descriptions serve the same purpose but are static. A future enhancement: AI-generated descriptions based on the matched command context.

2. **Permission scoping.** Claude Code restricts writes to the working directory. Hermes can't do this without OS-level changes, but the plugin could document it as a complementary hardening step.

#### From Aider + CodeGate

1. **Middleware as a security layer.** CodeGate sits between Aider and the LLM API, inspecting traffic. This is architecturally cleaner than monkey-patching internal functions. If Hermes ever adds a middleware/hook system that fires *before* tool execution (not just before approval), plugins could use it instead of monkey-patching.

2. **Git as an audit trail.** Aider's git-based change tracking means every modification is revertible. Hermes doesn't have this for shell commands, but a future plugin could log all commands + approval decisions to a structured audit log.

---

## 6. Roadmap Quality Assessment

The ROADMAP.md is **exceptionally thorough** for a v0.1.0 plugin. Most open-source projects don't reach this level of roadmap clarity until much later. Specific strengths:

### 6.1 v0.2.0 — Safety Hardening

| Feature | Assessment |
|---------|-----------|
| `enabled` field | Good. "Pause without delete" is a common user need. |
| `group` tag | Good. Enables bulk management and the test pattern collection. |
| `deny_patterns` | **Excellent.** This fills the gap between hardline (immutable, unconditional) and block patterns (prompt-based). Team policies need a "no prompt" tier. |
| `protected: true` | Good within plugin constraints. Won't stop a determined agent but will catch accidents. |
| Config hash tracking | Essential. The only structural integrity check the plugin can provide. |
| Allow shadowing warning | Smart. Addresses the most dangerous self-modification vector. |
| Directory config | Necessary for scale. Single-file YAML breaks down past ~20 patterns. |
| AGENTS.md safety guard | Important. Other AI agents working on this codebase need to know the risks. |

### 6.2 v0.3.0 — Usability

The CLI tooling (`hermes custom-patterns add/remove/list/test`) is the right priority after safety hardening. The `test` subcommand is particularly important — users need to verify their patterns work before relying on them.

**Missing:** Pattern import/export. The ability to share patterns between users (`hermes custom-patterns export --group cloud > cloud-patterns.yaml`) would accelerate adoption.

### 6.3 v0.4.0 — Power Features

Pattern profiles and import directives are good. Community pattern packs are aspirational but depend on adoption.

**Missing:** Pattern effectiveness analytics. Which patterns fire most often? Which are most often allowed vs. denied? This data would help users refine their config and remove noisy patterns.

### 6.4 v0.5.0 — Core Integration (Out of Scope)

Correctly identified as requiring Hermes core changes. The two most important upstream requests:
1. **Sensitive-write gate for plugin config** — this is the architectural fix for the self-modification problem
2. **Pattern convergence** — long-term, custom patterns should be `approvals.custom_patterns` in `config.yaml`, not a separate file the agent can "reach around"

---

## 7. Implementation Gaps

### 7.1 Missing: Tests

The SPEC describes test categories (unit tests for config loading, pattern compilation, allow matching, monkey-patch correctness; integration tests for DANGEROUS_PATTERNS injection; manual test procedures) but **no tests exist in the repository**. This is the most significant gap for a security-sensitive plugin.

Recommended test structure:

```
tests/
├── test_config.py          # YAML loading, validation, caching, missing file
├── test_patterns.py        # Compilation, allow matching, normalization
├── test_integration.py     # Mock DANGEROUS_PATTERNS injection, monkey-patch behavior
└── fixtures/
    ├── valid_config.yaml
    ├── invalid_regex.yaml
    ├── empty_config.yaml
    └── missing_config.yaml (path that doesn't exist)
```

### 7.2 Missing: Import Order Verification

As noted in §3.2.3, the plugin doesn't verify that its patterns were successfully injected. A post-injection check:

```python
# After injection in register():
if block_compiled:
    injected_patterns = {p.pattern for p, _ in block_compiled}
    live_patterns = {p.pattern for p, _ in DANGEROUS_PATTERNS_COMPILED}
    if not injected_patterns.issubset(live_patterns):
        logger.error(
            "custom-dangerous-patterns: patterns not injected — "
            "approval.py may have been imported before plugin registration"
        )
```

### 7.3 Missing: Hermes Version Compatibility

The plugin doesn't declare what versions of Hermes it supports. The README says "tested with 0.15.1" but there's no version check at load time. If Hermes changes its internal API (e.g., renames `DANGEROUS_PATTERNS_COMPILED` or moves `detect_dangerous_command`), the plugin will fail silently — the import will raise and the plugin won't load, but there's no clear error message.

A version compatibility check with a helpful error message would improve the user experience.

### 7.4 Missing: Config Reloading

The plugin loads config once at startup. If the user edits the YAML while Hermes is running, changes don't take effect. A `hermes custom-patterns reload` CLI command (v0.3.0) or a file watcher that detects config changes and re-injects patterns would address this.

---

## 8. Ecosystem Impact Assessment

### 8.1 What This Plugin Enables

1. **Domain-specific safety.** Every Hermes user has different tools they consider dangerous. This plugin makes safety personal.
2. **Team safety policies.** With directory config and version control, teams can share and enforce safety policies.
3. **Pattern experimentation.** Users can try patterns, see what works, and iterate — without waiting for Hermes core releases.
4. **Community pattern sharing.** The directory config format enables GitHub repos of shared pattern packs.

### 8.2 Risks to the Ecosystem

1. **False sense of security.** Users might believe their patterns make them "safe" when in reality:
   - The agent can modify the patterns
   - Regex can't catch obfuscated commands
   - File-write tool calls bypass command-line pattern matching
   
2. **Pattern conflicts.** If multiple plugins inject patterns into `DANGEROUS_PATTERNS`, there's no coordination mechanism. Two plugins could add conflicting allow/block patterns.

3. **Maintenance burden.** If this plugin becomes popular, Hermes core changes that affect `DANGEROUS_PATTERNS` or `detect_dangerous_command` will need to consider backward compatibility with this plugin's monkey-patch.

### 8.3 Recommendations for Hermes Core

1. **Add a `register_dangerous_pattern()` API to `PluginContext`.** This would eliminate the need for monkey-patching and direct list manipulation. Plugins would call `ctx.register_dangerous_pattern(pattern, description)` and `ctx.register_allow_pattern(pattern)`.

2. **Add plugin config files to `_SENSITIVE_WRITE_TARGET`.** The terminal-write gate should protect `custom-dangerous-patterns.yaml` and `custom-dangerous-patterns.d/` the same way it protects `config.yaml`.

3. **Consider a `pre_tool_execution` hook.** Currently, hooks are observer-only and fire after detection. A pre-execution hook that can veto commands would let plugins do context-aware safety checks without monkey-patching.

4. **Add structured logging for approval events.** A standardized event format for "command was flagged by pattern X, user chose action Y" would enable analytics and audit trails across all pattern sources (built-in, plugin, Tirith).

---

## 9. Conclusion

### 9.1 What's Excellent

- **Architecture:** Clean separation of concerns, minimal surface area, well-justified trade-offs
- **Documentation:** SPEC.md, ROADMAP.md, and README.md are thorough, honest about limitations, and forward-looking
- **Graceful degradation:** Never crashes the agent, handles all edge cases
- **Roadmap awareness:** Exceptionally clear about what's in scope vs. out of scope, what requires Hermes core changes

### 9.2 What Needs Attention

- **Tests:** The most significant gap. A security-sensitive plugin needs automated tests.
- **Import order verification:** Should detect and warn when patterns aren't injected.
- **Agent self-modification:** The roadmap's v0.2.0 mitigations are well-designed but the plugin's fundamental constraint (same-user filesystem access) means this can only be detected, not prevented.

### 9.3 Verdict

This is a **well-designed v0.1.0** that fills a genuine gap in the Hermes ecosystem. The implementation quality is high, the documentation is exceptional, and the roadmap shows deep understanding of both the plugin's strengths and its architectural constraints. The main risk is not in the plugin's design but in users misunderstanding what it can and cannot protect against — a risk the README and ROADMAP already address honestly.

The plugin would benefit most from: (1) automated tests, (2) Hermes core adopting a formal pattern-registration API to eliminate the monkey-patch, and (3) the v0.2.0 safety hardening features. With these, it would be production-ready for users who understand the local-agent trust model.
