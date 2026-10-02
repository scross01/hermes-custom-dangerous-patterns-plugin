"""Tests for the plugin entry point and the pre_tool_call enforcement hook.

The plugin used to inject patterns into DANGEROUS_PATTERNS and monkey-patch
tools.approval. It no longer does either. The tests below cover the hook
contract, the stable rule key, and the rule-9 guarantee that nothing under
Hermes's control is mutated.
"""

from __future__ import annotations

import logging
import sys
import types
from unittest.mock import MagicMock

BLOCK_CONFIG = {
    "patterns": [{"pattern": r"\bvultr\b", "description": "Vultr CLI"}],
    "allow_patterns": [],
    "deny_patterns": [],
}

DENY_CONFIG = {
    "patterns": [{"pattern": r"\becho\b", "description": "Echo"}],
    "allow_patterns": [],
    "deny_patterns": [
        {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby system exec"},
    ],
}

BOTH_CONFIG = {
    "patterns": [{"pattern": r"\becho\b", "description": "Echo"}],
    "allow_patterns": [],
    "deny_patterns": [
        {"pattern": r"\becho\s+deny\b", "description": "Deny echo deny"},
    ],
}


def _install_fake_approval(monkeypatch):
    """Install a fake ``tools.approval_detection`` with observable pattern lists.

    The lists are real Python lists so a mutation would be visible. The plugin
    must never write to them.
    """
    patterns: list = []
    compiled: list = []

    approval_detection = types.ModuleType("tools.approval_detection")
    approval_detection.DANGEROUS_PATTERNS = patterns
    approval_detection.DANGEROUS_PATTERNS_COMPILED = compiled

    tools = types.ModuleType("tools")
    tools.approval_detection = approval_detection

    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.approval_detection", approval_detection)
    return patterns, compiled


def _hook_from_register(ctx):
    """Extract the registered pre_tool_call hook from a MagicMock ctx."""
    calls = [
        c for c in ctx.register_hook.call_args_list if c.args and c.args[0] == "pre_tool_call"
    ]
    assert len(calls) == 1, f"expected exactly one pre_tool_call registration, got {calls}"
    return calls[0].args[1]


# ---------------------------------------------------------------------------
# register(): rule-9 guarantees
# ---------------------------------------------------------------------------


def test_register_does_not_touch_core_tables(monkeypatch, tmp_path, init_register):
    """register() must leave Hermes's pattern tables untouched (catalog rule 9).

    Table writes are NOT detected by `hermes plugins validate`, so this is the
    only automated check that they have not crept back in.
    """
    monkeypatch.setattr(init_register.config, "load_config", lambda: dict(BLOCK_CONFIG))
    patterns, compiled = _install_fake_approval(monkeypatch)

    init_register.register(MagicMock())

    assert patterns == [], "plugin wrote to DANGEROUS_PATTERNS"
    assert compiled == [], "plugin wrote to DANGEROUS_PATTERNS_COMPILED"


def test_register_does_not_rebind_core_functions(monkeypatch, tmp_path, init_register):
    """register() must not replace any tools.approval function."""
    monkeypatch.setattr(init_register.config, "load_config", lambda: dict(BLOCK_CONFIG))

    approval = types.ModuleType("tools.approval")
    original_detect = lambda cmd: (False, None, None)  # noqa: E731
    original_guards = lambda *a, **k: {"approved": True}  # noqa: E731
    approval.detect_dangerous_command = original_detect
    approval.check_all_command_guards = original_guards

    tools = types.ModuleType("tools")
    tools.approval = approval
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.approval", approval)

    init_register.register(MagicMock())

    assert approval.detect_dangerous_command is original_detect
    assert approval.check_all_command_guards is original_guards


def test_deleted_patch_helpers_are_absent(init_register):
    """The five monkey-patch helpers were deleted in the hook-only migration."""
    for name in (
        "_patch_block_logging",
        "_patch_detect_function",
        "_patch_deny_handler",
        "_patch_detect_function_for_deny",
        "_extract_guard_command",
        "_check_allow_shadowing",
    ):
        assert not hasattr(init_register, name), f"{name} still present"


def test_register_registers_pre_tool_call_hook(monkeypatch, tmp_path, init_register):
    """The hook is registered exactly once, for the pre_tool_call event."""
    monkeypatch.setattr(init_register.config, "load_config", lambda: dict(BLOCK_CONFIG))
    ctx = MagicMock()

    init_register.register(ctx)

    assert ctx.register_hook.call_count == 1
    assert ctx.register_hook.call_args.args[0] == "pre_tool_call"


def test_register_is_idle_without_patterns(monkeypatch, tmp_path, init_register):
    """With no patterns the plugin still registers its hook and logs idleness.

    Registering unconditionally keeps the manifest's provides_hooks declaration
    in agreement with runtime registration, which Hermes doctor checks.
    """
    monkeypatch.setattr(
        init_register.config,
        "load_config",
        lambda: {"patterns": [], "allow_patterns": [], "deny_patterns": []},
    )

    messages: list[str] = []

    class Handler(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    log = logging.getLogger("hermes_plugins._init_")
    log.addHandler(Handler())
    log.setLevel(logging.INFO)

    ctx = MagicMock()
    init_register.register(ctx)

    assert any("no active patterns" in m for m in messages)
    assert ctx.register_hook.call_count == 1


# ---------------------------------------------------------------------------
# Hook: argument handling
# ---------------------------------------------------------------------------


def _hook(init_register, config):
    """Build a hook against a compiled config, without a full register()."""
    init_register.patterns.compile_all(config)
    return init_register._make_policy_hook(
        init_register.patterns.find_block_match,
        init_register.patterns.find_deny_match,
    )


def test_hook_returns_none_for_non_terminal_tool(init_register):
    hook = _hook(init_register, BLOCK_CONFIG)
    assert hook("read_file", {"path": "/tmp/x"}) is None


def test_hook_returns_none_for_empty_command(init_register):
    hook = _hook(init_register, BLOCK_CONFIG)
    assert hook("terminal", {}) is None
    assert hook("terminal", {"command": ""}) is None


def test_hook_returns_none_for_non_str_command(init_register):
    """A malformed arg must not raise: Hermes fails closed on hook exceptions,
    so a crash would block every terminal call, not just this one."""
    hook = _hook(init_register, BLOCK_CONFIG)
    assert hook("terminal", {"command": 123}) is None
    assert hook("terminal", {"command": ["a", "b"]}) is None


def test_hook_returns_none_when_no_patterns_match(init_register):
    hook = _hook(init_register, BLOCK_CONFIG)
    assert hook("terminal", {"command": "ls -la"}) is None


def test_hook_returns_none_for_empty_config(init_register):
    hook = _hook(init_register, {"patterns": [], "allow_patterns": [], "deny_patterns": []})
    assert hook("terminal", {"command": "anything at all"}) is None


# ---------------------------------------------------------------------------
# Hook: directives
# ---------------------------------------------------------------------------


def test_hook_denies_matching_command(init_register):
    hook = _hook(init_register, DENY_CONFIG)
    result = hook("terminal", {"command": "ruby -e 'system(\"ls\")'"})
    assert result is not None
    assert result["action"] == "block"
    assert "Ruby system exec" in result["message"]


def test_hook_denies_before_blocking(init_register):
    """Deny wins when a command matches both a deny and a block pattern."""
    hook = _hook(init_register, BOTH_CONFIG)
    result = hook("terminal", {"command": "echo deny"})
    assert result["action"] == "block", "deny must take precedence over block"
    assert "Deny echo deny" in result["message"]


def test_hook_block_returns_approve_with_rule_key(init_register):
    hook = _hook(init_register, BLOCK_CONFIG)
    result = hook("terminal", {"command": "vultr instance list"})
    assert result is not None
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("cdp:")
    assert "Vultr CLI" in result["message"]


def test_hook_deny_has_no_rule_key(init_register):
    """A deny match blocks outright; an approval grain would be meaningless."""
    hook = _hook(init_register, DENY_CONFIG)
    result = hook("terminal", {"command": "ruby -e 'system(\"ls\")'"})
    assert "rule_key" not in result


# ---------------------------------------------------------------------------
# Rule key stability -- the load-bearing property
# ---------------------------------------------------------------------------


def test_rule_key_is_stable_across_description_edits(init_register):
    """Editing a pattern's description must not reset the user's [a]lways.

    request_tool_approval() falls back to hashing the *description*, so a
    description-derived rule_key would silently drop permanent approvals. This
    builds two configs that differ ONLY in description and asserts the emitted
    rule_key is byte-identical.
    """
    hook_before = _hook(
        init_register,
        {"patterns": [{"pattern": r"\bvultr\b", "description": "Old label"}],
         "allow_patterns": [], "deny_patterns": []},
    )
    key_before = hook_before("terminal", {"command": "vultr instance list"})["rule_key"]

    hook_after = _hook(
        init_register,
        {"patterns": [{"pattern": r"\bvultr\b", "description": "Totally new label"}],
         "allow_patterns": [], "deny_patterns": []},
    )
    key_after = hook_after("terminal", {"command": "vultr instance list"})["rule_key"]

    assert key_before == key_after, "description edit must not change the rule_key"


def test_rule_key_changes_when_regex_changes(init_register):
    hook_a = _hook(
        init_register,
        {"patterns": [{"pattern": r"\bvultr\b", "description": "A"}],
         "allow_patterns": [], "deny_patterns": []},
    )
    key_a = hook_a("terminal", {"command": "vultr x"})["rule_key"]

    hook_b = _hook(
        init_register,
        {"patterns": [{"pattern": r"\baws\b", "description": "A"}],
         "allow_patterns": [], "deny_patterns": []},
    )
    key_b = hook_b("terminal", {"command": "aws x"})["rule_key"]

    assert key_a != key_b


def test_rule_key_is_deterministic_across_calls(init_register):
    """No dependence on hash() or PYTHONHASHSEED -- keys must survive restarts."""
    hook = _hook(init_register, BLOCK_CONFIG)
    first = hook("terminal", {"command": "vultr x"})["rule_key"]
    second = hook("terminal", {"command": "vultr x"})["rule_key"]
    assert first == second


def test_distinct_patterns_get_distinct_rule_keys(init_register):
    """Guards against every rule collapsing into one allowlist entry.

    Hermes passes `details.rule_key or tool_name` to request_tool_approval, so
    an omitted or shared rule_key would allowlist every custom terminal rule at
    once. Distinct patterns MUST produce distinct keys.
    """
    hook = _hook(
        init_register,
        {
            "patterns": [
                {"pattern": r"\bvultr\b", "description": "Vultr"},
                {"pattern": r"\baws\b", "description": "AWS"},
            ],
            "allow_patterns": [],
            "deny_patterns": [],
        },
    )
    key_vultr = hook("terminal", {"command": "vultr x"})["rule_key"]
    key_aws = hook("terminal", {"command": "aws x"})["rule_key"]
    assert key_vultr != key_aws


def test_same_regex_gives_same_key(init_register):
    """Identical regex source must yield an identical key (deterministic)."""
    assert init_register._rule_key_for(r"\bvultr\b") == init_register._rule_key_for(r"\bvultr\b")


def test_rule_key_format(init_register):
    """Keys are namespaced and short: Hermes stores them in command_allowlist
    as plugin_rule:<rule_key>, so an unbounded or unprefixed key would be
    confusing in the user's config."""
    key = init_register._rule_key_for(r"\bvultr\b")
    assert key.startswith("cdp:")
    digest = key[len("cdp:"):]
    assert len(digest) == 12
    assert all(c in "0123456789abcdef" for c in digest)


# ---------------------------------------------------------------------------
# Logging must never break enforcement
# ---------------------------------------------------------------------------


def test_hook_logs_block_match(init_register, monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(
        init_register, "log_match", lambda *a: seen.append(a), raising=False
    )
    hook = _hook(init_register, BLOCK_CONFIG)
    hook("terminal", {"command": "vultr instance list"})
    assert seen
    assert seen[0][1] == "block"


def test_hook_logs_deny_match(init_register, monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(
        init_register, "log_match", lambda *a: seen.append(a), raising=False
    )
    hook = _hook(init_register, DENY_CONFIG)
    hook("terminal", {"command": "ruby -e 'system(\"ls\")'"})
    assert seen
    assert seen[0][1] == "deny"


def test_hook_swallows_logging_errors(init_register, monkeypatch):
    """A logging failure must never propagate: Hermes fails closed on hook
    exceptions, so a raise would block every terminal call."""

    def boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(init_register, "log_match", boom, raising=False)
    hook = _hook(init_register, BLOCK_CONFIG)
    result = hook("terminal", {"command": "vultr instance list"})
    assert result is not None
    assert result["action"] == "approve"


# ---------------------------------------------------------------------------
# patterns._patterns_overlap / _extract_tokens
#
# The overlap helpers live in patterns.py (shared with cli.py). They are tested
# here against their canonical location.
# ---------------------------------------------------------------------------


def test_patterns_overlap_broad():
    """Broad patterns like '.*' shadow everything."""
    import re

    from patterns import _patterns_overlap

    r1 = re.compile(".*")
    r2 = re.compile(r"\brm\b")
    assert _patterns_overlap(r1, r2) is True


def test_patterns_overlap_token_match():
    """Patterns with shared tokens overlap."""
    import re

    from patterns import _patterns_overlap

    r1 = re.compile(r"\baws\b.*")
    r2 = re.compile(r"\baws\s+ec2\b")
    assert _patterns_overlap(r1, r2) is True


def test_patterns_overlap_no_match():
    """Unrelated patterns don't overlap."""
    import re

    from patterns import _patterns_overlap

    r1 = re.compile(r"\bvultr\b")
    r2 = re.compile(r"\baws\b")
    assert _patterns_overlap(r1, r2) is False


def test_extract_tokens():
    """Extracts word tokens >= 3 chars from regex."""
    from patterns import _extract_tokens

    tokens = _extract_tokens(r"\baws\s+(ec2|s3|rds)\b")
    assert "aws" in tokens
    assert "ec2" in tokens
    assert "rds" in tokens
    # s3 is only 2 chars, filtered out by >=3 token rule
