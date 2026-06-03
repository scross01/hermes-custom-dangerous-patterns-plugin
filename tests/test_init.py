from __future__ import annotations

import logging
import sys
import types
from unittest.mock import MagicMock


def _install_tools_approval(monkeypatch):
    """Install mock tools and tools.approval modules into sys.modules."""
    approval = types.ModuleType("tools.approval")
    approval.DANGEROUS_PATTERNS = []
    approval.DANGEROUS_PATTERNS_COMPILED = []
    approval.detect_dangerous_command = lambda cmd: (False, None, None)

    tools = types.ModuleType("tools")
    tools.approval = approval
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.approval", approval)
    return approval


SAMPLE_PATTERN_CONFIG = {
    "patterns": [
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
    ],
    "allow_patterns": [],
    "deny_patterns": [],
}

SAMPLE_ALLOW_CONFIG = {
    "patterns": [
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
    ],
    "allow_patterns": [
        {"pattern": r"\bvultr\s+account\s+info\b", "description": "Read-only"},
    ],
    "deny_patterns": [],
}

SAMPLE_DENY_CONFIG = {
    "patterns": [
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
    ],
    "allow_patterns": [],
    "deny_patterns": [
        {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby system exec"},
    ],
}


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------


def test_register_no_patterns(
    monkeypatch, tmp_path, init_register
):
    """register() with no patterns logs and returns without injecting."""
    # Mock load_config to return empty patterns
    monkeypatch.setattr(
        init_register.config, "load_config",
        lambda: {"patterns": [], "allow_patterns": []},
    )

    messages = []

    class Handler(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    logger = logging.getLogger("hermes_plugins._init_")
    logger.addHandler(Handler())
    logger.setLevel(logging.INFO)

    ctx = MagicMock()
    init_register.register(ctx)

    assert any("no active patterns" in m for m in messages)


def test_register_injects_block_patterns(
    monkeypatch, tmp_path, init_register
):
    """register() with patterns appends to DANGEROUS_PATTERNS."""
    monkeypatch.setattr(
        init_register.config, "load_config",
        lambda: dict(SAMPLE_PATTERN_CONFIG),
    )

    approval = _install_tools_approval(monkeypatch)

    ctx = MagicMock()
    init_register.register(ctx)

    assert len(approval.DANGEROUS_PATTERNS) == 1
    assert approval.DANGEROUS_PATTERNS[0][1] == "Vultr CLI"


def test_register_injects_to_both_lists(
    monkeypatch, tmp_path, init_register
):
    """register() appends to both DANGEROUS_PATTERNS and DANGEROUS_PATTERNS_COMPILED."""
    monkeypatch.setattr(
        init_register.config, "load_config",
        lambda: dict(SAMPLE_PATTERN_CONFIG),
    )

    approval = _install_tools_approval(monkeypatch)

    ctx = MagicMock()
    init_register.register(ctx)

    assert len(approval.DANGEROUS_PATTERNS) == 1
    assert len(approval.DANGEROUS_PATTERNS_COMPILED) == 1
    assert approval.DANGEROUS_PATTERNS_COMPILED[0][1] == "Vultr CLI"


def test_register_no_block_no_injection(
    monkeypatch, tmp_path, init_register
):
    """register() without block patterns does not inject."""
    monkeypatch.setattr(
        init_register.config, "load_config",
        lambda: {"patterns": [], "allow_patterns": [{"pattern": r"\bvultr\b", "description": "Vultr"}]},
    )

    approval = _install_tools_approval(monkeypatch)

    ctx = MagicMock()
    init_register.register(ctx)

    assert len(approval.DANGEROUS_PATTERNS) == 0


# ---------------------------------------------------------------------------
# _patch_detect_function
# ---------------------------------------------------------------------------


def test_patched_allow_match_bypasses_original(monkeypatch):
    """When allow pattern matches, original detect is not called."""
    mock_original = MagicMock(return_value=(True, "dangerous", "rm -rf /"))
    approval = _install_tools_approval(monkeypatch)
    approval.detect_dangerous_command = mock_original

    from __init__ import _patch_detect_function

    def allow_checker(cmd):
        return "Allowed" if "safe" in cmd else None

    _patch_detect_function(allow_checker)
    result = approval.detect_dangerous_command("safe command")
    assert result == (False, None, None)
    mock_original.assert_not_called()


def test_patched_no_match_falls_through(monkeypatch):
    """When no allow pattern matches, original detect is called."""
    mock_original = MagicMock(return_value=(True, "dangerous", "rm -rf /"))
    approval = _install_tools_approval(monkeypatch)
    approval.detect_dangerous_command = mock_original

    from __init__ import _patch_detect_function

    def allow_checker(cmd):
        return None

    _patch_detect_function(allow_checker)
    result = approval.detect_dangerous_command("rm -rf /")
    assert result == (True, "dangerous", "rm -rf /")
    mock_original.assert_called_once_with("rm -rf /")


def test_patched_preserves_function_metadata(monkeypatch):
    """Patched function retains detect_dangerous_command name."""
    mock_original = MagicMock()
    approval = _install_tools_approval(monkeypatch)
    approval.detect_dangerous_command = mock_original

    from __init__ import _patch_detect_function

    def allow_checker(cmd):
        return None

    _patch_detect_function(allow_checker)
    assert approval.detect_dangerous_command.__name__ == "detect_dangerous_command"
    assert approval.detect_dangerous_command.__qualname__ == "detect_dangerous_command"


# ---------------------------------------------------------------------------
# _patch_deny_handler
# ---------------------------------------------------------------------------


def test_deny_handler_blocks_matching_command(monkeypatch):
    """When deny pattern matches, returns blocked result without calling original."""
    approval = _install_tools_approval(monkeypatch)
    mock_original = MagicMock()
    approval.check_all_command_guards = mock_original

    from __init__ import _patch_deny_handler

    def deny_checker(cmd):
        return "Ruby system exec" if "ruby" in cmd else None

    _patch_deny_handler(deny_checker)
    result = approval.check_all_command_guards("ruby -e 'system(\"rm\")'")
    assert result["approved"] is False
    assert "Ruby system exec" in result["message"]
    assert "deny" in result["message"].lower()
    mock_original.assert_not_called()


def test_deny_handler_no_match_falls_through(monkeypatch):
    """When no deny pattern matches, original guard function is called."""
    approval = _install_tools_approval(monkeypatch)
    mock_original = MagicMock(return_value={"approved": True, "message": "ok"})
    approval.check_all_command_guards = mock_original

    from __init__ import _patch_deny_handler

    def deny_checker(cmd):
        return None

    _patch_deny_handler(deny_checker)
    result = approval.check_all_command_guards("echo hello")
    assert result["approved"] is True
    mock_original.assert_called_once()


def test_deny_handler_fallback_when_guards_missing(monkeypatch):
    """When check_all_command_guards is missing, falls back to detect patch."""
    approval = _install_tools_approval(monkeypatch)
    # check_all_command_guards was never set on this mock - the fallback
    # path in _patch_deny_handler tests getattr returning None

    mock_original = MagicMock(return_value=(False, None, None))
    approval.detect_dangerous_command = mock_original

    from __init__ import _patch_deny_handler

    def deny_checker(cmd):
        return "Blocked" if "danger" in cmd else None

    _patch_deny_handler(deny_checker)
    result = approval.detect_dangerous_command("danger command")
    assert result[0] is True
    assert "DENY" in result[1]
    mock_original.assert_not_called()


def test_deny_handler_fallback_composes_with_allow(monkeypatch):
    """Fallback path preserves allow-before-deny when allow already patched."""
    approval = _install_tools_approval(monkeypatch)

    # Phase 1: patch allow patterns (simulating register step 3)
    from __init__ import _patch_detect_function, _patch_deny_handler

    def allow_checker(cmd):
        return "Allowed" if "safe" in cmd else None

    _patch_detect_function(allow_checker)

    # Phase 2: patch deny patterns via fallback (simulating register step 4)
    # Pass allow_checker so the fallback wrapper checks allow before deny
    def deny_checker(cmd):
        return "Blocked" if "danger" in cmd else None

    _patch_deny_handler(deny_checker, allow_checker)

    # Allow wins: command matches both allow and deny, allow checked first
    result = approval.detect_dangerous_command("safe danger command")
    assert result == (False, None, None)  # allow exempts

    # Deny-only: command matches only deny, should be blocked
    result = approval.detect_dangerous_command("danger command")
    assert result[0] is True
    assert "DENY" in result[1]

    # No match: falls through to original
    result = approval.detect_dangerous_command("ordinary command")
    assert result == (False, None, None)


def test_register_with_deny_patterns(
    monkeypatch, tmp_path, init_register
):
    """register() with deny patterns patches check_all_command_guards."""
    monkeypatch.setattr(
        init_register.config, "load_config",
        lambda: dict(SAMPLE_DENY_CONFIG),
    )

    approval = _install_tools_approval(monkeypatch)
    approval.check_all_command_guards = MagicMock()

    ctx = MagicMock()
    init_register.register(ctx)

    # Verify check_all_command_guards was patched (deny handler installed)
    assert approval.check_all_command_guards.__name__ == "check_all_command_guards"
    assert approval.check_all_command_guards.__qualname__ == "check_all_command_guards"


# ---------------------------------------------------------------------------
# _check_allow_shadowing / _patterns_overlap / _extract_tokens
# ---------------------------------------------------------------------------


def test_patterns_overlap_broad():
    """Broad patterns like '.*' shadow everything."""
    import re
    from __init__ import _patterns_overlap

    r1 = re.compile(".*")
    r2 = re.compile(r"\brm\b")
    assert _patterns_overlap(r1, r2) is True


def test_patterns_overlap_token_match():
    """Patterns with shared tokens overlap."""
    import re
    from __init__ import _patterns_overlap

    r1 = re.compile(r"\baws\b.*")
    r2 = re.compile(r"\baws\s+ec2\b")
    assert _patterns_overlap(r1, r2) is True


def test_patterns_overlap_no_match():
    """Unrelated patterns don't overlap."""
    import re
    from __init__ import _patterns_overlap

    r1 = re.compile(r"\bvultr\b")
    r2 = re.compile(r"\baws\b")
    assert _patterns_overlap(r1, r2) is False


def test_extract_tokens():
    """Extracts word tokens >= 3 chars from regex."""
    from __init__ import _extract_tokens

    tokens = _extract_tokens(r"\baws\s+(ec2|s3|rds)\b")
    assert "aws" in tokens
    assert "ec2" in tokens
    assert "rds" in tokens
    # s3 is only 2 chars, filtered out by >=3 token rule
