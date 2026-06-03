from __future__ import annotations

import logging
import sys
import types
from unittest.mock import MagicMock

import pytest


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
}

SAMPLE_ALLOW_CONFIG = {
    "patterns": [
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
    ],
    "allow_patterns": [
        {"pattern": r"\bvultr\s+account\s+info\b", "description": "Read-only"},
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

    assert any("no patterns configured" in m for m in messages)


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
