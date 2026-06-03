from __future__ import annotations

import re

import pytest


# ---------------------------------------------------------------------------
# compile_block_patterns
# ---------------------------------------------------------------------------


def test_compile_block_patterns_valid():
    """Valid pattern strings compile correctly."""
    from patterns import compile_block_patterns

    raw = [
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
        {"pattern": r"\baws\b", "description": "AWS CLI"},
    ]
    compiled = compile_block_patterns(raw)
    assert len(compiled) == 2
    for regex, desc in compiled:
        assert isinstance(regex, re.Pattern)
        assert isinstance(desc, str)


def test_compile_block_patterns_uses_description_fallback():
    """When description is missing, pattern string is used as description."""
    from patterns import compile_block_patterns

    raw = [{"pattern": r"\bvultr\b"}]
    compiled = compile_block_patterns(raw)
    assert compiled[0][1] == r"\bvultr\b"


def test_compile_block_patterns_skips_invalid_regex():
    """Invalid regex is skipped, valid ones still compile."""
    from patterns import compile_block_patterns

    raw = [
        {"pattern": "[invalid", "description": "Bad"},
        {"pattern": r"\bvultr\b", "description": "Good"},
    ]
    compiled = compile_block_patterns(raw)
    assert len(compiled) == 1
    assert compiled[0][1] == "Good"


def test_compile_block_patterns_empty():
    """Empty input returns empty list."""
    from patterns import compile_block_patterns

    assert compile_block_patterns([]) == []


# ---------------------------------------------------------------------------
# compile_allow_patterns
# ---------------------------------------------------------------------------


def test_compile_allow_patterns_valid():
    """Valid allow patterns compile correctly."""
    from patterns import compile_allow_patterns

    raw = [{"pattern": r"\bvultr\s+account\s+info\b", "description": "Read-only"}]
    compiled = compile_allow_patterns(raw)
    assert len(compiled) == 1
    assert isinstance(compiled[0][0], re.Pattern)


def test_compile_allow_patterns_skips_invalid():
    """Invalid allow regex is skipped."""
    from patterns import compile_allow_patterns

    raw = [
        {"pattern": "(unclosed", "description": "Bad"},
        {"pattern": r"\bvultr\b", "description": "Good"},
    ]
    compiled = compile_allow_patterns(raw)
    assert len(compiled) == 1


# ---------------------------------------------------------------------------
# compile_all
# ---------------------------------------------------------------------------


def test_compile_all_sets_globals(reset_patterns_globals):
    """compile_all sets module-level block and allow lists."""
    from patterns import compile_all, get_block_patterns

    config = {
        "patterns": [{"pattern": r"\bvultr\b", "description": "Vultr"}],
        "allow_patterns": [{"pattern": r"\bvultr\s+info\b", "description": "Info"}],
    }
    compile_all(config)
    assert len(get_block_patterns()) == 1


def test_compile_all_empty_config(reset_patterns_globals):
    """Empty config leaves globals empty."""
    from patterns import compile_all, get_block_patterns

    compile_all({})
    assert get_block_patterns() == []


# ---------------------------------------------------------------------------
# is_allow_pattern
# ---------------------------------------------------------------------------


def test_is_allow_pattern_matches(reset_patterns_globals):
    """Matching command returns the allow pattern description."""
    from patterns import compile_all, is_allow_pattern

    config = {
        "allow_patterns": [
            {"pattern": r"\bvultr\s+account\s+info\b", "description": "Vultr read-only"}
        ]
    }
    compile_all(config)
    result = is_allow_pattern("vultr account info")
    assert result == "Vultr read-only"


def test_is_allow_pattern_no_match(reset_patterns_globals):
    """Non-matching command returns None."""
    from patterns import compile_all, is_allow_pattern

    config = {
        "allow_patterns": [
            {"pattern": r"\bvultr\s+account\s+info\b", "description": "Vultr read-only"}
        ]
    }
    compile_all(config)
    result = is_allow_pattern("vultr instance create")
    assert result is None


def test_is_allow_pattern_no_patterns(reset_patterns_globals):
    """No allow patterns returns None."""
    from patterns import compile_all, is_allow_pattern

    compile_all({})
    assert is_allow_pattern("anything") is None


def test_is_allow_pattern_case_insensitive(reset_patterns_globals):
    """Matching is case-insensitive."""
    from patterns import compile_all, is_allow_pattern

    config = {
        "allow_patterns": [
            {"pattern": r"\bVULTR\b", "description": "Vultr"}
        ]
    }
    compile_all(config)
    assert is_allow_pattern("Vultr list") == "Vultr"
    assert is_allow_pattern("vultr list") == "Vultr"
    assert is_allow_pattern("VULTR LIST") == "Vultr"


# ---------------------------------------------------------------------------
# get_block_patterns
# ---------------------------------------------------------------------------


def test_get_block_patterns_returns_copy(reset_patterns_globals):
    """get_block_patterns returns a copy, not the internal list."""
    from patterns import compile_all, get_block_patterns

    compile_all({
        "patterns": [{"pattern": r"\bvultr\b", "description": "Vultr"}]
    })
    patterns = get_block_patterns()
    patterns.clear()
    assert len(get_block_patterns()) == 1


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


def test_normalize_strips_ansi():
    """ANSI escape sequences are stripped."""
    from patterns import _normalize

    result = _normalize("\x1b[31mvultr\x1b[0m list")
    assert result == "vultr list"


def test_normalize_removes_null_bytes():
    """Null bytes are removed."""
    from patterns import _normalize

    result = _normalize("vultr\x00 list")
    assert result == "vultr list"


def test_normalize_unicode_nfkc():
    """Unicode is normalized to NFKC."""
    from patterns import _normalize

    result = _normalize("vultr\u00b2")  # superscript 2
    assert result == "vultr2"


def test_normalize_comprehensive():
    """All normalizations applied together."""
    from patterns import _normalize

    result = _normalize("\x1b[1mvultr\x00\x1b[0m \u00b2")
    assert result == "vultr 2"


def test_normalize_fallback_on_missing_strip_ansi(monkeypatch):
    """Fallback regex works when tools.ansi_strip is unavailable."""
    import sys
    import types

    m = types.ModuleType("tools")
    monkeypatch.setitem(sys.modules, "tools", m)

    from patterns import _normalize

    result = _normalize("\x1b[31mhello\x1b[0m world")
    assert result == "hello world"
