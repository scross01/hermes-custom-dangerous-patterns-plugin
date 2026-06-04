from __future__ import annotations

import re

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


def test_compile_block_patterns_skips_disabled():
    """Patterns with enabled: false are skipped."""
    from patterns import compile_block_patterns

    raw = [
        {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": False},
        {"pattern": r"\baws\b", "description": "AWS"},
    ]
    compiled = compile_block_patterns(raw)
    assert len(compiled) == 1
    assert compiled[0][1] == "AWS"


def test_compile_allow_patterns_skips_disabled():
    """Allow patterns with enabled: false are skipped."""
    from patterns import compile_allow_patterns

    raw = [
        {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": False},
        {"pattern": r"\baws\b", "description": "AWS"},
    ]
    compiled = compile_allow_patterns(raw)
    assert len(compiled) == 1
    assert compiled[0][1] == "AWS"


# ---------------------------------------------------------------------------
# compile_deny_patterns
# ---------------------------------------------------------------------------


def test_compile_deny_patterns_valid():
    """Valid deny patterns compile correctly."""
    from patterns import compile_deny_patterns

    raw = [{"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby exec"}]
    compiled = compile_deny_patterns(raw)
    assert len(compiled) == 1
    assert isinstance(compiled[0][0], re.Pattern)
    assert compiled[0][1] == "Ruby exec"


def test_compile_deny_patterns_skips_disabled():
    """Deny patterns with enabled: false are skipped."""
    from patterns import compile_deny_patterns

    raw = [
        {"pattern": r"\bdanger\b", "description": "Danger", "enabled": False},
        {"pattern": r"\bsafe\b", "description": "Safe"},
    ]
    compiled = compile_deny_patterns(raw)
    assert len(compiled) == 1
    assert compiled[0][1] == "Safe"


def test_compile_deny_patterns_skips_invalid():
    """Invalid deny regex is skipped."""
    from patterns import compile_deny_patterns

    raw = [
        {"pattern": "(unclosed", "description": "Bad"},
        {"pattern": r"\bsafe\b", "description": "Good"},
    ]
    compiled = compile_deny_patterns(raw)
    assert len(compiled) == 1


# ---------------------------------------------------------------------------
# is_deny_pattern
# ---------------------------------------------------------------------------


def test_is_deny_pattern_matches(reset_patterns_globals):
    """Matching command returns the deny pattern description."""
    from patterns import compile_all, is_deny_pattern

    config = {
        "deny_patterns": [
            {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby system exec"}
        ]
    }
    compile_all(config)
    result = is_deny_pattern("ruby -e 'system(\"rm -rf /\")'")
    assert result == "Ruby system exec"


def test_is_deny_pattern_no_match(reset_patterns_globals):
    """Non-matching command returns None."""
    from patterns import compile_all, is_deny_pattern

    config = {
        "deny_patterns": [
            {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby system exec"}
        ]
    }
    compile_all(config)
    result = is_deny_pattern("ruby -e 'puts \"hello\"'")
    assert result is None


def test_is_deny_pattern_no_patterns(reset_patterns_globals):
    """No deny patterns returns None."""
    from patterns import compile_all, is_deny_pattern

    compile_all({})
    assert is_deny_pattern("anything") is None


def test_get_deny_patterns_returns_copy(reset_patterns_globals):
    """get_deny_patterns returns a copy, not the internal list."""
    from patterns import compile_all, get_deny_patterns

    compile_all({
        "deny_patterns": [{"pattern": r"\bdanger\b", "description": "Danger"}]
    })
    patterns = get_deny_patterns()
    patterns.clear()
    assert len(get_deny_patterns()) == 1


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
    result = is_allow_pattern("vultr instance delete")
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


# ---------------------------------------------------------------------------
# glob_to_regex
# ---------------------------------------------------------------------------


def test_glob_to_regex_basic():
    """Simple two-word glob generates correct regex."""
    from patterns import glob_to_regex

    assert glob_to_regex("echo hello") == r"\becho\s+hello\b"


def test_glob_to_regex_wildcard_end():
    """Trailing * produces unbounded .*"""
    from patterns import glob_to_regex

    result = glob_to_regex("rm -rf /tmp/*")
    assert result == r"\brm\s+-rf\s+/tmp/.*"


def test_glob_to_regex_wildcard_both_ends():
    """Leading and trailing * → no word boundaries."""
    from patterns import glob_to_regex

    result = glob_to_regex("*danger*")
    assert result == r".*danger.*"


def test_glob_to_regex_mid_wildcard():
    """Wildcard in the middle of the pattern."""
    from patterns import glob_to_regex

    result = glob_to_regex("docker * rm")
    assert result == r"\bdocker\s+.*\s+rm\b"


def test_glob_to_regex_question_mark():
    """Question mark glob → single-char regex."""
    from patterns import glob_to_regex

    result = glob_to_regex("chmod 7??")
    assert result == r"\bchmod\s+7.."


def test_glob_to_regex_meta_chars():
    """Regex meta-chars in glob are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex(".hidden")
    assert result == r"\.hidden\b"


def test_glob_to_regex_pipes():
    """Pipe characters are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("*curl* | *sh*")
    assert result == r".*curl.*\s+\|\s+.*sh.*"


def test_glob_to_regex_parentheses():
    """Parentheses are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("python -c (.*)")
    assert result == r"\bpython\s+-c\s+\(\..*\)"


def test_glob_to_regex_empty():
    """Empty input returns empty string."""
    from patterns import glob_to_regex

    assert glob_to_regex("") == ""


def test_glob_to_regex_single_word():
    """Single word gets word boundaries."""
    from patterns import glob_to_regex

    assert glob_to_regex("echo") == r"\becho\b"


def test_glob_to_regex_whitespace_run():
    """Multiple spaces compress to single \\s+."""
    from patterns import glob_to_regex

    result = glob_to_regex("git    push   --force")
    assert result == r"\bgit\s+push\s+--force\b"


def test_glob_to_regex_leading_trailing_spaces():
    """Leading/trailing whitespace in input is ignored."""
    from patterns import glob_to_regex

    result = glob_to_regex("  echo hello  ")
    assert result == r"\becho\s+hello\b"


def test_glob_to_regex_numeric_boundary():
    """Numeric first/last char gets word boundary."""
    from patterns import glob_to_regex

    result = glob_to_regex("7z x")
    assert result == r"\b7z\s+x\b"


def test_glob_to_regex_brackets():
    """Square brackets are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("echo [hello]")
    assert result == r"\becho\s+\[hello\]"


def test_glob_to_regex_compiles_valid_regex():
    """Every glob_to_regex output must compile as valid regex."""
    from patterns import glob_to_regex

    test_cases = [
        "echo hello",
        "rm -rf /tmp/*",
        "*danger*",
        "docker * rm",
        "git push --force",
        "chmod 777",
        ".hidden",
        "*curl* | *sh*",
        "python -c (.*)",
        "echo",
        "npm install *",
        "apt-get purge *",
        "kill -9",
        "$HOME/test",
    ]
    for glob_in in test_cases:
        regex = glob_to_regex(glob_in)
        re.compile(regex, re.IGNORECASE | re.DOTALL)  # Must not raise


def test_glob_to_regex_matches_as_expected():
    """Generated regexes match the commands they should."""
    from patterns import glob_to_regex

    cases = [
        ("echo hello", "echo hello", True),
        ("echo hello", "  echo  hello  ", True),  # \s+ matches multiple spaces
        ("rm -rf /tmp/*", "rm -rf /tmp/foo", True),
        ("rm -rf /tmp/*", "rm -rf /var/foo", False),
        ("*danger*", "very danger ous", True),
        ("*danger*", "safe", False),
        ("docker * rm", "docker container rm", True),
        ("docker * rm", "docker compose up", False),
        ("git push --force", "git push --force origin main", True),
        ("git push --force", "git push origin main", False),
        (".hidden", ".hidden", True),
        (".hidden", "hidden", False),
        ("echo", "echo", True),
        ("echo", "echoooo", False),  # word boundary prevents partial match
    ]
    for glob_in, command, should_match in cases:
        regex = glob_to_regex(glob_in)
        compiled = re.compile(regex, re.IGNORECASE | re.DOTALL)
        result = bool(compiled.search(command))
        assert result == should_match, (
            f"glob={glob_in!r} → regex={regex!r} search={command!r} "
            f"expected={should_match} got={result}"
        )


def test_normalize_fallback_on_missing_strip_ansi(monkeypatch):
    """Fallback regex works when tools.ansi_strip is unavailable."""
    import sys
    import types

    m = types.ModuleType("tools")
    monkeypatch.setitem(sys.modules, "tools", m)

    from patterns import _normalize

    result = _normalize("\x1b[31mhello\x1b[0m world")
    assert result == "hello world"
