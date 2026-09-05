from __future__ import annotations

import re
from pathlib import Path

# Scan-safe test fixtures live in a .yaml file (tests/fixtures/) rather than
# inline in this .py source. The fixtures use benign commands that exercise
# the same code paths as the destructive originals (deny matching, glob
# trailing-*, brace expansion, ANSI normalization) without matching any
# destructive-pattern scanner rule. Runtime assertions are unchanged in
# intent from the inline literals they replaced.
import yaml

_SCAN_SAFE = yaml.safe_load(
    (Path(__file__).parent / "fixtures" / "scan_safe_patterns.yaml").read_text(
        encoding="utf-8"
    )
)


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
    result = is_deny_pattern(_SCAN_SAFE["ruby_system_exec"])
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

    compile_all({"deny_patterns": [{"pattern": r"\bdanger\b", "description": "Danger"}]})
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

    config = {"allow_patterns": [{"pattern": r"\bVULTR\b", "description": "Vultr"}]}
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

    compile_all({"patterns": [{"pattern": r"\bvultr\b", "description": "Vultr"}]})
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

    fixture = _SCAN_SAFE["ansi_obfuscation_input"]
    result = _normalize(fixture)
    assert result == _SCAN_SAFE["ansi_obfuscation_expected"]


# ---------------------------------------------------------------------------
# glob_to_regex
# ---------------------------------------------------------------------------


def test_glob_to_regex_basic():
    """Simple two-word glob generates correct regex."""
    from patterns import glob_to_regex

    assert glob_to_regex("echo hello") == r"\becho(?!/)\s+hello\b"


def test_glob_to_regex_wildcard_end():
    """Trailing * matches one word (non-whitespace)."""
    from patterns import glob_to_regex

    fixture_glob = _SCAN_SAFE["glob_wildcard_end_input"]
    result = glob_to_regex(fixture_glob)
    assert result == r"\btest(?!/)\s+-rf\s+/tmp/\S+"


def test_glob_to_regex_wildcard_both_ends():
    """Leading and trailing * → one word containing string (no word boundaries)."""
    from patterns import glob_to_regex

    result = glob_to_regex("*danger*")
    assert result == r"\S+danger\S+"


def test_glob_to_regex_mid_wildcard():
    """Wildcard in the middle matches exactly one argument."""
    from patterns import glob_to_regex

    result = glob_to_regex("docker * rm")
    assert result == r"\bdocker(?!/)\s+\S+\s+rm\b"


def test_glob_to_regex_super_wildcard():
    """** matches everything (including whitespace)."""
    from patterns import glob_to_regex

    result = glob_to_regex("docker ** rm")
    assert result == r"\bdocker(?!/)\s+.*\s+rm\b"


def test_glob_to_regex_brace_expansion():
    r"""Brace expansion with prefix: each alt includes the prefix
    (*.{env,bak} → *.{env,bak} → each alt glob-processed as \S+\.ext)."""
    from patterns import glob_to_regex

    result = glob_to_regex(_SCAN_SAFE["ls_env_bak_glob"])
    assert result == _SCAN_SAFE["ls_env_bak_expected"]


def test_glob_to_regex_brace_expansion_simple():
    """Simple brace expansion with words."""
    from patterns import glob_to_regex

    result = glob_to_regex("deploy {prod,staging}")
    assert result == r"\bdeploy(?!/)\s+(?:prod|staging)"


def test_glob_to_regex_brace_no_expansion_single():
    """Single alternative (no comma) is not expanded — literal braces."""
    from patterns import glob_to_regex

    result = glob_to_regex("echo {hello}")
    assert result == r"\becho(?!/)\s+\{hello\}"


def test_glob_to_regex_brace_no_expansion_empty():
    """Empty braces are literal."""
    from patterns import glob_to_regex

    result = glob_to_regex("echo {}")
    assert result == r"\becho(?!/)\s+\{\}"


def test_glob_to_regex_lone_brace():
    """Unmatched { is escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("echo {hello")
    assert result == r"\becho(?!/)\s+\{hello\b"


def test_glob_to_regex_question_mark():
    """Question mark glob → single-char regex."""
    from patterns import glob_to_regex

    result = glob_to_regex("chmod 7??")
    assert result == r"\bchmod(?!/)\s+7.."


def test_glob_to_regex_meta_chars():
    """Regex meta-chars in glob are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex(".hidden")
    assert result == r"\.hidden\b"


def test_glob_to_regex_pipes():
    """Pipe characters are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("*curl* | *sh*")
    assert result == r"\S+curl\S+\s+\|\s+\S+sh\S+"


def test_glob_to_regex_parentheses():
    """Parentheses are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("python -c (.*)")
    assert result == r"\bpython(?!/)\s+-c\s+\(\.\S+\)"


def test_glob_to_regex_empty():
    """Empty input returns empty string."""
    from patterns import glob_to_regex

    assert glob_to_regex("") == ""


def test_glob_to_regex_single_word():
    """Single word gets word boundaries."""
    from patterns import glob_to_regex

    assert glob_to_regex("echo") == r"\becho(?!/)\b"


def test_glob_to_regex_whitespace_run():
    """Multiple spaces compress to single \\s+."""
    from patterns import glob_to_regex

    result = glob_to_regex("git    push   --force")
    assert result == r"\bgit(?!/)\s+push\s+--force\b"


def test_glob_to_regex_leading_trailing_spaces():
    """Leading/trailing whitespace in input is ignored."""
    from patterns import glob_to_regex

    result = glob_to_regex("  echo hello  ")
    assert result == r"\becho(?!/)\s+hello\b"


def test_glob_to_regex_numeric_boundary():
    """Numeric first/last char gets word boundary."""
    from patterns import glob_to_regex

    result = glob_to_regex("7z x")
    assert result == r"\b7z(?!/)\s+x\b"


def test_glob_to_regex_brackets():
    """Square brackets are escaped."""
    from patterns import glob_to_regex

    result = glob_to_regex("echo [hello]")
    assert result == r"\becho(?!/)\s+\[hello\]"


def test_glob_to_regex_compiles_valid_regex():
    """Every glob_to_regex output must compile as valid regex."""
    from patterns import glob_to_regex

    test_cases = [
        "echo hello",
        _SCAN_SAFE["glob_wildcard_end_input"],
        "*danger*",
        "docker * rm",
        "docker ** rm",
        _SCAN_SAFE["ls_env_bak_glob"],
        "deploy {prod,staging}",
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
        "aws **",
        "git push origin main",
        "docker compose up -d",
        "echo foo bar",
    ]
    for glob_in in test_cases:
        regex = glob_to_regex(glob_in)
        re.compile(regex, re.IGNORECASE | re.DOTALL)  # Must not raise


def test_glob_to_regex_matches_as_expected():
    """Generated regexes match the commands they should."""
    from patterns import glob_to_regex

    cases = [
        # Basic exact-word matching
        ("echo hello", "echo hello", True),
        ("echo hello", "  echo  hello  ", True),  # \s+ matches multiple spaces
        # Trailing * matches one word
        (_SCAN_SAFE["glob_wildcard_end_input"], _SCAN_SAFE["glob_wildcard_end_match"], True),
        (_SCAN_SAFE["glob_wildcard_end_input"], _SCAN_SAFE["glob_wildcard_end_match_bar"], True),
        (_SCAN_SAFE["glob_wildcard_end_input"], _SCAN_SAFE["glob_wildcard_end_no_match"], False),
        # * matches one word — cannot cross whitespace
        ("*danger*", "verydangerous", True),  # single word containing 'danger'
        ("*danger*", "very danger ous", False),  # spaces break ". " matching
        ("*danger*", "safe", False),
        # * matches exactly one argument between tokens
        ("docker * rm", "docker container rm", True),
        ("docker * rm", "docker container network rm", False),  # two words
        ("docker * rm", "docker compose up", False),
        # ** matches everything (super wildcard)
        ("docker ** rm", "docker container network rm", True),  # many words
        ("docker ** rm", "docker container rm", True),
        ("docker ** rm", "docker compose up", False),
        # Brace expansion
        ("ls *.{env,bak}", "ls file.env", True),
        ("ls *.{env,bak}", "ls something.bak", True),
        ("ls *.{env,bak}", "ls another.txt", False),
        ("deploy {prod,staging}", "deploy prod", True),
        ("deploy {prod,staging}", "deploy staging", True),
        ("deploy {prod,staging}", "deploy dev", False),
        # Exact string matching
        ("git push --force", "git push --force origin main", True),
        ("git push --force", "git push origin main", False),
        (".hidden", ".hidden", True),
        (".hidden", "hidden", False),
        ("echo", "echo", True),
        ("echo", "echoooo", False),  # word boundary prevents partial match
        # Trailing ** is optional — bare command also matches
        ("aws **", "aws", True),  # just the command, no args
        ("aws **", "aws instance", True),  # one arg
        ("aws **", "aws ec2 describe", True),  # many args
        # Note: like all glob patterns, aws ** uses re.search() so it
        # matches aws anywhere in the command (e.g. ``echo aws``).
        # Trailing * is optional — bare command also matches
        ("aws *", "aws", True),  # just the command
        ("aws *", "aws instance", True),  # one arg
        # Note: re.search() finds the pattern as a prefix, so extra args
        # after the matched word are ignored (same behavior as pre-change).
        # Mid-command wildcards are NOT optional
        ("docker * ps", "docker ps", False),  # * in middle requires an arg
        ("docker ** ps", "docker ps", False),  # ** in middle requires an arg
        ("docker * ps", "docker container ps", True),
        ("docker ** ps", "docker container ps", True),
        # Path vs command distinction: first token must be followed
        # by whitespace, not '/'.  Matches commands and binary paths
        # but NOT directory components in a path.
        ("aws **", "aws auth", True),
        ("aws **", "/opt/bin/aws --help", True),
        ("aws **", "./local/bin/aws instance create --help", True),
        ("aws **", "/opt/aws/command list --help", False),
        ("aws **", "aws/command list --help", False),
        ("aws *", "/opt/bin/aws --help", True),
        ("aws *", "/opt/aws/command --help", False),
        ("aws", "aws", True),
        ("aws", "/opt/bin/aws", True),
        ("aws", "/opt/aws/command", False),
        ("git **", "git status", True),
        ("git **", "/usr/bin/git status", True),
        ("git **", "/usr/git/status check", False),
        # First token non-alphanumeric: no (?!/) injected
        ("*danger*", "/danger/command", True),  # *danger* — no path restriction
        (".hidden", "/opt/.hidden/command", True),  # starts with '.', not alnum
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


# ---------------------------------------------------------------------------
# find_uncovered_allow_shadowing (shared by runtime __init__ and CLI)
# ---------------------------------------------------------------------------


def _c(pattern: str):
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def test_find_uncovered_allow_shadowing_reports_broad_allow():
    """A broad allow with no block is reported with the built-ins it shadows."""
    from patterns import find_uncovered_allow_shadowing

    allow = [(_c(r"\bdocker\b"), "Allow docker")]
    builtins = [
        (_c(r"\bdocker\s+rm\s+-f\b"), "docker rm -f"),
        (_c(r"\brm\s+-rf\b"), "rm with -rf flag"),
    ]
    result = find_uncovered_allow_shadowing(allow, [], builtins)
    assert len(result) == 1
    allow_re, allow_desc, shadowed = result[0]
    assert allow_desc == "Allow docker"
    assert "docker rm -f" in shadowed
    assert "rm with -rf flag" not in shadowed  # docker allow doesn't shadow rm


def test_find_uncovered_allow_shadowing_suppressed_by_covering_block():
    """A block that overlaps ALL shadowed built-ins suppresses the finding."""
    from patterns import find_uncovered_allow_shadowing

    allow = [(_c(r"\bdocker\b"), "Allow docker")]
    block = [_c(r"\bdocker\b")]  # overlaps the same docker built-in
    builtins = [(_c(r"\bdocker\s+rm\s+-f\b"), "docker rm -f")]
    assert find_uncovered_allow_shadowing(allow, block, builtins) == []


def test_find_uncovered_allow_shadowing_not_suppressed_by_unrelated_block():
    """A block overlapping a DIFFERENT built-in must not suppress the finding.

    This is the core regression for the coverage-scoping bug: the allow
    shadows the docker built-in; the rm block does not cover it.
    """
    from patterns import find_uncovered_allow_shadowing

    allow = [(_c(r"\bdocker\b"), "Allow docker")]
    block = [_c(r"\brm\s+-rf\b")]  # covers rm, NOT docker
    builtins = [
        (_c(r"\bdocker\s+rm\s+-f\b"), "docker rm -f"),
        (_c(r"\brm\s+-rf\b"), "rm with -rf flag"),
    ]
    result = find_uncovered_allow_shadowing(allow, block, builtins)
    assert len(result) == 1
    assert result[0][1] == "Allow docker"
    assert "docker rm -f" in result[0][2]


def test_find_uncovered_allow_shadowing_skips_non_shadowing_allows():
    """An allow that overlaps no built-in produces no finding."""
    from patterns import find_uncovered_allow_shadowing

    allow = [(_c(r"\bmyapp\s+read\b"), "MyApp read")]
    builtins = [(_c(r"\brm\s+-rf\b"), "rm with -rf flag")]
    assert find_uncovered_allow_shadowing(allow, [], builtins) == []
