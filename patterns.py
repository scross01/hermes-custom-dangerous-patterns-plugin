"""Pattern compilation and allow-pattern matching.

Compiles raw config patterns into (compiled_regex, description) tuples
and provides the allow-pattern check used by the monkey-patch.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_RE_FLAGS = re.IGNORECASE | re.DOTALL

# Module-level compiled patterns, set once by compile_all().
_block_compiled: list[tuple[re.Pattern, str]] = []
_allow_compiled: list[tuple[re.Pattern, str]] = []
_deny_compiled: list[tuple[re.Pattern, str]] = []


def compile_block_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile block patterns from config into (compiled_regex, description).

    These get appended to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED.
    Invalid regexes are logged and skipped. Disabled patterns (enabled: false)
    are skipped without warning — they're intentionally paused.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid block regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


def compile_allow_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile allow patterns from config into (compiled_regex, description).

    These are checked BEFORE block patterns. A matching allow pattern
    exempts the command from ALL approval checks (block + built-in).
    Disabled patterns (enabled: false) are skipped.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid allow regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


def compile_deny_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile deny patterns from config into (compiled_regex, description).

    Deny patterns block commands immediately without an approval prompt.
    They are checked AFTER allow patterns but BEFORE block patterns.
    Disabled patterns (enabled: false) are skipped.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid deny regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


def compile_all(config: dict[str, Any]) -> None:
    """Compile all patterns from config and store in module globals.

    Call once during plugin registration.
    """
    global _block_compiled, _allow_compiled, _deny_compiled
    _block_compiled = compile_block_patterns(config.get("patterns", []))
    _allow_compiled = compile_allow_patterns(config.get("allow_patterns", []))
    _deny_compiled = compile_deny_patterns(config.get("deny_patterns", []))


def is_allow_pattern(command: str) -> str | None:
    """Check if a command matches any allow pattern.

    Uses the same normalization as approval.py's detection.

    Returns:
        The matching allow pattern's description if matched, or None.
    """
    if not _allow_compiled:
        return None

    # Normalize same way approval.py does: strip ANSI, null bytes, Unicode normalize
    cmd_normalized = _normalize(command)

    for allow_re, desc in _allow_compiled:
        if allow_re.search(cmd_normalized):
            return desc

    return None


def get_block_patterns() -> list[tuple[re.Pattern, str]]:
    """Return the compiled block patterns (for injection into DANGEROUS_PATTERNS)."""
    return list(_block_compiled)


def get_deny_patterns() -> list[tuple[re.Pattern, str]]:
    """Return the compiled deny patterns."""
    return list(_deny_compiled)


def is_deny_pattern(command: str) -> str | None:
    """Check if a command matches any deny pattern.

    Called BEFORE the approval prompt. Returns the matching deny pattern's
    description if matched, or None. Unlike block patterns, deny matches
    result in immediate blocking without a prompt.
    """
    if not _deny_compiled:
        return None

    cmd_normalized = _normalize(command)

    for deny_re, desc in _deny_compiled:
        if deny_re.search(cmd_normalized):
            return desc

    return None


def glob_to_regex(glob_str: str) -> str:
    """Convert a glob-style command pattern to a regex.

    Used by `add --interactive` and `add --glob` so users can type
    intuitive patterns like ``echo hello`` instead of raw regex like
    ``\\becho\\s+hello\\b``.

    Conversion rules:
        - Whitespace runs    → ``\\s+``
        - ``*``              → ``\\S+``  (one non-whitespace word)
        - ``**``             → ``.*``    (match anything, super wildcard)
        - ``?``              → ``.``     (match exactly one char)
        - ``{a,b}``          → ``(?:a|b)``  (brace expansion / alternation)
        - Regex meta-chars   → escaped
          (``.`` ``^`` ``$`` ``+`` ``[`` ``]`` ``\\`` ``|`` ``(`` ``)``)
        - Trailing ``*``/``**`` → both the preceding ``\\s+`` and the
          wildcard are wrapped in ``(?:...)?`` so the bare command also
          matches (e.g. ``aws **`` matches ``aws`` and ``aws instance``).
        - ``\\b`` at start if first token starts with alphanumeric
        - ``(?!/)`` after the first token if it starts with alphanumeric,
          preventing the command name from matching directory components
          (e.g. ``aws **`` matches ``/opt/bin/aws --help`` but not
          ``/opt/aws/command``).
        - ``\\b`` at end if last token ends with alphanumeric

    Brace expansion (``{a,b}``) creates regex alternation: ``{a,b}`` becomes
    ``(?:a|b)``. Each alternative is individually glob-processed. Requires
    at least two comma-separated values inside the braces. Nested braces are
    not supported.

    Args:
        glob_str: A glob-style pattern (e.g. ``"echo hello"``, ``"rm -rf /tmp/*"``).

    Returns:
        The equivalent regex pattern string.
    """
    # Tokenize: split on whitespace to preserve whitespace positions
    tokens = glob_str.split()
    if not tokens:
        return ""

    # { and } are handled specially (brace expansion) so they're not in this set
    _regex_meta = set(r".^$+[]\|()")

    def _process_token(token: str) -> str:
        """Convert a single glob token to its regex fragment.

        Brace expansion (``{a,b}``) is handled first: the prefix before
        ``{`` is shared by all alternatives (like shell brace expansion),
        so ``*.{env,bak}`` becomes ``(?:\\.env|\\.bak)`` where each
        alternative is ``\\.env`` / ``\\.bak`` — glob-processed as a
        complete unit including the prefix.
        """
        # Scan for a valid brace expansion group
        scan = 0
        brace_start = None
        brace_end = None
        while scan < len(token):
            if token[scan] == "{":
                end = token.find("}", scan + 1)
                if end != -1:
                    inner = token[scan + 1:end]
                    if inner:
                        alts = [a for a in inner.split(",") if a]
                        if len(alts) > 1:
                            brace_start = scan
                            brace_end = end
                            break
                    # Not a valid expansion — skip past and keep scanning
                    scan = end + 1
                    continue
                # No closing brace — rest is literal
                break
            elif token[scan] == "}":
                # Unmatched close brace — rest is literal
                break
            scan += 1

        if brace_start is not None:
            # Brace expansion: prefix + each alt is glob-processed as a unit
            prefix = token[:brace_start]
            inner = token[brace_start + 1:brace_end]
            alts = [a for a in inner.split(",") if a]
            alternatives = [
                _process_token(prefix + alt) for alt in alts
            ]
            processed = "|".join(alternatives)
            # Suffix (chars after closing })
            suffix = token[brace_end + 1:]
            if suffix:
                return "(?:" + processed + ")" + _process_token(suffix)
            return "(?:" + processed + ")"

        # Normal processing (no brace expansion)
        result: list[str] = []
        i = 0
        while i < len(token):
            ch = token[i]
            # ** super wildcard (match everything) — check before single *
            if ch == "*" and i + 1 < len(token) and token[i + 1] == "*":
                result.append(".*")
                i += 2
            # * single wildcard (match one non-whitespace word)
            elif ch == "*":
                result.append("\\S+")
                i += 1
            elif ch == "?":
                result.append(".")
                i += 1
            elif ch == "{":
                result.append("\\{")
                i += 1
            elif ch == "}":
                result.append("\\}")
                i += 1
            elif ch in _regex_meta:
                result.append("\\" + ch)
                i += 1
            else:
                result.append(ch)
                i += 1
        return "".join(result)

    # Build the regex body. When the last token is a standalone ``*`` or
    # ``**``, both the preceding ``\\s+`` separator and the wildcard itself
    # are wrapped in ``(?:...)?`` so the bare command (no arguments) also
    # matches.  Mid-command wildcards remain mandatory.
    if len(tokens) > 1 and tokens[-1] in ("*", "**"):
        prefix = r"\s+".join(_process_token(t) for t in tokens[:-1])
        last_re = _process_token(tokens[-1])
        regex_body = prefix + r"(?:\s+" + last_re + r")?"
    else:
        regex_body = r"\s+".join(_process_token(t) for t in tokens)

    # Add word boundaries only at positions that are alphanumeric.
    # Use tokens (not raw glob_str) so leading/trailing whitespace
    # and special chars like * or ? are handled correctly.
    if tokens and tokens[0] and tokens[0][0].isalnum():
        first_re = _process_token(tokens[0])
        # Insert (?!/) after the first token so the command name matches
        # when followed by whitespace but NOT by '/' — prevents matching
        # directory components like /opt/aws/command (vs /opt/bin/aws --help).
        regex_body = first_re + r"(?!/)" + regex_body[len(first_re):]
        regex_body = r"\b" + regex_body
    if tokens and tokens[-1] and tokens[-1][-1].isalnum():
        regex_body = regex_body + r"\b"

    return regex_body


def _normalize(command: str) -> str:
    """Normalize a command string for pattern matching.

    Mirrors approval.py._normalize_command_for_detection():
    strips ANSI escapes, null bytes, and normalizes Unicode.
    """
    try:
        from tools.ansi_strip import strip_ansi

        command = strip_ansi(command)
    except ImportError:
        # Fallback: strip common ANSI sequences
        command = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", command)

    command = command.replace("\x00", "")
    import unicodedata

    command = unicodedata.normalize("NFKC", command)
    return command
