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
