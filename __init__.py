"""custom-dangerous-patterns plugin — inject user-defined patterns into
Hermes's built-in dangerous command approval system.

What it does:
  1. Reads ~/.hermes/custom-dangerous-patterns.yaml
  2. Compiles user-defined regex patterns
  3. Appends them to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED
  4. Monkey-patches detect_dangerous_command() to check allow patterns first

Result: custom patterns get the full once/session/always/deny approval
flow, with no custom approval logic needed.

Allow patterns are checked BEFORE block patterns. If a command matches
an allow pattern, it bypasses ALL detection (custom + built-in).
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Set after registration — used by the monkey-patched detect function.
_allow_patterns: list = []


def register(ctx: Any) -> None:
    """Plugin entry point. Called by Hermes at startup."""
    from .config import load_config
    from .patterns import compile_all, get_block_patterns, is_allow_pattern

    global _allow_patterns

    # ── 1. Load and compile config ──────────────────────────────────
    config = load_config()
    raw_block = config.get("patterns", [])
    raw_allow = config.get("allow_patterns", [])

    if not raw_block:
        logger.info("custom-dangerous-patterns: no patterns configured, plugin idle")
        return

    compile_all(config)

    # ── 2. Inject block patterns into DANGEROUS_PATTERNS ────────────
    from tools.approval import (
        DANGEROUS_PATTERNS,
        DANGEROUS_PATTERNS_COMPILED,
    )

    block_compiled = get_block_patterns()
    for regex_obj, desc in block_compiled:
        DANGEROUS_PATTERNS.append((regex_obj.pattern, desc))
        DANGEROUS_PATTERNS_COMPILED.append((regex_obj, desc))

    logger.info(
        "custom-dangerous-patterns: injected %d block patterns into DANGEROUS_PATTERNS",
        len(block_compiled),
    )

    # ── 3. Store allow patterns for the monkey-patch ────────────────
    _allow_patterns = list(config.get("allow_patterns", []))

    if _allow_patterns:
        # ── 4. Monkey-patch detect_dangerous_command ────────────────
        _patch_detect_function(is_allow_pattern)
        logger.info(
            "custom-dangerous-patterns: patched detect_dangerous_command with %d allow patterns",
            len(_allow_patterns),
        )


# ---------------------------------------------------------------------------
# Monkey-patch
# ---------------------------------------------------------------------------

def _patch_detect_function(allow_checker) -> None:
    """Wrap detect_dangerous_command to skip commands matching allow patterns.

    This runs BEFORE check_all_command_guards(), so if we return
    (False, None, None) the entire approval flow is bypassed for
    allow-patterned commands.
    """
    from tools import approval

    _original = approval.detect_dangerous_command

    def _patched(command: str) -> Tuple[bool, Optional[str], Optional[str]]:
        # Check allow patterns first
        allow_match = allow_checker(command)
        if allow_match is not None:
            logger.debug(
                "custom-dangerous-patterns: command exempt via allow pattern (%s): %s",
                allow_match, command[:80],
            )
            return (False, None, None)

        # Fall through to original detection (our injected patterns are
        # already in DANGEROUS_PATTERNS_COMPILED at this point)
        return _original(command)

    _patched.__name__ = "detect_dangerous_command"
    _patched.__qualname__ = "detect_dangerous_command"
    approval.detect_dangerous_command = _patched
