"""custom-dangerous-patterns plugin -- inject user-defined patterns into
Hermes's built-in dangerous command approval system.

What it does:
  1. Reads ~/.hermes/custom-dangerous-patterns.yaml
  2. Compiles user-defined regex patterns
  3. Appends them to DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED
  4. Monkey-patches detect_dangerous_command() to check allow patterns first
  5. Monkey-patches check_all_command_guards() to intercept deny patterns

Result: custom patterns get the full once/session/always/deny approval
flow, with no custom approval logic needed.

Allow patterns are checked BEFORE block patterns. If a command matches
an allow pattern, it bypasses ALL detection (custom + built-in).

Deny patterns block commands immediately without an approval prompt.
They are checked AFTER allow patterns but BEFORE block patterns.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def register(ctx: Any) -> None:
    """Plugin entry point. Called by Hermes at startup."""
    from .config import load_config
    from .patterns import (
        compile_all,
        get_block_patterns,
        is_allow_pattern,
        is_deny_pattern,
    )

    # 1. Load and compile config
    config = load_config()
    compile_all(config)

    block_count = 0
    allow_count = 0
    deny_count = 0

    # 2. Inject block patterns into DANGEROUS_PATTERNS
    block_compiled = get_block_patterns()
    if block_compiled:
        from tools.approval import (
            DANGEROUS_PATTERNS,
            DANGEROUS_PATTERNS_COMPILED,
        )

        for regex_obj, desc in block_compiled:
            DANGEROUS_PATTERNS.append((regex_obj.pattern, desc))
            DANGEROUS_PATTERNS_COMPILED.append((regex_obj, desc))

        block_count = len(block_compiled)
        logger.info(
            "custom-dangerous-patterns: injected %d block patterns into "
            "DANGEROUS_PATTERNS",
            block_count,
        )

    # 3. Monkey-patch detect_dangerous_command for allow patterns
    allow_patterns = config.get("allow_patterns", [])
    if allow_patterns and any(p.get("enabled", True) for p in allow_patterns):
        _patch_detect_function(is_allow_pattern)
        allow_count = len([p for p in allow_patterns if p.get("enabled", True)])
        logger.info(
            "custom-dangerous-patterns: patched detect_dangerous_command with "
            "%d allow patterns",
            allow_count,
        )

    # 4. Monkey-patch check_all_command_guards for deny patterns
    deny_patterns = config.get("deny_patterns", [])
    if deny_patterns and any(p.get("enabled", True) for p in deny_patterns):
        # Pass allow checker so fallback path can compose allow-before-deny
        _patch_deny_handler(is_deny_pattern, is_allow_pattern)
        deny_count = len([p for p in deny_patterns if p.get("enabled", True)])
        logger.info(
            "custom-dangerous-patterns: patched check_all_command_guards with "
            "%d deny patterns",
            deny_count,
        )

    if not block_count and not allow_count and not deny_count:
        logger.info("custom-dangerous-patterns: no active patterns, plugin idle")
        return


# ---------------------------------------------------------------------------
# Monkey-patches
# ---------------------------------------------------------------------------


def _patch_detect_function(allow_checker) -> None:
    """Wrap detect_dangerous_command to skip commands matching allow patterns.

    This runs BEFORE check_all_command_guards(), so if we return
    (False, None, None) the entire approval flow is bypassed for
    allow-patterned commands.
    """
    from tools import approval

    _original = approval.detect_dangerous_command

    def _patched(command: str) -> tuple[bool, str | None, str | None]:
        # Check allow patterns first
        allow_match = allow_checker(command)
        if allow_match is not None:
            logger.debug(
                "custom-dangerous-patterns: command exempt via allow pattern "
                "(%s): %s",
                allow_match,
                command[:80],
            )
            return (False, None, None)

        # Fall through to original detection (our injected patterns are
        # already in DANGEROUS_PATTERNS_COMPILED at this point)
        return _original(command)

    _patched.__name__ = "detect_dangerous_command"
    _patched.__qualname__ = "detect_dangerous_command"
    approval.detect_dangerous_command = _patched


def _patch_deny_handler(deny_checker, allow_checker=None) -> None:
    """Wrap check_all_command_guards to block deny-pattern commands.

    Deny patterns are checked AFTER allow patterns (handled by
    _patch_detect_function) and BEFORE the approval prompt. When a deny
    pattern matches, we return a blocked result directly -- no prompt.

    Known limitation: deny patterns intercept BEFORE yolo/mode=off checks
    inside the original guard function, so --yolo does not bypass deny
    patterns. This is a structural limitation of patching at this level
    and can only be addressed by Hermes core integration (v0.5.0).

    If check_all_command_guards is not available, falls back to a combined
    detect_dangerous_command wrapper that checks allow before deny.
    """
    from tools import approval

    func_name = "check_all_command_guards"
    original = getattr(approval, func_name, None)

    if original is None:
        # Fallback: if check_all_command_guards doesn't exist, apply a
        # combined detect_dangerous_command wrapper with allow before deny.
        logger.warning(
            "custom-dangerous-patterns: %s not found in tools.approval -- "
            "deny patterns will show a prompt instead of blocking silently",
            func_name,
        )
        _patch_detect_function_for_deny(deny_checker, allow_checker)
        return

    def _patched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        # Extract command from positional or keyword args.
        command = args[0] if args else kwargs.get("command", "")

        # Check deny patterns before the original guard runs.
        deny_match = deny_checker(command)
        if deny_match is not None:
            logger.info(
                "custom-dangerous-patterns: command blocked by deny pattern "
                "(%s): %s",
                deny_match,
                command[:80],
            )
            return {
                "approved": False,
                "message": (
                    f"BLOCKED by deny pattern: {deny_match}\n\n"
                    f"[custom-dangerous-patterns] This command matches a "
                    f"deny-pattern rule and was blocked without a prompt. "
                    f"To permit this command, disable or remove the deny "
                    f"pattern in ~/.hermes/custom-dangerous-patterns.yaml."
                ),
                "pattern_keys": ["deny:" + deny_match],
            }

        return original(*args, **kwargs)

    _patched.__name__ = func_name
    _patched.__qualname__ = func_name
    setattr(approval, func_name, _patched)


def _patch_detect_function_for_deny(deny_checker, allow_checker=None) -> None:
    """Fallback: inject allow-then-deny check into detect_dangerous_command.

    Used when check_all_command_guards is not patchable. Creates a single
    combined wrapper that checks allow first, then deny, then original.
    This preserves allow-before-deny semantics even when both pattern
    types must share the same patch point.

    Deny matches return (True, "DENY: ...", command) so the prompt still
    appears but the deny reason is surfaced.
    """
    from tools import approval

    _original = approval.detect_dangerous_command

    def _patched(command: str) -> tuple[bool, str | None, str | None]:
        # Check allow patterns first (allow wins over deny)
        if allow_checker is not None:
            allow_match = allow_checker(command)
            if allow_match is not None:
                logger.debug(
                    "custom-dangerous-patterns: command exempt via allow "
                    "pattern (%s): %s",
                    allow_match,
                    command[:80],
                )
                return (False, None, None)

        # Then check deny patterns
        deny_match = deny_checker(command)
        if deny_match is not None:
            logger.info(
                "custom-dangerous-patterns: command blocked by deny pattern "
                "(%s): %s",
                deny_match,
                command[:80],
            )
            return (True, "DENY: " + deny_match, command)

        return _original(command)

    _patched.__name__ = "detect_dangerous_command"
    _patched.__qualname__ = "detect_dangerous_command"
    approval.detect_dangerous_command = _patched
