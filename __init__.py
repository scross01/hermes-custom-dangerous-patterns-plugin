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
import re
from typing import Any

logger = logging.getLogger(__name__)

try:
    from .logfile import log_match
except ImportError:
    def log_match(*args: Any, **kwargs: Any) -> None:  # type: ignore[misc]
        pass


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

        # Patch detect_dangerous_command to log block matches to the
        # dedicated log file, even when no allow patterns exist.
        # (When allow patterns ARE enabled, _patch_detect_function
        # already handles block logging.)
        allow_patterns = config.get("allow_patterns", [])
        if not (allow_patterns and any(p.get("enabled", True) for p in allow_patterns)):
            _patch_block_logging()

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
        # Check for allow patterns that shadow built-in dangerous patterns
        _check_allow_shadowing(config, is_allow_pattern)

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

        # 5. Register pre_tool_call hook to catch deny patterns BEFORE
        #    the terminal tool executes. This ensures the agent's blocked-
        #    tool handling kicks in (skip tool, return block message to LLM).
        #    Without this, deny patterns are checked inside the terminal
        #    tool and the agent treats the result as a regular error.
        ctx.register_hook("pre_tool_call", _make_deny_hook(is_deny_pattern, is_allow_pattern))

    # 6. Register CLI subcommands
    _register_cli(ctx)

    if not block_count and not allow_count and not deny_count:
        logger.info("custom-dangerous-patterns: no active patterns, plugin idle")
        return


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def _register_cli(ctx: Any) -> None:
    """Register ``hermes custom-dangerous-patterns`` CLI command.

    Produces ``hermes custom-dangerous-patterns <subcommand>`` with
    sub-subcommands: list, test, init, enable, disable, validate,
    info, logs, add, remove.

    The setup_fn (cli.register_cli) builds the argparse tree; each
    subcommand dispatches to its _handle_* adapter in cli.py.
    """
    try:
        from . import cli

        ctx.register_cli_command(
            name="custom-dangerous-patterns",
            help="Manage custom dangerous command patterns",
            setup_fn=cli.register_cli,
            handler_fn=None,
            description=(
                "Add, list, test, enable, disable, and remove custom "
                "dangerous command patterns that integrate with Hermes's "
                "built-in approval system."
            ),
        )
    except Exception:
        logger.warning(
            "custom-dangerous-patterns: failed to register CLI commands",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Monkey-patches
# ---------------------------------------------------------------------------


def _patch_block_logging() -> None:
    """Wrap detect_dangerous_command to log block matches to the dedicated log file.

    Runs regardless of whether allow patterns exist. Calls _log_block_matches()
    before falling through to the original detection.
    """
    from tools import approval

    _original = approval.detect_dangerous_command

    def _patched(command: str) -> tuple[bool, str | None, str | None]:
        _log_block_matches(command)
        return _original(command)

    _patched.__name__ = "detect_dangerous_command"
    _patched.__qualname__ = "detect_dangerous_command"
    approval.detect_dangerous_command = _patched


def _log_allow_match(command: str) -> None:
    """Find and log the matching allow pattern's info.

    Silently degrades (no-op) when the ``patterns`` module is not importable
    (e.g., in test environments without a package context).
    """
    try:
        from .patterns import _allow_compiled, _normalize
    except ImportError:
        return
    cmd_norm = _normalize(command)
    for allow_re, allow_desc in _allow_compiled:
        if allow_re.search(cmd_norm):
            log_match(command, "allow", allow_desc, allow_re.pattern)
            return


def _log_block_matches(command: str) -> None:
    """Log all matching block pattern's info.

    These are logged BEFORE the approval prompt, so the user's selection
    (once/session/always/deny) is not yet known. Capturing the selection
    would require monkey-patching Hermes's internal prompt handler
    (e.g. ``approval.perform_approval``), which is fragile and version-
    dependent — the user request indicated "if possible", acknowledging
    this limitation.

    Silently degrades (no-op) when the ``patterns`` module is not importable.
    """
    try:
        from .patterns import _block_compiled, _normalize
    except ImportError:
        return
    cmd_norm = _normalize(command)
    for block_re, block_desc in _block_compiled:
        if block_re.search(cmd_norm):
            log_match(command, "block", block_desc, block_re.pattern)


def _log_deny_match(command: str) -> None:
    """Find and log the matching deny pattern's info.

    Silently degrades (no-op) when the ``patterns`` module is not importable.
    """
    try:
        from .patterns import _deny_compiled, _normalize
    except ImportError:
        return
    cmd_norm = _normalize(command)
    for deny_re, deny_desc in _deny_compiled:
        if deny_re.search(cmd_norm):
            log_match(command, "deny", deny_desc, deny_re.pattern)
            return


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
            # Log the allow match with pattern details
            _log_allow_match(command)
            logger.debug(
                "custom-dangerous-patterns: command exempt via allow pattern "
                "(%s): %s",
                allow_match,
                command[:80],
            )
            return (False, None, None)

        # Log block pattern matches before falling through to original
        # (the original will also find them in DANGEROUS_PATTERNS_COMPILED
        # and trigger the approval prompt)
        _log_block_matches(command)

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
            # Log the deny match with pattern details
            _log_deny_match(command)
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

    # Also patch the local alias in terminal_tool.py which imports
    # check_all_command_guards as _check_all_guards_impl at module level.
    # Without this, terminal_tool calls the original (unpatched) function.
    try:
        from tools import terminal_tool as _tt
        if hasattr(_tt, "_check_all_guards_impl"):
            _tt._check_all_guards_impl = _patched
            logger.info(
                "custom-dangerous-patterns: also patched "
                "terminal_tool._check_all_guards_impl"
            )
    except ImportError:
        pass


def _make_deny_hook(deny_checker, allow_checker=None):
    """Create a pre_tool_call hook that blocks deny-pattern commands.

    This hook fires BEFORE the terminal tool executes, so the agent's
    blocked-tool handling kicks in (skip execution, return block message
    to LLM). Without this, deny patterns are checked inside the terminal
    tool and the agent treats the result as a regular error.
    """

    def _hook(tool_name: str, args: dict, **kwargs) -> dict | None:
        if tool_name != "terminal":
            return None

        command = args.get("command", "")
        if not command:
            return None

        # Check allow patterns first — allow wins over deny
        if allow_checker is not None:
            allow_match = allow_checker(command)
            if allow_match is not None:
                return None

        # Check deny patterns
        deny_match = deny_checker(command)
        if deny_match is not None:
            # Log the deny match with pattern details
            _log_deny_match(command)
            return {
                "action": "block",
                "message": (
                    f"BLOCKED by deny pattern: {deny_match}\n\n"
                    f"[custom-dangerous-patterns] This command matches a "
                    f"deny-pattern rule and was blocked without a prompt. "
                    f"To permit this command, disable or remove the deny "
                    f"pattern in ~/.hermes/custom-dangerous-patterns.yaml."
                ),
            }

        return None

    return _hook


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
            # Log the deny match with pattern details
            _log_deny_match(command)
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


# ---------------------------------------------------------------------------
# Allow shadowing check (v0.2.0)
# ---------------------------------------------------------------------------


def _check_allow_shadowing(config: dict, is_allow_pattern) -> None:
    """Warn when allow patterns could bypass built-in dangerous patterns.

    For each enabled allow pattern, checks if it matches any built-in
    DANGEROUS_PATTERNS entry without a corresponding custom block pattern.
    Logs a WARNING explaining the built-in bypass risk.
    """
    import re

    from tools.approval import DANGEROUS_PATTERNS_COMPILED

    from .patterns import compile_allow_patterns

    allow_compiled = compile_allow_patterns(config.get("allow_patterns", []))
    block_raw = config.get("patterns", [])
    block_enabled = [p for p in block_raw if p.get("enabled", True)]

    for allow_re, allow_desc in allow_compiled:
        # Check if this allow pattern matches any built-in dangerous pattern
        shadowed = []
        for builtin_re, builtin_desc in DANGEROUS_PATTERNS_COMPILED:
            if _patterns_overlap(allow_re, builtin_re):
                shadowed.append(builtin_desc)

        if shadowed:
            # Check if a custom block pattern would also match these commands
            covered = False
            for entry in block_enabled:
                try:
                    block_re = re.compile(
                        entry["pattern"], re.IGNORECASE | re.DOTALL
                    )
                    if all(
                        _patterns_overlap(block_re, builtin_re)
                        for builtin_re, _ in DANGEROUS_PATTERNS_COMPILED
                        if _patterns_overlap(allow_re, builtin_re)
                    ):
                        covered = True
                        break
                except re.error:
                    pass

            if not covered:
                logger.warning(
                    "custom-dangerous-patterns: ALLOW SHADOWING -- allow "
                    "pattern '%s' (%s) may bypass built-in dangerous "
                    "patterns: %s. Consider adding a corresponding custom "
                    "block pattern to scope the exemption.",
                    allow_re.pattern,
                    allow_desc,
                    ", ".join(shadowed[:3])
                    + ("..." if len(shadowed) > 3 else ""),
                )


def _patterns_overlap(re1: re.Pattern, re2: re.Pattern) -> bool:
    """Check if two compiled regex patterns can match overlapping strings.

    A simple heuristic: if the patterns share word-like tokens of length
    >= 3, they likely overlap. Broad patterns like '.*' shadow everything.
    Not perfect, but catches the most dangerous cases.
    """
    p1, p2 = re1.pattern, re2.pattern
    # Broad patterns shadow everything
    if p1 in (".*", ".+", "^.*$"):
        return True
    # Check token overlap
    tokens1 = set(_extract_tokens(p1))
    tokens2 = set(_extract_tokens(p2))
    return bool(tokens1 & tokens2)


def _extract_tokens(pattern: str) -> list[str]:
    """Extract word-like tokens from a regex pattern for overlap check."""
    # Remove word-boundary markers (e.g., \baws -> aws)
    cleaned = re.sub(r"\\b", " ", pattern)
    # Remove other regex metacharacters
    cleaned = re.sub(r"[\\*+?.^$()\[\]{}|]", " ", cleaned)
    return [t for t in cleaned.split() if len(t) >= 3]
