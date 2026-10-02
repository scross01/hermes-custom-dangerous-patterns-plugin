"""custom-dangerous-patterns plugin -- enforce user-defined patterns through
Hermes's public ``pre_tool_call`` hook.

What it does:
  1. Reads ~/.hermes/custom-dangerous-patterns.yaml
  2. Compiles user-defined regex patterns (block, deny)
  3. Registers ONE pre_tool_call hook that:
     - returns {"action": "block"}   for deny matches  (immediate, no prompt)
     - returns {"action": "approve"} for block matches (escalates to Hermes's
       own human approval gate, with a stable per-pattern rule_key)

Result: custom patterns get the full once/session/always/deny approval flow on
every surface (CLI, TUI, desktop, chat channels), rendered and persisted by
Hermes itself. The plugin implements no approval logic.

This plugin does NOT modify Hermes internals. It does not write to
DANGEROUS_PATTERNS / DANGEROUS_PATTERNS_COMPILED and does not rebind any
tools.approval function. Both are forbidden by the catalog guideline
("No runtime overrides of Hermes core"); note that Hermes's own admission lint
(`hermes plugins validate`) detects rebinding but NOT table writes, so passing
that lint is necessary but not sufficient. tests/test_core_surface.py is the
real guard.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

try:
    from .logfile import log_match
except ImportError:

    def log_match(*args: Any, **kwargs: Any) -> None:  # type: ignore[misc]
        pass


def register(ctx: Any) -> None:
    """Plugin entry point. Called by Hermes at startup."""
    from .config import (
        allow_pattern_retirement_notice,
        load_config,
        resolve_config_path,
    )
    from .patterns import (
        compile_all,
        find_block_match,
        find_deny_match,
        get_block_patterns,
        get_deny_patterns,
    )

    # 1. Load and compile config
    config = load_config()
    compile_all(config)

    # Allow patterns were retired: no supported Hermes surface can express
    # "do not apply a gate". Warn loudly (CRITICAL, not warning) so nobody
    # believes an exemption is still in force.
    notice = allow_pattern_retirement_notice(config, resolve_config_path())
    if notice:
        logger.critical("custom-dangerous-patterns: %s", notice)

    # Disclose block patterns that defer to the built-in gate. Without this the
    # deferral would be a silent enforcement change for anyone who grants
    # "always" on the resulting prompt.
    _warn_builtin_overlap()

    # Count what will ACTUALLY be enforced, i.e. what survived compile_all.
    # An invalid regex is skipped there with a WARNING, so counting config
    # entries would log "3 block patterns will request approval" for a config
    # where only 2 are live.
    block_count = len(get_block_patterns())
    deny_count = len(get_deny_patterns())

    # 2. Register the single enforcement hook.
    #
    #    Everything is enforced through this one public hook. The plugin does
    #    NOT write to Hermes's DANGEROUS_PATTERNS tables and does NOT rebind any
    #    tools.approval function -- both are forbidden by the catalog guideline,
    #    and the table writes are not even detected by `hermes plugins validate`,
    #    so a human reviewer is the only real check.
    #
    #    The hook is registered unconditionally so the manifest's provides_hooks
    #    declaration matches runtime registration (Hermes doctor warns when they
    #    disagree). With no patterns it returns None after two cheap checks.
    ctx.register_hook("pre_tool_call", _make_policy_hook(find_block_match, find_deny_match))

    if block_count:
        logger.info(
            "custom-dangerous-patterns: %d block patterns will request approval "
            "through Hermes's native approval gate",
            block_count,
        )
    if deny_count:
        logger.info(
            "custom-dangerous-patterns: %d deny patterns will block without a prompt",
            deny_count,
        )

    # 3. Register CLI subcommands
    _register_cli(ctx)

    if not block_count and not deny_count:
        logger.info("custom-dangerous-patterns: no active patterns, plugin idle")


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
# Enforcement hook
# ---------------------------------------------------------------------------


def _rule_key_for(pattern_str: str) -> str:
    """Stable per-pattern allowlist grain for the native approval gate.

    Hermes namespaces this as ``plugin_rule:<rule_key>`` and persists it to
    ``command_allowlist`` when the user chooses "always". Two traps make the
    derivation load-bearing:

    - Omitting ``rule_key`` entirely collapses EVERY custom rule on the
      ``terminal`` tool into ``plugin_rule:terminal`` (resolve_pre_tool_block
      passes ``details.rule_key or tool_name``), so one "always" would
      permanently allowlist all of them.
    - Deriving it from the description means editing a pattern's label in YAML
      silently resets the user's permanent approval, because
      ``request_tool_approval`` falls back to hashing the *description*.

    So: hash the regex, which is the rule's identity (already the dedup key in
    config._pattern_key). Stable across description edits, group renames,
    enable/disable toggles, and file moves in directory mode. A user who edits
    the regex is deliberately changing the rule and should re-approve, which
    matches Hermes's own pattern-description-keyed semantics.
    """
    digest = hashlib.sha256(pattern_str.encode("utf-8")).hexdigest()[:12]
    return f"cdp:{digest}"


def _log_match(
    command: str,
    match_type: str,
    description: str,
    regex: str,
    deferred: bool = False,
) -> None:
    """Log a pattern match to the dedicated log file.

    ``deferred`` marks a block match that was handed off to Hermes's built-in
    gate instead of escalating (see :func:`_make_policy_hook`). It is recorded
    because a deferred match is the only audit trail that a custom rule is not
    the thing gating the command.

    Wraps the module-level log_match (a no-op when logfile is unavailable) so a
    logging failure can never propagate into the hook: Hermes FAILS CLOSED on
    hook exceptions, so a raise here would block every terminal call, not just
    the one being matched. The blanket except is deliberate.
    """
    try:
        log_match(command, match_type, description, regex, deferred=deferred)
    except TypeError:
        # log_match predates the deferred keyword; fall back to the 4-arg form.
        try:
            log_match(command, match_type, description, regex)
        except Exception:
            logger.debug("custom-dangerous-patterns: match logging failed", exc_info=True)
    except Exception:
        logger.debug("custom-dangerous-patterns: match logging failed", exc_info=True)


def _make_policy_hook(block_checker, deny_checker):
    """Build the single pre_tool_call hook enforcing deny + block patterns.

    deny  -> {"action": "block",  ...}   immediate, no prompt, yolo cannot bypass
    block -> {"action": "approve", ...}  escalates to Hermes's native gate
    other -> None

    ``block_checker``/``deny_checker`` return ``(description, regex_source)`` for
    the first matching pattern, or None. Returning the regex source (not just
    the description) is required for the stable rule key above.

    Ordering is deny > block, matching the documented evaluation order. Deny
    patterns are checked first because they are unconditional and promptless.
    """

    def _hook(tool_name: str, args: dict, **kwargs) -> dict | None:
        if tool_name != "terminal":
            return None

        command = args.get("command", "")
        # A malformed arg must not raise: Hermes fails closed on hook
        # exceptions, so a crash here would block EVERY terminal call rather
        # than the one being matched.
        if not command or not isinstance(command, str):
            return None

        # 1. Deny first: immediate block, no prompt. Not bypassed by --yolo or
        #    approvals.mode: off, which is the documented point of a deny rule.
        deny_hit = deny_checker(command)
        if deny_hit is not None:
            desc, regex = deny_hit
            _log_match(command, "deny", desc, regex)
            return {
                "action": "block",
                "message": (
                    f"BLOCKED by deny pattern: {desc}\n\n"
                    f"[custom-dangerous-patterns] This command matches a "
                    f"deny-pattern rule and was blocked without a prompt. "
                    f"To permit this command, disable or remove the deny "
                    f"pattern in ~/.hermes/custom-dangerous-patterns.yaml."
                ),
            }

        # 2. Block patterns escalate to the native human approval gate.
        block_hit = block_checker(command)
        if block_hit is None:
            return None
        desc, regex = block_hit

        # Defer to Hermes's own gate when it would flag this command anyway.
        # check_all_command_guards presents custom+built-in findings as ONE
        # prompt; escalating separately would prompt twice, and "once" on the
        # first would not satisfy the second.
        from .patterns import builtin_overlaps

        if builtin_overlaps(command):
            _log_match(command, "block", desc, regex, deferred=True)
            return None

        _log_match(command, "block", desc, regex)
        return {
            "action": "approve",
            "message": (
                f"Command flagged as dangerous ({desc})\n\n"
                f"[custom-dangerous-patterns] This command matches a custom "
                f"block pattern. Approve once, allow for this session, or "
                f"allow permanently for this specific rule."
            ),
            "rule_key": _rule_key_for(regex),
        }

    return _hook


def _warn_builtin_overlap() -> None:
    """Warn about block patterns that will be enforced by the built-in gate.

    A block pattern that also matches a Hermes built-in pattern is DEFERRED to
    the built-in gate (see :func:`_make_policy_hook`), so only one prompt
    appears. The built-in description is shown instead of the custom one, and
    granting ``always`` on that prompt permanently allowlists the built-in key —
    which stops the custom rule firing for that command class.

    That trade is accepted to avoid double-prompting, but it must not be silent.
    Users already know how to read an allow-shadowing WARNING, so this uses the
    same shape and the same level.
    """
    from .patterns import builtin_overlap_report

    for description, builtin_desc in builtin_overlap_report():
        logger.warning(
            "custom-dangerous-patterns: BUILT-IN OVERLAP -- block pattern "
            "'%s' looks similar to Hermes's built-in '%s'. Commands matching "
            "both are enforced by the built-in gate, so the prompt shows the "
            "built-in description and granting `always` on it stops this custom "
            "rule firing for those commands. This is a similarity estimate, not "
            "a verdict: check a specific command with "
            "`custom-dangerous-patterns test '<command>'`, which asks Hermes "
            "directly. Narrow the pattern if you want your own description and "
            "an independent allowlist entry.",
            description,
            builtin_desc,
        )
