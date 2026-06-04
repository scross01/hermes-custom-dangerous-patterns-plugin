"""CLI command handlers for hermes custom-patterns (v0.3.0).

Pure config management and introspection — no monkey-patching, no Hermes
runtime dependencies. Each command handler is a standalone function that
operates on config dicts and returns (output: str, exit_code: int).

The register_subcommands() function is the entry point called by
ctx.register_cli_command() in __init__.py.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# CLI registration entry point
# ---------------------------------------------------------------------------


def register_subcommands(command_group: Any) -> None:
    """Register all custom-patterns subcommands on the command group.

    Called by ctx.register_cli_command() in __init__.py. The command_group
    object provides add_command() or similar for registering subcommands.
    We provide adapter functions that bridge between the command group's
    argument parsing and our stateless handler functions.
    """
    # Each command is registered with a handler that parses args and
    # calls the corresponding cmd_* function, then prints output and
    # exits with the appropriate code.

    _register(command_group, "list", _handle_list, help="List custom patterns")
    _register(command_group, "test", _handle_test, help="Test a command against patterns")
    _register(command_group, "init", _handle_init, help="Create a starter config")
    _register(command_group, "enable", _handle_enable, help="Enable patterns")
    _register(command_group, "disable", _handle_disable, help="Disable patterns")
    _register(command_group, "validate", _handle_validate, help="Validate config syntax")
    _register(command_group, "info", _handle_info, help="Show plugin state dashboard")
    _register(command_group, "logs", _handle_logs, help="Show plugin log entries")
    _register(command_group, "add", _handle_add, help="Add a custom pattern")
    _register(command_group, "remove", _handle_remove, help="Remove a custom pattern")


def _register(group: Any, name: str, handler: Callable, help: str) -> None:
    """Register a subcommand on the command group.

    Uses add_command() if available (argparse-like), otherwise falls back
    to setattr for compatibility with different Hermes CLI backends.
    """
    add_cmd = getattr(group, "add_command", None)
    if callable(add_cmd):
        add_cmd(name, handler, help=help)
    else:
        setattr(group, name, handler)


# ---------------------------------------------------------------------------
# Command handlers — each returns (output: str, exit_code: int)
# ---------------------------------------------------------------------------


def cmd_list(
    pattern_type: str | None = None,
    group: str | None = None,
    search: str | None = None,
    disabled: bool = False,
    enabled: bool = False,
    builtins: bool = False,
) -> tuple[str, int]:
    """List all user-defined patterns with their type, status, and description."""
    from .config import load_config, resolve_config_path

    config_path = resolve_config_path()
    config = load_config(force=True, integrity_check=False)

    if not config_path.exists():
        return (
            f"No config found at {config_path}.\n"
            f"Run `hermes custom-patterns init` to create a starter config.\n",
            0,
        )

    lines: list[str] = []
    sections: list[tuple[str, str, list[dict[str, Any]]]] = [
        ("BLOCK", "patterns", config.get("patterns", [])),
        ("ALLOW", "allow_patterns", config.get("allow_patterns", [])),
        ("DENY", "deny_patterns", config.get("deny_patterns", [])),
    ]

    # Flat index across all types
    flat_index = 0
    total_shown = 0

    for section_label, _config_key, entries in sections:
        # Apply filters
        filtered = list(entries)
        if pattern_type and pattern_type.upper() != section_label:
            continue
        if disabled:
            filtered = [e for e in filtered if not e.get("enabled", True)]
        elif enabled:
            filtered = [e for e in filtered if e.get("enabled", True)]
        if group:
            filtered = [e for e in filtered if e.get("group", "") == group]
        if search:
            term = search.lower()
            filtered = [
                e
                for e in filtered
                if term in e.get("description", "").lower()
                or term in e.get("pattern", "").lower()
            ]

        if not filtered:
            continue

        # Count active/disabled
        active_count = sum(1 for e in filtered if e.get("enabled", True))
        disabled_count = len(filtered) - active_count

        parts = [f"{section_label} patterns"]
        if active_count and disabled_count:
            parts.append(f"({active_count} active, {disabled_count} disabled):")
        elif active_count:
            parts.append(f"({active_count} active):")
        else:
            parts.append(f"({disabled_count} disabled):")

        lines.append(" ".join(parts))

        for entry in filtered:
            flat_index += 1
            is_enabled = entry.get("enabled", True)
            status = "\u2713" if is_enabled else "\u2717"  # ✓ or ✗
            desc = entry.get("description", entry.get("pattern", ""))
            grp = entry.get("group", "")
            grp_str = f"  group: {grp}" if grp else ""
            lines.append(f"  [{flat_index}] {status} {desc}{grp_str}")
            total_shown += 1

        lines.append("")

    has_any_patterns = any(
        config.get(key) for key in ("patterns", "allow_patterns", "deny_patterns")
    )
    if total_shown == 0:
        if has_any_patterns and (pattern_type or group or search or disabled or enabled):
            lines.append("No patterns match your filters.\n")
        else:
            lines.append(
                "No custom patterns defined. "
                "Edit your config file or use `hermes custom-patterns add`.\n"
            )

    # Config path display
    if config_path.is_dir():
        yaml_files = sorted(config_path.glob("*.yaml"))
        path_display = f"{config_path} ({len(yaml_files)} files)"
    else:
        path_display = str(config_path)
    lines.append(f"Config: {path_display}")

    # Built-in patterns
    if builtins:
        lines.append("")
        lines.extend(_format_builtins(search_term=search))

    return ("\n".join(lines) + "\n", 0)


def cmd_test(
    command: str,
    verbose: bool = False,
    skip_builtins: bool = False,
) -> tuple[str, int]:
    """Test a command against all pattern types and show the result.

    Simulates the exact evaluation order used at runtime:
      1. Deny patterns (block immediately, no prompt)
      2. Allow patterns (exempt from all checks)
      3. Block patterns (trigger approval prompt)
      4. Built-in patterns (alongside block patterns)
    """
    from .config import load_config
    from .patterns import compile_all, get_block_patterns, is_allow_pattern, is_deny_pattern

    if not command or not command.strip():
        return ("Error: command must not be empty.\n", 1)

    config = load_config(force=True, integrity_check=False)
    compile_all(config)

    lines: list[str] = []
    lines.append(f"Evaluating: {command}")
    lines.append("")

    # Step 1: Deny patterns
    deny_match = is_deny_pattern(command)
    lines.append("DENY patterns — checked first, block immediately:")
    if deny_match:
        lines.append(f"  \u2713 MATCH: {deny_match}")
    else:
        lines.append("  (no matches)")
    lines.append("")

    # Step 2: Allow patterns
    allow_match = is_allow_pattern(command)
    lines.append("ALLOW patterns — checked second, exempt from all checks:")
    if allow_match:
        lines.append(f"  \u2713 MATCH: {allow_match}")
    else:
        lines.append("  (no matches)")
    lines.append("")

    # Step 3: Block patterns (only if no deny match)
    block_matches: list[tuple[str, str]] = []
    if deny_match is None:
        lines.append("BLOCK patterns — checked third, trigger approval prompt:")
        for regex_obj, desc in get_block_patterns():
            cmd_normalized = _normalize_for_test(command)
            if regex_obj.search(cmd_normalized):
                block_matches.append((regex_obj.pattern, desc))
        if block_matches:
            for pattern_str, desc in block_matches:
                lines.append(f"  \u2713 MATCH: {desc}")
                if verbose:
                    lines.append(f"    Pattern: {pattern_str}")
        else:
            lines.append("  (no matches)")
    else:
        lines.append("BLOCK patterns — skipped (deny pattern already matched)")
    lines.append("")

    # Step 4: Built-in patterns
    if not skip_builtins:
        lines.append("BUILT-IN patterns — checked alongside block patterns:")
        builtin_matches = _check_builtins_for_test(command, verbose)
        if builtin_matches:
            for bm in builtin_matches:
                lines.append(f"  \u2713 MATCH: {bm}")
        else:
            lines.append("  (no matches)")
        lines.append("")

    # Determine result
    if deny_match is not None:
        lines.append("RESULT: DENY — command BLOCKED immediately, no prompt")
    elif allow_match is not None:
        lines.append("RESULT: ALLOW — command runs immediately, no prompt")
        if block_matches:
            lines.append("(Block patterns skipped — allow wins over block)")
    elif block_matches or (not skip_builtins and _check_builtins_for_test(command, False)):
        lines.append(
            "RESULT: APPROVAL PROMPT — user will see "
            "[o]nce/[s]ession/[a]lways/[d]eny"
        )
    else:
        lines.append(
            "RESULT: PASS — no patterns matched. "
            "Command would run normally without any approval prompt."
        )

    return ("\n".join(lines) + "\n", 0)


def _normalize_for_test(command: str) -> str:
    """Normalize a command string for pattern matching in the test command.

    Mirrors the normalization in patterns._normalize but works standalone.
    """
    import re as _re
    import unicodedata

    cmd = command
    try:
        from tools.ansi_strip import strip_ansi
        cmd = strip_ansi(cmd)
    except ImportError:
        cmd = _re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", cmd)

    cmd = cmd.replace("\x00", "")
    cmd = unicodedata.normalize("NFKC", cmd)
    return cmd


def _check_builtins_for_test(
    command: str,
    verbose: bool,
) -> list[str]:
    """Check if the command matches any built-in patterns."""
    import re as _re

    cmd = _normalize_for_test(command)
    matches: list[str] = []
    for pat, desc in _BUILTIN_PATTERNS:
        try:
            if _re.search(pat, cmd, _re.IGNORECASE | _re.DOTALL):
                if verbose:
                    matches.append(f"{desc} (pattern: {pat})")
                else:
                    matches.append(desc)
        except _re.error:
            pass
    return matches


def cmd_init(
    with_examples: bool = False,
    force: bool = False,
) -> tuple[str, int]:
    """Create a starter config file and guide the user.

    All example patterns are DISABLED by default — the user must
    review and enable the ones they want. Use --with-examples for
    a fully-enabled demonstration config.
    """
    from .config import resolve_config_path, save_config

    config_path = resolve_config_path()

    # Check if config already exists
    if config_path.exists():
        if not force:
            return (
                f"Config already exists at {config_path}.\n"
                f"Use --force to overwrite.\n",
                1,
            )

    # Load the example config template
    if with_examples:
        config_dict = _load_example_config(enabled=True)
    else:
        config_dict = _build_minimal_starter_config()

    # Count patterns for the output message
    block_count = len(config_dict.get("patterns", []))
    allow_count = len(config_dict.get("allow_patterns", []))
    deny_count = len(config_dict.get("deny_patterns", []))

    save_config(config_dict, config_path)

    lines = [
        f"Created: {config_path} ({block_count} block, {allow_count} allow, "
        f"{deny_count} deny patterns — all disabled)",
        "",
        "Next steps:",
        "  1. Review the config: hermes custom-patterns list --disabled",
        "  2. Enable patterns you want: hermes custom-patterns enable --group cloud",
        '  3. Test your patterns: hermes custom-patterns test "vultr instance delete"',
        "  4. Restart Hermes for changes to take effect",
    ]
    return ("\n".join(lines) + "\n", 0)


def _build_minimal_starter_config() -> dict[str, Any]:
    """Build a minimal starter config with [TEST] patterns only."""
    return {
        "patterns": [
            {
                "pattern": r"\becho\s+.*danger\b",
                "description": "[TEST] Echo with danger text",
                "enabled": False,
                "group": "testing",
            },
            {
                "pattern": r"\bping\s+-c\s+\d+\s+\d+\.\d+\.\d+\.\d+\b",
                "description": "[TEST] Excessive ping to IP",
                "enabled": False,
                "group": "testing",
            },
            {
                "pattern": r"\bsleep\s+\d{3,}\b",
                "description": "[TEST] Long sleep command",
                "enabled": False,
                "group": "testing",
            },
            {
                "pattern": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*)\s+/tmp/",
                "description": "[TEST] Scoped rm in /tmp",
                "enabled": False,
                "group": "testing",
            },
        ],
        "allow_patterns": [],
        "deny_patterns": [
            {
                "pattern": r"\bgit\s+push\s+--force\b",
                "description": "[TEST] Force git push",
                "enabled": False,
                "group": "testing",
            },
        ],
    }


def _load_example_config(enabled: bool = True) -> dict[str, Any]:
    """Load the example config from the plugin's examples directory.

    Tries to load from the installed plugin path first, then falls back
    to the built-in minimal config.
    """
    # Try the shipped examples file
    example_paths = [
        Path(__file__).resolve().parent / "examples" / "custom-dangerous-patterns.yaml",
        Path.home() / ".hermes" / "plugins" / "custom-dangerous-patterns"
        / "examples" / "custom-dangerous-patterns.yaml",
    ]

    for example_path in example_paths:
        if example_path.is_file():
            try:
                from .config import _load_single_yaml

                raw = _load_single_yaml(example_path)
                if raw:
                    from .config import _validate_config

                    config = _validate_config(raw)
                    # Set enabled/disabled based on flag
                    if not enabled:
                        for section in ("patterns", "allow_patterns", "deny_patterns"):
                            for entry in config.get(section, []):
                                entry["enabled"] = False
                    return config
            except Exception:
                pass

    # Fallback: minimal starter config
    return _build_minimal_starter_config()


def cmd_enable(
    target: str | None = None,
    pattern_type: str | None = None,
    group: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Enable patterns by index, description, or group."""
    return _toggle_patterns(enable=True, target=target, pattern_type=pattern_type,
                            group=group, dry_run=dry_run)


def cmd_disable(
    target: str | None = None,
    pattern_type: str | None = None,
    group: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Disable patterns by index, description, or group."""
    return _toggle_patterns(enable=False, target=target, pattern_type=pattern_type,
                            group=group, dry_run=dry_run)


def _toggle_patterns(
    enable: bool,
    target: str | None,
    pattern_type: str | None,
    group: str | None,
    dry_run: bool,
) -> tuple[str, int]:
    """Shared implementation for enable/disable commands."""
    from .config import load_config, resolve_config_path, save_config

    config_path = resolve_config_path()
    if not config_path.exists():
        return (
            f"No config found at {config_path}.\n"
            f"Run `hermes custom-patterns init` to create a starter config.\n",
            1,
        )

    config = load_config(force=True, integrity_check=False)
    action = "enabled" if enable else "disabled"
    new_state = True if enable else False

    # Build flat list of all patterns (add _section to originals so
    # modifications below affect the real config dict entries)
    all_entries: list[dict[str, Any]] = []
    for section_key in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in config.get(section_key, []):
            entry["_section"] = section_key
            all_entries.append(entry)

    if not all_entries:
        return ("No custom patterns defined. Nothing to change.\n", 1)

    # Find matching patterns
    matched: list[dict[str, Any]] = []

    if group:
        # Match by group
        matched = [e for e in all_entries if e.get("group", "") == group]
        if not matched:
            return (f"No patterns found in group '{group}'.\n", 1)
    elif target is not None:
        # Try index first
        try:
            idx = int(target)
            if 1 <= idx <= len(all_entries):
                matched = [all_entries[idx - 1]]
        except ValueError:
            pass

        # Fall back to description substring match
        if not matched:
            matched = [
                e for e in all_entries
                if target.lower() in e.get("description", "").lower()
            ]
            if pattern_type:
                type_map = {"block": "patterns", "allow": "allow_patterns", "deny": "deny_patterns"}
                section = type_map.get(pattern_type.lower(), "")
                matched = [e for e in matched if e["_section"] == section]

            if len(matched) > 1:
                lines = [f"Multiple patterns match '{target}'. Use index or be more specific:"]
                for i, e in enumerate(all_entries):
                    if e in matched:
                        type_label = e["_section"].replace("_patterns", "").upper()
                        lines.append(f"  [{i + 1}] {type_label}: {e['description']}")
                return ("\n".join(lines) + "\n", 1)

        if not matched:
            return (f"No patterns matched '{target}'.\n", 1)
    else:
        return ("Must specify a pattern index, description, or --group.\n", 1)

    # Check for protected patterns
    protected = [e for e in matched if e.get("protected")]
    if protected and not enable:
        names = ", ".join(f'"{e["description"]}"' for e in protected)
        return (
            f"Cannot disable protected patterns: {names}.\n"
            f"Edit the config file directly to modify protected patterns.\n",
            1,
        )

    # Check if already in desired state
    already = [e for e in matched if e.get("enabled", True) == new_state]
    if already and not dry_run:
        names = ", ".join(f'[{get_index(e, all_entries)}] "{e["description"]}"' for e in already)
        return (f"Pattern(s) already {action}: {names}\n", 0)

    if dry_run:
        lines = [f"Would {action} the following patterns:"]
        for e in matched:
            lines.append(f"  [{get_index(e, all_entries)}] {e['description']}")
        return ("\n".join(lines) + "\n", 0)

    # Apply the toggle
    changed = []
    for entry in matched:
        entry["enabled"] = new_state
        changed.append(entry)

    # Clean up _section marker before saving
    for entry in all_entries:
        entry.pop("_section", None)

    save_config(config, config_path)

    lines = [f"{action.capitalize()} {len(changed)} pattern(s):"]
    for e in changed:
        lines.append(f"  [{get_index(e, all_entries)}] {e['description']}")
    lines.append("")
    lines.append(_config_update_reminder().strip())
    return ("\n".join(lines) + "\n", 0)


def cmd_validate(
    path: str | None = None,
    quiet: bool = False,
) -> tuple[str, int]:
    """Validate config syntax and regexes."""
    from .config import _load_yaml, _validate_config, resolve_config_path

    if path:
        config_path = Path(path)
    else:
        config_path = resolve_config_path()

    warnings: list[str] = []

    # Check file exists
    if not config_path.exists():
        if quiet:
            return ("", 2)
        return (f"\u2717 Config not found: {config_path}\n\nResult: INVALID — file not found\n", 2)

    # Load YAML
    raw = _load_yaml(config_path)
    if raw is None:
        if quiet:
            return ("", 1)
        return (
            f"\u2717 Config: {config_path}\n"
            f"\u2717 YAML syntax: invalid — cannot parse file\n\n"
            f"Result: INVALID — fix the YAML syntax above before restarting Hermes\n",
            1,
        )

    # Validate
    validated = _validate_config(raw)

    lines: list[str] = []
    lines.append(f"\u2713 Config: {config_path}")
    lines.append("\u2713 YAML syntax: valid")
    lines.append("\u2713 Schema: valid")

    block_count = len(validated.get("patterns", []))
    allow_count = len(validated.get("allow_patterns", []))
    deny_count = len(validated.get("deny_patterns", []))

    # Check for regex warnings
    for section_key, section_label in [
        ("patterns", "block"),
        ("allow_patterns", "allow"),
        ("deny_patterns", "deny"),
    ]:
        for i, entry in enumerate(validated.get(section_key, [])):
            pat = entry.get("pattern", "")
            if pat in (".*", ".+", "^.*$"):
                warnings.append(
                    f"  \u26a0 {section_label}[{i}] regex warning: "
                    f"pattern '{pat}' matches everything"
                )

    if warnings:
        lines.extend(warnings)

    lines.append(
        f"\u2713 All regexes compile successfully "
        f"(patterns: {block_count} block, {allow_count} allow, {deny_count} deny)"
    )
    lines.append("")
    lines.append("Result: VALID")

    if quiet:
        return ("", 0)
    return ("\n".join(lines) + "\n", 0)


def cmd_info() -> tuple[str, int]:
    """Show plugin configuration dashboard."""
    from .config import (
        _load_hash_data,
        _resolve_hash_path,
        get_config_path_display,
        load_config,
        resolve_config_path,
    )

    config_path = resolve_config_path()
    plugin_version = "0.3.0"

    lines: list[str] = []
    lines.append(f"Plugin: custom-dangerous-patterns v{plugin_version}")

    if not config_path.exists():
        lines.append("Config: not found")
        lines.append("Run `hermes custom-patterns init` to create a starter config.")
        return ("\n".join(lines) + "\n", 0)

    path_display = get_config_path_display()
    lines.append(f"Config: {path_display}")

    # Integrity check
    hash_path = _resolve_hash_path(config_path)
    if hash_path.is_file():
        try:
            import hashlib
            import os
            from datetime import datetime

            previous = _load_hash_data(hash_path)
            prev_hash = previous.get("config_hash")
            if prev_hash and config_path.is_file():
                current_hash = hashlib.sha256(
                    config_path.read_text(encoding="utf-8").encode("utf-8")
                ).hexdigest()
                if current_hash == prev_hash:
                    lines.append("Integrity: \u2713 hash matches previous session")
                else:
                    lines.append("Integrity: \u26a0 hash changed since last session")
            mtime = os.path.getmtime(str(config_path))
            lines.append(
                f"Last changed: "
                f"{datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception:
            lines.append("Integrity: unknown")

    # Load config for counts
    config = load_config(force=True, integrity_check=False)
    lines.append("")
    lines.append("Pattern counts:")
    count_sections = [("Block", "patterns"), ("Allow", "allow_patterns"), ("Deny", "deny_patterns")]
    for label, key in count_sections:
        entries = config.get(key, [])
        active = sum(1 for e in entries if e.get("enabled", True))
        disabled = len(entries) - active
        if active and disabled:
            lines.append(f"  {label}:  {len(entries):>3} ({active} active, {disabled} disabled)")
        elif active:
            lines.append(f"  {label}:  {len(entries):>3} ({active} active)")
        elif entries:
            lines.append(f"  {label}:  {len(entries):>3} ({disabled} disabled)")
        else:
            lines.append(f"  {label}:  {len(entries):>3}")

    # Protected patterns
    protected_entries = []
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in config.get(section, []):
            if entry.get("protected"):
                protected_entries.append(entry)

    if protected_entries:
        lines.append("")
        lines.append(
            f"Protected patterns: {len(protected_entries)} registered, "
            f"{len([e for e in protected_entries if e.get('enabled', True)])} active"
        )
        for entry in protected_entries:
            status = "\u2713" if entry.get("enabled", True) else "\u2717"
            lines.append(f"  {status} {entry['description']}")

    # Groups
    groups: dict[str, dict[str, int]] = {}
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in config.get(section, []):
            grp = entry.get("group", "")
            if grp:
                if grp not in groups:
                    groups[grp] = {"total": 0, "active": 0}
                groups[grp]["total"] += 1
                if entry.get("enabled", True):
                    groups[grp]["active"] += 1

    if groups:
        lines.append("")
        lines.append("Groups:")
        for grp in sorted(groups):
            stats = groups[grp]
            extra = ""
            if stats["active"] == 0:
                extra = ", all disabled"
            lines.append(
                f"  {grp}: {stats['total']:>6} patterns "
                f"({stats['active']} active{extra})"
            )

    return ("\n".join(lines) + "\n", 0)


def cmd_logs(
    level: str | None = None,
    limit: int = 100,
    since: str | None = None,
    follow: bool = False,
) -> tuple[str, int]:
    """Show plugin-specific log entries from the Hermes log."""
    from .logs import extract_logs, follow_logs, format_log_entries, get_default_log_path

    log_path = get_default_log_path()

    if not log_path.is_file():
        return (
            f"No Hermes log file found at {log_path}.\n"
            f"Logs are only available when Hermes has been run at least once.\n",
            1,
        )

    if follow:
        follow_logs(log_path)
        return ("", 0)

    entries = extract_logs(log_path=log_path, level=level, limit=limit, since=since)
    lines = format_log_entries(entries, level=level)
    return ("\n".join(lines) + "\n", 0)


def cmd_add(
    interactive: bool = False,
    pattern_type: str | None = None,
    pattern: str | None = None,
    description: str | None = None,
    group: str | None = None,
    examples: list[str] | None = None,
    enabled_flag: bool | None = None,
    protected: bool = False,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Add a custom pattern via interactive prompts or CLI flags."""
    from .config import load_config, resolve_config_path

    config_path = resolve_config_path()
    config = load_config(force=True, integrity_check=False)

    if interactive:
        return _add_interactive(config, config_path, dry_run)

    # Non-interactive mode: require --type, --pattern, --description
    if not pattern_type or not pattern or not description:
        return (
            "Error: --type, --pattern, and --description are required "
            "in non-interactive mode.\n"
            "Use --interactive for guided entry.\n",
            1,
        )

    return _add_noninteractive(
        config, config_path, pattern_type, pattern, description,
        group or "", examples or [], enabled_flag if enabled_flag is not None else True,
        protected, dry_run,
    )


def _add_interactive(
    config: dict[str, Any], config_path: Path, dry_run: bool,
) -> tuple[str, int]:
    """Guided interactive pattern entry."""
    print()
    print("Pattern type:")
    print("  [1] block  — triggers approval prompt (once/session/always/deny)")
    print("  [2] allow  — command runs immediately, no prompt")
    print("  [3] deny   — command blocked immediately, no prompt")

    try:
        choice = input("Choose type [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    type_map = {"1": "block", "2": "allow", "3": "deny"}
    pattern_type = type_map.get(choice)
    if not pattern_type:
        return (f"Invalid choice: {choice}. Use 1, 2, or 3.\n", 1)

    try:
        pattern = input("Enter regex pattern: ").strip()
        if not pattern:
            return ("Pattern cannot be empty.\n", 1)
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        description = input("Enter description: ").strip()
        if not description:
            return ("Description cannot be empty.\n", 1)
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        group = input("Group (optional, press Enter to skip): ").strip()
        _ = group  # use later
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        enabled = input("Enabled? [Y/n]: ").strip().lower()
        enabled_flag = enabled != "n"
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        prot = input("Protected? [y/N]: ").strip().lower()
        protected = prot == "y"
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    return _add_noninteractive(
        config, config_path, pattern_type, pattern, description,
        group, [], enabled_flag, protected, dry_run,
    )


def _add_noninteractive(
    config: dict[str, Any],
    config_path: Path,
    pattern_type: str,
    pattern: str,
    description: str,
    group: str,
    examples: list[str],
    enabled_flag: bool,
    protected: bool,
    dry_run: bool,
) -> tuple[str, int]:
    """Add a pattern via CLI flags."""
    from .config import save_config

    # Validate regex
    try:
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        return (
            f"Error: invalid regex '{pattern}': {exc}\n"
            f"Pattern not added.\n",
            1,
        )

    section_key = {
        "block": "patterns",
        "allow": "allow_patterns",
        "deny": "deny_patterns",
    }.get(pattern_type, "patterns")

    entry = {
        "pattern": pattern,
        "description": description,
        "enabled": enabled_flag,
        "group": group,
        "protected": protected,
    }
    if examples:
        entry["examples"] = examples

    if dry_run:
        return (
            f"Would add {pattern_type} pattern: \"{description}\"\n"
            f"  Pattern: {pattern}\n"
            f"  Group: {group or '(none)'}\n"
            f"  Enabled: {enabled_flag}\n"
            f"  Protected: {protected}\n",
            0,
        )

    config.setdefault(section_key, []).append(entry)
    save_config(config, config_path)

    index = len(config.get(section_key, []))
    return (
        f"\u2713 Added {pattern_type} pattern: \"{description}\"\n"
        f"  Index: [{index}]\n"
        f"{_config_update_reminder()}",
        0,
    )


def cmd_remove(
    target: str | None = None,
    interactive: bool = False,
    pattern_type: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Remove a pattern interactively or by index/description."""
    from .config import load_config, resolve_config_path

    config_path = resolve_config_path()
    if not config_path.exists():
        return (
            f"No config found at {config_path}.\n"
            f"Run `hermes custom-patterns init` to create a starter config.\n",
            1,
        )

    config = load_config(force=True, integrity_check=False)

    # Build flat index (add _section to originals for mutation tracking)
    all_entries: list[dict[str, Any]] = []
    for section_key in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in config.get(section_key, []):
            entry["_section"] = section_key
            all_entries.append(entry)

    if not all_entries:
        return ("No patterns to remove. Config is empty.\n", 1)

    if interactive:
        return _remove_interactive(config, config_path, all_entries, dry_run)

    # Non-interactive: target is required
    if not target:
        return (
            "Must specify a pattern index, description, or --interactive.\n",
            1,
        )

    return _remove_by_target(config, config_path, all_entries, target, pattern_type, dry_run)


def _remove_interactive(
    config: dict[str, Any],
    config_path: Path,
    all_entries: list[dict[str, Any]],
    dry_run: bool,
) -> tuple[str, int]:
    """Interactive pattern removal with numbered selection."""
    from .config import save_config

    print()
    print("Select pattern to remove:")
    print()

    sections_order = [
        ("patterns", "BLOCK patterns:"),
        ("allow_patterns", "ALLOW patterns:"),
        ("deny_patterns", "DENY patterns:"),
    ]

    for section_key, label in sections_order:
        entries = [e for e in all_entries if e["_section"] == section_key]
        if not entries:
            continue
        print(label)
        for e in entries:
            idx = get_index(e, all_entries)
            grp = e.get("group", "")
            grp_str = f"  group: {grp}" if grp else ""
            print(f"  [{idx}] {e['description']}{grp_str}")
        print()

    try:
        choice = input("Enter index to remove (or 0 to cancel): ").strip()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        idx = int(choice)
    except ValueError:
        return (f"Invalid index: {choice}\n", 1)

    if idx == 0:
        return ("Cancelled.\n", 0)

    if idx < 1 or idx > len(all_entries):
        return (f"Invalid index: {idx}. Valid range: 1-{len(all_entries)}\n", 1)

    entry = all_entries[idx - 1]

    # Check protected
    if entry.get("protected"):
        return (
            f"Pattern [{idx}] \"{entry['description']}\" is protected.\n"
            f"Edit the config file directly to remove protected patterns.\n",
            1,
        )

    type_label = entry["_section"].replace("_patterns", "").upper()
    print(f"\nYou selected: [{idx}] \"{entry['description']}\" ({type_label})")

    try:
        confirm = input("Remove this pattern? This cannot be undone. [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    if confirm != "y":
        return ("Cancelled.\n", 0)

    if dry_run:
        return (
            f"Would remove {type_label} pattern [{idx}]: \"{entry['description']}\"\n"
            f"Use without --dry-run to confirm.\n",
            0,
        )

    # Remove from config (by index — entry is the original with _section)
    section = config.get(entry["_section"], [])
    section.pop(section.index(entry))
    _cleanup_sections(all_entries)
    save_config(config, config_path)

    return (
        f"\u2713 Removed {type_label} pattern [{idx}]: \"{entry['description']}\"\n"
        f"This cannot be undone. The pattern is permanently deleted.\n"
        f"{_config_update_reminder()}",
        0,
    )


def _remove_by_target(
    config: dict[str, Any],
    config_path: Path,
    all_entries: list[dict[str, Any]],
    target: str,
    pattern_type: str | None,
    dry_run: bool,
) -> tuple[str, int]:
    """Non-interactive pattern removal by index or description match."""
    from .config import save_config

    matched: list[dict[str, Any]] = []

    # Try index first
    try:
        idx = int(target)
        if 1 <= idx <= len(all_entries):
            matched = [all_entries[idx - 1]]
    except ValueError:
        pass

    # Fall back to description substring match
    if not matched:
        matched = [
            e for e in all_entries
            if target.lower() in e.get("description", "").lower()
        ]
        if pattern_type:
            type_map = {"block": "patterns", "allow": "allow_patterns", "deny": "deny_patterns"}
            section = type_map.get(pattern_type.lower(), "")
            matched = [e for e in matched if e["_section"] == section]

        if len(matched) > 1:
            lines = [f"Multiple patterns match '{target}'. Use index or be more specific:"]
            for e in matched:
                idx = get_index(e, all_entries)
                type_label = e["_section"].replace("_patterns", "").upper()
                lines.append(f"  [{idx}] {type_label}: {e['description']}")
            return ("\n".join(lines) + "\n", 1)

    if not matched:
        return (f"No patterns matched '{target}'.\n", 1)

    entry = matched[0]
    eidx = get_index(entry, all_entries)
    type_label = entry["_section"].replace("_patterns", "").upper()

    # Check protected
    if entry.get("protected"):
        return (
            f"Pattern [{eidx}] \"{entry['description']}\" is protected.\n"
            f"Edit the config file directly to remove protected patterns.\n",
            1,
        )

    if dry_run:
        return (
            f"Would remove {type_label} pattern [{eidx}]: \"{entry['description']}\"\n"
            f"Use without --dry-run to confirm.\n",
            0,
        )

    section = config.get(entry["_section"], [])
    section.pop(section.index(entry))
    _cleanup_sections(all_entries)
    save_config(config, config_path)

    return (
        f"\u2713 Removed {type_label} pattern [{eidx}]: \"{entry['description']}\"\n"
        f"This cannot be undone. The pattern is permanently deleted.\n"
        f"{_config_update_reminder()}",
        0,
    )


# ---------------------------------------------------------------------------
# Adapter functions — bridge between CLI argument parsing and cmd_* handlers
# ---------------------------------------------------------------------------


def _handle_list(args: Any) -> None:
    """Adapter: parse argparse-style args and call cmd_list."""
    output, exit_code = cmd_list(
        pattern_type=getattr(args, "type", None),
        group=getattr(args, "group", None),
        search=getattr(args, "search", None),
        disabled=getattr(args, "disabled", False),
        enabled=getattr(args, "enabled", False),
        builtins=getattr(args, "builtins", False),
    )
    _emit(output, exit_code)


def _handle_test(args: Any) -> None:
    output, exit_code = cmd_test(
        command=getattr(args, "command", ""),
        verbose=getattr(args, "verbose", False),
        skip_builtins=getattr(args, "skip_builtins", False),
    )
    _emit(output, exit_code)


def _handle_init(args: Any) -> None:
    output, exit_code = cmd_init(
        with_examples=getattr(args, "with_examples", False),
        force=getattr(args, "force", False),
    )
    _emit(output, exit_code)


def _handle_enable(args: Any) -> None:
    output, exit_code = cmd_enable(
        target=getattr(args, "target", None),
        pattern_type=getattr(args, "type", None),
        group=getattr(args, "group", None),
        dry_run=getattr(args, "dry_run", False),
    )
    _emit(output, exit_code)


def _handle_disable(args: Any) -> None:
    output, exit_code = cmd_disable(
        target=getattr(args, "target", None),
        pattern_type=getattr(args, "type", None),
        group=getattr(args, "group", None),
        dry_run=getattr(args, "dry_run", False),
    )
    _emit(output, exit_code)


def _handle_validate(args: Any) -> None:
    output, exit_code = cmd_validate(
        path=getattr(args, "path", None),
        quiet=getattr(args, "quiet", False),
    )
    _emit(output, exit_code)


def _handle_info(args: Any) -> None:
    output, exit_code = cmd_info()
    _emit(output, exit_code)


def _handle_logs(args: Any) -> None:
    output, exit_code = cmd_logs(
        level=getattr(args, "level", None),
        limit=getattr(args, "limit", 100),
        since=getattr(args, "since", None),
        follow=getattr(args, "follow", False),
    )
    _emit(output, exit_code)


def _handle_add(args: Any) -> None:
    output, exit_code = cmd_add(
        interactive=getattr(args, "interactive", False),
        pattern_type=getattr(args, "type", None),
        pattern=getattr(args, "pattern", None),
        description=getattr(args, "description", None),
        group=getattr(args, "group", None),
        examples=getattr(args, "examples", None),
        enabled_flag=not getattr(args, "disabled", False),
        protected=getattr(args, "protected", False),
        dry_run=getattr(args, "dry_run", False),
    )
    _emit(output, exit_code)


def _handle_remove(args: Any) -> None:
    output, exit_code = cmd_remove(
        target=getattr(args, "target", None),
        interactive=getattr(args, "interactive", False),
        pattern_type=getattr(args, "type", None),
        dry_run=getattr(args, "dry_run", False),
    )
    _emit(output, exit_code)


def _emit(output: str, exit_code: int) -> None:
    """Print output and exit with the given code."""
    if output:
        print(output)
    sys.exit(exit_code)


# ---------------------------------------------------------------------------
# Helpers — shared utilities used by multiple commands
# ---------------------------------------------------------------------------


# Snapshot of Hermes built-in DANGEROUS_PATTERNS for --builtins display.
# These are the ~47 patterns Hermes ships with. The list is a static
# reference bundled at plugin release time.
_BUILTIN_PATTERNS: list[tuple[str, str]] = [
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b", "rm with -rf flag"),
    (r"\brm\s+.*-rf\b", "rm with -rf flag"),
    (r"\bmkfs\b", "mkfs (filesystem creation, destructive)"),
    (r"\bdd\s+if=.*of=/dev/[a-zA-Z]+", "dd to raw device"),
    (r"\b:(){ :|:& };:", "Fork bomb"),
    (r"\bchmod\s+(-R\s+)?777\b", "chmod 777 (world-writable)"),
    (r"\bchown\s+(-R\s+)?root:root\s+/", "chown root:root /"),
    (r"\bgcc\s+.*-o\s+/", "gcc compile to root directory"),
    (r"\bgit\s+push\s+--force\b", "git push --force"),
    (r"\bgit\s+push\s+-f\b", "git push -f"),
    (r"\bsudo\s+su\b", "sudo su (become root)"),
    (r"\bsudo\s+.*>\s*/", "sudo redirect to root directory"),
    (r"\bDROP\s+(TABLE|DATABASE)\b", "SQL DROP statement"),
    (r"\bTRUNCATE\s+TABLE\b", "SQL TRUNCATE statement"),
    (r"\bDELETE\s+FROM\b", "SQL DELETE FROM"),
    (r"\bALTER\s+TABLE\s+\w+\s+DROP\b", "SQL ALTER TABLE DROP"),
    (r"\bcurl\b.*\|.*\b(ba)?sh\b", "curl piped to shell"),
    (r"\bwget\b.*\|.*\b(ba)?sh\b", "wget piped to shell"),
    (r"\bcurl\b.*\|.*\bpython\b", "curl piped to python"),
    (r"\bwget\b.*-O\s*-\s*\|.*\bpython\b", "wget piped to python"),
    (r"\bopenssl\s+.*-nodes\b", "openssl with -nodes (unencrypted key)"),
    (r"\bssh\s+.*-o\s+StrictHostKeyChecking=no\b", "SSH with disabled host key checking"),
    (r"\bscp\s+.*root@", "scp to root user"),
    (r"\biptables\s+-F\b", "iptables flush rules"),
    (r"\biptables\s+-P\s+INPUT\s+ACCEPT\b", "iptables accept all"),
    (r"\bdocker\s+rm\s+-f\b", "docker rm -f"),
    (r"\bdocker\s+system\s+prune\b", "docker system prune"),
    (r"\bdocker\s+volume\s+rm\b", "docker volume rm"),
    (r"\bdocker\s+network\s+rm\b", "docker network rm"),
    (r"\bdocker\s+compose\s+down\s+-v\b", "docker compose down -v"),
    (r"\bkubectl\s+delete\s+namespace\b", "kubectl delete namespace"),
    (r"\bkubectl\s+delete\s+deployment\b", "kubectl delete deployment"),
    (r"\bhelm\s+uninstall\b", "helm uninstall"),
    (r"\bterraform\s+(destroy|apply)", "Terraform destroy/apply"),
    (r"\bansible\b.*-e\s+.*state=absent", "Ansible state=absent"),
    (r"\bpip\s+uninstall\b", "pip uninstall"),
    (r"\bnpm\s+uninstall\b", "npm uninstall"),
    (r"\bapt-get\s+purge\b", "apt-get purge"),
    (r"\byum\s+remove\b", "yum remove"),
    (r"\bpacman\s+-R\b", "pacman -R (remove)"),
    (r"\bnpx\s+.*@", "npx with unknown package"),
    (r"\bpipx\s+run\b", "pipx run (arbitrary package execution)"),
    (r"\bshred\b", "shred (secure delete)"),
    (r"\bwiping\b", "wiping tools"),
    (r"\bcrontab\s+-r\b", "crontab -r (remove all cron jobs)"),
    (r"\bcrontab\s+.*>\s*/etc/cron", "crontab redirect to system"),
    (r"\bkill\s+-9\s+-1\b", "kill -9 -1 (all processes)"),
    (r"\buserdel\s+-r\b", "userdel -r (remove user and home)"),
]


def _format_builtins(
    search_term: str | None = None,
) -> list[str]:
    """Format the built-in patterns list for display."""
    lines = ["BUILT-IN patterns (Hermes):"]
    shown = 0
    for pat, desc in _BUILTIN_PATTERNS:
        if (
            search_term
            and search_term.lower() not in desc.lower()
            and search_term.lower() not in pat.lower()
        ):
            continue
        shown += 1
        lines.append(f"  [{shown}] [Hermes] {desc}")
    if shown == 0:
        lines.append("  (no built-in patterns match the filter)")
    return lines


def get_index(entry: dict[str, Any], all_entries: list[dict[str, Any]]) -> int:
    """Get the 1-based flat index of a pattern entry."""
    for i, e in enumerate(all_entries):
        if e is entry:
            return i + 1
    return -1


def _cleanup_sections(all_entries: list[dict[str, Any]]) -> None:
    """Remove _section marker from all entries before saving."""
    for entry in all_entries:
        entry.pop("_section", None)


def _config_update_reminder() -> str:
    """Return the standard reminder for config changes."""
    return (
        "\nRemember to restart the Hermes gateway and any active CLI/TUI sessions\n"
        "for changes to take effect.\n"
    )



