"""CLI command handlers for hermes custom-dangerous-patterns.

Pure config management and introspection — no monkey-patching, no Hermes
runtime dependencies. Each command handler is a standalone function that
operates on config dicts and returns (output: str, exit_code: int).

Commands are registered individually via ctx.register_cli_command() in
__init__.py, producing:
    hermes custom-dangerous-patterns list
    hermes custom-dangerous-patterns test "..."
    etc.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

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

    from .display import subheading, pattern_entry, muted, path_info, _s

    if not config_path.exists():
        return (
            f"[error]✗[/error] No config found at [path]{config_path}[/path]\n\n"
            f"Run `hermes custom-dangerous-patterns init` to create a starter config.\n",
            0,
        )

    # Build config path display at start
    if config_path.is_dir():
        yaml_files = sorted(config_path.glob("*.yaml"))
        path_display = f"{config_path} ({len(yaml_files)} files)"
    else:
        path_display = str(config_path)

    lines: list[str] = []
    lines.append(path_info("Config", path_display))
    lines.append("")

    # Build title with filter context
    filter_desc = ""
    filters = []
    if pattern_type:
        filters.append(f"type={pattern_type}")
    if group:
        filters.append(f"group={group}")
    if search:
        filters.append(f"search={search}")
    if disabled:
        filters.append("disabled only")
    elif enabled:
        filters.append("enabled only")
    if filters:
        filter_desc = f" — [dim]Filtered: {', '.join(filters)}[/dim]"

    sections: list[tuple[str, str, list[dict[str, Any]]]] = [
        ("BLOCK", "patterns", config.get("patterns", [])),
        ("ALLOW", "allow_patterns", config.get("allow_patterns", [])),
        ("DENY", "deny_patterns", config.get("deny_patterns", [])),
    ]

    # Section colour mapping
    section_colours = {"BLOCK": "yellow", "ALLOW": "green", "DENY": "red"}

    flat_index = 0
    total_shown = 0

    for section_label, _config_key, entries in sections:
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

        active_count = sum(1 for e in filtered if e.get("enabled", True))
        disabled_count = len(filtered) - active_count

        colour = section_colours.get(section_label, "white")
        styled_label = _s(
            f"[{colour} bold]◆ {section_label}[/{colour} bold]",
            f"◆ {section_label}",
        )
        parts = [f"{styled_label} patterns"]
        if active_count and disabled_count:
            parts.append(f"[dim]({active_count} active, {disabled_count} disabled)[/dim]")
        elif active_count:
            parts.append(f"[dim]({active_count} active)[/dim]")
        else:
            parts.append(f"[dim]({disabled_count} disabled)[/dim]")

        lines.append(" ".join(parts))

        for entry in filtered:
            flat_index += 1
            is_enabled = entry.get("enabled", True)
            desc = entry.get("description", entry.get("pattern", ""))
            grp = entry.get("group", "")
            lines.append(pattern_entry(flat_index, is_enabled, desc, grp))
            total_shown += 1

    has_any_patterns = any(
        config.get(key) for key in ("patterns", "allow_patterns", "deny_patterns")
    )
    if total_shown == 0:
        if has_any_patterns and (pattern_type or group or search or disabled or enabled):
            lines.append("\n[muted]No patterns match your filters.[/muted]")
        else:
            lines.append(
                "\n[muted]No custom patterns defined. "
                "Edit your config file or use `hermes custom-dangerous-patterns add`.[/muted]"
            )

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
    from .config import load_config, resolve_config_path
    from .patterns import compile_all, get_block_patterns, is_allow_pattern, is_deny_pattern
    from .display import subheading, success, muted, warn_mark, cross, result_panel, path_info

    if not command or not command.strip():
        return (f"[error]✗[/error] Error: command must not be empty.\n", 1)

    config = load_config(force=True, integrity_check=False)
    compile_all(config)

    config_path = resolve_config_path()
    if config_path.is_dir():
        yaml_files = sorted(config_path.glob("*.yaml"))
        path_display = f"{config_path} ({len(yaml_files)} files)"
    else:
        path_display = str(config_path)

    lines: list[str] = []
    lines.append(path_info("Config", path_display))
    lines.append("")

    # Step 1: Deny patterns
    deny_match = is_deny_pattern(command)
    lines.append(subheading("1. DENY Patterns  — checked first, block immediately"))
    if deny_match:
        lines.append(success(f"MATCH: {deny_match}"))
    else:
        lines.append(muted("  (no matches)"))

    # Step 2: Allow patterns
    allow_match = is_allow_pattern(command)
    lines.append(subheading("2. ALLOW Patterns — checked second, exempt from all checks"))
    if allow_match:
        lines.append(success(f"MATCH: {allow_match}"))
    else:
        lines.append(muted("  (no matches)"))

    # Step 3: Block patterns (only if no deny match)
    block_matches: list[tuple[str, str]] = []
    if deny_match is None:
        lines.append(subheading("3. BLOCK Patterns — checked third, trigger approval prompt"))
        for regex_obj, desc in get_block_patterns():
            cmd_normalized = _normalize_for_test(command)
            if regex_obj.search(cmd_normalized):
                block_matches.append((regex_obj.pattern, desc))
        if block_matches:
            for pattern_str, desc in block_matches:
                lines.append(f"  [yellow]⚠[/yellow] MATCH: {desc}")
                if verbose:
                    lines.append(f"    [dim]Pattern: {pattern_str}[/dim]")
        else:
            lines.append(muted("  (no matches)"))
    else:
        lines.append(subheading("3. BLOCK Patterns — [dim]skipped (deny already matched)[/dim]"))

    # Step 4: Built-in patterns
    if not skip_builtins:
        lines.append(subheading("4. BUILT-IN Patterns — checked alongside block patterns"))
        builtin_matches = _check_builtins_for_test(command, verbose)
        if builtin_matches:
            for bm in builtin_matches:
                lines.append(f"  [yellow]⚠[/yellow] MATCH: {bm}")
        else:
            lines.append(muted("  (no matches)"))

    # Determine result
    lines.append("")
    if deny_match is not None:
        lines.append(result_panel(
            "DENY",
            "command BLOCKED immediately, no prompt shown",
            "red",
        ))
    elif allow_match is not None:
        lines.append(result_panel(
            "ALLOW",
            "command runs immediately, no prompt shown",
            "green",
        ))
        if block_matches:
            lines.append(muted("(Block patterns skipped — allow wins over block)"))
    elif block_matches or (not skip_builtins and _check_builtins_for_test(command, False)):
        lines.append(result_panel(
            "APPROVAL PROMPT",
            "user will see (o)nce/(s)ession/(a)lways/(d)eny",
            "yellow",
        ))
    else:
        lines.append(result_panel(
            "PASS",
            "no patterns matched. Command would run normally",
            "green",
        ))

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
    """Create a starter config directory and guide the user.

    Creates ~/.hermes/custom-dangerous-patterns/ (a directory) with
    starter patterns. All patterns are DISABLED by default — the user
    must review and enable the ones they want. Use --with-examples for
    a fully-enabled demonstration config.

    Args:
        with_examples: Include fully-enabled example patterns.
        force: Overwrite existing config without asking.
    """
    from .config import resolve_config_path

    # Always use directory mode
    config_path = resolve_config_path()
    dir_path = config_path.parent / "custom-dangerous-patterns"
    config_path = dir_path

    from .display import success, muted, path_info

    # Check if config already exists
    if config_path.exists():
        if not force:
            return (
                f"[warning]⚠[/warning] Config already exists at [path]{config_path}[/path]\n"
                f"Use [bold]--force[/bold] to overwrite.\n",
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

    config_path.mkdir(parents=True, exist_ok=True)

    if with_examples:
        # Write test patterns (always disabled) to 00-test.yaml
        test_config = _build_minimal_starter_config()
        _write_init_yaml(test_config, config_path / "00-test.yaml")

        saved_files = ["00-test.yaml"]

        # Write example patterns (fully enabled) to 01-examples.yaml.
        # Guard against the fallback case where _load_example_config returns
        # the test config (example file not found) — skip to avoid duplicates.
        is_fallback = (
            config_dict.get("patterns", []) == test_config.get("patterns", [])
            and config_dict.get("deny_patterns", []) == test_config.get("deny_patterns", [])
        )
        if not is_fallback:
            _write_init_yaml(config_dict, config_path / "01-examples.yaml")
            saved_files.append("01-examples.yaml")
            # Add test pattern counts to the example counts already tallied
            block_count += len(test_config.get("patterns", []))
            allow_count += len(test_config.get("allow_patterns", []))
            deny_count += len(test_config.get("deny_patterns", []))
    else:
        target = config_path / "00-test.yaml"
        _write_init_yaml(config_dict, target)
        saved_files = ["00-test.yaml"]

    lines = [
        success(f"Created: [path]{config_path}/[/path] [dim]({', '.join(saved_files)})[/dim]"),
        f"  [dim]{block_count} block, {allow_count} allow, {deny_count} deny patterns — all disabled[/dim]",
        "",
        "[bold]Next steps:[/bold]",
        "  1. Review the config: [bold]hermes custom-dangerous-patterns list[/bold]",
        "  2. Enable patterns: [bold]hermes custom-dangerous-patterns enable --group testing[/bold]",
        "  3. Add new patterns: [bold]hermes custom-dangerous-patterns add[/bold]",
        "  4. Restart Hermes for changes to take effect",
    ]
    return ("\n".join(lines) + "\n", 0)


def _write_init_yaml(config_dict: dict[str, Any], target: Path) -> None:
    """Write a config dict to a YAML file during init (not delta-based)."""
    from .config import _clean_for_serialization, _write_yaml

    output: dict[str, Any] = {}
    for key in ("patterns", "allow_patterns", "deny_patterns"):
        entries = config_dict.get(key, [])
        if entries:
            output[key] = _clean_for_serialization(entries)
    if output:
        _write_yaml(output, target)


def _build_minimal_starter_config() -> dict[str, Any]:
    """Build a minimal starter config with [TEST] patterns only."""
    return {
        "patterns": [
            {
                "pattern": r"\becho\b",
                "description": "[TEST] Block any echo command",
                "enabled": False,
                "group": "testing",
            },
        ],
        "allow_patterns": [
            {
                "pattern": r"\becho\s+allow\b",
                "description": "[TEST] Allow echo allow",
                "enabled": False,
                "group": "testing",
            },
        ],
        "deny_patterns": [
            {
                "pattern": r"\becho\s+deny\b",
                "description": "[TEST] Deny echo deny",
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
        Path(__file__).resolve().parent / "examples" / "01-examples.yaml",
        Path.home() / ".hermes" / "plugins" / "custom-dangerous-patterns"
        / "examples" / "01-examples.yaml",
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
    """Enable patterns by index, description, or group.

    With no arguments, launches interactive selection.
    """
    return _toggle_patterns(enable=True, target=target, pattern_type=pattern_type,
                            group=group, dry_run=dry_run)


def cmd_disable(
    target: str | None = None,
    pattern_type: str | None = None,
    group: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Disable patterns by index, description, or group.

    With no arguments, launches interactive selection.
    """
    return _toggle_patterns(enable=False, target=target, pattern_type=pattern_type,
                            group=group, dry_run=dry_run)


def _toggle_patterns(
    enable: bool,
    target: str | None,
    pattern_type: str | None,
    group: str | None,
    dry_run: bool,
) -> tuple[str, int]:
    """Shared implementation for enable/disable commands.

    When no target, group, or type is specified, launches interactive
    selection automatically.
    """
    from .config import load_config, resolve_config_path, save_config
    from .display import muted

    config_path = resolve_config_path()
    if not config_path.exists():
        return (
            f"[error]✗[/error] No config found at [path]{config_path}[/path]\n\n"
            f"Run `hermes custom-dangerous-patterns init` to create a starter config.\n",
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
        return ("[error]✗[/error] No custom patterns defined. Nothing to change.\n", 1)

    # With no target/group/type, go interactive by default
    if target is None and group is None and pattern_type is None:
        return _toggle_interactive(config, config_path, all_entries, enable, dry_run)

    # Find matching patterns
    matched: list[dict[str, Any]] = []

    if group:
        # Match by group
        matched = [e for e in all_entries if e.get("group", "") == group]
        if not matched:
            return (f"[warning]⚠[/warning] No patterns found in group '[bold]{group}[/bold]'.\n", 1)
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
                lines = [f"[warning]⚠[/warning] Multiple patterns match '[bold]{target}[/bold]'. Use index or be more specific:"]
                for i, e in enumerate(all_entries):
                    if e in matched:
                        type_label = e["_section"].replace("_patterns", "").upper()
                        lines.append(f"  [{i + 1}] [bold]{type_label}:[/bold] {e['description']}")
                return ("\n".join(lines) + "\n", 1)

        if not matched:
            return (f"[warning]⚠[/warning] No patterns matched '[bold]{target}[/bold]'.\n", 1)
    else:
        return _toggle_interactive(config, config_path, all_entries, enable, dry_run)

    # Check for protected patterns
    protected = [e for e in matched if e.get("protected")]
    if protected and not enable:
        names = ", ".join(f'[bold]"{e["description"]}"[/bold]' for e in protected)
        return (
            f"[error]✗[/error] Cannot disable protected patterns: {names}.\n"
            f"Edit the config file directly to modify protected patterns.\n",
            1,
        )

    # Check if already in desired state
    already = [e for e in matched if e.get("enabled", True) == new_state]
    if already and not dry_run:
        names = ", ".join(f'[{get_index(e, all_entries)}] [bold]"{e["description"]}"[/bold]' for e in already)
        return (f"[dim]Pattern(s) already {action}: {names}[/dim]\n", 0)

    if dry_run:
        lines = [f"[bold]Would {action} the following patterns:[/bold]"]
        for e in matched:
            lines.append(f"  [{get_index(e, all_entries)}] {e['description']}")
        return ("\n".join(lines) + "\n", 0)

    # Apply the toggle
    changed = []
    for entry in matched:
        if enable:
            # Remove enabled key so it defaults to True (omitted from YAML output)
            entry.pop("enabled", None)
        else:
            entry["enabled"] = False
        changed.append(entry)

    # Clean up _section marker before saving
    for entry in all_entries:
        entry.pop("_section", None)

    save_config(config, config_path)

    lines = [f"[bold]{action.capitalize()} {len(changed)} pattern(s):[/bold]"]
    for e in changed:
        lines.append(f"  [{get_index(e, all_entries)}] {e['description']}")
    lines.append(_config_update_reminder())
    return ("\n".join(lines) + "\n", 0)


def _toggle_interactive(
    config: dict[str, Any],
    config_path: Path,
    all_entries: list[dict[str, Any]],
    enable: bool,
    dry_run: bool,
) -> tuple[str, int]:
    """Interactive enable/disable with numbered selection."""
    from .config import save_config
    from .display import _console
    from rich.text import Text

    # In enable mode, only show disabled patterns (ones that need enabling).
    # In disable mode, only show enabled patterns (ones that need disabling).
    show_disabled = enable

    action = "enable" if enable else "disable"
    action_past = "enabled" if enable else "disabled"

    # Build filtered list (by section, only patterns in the target state)
    section_styles = {
        "patterns": "yellow",
        "allow_patterns": "green",
        "deny_patterns": "red",
    }
    section_labels = {
        "patterns": "BLOCK",
        "allow_patterns": "ALLOW",
        "deny_patterns": "DENY",
    }

    # Build a visible-entries list (1-based displayed numbering)
    visible_entries: list[dict[str, Any]] = []
    _console.print()
    _console.print(f"Select pattern to {action}:")
    _console.print()

    for section_key in ("patterns", "allow_patterns", "deny_patterns"):
        entries = [e for e in all_entries if e["_section"] == section_key]
        # Filter: show disabled for enable, enabled for disable
        if show_disabled:
            entries = [e for e in entries if not e.get("enabled", True)]
        else:
            entries = [e for e in entries if e.get("enabled", True)]
        if not entries:
            continue
        colour = section_styles[section_key]
        label = section_labels[section_key]
        _console.print(f"[{colour} bold]\u25c6 {label}[/{colour} bold] patterns")
        for i, e in enumerate(entries):
            idx = get_index(e, all_entries)
            is_enabled = e.get("enabled", True)
            line = Text()
            line.append(f"  [{idx}] ")
            if is_enabled:
                line.append("\u2713 ", style="success")
            else:
                line.append("\u2717 ", style="error")
            line.append(e["description"])
            grp = e.get("group", "")
            if grp:
                line.append(f"  group: {grp}", style="dim")
            _console.print(line)
            visible_entries.append(e)
        _console.print()

    if not visible_entries:
        return (
            f"[dim]All patterns are already {action_past}. Nothing to {action}.[/dim]\n",
            0,
        )

    try:
        choice = input(f"Enter index to {action} (or 0 to cancel): ").strip()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    try:
        idx = int(choice)
    except ValueError:
        return (f"Invalid index: {choice}\n", 1)

    if idx == 0:
        return ("Cancelled.\n", 0)

    # Look up the entry in visible_entries by its global index
    entry = next((e for e in visible_entries if get_index(e, all_entries) == idx), None)
    if entry is None:
        return (f"Invalid index: {idx}. Valid range: visible pattern indices.\n", 1)

    # Check protected (only on disable)
    if not enable and entry.get("protected"):
        return (
            f"Pattern [{idx}] \"{entry['description']}\" is protected.\n"
            f"Edit the config file directly to modify protected patterns.\n",
            1,
        )

    # Check if already in desired state
    already = entry.get("enabled", True) == enable
    if already:
        return (f"Pattern [{idx}] \"{entry['description']}\" is already {action_past}.\n", 0)

    type_label = entry["_section"].replace("_patterns", "").upper()
    print(f"\nYou selected: [{idx}] \"{entry['description']}\" ({type_label})")

    try:
        confirm = input(f"{action.capitalize()} this pattern? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    if confirm != "y":
        return ("Cancelled.\n", 0)

    if dry_run:
        return (
            f"Would {action} {type_label} pattern [{idx}]: "
            f"\"{entry['description']}\"\n"
            f"Use without --dry-run to confirm.\n",
            0,
        )

    # Apply the toggle
    if enable:
        # Remove enabled key so it defaults to True (omitted from YAML output)
        entry.pop("enabled", None)
    else:
        entry["enabled"] = False

    _cleanup_sections(all_entries)
    save_config(config, config_path)

    return (
        f"\u2713 {action_past.capitalize()} {type_label} pattern [{idx}]: "
        f"\"{entry['description']}\"\n"
        f"{_config_update_reminder()}",
        0,
    )


def cmd_validate(
    path: str | None = None,
    quiet: bool = False,
) -> tuple[str, int]:
    """Validate config syntax and regexes."""
    from .config import _load_yaml, _validate_config, resolve_config_path
    from .display import subheading, check, cross, warn_mark, success, muted, path_info

    if path:
        config_path = Path(path)
    else:
        config_path = resolve_config_path()

    lines: list[str] = []
    warnings: list[str] = []

    # Check file exists
    if not config_path.exists():
        if quiet:
            return ("", 2)
        lines.append(cross(f"Config not found: [path]{config_path}[/path]"))
        lines.append("")
        lines.append("[bold red]Result: INVALID[/bold red] — file not found")
        return ("\n".join(lines) + "\n", 2)

    # Show config path at start
    if config_path.is_dir():
        yaml_files = sorted(config_path.glob("*.yaml"))
        path_display = f"{config_path} ({len(yaml_files)} files)"
    else:
        path_display = str(config_path)
    lines.append(path_info("Config", path_display))
    lines.append("")

    # Load YAML
    raw = _load_yaml(config_path)
    if raw is None:
        if quiet:
            return ("", 1)
        lines = []
        lines.append(cross(f"Config: [path]{config_path}[/path]"))
        lines.append(cross("YAML syntax: invalid — cannot parse file"))
        lines.append("")
        lines.append("[bold red]Result: INVALID[/bold red] — fix the YAML syntax above before restarting Hermes")
        return ("\n".join(lines) + "\n", 1)

    # Validate
    validated = _validate_config(raw)

    lines.append(check(f"Config: [path]{config_path}[/path]"))
    lines.append(check("YAML syntax: valid"))
    lines.append(check("Schema: valid"))

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
                    warn_mark(f"{section_label}[{i}] regex warning: "
                    f"pattern '[bold]{pat}[/bold]' matches everything")
                )

    if warnings:
        lines.append("")
        lines.extend(warnings)

    lines.append("")
    lines.append(success(
        f"All regexes compile successfully "
        f"[dim](patterns: {block_count} block, {allow_count} allow, {deny_count} deny)[/dim]"
    ))
    lines.append("")
    lines.append("[bold green]Result: VALID[/bold green] — config is well-formed")

    if quiet:
        return ("", 0)
    return ("\n".join(lines) + "\n", 0)


def cmd_info() -> tuple[str, int]:
    """Show plugin configuration dashboard."""
    from .config import load_config, resolve_config_path, get_config_path_display, _resolve_hash_path, _load_hash_data
    from .display import subheading, success, check, cross, warn_mark, muted, path_info, key_value

    config_path = resolve_config_path()
    plugin_version = "0.3.0"

    lines: list[str] = []

    if not config_path.exists():
        lines.append(cross("Config: not found"))
        lines.append(muted("  Run `hermes custom-dangerous-patterns init` to create a starter config."))
        return ("\n".join(lines) + "\n", 0)

    path_display = get_config_path_display()
    lines.append(path_info("Config", path_display))

    # Integrity check
    hash_path = _resolve_hash_path(config_path)
    if hash_path.is_file():
        try:
            previous = _load_hash_data(hash_path)
            prev_hash = previous.get("config_hash")
            if prev_hash and config_path.is_file():
                current_hash = hashlib.sha256(
                    config_path.read_text(encoding="utf-8").encode("utf-8")
                ).hexdigest()
                if current_hash == prev_hash:
                    lines.append(check("Integrity: hash matches previous session"))
                else:
                    lines.append(warn_mark("Integrity: hash changed since last session"))
            mtime = os.path.getmtime(str(config_path))
            lines.append(
                muted(f"  Last changed: "
                f"{datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')}")
            )
        except Exception:
            lines.append(muted("  Integrity: unknown"))

    # Load config for counts
    # Load config for counts
    config = load_config(force=True, integrity_check=False)
    lines.append("")
    lines.append(subheading("Pattern Counts"))
    count_sections = [("Block", "patterns"), ("Allow", "allow_patterns"), ("Deny", "deny_patterns")]
    for label, key in count_sections:
        entries = config.get(key, [])
        active = sum(1 for e in entries if e.get("enabled", True))
        disabled = len(entries) - active
        if active and disabled:
            lines.append(f"  [bold]{label}:[/bold] {len(entries):>3} [dim]({active} active, {disabled} disabled)[/dim]")
        elif active:
            lines.append(f"  [bold]{label}:[/bold] {len(entries):>3} [dim]({active} active)[/dim]")
        elif entries:
            lines.append(f"  [bold]{label}:[/bold] {len(entries):>3} [dim]({disabled} disabled)[/dim]")
        else:
            lines.append(f"  [bold]{label}:[/bold] {len(entries):>3}")

    # Protected patterns
    # Protected patterns
    protected_entries = []
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in config.get(section, []):
            if entry.get("protected"):
                protected_entries.append(entry)

    if protected_entries:
        lines.append("")
        lines.append(subheading("Protected Patterns"))
        lines.append(
            f"  [bold]{len(protected_entries)} registered[/bold], "
            f"[dim]{len([e for e in protected_entries if e.get('enabled', True)])} active[/dim]"
        )
        for entry in protected_entries:
            if entry.get("enabled", True):
                lines.append(check(f"  {entry['description']}"))
            else:
                lines.append(cross(f"  {entry['description']}"))

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
        lines.append(subheading("Groups"))
        for grp in sorted(groups):
            stats = groups[grp]
            extra = ""
            if stats["active"] == 0:
                extra = " [dim], all disabled[/dim]"
            lines.append(
                f"  [bold]{grp}:[/bold] {stats['total']:>2} patterns "
                f"[dim]({stats['active']} active{extra})[/dim]"
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
    from .display import muted, cross

    log_path = get_default_log_path()

    if not log_path.is_dir():
        return (
            f"[error]✗[/error] Hermes log directory not found at [path]{log_path}[/path]\n"
            f"Logs are only available when Hermes has been run at least once.\n",
            1,
        )

    # Check for any *.log files
    log_files = sorted(log_path.glob("*.log"))
    if not log_files:
        return (
            f"[error]✗[/error] No *.log files found in [path]{log_path}[/path]\n"
            f"Logs are only available when Hermes has been run at least once.\n",
            1,
        )

    if follow:
        follow_logs(log_path)
        return ("", 0)

    entries = extract_logs(log_path=log_path, level=level, limit=limit, since=since)
    lines = format_log_entries(entries, level=level)
    # Add a note about which files were scanned
    file_list = ", ".join(f.name for f in log_files)
    lines.append("")
    lines.append(muted(f"Scanned: {len(log_files)} log file(s) — {file_list}"))
    return ("\n".join(lines) + "\n", 0)


def cmd_add(
    pattern_type: str | None = None,
    pattern: str | None = None,
    description: str | None = None,
    group: str | None = None,
    examples: list[str] | None = None,
    enabled_flag: bool | None = None,
    protected: bool = False,
    dry_run: bool = False,
    glob_str: str | None = None,
    target_file: str | None = None,
) -> tuple[str, int]:
    """Add a custom pattern via interactive prompts or CLI flags.

    With no arguments, launches interactive entry automatically.
    Use --target FILENAME to write to a specific YAML file in the config
    directory (requires directory mode; file extension must be .yaml).
    """
    from .config import load_config, resolve_config_path, append_to_yaml_file
    from .patterns import glob_to_regex
    from .display import success, cross, muted

    config_path = resolve_config_path()

    # Validate --target early
    if target_file is not None:
        if not config_path.is_dir():
            return (
                "[error]✗[/error] --target requires directory mode. "
                "Run `hermes custom-dangerous-patterns init` first.\n",
                1,
            )
        if not target_file.endswith(".yaml"):
            return (
                "[error]✗[/error] --target file must have a .yaml extension.\n",
                1,
            )
        if "/" in target_file:
            return (
                "[error]✗[/error] --target must be a filename, not a path.\n",
                1,
            )

    config = load_config(force=True, integrity_check=False)

    # Go interactive when no type, pattern/glob, or description provided
    if not pattern_type and not pattern and not description and not glob_str and not target_file:
        return _add_interactive(config, config_path, dry_run, target_file)

    # Handle --glob (mutually exclusive with --pattern)
    if glob_str and pattern:
        return (
            "[error]✗[/error] Error: Cannot specify both --glob and --pattern.\n"
            "Use one or the other.\n",
            1,
        )
    if glob_str:
        if not glob_str.strip():
            return (
                "[error]✗[/error] Error: --glob cannot be empty or whitespace-only.\n",
                1,
            )
        pattern = glob_to_regex(glob_str)
        if not pattern:
            return (
                "[error]✗[/error] Error: --glob produced an empty regex. "
                "Check that the glob contains non-whitespace characters.\n",
                1,
            )

    # Non-interactive mode: require --type, --pattern, --description
    if not pattern_type or not pattern or not description:
        return (
            "[error]✗[/error] Error: --type, --pattern, and --description are required "
            "in non-interactive mode.\n",
            1,
        )

    return _add_noninteractive(
        config, config_path, pattern_type, pattern, description,
        group or "", examples or [], enabled_flag if enabled_flag is not None else True,
        protected, dry_run, glob_str if glob_str else None, target_file,
    )


def _add_interactive(
    config: dict[str, Any], config_path: Path, dry_run: bool,
    target_file: str | None = None,
) -> tuple[str, int]:
    """Guided interactive pattern entry with glob-to-regex support.

    Flow:
      1. Pattern type (block/allow/deny)
      2. Glob entry → auto-generate regex → confirm/edit
      3. Optional example testing with validation loop
      4. Description, group, enabled, protected
    """
    from .patterns import glob_to_regex

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

    # --- Glob entry ---
    try:
        glob_input = input(
            "Enter a glob-style pattern (or press Enter for raw regex): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    glob_str = ""
    if glob_input:
        glob_str = glob_input
        pattern = glob_to_regex(glob_input)
        print(f"\nGenerated regex: {pattern}")

        try:
            confirm = input("Accept generated regex? [Y/n/edit]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ("\nCancelled.\n", 1)

        if confirm == "n":
            try:
                glob_input = input(
                    "Enter a glob-style pattern (or press Enter for raw regex): "
                ).strip()
                if not glob_input:
                    glob_str = ""  # Fall through to raw regex
                else:
                    glob_str = glob_input
                    pattern = glob_to_regex(glob_input)
                    print(f"Generated regex: {pattern}")
                    confirm2 = input("Accept generated regex? [Y/n/edit]: ").strip().lower()
                    if confirm2 == "n":
                        glob_str = ""  # Fall through to raw regex
                    elif confirm2 in ("edit", "e"):
                        glob_str = ""
            except (EOFError, KeyboardInterrupt):
                return ("\nCancelled.\n", 1)
        elif confirm in ("edit", "e"):
            glob_str = ""  # Fall through to raw regex below
    if not glob_str:
        try:
            pattern = input("Enter regex pattern: ").strip()
            if not pattern:
                return ("Pattern cannot be empty.\n", 1)
        except (EOFError, KeyboardInterrupt):
            return ("\nCancelled.\n", 1)

    # --- Example testing ---
    example: str = ""
    try:
        ex_input = input(
            "\nEnter an example command to test (press Enter to skip): "
        ).strip()
    except (EOFError, KeyboardInterrupt):
        return ("\nCancelled.\n", 1)

    if ex_input:
        example = ex_input
        print("\nTesting example against generated regex...")
        try:
            compiled = re.compile(pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            return (f"Error: generated regex is invalid: {exc}\n", 1)

        if compiled.search(example):
            print(f"  \u2713 {example}")
        else:
            print(f"  \u2717 {example}  (does not match)")
            try:
                fix = input("Edit glob to fix? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return ("\nCancelled.\n", 1)

            if fix == "y":
                try:
                    glob_input = input("Enter glob pattern: ").strip()
                    if glob_input:
                        glob_str = glob_input
                        pattern = glob_to_regex(glob_input)
                        print(f"Generated regex: {pattern}")
                        try:
                            compiled = re.compile(
                                pattern, re.IGNORECASE | re.DOTALL
                            )
                        except re.error as compile_exc:
                            print(
                                f"  Error: generated regex is invalid: "
                                f"{compile_exc}"
                            )
                        else:
                            print("Re-testing...")
                            if compiled.search(example):
                                print(f"  \u2713 {example}")
                            else:
                                print(f"  \u2717 {example}")
                    else:
                        return ("Pattern cannot be empty.\n", 1)
                except (EOFError, KeyboardInterrupt):
                    return ("\nCancelled.\n", 1)

    # --- Description (glob is offered as default) ---
    while True:
        try:
            if glob_str:
                prompt = f"\nEnter description [{glob_str}]: "
            else:
                prompt = "\nEnter description: "
            description = input(prompt).strip()
            if not description and glob_str:
                description = glob_str
                break
            elif not description:
                print("Description cannot be empty.")
                continue
            break
        except (EOFError, KeyboardInterrupt):
            return ("\nCancelled.\n", 1)

    try:
        group = input("Group (optional, press Enter to skip): ").strip()
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
        group, [example] if example else [], enabled_flag, protected, dry_run,
        glob_str if glob_str else None, target_file,
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
    glob_str: str | None = None,
    target_file: str | None = None,
) -> tuple[str, int]:
    """Add a pattern via CLI flags."""
    from .config import save_config, append_to_yaml_file
    from .display import success, cross, muted

    # Validate regex
    try:
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        return (
            f"[error]✗[/error] Error: invalid regex '[bold]{pattern}[/bold]': {exc}\n"
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
    if glob_str:
        entry["glob"] = glob_str

    # Resolve target file path for display in dry-run / success output
    target_path = (config_path / target_file) if target_file else None

    if dry_run:
        lines = [
            "[bold]Would add pattern:[/bold]",
            f"  [bold]Type:[/bold] {pattern_type}",
            f"  [bold]Description:[/bold] {description}",
            f"  [bold]Pattern:[/bold] {pattern}"
        ]
        if target_file:
            lines.append(f"  [bold]Target file:[/bold] {target_file}")
        if glob_str:
            lines.append(f"  [bold]Glob:[/bold] {glob_str}")
        lines.extend([
            f"  [bold]Group:[/bold] {group or '(none)'}",
            f"  [bold]Enabled:[/bold] {enabled_flag}",
            f"  [bold]Protected:[/bold] {protected}",
        ])
        return ("\n".join(lines) + "\n", 0)

    if target_file:
        # Write directly to the target file (skip save_config delta).
        # Clean the entry first for proper YAML field order.
        from .config import _clean_for_serialization
        clean_entry = _clean_for_serialization([entry])[0]
        append_to_yaml_file(clean_entry, target_path, section_key)
        # Calculate approximate index for display
        config.setdefault(section_key, []).append(entry)
        index = len(config.get(section_key, [])) + 1  # estimate for display
    else:
        # Normal path: add to merged config and let save_config handle delta
        config.setdefault(section_key, []).append(entry)
        save_config(config, config_path)
        index = len(config.get(section_key, []))

    file_info = f"  [dim]File: {target_file}[/dim]\n" if target_file else ""
    return (
        f"[success]✓[/success] Added {pattern_type} pattern: [bold]\"{description}\"[/bold]\n"
        f"{file_info}"
        f"  Index: [{index}]\n"
        f"{_config_update_reminder()}",
        0,
    )


def cmd_remove(
    target: str | None = None,
    pattern_type: str | None = None,
    dry_run: bool = False,
    force: bool = False,
) -> tuple[str, int]:
    """Remove a pattern interactively or by index/description.

    With no target, launches interactive selection automatically.
    With --force, bypasses the confirmation prompt in non-interactive mode.
    """
    from .config import load_config, resolve_config_path
    from .display import success, cross, muted

    config_path = resolve_config_path()
    if not config_path.exists():
        return (
            f"[error]✗[/error] No config found at [path]{config_path}[/path]\n\n"
            f"Run `hermes custom-dangerous-patterns init` to create a starter config.\n",
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
        return ("[error]✗[/error] No patterns to remove. Config is empty.\n", 1)

    # Go interactive when no target specified
    if target is None:
        return _remove_interactive(config, config_path, all_entries, dry_run)

    return _remove_by_target(config, config_path, all_entries, target, pattern_type, dry_run, force)


def _remove_interactive(
    config: dict[str, Any],
    config_path: Path,
    all_entries: list[dict[str, Any]],
    dry_run: bool,
) -> tuple[str, int]:
    """Interactive pattern removal with numbered selection."""
    from .config import save_config, remove_entry_from_file
    from .display import _console
    from rich.text import Text

    _console.print()
    _console.print("Select pattern to remove:")
    _console.print()

    section_styles = {
        "patterns": "yellow",
        "allow_patterns": "green",
        "deny_patterns": "red",
    }
    section_labels = {
        "patterns": "BLOCK",
        "allow_patterns": "ALLOW",
        "deny_patterns": "DENY",
    }

    for section_key in ("patterns", "allow_patterns", "deny_patterns"):
        entries = [e for e in all_entries if e["_section"] == section_key]
        if not entries:
            continue
        colour = section_styles[section_key]
        label = section_labels[section_key]
        _console.print(f"[{colour} bold]\u25c6 {label}[/{colour} bold] patterns")
        for e in entries:
            idx = get_index(e, all_entries)
            is_enabled = e.get("enabled", True)
            is_protected = e.get("protected", False)
            line = Text()
            line.append(f"  [{idx}] ")
            if is_enabled:
                line.append("\u2713 ", style="success")
            else:
                line.append("\u2717 ", style="error")
            line.append(e["description"])
            if is_protected:
                line.append(" \U0001f512", style="bold yellow")
            grp = e.get("group", "")
            if grp:
                line.append(f"  group: {grp}", style="dim")
            _console.print(line)
        _console.print()

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

    # Delete from source YAML file first (lines gone, no remnant)
    remove_entry_from_file(entry, config_path)

    # Remove from config (by index — entry is the original with _section)
    section = config.get(entry["_section"], [])
    section.pop(section.index(entry))
    _cleanup_sections(all_entries)
    save_config(config, config_path)

    return (
        f"\u2713 Removed {type_label} pattern [{idx}]: \"{entry['description']}\"\n"
        f"The pattern is permanently deleted.\n"
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
    force: bool = False,
) -> tuple[str, int]:
    """Non-interactive pattern removal by index or description match.

    Shows the matched pattern and requests confirmation before removing,
    unless --force is passed.
    """
    from .config import save_config, remove_entry_from_file
    from .display import _console

    try:
        from rich.markup import escape as _rich_escape
    except ImportError:
        _rich_escape = lambda s: s  # type: ignore

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
            lines = [f"[warning]⚠[/warning] Multiple patterns match '[bold]{target}[/bold]'. Use index or be more specific:"]
            for e in matched:
                idx = get_index(e, all_entries)
                type_label = e["_section"].replace("_patterns", "").upper()
                is_enabled = e.get("enabled", True)
                is_protected = e.get("protected", False)
                status = "[success]✓[/success]" if is_enabled else "[error]✗[/error]"
                prot = " [bold yellow]🔒[/bold yellow]" if is_protected else ""
                desc_safe = _rich_escape(e["description"])
                lines.append(f"  [{idx}] [bold]{type_label}:[/bold] {status} {desc_safe}{prot}")
            return ("\n".join(lines) + "\n", 1)

    if not matched:
        return (f"[warning]⚠[/warning] No patterns matched '[bold]{target}'.\n", 1)

    entry = matched[0]
    eidx = get_index(entry, all_entries)
    type_label = entry["_section"].replace("_patterns", "").upper()

    # Check protected
    if entry.get("protected"):
        return (
            f"[error]✗[/error] Pattern [{eidx}] [bold]\"{entry['description']}\"[/bold] is protected.\n"
            f"Edit the config file directly to remove protected patterns.\n",
            1,
        )

    if dry_run:
        return (
            f"[bold]Would remove {type_label} pattern [{eidx}]:[/bold] [bold]\"{entry['description']}\"[/bold]\n"
            f"Use without --dry-run to confirm.\n",
            0,
        )

    # Show matched pattern and request confirmation (unless --force)
    if not force:
        desc_safe = _rich_escape(entry["description"])
        _console.print()
        _console.print(
            f"[bold]Matched pattern:[/bold] [{eidx}] "
            f"[bold]{type_label}:[/bold] {desc_safe}"
        )
        try:
            confirm = input(
                f"Remove this pattern? This cannot be undone. [y/N]: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return ("\nCancelled.\n", 1)
        if confirm != "y":
            return ("Cancelled.\n", 0)

    # Delete from source YAML file first (lines gone, no remnant)
    remove_entry_from_file(entry, config_path)

    section = config.get(entry["_section"], [])
    section.pop(section.index(entry))
    _cleanup_sections(all_entries)
    save_config(config, config_path)

    return (
        f"[success]✓[/success] Removed {type_label} pattern [{eidx}]: [bold]\"{entry['description']}\"[/bold]\n"
        f"[dim]The pattern is permanently deleted.[/dim]\n"
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
        pattern_type=getattr(args, "type", None),
        pattern=getattr(args, "pattern", None),
        description=getattr(args, "description", None),
        group=getattr(args, "group", None),
        examples=getattr(args, "examples", None),
        enabled_flag=not getattr(args, "disabled", False),
        protected=getattr(args, "protected", False),
        dry_run=getattr(args, "dry_run", False),
        glob_str=getattr(args, "glob", None),
        target_file=getattr(args, "target", None),
    )
    _emit(output, exit_code)


def _handle_remove(args: Any) -> None:
    output, exit_code = cmd_remove(
        target=getattr(args, "target", None),
        pattern_type=getattr(args, "type", None),
        dry_run=getattr(args, "dry_run", False),
        force=getattr(args, "force", False),
    )
    _emit(output, exit_code)


def _emit(output: str, exit_code: int) -> None:
    """Print output and exit with the given code.

    Renders Rich markup through the display module's Console so that
    styled output (colours, headings) appears on TTYs and degrades
    gracefully to plain text when piped or not a TTY.
    """
    if output:
        from .display import render_and_print

        render_and_print(output)
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
    lines = ["[bold cyan]BUILT-IN patterns (Hermes):[/bold cyan]"]
    shown = 0
    for pat, desc in _BUILTIN_PATTERNS:
        if (
            search_term
            and search_term.lower() not in desc.lower()
            and search_term.lower() not in pat.lower()
        ):
            continue
        shown += 1
        lines.append(f"  [[dim]{shown}[/dim]] [cyan][Hermes][/cyan] {desc}")
    if shown == 0:
        lines.append("  [muted](no built-in patterns match the filter)[/muted]")
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
        "\n[dim]Remember to restart the Hermes gateway and any active CLI/TUI sessions\n"
        "for changes to take effect.[/dim]"
    )


# ---------------------------------------------------------------------------
# CLI registration — called by __init__.py via ctx.register_cli_command()
# ---------------------------------------------------------------------------


def register_cli(subparser: argparse.ArgumentParser) -> None:
    """Build the ``hermes custom-dangerous-patterns`` argparse tree.

    Called by __init__.py at plugin load time via ctx.register_cli_command().
    Sets up sub-subcommands: list, test, init, enable, disable, validate,
    info, logs, add, remove.
    """
    subs = subparser.add_subparsers(dest="cdp_command")

    # -- list --
    list_p = subs.add_parser("list", help="List custom patterns")
    list_p.add_argument(
        "-t", "--type", dest="type",
        choices=["block", "allow", "deny"],
        help="Filter by pattern type",
    )
    list_p.add_argument("-g", "--group", help="Filter by group name")
    list_p.add_argument("-s", "--search", help="Search in description/pattern")
    list_p.add_argument(
        "--disabled", action="store_true", help="Show only disabled patterns"
    )
    list_p.add_argument(
        "--enabled", action="store_true", help="Show only enabled patterns"
    )
    list_p.add_argument(
        "--builtins", action="store_true",
        help="Also show Hermes built-in patterns",
    )
    list_p.set_defaults(func=_handle_list)

    # -- test --
    test_p = subs.add_parser(
        "test", help="Test a command against all pattern types"
    )
    test_p.add_argument("command", help="Command string to test")
    test_p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Show matched regex patterns",
    )
    test_p.add_argument(
        "--skip-builtins", action="store_true",
        help="Skip built-in Hermes patterns",
    )
    test_p.set_defaults(func=_handle_test)

    # -- init --
    init_p = subs.add_parser(
        "init", help="Create a starter config file"
    )
    init_p.add_argument(
        "--with-examples", action="store_true",
        help="Include fully-enabled example patterns",
    )
    init_p.add_argument(
        "-f", "--force", action="store_true",
        help="Overwrite existing config",
    )
    init_p.set_defaults(func=_handle_init)

    # -- enable --
    enable_p = subs.add_parser("enable", help="Enable patterns")
    enable_p.add_argument(
        "target", nargs="?", default=None,
        help="Pattern index or description substring",
    )
    enable_p.add_argument(
        "-t", "--type", dest="type",
        choices=["block", "allow", "deny"],
        help="Filter by pattern type",
    )
    enable_p.add_argument("-g", "--group", help="Enable all patterns in group")
    enable_p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without saving",
    )
    enable_p.set_defaults(func=_handle_enable)

    # -- disable --
    disable_p = subs.add_parser("disable", help="Disable patterns")
    disable_p.add_argument(
        "target", nargs="?", default=None,
        help="Pattern index or description substring",
    )
    disable_p.add_argument(
        "-t", "--type", dest="type",
        choices=["block", "allow", "deny"],
        help="Filter by pattern type",
    )
    disable_p.add_argument("-g", "--group", help="Disable all patterns in group")
    disable_p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would change without saving",
    )
    disable_p.set_defaults(func=_handle_disable)

    # -- validate --
    validate_p = subs.add_parser(
        "validate", help="Validate config syntax and regexes"
    )
    validate_p.add_argument(
        "path", nargs="?", default=None,
        help="Config path (default: auto-detect)",
    )
    validate_p.add_argument(
        "-q", "--quiet", action="store_true",
        help="Exit code only, no output",
    )
    validate_p.set_defaults(func=_handle_validate)

    # -- info --
    info_p = subs.add_parser("info", help="Show plugin state dashboard")
    info_p.set_defaults(func=_handle_info)

    # -- logs --
    logs_p = subs.add_parser(
        "logs", help="Show plugin log entries"
    )
    logs_p.add_argument(
        "-l", "--level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Filter by log level",
    )
    logs_p.add_argument(
        "-n", "--limit", type=int, default=100,
        help="Max entries to show (default: 100)",
    )
    logs_p.add_argument(
        "--since", default=None,
        help="Show entries since timestamp (e.g. '2h', '30m')",
    )
    logs_p.add_argument(
        "-f", "--follow", action="store_true",
        help="Follow log file (tail -f)",
    )
    logs_p.set_defaults(func=_handle_logs)

    # -- add --
    add_p = subs.add_parser("add", help="Add a custom pattern")
    add_p.add_argument(
        "-t", "--type", dest="type",
        choices=["block", "allow", "deny"],
        help="Pattern type (required in non-interactive mode)",
    )
    add_p.add_argument(
        "-p", "--pattern", default=None,
        help="Regex pattern (required in non-interactive mode)",
    )
    add_p.add_argument(
        "-d", "--description", default=None,
        help="Description (required in non-interactive mode)",
    )
    add_p.add_argument("-g", "--group", default=None, help="Group name")
    add_p.add_argument(
        "--examples", nargs="+", default=None,
        help="Example commands that match this pattern",
    )
    add_p.add_argument(
        "--disabled", action="store_true",
        help="Add pattern as disabled (default: enabled)",
    )
    add_p.add_argument(
        "--protected", action="store_true",
        help="Protect pattern from enable/disable/remove",
    )
    add_p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be added without saving",
    )
    add_p.add_argument(
        "--glob", default=None,
        help="Glob-style pattern (e.g. 'echo hello'). Converted to regex. "
             "Mutually exclusive with --pattern.",
    )
    add_p.add_argument(
        "--target", default=None,
        help="Write to a specific .yaml file in the config directory "
             "(requires directory mode; file must have .yaml extension)",
    )
    add_p.set_defaults(func=_handle_add)

    # -- remove --
    remove_p = subs.add_parser("remove", help="Remove a custom pattern")
    remove_p.add_argument(
        "target", nargs="?", default=None,
        help="Pattern index or description substring",
    )
    remove_p.add_argument(
        "-t", "--type", dest="type",
        choices=["block", "allow", "deny"],
        help="Filter by pattern type",
    )
    remove_p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be removed without saving",
    )
    remove_p.add_argument(
        "--force", action="store_true",
        help="Skip confirmation prompt",
    )
    remove_p.set_defaults(func=_handle_remove)

