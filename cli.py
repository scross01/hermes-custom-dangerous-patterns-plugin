"""CLI command handlers for hermes custom-patterns (v0.3.0).

Pure config management and introspection — no monkey-patching, no Hermes
runtime dependencies. Each command handler is a standalone function that
operates on config dicts and returns (output: str, exit_code: int).

The register_subcommands() function is the entry point called by
ctx.register_cli_command() in __init__.py.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
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
    """Test a command against all pattern types."""
    # Stub — implemented in Chunk 3
    return ("test: not yet implemented\n", 1)


def cmd_init(
    with_examples: bool = False,
    force: bool = False,
) -> tuple[str, int]:
    """Create a starter config file."""
    # Stub — implemented in Chunk 4
    return ("init: not yet implemented\n", 1)


def cmd_enable(
    target: str | None = None,
    pattern_type: str | None = None,
    group: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Enable patterns by index, description, or group."""
    # Stub — implemented in Chunk 6
    return ("enable: not yet implemented\n", 1)


def cmd_disable(
    target: str | None = None,
    pattern_type: str | None = None,
    group: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Disable patterns by index, description, or group."""
    # Stub — implemented in Chunk 6
    return ("disable: not yet implemented\n", 1)


def cmd_validate(
    path: str | None = None,
    quiet: bool = False,
) -> tuple[str, int]:
    """Validate config syntax and regexes."""
    # Stub — implemented in Chunk 6
    return ("validate: not yet implemented\n", 1)


def cmd_info() -> tuple[str, int]:
    """Show plugin configuration dashboard."""
    # Stub — implemented in Chunk 6
    return ("info: not yet implemented\n", 1)


def cmd_logs(
    level: str | None = None,
    limit: int = 100,
    since: str | None = None,
    follow: bool = False,
) -> tuple[str, int]:
    """Show plugin-specific log entries."""
    # Stub — implemented in Chunk 7
    return ("logs: not yet implemented\n", 1)


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
    """Add a pattern interactively or via flags."""
    # Stub — implemented in Chunk 9
    return ("add: not yet implemented\n", 1)


def cmd_remove(
    target: str | None = None,
    interactive: bool = False,
    pattern_type: str | None = None,
    dry_run: bool = False,
) -> tuple[str, int]:
    """Remove a pattern interactively or by index/description."""
    # Stub — implemented in Chunk 9
    return ("remove: not yet implemented\n", 1)


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


def _config_update_reminder() -> str:
    """Return the standard reminder for config changes."""
    return (
        "\nRemember to restart the Hermes gateway and any active CLI/TUI sessions\n"
        "for changes to take effect.\n"
    )



