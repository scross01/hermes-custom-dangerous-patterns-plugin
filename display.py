"""Terminal display formatting using Rich.

Provides consistent styled output for all CLI commands, matching the
visual style of Hermes's built-in commands (status, doctor). Uses Rich
for color, panels, and layout.

Auto-degrades to plain text when stdout is not a TTY (tests, pipes) by
stripping Rich markup tags. This ensures tests get clean output without
needing to call _emit().
"""

from __future__ import annotations

import re
import sys
from typing import Any

# ── Rich availability check ──────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.theme import Theme
    from rich import box

    _has_rich = True
except ImportError:
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Text = None  # type: ignore
    Theme = None  # type: ignore
    box = None  # type: ignore
    _has_rich = False

# ── Theme & Console (only if Rich available) ─────────────────────────────

if _has_rich:
    _HERMES_THEME = Theme({
        "heading": "bold cyan",
        "subheading": "bold cyan",
        "section": "bold cyan",
        "info": "dim cyan",
        "success": "bold green",
        "error": "bold red",
        "warning": "bold yellow",
        "match": "green",
        "no_match": "dim",
        "label": "bold",
        "value": "white",
        "index": "dim cyan",
        "path": "dim",
        "muted": "dim",
        "highlight": "bold white",
    })
    _console = Console(theme=_HERMES_THEME, highlight=False)
else:
    _HERMES_THEME = None  # type: ignore
    _console = None  # type: ignore

# ── Markup stripping ─────────────────────────────────────────────────────

_MARKUP_RE = re.compile(r"\[/?[a-z_ ]+(?: [^\]]*)?\]")


def _strip_markup(text: str) -> str:
    """Strip all Rich markup tags from a string.

    Handles Rich's [[ escape syntax (literal opening bracket) before
    stripping markup tags, so escaped content like [[o]nce survives.
    """
    # First, resolve Rich escapes: [[ → [
    text = text.replace("[[", "[")
    # Then strip remaining markup tags
    return _MARKUP_RE.sub("", text)


def should_strip() -> bool:
    """Return True if markup should be stripped (non-TTY or no Rich)."""
    if not _has_rich:
        return True
    return not _console.is_terminal


# Backward-compatible alias
_should_strip = should_strip


def styled(text: str, fallback: str | None = None) -> str:
    """Return Rich markup when TTY, stripped text otherwise.

    Args:
        text: The Rich-markup string.
        fallback: Optional separate plain-text version. If None,
                  strips markup from `text`.
    """
    if should_strip():
        return fallback if fallback is not None else _strip_markup(text)
    return text


# Backward-compatible alias
_s = styled


# ── Headings ─────────────────────────────────────────────────────────────

def heading(title: str, subtitle: str | None = None) -> str:
    """Return a boxed heading panel string.

    Uses Rich Panel when available and TTY. Falls back to a simple
    text heading with separator lines.
    """
    if should_strip():
        width = len(title) + 4
        line = "━" * width
        lines = [line, f"  {title}", line]
        if subtitle:
            lines.insert(2, f"  {_strip_markup(subtitle)}")
        return "\n".join(lines)

    content = Text()
    content.append(title, style="heading")
    if subtitle:
        content.append("\n")
        content.append(subtitle, style="info")

    panel = Panel(
        content,
        box=box.SQUARE,
        border_style="cyan",
        padding=(0, 1),
        expand=False,
    )
    return _render(panel)


def subheading(text: str) -> str:
    """Return a section subheading."""
    return _s(
        f"\n[subheading]◆ {text}[/subheading]",
        f"\n◆ {text}",
    )


def section(text: str) -> str:
    """Return a bold section label."""
    return _s(f"[section]{text}[/section]", text)


# ── Status indicators ────────────────────────────────────────────────────

def success(text: str) -> str:
    return _s(f"  [success]✓[/success] {text}", f"  ✓ {text}")


def error(text: str) -> str:
    return _s(f"  [error]✗[/error] {text}", f"  ✗ {text}")


def warning(text: str) -> str:
    return _s(f"  [warning]⚠[/warning] {text}", f"  ⚠ {text}")


def check(text: str) -> str:
    return _s(f"[success]✓[/success] {text}", f"✓ {text}")


def cross(text: str) -> str:
    return _s(f"[error]✗[/error] {text}", f"✗ {text}")


def warn_mark(text: str) -> str:
    return _s(f"[warning]⚠[/warning] {text}", f"⚠ {text}")


# ── Content formatting ───────────────────────────────────────────────────

def key_value(key: str, value: str, indent: int = 2) -> str:
    space = " " * indent
    return _s(
        f"{space}[label]{key}:[/label] {value}",
        f"{space}{key}: {value}",
    )


def pattern_entry(
    index: int,
    enabled: bool,
    description: str,
    group: str = "",
    type_label: str = "",
    indent: int = 2,
) -> str:
    """Return a formatted pattern entry line."""
    space = " " * indent
    if enabled:
        status = _s("[success]✓[/success]", "✓")
    else:
        status = _s("[error]✗[/error]", "✗")

    # Escape user data that might contain Rich-tag-like brackets (e.g. [TEST])
    if _has_rich and not should_strip():
        from rich.markup import escape as _rich_escape
        desc_safe = _rich_escape(description)
        grp_safe = _rich_escape(group) if group else ""
    else:
        desc_safe = description
        grp_safe = group

    parts = [f"{space}[{index}]", status, desc_safe]
    if type_label:
        parts.append(_s(f"[dim]({type_label})[/dim]", f"({type_label})"))
    if grp_safe:
        parts.append(_s(f"[muted]group: {grp_safe}[/muted]", f"group: {grp_safe}"))

    return " ".join(parts)


def muted(text: str) -> str:
    return _s(f"[muted]{text}[/muted]", text)


def bold(text: str) -> str:
    return _s(f"[bold]{text}[/bold]", text)


# ── Result panels ────────────────────────────────────────────────────────

def result_panel(title: str, subtitle: str, colour: str) -> str:
    """Return a colored result panel for the test command.

    On TTY: Rich Panel with colored border. On non-TTY: plain text.
    """
    if should_strip():
        return f"\n{'─' * (len(title) + 6)}\n  {title}\n  {subtitle}\n{'─' * (len(title) + 6)}\n"

    content = Text()
    content.append(title, style=f"bold {colour}")
    content.append("\n")
    content.append(subtitle, style="dim")

    panel = Panel(
        content,
        box=box.SQUARE,
        border_style=colour,
        padding=(0, 1),
        expand=False,
    )
    return _render(panel)


# ── Divider ──────────────────────────────────────────────────────────────

def divider() -> str:
    return _s("[dim]" + "─" * 60 + "[/dim]", "─" * 60)


# ── Config path display ──────────────────────────────────────────────────

def path_info(label: str, path: str) -> str:
    return _s(
        f"  [label]{label}:[/label] [path]{path}[/path]",
        f"  {label}: {path}",
    )


# ── Internal rendering ───────────────────────────────────────────────────

def _render(renderable: Any) -> str:
    """Render a Rich renderable to a string."""
    if not _has_rich:
        if hasattr(renderable, "renderable"):
            return str(getattr(renderable, "renderable", renderable))
        return str(renderable)

    from io import StringIO

    buf = StringIO()
    tmp = Console(file=buf, force_terminal=_console.is_terminal)
    tmp.print(renderable)
    return buf.getvalue().rstrip("\n")


def render_and_print(text: str) -> None:
    """Render a Rich-markup string to stdout.

    On TTY: processes Rich markup with colors/styles via Console.
    On non-TTY or no Rich: strips markup and prints plain text.

    Prints the whole text at once so multiline markup (e.g. [dim]...
    spanning multiple lines ...[/dim]) is parsed correctly.
    """
    if not text:
        return

    if should_strip():
        for line in text.split("\n"):
            sys.stdout.write(_strip_markup(line) + "\n")
        return

    _console.print(text)
