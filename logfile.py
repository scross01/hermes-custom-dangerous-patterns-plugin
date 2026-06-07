"""Dedicated match log file for custom-dangerous-patterns.

Writes structured JSONL entries to ``~/.hermes/logs/custom-dangerous-patterns.log``
every time a command is matched by a custom pattern, including the command
text, pattern type, description, regex, and user's selection when available.

Log rotation: when the file exceeds 10 MB, it is rotated (``.log.1`` → ``.log.5``).

This is separate from Hermes's main log — it captures only custom-dangerous-
patterns match events in a machine-readable format.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_LOG_DIR = Path.home() / ".hermes" / "logs"
_LOG_FILE = _LOG_DIR / "custom-dangerous-patterns.log"
_MAX_LOG_BYTES = 10 * 1024 * 1024  # 10 MB


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_log_dir() -> None:
    """Create the log directory if it doesn't exist."""
    _LOG_DIR.mkdir(parents=True, exist_ok=True)


def _rotate() -> None:
    """Rotate the log file if it exceeds the maximum size.

    Keeps at most 5 rotated files (``.log.1`` … ``.log.5``).
    """
    if not _LOG_FILE.is_file():
        return
    file_size = _LOG_FILE.stat().st_size
    if file_size <= _MAX_LOG_BYTES:
        return
    for i in range(4, 0, -1):
        old = _LOG_FILE.with_suffix(f".log.{i}")
        new = _LOG_FILE.with_suffix(f".log.{i + 1}")
        if old.is_file():
            old.rename(new)
    _LOG_FILE.rename(_LOG_FILE.with_suffix(".log.1"))


# ---------------------------------------------------------------------------
# Reader — parse match log entries for the CLI logs command
# ---------------------------------------------------------------------------


def read_match_log_entries(
    limit: int = 100,
    since_dt: datetime | None = None,
) -> list[dict[str, Any]]:
    """Read and parse entries from the match log file.

    Returns entries in chronological order (earliest first) with
    ``timestamp``, ``level``, and ``message`` keys, compatible with
    the format used by :func:`logs.extract_logs`.

    Args:
        limit: Maximum number of entries to return (most recent).
        since_dt: If provided, only entries after this datetime.

    Returns:
        List of dicts with ``timestamp``, ``level``, ``message`` keys.
        Empty list if the file doesn't exist or is unreadable.
    """
    if not _LOG_FILE.is_file():
        return []

    entries: list[dict[str, Any]] = []

    try:
        with open(_LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Parse timestamp (ISO-8601) -> YYYY-MM-DD HH:MM:SS
                raw_ts = data.get("timestamp", "")
                try:
                    dt = datetime.fromisoformat(raw_ts)
                    ts_str = dt.strftime("%Y-%m-%d %H:%M:%S") + f",{dt.microsecond // 1000:03d}"
                except (ValueError, TypeError):
                    continue

                # Filter by date
                if since_dt is not None and dt.replace(tzinfo=None) < since_dt:
                    continue

                # Build a human-readable message
                match_type = data.get("type", "unknown")
                cmd = data.get("command", "")
                pattern_desc = data.get("pattern", {}).get("description", "")
                pattern_regex = data.get("pattern", {}).get("regex", "")
                user_selection = data.get("user_selection")

                parts = [f"[{match_type.upper()}] {cmd}"]
                parts.append(f"matched '{pattern_desc}' ({pattern_regex})")
                if user_selection:
                    parts.append(f"→ user selection: {user_selection}")

                entries.append({
                    "timestamp": ts_str,
                    "level": "MATCH",
                    "source": _LOG_FILE.name,
                    "message": " ".join(parts),
                })
    except OSError:
        return []

    # Sort earliest first, return most recent `limit` entries
    entries.sort(key=lambda e: e["timestamp"])
    return entries[-limit:]


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


def log_match(
    command: str,
    match_type: str,
    pattern_description: str,
    pattern_regex: str,
    user_selection: str | None = None,
) -> None:
    """Write a structured JSONL entry for a pattern match.

    The entry is a JSON object with keys:
      - ``timestamp``: ISO-8601 local timestamp (consistent with Hermes logs)
      - ``event``: always ``"pattern_match"``
      - ``command``: the matched command string
      - ``type``: ``"allow"``, ``"block"``, or ``"deny"``
      - ``pattern.description``: human-readable pattern name
      - ``pattern.regex``: the regex string that matched
      - ``user_selection``: (optional) ``"once"``, ``"session"``, ``"always"``,
        or ``"deny"`` — only present for block patterns where an approval
        prompt was shown

    Args:
        command: The command string that was matched.
        match_type: ``'allow'``, ``'block'``, or ``'deny'``.
        pattern_description: Human-readable description of the matched pattern.
        pattern_regex: The regex pattern string that matched.
        user_selection: User's choice from the approval prompt, if available.
                        ``None`` for allow/deny patterns where no interactive
                        selection is involved.
    """
    _ensure_log_dir()
    _rotate()

    entry: dict[str, Any] = {
        "timestamp": datetime.now().isoformat(),
        "event": "pattern_match",
        "command": command,
        "type": match_type,
        "pattern": {
            "description": pattern_description,
            "regex": pattern_regex,
        },
    }
    if user_selection is not None:
        entry["user_selection"] = user_selection

    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning(
            "custom-dangerous-patterns: failed to write match log: %s", exc
        )
