"""Log extraction and filtering for the custom-dangerous-patterns plugin (v0.3.0).

Extracts plugin-specific log entries from the Hermes log file at
~/.hermes/logs/hermes.log. Supports level filtering, date filtering,
limit, and follow (tail -f) mode.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

# Default Hermes log location
_DEFAULT_LOG_PATH = Path.home() / ".hermes" / "logs" / "hermes.log"

# Pattern to identify plugin-specific log entries.
# Matches the logger format used by the plugin: logger.info("custom-dangerous-patterns: ...")
_PLUGIN_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\[(?P<level>[A-Z]+)\]"
    r".*custom-dangerous-patterns:\s+(?P<message>.*)$"
)


def extract_logs(
    log_path: Path | None = None,
    level: str | None = None,
    limit: int = 100,
    since: str | None = None,
) -> list[dict[str, Any]]:
    """Extract plugin-specific log entries from the Hermes log file.

    Args:
        log_path: Path to the Hermes log file. Defaults to ~/.hermes/logs/hermes.log.
        level: Minimum log level filter (e.g., "WARNING", "ERROR", "CRITICAL").
        limit: Maximum number of entries to return (most recent first).
        since: Date string (YYYY-MM-DD) for entries after this date.

    Returns:
        List of dicts with 'timestamp', 'level', and 'message' keys.
    """
    if log_path is None:
        log_path = _DEFAULT_LOG_PATH

    if not log_path.is_file():
        return []

    entries: list[dict[str, Any]] = []
    since_dt = _parse_since(since) if since else None

    _level_rank = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    min_rank = _level_rank.get(level.upper(), 0) if level else 0

    try:
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                m = _PLUGIN_LOG_PATTERN.search(line)
                if not m:
                    continue

                ts_str = m.group("timestamp")
                entry_level = m.group("level")
                message = m.group("message")

                # Level filter
                entry_rank = _level_rank.get(entry_level, 0)
                if entry_rank < min_rank:
                    continue

                # Date filter
                if since_dt is not None:
                    try:
                        entry_dt = datetime.strptime(
                            ts_str.strip(), "%Y-%m-%d %H:%M:%S"
                        )
                        if entry_dt < since_dt:
                            continue
                    except ValueError:
                        pass

                entries.append({
                    "timestamp": ts_str.strip(),
                    "level": entry_level,
                    "message": message,
                })
    except OSError:
        return []

    # Return most recent first, limited
    return entries[-limit:][::-1]


def follow_logs(log_path: Path | None = None) -> None:
    """Tail the Hermes log file and print plugin entries in real time.

    Blocks until interrupted (Ctrl+C). Intended for use from the CLI.
    """
    import time

    if log_path is None:
        log_path = _DEFAULT_LOG_PATH

    if not log_path.is_file():
        print(f"No Hermes log file found at {log_path}")
        return

    try:
        with open(log_path, encoding="utf-8") as f:
            f.seek(0, 2)  # Move to end of file
            while True:
                line = f.readline()
                if line:
                    m = _PLUGIN_LOG_PATTERN.search(line)
                    if m:
                        print(line.rstrip())
                else:
                    time.sleep(0.5)
    except KeyboardInterrupt:
        pass


def format_log_entries(
    entries: list[dict[str, Any]],
    level: str | None = None,
) -> list[str]:
    """Format log entries for display.

    Returns a list of strings ready for printing.
    """
    if not entries:
        return ["No plugin-specific log entries found."]

    lines: list[str] = []
    for entry in entries:
        ts = entry["timestamp"]
        lvl = entry["level"]
        msg = entry["message"]
        lines.append(f"[{ts}] [{lvl}] [Plugin] {msg}")

    return lines


def _parse_since(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD date string into a datetime.

    Returns datetime at 00:00:00 of that day.
    """
    return datetime.strptime(date_str.strip(), "%Y-%m-%d")


def get_default_log_path() -> Path:
    """Return the default path to the Hermes log file."""
    return _DEFAULT_LOG_PATH
