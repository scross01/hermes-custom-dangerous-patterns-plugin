"""Log extraction and filtering for the custom-dangerous-patterns plugin.

Extracts plugin-specific log entries from all *.log files under
~/.hermes/logs/. Supports level filtering, date filtering,
limit, and follow (tail -f) mode.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

# Default Hermes log directory (contains agent.log, errors.log, gateway.log, etc.)
_DEFAULT_LOG_PATH = Path.home() / ".hermes" / "logs"

# Match log filename (written by logfile.log_match)
_MATCH_LOG_FILENAME = "custom-dangerous-patterns.log"

# Pattern to identify plugin-specific log entries.
# Matches the logger format used by the plugin: logger.info("custom-dangerous-patterns: ...")
_PLUGIN_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)"
    r"\s+(?P<level>[A-Z]+)"
    r"\s+.*custom-dangerous-patterns:\s+(?P<message>.*)$"
)


def extract_logs(
    log_path: Path | None = None,
    level: str | None = None,
    limit: int = 100,
    since: str | None = None,
    include_match_log: bool = True,
) -> list[dict[str, Any]]:
    """Extract plugin-specific log entries from Hermes logs and the match log.

    Scans all ``*.log`` files under the Hermes log directory for
    ``custom-dangerous-patterns:`` prefixed entries (Hermes's standard
    Python logging). Also reads the dedicated match log
    (``custom-dangerous-patterns.log``) if **include_match_log** is True.

    All entries are merged, sorted chronologically (earliest first), and
    the most recent **limit** entries are returned.

    Args:
        log_path: Path to the Hermes log directory. Defaults to ``~/.hermes/logs``.
        level: Minimum log level filter (e.g. ``"WARNING"``, ``"ERROR"``).
        limit: Maximum number of entries to return (most recent, max 10000).
        since: Date string (``YYYY-MM-DD``) for entries after this date.
        include_match_log: Whether to include entries from the dedicated
                           match log file. Defaults to True.

    Returns:
        List of dicts with ``'timestamp'``, ``'level'``, and ``'message'`` keys,
        sorted earliest to latest.
    """
    if log_path is None:
        log_path = _DEFAULT_LOG_PATH

    if not log_path.is_dir():
        return []

    entries: list[dict[str, Any]] = []
    since_dt = _parse_since(since) if since else None
    limit = min(limit, 10000)  # Sanity cap

    _level_rank = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4}
    min_rank = _level_rank.get(level.upper(), 0) if level else 0

    # 1. Extract from Hermes *.log files (standard Python logging)
    log_files = sorted(
        [
            f for f in log_path.glob("*.log") if f.is_file()
            and f.name != _MATCH_LOG_FILENAME
        ],
        key=lambda p: p.stat().st_mtime,
    )

    for log_file in log_files:
        try:
            with open(log_file, encoding="utf-8", errors="replace") as f:
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
                        "source": log_file.name,
                        "message": message,
                    })
        except OSError:
            continue

    # 2. Extract from the dedicated match log (JSONL)
    if include_match_log:
        try:
            from .logfile import read_match_log_entries
            match_entries = read_match_log_entries(
                limit=limit,
                since_dt=since_dt,
            )
            entries.extend(match_entries)
        except ImportError:
            pass  # Gracefully degrade if logfile module isn't available

    # 3. Sort chronologically (earliest first), return most recent `limit`
    entries.sort(key=lambda e: e["timestamp"])
    return entries[-limit:]


def follow_logs(log_path: Path | None = None) -> None:
    """Tail the most recent Hermes log file and print plugin entries in real time.

    Blocks until interrupted (Ctrl+C). Follows the most recently modified
    *.log file in the Hermes log directory. Intended for use from the CLI.
    """
    import time

    if log_path is None:
        log_path = _DEFAULT_LOG_PATH

    if not log_path.is_dir():
        print(f"Hermes log directory not found at {log_path}")
        return

    # Find the most recently modified *.log file
    log_files = sorted(
        [f for f in log_path.glob("*.log") if f.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not log_files:
        print(f"No *.log files found in {log_path}")
        return

    target = log_files[0]
    print(f"Following: {target.name} (Ctrl+C to stop)")

    try:
        with open(target, encoding="utf-8", errors="replace") as f:
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

    Entries from the Hermes standard log are labelled ``[Plugin]``.
    Entries from the dedicated match log (``MATCH`` level) are labelled
    ``[Match]`` to distinguish them visually.

    Returns a list of :class:`rich.text.Text` objects ready for printing,
    earliest first.  Using ``Text`` avoids Rich markup misinterpreting
    square brackets in source filenames (e.g. ``[agent.log]``).
    """
    from rich.text import Text

    if not entries:
        return ["No plugin-specific log entries found."]

    lines = []
    for entry in entries:
        ts = entry["timestamp"]
        lvl = entry["level"]
        msg = entry["message"]
        src = entry.get("source", "")

        t = Text()
        t.append(f"[{ts}] ")
        if src:
            t.append(f"[{src}]")
            t.append(" ")
        if lvl == "MATCH":
            t.append(f"[{lvl}] [Match] {msg}")
        else:
            t.append(f"[{lvl}] [Plugin] {msg}")
        lines.append(t)

    return lines


def _parse_since(date_str: str) -> datetime:
    """Parse a YYYY-MM-DD date string into a datetime.

    Returns datetime at 00:00:00 of that day.
    """
    return datetime.strptime(date_str.strip(), "%Y-%m-%d")


def get_default_log_path() -> Path:
    """Return the default path to the Hermes log directory (~/.hermes/logs/)."""
    return _DEFAULT_LOG_PATH
