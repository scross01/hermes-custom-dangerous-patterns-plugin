"""Tests for logfile.py (match-log writer/reader/rotation) and logs.py
(the `logs` CLI command's extraction/filtering/formatting).

Both modules read module-level path globals (_LOG_DIR / _LOG_FILE in
logfile.py, _DEFAULT_LOG_PATH in logs.py). The fixture below loads them
under the hermes_plugins package (logs.py uses a deferred relative import
`from .logfile import ...`) and redirects those globals to a tmp dir so
no real ~/.hermes state is touched.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest


@pytest.fixture
def logs_modules(monkeypatch, tmp_path):
    """Load logfile.py and logs.py under hermes_plugins.* with tmp log paths."""
    plugin_dir = Path(__file__).resolve().parent.parent

    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = [str(plugin_dir)]
    monkeypatch.setitem(sys.modules, "hermes_plugins", pkg)

    modules = {}
    for name in ("logfile", "logs"):
        spec = importlib.util.spec_from_file_location(
            f"hermes_plugins.{name}", plugin_dir / f"{name}.py"
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"hermes_plugins.{name}", mod)
        spec.loader.exec_module(mod)
        modules[name] = mod

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    match_log = log_dir / "custom-dangerous-patterns.log"

    # Redirect every module-level path global to the tmp dir.
    monkeypatch.setattr(modules["logfile"], "_LOG_DIR", log_dir)
    monkeypatch.setattr(modules["logfile"], "_LOG_FILE", match_log)
    monkeypatch.setattr(modules["logs"], "_DEFAULT_LOG_PATH", log_dir)

    return types.SimpleNamespace(
        logfile=modules["logfile"], logs=modules["logs"],
        log_dir=log_dir, match_log=match_log,
    )


def _write_match_line(match_log: Path, ts_iso: str, **fields) -> None:
    """Append a single controlled JSONL match-log entry."""
    entry = {
        "timestamp": ts_iso,
        "event": "pattern_match",
        "command": fields.get("command", "vultr instance list"),
        "type": fields.get("type", "block"),
        "pattern": {
            "description": fields.get("desc", "Vultr CLI"),
            "regex": fields.get("regex", r"\bvultr\b"),
        },
    }
    if "user_selection" in fields:
        entry["user_selection"] = fields["user_selection"]
    with open(match_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _plugin_log_line(ts: str, level: str, message: str) -> str:
    """Build a Hermes-log line that matches _PLUGIN_LOG_PATTERN."""
    logger_name = "hermes_plugins.custom_dangerous_patterns"
    return f"{ts} {level} {logger_name} custom-dangerous-patterns: {message}"


# ---------------------------------------------------------------------------
# logfile.py — log_match (writer)
# ---------------------------------------------------------------------------


def test_log_match_writes_jsonl_entry(logs_modules):
    """log_match appends a valid JSON object with all required fields."""
    logs_modules.logfile.log_match(
        "vultr instance delete", "block",
        "Vultr destructive", r"\bvultr\s+instance\s+delete\b",
    )
    raw = logs_modules.match_log.read_text(encoding="utf-8").strip()
    data = json.loads(raw)
    assert data["event"] == "pattern_match"
    assert data["command"] == "vultr instance delete"
    assert data["type"] == "block"
    assert data["pattern"]["description"] == "Vultr destructive"
    assert data["pattern"]["regex"] == r"\bvultr\s+instance\s+delete\b"
    assert "user_selection" not in data  # omitted when None
    # timestamp parses as ISO-8601
    datetime.fromisoformat(data["timestamp"])


def test_log_match_includes_user_selection_when_provided(logs_modules):
    """user_selection appears only when explicitly passed."""
    logs_modules.logfile.log_match(
        "rm -rf /tmp", "block", "rm rf", r"\brm\s+-rf\b",
        user_selection="session",
    )
    data = json.loads(logs_modules.match_log.read_text(encoding="utf-8"))
    assert data["user_selection"] == "session"


def test_log_match_creates_log_dir(monkeypatch, tmp_path):
    """_ensure_log_dir creates the directory tree on first write."""
    plugin_dir = Path(__file__).resolve().parent.parent
    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = [str(plugin_dir)]
    monkeypatch.setitem(sys.modules, "hermes_plugins", pkg)
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.logfile", plugin_dir / "logfile.py"
    )
    logfile = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "hermes_plugins.logfile", logfile)
    spec.loader.exec_module(logfile)

    fresh = tmp_path / "deep" / "nested" / "logs"
    match = fresh / "custom-dangerous-patterns.log"
    monkeypatch.setattr(logfile, "_LOG_DIR", fresh)
    monkeypatch.setattr(logfile, "_LOG_FILE", match)

    assert not fresh.exists()
    logfile.log_match("cmd", "allow", "d", "r")
    assert fresh.is_dir()
    assert match.is_file()


# ---------------------------------------------------------------------------
# logfile.py — read_match_log_entries (reader)
# ---------------------------------------------------------------------------


def test_read_match_log_entries_parses_and_sorts(logs_modules):
    """Entries are returned earliest-first with parsed timestamps."""
    for i in range(3):
        _write_match_line(
            logs_modules.match_log,
            f"2026-06-0{i+1}T10:00:00",
            command=f"cmd{i}", type="block",
        )
    entries = logs_modules.logfile.read_match_log_entries()
    assert len(entries) == 3
    # earliest first
    assert entries[0]["timestamp"] < entries[1]["timestamp"] < entries[2]["timestamp"]
    assert entries[0]["level"] == "MATCH"
    assert "[BLOCK]" in entries[0]["message"]
    assert "matched" in entries[0]["message"]


def test_read_match_log_entries_limit_returns_most_recent(logs_modules):
    """limit returns the most recent N entries (after sort)."""
    for i in range(5):
        _write_match_line(logs_modules.match_log, f"2026-06-01T10:0{i}:00")
    entries = logs_modules.logfile.read_match_log_entries(limit=2)
    assert len(entries) == 2
    # the two most recent (latest timestamps)
    assert "10:03" in entries[0]["timestamp"] or "10:04" in entries[0]["timestamp"]
    assert entries[0]["timestamp"] < entries[1]["timestamp"]


def test_read_match_log_entries_since_filter(logs_modules):
    """since_dt excludes entries before the cutoff."""
    _write_match_line(logs_modules.match_log, "2026-06-01T08:00:00")
    _write_match_line(logs_modules.match_log, "2026-06-02T08:00:00")
    _write_match_line(logs_modules.match_log, "2026-06-03T08:00:00")
    since = datetime(2026, 6, 2, 12, 0, 0)
    entries = logs_modules.logfile.read_match_log_entries(since_dt=since)
    assert len(entries) == 1
    assert "2026-06-03" in entries[0]["timestamp"]


def test_read_match_log_entries_missing_file_returns_empty(logs_modules):
    """No log file -> empty list, no error."""
    assert logs_modules.logfile.read_match_log_entries() == []


def test_read_match_log_entries_skips_malformed_lines(logs_modules):
    """Malformed JSON and unparseable timestamps are skipped, not fatal."""
    logs_modules.match_log.write_text(
        "not json at all\n"
        + json.dumps({"no_timestamp": True}) + "\n"
        + json.dumps({"timestamp": "not-a-date", "type": "block"}) + "\n"
        + json.dumps({
            "timestamp": "2026-06-01T10:00:00",
            "type": "block",
            "command": "good",
            "pattern": {"description": "d", "regex": "r"},
        }) + "\n",
        encoding="utf-8",
    )
    entries = logs_modules.logfile.read_match_log_entries()
    assert len(entries) == 1
    assert "good" in entries[0]["message"]


# ---------------------------------------------------------------------------
# logfile.py — _rotate
# ---------------------------------------------------------------------------


def test_rotate_no_rotation_under_limit(logs_modules):
    """A small file is not rotated."""
    logs_modules.match_log.write_text("x" * 1024, encoding="utf-8")
    logs_modules.logfile._rotate()
    assert logs_modules.match_log.is_file()
    assert not logs_modules.match_log.with_suffix(".log.1").exists()


def test_rotate_rotates_when_over_limit(monkeypatch, logs_modules):
    """A file exceeding _MAX_LOG_BYTES is rotated to .log.1."""
    logs_modules.match_log.write_text("payload", encoding="utf-8")  # 7 bytes
    monkeypatch.setattr(logs_modules.logfile, "_MAX_LOG_BYTES", 4)  # below payload

    logs_modules.logfile._rotate()

    rotated = logs_modules.log_dir / "custom-dangerous-patterns.log.1"
    assert rotated.is_file()
    assert rotated.read_text(encoding="utf-8") == "payload"
    # original moved away
    assert not logs_modules.match_log.exists()


def test_rotate_shifts_existing_rotated_files(monkeypatch, logs_modules):
    """Existing .log.N files are shifted up before the active file rotates."""
    logs_modules.match_log.write_text("active", encoding="utf-8")
    # Pre-create .log.1 .. .log.3 with markers
    for i in (1, 2, 3):
        (logs_modules.log_dir / f"custom-dangerous-patterns.log.{i}").write_text(
            f"old{i}", encoding="utf-8"
        )
    monkeypatch.setattr(logs_modules.logfile, "_MAX_LOG_BYTES", 1)

    logs_modules.logfile._rotate()

    d = logs_modules.log_dir
    assert (d / "custom-dangerous-patterns.log.1").read_text() == "active"
    assert (d / "custom-dangerous-patterns.log.2").read_text() == "old1"
    assert (d / "custom-dangerous-patterns.log.3").read_text() == "old2"
    assert (d / "custom-dangerous-patterns.log.4").read_text() == "old3"
    # original moved away
    assert not logs_modules.match_log.exists()


# ---------------------------------------------------------------------------
# logs.py — extract_logs
# ---------------------------------------------------------------------------


def test_get_default_log_path_is_under_hermes_home(logs_modules):
    """get_default_log_path returns the module global (redirected in fixture)."""
    assert logs_modules.logs.get_default_log_path() == logs_modules.log_dir


def test_parse_since():
    """_parse_since returns midnight of the given day."""
    from logs import _parse_since

    dt = _parse_since("2026-06-15")
    assert dt == datetime(2026, 6, 15, 0, 0, 0)


def test_extract_logs_missing_dir_returns_empty(monkeypatch, tmp_path):
    """A non-existent log dir yields an empty list."""
    from logs import extract_logs

    assert extract_logs(log_path=tmp_path / "nope") == []


def test_extract_logs_parses_plugin_entries(logs_modules):
    """Plugin entries matching the pattern are extracted with metadata."""
    agent_log = logs_modules.log_dir / "agent.log"
    agent_log.write_text(
        "\n".join([
            "2026-06-22 10:00:00,111 INFO other.logger unrelated line",
            _plugin_log_line("2026-06-22 10:01:00", "WARNING", "CONFIG CHANGED"),
            _plugin_log_line("2026-06-22 10:02:00", "INFO", "loaded 3 patterns"),
        ]) + "\n",
        encoding="utf-8",
    )
    entries = logs_modules.logs.extract_logs(log_path=logs_modules.log_dir)
    assert len(entries) == 2
    assert all(e["level"] in ("WARNING", "INFO") for e in entries)
    # earliest first
    assert entries[0]["message"] == "CONFIG CHANGED"
    assert entries[1]["message"] == "loaded 3 patterns"
    assert entries[0]["source"] == "agent.log"


def test_extract_logs_level_filter(logs_modules):
    """Minimum level excludes lower-severity entries."""
    agent_log = logs_modules.log_dir / "agent.log"
    agent_log.write_text(
        "\n".join([
            _plugin_log_line("2026-06-22 10:00:00", "INFO", "loaded 1"),
            _plugin_log_line("2026-06-22 10:01:00", "WARNING", "config changed"),
            _plugin_log_line("2026-06-22 10:02:00", "ERROR", "boom"),
        ]) + "\n",
        encoding="utf-8",
    )
    entries = logs_modules.logs.extract_logs(
        log_path=logs_modules.log_dir, level="WARNING",
    )
    levels = {e["level"] for e in entries}
    assert levels == {"WARNING", "ERROR"}


def test_extract_logs_since_filter(logs_modules):
    """since (YYYY-MM-DD) excludes earlier entries."""
    agent_log = logs_modules.log_dir / "agent.log"
    agent_log.write_text(
        "\n".join([
            _plugin_log_line("2026-06-20 10:00:00", "INFO", "old"),
            _plugin_log_line("2026-06-22 10:00:00", "INFO", "new"),
        ]) + "\n",
        encoding="utf-8",
    )
    entries = logs_modules.logs.extract_logs(
        log_path=logs_modules.log_dir, since="2026-06-21",
    )
    assert len(entries) == 1
    assert entries[0]["message"] == "new"


def test_extract_logs_limit_returns_most_recent(logs_modules):
    """limit returns the most recent N after chronological sort."""
    agent_log = logs_modules.log_dir / "agent.log"
    lines = [
        _plugin_log_line(f"2026-06-22 10:0{i}:00", "INFO", f"m{i}") for i in range(5)
    ]
    agent_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    entries = logs_modules.logs.extract_logs(
        log_path=logs_modules.log_dir, limit=2,
    )
    assert len(entries) == 2
    assert [e["message"] for e in entries] == ["m3", "m4"]


def test_extract_logs_merges_match_log(logs_modules):
    """The dedicated match log is merged into the results with level MATCH."""
    agent_log = logs_modules.log_dir / "agent.log"
    agent_log.write_text(
        _plugin_log_line("2026-06-22 10:00:00", "INFO", "loaded") + "\n",
        encoding="utf-8",
    )
    _write_match_line(logs_modules.match_log, "2026-06-22T09:00:00", command="cmd")

    entries = logs_modules.logs.extract_logs(log_path=logs_modules.log_dir)
    levels = [e["level"] for e in entries]
    assert "INFO" in levels
    assert "MATCH" in levels
    # match entry sorted before the later INFO entry
    match_entry = next(e for e in entries if e["level"] == "MATCH")
    assert "[BLOCK]" in match_entry["message"]


def test_extract_logs_excludes_match_log_from_plugin_scan(logs_modules):
    """The match log file is not double-counted as a plugin-log source."""
    # Write a valid match entry, and the match log filename must NOT be parsed
    # by the *.log plugin-line scanner (only by read_match_log_entries).
    _write_match_line(logs_modules.match_log, "2026-06-22T09:00:00")
    entries = logs_modules.logs.extract_logs(log_path=logs_modules.log_dir)
    # Exactly one entry, from the match log reader (not duplicated by the
    # generic scanner which would have produced zero matches anyway).
    assert len(entries) == 1
    assert entries[0]["level"] == "MATCH"


# ---------------------------------------------------------------------------
# logs.py — format_log_entries
# ---------------------------------------------------------------------------


def test_format_log_entries_labels_plugin_and_match(logs_modules):
    """Plugin entries render as [Plugin], match entries as [Match]."""
    entries = [
        {
            "timestamp": "2026-06-22 10:00:00",
            "level": "INFO",
            "message": "hi",
            "source": "agent.log",
        },
        {
            "timestamp": "2026-06-22 10:01:00",
            "level": "MATCH",
            "message": "blocked",
            "source": "custom-dangerous-patterns.log",
        },
    ]
    out = logs_modules.logs.format_log_entries(entries)
    assert any("[Plugin]" in t.plain for t in out)
    assert any("[Match]" in t.plain for t in out)
    # source filename appears
    assert any("agent.log" in t.plain for t in out)


def test_format_log_entries_empty_message():
    """No entries yields the not-found placeholder."""
    from logs import format_log_entries

    out = format_log_entries([])
    assert len(out) == 1
    assert "No plugin-specific log entries" in out[0]


# ---------------------------------------------------------------------------
# logs.py — follow_logs (early returns + clean interrupt exit)
# ---------------------------------------------------------------------------


def test_follow_logs_missing_dir_prints_message(monkeypatch, tmp_path, capsys):
    """A missing log dir prints a message and returns without blocking."""
    from logs import follow_logs

    follow_logs(log_path=tmp_path / "missing")
    captured = capsys.readouterr()
    assert "not found" in captured.out


def test_follow_logs_no_log_files(monkeypatch, tmp_path, capsys):
    """An empty log dir prints a message and returns without blocking."""
    from logs import follow_logs

    follow_logs(log_path=tmp_path)
    captured = capsys.readouterr()
    assert "No *.log files" in captured.out


def test_follow_logs_exits_cleanly_on_interrupt(monkeypatch, tmp_path, capsys):
    """A KeyboardInterrupt from the tail loop exits cleanly (Ctrl-C path).

    Real tail blocks on time.sleep; we monkeypatch sleep to raise
    KeyboardInterrupt on first call so the open/seek/readline path runs
    once and then unwinds via the existing `except KeyboardInterrupt`.
    This guards the 0.3.3 fix (ValueError on Ctrl-C in follow mode).
    """
    import logs

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "agent.log").write_text(
        _plugin_log_line("2026-06-22 10:00:00", "INFO", "loaded") + "\n",
        encoding="utf-8",
    )

    def _boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("time.sleep", _boom)

    # Must return, not raise.
    logs.follow_logs(log_path=log_dir)
    captured = capsys.readouterr()
    assert "Following" in captured.out
