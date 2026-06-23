"""Tests for CLI command handlers.

Tests cmd_list, cmd_test, and cmd_init — the P0 commands.
All other command handlers are stubs and tested in later chunks.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path

import pytest


@pytest.fixture
def cli_module(monkeypatch):
    """Import cli.py under the hermes_plugins package namespace.

    Required because cli.py uses relative imports (from .config, .patterns).
    """
    plugin_dir = Path(__file__).resolve().parent.parent

    # Ensure hermes_plugins package exists
    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = [str(plugin_dir)]
    monkeypatch.setitem(sys.modules, "hermes_plugins", pkg)

    # Load sibling modules (config, patterns) under the package
    for name in ("config", "patterns"):
        spec = importlib.util.spec_from_file_location(
            f"hermes_plugins.{name}",
            plugin_dir / f"{name}.py",
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"hermes_plugins.{name}", mod)
        spec.loader.exec_module(mod)

    # Load cli.py under the package
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.cli",
        plugin_dir / "cli.py",
    )
    cli_mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "hermes_plugins.cli", cli_mod)
    spec.loader.exec_module(cli_mod)

    return cli_mod


# ---------------------------------------------------------------------------
# cmd_list tests
# ---------------------------------------------------------------------------


def test_cmd_list_no_config(monkeypatch, cli_module, tmp_path):
    """cmd_list with a non-existent config path shows init suggestion."""

    # Mock resolve_config_path and load_config
    fake_path = tmp_path / "nonexistent.yaml"
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )

    output, exit_code = cli_module.cmd_list()
    assert exit_code == 0
    assert "No config found" in output
    assert "init" in output


def test_cmd_list_with_patterns(monkeypatch, cli_module, tmp_path):
    """cmd_list shows all pattern types with indices and status."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {
                    "pattern": r"\bvultr\b",
                    "description": "Vultr CLI",
                    "enabled": True,
                    "group": "cloud",
                },
                {
                    "pattern": r"\baws\b",
                    "description": "AWS CLI",
                    "enabled": False,
                    "group": "",
                },
            ],
            "allow_patterns": [
                {
                    "pattern": r"\bvultr\s+info\b",
                    "description": "Vultr info",
                    "enabled": True,
                    "group": "cloud",
                },
            ],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list()
    assert exit_code == 0
    assert "BLOCK patterns" in output
    assert "[1]" in output
    assert "Vultr CLI" in output
    assert "group: cloud" in output
    assert "ALLOW patterns" in output
    # AWS should be marked disabled
    assert "AWS CLI" in output


def test_cmd_list_filter_by_type(monkeypatch, cli_module, tmp_path):
    """cmd_list --type allow shows only allow patterns."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": True},
            ],
            "allow_patterns": [
                {"pattern": r"\bvultr\s+info\b", "description": "Vultr info", "enabled": True},
            ],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list(pattern_type="allow")
    assert exit_code == 0
    assert "BLOCK patterns" not in output
    assert "ALLOW patterns" in output
    assert "Vultr info" in output


def test_cmd_list_filter_disabled(monkeypatch, cli_module, tmp_path):
    """cmd_list --disabled shows only disabled patterns."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": True},
                {"pattern": r"\baws\b", "description": "AWS", "enabled": False},
            ],
            "allow_patterns": [],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list(disabled=True)
    assert exit_code == 0
    assert "Vultr" not in output  # enabled, should be filtered out
    assert "AWS" in output  # disabled, should be shown


def test_cmd_list_filter_enabled(monkeypatch, cli_module, tmp_path):
    """cmd_list --enabled shows only enabled patterns."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": True},
                {"pattern": r"\baws\b", "description": "AWS", "enabled": False},
            ],
            "allow_patterns": [],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list(enabled=True)
    assert exit_code == 0
    assert "Vultr" in output
    assert "AWS" not in output  # disabled, should be filtered out


def test_cmd_list_filter_by_group(monkeypatch, cli_module, tmp_path):
    """cmd_list --group cloud shows only patterns in that group."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {
                    "pattern": r"\bvultr\b",
                    "description": "Vultr",
                    "group": "cloud",
                    "enabled": True,
                },
                {
                    "pattern": r"\baws\b",
                    "description": "AWS",
                    "group": "iac",
                    "enabled": True,
                },
            ],
            "allow_patterns": [],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list(group="cloud")
    assert exit_code == 0
    assert "Vultr" in output
    assert "AWS" not in output


def test_cmd_list_filter_no_match(monkeypatch, cli_module, tmp_path):
    """cmd_list with filter that matches nothing shows appropriate message."""
    fake_path = tmp_path / "config.yaml"
    fake_path.write_text("")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: fake_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [
                {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": True},
            ],
            "allow_patterns": [],
            "deny_patterns": [],
        },
    )

    output, exit_code = cli_module.cmd_list(group="nonexistent")
    assert exit_code == 0
    assert "No patterns match your filters" in output


# ---------------------------------------------------------------------------
# cmd_test tests
# ---------------------------------------------------------------------------


def test_cmd_test_empty_command(monkeypatch, cli_module):
    """cmd_test with empty string returns error."""
    output, exit_code = cli_module.cmd_test("")
    assert exit_code == 1
    assert "must not be empty" in output


def test_cmd_test_no_patterns(monkeypatch, cli_module, tmp_path):
    """cmd_test with no custom patterns shows all clear."""

    # Mock config resolution and patterns
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [], "allow_patterns": [], "deny_patterns": []
        },
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "compile_all",
        lambda config: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_deny_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_allow_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "get_block_patterns",
        lambda: [],
    )

    output, exit_code = cli_module.cmd_test("echo hello")
    assert exit_code == 0
    assert "PASS" in output


def test_cmd_test_deny_match(monkeypatch, cli_module, tmp_path):
    """cmd_test when deny pattern matches shows DENY result."""
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [], "allow_patterns": [], "deny_patterns": []
        },
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "compile_all",
        lambda config: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_deny_pattern",
        lambda cmd: "Force git push",
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_allow_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "get_block_patterns",
        lambda: [],
    )

    output, exit_code = cli_module.cmd_test("git push --force")
    assert exit_code == 0
    assert "DENY" in output
    assert "Force git push" in output


def test_cmd_test_allow_match(monkeypatch, cli_module, tmp_path):
    """cmd_test when allow pattern matches shows ALLOW result."""
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [], "allow_patterns": [], "deny_patterns": []
        },
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "compile_all",
        lambda config: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_deny_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_allow_pattern",
        lambda cmd: "Read-only Vultr commands",
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "get_block_patterns",
        lambda: [],
    )

    output, exit_code = cli_module.cmd_test("vultr account info")
    assert exit_code == 0
    assert "ALLOW" in output
    assert "Read-only Vultr commands" in output


def test_cmd_test_approval_prompt(monkeypatch, cli_module, tmp_path):
    """cmd_test when only block patterns match shows APPROVAL PROMPT."""
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [], "allow_patterns": [], "deny_patterns": []
        },
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "compile_all",
        lambda config: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_deny_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_allow_pattern",
        lambda cmd: None,
    )

    import re as _re
    compiled_re = _re.compile(r"\bvultr\b", _re.IGNORECASE | _re.DOTALL)
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "get_block_patterns",
        lambda: [(compiled_re, "Vultr CLI")],
    )

    output, exit_code = cli_module.cmd_test("vultr instance delete")
    assert exit_code == 0
    assert "APPROVAL PROMPT" in output
    assert "Vultr CLI" in output


def test_cmd_test_skip_builtins(monkeypatch, cli_module, tmp_path):
    """cmd_test --skip-builtins omits built-in pattern section."""
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "load_config",
        lambda force=False, integrity_check=True: {
            "patterns": [], "allow_patterns": [], "deny_patterns": []
        },
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "compile_all",
        lambda config: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_deny_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "is_allow_pattern",
        lambda cmd: None,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.patterns"],
        "get_block_patterns",
        lambda: [],
    )

    output, exit_code = cli_module.cmd_test("echo hello", skip_builtins=True)
    assert exit_code == 0
    assert "BUILT-IN patterns" not in output


# ---------------------------------------------------------------------------
# cmd_init tests
# ---------------------------------------------------------------------------


def test_cmd_init_creates_config(monkeypatch, cli_module, tmp_path):
    """cmd_init creates a config directory and returns success."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )

    output, exit_code = cli_module.cmd_init()
    assert exit_code == 0
    assert "Created:" in output
    assert "Next steps:" in output
    assert "list" in output
    assert "enable --group" in output
    # Should create the directory, not the file
    assert (config_path.parent / "custom-dangerous-patterns").is_dir()


def test_cmd_init_existing_config_no_force(monkeypatch, cli_module, tmp_path):
    """cmd_init with existing config dir (no --force) returns error."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    dir_path = tmp_path / "custom-dangerous-patterns"
    dir_path.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )

    output, exit_code = cli_module.cmd_init()
    assert exit_code == 1
    assert "already exists" in output
    assert "--force" in output


def test_cmd_init_force_overwrites(monkeypatch, cli_module, tmp_path):
    """cmd_init --force overwrites existing config dir."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    dir_path = tmp_path / "custom-dangerous-patterns"
    dir_path.mkdir(parents=True, exist_ok=True)
    (dir_path / "old.yaml").write_text("patterns: []")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )

    output, exit_code = cli_module.cmd_init(force=True)
    assert exit_code == 0
    assert "Created:" in output
    # Should create the directory with 00-test.yaml
    assert (dir_path / "00-test.yaml").is_file()


def test_cmd_init_with_examples(monkeypatch, cli_module, tmp_path):
    """cmd_init --with-examples creates config directory with example patterns."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )

    output, exit_code = cli_module.cmd_init(with_examples=True)
    assert exit_code == 0
    assert "Created:" in output
    dir_path = tmp_path / "custom-dangerous-patterns"
    assert (dir_path / "00-test.yaml").is_file()


# ---------------------------------------------------------------------------
# cmd_validate tests — glob mismatch warning
# ---------------------------------------------------------------------------


def test_cmd_validate_glob_mismatch_warning(monkeypatch, cli_module, tmp_path):
    """cmd_validate warns when glob and pattern disagree."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("patterns: []", encoding="utf-8")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )
    # Return raw config where a pattern has both glob and pattern that differ
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "_load_yaml",
        lambda path: {
            "patterns": [
                {
                    "glob": "echo hello",
                    "pattern": r"\becho\s+world\b",
                    "description": "Mismatch test",
                },
            ],
        },
    )

    output, exit_code = cli_module.cmd_validate()
    assert exit_code == 0
    assert "glob warning" in output
    assert "echo hello" in output  # glob value shown
    # Check that generated and stored patterns appear (use raw strings
    # so \\b and \\s are literal backslash sequences, not escape sequences)
    assert r"\becho(?!/)\s+hello\b" in output  # generated from glob "echo hello"
    assert r"\becho\s+world\b" in output   # stored pattern


def test_cmd_validate_glob_match_no_warning(monkeypatch, cli_module, tmp_path):
    """cmd_validate does not warn when glob and pattern agree."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("patterns: []", encoding="utf-8")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "_load_yaml",
        lambda path: {
            "patterns": [
                {
                    "glob": "echo hello",
                    "pattern": r"\becho(?!/)\s+hello\b",
                    "description": "Match test",
                },
            ],
        },
    )

    output, exit_code = cli_module.cmd_validate()
    assert exit_code == 0
    assert "glob warning" not in output
    assert "Result: VALID" in output


def test_cmd_validate_no_glob_no_warning(monkeypatch, cli_module, tmp_path):
    """cmd_validate does not warn when no glob is present."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("patterns: []", encoding="utf-8")
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "resolve_config_path",
        lambda: config_path,
    )
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "_load_yaml",
        lambda path: {
            "patterns": [
                {
                    "pattern": r"\becho\s+hello\b",
                    "description": "No glob here",
                },
            ],
        },
    )

    output, exit_code = cli_module.cmd_validate()
    assert exit_code == 0
    assert "glob warning" not in output
    assert "Result: VALID" in output


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


def test_build_minimal_starter_config(cli_module):
    """_build_minimal_starter_config returns expected structure."""
    config = cli_module._build_minimal_starter_config()
    assert "patterns" in config
    assert "allow_patterns" in config
    assert "deny_patterns" in config
    assert len(config["patterns"]) == 1
    assert len(config["allow_patterns"]) == 1
    assert len(config["deny_patterns"]) == 1
    # All patterns should be disabled
    for entry in config["patterns"]:
        assert entry["enabled"] is False
    assert all(p["group"] == "testing" for p in config["patterns"])
    assert all(p["group"] == "testing" for p in config["allow_patterns"])
    assert all(p["group"] == "testing" for p in config["deny_patterns"])


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------


def test_emit(monkeypatch, cli_module):
    """_emit prints output and exits with given code."""
    with pytest.raises(SystemExit) as exc_info:
        cli_module._emit("hello\n", 42)
    assert exc_info.value.code == 42


def test_config_update_reminder(cli_module):
    """_config_update_reminder mentions restart."""
    reminder = cli_module._config_update_reminder()
    assert "restart" in reminder.lower()
    assert "Hermes" in reminder


def test_format_builtins_smoke(cli_module):
    """_format_builtins returns a list with header."""
    lines = cli_module._format_builtins()
    assert len(lines) > 1
    assert "BUILT-IN patterns" in lines[0]


def test_format_builtins_with_search(cli_module):
    """_format_builtins with search filters results."""
    lines_all = cli_module._format_builtins()
    lines_filtered = cli_module._format_builtins(search_term="docker")
    assert len(lines_filtered) < len(lines_all)
    assert any("docker" in line.lower() for line in lines_filtered)


# ---------------------------------------------------------------------------
# Allow shadowing checks
# ---------------------------------------------------------------------------


def test_add_allow_pattern_shadowing_warning(cli_module):
    """Broad allow pattern that shadows built-ins triggers warning."""
    config = {
        "patterns": [],
        "allow_patterns": [
            {"pattern": r"\bdocker\b", "description": "Allow docker", "enabled": True},
        ],
        "deny_patterns": [],
    }
    warnings = cli_module._check_allow_shadowing_for_cli(config)
    assert len(warnings) > 0
    assert any("shadow" in w.lower() for w in warnings)
    assert any("docker" in w.lower() for w in warnings)


def test_add_block_pattern_no_shadowing_warning(cli_module):
    """Block pattern produces no shadowing warnings."""
    config = {
        "patterns": [
            {"pattern": r"\bvultr\b", "description": "Vultr", "enabled": True},
        ],
        "allow_patterns": [],
        "deny_patterns": [],
    }
    warnings = cli_module._check_allow_shadowing_for_cli(config)
    assert len(warnings) == 0


def test_add_allow_pattern_no_shadowing(cli_module):
    """Narrow allow pattern that doesn't shadow built-ins produces no warnings."""
    config = {
        "patterns": [],
        "allow_patterns": [
            {"pattern": r"\bmyapp\s+read\b", "description": "MyApp read", "enabled": True},
        ],
        "deny_patterns": [],
    }
    warnings = cli_module._check_allow_shadowing_for_cli(config)
    assert len(warnings) == 0


def test_allow_shadowing_not_suppressed_by_unrelated_block(cli_module):
    """A block covering a *different* built-in must not suppress the warning.

    Regression: the CLI coverage check previously flipped ``covered_by_block``
    True if any block overlapped *any* built-in, instead of the specific
    built-ins the allow shadows. That silenced real shadowing warnings — the
    unsafe direction for a safety plugin. Here an allow for ``\bdocker\b``
    shadows docker built-ins, while the block only covers the ``rm -rf`` /
    ``dd`` built-ins. The shadowing must still be reported.
    """
    config = {
        "patterns": [
            {
                "pattern": r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f)\b",
                "description": "rm -rf block",
                "enabled": True,
            },
        ],
        "allow_patterns": [
            {"pattern": r"\bdocker\b", "description": "Allow docker", "enabled": True},
        ],
        "deny_patterns": [],
    }
    warnings = cli_module._check_allow_shadowing_for_cli(config)
    assert len(warnings) > 0, (
        "shadowing warning was suppressed by an unrelated block pattern"
    )
    assert any("docker" in w.lower() for w in warnings)


def test_allow_shadowing_suppressed_when_block_covers_same_builtins(cli_module):
    """A block that covers the same built-ins DOES suppress the warning.

    Positive control for the coverage-scoping fix: an allow for
    ``\bdocker\b`` plus a block for ``\bdocker\b`` (which overlaps the same
    docker built-ins) is treated as intentionally scoped — no warning.
    """
    config = {
        "patterns": [
            {"pattern": r"\bdocker\b", "description": "docker block", "enabled": True},
        ],
        "allow_patterns": [
            {"pattern": r"\bdocker\b", "description": "Allow docker", "enabled": True},
        ],
        "deny_patterns": [],
    }
    warnings = cli_module._check_allow_shadowing_for_cli(config)
    assert len(warnings) == 0


# ---------------------------------------------------------------------------
# cmd_info — integrity status (single-file AND directory modes)
# ---------------------------------------------------------------------------


def _write_hash_file(config_path, config_hash):
    """Write a .custom-patterns-hash file alongside the config."""
    import json

    hash_path = config_path.parent / ".custom-patterns-hash"
    hash_path.write_text(
        json.dumps({
            "config_hash": config_hash,
            "pattern_counts": {"patterns": 0, "allow_patterns": 0, "deny_patterns": 0},
            "protected": {},
        }),
        encoding="utf-8",
    )
    return hash_path


def _config_raw_hash(config_path):
    """Compute the config hash the same way cmd_info now does."""
    import hashlib

    cfg_mod = sys.modules["hermes_plugins.config"]
    raw = cfg_mod._load_raw_config_text(config_path)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _patch_config_path(monkeypatch, config_path):
    """Redirect config path resolution to config_path."""
    monkeypatch.setattr(
        sys.modules["hermes_plugins.config"],
        "_resolve_config_path",
        lambda: config_path,
    )


def test_cmd_info_integrity_matches_single_file(monkeypatch, cli_module, tmp_path):
    """Single-file config with a matching hash reports 'hash matches'."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    config_path.write_text("patterns: []\nallow_patterns: []\ndeny_patterns: []\n",
                           encoding="utf-8")
    _write_hash_file(config_path, _config_raw_hash(config_path))
    _patch_config_path(monkeypatch, config_path)

    output, exit_code = cli_module.cmd_info()
    assert exit_code == 0
    assert "hash matches previous session" in output
    assert "Last changed" in output


def test_cmd_info_integrity_changed_single_file(monkeypatch, cli_module, tmp_path):
    """Single-file config with a stale hash reports 'hash changed'."""
    config_path = tmp_path / "custom-dangerous-patterns.yaml"
    config_path.write_text("patterns: []\nallow_patterns: []\ndeny_patterns: []\n",
                           encoding="utf-8")
    _write_hash_file(config_path, "0" * 64)  # wrong hash
    _patch_config_path(monkeypatch, config_path)

    output, _ = cli_module.cmd_info()
    assert "hash changed since last session" in output


def test_cmd_info_integrity_matches_directory_mode(monkeypatch, cli_module, tmp_path):
    """Directory config with a matching hash reports 'hash matches'.

    Regression: the integrity block was previously gated on
    ``config_path.is_file()``, so directory configs (the recommended
    default) silently skipped the hash comparison and showed no status.
    """
    config_dir = tmp_path / "custom-dangerous-patterns"
    config_dir.mkdir()
    (config_dir / "10-cloud.yaml").write_text(
        "patterns:\n  - pattern: '\\bvultr\\b'\n    description: 'Vultr'\n",
        encoding="utf-8",
    )
    (config_dir / "20-db.yaml").write_text(
        "patterns:\n  - pattern: '\\bDROP\\b'\n    description: 'DROP'\n",
        encoding="utf-8",
    )
    _write_hash_file(config_dir, _config_raw_hash(config_dir))
    _patch_config_path(monkeypatch, config_dir)

    output, exit_code = cli_module.cmd_info()
    assert exit_code == 0
    assert "hash matches previous session" in output


def test_cmd_info_integrity_changed_directory_mode(monkeypatch, cli_module, tmp_path):
    """Directory config with a stale hash reports 'hash changed'.

    Second half of the directory-mode regression: previously the stale hash
    was never compared, so a tampered directory config showed no warning.
    """
    config_dir = tmp_path / "custom-dangerous-patterns"
    config_dir.mkdir()
    (config_dir / "10-cloud.yaml").write_text(
        "patterns:\n  - pattern: '\\bvultr\\b'\n    description: 'Vultr'\n",
        encoding="utf-8",
    )
    _write_hash_file(config_dir, "0" * 64)  # wrong hash
    _patch_config_path(monkeypatch, config_dir)

    output, _ = cli_module.cmd_info()
    assert "hash changed since last session" in output


# _config_content_files (mtime display helper)


def test_config_content_files_single_file(cli_module, tmp_path):
    f = tmp_path / "custom-dangerous-patterns.yaml"
    f.write_text("", encoding="utf-8")
    assert cli_module._config_content_files(f) == [f]


def test_config_content_files_directory_includes_yaml(cli_module, tmp_path):
    d = tmp_path / "custom-dangerous-patterns"
    d.mkdir()
    a = d / "10.yaml"
    b = d / "20.yaml"
    a.write_text("", encoding="utf-8")
    b.write_text("", encoding="utf-8")
    assert cli_module._config_content_files(d) == [a, b]


def test_config_content_files_directory_with_sibling(cli_module, tmp_path):
    """Combined mode: the sibling .yaml is appended after dir files."""
    d = tmp_path / "custom-dangerous-patterns"
    d.mkdir()
    a = d / "10.yaml"
    a.write_text("", encoding="utf-8")
    sibling = tmp_path / "custom-dangerous-patterns.yaml"
    sibling.write_text("", encoding="utf-8")
    files = cli_module._config_content_files(d)
    assert a in files and sibling in files
