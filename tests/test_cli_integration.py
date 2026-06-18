"""Integration tests for CLI commands against real config files on disk.

Tests cmd_add, cmd_remove, cmd_enable, cmd_disable, and cmd_list in
file-only, directory-only, and combined file+directory modes using real
YAML files on disk — not mocked config loading or path resolution.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SIMPLE_BLOCK_PATTERNS = [
    {"pattern": r"\bvultr\b", "description": "Vultr CLI",
     "enabled": True, "group": "", "protected": False},
    {"pattern": r"\baws\b", "description": "AWS CLI",
     "enabled": True, "group": "cloud", "protected": False},
]

SIMPLE_ALLOW_PATTERNS = [
    {"pattern": r"\bvultr\s+info\b", "description": "Vultr info",
     "enabled": True, "group": "", "protected": False},
]

SIMPLE_DENY_PATTERNS = [
    {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby exec",
     "enabled": True, "group": "", "protected": False},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    """Write a YAML dict to disk for testing."""
    import ruamel.yaml

    path.parent.mkdir(parents=True, exist_ok=True)
    yaml = ruamel.yaml.YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f)


def _read_yaml(path: Path) -> dict[str, Any]:
    """Read a YAML file from disk. Returns empty dict if missing."""
    if not path.is_file():
        return {}
    import ruamel.yaml

    yaml = ruamel.yaml.YAML(typ="safe")
    return yaml.load(path.read_text(encoding="utf-8"))


def _config(patterns=None, allow=None, deny=None) -> dict[str, Any]:
    """Build a minimal config dict with optional sections."""
    return {
        "patterns": patterns or [],
        "allow_patterns": allow or [],
        "deny_patterns": deny or [],
    }


def _pattern_descriptions(
    entries: Sequence[dict[str, Any]],
) -> set[str]:
    """Extract description set from a list of pattern entries."""
    return {e.get("description", "") for e in entries}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def cli_module(monkeypatch):
    """Import cli.py under the hermes_plugins package namespace."""
    plugin_dir = Path(__file__).resolve().parent.parent

    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = [str(plugin_dir)]
    monkeypatch.setitem(sys.modules, "hermes_plugins", pkg)

    for name in ("config", "patterns"):
        spec = importlib.util.spec_from_file_location(
            f"hermes_plugins.{name}",
            plugin_dir / f"{name}.py",
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"hermes_plugins.{name}", mod)
        spec.loader.exec_module(mod)

    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.cli",
        plugin_dir / "cli.py",
    )
    cli_mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "hermes_plugins.cli", cli_mod)
    spec.loader.exec_module(cli_mod)

    return cli_mod


@pytest.fixture
def hermes_home(monkeypatch, tmp_path) -> Path:
    """Point hermes_constants.get_hermes_home() to a tmp_path/.hermes."""
    home = tmp_path / ".hermes"
    home.mkdir()
    mock = types.ModuleType("hermes_constants")
    mock.get_hermes_home = lambda: home
    monkeypatch.setitem(sys.modules, "hermes_constants", mock)
    return home





# ---------------------------------------------------------------------------
# File-only mode
# ---------------------------------------------------------------------------


class TestFileMode:
    """Test CLI commands against a single-file config."""

    @staticmethod
    def yaml_path(hermes_home: Path) -> Path:
        return hermes_home / "custom-dangerous-patterns.yaml"

    # --- add ---

    def test_add_block_pattern(self, cli_module, hermes_home):
        """Adding a block pattern to a file-mode config persists to disk."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_add(
            pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI",
        )
        assert exit_code == 0
        assert "added" in output.lower()

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("patterns", [])) == 3
        descs = _pattern_descriptions(data["patterns"])
        assert "Vultr CLI" in descs
        assert "GCP CLI" in descs

    def test_add_allow_pattern(self, cli_module, hermes_home):
        """Adding an allow pattern to a file-mode config persists to disk."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_add(
            pattern_type="allow", pattern=r"\bgcloud\s+info\b", description="GCP info",
        )
        assert exit_code == 0

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("allow_patterns", [])) == 1
        assert data["allow_patterns"][0]["description"] == "GCP info"

    def test_add_deny_pattern(self, cli_module, hermes_home):
        """Adding a deny pattern persists to disk."""
        _write_yaml(self.yaml_path(hermes_home), _config())

        output, exit_code = cli_module.cmd_add(
            pattern_type="deny", pattern=r"\bdanger\b", description="Danger command",
        )
        assert exit_code == 0

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("deny_patterns", [])) == 1
        assert data["deny_patterns"][0]["description"] == "Danger command"

    # --- remove ---

    def test_remove_by_index(self, cli_module, hermes_home):
        """Removing a pattern by index deletes it from the file."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_remove(target="2", force=True)
        assert exit_code == 0
        assert "AWS CLI" in output

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("patterns", [])) == 1
        assert data["patterns"][0]["description"] == "Vultr CLI"

    def test_remove_by_description(self, cli_module, hermes_home):
        """Removing a pattern by description substring works."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_remove(target="Vultr", force=True)
        assert exit_code == 0

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("patterns", [])) == 1
        assert data["patterns"][0]["description"] == "AWS CLI"

    def test_remove_allows(self, cli_module, hermes_home):
        """Removing an allow pattern works."""
        _write_yaml(self.yaml_path(hermes_home), _config(allow=SIMPLE_ALLOW_PATTERNS))

        output, exit_code = cli_module.cmd_remove(target="1", force=True)
        assert exit_code == 0

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("allow_patterns", [])) == 0

    def test_remove_without_force_cancels(self, cli_module, hermes_home, monkeypatch, capsys):
        """Without --force, confirmation prompt shown and pattern not removed on cancel."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        monkeypatch.setattr("builtins.input", lambda _: "n")
        output, exit_code = cli_module.cmd_remove(target="2")

        assert exit_code == 0
        assert "Cancelled" in output
        captured = capsys.readouterr()
        assert "Matched pattern" in captured.out

        data = _read_yaml(self.yaml_path(hermes_home))
        assert len(data.get("patterns", [])) == 2

    # --- enable / disable ---

    def test_enable_pattern(self, cli_module, hermes_home):
        """Enable a disabled pattern."""
        disabled = [dict(SIMPLE_BLOCK_PATTERNS[0], enabled=False)]
        _write_yaml(self.yaml_path(hermes_home), _config(disabled))

        output, exit_code = cli_module.cmd_enable(target="1")
        assert exit_code == 0
        assert "Enabled" in output

        # enabled: True is omitted from YAML (it's the default),
        # so absent means enabled
        data = _read_yaml(self.yaml_path(hermes_home))
        assert data["patterns"][0].get("enabled", True) is True

    def test_disable_pattern(self, cli_module, hermes_home):
        """Disable an enabled pattern."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_disable(target="1")
        assert exit_code == 0
        assert "Disabled" in output

        data = _read_yaml(self.yaml_path(hermes_home))
        assert data["patterns"][0].get("enabled") is False

    def test_enable_already_enabled(self, cli_module, hermes_home):
        """Enabling an already-enabled pattern returns a message."""
        _write_yaml(self.yaml_path(hermes_home), _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_enable(target="1")
        assert exit_code == 0
        assert "already enabled" in output.lower()

    def test_enable_by_group(self, cli_module, hermes_home):
        """Enable all patterns in a group."""
        disabled = dict(SIMPLE_BLOCK_PATTERNS[1], enabled=False)
        _write_yaml(
            self.yaml_path(hermes_home),
            _config([SIMPLE_BLOCK_PATTERNS[0], disabled]),
        )

        output, exit_code = cli_module.cmd_enable(group="cloud")
        assert exit_code == 0
        assert "Enabled" in output

        # enabled: True is omitted (default), so absent means enabled
        data = _read_yaml(self.yaml_path(hermes_home))
        cloud = [e for e in data.get("patterns", []) if e.get("group") == "cloud"]
        assert len(cloud) == 1
        assert cloud[0].get("enabled", True) is True

    # --- list ---

    def test_list_with_patterns(self, cli_module, hermes_home):
        """List shows all pattern types with descriptions."""
        _write_yaml(
            self.yaml_path(hermes_home),
            _config(SIMPLE_BLOCK_PATTERNS, SIMPLE_ALLOW_PATTERNS,
                    SIMPLE_DENY_PATTERNS),
        )

        output, exit_code = cli_module.cmd_list()
        assert exit_code == 0
        assert "BLOCK patterns" in output
        assert "ALLOW patterns" in output
        assert "DENY patterns" in output
        assert "Vultr CLI" in output
        assert "Vultr info" in output
        assert "Ruby exec" in output

    def test_list_no_config(self, cli_module, hermes_home):
        """List with no config shows init suggestion."""
        output, exit_code = cli_module.cmd_list()
        assert exit_code == 0
        assert "No config found" in output
        assert "init" in output


# ---------------------------------------------------------------------------
# Directory-only mode
# ---------------------------------------------------------------------------


class TestDirMode:
    """Test CLI commands against a directory-mode config (custom-dangerous-patterns/)."""

    @staticmethod
    def dir_path(hermes_home: Path) -> Path:
        return hermes_home / "custom-dangerous-patterns"

    @staticmethod
    def source_file(hermes_home: Path, name: str = "00-test.yaml") -> Path:
        return TestDirMode.dir_path(hermes_home) / name

    @staticmethod
    def cli_file(hermes_home: Path) -> Path:
        return TestDirMode.dir_path(hermes_home) / "99-custom.yaml"

    @staticmethod
    def yaml_path(hermes_home: Path) -> Path:
        return hermes_home / "custom-dangerous-patterns.yaml"

    def setup_dir(self, hermes_home: Path, config: dict[str, Any]) -> None:
        """Create a source file in the .d/ directory."""
        d = self.dir_path(hermes_home)
        d.mkdir(parents=True, exist_ok=True)
        _write_yaml(self.source_file(hermes_home), config)

    # --- add ---

    def test_add_writes_delta_to_99_custom(self, cli_module, hermes_home):
        """Adding a pattern in dir mode writes to 99-custom.yaml, not the source."""
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_add(
            pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI",
        )
        assert exit_code == 0

        # Source file unchanged
        src = _read_yaml(self.source_file(hermes_home))
        assert len(src.get("patterns", [])) == 2
        assert "GCP CLI" not in _pattern_descriptions(src["patterns"])

        # 99-custom.yaml has the delta (only the new pattern)
        cli = _read_yaml(self.cli_file(hermes_home))
        assert "patterns" in cli
        assert "GCP CLI" in _pattern_descriptions(cli["patterns"])
        assert "Vultr CLI" not in _pattern_descriptions(cli["patterns"])

    def test_add_deny_in_dir_mode(self, cli_module, hermes_home):
        """Adding a deny pattern in dir mode writes to 99-custom.yaml."""
        self.setup_dir(hermes_home, _config())

        output, exit_code = cli_module.cmd_add(
            pattern_type="deny", pattern=r"\bdanger\b", description="Danger",
        )
        assert exit_code == 0

        cli = _read_yaml(self.cli_file(hermes_home))
        assert len(cli.get("deny_patterns", [])) == 1

    # --- remove ---

    def test_remove_writes_disabled_to_99_custom(self, cli_module, hermes_home):
        """Removing a pattern in dir mode writes it as disabled, not deleted."""
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_remove(target="1", force=True)
        assert exit_code == 0

        # 99-custom.yaml has the removed pattern as disabled
        cli = _read_yaml(self.cli_file(hermes_home))
        assert "patterns" in cli
        assert len(cli["patterns"]) == 1
        assert cli["patterns"][0]["description"] == "Vultr CLI"
        assert cli["patterns"][0].get("enabled") is False

        # Source file unchanged (Vultr still there)
        src = _read_yaml(self.source_file(hermes_home))
        assert len(src.get("patterns", [])) == 2

    # --- enable / disable ---

    def test_disable_writes_to_99_custom(self, cli_module, hermes_home):
        """Disabling a pattern in dir mode writes delta to 99-custom.yaml."""
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_disable(target="1")
        assert exit_code == 0

        cli = _read_yaml(self.cli_file(hermes_home))
        assert "patterns" in cli
        assert cli["patterns"][0]["description"] == "Vultr CLI"
        assert cli["patterns"][0].get("enabled") is False

    def test_enable_writes_to_99_custom(self, cli_module, hermes_home):
        """Enabling a disabled pattern in dir mode writes delta."""
        disabled = [dict(SIMPLE_BLOCK_PATTERNS[0], enabled=False)]
        self.setup_dir(hermes_home, _config(disabled))

        output, exit_code = cli_module.cmd_enable(target="1")
        assert exit_code == 0

        # enabled: True is omitted from YAML (it's the default),
        # so absent means enabled
        cli = _read_yaml(self.cli_file(hermes_home))
        assert "patterns" in cli
        assert cli["patterns"][0].get("enabled", True) is True

    # --- list ---

    def test_list_from_dir(self, cli_module, hermes_home):
        """List reads merged config from directory."""
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS, SIMPLE_ALLOW_PATTERNS))

        output, exit_code = cli_module.cmd_list()
        assert exit_code == 0
        assert "BLOCK patterns" in output
        assert "ALLOW patterns" in output
        assert "Vultr CLI" in output
        assert "Vultr info" in output

    # --- 99-custom.yaml persistence ---

    def test_multiple_adds_accumulate(self, cli_module, hermes_home):
        """Multiple add operations accumulate entries in 99-custom.yaml."""
        self.setup_dir(hermes_home, _config())

        cli_module.cmd_add(pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI")
        cli_module.cmd_add(pattern_type="block", pattern=r"\bazure\b", description="Azure CLI")

        cli = _read_yaml(self.cli_file(hermes_home))
        assert len(cli.get("patterns", [])) == 2
        descs = _pattern_descriptions(cli["patterns"])
        assert "GCP CLI" in descs
        assert "Azure CLI" in descs

    def test_remove_then_add_preserves_other_entries(self, cli_module, hermes_home):
        """Removing one pattern then adding another preserves both entries in 99-custom."""
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS))

        # Remove Vultr -> writes disabled entry to 99-custom
        cli_module.cmd_remove(target="1", force=True)
        # Add new pattern -> writes new entry alongside existing disabled
        cli_module.cmd_add(
            pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI",
        )

        cli = _read_yaml(self.cli_file(hermes_home))
        assert len(cli.get("patterns", [])) == 2
        vultr = [e for e in cli["patterns"] if "Vultr" in e.get("description", "")]
        gcp = [e for e in cli["patterns"] if "GCP" in e.get("description", "")]
        assert len(vultr) == 1
        assert vultr[0].get("enabled") is False
        assert len(gcp) == 1
        # enabled: True is omitted from YAML (default), so absent means enabled
        assert gcp[0].get("enabled", True) is True

    def test_manually_removed_pattern_stays_removed_after_add(
        self, cli_module, hermes_home,
    ):
        """Pattern manually removed from source file stays removed after a CLI add.

        This is the regression test for the bug where patterns manually
        removed from source files were re-added by the next CLI operation.
        """
        # Setup: source has pattern X, 99-custom has pattern X as disabled (from a prev removal)
        self.setup_dir(hermes_home, _config(SIMPLE_BLOCK_PATTERNS))

        # Simulate: user adds a pattern via CLI (creates 99-custom)
        cli_module.cmd_add(pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI")

        # Simulate: user manually removes pattern from source
        _write_yaml(
            self.source_file(hermes_home),
            _config([SIMPLE_BLOCK_PATTERNS[1]]),  # only AWS, Vultr removed
        )

        # Now user does another CLI operation (add)
        cli_module.cmd_add(
    pattern_type="allow", pattern=r"\bgcloud\s+info\b", description="GCP info",
)

        # Vultr should NOT have been re-added to 99-custom
        cli = _read_yaml(self.cli_file(hermes_home))
        descs = _pattern_descriptions(cli.get("patterns", []))
        assert "Vultr CLI" not in descs, (
            "Vultr was re-added to 99-custom after being manually removed from source"
        )


# ---------------------------------------------------------------------------
# Combined mode: both .yaml and .d/ exist
# ---------------------------------------------------------------------------


class TestCombinedMode:
    """Test CLI commands when both .yaml file and directory exist."""

    @staticmethod
    def dir_path(hermes_home: Path) -> Path:
        return hermes_home / "custom-dangerous-patterns"

    @staticmethod
    def yaml_path(hermes_home: Path) -> Path:
        return hermes_home / "custom-dangerous-patterns.yaml"

    @staticmethod
    def cli_file(hermes_home: Path) -> Path:
        return TestCombinedMode.dir_path(hermes_home) / "99-custom.yaml"

    def setup_combined(
        self, hermes_home: Path,
        yaml_config: dict[str, Any],
        dir_files: dict[str, dict[str, Any]],
    ) -> None:
        """Set up both a .yaml file and a directory with files."""
        _write_yaml(self.yaml_path(hermes_home), yaml_config)
        d = self.dir_path(hermes_home)
        d.mkdir(parents=True, exist_ok=True)
        for filename, config in dir_files.items():
            _write_yaml(d / filename, config)

    # --- resolve_config_path returns dir in combined mode ---

    def test_add_in_combined_mode(self, cli_module, hermes_home):
        """Adding in combined mode writes delta to 99-custom.yaml."""
        self.setup_combined(
            hermes_home,
            _config([SIMPLE_BLOCK_PATTERNS[0]]),  # Vultr in .yaml
            {"00-test.yaml": _config([SIMPLE_BLOCK_PATTERNS[1]])},  # AWS in .d/
        )

        output, exit_code = cli_module.cmd_add(
            pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI",
        )
        assert exit_code == 0

        # Write goes to 99-custom.yaml
        cli = _read_yaml(self.cli_file(hermes_home))
        assert "GCP CLI" in _pattern_descriptions(cli.get("patterns", []))

    def test_list_in_combined_mode_merges_both(self, cli_module, hermes_home):
        """List in combined mode shows patterns from both .yaml and .d/."""
        self.setup_combined(
            hermes_home,
            _config([SIMPLE_BLOCK_PATTERNS[0]]),  # Vultr in .yaml
            {"00-test.yaml": _config([SIMPLE_BLOCK_PATTERNS[1]])},  # AWS in .d/
        )

        output, exit_code = cli_module.cmd_list()
        assert exit_code == 0
        assert "Vultr CLI" in output
        assert "AWS CLI" in output

    def test_remove_in_combined_mode(self, cli_module, hermes_home):
        """Removing in combined mode writes disabled entry to 99-custom."""
        self.setup_combined(
            hermes_home,
            _config([SIMPLE_BLOCK_PATTERNS[0]]),  # Vultr in .yaml
            {"00-test.yaml": _config([SIMPLE_BLOCK_PATTERNS[1]])},  # AWS in .d/
        )

        output, exit_code = cli_module.cmd_remove(target="1", force=True)
        assert exit_code == 0

        cli = _read_yaml(self.cli_file(hermes_home))
        assert len(cli.get("patterns", [])) == 1
        assert cli["patterns"][0]["description"] == "Vultr CLI"
        assert cli["patterns"][0].get("enabled") is False

    def test_disable_then_reload_shows_disabled(
        self, cli_module, hermes_home,
    ):
        """After disable+reload, the merged config shows pattern as disabled."""
        self.setup_combined(
            hermes_home,
            _config([SIMPLE_BLOCK_PATTERNS[0]]),  # Vultr enabled in .yaml
            {},
        )

        # Disable via CLI
        cli_module.cmd_disable(target="1")

        # Reload and verify merged config sees it as disabled
        from config import load_config
        config = load_config(force=True)
        vultr = [e for e in config.get("patterns", []) if "Vultr" in e.get("description", "")]
        assert len(vultr) == 1
        assert vultr[0].get("enabled") is False

    def test_sibling_yaml_preserved_after_cli_operations(
        self, cli_module, hermes_home,
    ):
        """The sibling .yaml file is never modified by CLI operations."""
        yaml_content = _config([SIMPLE_BLOCK_PATTERNS[0]])
        self.setup_combined(hermes_home, yaml_content, {})

        # Run several CLI operations
        cli_module.cmd_add(pattern_type="block", pattern=r"\bgcloud\b", description="GCP CLI")
        cli_module.cmd_disable(target="1")

        # .yaml file should be untouched
        yaml_on_disk = _read_yaml(self.yaml_path(hermes_home))
        assert yaml_on_disk == yaml_content


# ---------------------------------------------------------------------------
# Error handling & edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Test error handling and edge cases across all modes."""

    def test_add_requires_type_pattern_description(self, cli_module, hermes_home):
        """Non-interactive add requires --type, --pattern, --description."""
        output, exit_code = cli_module.cmd_add(pattern="test", description="Test")
        assert exit_code == 1
        assert "required" in output

    def test_remove_no_config(self, cli_module, hermes_home):
        """Remove with no config shows init suggestion."""
        output, exit_code = cli_module.cmd_remove(target="1")
        assert exit_code == 1
        assert "No config found" in output

    def test_enable_no_config(self, cli_module, hermes_home):
        """Enable with no config shows init suggestion."""
        output, exit_code = cli_module.cmd_enable(target="1")
        assert exit_code == 1
        assert "No config found" in output

    def test_add_invalid_regex(self, cli_module, hermes_home):
        """Adding a pattern with invalid regex returns error."""
        yaml_path = hermes_home / "custom-dangerous-patterns.yaml"
        _write_yaml(yaml_path, _config(SIMPLE_BLOCK_PATTERNS))

        output, exit_code = cli_module.cmd_add(
            pattern_type="block", pattern="[invalid", description="Bad regex",
        )
        assert exit_code == 1
        assert "invalid" in output.lower()
