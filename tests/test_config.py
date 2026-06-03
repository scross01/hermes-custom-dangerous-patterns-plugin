from __future__ import annotations

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# _resolve_config_path
# ---------------------------------------------------------------------------


def test_resolve_default_path_no_hermes_constants():
    """Fallback to ~/.hermes/ when hermes_constants is not importable."""
    mods = {k: v for k, v in sys.modules.items() if k != "hermes_constants"}
    with pytest.MonkeyPatch.context() as mp:
        mp.setitem(sys.modules, "hermes_constants", {})
        mp.delitem(sys.modules, "hermes_constants", raising=False)

        from config import _resolve_config_path

        result = _resolve_config_path()
    assert result == Path.home() / ".hermes" / "custom-dangerous-patterns.yaml"


def test_resolve_path_with_hermes_constants(mock_hermes_constants, tmp_hermes_home):
    """Uses hermes_constants.get_hermes_home() when available."""
    from config import _resolve_config_path

    result = _resolve_config_path()
    assert result == tmp_hermes_home / "custom-dangerous-patterns.yaml"


def test_resolve_path_env_var(monkeypatch, tmp_path):
    """HERMES_CUSTOM_PATTERNS_PATH env var takes precedence."""
    custom_path = tmp_path / "custom.yaml"
    monkeypatch.setenv("HERMES_CUSTOM_PATTERNS_PATH", str(custom_path))

    from config import _resolve_config_path

    result = _resolve_config_path()
    assert result == custom_path


# ---------------------------------------------------------------------------
# _load_yaml
# ---------------------------------------------------------------------------


def test_load_yaml_missing_file(tmp_path):
    """Missing file returns None."""
    from config import _load_yaml

    result = _load_yaml(tmp_path / "nonexistent.yaml")
    assert result is None


def test_load_yaml_valid(config_with_content):
    """Valid YAML file returns parsed dict."""
    from config import _load_yaml

    result = _load_yaml(config_with_content)
    assert isinstance(result, dict)
    assert "patterns" in result
    assert "allow_patterns" in result


def test_load_yaml_invalid_syntax(tmp_path):
    """Invalid YAML returns None."""
    path = tmp_path / "bad.yaml"
    path.write_text("{{{{ invalid: yaml", encoding="utf-8")

    from config import _load_yaml

    result = _load_yaml(path)
    assert result is None


def test_load_yaml_not_a_dict(tmp_path):
    """Non-dict YAML returns None."""
    path = tmp_path / "scalar.yaml"
    path.write_text("just a string", encoding="utf-8")

    from config import _load_yaml

    result = _load_yaml(path)
    assert result is None


# ---------------------------------------------------------------------------
# _validate_pattern
# ---------------------------------------------------------------------------


def test_validate_pattern_valid():
    """Valid pattern dict returns normalized entry."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI", "examples": ["vultr list"]},
        0,
        "patterns",
    )
    assert result is not None
    assert result["pattern"] == r"\bvultr\b"
    assert result["description"] == "Vultr CLI"
    assert result["examples"] == ["vultr list"]
    assert result["enabled"] is True  # default
    assert result["group"] == ""  # default


def test_validate_pattern_disabled():
    """Pattern with enabled: false is preserved as disabled."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI", "enabled": False},
        0,
        "patterns",
    )
    assert result is not None
    assert result["enabled"] is False


def test_validate_pattern_with_group():
    """Pattern with group tag preserves the group."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI", "group": "cloud"},
        0,
        "patterns",
    )
    assert result is not None
    assert result["group"] == "cloud"


def test_validate_pattern_enabled_non_bool_defaults_true():
    """Non-bool enabled value defaults to True."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI", "enabled": "yes"},
        0,
        "patterns",
    )
    assert result is not None
    assert result["enabled"] is True


def test_validate_pattern_protected():
    """Pattern with protected: true preserves the flag."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI", "protected": True},
        0,
        "patterns",
    )
    assert result is not None
    assert result["protected"] is True


def test_validate_pattern_protected_defaults_false():
    """Pattern without protected field defaults to False."""
    from config import _validate_pattern

    result = _validate_pattern(
        {"pattern": r"\bvultr\b", "description": "Vultr CLI"},
        0,
        "patterns",
    )
    assert result is not None
    assert result["protected"] is False


def test_validate_pattern_not_a_dict():
    """Non-dict entry returns None."""
    from config import _validate_pattern

    result = _validate_pattern("not a dict", 0, "patterns")
    assert result is None


def test_validate_pattern_missing_pattern():
    """Missing pattern field returns None."""
    from config import _validate_pattern

    result = _validate_pattern({"description": "no pattern here"}, 0, "patterns")
    assert result is None


def test_validate_pattern_empty_pattern():
    """Empty pattern string returns None."""
    from config import _validate_pattern

    result = _validate_pattern({"pattern": ""}, 0, "patterns")
    assert result is None


def test_validate_pattern_invalid_regex():
    """Invalid regex returns None."""
    from config import _validate_pattern

    result = _validate_pattern({"pattern": "[invalid"}, 0, "patterns")
    assert result is None


# ---------------------------------------------------------------------------
# _validate_config
# ---------------------------------------------------------------------------


def test_validate_config_full(sample_config):
    """Full valid config returns all three pattern lists."""
    from config import _validate_config

    result = _validate_config(sample_config)
    assert len(result["patterns"]) == 2
    assert len(result["allow_patterns"]) == 1
    assert len(result["deny_patterns"]) == 0


def test_validate_config_with_deny_patterns():
    """Config with deny_patterns validates correctly."""
    from config import _validate_config

    raw = {
        "deny_patterns": [
            {"pattern": r"\bruby\s+-e\s+.*system\b", "description": "Ruby system exec"},
        ],
    }
    result = _validate_config(raw)
    assert len(result["deny_patterns"]) == 1
    assert result["deny_patterns"][0]["description"] == "Ruby system exec"


def test_validate_config_deny_not_list():
    """deny_patterns field that is not a list logs warning, returns empty."""
    from config import _validate_config

    result = _validate_config({"deny_patterns": "not a list"})
    assert result["deny_patterns"] == []


def test_validate_config_empty():
    """Empty config returns empty lists."""
    from config import _validate_config

    result = _validate_config({})
    assert result == {"patterns": [], "allow_patterns": [], "deny_patterns": []}


def test_validate_config_patterns_not_list():
    """patterns field that is not a list logs warning, returns empty."""
    from config import _validate_config

    result = _validate_config({"patterns": "not a list"})
    assert result["patterns"] == []


def test_validate_config_allow_not_list():
    """allow_patterns field that is not a list logs warning, returns empty."""
    from config import _validate_config

    result = _validate_config({"allow_patterns": "not a list"})
    assert result["allow_patterns"] == []


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------


def test_load_config_missing_defaults(reset_config_cache, mock_hermes_constants):
    """Missing config file returns empty pattern lists."""
    from config import load_config

    result = load_config()
    assert result == {"patterns": [], "allow_patterns": [], "deny_patterns": []}


def test_load_config_with_valid_config(reset_config_cache, config_with_content, mock_hermes_constants):
    """Valid config returns loaded patterns."""
    from config import load_config

    result = load_config()
    assert len(result["patterns"]) == 2
    assert len(result["allow_patterns"]) == 1


def test_load_config_caching(reset_config_cache, mock_hermes_constants, config_with_content):
    """Second call without force=True returns cached result."""
    from config import load_config

    first = load_config()
    second = load_config()
    assert second is first


def test_load_config_force_true(reset_config_cache, mock_hermes_constants, config_with_content):
    """force=True bypasses cache."""
    from config import load_config

    first = load_config()

    import config as cfg

    cfg._config_cache = {"patterns": [], "allow_patterns": []}
    forced = load_config(force=True)
    assert len(forced["patterns"]) == 2


def test_load_config_env_var_override(reset_config_cache, tmp_path, monkeypatch):
    """Config loaded from env var override path."""
    custom_path = tmp_path / "custom.yaml"
    custom_path.write_text(
        """
patterns:
  - pattern: '\\bgcloud\\b'
    description: 'GCP CLI'
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_CUSTOM_PATTERNS_PATH", str(custom_path))

    from config import load_config

    result = load_config(integrity_check=False)
    assert len(result["patterns"]) == 1
    assert result["patterns"][0]["description"] == "GCP CLI"


# ---------------------------------------------------------------------------
# Hash / integrity (v0.2.0)
# ---------------------------------------------------------------------------


def test_resolve_hash_path():
    """Hash file is alongside config in the same directory."""
    from pathlib import Path
    from config import _resolve_hash_path

    config_path = Path("/home/user/.hermes/custom-dangerous-patterns.yaml")
    result = _resolve_hash_path(config_path)
    assert result == Path("/home/user/.hermes/.custom-patterns-hash")


def test_compute_config_hash():
    """Same text produces same hash, different text produces different hash."""
    from config import _compute_config_hash

    h1 = _compute_config_hash("patterns:\n  - pattern: test")
    h2 = _compute_config_hash("patterns:\n  - pattern: test")
    h3 = _compute_config_hash("patterns:\n  - pattern: other")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 64  # SHA-256 hex digest


def test_load_hash_data_missing(tmp_path):
    """Missing hash file returns empty dict."""
    from config import _load_hash_data

    result = _load_hash_data(tmp_path / "nonexistent.json")
    assert result == {}


def test_load_hash_data_valid(tmp_path):
    """Valid hash file returns parsed data."""
    from config import _load_hash_data

    hash_path = tmp_path / "hash.json"
    hash_path.write_text('{"config_hash": "abc123"}', encoding="utf-8")
    result = _load_hash_data(hash_path)
    assert result == {"config_hash": "abc123"}


def test_save_and_load_hash_data_roundtrip(tmp_path):
    """Saved hash data can be loaded back."""
    from config import _save_hash_data, _load_hash_data

    hash_path = tmp_path / "hash.json"
    data = {"config_hash": "def456", "protected": {"key": "hash"}}
    _save_hash_data(hash_path, data)
    loaded = _load_hash_data(hash_path)
    assert loaded == data


def test_check_protected_patterns_missing(caplog):
    """Missing protected pattern logs CRITICAL."""
    from config import _check_protected_patterns

    validated = {"patterns": []}
    previous = {"protected": {"Critical Pattern": "somehash"}}

    with caplog.at_level("CRITICAL"):
        _check_protected_patterns(validated, previous)

    assert any("PROTECTED PATTERN MISSING" in r.message for r in caplog.records)
    assert any("Critical Pattern" in r.message for r in caplog.records)


def test_check_protected_patterns_modified(caplog):
    """Modified protected pattern regex logs CRITICAL."""
    import hashlib
    from config import _check_protected_patterns

    validated = {
        "patterns": [
            {
                "pattern": r"\bnewpattern\b",
                "description": "Critical Pattern",
                "protected": True,
                "enabled": True,
            }
        ]
    }
    previous = {
        "protected": {
            "Critical Pattern": hashlib.sha256(
                r"\bOldPattern\b".encode("utf-8")
            ).hexdigest()
        }
    }

    with caplog.at_level("CRITICAL"):
        _check_protected_patterns(validated, previous)

    assert any("PROTECTED PATTERN MODIFIED" in r.message for r in caplog.records)


def test_check_protected_patterns_unchanged(caplog):
    """Unchanged protected pattern logs nothing."""
    import hashlib
    from config import _check_protected_patterns

    validated = {
        "patterns": [
            {
                "pattern": r"\bvultr\b",
                "description": "Vultr CLI",
                "protected": True,
                "enabled": True,
            }
        ]
    }
    previous = {
        "protected": {
            "Vultr CLI": hashlib.sha256(r"\bvultr\b".encode("utf-8")).hexdigest()
        }
    }

    with caplog.at_level("CRITICAL"):
        _check_protected_patterns(validated, previous)

    assert not any("PROTECTED" in r.message for r in caplog.records)


def test_check_protected_patterns_no_previous(caplog):
    """No previous protected patterns logs nothing."""
    from config import _check_protected_patterns

    validated = {
        "patterns": [
            {
                "pattern": r"\bvultr\b",
                "description": "Vultr CLI",
                "protected": True,
                "enabled": True,
            }
        ]
    }

    with caplog.at_level("CRITICAL"):
        _check_protected_patterns(validated, {})

    assert not any("PROTECTED" in r.message for r in caplog.records)


def test_check_config_integrity_hash_changed(caplog, tmp_path):
    """Changed config hash logs WARNING on second run."""
    import json
    from config import _check_config_integrity

    config_path = tmp_path / "config.yaml"
    hash_path = tmp_path / ".custom-patterns-hash"
    raw_text = "patterns:\n  - pattern: test"
    validated = {"patterns": [{}], "allow_patterns": [], "deny_patterns": []}

    # Simulate a previous session with a different config hash
    hash_path.write_text(
        json.dumps({"config_hash": "0000111122223333", "pattern_counts": {"patterns": 0, "allow_patterns": 0, "deny_patterns": 0}}),
        encoding="utf-8",
    )

    with caplog.at_level("WARNING"):
        _check_config_integrity(config_path, raw_text, validated, True)

    assert any("CONFIG CHANGED" in r.message for r in caplog.records)


def test_check_config_integrity_first_run_no_warning(caplog, tmp_path):
    """First run (no previous hash) logs nothing about changes."""
    from config import _check_config_integrity

    config_path = tmp_path / "config.yaml"
    raw_text = "patterns: []"
    validated = {"patterns": [], "allow_patterns": [], "deny_patterns": []}

    with caplog.at_level("WARNING"):
        _check_config_integrity(config_path, raw_text, validated, True)

    assert not any("CONFIG CHANGED" in r.message for r in caplog.records)


def test_check_config_integrity_disabled(caplog, tmp_path):
    """integrity_check=False skips all checks."""
    from config import _check_config_integrity

    config_path = tmp_path / "config.yaml"
    raw_text = "patterns: []"
    validated = {"patterns": [], "allow_patterns": [], "deny_patterns": []}

    with caplog.at_level("WARNING"):
        _check_config_integrity(config_path, raw_text, validated, False)

    assert not caplog.records


def test_load_config_with_integrity_check(reset_config_cache, config_with_content, mock_hermes_constants):
    """load_config runs integrity checks by default."""
    from config import load_config

    result = load_config()
    assert len(result["patterns"]) == 2


def test_load_config_skip_integrity(reset_config_cache, config_with_content, mock_hermes_constants):
    """load_config skips integrity when integrity_check=False."""
    from config import load_config

    result = load_config(integrity_check=False)
    assert len(result["patterns"]) == 2
