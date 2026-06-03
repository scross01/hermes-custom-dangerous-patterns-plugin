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
    """Full valid config returns both pattern lists."""
    from config import _validate_config

    result = _validate_config(sample_config)
    assert len(result["patterns"]) == 2
    assert len(result["allow_patterns"]) == 1


def test_validate_config_empty():
    """Empty config returns empty lists."""
    from config import _validate_config

    result = _validate_config({})
    assert result == {"patterns": [], "allow_patterns": []}


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
    assert result == {"patterns": [], "allow_patterns": []}


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

    result = load_config()
    assert len(result["patterns"]) == 1
    assert result["patterns"][0]["description"] == "GCP CLI"
