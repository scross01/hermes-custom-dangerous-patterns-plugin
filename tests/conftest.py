from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import types
from pathlib import Path
from typing import Any

import pytest

SAMPLE_CONFIG = {
    "patterns": [
        {
            "pattern": r"\bvultr\b",
            "description": "Vultr CLI command",
            "examples": ["vultr account info", "vultr instance list"],
        },
        {
            "pattern": r"\bterraform\s+(destroy|apply)\b",
            "description": "Terraform destroy/apply",
        },
    ],
    "allow_patterns": [
        {
            "pattern": r"\bvultr\s+account\s+info\b",
            "description": "Read-only Vultr account info",
        },
    ],
    "deny_patterns": [],
}

SAMPLE_YAML = """
patterns:
  - pattern: '\\bvultr\\b'
    description: 'Vultr CLI command'
    examples:
      - 'vultr account info'
      - 'vultr instance list'
  - pattern: '\\bterraform\\s+(destroy|apply)\\b'
    description: 'Terraform destroy/apply'

allow_patterns:
  - pattern: '\\bvultr\\s+account\\s+info\\b'
    description: 'Read-only Vultr account info'

deny_patterns: []
"""


@pytest.fixture
def tmp_hermes_home(tmp_path: Path) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    return home


@pytest.fixture
def config_path(tmp_hermes_home: Path) -> Path:
    return tmp_hermes_home / "custom-dangerous-patterns.yaml"


@pytest.fixture
def config_with_content(config_path: Path) -> Path:
    config_path.write_text(SAMPLE_YAML, encoding="utf-8")
    return config_path


@pytest.fixture
def sample_config() -> dict[str, Any]:
    return dict(SAMPLE_CONFIG)


@pytest.fixture
def reset_config_cache(monkeypatch):
    import config as config_module

    monkeypatch.setattr(config_module, "_config_cache", None)


@pytest.fixture
def reset_patterns_globals(monkeypatch):
    import patterns as patterns_module

    monkeypatch.setattr(patterns_module, "_block_compiled", [])
    monkeypatch.setattr(patterns_module, "_allow_compiled", [])
    monkeypatch.setattr(patterns_module, "_deny_compiled", [])


@pytest.fixture
def mock_hermes_constants(monkeypatch, tmp_hermes_home: Path):
    mock = types.ModuleType("hermes_constants")
    mock.get_hermes_home = lambda: tmp_hermes_home
    monkeypatch.setitem(sys.modules, "hermes_constants", mock)
    return mock


@pytest.fixture
def mock_tools(monkeypatch):
    tools = types.ModuleType("tools")
    monkeypatch.setitem(sys.modules, "tools", tools)
    return tools


@pytest.fixture
def mock_tools_approval(monkeypatch, mock_tools):
    approval = types.ModuleType("tools.approval")
    approval.DANGEROUS_PATTERNS = []
    approval.DANGEROUS_PATTERNS_COMPILED = []
    approval.detect_dangerous_command = lambda cmd: (False, None, None)
    mock_tools.approval = approval
    monkeypatch.setitem(sys.modules, "tools.approval", approval)
    return approval


@pytest.fixture
def mock_tools_ansi_strip(monkeypatch):
    m = types.ModuleType("tools.ansi_strip")
    m.strip_ansi = lambda s: s
    tools_inner = types.ModuleType("tools")
    tools_inner.ansi_strip = m
    monkeypatch.setitem(sys.modules, "tools", tools_inner)
    monkeypatch.setitem(sys.modules, "tools.ansi_strip", m)
    return m


@pytest.fixture
def init_register(monkeypatch):
    """Import __init__ under a package namespace so relative imports work.

    Hermes plugins use ``from .config import load_config`` relative imports.
    When pytest imports ``__init__`` as a top-level module, those relative
    imports fail at call time.  This fixture loads ``__init__`` as
    ``hermes_plugins._init_`` so that ``from .config`` resolves correctly.
    Also resets module-level caches to give each test a clean slate.
    """
    plugin_dir = Path(__file__).resolve().parent.parent

    pkg = types.ModuleType("hermes_plugins")
    pkg.__path__ = [str(plugin_dir)]
    monkeypatch.setitem(sys.modules, "hermes_plugins", pkg)

    modules = {}
    for name in ("config", "patterns"):
        spec = importlib.util.spec_from_file_location(
            f"hermes_plugins.{name}",
            plugin_dir / f"{name}.py",
        )
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, f"hermes_plugins.{name}", mod)
        spec.loader.exec_module(mod)
        modules[name] = mod

    loader = importlib.machinery.SourceFileLoader(
        "hermes_plugins._init_",
        str(plugin_dir / "__init__.py"),
    )
    spec = importlib.machinery.ModuleSpec("hermes_plugins._init_", loader)
    # spec_from_file_location on __init__.py (Python 3.14+) would auto-detect
    # __init__.py as a package and set parent to "hermes_plugins._init_", making
    # "from .config" resolve to hermes_plugins._init_.config instead of
    # hermes_plugins.config.  Using ModuleSpec directly avoids this heuristic
    # — parent defaults to "hermes_plugins" via rpartition.
    init_mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "hermes_plugins._init_", init_mod)
    spec.loader.exec_module(init_mod)

    # Attach sibling modules so tests can monkeypatch them
    init_mod.config = modules["config"]
    init_mod.patterns = modules["patterns"]

    # Reset module-level caches so each test starts fresh
    modules["config"]._config_cache = None
    modules["patterns"]._block_compiled = []
    modules["patterns"]._allow_compiled = []

    return init_mod
