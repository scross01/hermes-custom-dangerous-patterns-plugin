"""Configuration loading for custom-dangerous-patterns plugin.

Loads ~/.hermes/custom-dangerous-patterns.yaml, validates the schema,
and returns a structured config dict. Caches the result per-process so
repeated reads during pattern injection are free.

Config path can be overridden via HERMES_CUSTOM_PATTERNS_PATH env var.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILENAME = "custom-dangerous-patterns.yaml"
_ENV_OVERRIDE = "HERMES_CUSTOM_PATTERNS_PATH"

# Module-level cache — loaded once per process, never stale within a run.
_config_cache: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------


def _resolve_config_path() -> Path:
    """Return the path to the user's custom patterns config file.

    Resolution order:
      1. HERMES_CUSTOM_PATTERNS_PATH env var
      2. ~/.hermes/custom-dangerous-patterns.yaml
    """
    env_path = os.environ.get(_ENV_OVERRIDE, "").strip()
    if env_path:
        return Path(env_path).expanduser()

    try:
        from hermes_constants import get_hermes_home

        return get_hermes_home() / _DEFAULT_CONFIG_FILENAME
    except ImportError:
        return Path.home() / ".hermes" / _DEFAULT_CONFIG_FILENAME


# ---------------------------------------------------------------------------
# YAML loading (lazy import — yaml is optional at module level)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """Parse a YAML file. Returns None on missing/unreadable/invalid."""
    if not path.is_file():
        logger.debug("custom-dangerous-patterns: config not found at %s", path)
        return None

    try:
        import yaml
    except ImportError:
        logger.warning(
            "custom-dangerous-patterns: PyYAML not installed — cannot load config. "
            "Install with: pip install pyyaml"
        )
        return None

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(
            "custom-dangerous-patterns: failed to read config at %s: %s",
            path,
            exc,
        )
        return None

    if not isinstance(raw, dict):
        logger.warning(
            "custom-dangerous-patterns: config at %s is not a YAML mapping (got %s)",
            path,
            type(raw).__name__,
        )
        return None

    return raw


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_pattern(entry: Any, index: int, field: str) -> dict[str, str] | None:
    """Validate a single pattern entry. Returns normalized dict or None."""
    if not isinstance(entry, dict):
        logger.warning(
            "custom-dangerous-patterns: %s[%d] must be a mapping, got %s — skipping",
            field,
            index,
            type(entry).__name__,
        )
        return None

    pattern = entry.get("pattern")
    if not isinstance(pattern, str) or not pattern.strip():
        logger.warning(
            "custom-dangerous-patterns: %s[%d] missing required 'pattern' string — skipping",
            field,
            index,
        )
        return None

    import re

    try:
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as exc:
        logger.warning(
            "custom-dangerous-patterns: %s[%d] invalid regex %r: %s — skipping",
            field,
            index,
            pattern,
            exc,
        )
        return None

    description = entry.get("description", "")
    if not isinstance(description, str):
        description = str(description)

    examples = entry.get("examples", [])
    if not isinstance(examples, list):
        examples = []

    # Optional fields (v0.2.0)
    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        enabled = True

    group = entry.get("group", "")
    if not isinstance(group, str):
        group = str(group)

    return {
        "pattern": pattern.strip(),
        "description": description.strip(),
        "examples": examples,
        "enabled": enabled,
        "group": group.strip(),
    }


def _validate_config(raw: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize the raw config dict.

    Returns a clean dict with 'patterns' and 'allow_patterns' lists.
    Invalid entries are logged and skipped — never raises.
    """
    result: dict[str, Any] = {"patterns": [], "allow_patterns": [], "deny_patterns": []}

    # Block patterns
    raw_patterns = raw.get("patterns")
    if raw_patterns is None:
        pass  # no patterns defined — valid
    elif not isinstance(raw_patterns, list):
        logger.warning(
            "custom-dangerous-patterns: 'patterns' must be a list, got %s",
            type(raw_patterns).__name__,
        )
    else:
        for i, entry in enumerate(raw_patterns):
            validated = _validate_pattern(entry, i, "patterns")
            if validated:
                result["patterns"].append(validated)

    # Allow patterns
    raw_allow = raw.get("allow_patterns")
    if raw_allow is None:
        pass
    elif not isinstance(raw_allow, list):
        logger.warning(
            "custom-dangerous-patterns: 'allow_patterns' must be a list, got %s",
            type(raw_allow).__name__,
        )
    else:
        for i, entry in enumerate(raw_allow):
            validated = _validate_pattern(entry, i, "allow_patterns")
            if validated:
                result["allow_patterns"].append(validated)

    # Deny patterns (v0.2.0) — matched commands are blocked immediately, no prompt
    raw_deny = raw.get("deny_patterns")
    if raw_deny is None:
        pass
    elif not isinstance(raw_deny, list):
        logger.warning(
            "custom-dangerous-patterns: 'deny_patterns' must be a list, got %s",
            type(raw_deny).__name__,
        )
    else:
        for i, entry in enumerate(raw_deny):
            validated = _validate_pattern(entry, i, "deny_patterns")
            if validated:
                result["deny_patterns"].append(validated)

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(force: bool = False) -> dict[str, Any]:
    """Load, validate, and cache the custom patterns config.

    Returns a dict with keys:
      - 'patterns': list of {'pattern': str, 'description': str, 'examples': list}
      - 'allow_patterns': list of {'pattern': str, 'description': str, 'examples': list}

    Returns empty lists if config is missing, invalid, or unreadable.
    Pass force=True to bypass the cache (useful for testing).
    """
    global _config_cache

    if _config_cache is not None and not force:
        return _config_cache

    path = _resolve_config_path()
    raw = _load_yaml(path)

    if raw is None:
        result = {"patterns": [], "allow_patterns": [], "deny_patterns": []}
    else:
        result = _validate_config(raw)

    n_block = len(result["patterns"])
    n_allow = len(result["allow_patterns"])
    n_deny = len(result["deny_patterns"])
    if n_block or n_allow or n_deny:
        logger.info(
            "custom-dangerous-patterns: loaded %d block, %d allow, %d deny patterns from %s",
            n_block,
            n_allow,
            n_deny,
            path,
        )

    _config_cache = result
    return result
