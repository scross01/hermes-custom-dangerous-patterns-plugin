"""Configuration loading for custom-dangerous-patterns plugin.

Loads ~/.hermes/custom-dangerous-patterns.yaml, validates the schema,
and returns a structured config dict. Caches the result per-process so
repeated reads during pattern injection are free.

Config path can be overridden via HERMES_CUSTOM_PATTERNS_PATH env var.

v0.2.0: Config hash tracking and protected pattern tier. SHA-256 hash
of the config is persisted across sessions to detect tampering.
Protected patterns (protected: true) are verified at load."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILENAME = "custom-dangerous-patterns.yaml"
_HASH_FILENAME = ".custom-patterns-hash"
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

    protected = entry.get("protected", False)
    if not isinstance(protected, bool):
        protected = False

    return {
        "pattern": pattern.strip(),
        "description": description.strip(),
        "examples": examples,
        "enabled": enabled,
        "group": group.strip(),
        "protected": protected,
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
# Hash / integrity (v0.2.0)
# ---------------------------------------------------------------------------


def _resolve_hash_path(config_path: Path) -> Path:
    """Return the path to the integrity hash file.

    Lives alongside the config file in the same directory.
    """
    return config_path.parent / _HASH_FILENAME


def _compute_config_hash(raw_yaml_text: str) -> str:
    """Compute SHA-256 hash of raw config YAML text."""
    return hashlib.sha256(raw_yaml_text.encode("utf-8")).hexdigest()


def _load_hash_data(hash_path: Path) -> dict[str, Any]:
    """Load the previous integrity hash file. Returns empty dict if missing."""
    if not hash_path.is_file():
        return {}
    try:
        return json.loads(hash_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.warning(
            "custom-dangerous-patterns: cannot read hash file at %s",
            hash_path,
        )
        return {}


def _save_hash_data(hash_path: Path, data: dict[str, Any]) -> None:
    """Persist integrity hash data."""
    try:
        hash_path.parent.mkdir(parents=True, exist_ok=True)
        hash_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.debug(
            "custom-dangerous-patterns: saved integrity hash to %s",
            hash_path,
        )
    except OSError as exc:
        logger.warning(
            "custom-dangerous-patterns: cannot write hash file at %s: %s",
            hash_path,
            exc,
        )


def _check_protected_patterns(
    validated_config: dict[str, Any],
    previous_hash_data: dict[str, Any],
) -> None:
    """Verify protected patterns are present and unmodified.

    Protected patterns must exist in the config and their regex must
    match the stored hash from the previous session.
    """
    stored_protected = previous_hash_data.get("protected", {})
    if not stored_protected:
        return  # No previously recorded protected patterns

    # Collect current protected patterns by description
    current = {}
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in validated_config.get(section, []):
            if entry.get("protected") and entry.get("enabled", True):
                desc = entry["description"]
                current[desc] = hashlib.sha256(
                    entry["pattern"].encode("utf-8")
                ).hexdigest()

    # Check for missing protected patterns
    missing = []
    modified = []
    for desc, expected_hash in stored_protected.items():
        if desc not in current:
            missing.append(desc)
        elif current[desc] != expected_hash:
            modified.append(desc)

    if missing:
        logger.critical(
            "custom-dangerous-patterns: PROTECTED PATTERN MISSING: %s. "
            "These patterns were previously marked as protected and are no "
            "longer present in the config. This may indicate accidental removal "
            "or tampering.",
            ", ".join(missing),
        )

    if modified:
        logger.critical(
            "custom-dangerous-patterns: PROTECTED PATTERN MODIFIED: %s. "
            "These patterns were previously marked as protected and their regex "
            "has changed. Review the changes in ~/.hermes/custom-dangerous-patterns.yaml.",
            ", ".join(modified),
        )


def _check_config_integrity(
    config_path: Path,
    raw_yaml_text: str,
    validated_config: dict[str, Any],
    integrity_check: bool,
) -> None:
    """Run integrity checks: hash comparison and protected pattern verification."""
    if not integrity_check:
        return

    hash_path = _resolve_hash_path(config_path)
    previous = _load_hash_data(hash_path)
    current_hash = _compute_config_hash(raw_yaml_text)

    # Check config hash delta
    previous_hash = previous.get("config_hash")
    if previous_hash and previous_hash != current_hash:
        # Build a summary of what changed
        prev_n = previous.get("pattern_counts", {})
        curr_n = {
            "patterns": len(validated_config.get("patterns", [])),
            "allow_patterns": len(validated_config.get("allow_patterns", [])),
            "deny_patterns": len(validated_config.get("deny_patterns", [])),
        }
        logger.warning(
            "custom-dangerous-patterns: CONFIG CHANGED since last session. "
            "Previous pattern counts: %s. Current pattern counts: %s. "
            "Review changes in %s if unexpected.",
            prev_n,
            curr_n,
            config_path,
        )

    # Check protected patterns
    _check_protected_patterns(validated_config, previous)

    # Collect protected pattern hashes to store
    protected_hashes = {}
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        for entry in validated_config.get(section, []):
            if entry.get("protected") and entry.get("enabled", True):
                protected_hashes[entry["description"]] = hashlib.sha256(
                    entry["pattern"].encode("utf-8")
                ).hexdigest()

    # Save updated hash data
    new_data = {
        "config_hash": current_hash,
        "pattern_counts": {
            "patterns": len(validated_config.get("patterns", [])),
            "allow_patterns": len(validated_config.get("allow_patterns", [])),
            "deny_patterns": len(validated_config.get("deny_patterns", [])),
        },
        "protected": protected_hashes,
    }
    _save_hash_data(hash_path, new_data)


def load_config(force: bool = False, integrity_check: bool = True) -> dict[str, Any]:
    """Load, validate, and cache the custom patterns config.

    Returns a dict with keys:
      - 'patterns': list of {'pattern': str, 'description': str, ...}
      - 'allow_patterns': list of {'pattern': str, 'description': str, ...}
      - 'deny_patterns': list of {'pattern': str, 'description': str, ...}

    Returns empty lists if config is missing, invalid, or unreadable.
    Pass force=True to bypass the cache (useful for testing).
    Pass integrity_check=False to skip hash tracking (v0.2.0).
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
        # Run integrity checks if config loaded successfully
        if integrity_check and path.is_file():
            try:
                raw_text = path.read_text(encoding="utf-8")
                _check_config_integrity(path, raw_text, result, integrity_check)
            except OSError:
                pass  # Can't read for hashing — skip integrity check silently

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
