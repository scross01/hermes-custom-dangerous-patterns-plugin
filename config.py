"""Configuration loading for custom-dangerous-patterns plugin.

Loads ~/.hermes/custom-dangerous-patterns.yaml, validates the schema,
and returns a structured config dict. Caches the result per-process so
repeated reads during pattern injection are free.

Config path can be overridden via HERMES_CUSTOM_PATTERNS_PATH env var.

v0.2.0: Config hash tracking and protected pattern tier. SHA-256 hash
of the config is persisted across sessions to detect tampering.
Protected patterns (protected: true) are verified at load.

v0.3.0: Switched from PyYAML to ruamel.yaml for YAML handling.
Added save_config() for CLI write-back support. Note: CLI write
operations (add, remove, enable, disable) will not preserve
user comments/formatting in the config file. The validated config
dict is a normalized representation — YAML comments are lost
at load time because the validation step builds a fresh dict.
Full round-trip comment preservation is deferred to a future
release requiring in-place editing of ruamel.yaml's CommentedMap
structures.
"""

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
      2. ~/.hermes/custom-dangerous-patterns.yaml (single file)
      3. ~/.hermes/custom-dangerous-patterns.d/ (directory of YAML files)
    """
    env_path = os.environ.get(_ENV_OVERRIDE, "").strip()
    if env_path:
        return Path(env_path).expanduser()

    try:
        from hermes_constants import get_hermes_home
        hermes_home = get_hermes_home()
    except ImportError:
        hermes_home = Path.home() / ".hermes"

    single_file = hermes_home / _DEFAULT_CONFIG_FILENAME
    if single_file.is_file():
        return single_file

    dir_path = hermes_home / "custom-dangerous-patterns.d"
    if dir_path.is_dir():
        return dir_path

    return single_file  # return default even if missing (will log warning)


def resolve_config_path() -> Path:
    """Public API for path resolution (v0.3.0).

    Same as _resolve_config_path but importable by CLI modules.
    """
    return _resolve_config_path()


def get_config_path_display() -> str:
    """Return a human-readable description of the config path (v0.3.0).

    Includes whether the config is a single file or directory.
    """
    path = _resolve_config_path()
    if path.is_dir():
        yaml_files = sorted(path.glob("*.yaml"))
        return f"{path} ({len(yaml_files)} files loaded)"
    return str(path)


# ---------------------------------------------------------------------------
# YAML loading (lazy import — yaml is optional at module level)
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any] | None:
    """Parse a YAML file or directory of *.yaml files.

    If path is a directory, loads all *.yaml files in alphabetical
    order and merges them (later files' lists append, later files'
    scalars override). Returns None on missing/unreadable/invalid.
    """
    # Directory mode (v0.2.0): load *.yaml files in alphabetical order
    if path.is_dir():
        yaml_files = sorted(path.glob("*.yaml"))
        if not yaml_files:
            logger.debug(
                "custom-dangerous-patterns: no *.yaml files in directory %s",
                path,
            )
            return None
        merged: dict[str, Any] = {}
        for yf in yaml_files:
            single = _load_single_yaml(yf)
            if single:
                for key, val in single.items():
                    if key in merged and isinstance(merged[key], list) and isinstance(val, list):
                        merged[key].extend(val)
                    else:
                        merged[key] = val
                merged.setdefault("patterns", [])
                merged.setdefault("allow_patterns", [])
                merged.setdefault("deny_patterns", [])
        if merged:
            logger.info(
                "custom-dangerous-patterns: loaded config from %d files in %s",
                len(yaml_files),
                path,
            )
        return merged if merged else None

    # Single file mode
    return _load_single_yaml(path)


def _load_single_yaml(path: Path) -> dict[str, Any] | None:
    """Parse a single YAML file. Returns None on missing/unreadable/invalid."""
    if not path.is_file():
        logger.debug("custom-dangerous-patterns: config not found at %s", path)
        return None

    try:
        from ruamel.yaml import YAML
    except ImportError:
        logger.warning(
            "custom-dangerous-patterns: ruamel.yaml not installed -- cannot load config. "
            "Install with: pip install ruamel.yaml"
        )
        return None

    try:
        yaml = YAML(typ="safe")
        raw = yaml.load(path.read_text(encoding="utf-8"))
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
# Config write-back (v0.3.0)
# ---------------------------------------------------------------------------


def save_config(config_dict: dict[str, Any], path: Path | None = None) -> Path:
    """Serialize the config dict back to YAML and write to disk.

    Uses ruamel.yaml for comment-preserving round-trips. For single-file
    configs, writes atomically (temp file + rename). For directory configs,
    writes to the last file in the merge order.

    Args:
        config_dict: The validated config dict with 'patterns',
                     'allow_patterns', and 'deny_patterns' keys.
        path: Target path. If None, uses the default resolved config path.

    Returns:
        The path that was written to.

    Raises:
        ImportError: If ruamel.yaml is not installed.
        OSError: If the file cannot be written.
    """
    from ruamel.yaml import YAML

    if path is None:
        path = _resolve_config_path()

    # Directory mode: write to the last file (highest precedence)
    if path.is_dir():
        yaml_files = sorted(path.glob("*.yaml"))
        if yaml_files:
            path = yaml_files[-1]
        else:
            path = path / "00-custom.yaml"

    # Build the output dict — only include non-empty sections
    output: dict[str, Any] = {}
    for key in ("patterns", "allow_patterns", "deny_patterns"):
        entries = config_dict.get(key, [])
        if entries:
            output[key] = _clean_for_serialization(entries)

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write atomically: temp file, then rename
    import tempfile

    tmp_path = Path(tempfile.mktemp(suffix=".yaml", dir=path.parent))
    try:
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.dump(output, f)
        tmp_path.replace(path)
        logger.info(
            "custom-dangerous-patterns: saved config to %s",
            path,
        )
    except Exception:
        # Clean up temp file on failure
        if tmp_path.exists():
            tmp_path.unlink()
        raise

    return path


def _clean_for_serialization(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove internal-only fields and empty optional fields for clean YAML output."""
    cleaned = []
    for entry in entries:
        out: dict[str, Any] = {
            "pattern": entry["pattern"],
            "description": entry.get("description", ""),
        }
        # Only include non-default optional fields
        if entry.get("examples"):
            out["examples"] = entry["examples"]
        if entry.get("enabled") is False:
            out["enabled"] = False
        if entry.get("group"):
            out["group"] = entry["group"]
        if entry.get("protected") is True:
            out["protected"] = True
        cleaned.append(out)
    return cleaned


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

    # Collect current protected patterns with index-prefixed keys
    current = {}
    for section in ("patterns", "allow_patterns", "deny_patterns"):
        entries = validated_config.get(section, [])
        for index, entry in enumerate(entries):
            if entry.get("protected") and entry.get("enabled", True):
                key = f"{index}:{entry['description']}"
                current[key] = hashlib.sha256(
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
        entries = validated_config.get(section, [])
        for index, entry in enumerate(entries):
            if entry.get("protected") and entry.get("enabled", True):
                protected_hashes[f"{index}:{entry['description']}"] = hashlib.sha256(
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
