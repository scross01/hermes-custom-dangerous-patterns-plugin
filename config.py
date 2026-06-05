"""Configuration loading for custom-dangerous-patterns plugin.

Loads ~/.hermes/custom-dangerous-patterns.yaml, validates the schema,
and returns a structured config dict. Caches the result per-process so
repeated reads during pattern injection are free.

Config path can be overridden via HERMES_CUSTOM_PATTERNS_PATH env var.
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
      3. ~/.hermes/custom-dangerous-patterns/ (directory of YAML files)

    When both the single file and the directory exist (combined mode),
    the directory is returned so that CLI write operations (add, remove,
    enable, disable) go to ``99-custom.yaml`` inside the directory.
    Loading merges both locations — see :func:`_load_yaml`.
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
    dir_path = hermes_home / "custom-dangerous-patterns"

    # Combined mode: both exist — prefer dir for writes; loading merges both
    if single_file.is_file() and dir_path.is_dir():
        return dir_path

    if single_file.is_file():
        return single_file

    if dir_path.is_dir():
        return dir_path

    return dir_path  # return default even if missing (will log warning)


def resolve_config_path() -> Path:
    """Public API for path resolution.

    Same as _resolve_config_path but importable by CLI modules.
    """
    return _resolve_config_path()


def get_config_path_display() -> str:
    """Return a human-readable description of the config path.

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

        # Combined mode: start by loading the sibling .yaml file as baseline
        # (e.g., ~/.hermes/custom-dangerous-patterns.yaml alongside
        #  ~/.hermes/custom-dangerous-patterns/). Directory files are
        # merged on top so they take precedence via dedup (last wins).
        sibling_file = path.parent / (path.stem + ".yaml")
        if sibling_file.is_file():
            base = _load_single_yaml(sibling_file) or {}
        else:
            base = {}

        if not yaml_files and not base:
            logger.debug(
                "custom-dangerous-patterns: no *.yaml files in directory %s",
                path,
            )
            return None

        merged: dict[str, Any] = dict(base)
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
        # Ensure sections exist even if neither base nor any yaml_file had them
        for key in ("patterns", "allow_patterns", "deny_patterns"):
            if key not in merged:
                merged[key] = []
    # Deduplicate pattern entries by key (later files win) so that
    # removals written to 99-custom.yaml (enabled: False) correctly
    # override matching entries from user-created files — without
    # this, the same pattern appears once enabled and once disabled.
        for section in ("patterns", "allow_patterns", "deny_patterns"):
            if section in merged:
                merged[section] = _dedup_entries(merged[section])
        if merged:
            source_desc = f"{len(yaml_files)} files in {path}"
            if base:
                source_desc += f" + {sibling_file.name}"
            logger.info(
                "custom-dangerous-patterns: loaded config from %s",
                source_desc,
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

    glob_str = entry.get("glob")
    if glob_str is not None and not isinstance(glob_str, str):
        glob_str = None

    result = {
        "pattern": pattern.strip(),
        "description": description.strip(),
        "examples": examples,
        "enabled": enabled,
        "group": group.strip(),
        "protected": protected,
    }
    if glob_str:
        result["glob"] = glob_str
    return result


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
# Config write-back
# ---------------------------------------------------------------------------


_CLI_WRITE_FILENAME = "99-custom.yaml"
"""Filename used in directory mode for all CLI write operations.

Sorts last alphabetically so it has highest merge precedence. When
config is a directory, CLI commands (add, remove, enable, disable)
write only the delta (changed entries) to this file — user-created
files are never touched and the full merged config is never written
here, avoiding pattern duplication on reload.
"""


def save_config(config_dict: dict[str, Any], path: Path | None = None) -> Path:
    """Serialize the config dict back to YAML and write to disk.

    Uses ruamel.yaml for comment-preserving round-trips. For single-file
    configs, writes atomically (temp file + rename). For directory configs,
    computes the delta between user files and the merged config, writing
    only the changed entries to a dedicated ``99-custom.yaml`` file that
    sorts last in the merge order — user-created files are never touched
    and pattern duplication on reload is avoided.

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
    if path is None:
        path = _resolve_config_path()

    # Directory mode: compute delta and write only changed entries
    if path.is_dir():
        target = path / _CLI_WRITE_FILENAME

        # Load user baseline: directory files (excluding 99-custom.yaml)
        user_config = _load_yaml_excluding(path, _CLI_WRITE_FILENAME)

        # Combined mode: also include the sibling .yaml file in the baseline
        sibling_file = path.parent / (path.stem + ".yaml")
        if sibling_file.is_file():
            sibling = _load_single_yaml(sibling_file)
            if sibling:
                if user_config is None:
                    user_config = dict(sibling)
                else:
                    for key, val in sibling.items():
                        if (
                            key in user_config
                            and isinstance(user_config[key], list)
                            and isinstance(val, list)
                        ):
                            user_config[key].extend(val)
                        else:
                            user_config[key] = val
                    for key in ("patterns", "allow_patterns", "deny_patterns"):
                        user_config.setdefault(key, [])

        # Load existing 99-custom.yaml to include in the user baseline
        # (so patterns previously written via CLI aren't detected as "new"
        # by delta computation) AND to preserve them in the output.
        existing_cli: dict[str, Any] = {}
        if target.is_file():
            loaded = _load_single_yaml(target)
            if loaded:
                existing_cli = loaded

        # Include 99-custom.yaml entries in the user baseline so the delta
        # recognizes them as existing (not new). Without this, patterns
        # previously written to 99-custom.yaml get detected as "new" on
        # every CLI operation and re-written, accumulating stale entries.
        if existing_cli:
            if user_config is None:
                user_config = dict(existing_cli)
            else:
                for key, val in existing_cli.items():
                    if (
                        key in user_config
                        and isinstance(user_config[key], list)
                        and isinstance(val, list)
                    ):
                        user_config[key].extend(val)
                    else:
                        user_config[key] = val
                for key in ("patterns", "allow_patterns", "deny_patterns"):
                    user_config.setdefault(key, [])

        user_validated = (
            _validate_config(user_config)
            if user_config
            else {"patterns": [], "allow_patterns": [], "deny_patterns": []}
        )
        # Also dedup the user baseline so comparison is correct
        for section in ("patterns", "allow_patterns", "deny_patterns"):
            user_validated[section] = _dedup_entries(user_validated[section])
        delta = _compute_delta(user_validated, config_dict)

        # Build output: start with existing 99-custom.yaml entries, overlay
        # delta on top (delta replaces matching entries by pattern key).
        # This preserves pre-existing entries in 99-custom.yaml that haven't
        # changed, preventing them from being lost on every rewrite.
        output: dict[str, Any] = dict(existing_cli) if existing_cli else {}
        for key in ("patterns", "allow_patterns", "deny_patterns"):
            delta_entries = delta.get(key, [])
            existing_section = output.get(key, []) if output else []

            if not delta_entries and not existing_section:
                continue

            if delta_entries:
                # Replace matching entries in output with delta entries
                delta_keys = {_pattern_key(e) for e in delta_entries}
                filtered_existing = [
                    e for e in existing_section
                    if _pattern_key(e) not in delta_keys
                ]
                combined = (
                    _clean_for_serialization(filtered_existing)
                    + _clean_for_serialization(delta_entries)
                )
            else:
                # No delta changes — keep existing entries as-is
                if existing_section:
                    combined = _clean_for_serialization(existing_section)
                else:
                    continue

            if combined:
                output[key] = combined
            elif key in output:
                del output[key]

        if not output:
            # Nothing to write — no-op
            return target

        _write_yaml(output, target)
        logger.info(
            "custom-dangerous-patterns: saved %d changed entries to %s",
            sum(len(v) for v in output.values()),
            target,
        )
        return target

    # Single file mode: write everything
    output = {}
    for key in ("patterns", "allow_patterns", "deny_patterns"):
        entries = config_dict.get(key, [])
        if entries:
            output[key] = _clean_for_serialization(entries)

    _write_yaml(output, path)
    return path


def _load_yaml_excluding(directory: Path, exclude_filename: str) -> dict[str, Any] | None:
    """Load all *.yaml files in a directory except the excluded one.

    Merges using the same extend/override semantics as _load_yaml.
    Used by save_config to compute the baseline of user-created files.
    """
    yaml_files = sorted(
        [f for f in directory.glob("*.yaml") if f.name != exclude_filename]
    )
    if not yaml_files:
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

    return merged if merged else None


def _pattern_key(entry: dict[str, Any]) -> str:
    """Return the comparison key for a pattern entry (its regex pattern)."""
    return entry.get("pattern", "")


def _dedup_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate pattern entries by pattern key, keeping the last occurrence.

    When the same regex pattern appears in multiple YAML files, later
    files' version wins. This is critical for directory mode where
    99-custom.yaml (sorted last) needs its enabled=False override to
    correctly suppress patterns removed from user-created files.
    """
    seen: dict[str, int] = {}
    deduped: list[dict[str, Any]] = []
    for entry in entries:
        key = _pattern_key(entry)
        if key in seen:
            deduped[seen[key]] = entry  # replace previous occurrence
        else:
            seen[key] = len(deduped)
            deduped.append(entry)
    return deduped


def _normalized_for_compare(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize an entry for comparison (same as _clean_for_serialization)."""
    out: dict[str, Any] = {}
    out["description"] = entry.get("description", "")
    if entry.get("enabled") is False:
        out["enabled"] = False
    if entry.get("protected") is True:
        out["protected"] = True
    if entry.get("group"):
        out["group"] = entry["group"]
    if entry.get("glob"):
        out["glob"] = entry["glob"]
    out["pattern"] = entry["pattern"]
    if entry.get("examples"):
        out["examples"] = entry["examples"]
    return out


def _compute_delta(
    user_config: dict[str, Any],
    merged_config: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Compute which entries changed between user files and the merged config.

    Returns a dict with the same keys as config ('patterns',
    'allow_patterns', 'deny_patterns'), each containing only
    the entries that differ from the user baseline.

    Keys are compared by pattern regex string. Entries present in
    merged but not in user files are new. Entries with the same
    pattern but different fields are modified. Entries    removed from user files (not in merged) are written with enabled=False
    to prevent them from reappearing on reload.
    """
    delta: dict[str, list[dict[str, Any]]] = {}

    for section in ("patterns", "allow_patterns", "deny_patterns"):
        user_entries = user_config.get(section, [])
        merged_entries = merged_config.get(section, [])

        user_by_key = {_pattern_key(e): e for e in user_entries}
        merged_by_key = {_pattern_key(e): e for e in merged_entries}

        delta_entries: list[dict[str, Any]] = []

        # New or modified entries in merged config
        for entry in merged_entries:
            key = _pattern_key(entry)
            if key not in user_by_key:
                delta_entries.append(entry)
            elif _normalized_for_compare(user_by_key[key]) != _normalized_for_compare(entry):
                delta_entries.append(entry)

        # Entries removed from user files — write as disabled to prevent
        # them reappearing on reload (since they're still in the user file)
        for key, entry in user_by_key.items():
            if key not in merged_by_key:
                removed = dict(entry)
                removed["enabled"] = False
                delta_entries.append(removed)

        if delta_entries:
            delta[section] = delta_entries

    return delta


def _write_yaml(output: dict[str, Any], path: Path) -> None:
    """Write a YAML dict to disk atomically using ruamel.yaml."""
    from ruamel.yaml import YAML

    path.parent.mkdir(parents=True, exist_ok=True)

    import tempfile

    tmp_path = Path(tempfile.mktemp(suffix=".yaml", dir=path.parent))
    try:
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False
        with open(tmp_path, "w", encoding="utf-8") as f:
            yaml.dump(output, f)
        tmp_path.replace(path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _clean_for_serialization(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove internal-only fields and empty optional fields for clean YAML output."""
    # Field order in YAML output (user-facing readability):
    #   description  — always
    #   enabled      — only if disabled (omitted when true — default)
    #   protected    — only if protected (omitted when false — default)
    #   group        — only if set
    #   glob         — only if regex was generated from a glob
    #   pattern      — always (the actual regex)
    #   examples     — only if provided
    cleaned = []
    for entry in entries:
        out: dict[str, Any] = {}
        out["description"] = entry.get("description", "")
        if entry.get("enabled") is False:
            out["enabled"] = False
        if entry.get("protected") is True:
            out["protected"] = True
        if entry.get("group"):
            out["group"] = entry["group"]
        if entry.get("glob"):
            out["glob"] = entry["glob"]
        out["pattern"] = entry["pattern"]
        if entry.get("examples"):
            out["examples"] = entry["examples"]
        cleaned.append(out)
    return cleaned


def append_to_yaml_file(
    entry: dict[str, Any],
    file_path: Path,
    section_key: str = "patterns",
) -> None:
    """Append a single pattern entry to a specific YAML file.

    Loads the file with ruamel.yaml round-trip (preserving comments and
    formatting), appends the entry to the appropriate section (controlled
    by *section_key*), and writes back. If the file does not exist, creates
    it with the required sections.

    Used by ``add --target <filename>`` to write directly to a named file
    in the config directory instead of going through ``save_config``.
    """
    from ruamel.yaml import YAML

    try:
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.default_flow_style = False

        if file_path.is_file():
            raw = yaml.load(file_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raw = {}
        else:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            raw = {}

        # Ensure section exists
        if section_key not in raw or not isinstance(raw[section_key], list):
            raw[section_key] = []

        raw[section_key].append(entry)
        yaml.dump(raw, file_path)
    except Exception as exc:
        raise OSError(f"Failed to write to {file_path}: {exc}") from exc


def remove_entry_from_file(entry: dict[str, Any], config_path: Path) -> bool:
    """Delete a pattern entry from ALL YAML files that contain it.

    Scans every YAML file in the config directory (and the sibling
    ``.yaml`` file in combined mode), finds the entry by regex pattern,
    and removes all occurrences using ruamel.yaml round-trip loading
    so comments and formatting are preserved.

    This is the "true delete" for the CLI remove command — the pattern
    is gone from every file, no remnant written.

    Returns True if at least one occurrence was found and removed.
    """
    from ruamel.yaml import YAML

    pattern_val = entry.get("pattern", "")
    section_key = entry.get("_section", "patterns")

    # Collect YAML files to scan (directory mode + combined mode sibling)
    files_to_scan: list[Path] = []
    if config_path.is_dir():
        files_to_scan.extend(sorted(config_path.glob("*.yaml")))
        # Combined mode: also scan the sibling .yaml file
        sibling = config_path.parent / (config_path.stem + ".yaml")
        if sibling.is_file():
            files_to_scan.append(sibling)
    elif config_path.is_file():
        files_to_scan = [config_path]
    else:
        return False

    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False

    any_removed = False

    for yf in files_to_scan:
        try:
            raw = yaml.load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue

        section = raw.get(section_key)
        if not isinstance(section, list):
            continue

        # Scan in reverse order so indices stay valid after deletions
        removed_from_this_file = False
        for i in range(len(section) - 1, -1, -1):
            item = section[i]
            if isinstance(item, dict) and item.get("pattern") == pattern_val:
                del section[i]
                removed_from_this_file = True
                any_removed = True

        if removed_from_this_file:
            try:
                yaml.dump(raw, yf)
            except Exception:
                pass  # Logged below if nothing was removed at all
            logger.info(
                "custom-dangerous-patterns: deleted pattern %r from %s",
                pattern_val,
                yf,
            )

    if not any_removed:
        logger.warning(
            "custom-dangerous-patterns: pattern %r not found in any YAML file",
            pattern_val,
        )

    return any_removed


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
