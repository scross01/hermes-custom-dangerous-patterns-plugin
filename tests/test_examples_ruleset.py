"""Liveness guards for the shipped example ruleset (plans 038-041).

Every command string in this module is REGEX INPUT ONLY and is never executed;
see AGENTS.md "Testing Safety".
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

import patterns

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

# The flags the plugin itself compiles with (patterns._RE_FLAGS).
_RE_FLAGS = re.IGNORECASE | re.DOTALL

# Every enabled deny rule carries a bracketed tag prefix, e.g.
# "[GIT_WRITE] Deny git push" or "[BYPASS] Deny eval wrapping ...".
_TAGGED_DESCRIPTION = re.compile(r"^\[[^\]\n]+\]")


def _example_documents():
    """Yield ``(filename, parsed_doc)`` for every ``examples/*.yaml``.

    Sorted filename order is the order Hermes loads config sources in, so the
    position of a rule in this iteration is its position in the
    first-match-wins deny evaluation.
    """
    for path in sorted(EXAMPLES_DIR.glob("*.yaml")):
        yield path.name, yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _regex_source(entry):
    """Regex source for one entry, mirroring config.py's glob->pattern fallback.

    ``pattern:`` wins when both are present; ``glob:`` is resolved through
    ``patterns.glob_to_regex`` exactly as the shipped loader does.
    """
    source = entry.get("pattern")
    if not isinstance(source, str) or not source.strip():
        glob_str = entry.get("glob")
        if not isinstance(glob_str, str) or not glob_str.strip():
            return None
        source = patterns.glob_to_regex(glob_str.strip())
    return source if isinstance(source, str) and source.strip() else None


def load_deny_rules():
    """``[(filename, index_in_file, description, compiled_regex)]``.

    Enabled deny rules only, in load order, with ``glob:`` entries resolved.
    """
    rules = []
    for filename, doc in _example_documents():
        for index, entry in enumerate(doc.get("deny_patterns") or []):
            if not isinstance(entry, dict) or not entry.get("enabled", True):
                continue
            source = _regex_source(entry)
            if not source:
                continue
            rules.append(
                (filename, index, entry.get("description", ""), re.compile(source, _RE_FLAGS))
            )
    return rules


def _first_deny_match(command):
    """The ``(filename, description)`` of the deny rule that fires first."""
    for filename, _index, description, regex in load_deny_rules():
        if regex.search(command):
            return filename, description
    return None, None


# ---------------------------------------------------------------------------
# Plan 038 — shadow probes
# ---------------------------------------------------------------------------
#
# Each row is ``(winning_file, winning_description, probe_command)``: the test
# asserts that the command is denied by the file it is registered under, so a
# future "add a narrower rule" edit that steals a probe fails here instead of
# shipping a rule that can never fire.
#
# Three rows are registered under `05-git-write.yaml` rather than under the
# `07-bypass-attempts.yaml` rule they exercise. The 07 rules DO match those
# commands -- `test_bypass_rule_matches_its_named_evasion_form` (plan 040)
# asserts that directly -- but `05-git-write.yaml` loads first and its generic
# `git <subcommand>` rule wins the first-match evaluation. Registering them
# under 05 states what actually happens; registering them under 07 would assert
# a precedence the shipped config does not have.
SHADOW_PROBES = [
    ("05-git-write.yaml", "[GIT_WRITE] Deny git push", "git push --force origin main"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git push", "git push --mirror origin"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git push", "git push --delete origin feature"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git push", "git push origin :feature"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git reset", "git reset --hard HEAD~1"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git reset", "git reset HEAD~5"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git clean", "git clean -fdx"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git config", "git config user.email a@b.c"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git config", "git config --global user.name x"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git config", "git config core.hooksPath /tmp/x"),
    ("06-shell-repo-destruction.yaml", "[REPO_DESTROY] Deny rm -rf .git", "rm -rf .git"),
    ("06-shell-repo-destruction.yaml", "[REPO_DESTROY] Deny rm -rf .git", "rm -rf ./.git"),
    (
        "06-shell-repo-destruction.yaml",
        "[REPO_DESTROY] Deny find ... -delete without path constraint (broad wipe)",
        "find . -name '*.log' -delete",
    ),
    # Won by 05, not 07 -- see the note above. The 07 rules still match.
    ("05-git-write.yaml", "[GIT_WRITE] Deny git commit", "eval 'git commit -m x'"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git commit", "bash -c 'git commit -m x'"),
    ("05-git-write.yaml", "[GIT_WRITE] Deny git commit", "xargs git commit"),
]


def test_no_deny_rule_is_shadowed_by_an_earlier_rule():
    """No probe may be won by a different file than the one it is registered under.

    Deny rules are evaluated first-match-wins in sorted-filename load order, so
    a narrower rule added in a later-sorted file can never fire. That mistake
    shipped silently in examples/08-force-push-and-destruction-explicit.yaml,
    where all 10 rules were unreachable behind examples/05-git-write.yaml.
    """
    failures = []
    for registered_file, expected_description, command in SHADOW_PROBES:
        winner_file, winner_description = _first_deny_match(command)
        if winner_file != registered_file:
            failures.append(
                f"{command!r}: expected {registered_file} ({expected_description}) to win, "
                f"got {winner_file} ({winner_description})"
            )
    assert not failures, "deny rules shadowed by an earlier-loaded rule:\n  " + "\n  ".join(
        failures
    )


def test_every_enabled_deny_rule_has_a_description():
    """Every enabled deny rule carries the bracketed-tag description convention."""
    empty = []
    for filename, index, description, _regex in load_deny_rules():
        if not description or not _TAGGED_DESCRIPTION.match(description):
            empty.append(f"{filename}[{index}]: {description!r}")
    assert not empty, "deny rules missing a bracketed description tag:\n  " + "\n  ".join(empty)
