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


def load_block_rules():
    """``[(filename, description, regex_source)]`` for enabled block patterns.

    ``glob:`` entries are resolved through ``patterns.glob_to_regex``, so the
    source is what the plugin actually compiles at startup.
    """
    rules = []
    for filename, doc in _example_documents():
        for entry in doc.get("patterns") or []:
            if not isinstance(entry, dict) or not entry.get("enabled", True):
                continue
            source = _regex_source(entry)
            if source:
                rules.append((filename, entry.get("description", ""), source))
    return rules


def load_block_entries():
    """``[(filename, raw_entry)]`` for enabled block patterns, key and all."""
    entries = []
    for filename, doc in _example_documents():
        for entry in doc.get("patterns") or []:
            if isinstance(entry, dict) and entry.get("enabled", True):
                entries.append((filename, entry))
    return entries


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


# ---------------------------------------------------------------------------
# Plan 039 -- glob rules that could not match their own target command
# ---------------------------------------------------------------------------

# ``(filename, description, command, should_match)``. Every ``True`` row was
# silently unmatched before the conversion to ``pattern:``; every ``False`` row
# exists so an over-broad replacement that prompts on every ``docker run``
# cannot pass.
BLOCK_MATCH_CASES = [
    ("02-infra.yaml", "docker run with privileged flag", "docker run --privileged ubuntu", True),
    (
        "02-infra.yaml",
        "docker run with privileged flag",
        "docker run -it --privileged ubuntu sh",
        True,
    ),
    (
        "02-infra.yaml",
        "docker run with privileged flag",
        "docker run --privileged=true ubuntu",
        True,
    ),
    (
        "02-infra.yaml",
        "docker run with privileged flag",
        "docker run --rm -v /:/host alpine",
        False,
    ),
    ("02-infra.yaml", "docker run mounting root filesystem", "docker run -v /:/host alpine", True),
    (
        "02-infra.yaml",
        "docker run mounting root filesystem",
        "docker run --rm -v /:/host alpine",
        True,
    ),
    ("02-infra.yaml", "docker run mounting /etc", "docker run -v /etc:/etc alpine", True),
    ("02-infra.yaml", "docker run mounting /etc", "docker run -v /var:/v alpine", False),
    ("02-infra.yaml", "podman run with privileged flag", "podman run --privileged alpine", True),
    ("02-infra.yaml", "podman run with privileged flag", "podman run alpine", False),
    ("03-tools.yaml", "rsync with --delete (mirror-delete)", "rsync --delete src/ dst/", True),
    ("03-tools.yaml", "rsync with --delete (mirror-delete)", "rsync -a --delete src/ dst/", True),
    ("03-tools.yaml", "rsync with --delete (mirror-delete)", "rsync -a src/ dst/", False),
    ("03-tools.yaml", "clamscan with --move (quarantine)", "clamscan --move=./q /tmp/x", True),
    ("03-tools.yaml", "clamscan with --move (quarantine)", "clamscan -r --move=./q /tmp/x", True),
    ("03-tools.yaml", "clamscan with --move (quarantine)", "clamscan /tmp/x", False),
]

# The six rules that were converted from ``glob:`` to ``pattern:``.
FIXED_GLOB_RULES = {(f, d) for f, d, _c, _e in BLOCK_MATCH_CASES}


def test_block_rule_matches_its_named_target_command():
    r"""Each converted rule matches the commands it is named for -- and only those.

    ``**`` compiles to ``.*\s+``, so a glob needs a token on BOTH sides of it.
    ``docker run ** --privileged`` therefore never matched
    ``docker run --privileged ubuntu``, which is the common spelling of the very
    command the rule exists to catch, and no Hermes built-in covers it either.
    """
    rules = {(f, d): src for f, d, src in load_block_rules()}
    failures = []
    for filename, description, command, should_match in BLOCK_MATCH_CASES:
        source = rules.get((filename, description))
        if source is None:
            failures.append(f"{filename} :: {description!r} not found")
            continue
        matched = bool(re.search(source, command, _RE_FLAGS))
        if matched is not should_match:
            verb = "should have matched" if should_match else "should NOT have matched"
            failures.append(
                f"{filename} :: {description!r}: {verb} {command!r} (source {source!r})"
            )
    assert not failures, "block-rule target mismatches:\n  " + "\n  ".join(failures)


def test_six_fixed_rules_are_patterns_not_globs():
    """The repaired rules must be hand-written ``pattern:`` entries.

    A future edit that turns one back into a ``glob:`` silently reintroduces
    the false negative, because the glob translator is not being changed.
    """
    entries = {(f, e.get("description")): e for f, e in load_block_entries()}
    wrong = []
    for key in sorted(FIXED_GLOB_RULES):
        entry = entries.get(key)
        if entry is None:
            wrong.append(f"{key} not found")
        elif "pattern" not in entry or "glob" in entry:
            wrong.append(f"{key} uses keys {sorted(entry)} instead of pattern:")
    assert not wrong, "repaired rules reverted to glob form:\n  " + "\n  ".join(wrong)


def test_no_block_rule_uses_a_glob_with_a_trailing_literal_flag():
    """No ``glob:`` may END in a flag literal that some earlier ``**`` precedes.

    That is the shape that produced the false negatives this plan fixes:
    ``**`` requires a token on both sides, so a flag written as the final glob
    token can never be the first argument after the tool name --
    ``docker run ** --privileged`` could not match
    ``docker run --privileged ubuntu``.

    Only the FINAL token is examined, deliberately. A mid-glob flag such as
    ``ansible ** -m shell **`` is correct: ansible requires a host pattern
    before ``-m``, and that rule's trailing ``**`` is what carries it. The
    mid-glob shape is still guarded, but semantically -- by
    ``test_block_rule_matches_its_named_target_command``, which fails if any of
    the six repaired rules is reverted to a glob.
    """
    offenders = []
    for filename, entry in load_block_entries():
        glob_str = entry.get("glob")
        if not isinstance(glob_str, str) or not glob_str.split():
            continue
        tokens = glob_str.split()
        final = tokens[-1]
        if not (final.startswith("-") or "=" in final):
            continue
        if any(not t.strip("*") for t in tokens[:-1]):
            offenders.append(f"{filename} :: {entry.get('description')!r} :: {glob_str!r}")
    assert not offenders, "globs ending in a flag after '**':\n  " + "\n  ".join(offenders)
