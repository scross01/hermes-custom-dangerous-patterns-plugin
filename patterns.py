"""Pattern compilation and command matching.

Compiles raw config patterns into (compiled_regex, description) tuples and
provides the matchers used to decide what the pre_tool_call hook does.

Two different consumers, and the distinction matters:

* The HOOK calls only :func:`find_block_match` and :func:`find_deny_match`
  (see ``__init__.py``, where they are handed to ``_make_policy_hook``).
  Those are the only functions on the enforcement path.
* The CLI ``test`` subcommand calls :func:`is_deny_pattern` and
  :func:`is_allow_pattern`, which report a description for the first match.
  They are diagnostics for that one subcommand.

Allow patterns were retired in plan 034 -- no supported Hermes surface can
express "do not apply a gate" -- but they are still COMPILED here:
:func:`compile_all` populates ``_allow_compiled`` and :func:`is_allow_pattern`
still reads it. What is retired is ENFORCEMENT: nothing on the hook path
consults ``_allow_compiled``, so a compiled allow pattern gates nothing. The
retained helpers are deliberate (see the note in cli.py) and still covered by
tests; do not remove ``_allow_compiled`` on the assumption that allow patterns
are gone -- it is the CLI's report path, and plan 032 still references it.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_RE_FLAGS = re.IGNORECASE | re.DOTALL

# Module-level compiled patterns, set once by compile_all().
_block_compiled: list[tuple[re.Pattern, str]] = []
_allow_compiled: list[tuple[re.Pattern, str]] = []
_deny_compiled: list[tuple[re.Pattern, str]] = []

def builtin_overlaps(command: str) -> bool:
    """True when Hermes's own dangerous-command detector would flag ``command``.

    Read-only: calls tools.approval_detection.detect_dangerous_command and
    discards the result. It never mutates DANGEROUS_PATTERNS* — those writes are
    forbidden by the catalog guideline and, unlike rebinds, are NOT detected by
    `hermes plugins validate`.

    Used to decide whether a custom block match should defer to the built-in
    gate instead of escalating separately (which would double-prompt, and
    "once" on the first would not satisfy the second).

    Fails SAFE: any ImportError or unexpected error returns False, so the plugin
    escalates on its own rather than silently deferring to a gate it could not
    confirm exists.
    """
    try:
        from tools.approval_detection import detect_dangerous_command
    except ImportError:
        return False
    try:
        is_dangerous, _key, _desc = detect_dangerous_command(command)
    except Exception:
        return False
    return bool(is_dangerous)


def _normalized_tokens(pattern: str) -> list[str]:
    """Bare word tokens from a regex source, with regex syntax stripped.

    ``_extract_tokens`` keeps escape sequences, so ``rm\\s+-rf`` yields
    ``['rm\\\\s+', '-rf\\\\s+']`` -- which shares nothing with the literal
    ``['rm', '-rf']`` that a hand-written or differently-spelled built-in
    produces. Comparing those two spellings found *zero* overlap between a
    user's ``rm\\s+-rf\\s+/`` rule and Hermes's own recursive-delete pattern.
    Collapsing the syntax first is what makes the comparison mean anything.
    """
    s = re.sub(r"\\s\*\+?", " ", pattern)          # \s* \s+ \s  ->  a space
    s = re.sub(r"\\[bBAWZdDsSwW]", " ", s)        # anchors and character classes
    s = re.sub(r"[\\*+?.^$()\[\]{}|]", " ", s)
    s = s.replace("\\", " ")
    return [t for t in re.split(r"[^A-Za-z0-9_@%/.:+-]+", s) if re.search(r"[A-Za-z0-9]", t)]


def _bigrams(tokens: list[str]) -> set[tuple[str, str]]:
    return {(tokens[i], tokens[i + 1]) for i in range(len(tokens) - 1)}


def _regexes_suspect_overlap(a: str, b: str) -> bool:
    """Heuristic: two regex SOURCES plausibly match the same commands.

    Compares ADJACENT token pairs rather than any shared token. A single shared
    token is far too weak: measured against Hermes's real built-in table over
    ``examples/*.yaml``, "any shared token" fired on 29 of 48 shipped examples,
    pairing things like `brew install` with "stop/restart hermes launchd
    service" over the token `remove`. Requiring a shared bigram drops that to 3
    and keeps the pairings plausible.

    Those 3 were then audited (plan 041) and every one of them turned out to be
    a false positive -- `colima`/`limactl`/`podman` never defer to Hermes's
    `sc stop|delete` or docker-compose rules -- while five package-manager rules
    deferred in silence. With the example data corrected, the shipped examples
    now produce **0** warnings against both the real table and the pinned
    corpus, and ``tests/test_overlap.py`` asserts exactly that.

    A bare ``== 0`` on its own would be a weaker guard than the two-sided bound
    it replaced: a matcher stubbed to ``return False`` also yields 0. The lower
    half of the bound therefore moved out of the count and into a direct
    assertion against the corpus's synthetic genuine-overlap pair, which fails
    if this function stops firing regardless of what the examples happen to
    contain. The corpus's discriminating headroom is pinned separately by
    replaying the old any-shared-token rule over it (17 of 59 after the splits,
    far above the bound).

    This remains a heuristic. Two spellings of the same rule can share no bigram
    at all, so a real overlap can be missed -- which is why the enforcement-time
    probe :func:`builtin_overlaps` is the authority, and why the caller must
    phrase its warning as a possibility rather than a fact.
    """
    left, right = _bigrams(_normalized_tokens(a)), _bigrams(_normalized_tokens(b))
    if not left or not right:
        return False
    return bool(left & right)


def builtin_overlap_report() -> list[tuple[str, str]]:
    """Enabled block patterns that may overlap a Hermes built-in pattern.

    Returns ``[(custom_description, builtin_description), ...]``.

    Both sides are REGEX SOURCES, not commands, so they are compared with
    :func:`_regexes_suspect_overlap` rather than matched against each other.
    The comparison is inherently approximate in BOTH directions and this function
    must be treated as a prompt to check, not a verdict: use
    ``custom-dangerous-patterns test '<command>'`` for a specific command, which
    consults the exact probe (:func:`builtin_overlaps`).

    Reads tools.approval_detection.DANGEROUS_PATTERNS (read-only). Returns
    ``[]`` (never raises) when Hermes's table is unavailable, e.g. the CLI
    running outside Hermes or in unit tests.
    """
    try:
        from tools.approval_detection import DANGEROUS_PATTERNS
    except ImportError:
        return []

    report: list[tuple[str, str]] = []
    for _block_re, desc in _block_compiled:
        for builtin_pat, builtin_desc in DANGEROUS_PATTERNS:
            if not isinstance(builtin_pat, str):
                continue
            if _regexes_suspect_overlap(_block_re.pattern, builtin_pat):
                report.append((desc, builtin_desc))
                break
    return report


def compile_block_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile block patterns from config into (compiled_regex, description).

    These stay INSIDE this plugin and are matched by find_block_match(). They
    are deliberately NOT appended to DANGEROUS_PATTERNS /
    DANGEROUS_PATTERNS_COMPILED: writing to those Hermes-owned tables is
    forbidden by the catalog rules and by AGENTS.md, and `hermes plugins
    validate` does not detect it (see tests/test_core_surface.py, which is the
    real gate). Matching is done here so the hook can escalate to
    `{"action": "approve", "rule_key": ...}` under the command normalization
    Hermes itself uses, rather than injecting a match into Hermes's matcher.

    Invalid regexes are logged and skipped. Disabled patterns (enabled: false)
    are skipped without warning — they're intentionally paused.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid block regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


# ---------------------------------------------------------------------------
# Catch-all allow pattern refusal
# ---------------------------------------------------------------------------
#
# An allow pattern short-circuits detect_dangerous_command() for every command
# it matches, bypassing *all* built-in and custom block patterns. A catch-all
# allow pattern (``.*``, ``^.+$``, ``(?s).*``, an empty string, ...) therefore
# disables the approval system outright. Such patterns are refused rather
# than merely warned about.
#
# Detection is behavioural, not syntactic: the pattern is exercised against a
# small fixed set of probe commands representative of Hermes's built-in
# dangerous-command examples. It is refused when it either fully matches any
# single probe (it whitelists a known-dangerous command verbatim) or
# search-matches *every* probe (it is a de-facto catch-all such as ``^``,
# ``\b`` or ``.``).
# Probes are assembled from tokens rather than written as literal command
# strings so the plugin security scanner (which flags destructive command
# literals in source files) does not report this refusal list as a threat.
_CATCH_ALL_PROBES: tuple[str, ...] = tuple(
    " ".join(tokens)
    for tokens in (
        ("rm", "-rf", "/"),  # recursive delete from root
        ("rm", "-rf", "~"),  # recursive delete of the home directory
        ("dd", "if=/dev/zero", "of=/dev/sda"),  # raw disk overwrite
        ("git", "push", "--force", "origin", "main"),  # history rewrite on a remote
        ("curl", "http://x", "|", "sh"),  # download-and-execute
    )
)


def catch_all_reason(pattern_str: Any) -> str | None:
    """Return why ``pattern_str`` is refused as an allow pattern, or None.

    Returns a short human-readable reason when the pattern is empty,
    whitespace-only, or behaves as a catch-all against
    :data:`_CATCH_ALL_PROBES`; returns None when the pattern is acceptable
    (including when it does not compile -- the caller reports that
    separately).
    """
    if not isinstance(pattern_str, str) or not pattern_str.strip():
        return "empty or whitespace-only allow pattern would exempt every command"
    try:
        compiled = re.compile(pattern_str, _RE_FLAGS)
    except re.error:
        return None

    for probe in _CATCH_ALL_PROBES:
        if compiled.fullmatch(probe):
            return (
                "allow pattern fully matches a built-in dangerous-command example "
                f"({probe!r}) and would exempt it from approval"
            )
    if all(compiled.search(probe) for probe in _CATCH_ALL_PROBES):
        return (
            "allow pattern matches every built-in dangerous-command example "
            "(catch-all) and would disable the approval system"
        )
    return None


def is_catch_all_allow_pattern(pattern_str: Any) -> bool:
    """True when :func:`catch_all_reason` refuses ``pattern_str``."""
    return catch_all_reason(pattern_str) is not None


def compile_allow_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile allow patterns from config into (compiled_regex, description).

    These are checked BEFORE block patterns. A matching allow pattern
    exempts the command from ALL approval checks (block + built-in).
    Disabled patterns (enabled: false) are skipped. Catch-all patterns
    (see :func:`catch_all_reason`) are refused with an ERROR log.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        reason = catch_all_reason(pattern_str)
        if reason is not None:
            # Allow patterns are RETIRED -- nothing here is enforced any more,
            # so "REFUSING" is a lie and ERROR would read as a broken config on
            # every startup for anyone who still has a catch-all entry. The
            # retirement CRITICAL notice in __init__.register is the disclosure
            # that matters; this line just keeps the CLI's "would have exempted"
            # preview from claiming a catch-all matched.
            logger.debug(
                "custom-dangerous-patterns: skipping retired allow pattern %r "
                "(%s) in the CLI preview; allow patterns are not enforced",
                pattern_str,
                reason,
            )
            continue
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid allow regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


def compile_deny_patterns(raw_patterns: list[dict[str, str]]) -> list[tuple[re.Pattern, str]]:
    """Compile deny patterns from config into (compiled_regex, description).

    Deny patterns block commands immediately without an approval prompt.
    They are checked AFTER allow patterns but BEFORE block patterns.
    Disabled patterns (enabled: false) are skipped.
    """
    compiled = []
    for entry in raw_patterns:
        if not entry.get("enabled", True):
            continue
        pattern_str = entry["pattern"]
        description = entry.get("description", pattern_str)
        try:
            compiled.append((re.compile(pattern_str, _RE_FLAGS), description))
        except re.error as exc:
            logger.warning(
                "custom-dangerous-patterns: skipping invalid deny regex %r: %s",
                pattern_str,
                exc,
            )
    return compiled


def compile_all(config: dict[str, Any]) -> None:
    """Compile all patterns from config and store in module globals.

    Call once during plugin registration.
    """
    global _block_compiled, _allow_compiled, _deny_compiled
    _block_compiled = compile_block_patterns(config.get("patterns", []))
    _allow_compiled = compile_allow_patterns(config.get("allow_patterns", []))
    _deny_compiled = compile_deny_patterns(config.get("deny_patterns", []))


def is_allow_pattern(command: str) -> str | None:
    """Check if a command matches any allow pattern.

    Uses the same normalization as approval.py's detection.

    Returns:
        The matching allow pattern's description if matched, or None.
    """
    if not _allow_compiled:
        return None

    # Normalize same way approval.py does: strip ANSI, null bytes, Unicode normalize
    cmd_normalized = _normalize(command)

    for allow_re, desc in _allow_compiled:
        if allow_re.search(cmd_normalized):
            return desc

    return None


def _normalized_variants(command: str) -> list[str]:
    """Forms of ``command`` that a pattern should be matched against.

    Delegating to Hermes's own ``_command_detection_variants`` is a SECURITY
    requirement, not a convenience. Hermes's normalizer collapses shell
    splicing that a raw substring match would sail straight past:

        "rm \\-rf /home"        -> "rm -rf /home"   (backslash escape stripped)
        "r\\m -rf /home"       -> "rm -rf /home"
        "rm${IFS}-rf /home"    -> "rm -rf /home"   ($IFS folded to a space)
        "rm -rf \\" NL "/home" -> "rm -rf /home"   (line continuation collapsed)

    Before the hook migration these rules were APPENDED to
    ``DANGEROUS_PATTERNS_COMPILED`` and therefore matched by exactly this
    pipeline. Matching them here with the plugin's own much weaker
    :func:`_normalize` silently downgraded every custom rule to a plain regex
    over raw text -- an evasion surface the built-ins do not have.

    The plugin's own normalization is always appended as a final variant so
    behaviour is unchanged when Hermes is absent (the CLI, unit tests) or when
    a future Hermes renames the private helper.

    Read-only, and fails soft: any import or iteration failure degrades to the
    local normalizer alone.
    """
    variants: list[str] = []
    try:
        from tools.approval_detection import _command_detection_variants

        for variant in _command_detection_variants(command):
            if variant and variant not in variants:
                variants.append(variant)
    except Exception:
        # Two different reasons land here and they deserve different levels.
        #
        # Inside Hermes but unable to import tools.approval_detection means the
        # core is older than 0.21.4: _command_detection_variants is the thing
        # that collapses evasion spellings (rm\\-rf, rm${IFS}-rf, line
        # continuations), so block and deny rules are silently matching raw
        # text only. plugin.yaml's requires_hermes should prevent that; warn
        # anyway so a mismatch is visible rather than silent.
        #
        # Outside Hermes (or a renamed private helper) is routine and expected:
        # the CLI is a standalone tool and every `test` invocation reaches here.
        # Keep that at DEBUG so ordinary use does not emit warnings.
        in_hermes = False
        try:
            import tools  # noqa: F401

            in_hermes = True
        except ImportError:
            in_hermes = False

        message = (
            "custom-dangerous-patterns: Hermes command-normalization helper "
            "unavailable; rules are matching raw text only. This weakens every "
            "block and deny pattern (Hermes >=0.21.4 is required)."
        )
        if in_hermes:
            logger.warning(message, exc_info=True)
        else:
            logger.debug(
                "custom-dangerous-patterns: Hermes detection variants unavailable",
                exc_info=True,
            )

    local = _normalize(command)
    if local and local not in variants:
        variants.append(local)
    return variants


def find_block_match(command: str) -> tuple[str, str] | None:
    """First matching block pattern as ``(description, regex_source)``, or None.

    The regex source is returned alongside the description because the runtime
    hook derives the approval rule key from the regex, never from the
    description (see __init__._rule_key_for).

    Matched against :func:`_normalized_variants`, i.e. the same evasion-
    resistant forms Hermes matches its own patterns against.
    """
    if not _block_compiled:
        return None

    for variant in _normalized_variants(command):
        for block_re, desc in _block_compiled:
            if block_re.search(variant):
                return (desc, block_re.pattern)

    return None


def find_deny_match(command: str) -> tuple[str, str] | None:
    """First matching deny pattern as ``(description, regex_source)``, or None.

    Same contract as :func:`find_block_match`; the regex source is returned so
    the caller can log the exact rule that fired.
    """
    if not _deny_compiled:
        return None

    for variant in _normalized_variants(command):
        for deny_re, desc in _deny_compiled:
            if deny_re.search(variant):
                return (desc, deny_re.pattern)

    return None


def get_block_patterns() -> list[tuple[re.Pattern, str]]:
    """Return the compiled block patterns (for the CLI's test/list views)."""
    return list(_block_compiled)


def get_deny_patterns() -> list[tuple[re.Pattern, str]]:
    """Return the compiled deny patterns."""
    return list(_deny_compiled)


def is_deny_pattern(command: str) -> str | None:
    """Check if a command matches any deny pattern.

    Called BEFORE the approval prompt. Returns the matching deny pattern's
    description if matched, or None. Unlike block patterns, deny matches
    result in immediate blocking without a prompt.

    Delegates to :func:`find_deny_match` so this answer -- which
    ``custom-dangerous-patterns test`` reports as the DENY verdict -- can never
    disagree with what the runtime hook actually enforces.
    """
    hit = find_deny_match(command)
    return hit[0] if hit is not None else None


def glob_to_regex(glob_str: str) -> str:
    """Convert a glob-style command pattern to a regex.

    Used by `add --interactive` and `add --glob` so users can type
    intuitive patterns like ``echo hello`` instead of raw regex like
    ``\\becho\\s+hello\\b``.

    Conversion rules:
        - Whitespace runs    → ``\\s+``
        - ``*``              → ``\\S+``  (one non-whitespace word)
        - ``**``             → ``.*``    (match anything, super wildcard)
        - ``?``              → ``.``     (match exactly one char)
        - ``{a,b}``          → ``(?:a|b)``  (brace expansion / alternation)
        - Regex meta-chars   → escaped
          (``.`` ``^`` ``$`` ``+`` ``[`` ``]`` ``\\`` ``|`` ``(`` ``)``)
        - Trailing ``*``/``**`` → both the preceding ``\\s+`` and the
          wildcard are wrapped in ``(?:...)?`` so the bare command also
          matches (e.g. ``aws **`` matches ``aws`` and ``aws instance``).
        - ``\\b`` at start if first token starts with alphanumeric
        - ``(?!/)`` after the first token if it starts with alphanumeric,
          preventing the command name from matching directory components
          (e.g. ``aws **`` matches ``/opt/bin/aws --help`` but not
          ``/opt/aws/command``).
        - ``\\b`` at end if last token ends with alphanumeric

    Brace expansion (``{a,b}``) creates regex alternation: ``{a,b}`` becomes
    ``(?:a|b)``. Each alternative is individually glob-processed. Requires
    at least two comma-separated values inside the braces. Nested braces are
    not supported.

    Args:
        glob_str: A glob-style pattern (e.g. ``"echo hello"``, ``"rm -rf /tmp/*"``).

    Returns:
        The equivalent regex pattern string.
    """
    # Tokenize: split on whitespace to preserve whitespace positions
    tokens = glob_str.split()
    if not tokens:
        return ""

    # { and } are handled specially (brace expansion) so they're not in this set
    _regex_meta = set(r".^$+[]\|()")

    def _process_token(token: str) -> str:
        """Convert a single glob token to its regex fragment.

        Brace expansion (``{a,b}``) is handled first: the prefix before
        ``{`` is shared by all alternatives (like shell brace expansion),
        so ``*.{env,bak}`` becomes ``(?:\\.env|\\.bak)`` where each
        alternative is ``\\.env`` / ``\\.bak`` — glob-processed as a
        complete unit including the prefix.
        """
        # Scan for a valid brace expansion group
        scan = 0
        brace_start = None
        brace_end = None
        while scan < len(token):
            if token[scan] == "{":
                end = token.find("}", scan + 1)
                if end != -1:
                    inner = token[scan + 1 : end]
                    if inner:
                        alts = [a for a in inner.split(",") if a]
                        if len(alts) > 1:
                            brace_start = scan
                            brace_end = end
                            break
                    # Not a valid expansion — skip past and keep scanning
                    scan = end + 1
                    continue
                # No closing brace — rest is literal
                break
            elif token[scan] == "}":
                # Unmatched close brace — rest is literal
                break
            scan += 1

        if brace_start is not None:
            # Brace expansion: prefix + each alt is glob-processed as a unit
            prefix = token[:brace_start]
            inner = token[brace_start + 1 : brace_end]
            alts = [a for a in inner.split(",") if a]
            alternatives = [_process_token(prefix + alt) for alt in alts]
            processed = "|".join(alternatives)
            # Suffix (chars after closing })
            suffix = token[brace_end + 1 :]
            if suffix:
                return "(?:" + processed + ")" + _process_token(suffix)
            return "(?:" + processed + ")"

        # Normal processing (no brace expansion)
        result: list[str] = []
        i = 0
        while i < len(token):
            ch = token[i]
            # ** super wildcard (match everything) — check before single *
            if ch == "*" and i + 1 < len(token) and token[i + 1] == "*":
                result.append(".*")
                i += 2
            # * single wildcard (match one non-whitespace word)
            elif ch == "*":
                result.append("\\S+")
                i += 1
            elif ch == "?":
                result.append(".")
                i += 1
            elif ch == "{":
                result.append("\\{")
                i += 1
            elif ch == "}":
                result.append("\\}")
                i += 1
            elif ch in _regex_meta:
                result.append("\\" + ch)
                i += 1
            else:
                result.append(ch)
                i += 1
        return "".join(result)

    # Build the regex body. When the last token is a standalone ``*`` or
    # ``**``, both the preceding ``\\s+`` separator and the wildcard itself
    # are wrapped in ``(?:...)?`` so the bare command (no arguments) also
    # matches.  Mid-command wildcards remain mandatory.
    if len(tokens) > 1 and tokens[-1] in ("*", "**"):
        prefix = r"\s+".join(_process_token(t) for t in tokens[:-1])
        last_re = _process_token(tokens[-1])
        regex_body = prefix + r"(?:\s+" + last_re + r")?"
    else:
        regex_body = r"\s+".join(_process_token(t) for t in tokens)

    # Add word boundaries only at positions that are alphanumeric.
    # Use tokens (not raw glob_str) so leading/trailing whitespace
    # and special chars like * or ? are handled correctly.
    if tokens and tokens[0] and tokens[0][0].isalnum():
        first_re = _process_token(tokens[0])
        # Insert (?!/) after the first token so the command name matches
        # when followed by whitespace but NOT by '/' — prevents matching
        # directory components like /opt/aws/command (vs /opt/bin/aws --help).
        regex_body = first_re + r"(?!/)" + regex_body[len(first_re) :]
        regex_body = r"\b" + regex_body
    if tokens and tokens[-1] and tokens[-1][-1].isalnum():
        regex_body = regex_body + r"\b"

    return regex_body


def _normalize(command: str) -> str:
    """Normalize a command string for pattern matching.

    Mirrors approval.py._normalize_command_for_detection():
    strips ANSI escapes, null bytes, and normalizes Unicode.
    """
    try:
        from tools.ansi_strip import strip_ansi

        command = strip_ansi(command)
    except ImportError:
        # Fallback: strip common ANSI sequences
        command = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", command)

    command = command.replace("\x00", "")
    import unicodedata

    command = unicodedata.normalize("NFKC", command)
    return command


# ---------------------------------------------------------------------------
# Allow-shadowing analysis (shared by runtime __init__ and CLI)
# ---------------------------------------------------------------------------
#
# These helpers live here -- not in __init__.py or cli.py -- so the runtime
# path and the CLI path share ONE implementation. Previously the logic was
# duplicated and the two copies diverged: the CLI's coverage check treated a
# block pattern as "covering" an allow's shadowing if it overlapped *any*
# built-in, instead of the specific built-ins the allow shadows. That
# suppressed real shadowing warnings -- the unsafe direction for a safety
# plugin. Keeping a single source of truth prevents that drift recurring.


def _extract_tokens(pattern: str) -> list[str]:
    """Extract word-like tokens (length >= 3) from a regex for overlap checks.

    Strips word-boundary markers (``\\b``) and regex metacharacters, then
    returns whitespace-separated tokens at least 3 characters long.
    """
    cleaned = re.sub(r"\\b", " ", pattern)
    cleaned = re.sub(r"[\\*+?.^$()\[\]{}|]", " ", cleaned)
    return [t for t in cleaned.split() if len(t) >= 3]


def _patterns_overlap(re1: re.Pattern, re2: re.Pattern) -> bool:
    """Heuristic: could two compiled regexes match overlapping strings?

    Broad patterns (``.*``, ``.+``, ``^.*$``) in *either* operand shadow
    everything. Otherwise, patterns sharing a word-like token (>= 3 chars)
    are treated as overlapping. Not exact, but catches the dangerous cases.
    """
    p1, p2 = re1.pattern, re2.pattern
    if p1 in (".*", ".+", "^.*$") or p2 in (".*", ".+", "^.*$"):
        return True
    tokens1 = set(_extract_tokens(p1))
    tokens2 = set(_extract_tokens(p2))
    return bool(tokens1 & tokens2)


def find_uncovered_allow_shadowing(
    allow_compiled: list[tuple[re.Pattern, str]],
    block_compiled: list[re.Pattern],
    builtin_compiled: list[tuple[re.Pattern, str]],
) -> list[tuple[re.Pattern, str, list[str]]]:
    """Find allow patterns that shadow built-ins with no covering block.

    For each allow pattern, compute the built-ins it could bypass (those
    whose regex overlaps the allow). A custom block pattern **covers** the
    shadowing only if it overlaps *every* built-in the allow shadows --
    scoping coverage to the specific built-ins at risk, not just any.

    Args:
        allow_compiled: ``[(regex, description), ...]`` of enabled allow
            patterns.
        block_compiled: ``[regex, ...]`` of enabled custom block patterns.
        builtin_compiled: ``[(regex, description), ...]`` of the built-in
            dangerous patterns to check against (the runtime passes Hermes's
            live ``DANGEROUS_PATTERNS_COMPILED``; the CLI passes its static
            snapshot).

    Returns:
        List of ``(allow_re, allow_desc, [builtin_desc, ...])`` tuples for
        allow patterns whose shadowing is **not** covered by any single
        block pattern. Only allow patterns that shadow at least one built-in
        are considered.
    """
    uncovered: list[tuple[re.Pattern, str, list[str]]] = []
    for allow_re, allow_desc in allow_compiled:
        shadowed = [
            builtin_desc
            for builtin_re, builtin_desc in builtin_compiled
            if _patterns_overlap(allow_re, builtin_re)
        ]
        if not shadowed:
            continue

        covered = False
        for block_re in block_compiled:
            if all(
                _patterns_overlap(block_re, builtin_re)
                for builtin_re, _ in builtin_compiled
                if _patterns_overlap(allow_re, builtin_re)
            ):
                covered = True
                break

        if not covered:
            uncovered.append((allow_re, allow_desc, shadowed))
    return uncovered
