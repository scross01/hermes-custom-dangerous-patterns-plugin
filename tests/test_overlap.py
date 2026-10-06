"""Append plan-035 coverage: built-in overlap deferral, the startup overlap
warning, and the deferred flag in the match log.

Split into its own module so the existing suites stay focused.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

BLOCK_ONLY = {
    "patterns": [{"pattern": r"\bvultr\b", "description": "Vultr CLI"}],
    "allow_patterns": [],
    "deny_patterns": [],
}

DENY_AND_BLOCK = {
    "patterns": [{"pattern": r"\becho\b", "description": "Echo"}],
    "allow_patterns": [],
    "deny_patterns": [{"pattern": r"\becho\s+deny\b", "description": "Deny echo"}],
}


@pytest.fixture
def logfile_mod(monkeypatch, tmp_path):
    """Load logfile.py standalone with its log path redirected to tmp_path."""
    import importlib.util
    from pathlib import Path

    plugin_dir = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("cdp_logfile", plugin_dir / "logfile.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    monkeypatch.setattr(mod, "_LOG_DIR", log_dir)
    monkeypatch.setattr(mod, "_LOG_FILE", log_dir / "custom-dangerous-patterns.log")
    return mod


@pytest.fixture
def fake_detector(monkeypatch):
    """Install a controllable tools.approval_detection.detect_dangerous_command.

    Returns a setter: set_detector(flag) makes the probe report flag.
    """
    state = {"result": (False, None, None), "calls": 0, "raises": False}

    def detect(command):
        state["calls"] += 1
        if state["raises"]:
            raise RuntimeError("detector exploded")
        return state["result"]

    detection = types.ModuleType("tools.approval_detection")
    detection.detect_dangerous_command = detect
    detection.DANGEROUS_PATTERNS = [(r"\brm\s+-rf\b", "Recursive delete")]
    tools = types.ModuleType("tools")
    tools.approval_detection = detection
    monkeypatch.setitem(sys.modules, "tools", tools)
    monkeypatch.setitem(sys.modules, "tools.approval_detection", detection)

    def set_detector(flag, description="Recursive delete", key="k"):
        state["result"] = (flag, key, description) if flag else (False, None, None)
        state["calls"] = 0
        state["raises"] = False

    set_detector.state = state
    return set_detector


def _hook(init_register, config):
    init_register.patterns.compile_all(config)
    return init_register._make_policy_hook(
        init_register.patterns.find_block_match,
        init_register.patterns.find_deny_match,
    )


# ---------------------------------------------------------------------------
# builtin_overlaps: the probe
# ---------------------------------------------------------------------------


def test_builtin_overlaps_reads_detector(init_register, fake_detector):
    fake_detector(True)
    assert init_register.patterns.builtin_overlaps("rm -rf /tmp/x") is True


def test_builtin_overlaps_false_when_not_flagged(init_register, fake_detector):
    fake_detector(False)
    assert init_register.patterns.builtin_overlaps("ls -la") is False


def test_builtin_overlaps_false_on_import_error(init_register, monkeypatch):
    """No detector -> False, so the plugin escalates rather than defers blind."""
    monkeypatch.setitem(sys.modules, "tools", types.ModuleType("tools"))
    monkeypatch.delitem(sys.modules, "tools.approval_detection", raising=False)
    assert init_register.patterns.builtin_overlaps("rm -rf /") is False


def test_builtin_overlaps_false_on_detector_exception(init_register, fake_detector):
    """A raising detector must not propagate: fails SAFE toward escalating."""
    fake_detector(False)
    fake_detector.state["raises"] = True
    assert init_register.patterns.builtin_overlaps("rm -rf /") is False


def test_builtin_overlap_probe_does_not_mutate_core_table(init_register, fake_detector):
    """The probe is read-only. Table writes are forbidden by the catalog rule
    and are NOT detected by `hermes plugins validate`, so this is the check."""
    p = init_register.patterns
    detection = sys.modules["tools.approval_detection"]
    before = list(detection.DANGEROUS_PATTERNS)
    compiled_before = list(getattr(detection, "DANGEROUS_PATTERNS_COMPILED", []))

    p.builtin_overlaps("rm -rf /tmp/x")
    p.builtin_overlap_report()

    assert detection.DANGEROUS_PATTERNS == before
    assert getattr(detection, "DANGEROUS_PATTERNS_COMPILED", []) == compiled_before


# ---------------------------------------------------------------------------
# builtin_overlap_report: the startup warning source
# ---------------------------------------------------------------------------


def test_overlap_report_names_both_descriptions(init_register, fake_detector):
    init_register.patterns.compile_all(
        {"patterns": [{"pattern": r"\brm\s+-rf\b", "description": "My rm rule"}],
         "allow_patterns": [], "deny_patterns": []}
    )
    report = init_register.patterns.builtin_overlap_report()
    assert report == [("My rm rule", "Recursive delete")]


def test_overlap_report_empty_without_overlap(init_register, fake_detector):
    init_register.patterns.compile_all(BLOCK_ONLY)
    assert init_register.patterns.builtin_overlap_report() == []


def test_overlap_report_empty_when_builtins_unavailable(init_register, monkeypatch):
    """Must return [] rather than raise when Hermes's table is unreadable."""
    monkeypatch.setitem(sys.modules, "tools", types.ModuleType("tools"))
    monkeypatch.delitem(sys.modules, "tools.approval_detection", raising=False)
    init_register.patterns.compile_all(BLOCK_ONLY)
    assert init_register.patterns.builtin_overlap_report() == []


def test_register_warns_once_per_overlapping_pattern(
    monkeypatch, tmp_path, init_register, fake_detector, caplog
):
    """The deferral cost must be disclosed at startup, per pattern."""
    monkeypatch.setattr(init_register.config, "load_config", lambda: {
        "patterns": [{"pattern": r"\brm\s+-rf\b", "description": "My rm rule"}],
        "allow_patterns": [],
        "deny_patterns": [],
    })

    import logging

    with caplog.at_level(logging.WARNING, logger="hermes_plugins._init_"):
        init_register.register(MagicMock())

    warnings = [r for r in caplog.records if "BUILT-IN OVERLAP" in r.getMessage()]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "My rm rule" in message
    assert "Recursive delete" in message
    # The message must state the consequence, not just the fact.
    assert "always" in message


def test_register_no_overlap_warning_when_none_overlap(
    monkeypatch, tmp_path, init_register, fake_detector, caplog
):
    import logging

    monkeypatch.setattr(init_register.config, "load_config", lambda: dict(BLOCK_ONLY))

    with caplog.at_level(logging.WARNING, logger="hermes_plugins._init_"):
        init_register.register(MagicMock())

    assert not [r for r in caplog.records if "BUILT-IN OVERLAP" in r.getMessage()]


# ---------------------------------------------------------------------------
# Hook behaviour under overlap
# ---------------------------------------------------------------------------


def test_block_match_defers_on_builtin_overlap(init_register, fake_detector):
    fake_detector(True)
    hook = _hook(init_register, BLOCK_ONLY)
    assert hook("terminal", {"command": "vultr instance list"}) is None


def test_block_match_escalates_without_overlap(init_register, fake_detector):
    fake_detector(False)
    hook = _hook(init_register, BLOCK_ONLY)
    result = hook("terminal", {"command": "vultr instance list"})
    assert result["action"] == "approve"
    assert result["rule_key"].startswith("cdp:")


def test_deny_still_blocks_on_builtin_overlap(init_register, fake_detector):
    """Deny short-circuits BEFORE the probe: a deny match must never defer."""
    fake_detector(True)
    hook = _hook(init_register, DENY_AND_BLOCK)
    result = hook("terminal", {"command": "echo deny"})
    assert result["action"] == "block"


def test_overlap_probe_not_called_without_block_match(init_register, fake_detector):
    """The common path costs nothing: no custom match -> no probe call."""
    fake_detector(False)
    hook = _hook(init_register, BLOCK_ONLY)
    assert hook("terminal", {"command": "ls -la"}) is None
    assert fake_detector.state["calls"] == 0


# ---------------------------------------------------------------------------
# Deferred flag in the match log
# ---------------------------------------------------------------------------


def test_deferred_match_is_logged(init_register, fake_detector, monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(init_register, "log_match", lambda *a, **k: seen.append((a, k)))
    fake_detector(True)
    hook = _hook(init_register, BLOCK_ONLY)
    hook("terminal", {"command": "vultr instance list"})
    assert seen, "a deferred match must still be logged"
    args, kwargs = seen[0]
    assert args[1] == "block"
    assert kwargs.get("deferred") is True


def test_non_deferred_match_not_flagged(init_register, fake_detector, monkeypatch):
    seen: list[tuple] = []
    monkeypatch.setattr(init_register, "log_match", lambda *a, **k: seen.append((a, k)))
    fake_detector(False)
    hook = _hook(init_register, BLOCK_ONLY)
    hook("terminal", {"command": "vultr instance list"})
    args, kwargs = seen[0]
    assert kwargs.get("deferred") is False


def test_log_match_records_deferred_field(logfile_mod):
    """log_match writes a separate 'deferred' boolean, not a new match_type."""
    import json

    logfile = logfile_mod
    log_file = logfile._LOG_FILE

    logfile.log_match("ls", "block", "Desc", r"\bls\b", deferred=True)
    logfile.log_match("ls", "block", "Desc", r"\bls\b")

    entries = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
    assert entries[0]["deferred"] is True
    assert "deferred" not in entries[1]
    # match_type stays in the documented three-value set.
    assert {e["type"] for e in entries} == {"block"}


def test_read_match_log_entries_renders_deferred(logfile_mod):
    import json
    from datetime import datetime

    logfile = logfile_mod
    logfile.log_match("ls", "block", "Desc", r"\bls\b", deferred=True)
    logfile.log_match("ls", "block", "Desc", r"\bls\b")

    entries = logfile.read_match_log_entries(limit=10, since_dt=datetime(2000, 1, 1))
    assert len(entries) == 2
    assert "deferred to Hermes built-in gate" in entries[0]["message"]
    assert "deferred" not in entries[1]["message"]
    assert json.dumps(entries)  # serialisable for the logs subcommand
# ---------------------------------------------------------------------------
# Overlap estimation precision (added after the 0.5.0 upgrade review)
# ---------------------------------------------------------------------------


def test_overlap_ignores_a_single_generic_shared_token(init_register):
    """One generic token must not make two unrelated patterns "overlap".

    The shipped examples produced 29 startup warnings out of 48 patterns,
    pairing e.g. `brew install/uninstall/remove` with "stop/restart hermes
    launchd service" over the single token `remove`. Requiring a shared
    adjacent token pair drops that to 3 and keeps the pairings plausible.
    """
    p = init_register.patterns
    assert not p._regexes_suspect_overlap(
        r"\bbrew\s+(install|uninstall|remove)\b",
        r"\b(?:brew\s+)?launchctl\s+(stop|restart)\b",
    )


def test_overlap_is_precise_but_not_complete(init_register):
    r"""The estimator is tuned for precision, and its recall limit is documented.

    Two regex SOURCES cannot be compared soundly: a built-in written with a
    wildcard (\brm\s+(-[^\s]*\s+)*/) shares no adjacent token pair with
    a user rule spelled rm\s+-rf\s+/. Measured against Hermes's real table
    and realistic user rules, the estimator has 0 false positives but does miss
    genuine overlaps -- which is exactly why the startup message says
    "looks similar" and points at `custom-dangerous-patterns test`, whose probe
    asks Hermes about a real command. Do not let a future edit re-tighten this
    into a claim of completeness.
    """
    p = init_register.patterns
    assert callable(p._regexes_suspect_overlap)
    # The recall limit is load-bearing; assert the specific miss so it is
    # visible rather than folklore.
    assert not p._regexes_suspect_overlap(
        r"rm\s+-rf\s+/[^\s]", r"\brm\s+(-[^\s]*\s+)*/"
    ), "if this now matches, the estimator improved and the docs should say so"


def test_normalized_tokens_strip_regex_syntax(init_register):
    """Escape sequences must not survive, or two spellings never compare.

    The old extractor kept them, which is why a user rule spelled
    ``rm\\s+-rf\\s+/`` shared NOTHING with a literal ``rm -rf /`` built-in --
    the warning missed the exact case it exists to disclose.
    """
    p = init_register.patterns
    assert "rm" in p._normalized_tokens(r"rm\s+-rf\s+/")
    assert "rm" in p._normalized_tokens("rm -rf /")
    assert p._bigrams(p._normalized_tokens(r"rm\s+-rf\s+/")) == p._bigrams(
        p._normalized_tokens("rm -rf /")
    )


def _shipped_example_patterns(p):
    """Every pattern the plugin ships in examples/, glob entries resolved."""
    import yaml

    plugin_dir = Path(__file__).resolve().parent.parent
    out = []
    for f in sorted((plugin_dir / "examples").glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        entries = []
        for e in data.get("patterns") or []:
            if not isinstance(e, dict):
                continue
            e = dict(e)
            if not e.get("pattern") and e.get("glob"):
                e["pattern"] = p.glob_to_regex(e["glob"])
            if e.get("pattern"):
                entries.append(e)
        if entries:
            out.append((f.name, entries))
    return out


def test_shipped_examples_produce_few_overlap_warnings(init_register, fake_detector):
    """Regression guard against the startup warning becoming noise again.

    Measured against the real built-in table, the shipped example configs
    emitted 29 warnings before bigrams were required; the bigram rule brought
    that to 3 of 48 -- and all 3 were then shown to be false positives (plan
    041): `colima`/`limactl`/`podman` never defer to Hermes's `sc stop|delete`
    or docker-compose rules, they only shared bigrams with them.

    With the offending examples corrected, the honest figure is now **0**, and
    0 is what is asserted. The upper half of the old two-sided bound therefore
    collapses to an exact value: any warning over a shipped example is a bug in
    the example, not acceptable noise.

    That would be a WEAKER guard on its own -- a matcher stubbed to
    ``return False`` also yields 0 -- so the lower half of the bound moved out
    of this count and into ``test_overlap_matcher_still_detects_a_genuine_overlap``
    below, which asserts the matcher fires against the corpus's synthetic
    genuine-overlap pair directly. Companion test
    ``test_overlap_corpus_would_catch_a_regression_to_any_shared_token`` keeps
    the corpus's noise headroom pinned so it cannot be quietly blunted.

    The corpus is fixtures/builtin_overlap_corpus.yaml, a stand-in for Hermes's
    table (6 of 107 entries: 2 synthetic genuine-overlap + 4 original
    false-positive sources). It is NOT the one-entry ``fake_detector`` stub:
    measuring noise needs a table with enough entries for noise to be possible.

    Note the exact ``== 0`` is deliberately strict, and that strictness is the
    trade: a future Hermes built-in sharing a bigram with a shipped example
    rule will fail this test. That is the intended signal -- the example should
    then be split or reworded, the way plan 041 split the package-manager and
    container rules.
    """
    import yaml

    p = init_register.patterns
    corpus = [
        (e["pattern"], e["description"])
        for e in yaml.safe_load(
            (Path(__file__).parent / "fixtures" / "builtin_overlap_corpus.yaml").read_text(
                encoding="utf-8"
            )
        )
    ]

    total = 0
    warned = 0
    for _name, entries in _shipped_example_patterns(p):
        total += len(entries)
        for e in entries:
            if any(p._regexes_suspect_overlap(e["pattern"], bp) for bp, _bd in corpus):
                warned += 1

    assert total > 40, "expected the shipped examples to still load"
    assert warned == 0, f"overlap warning noise regressed: {warned}/{total} patterns"


def test_overlap_matcher_still_detects_a_genuine_overlap(init_register, fake_detector):
    """The bigram matcher must still fire; a 0-warning corpus must not mean
    a dead matcher. Pinned directly against the corpus's genuine pair rather
    than inferred from the shipped-example count.

    This is the lower half of the bound that
    ``test_shipped_examples_produce_few_overlap_warnings`` gave up when the
    correct answer became exactly 0: without it, stubbing
    ``_regexes_suspect_overlap`` to ``return False`` would satisfy the count.
    """
    import yaml

    p = init_register.patterns
    corpus = [
        e["pattern"]
        for e in yaml.safe_load(
            (Path(__file__).parent / "fixtures" / "builtin_overlap_corpus.yaml").read_text(
                encoding="utf-8"
            )
        )
    ]
    a, b = corpus[0], corpus[1]
    assert p._regexes_suspect_overlap(a, b), (
        "the bigram overlap matcher stopped firing on the corpus's own "
        "genuine-overlap pair"
    )


def test_overlap_corpus_would_catch_a_regression_to_any_shared_token(
    init_register, fake_detector
):
    """The corpus must still fail under the OLD rule, or the guard is blind.

    A noise guard is only meaningful if loosening the matcher trips it. This
    replays the pre-fix rule ("any shared token overlaps") over the same
    corpus and shipped examples; it produced 29 warnings against the real
    table, and 13 against this subset -- far above the pinned bound. If a
    future edit to the corpus drops that headroom, the guard above would go
    quiet without anyone noticing.
    """
    import yaml

    p = init_register.patterns
    corpus = [
        e["pattern"]
        for e in yaml.safe_load(
            (Path(__file__).parent / "fixtures" / "builtin_overlap_corpus.yaml").read_text(
                encoding="utf-8"
            )
        )
    ]

    def any_shared_token(a: str, b: str) -> bool:
        return bool(set(p._normalized_tokens(a)) & set(p._normalized_tokens(b)))

    warned = sum(
        1
        for _name, entries in _shipped_example_patterns(p)
        for e in entries
        if any(any_shared_token(e["pattern"], bp) for bp in corpus)
    )

    assert warned > 3, (
        "corpus no longer discriminates: the any-shared-token rule no longer "
        f"exceeds the pinned bound ({warned})"
    )
