"""Static guard: this plugin must not override Hermes core at runtime.

Hermes's catalog guideline (rule 9) forbids runtime overrides. Hermes's own
admission lint (``hermes_cli/plugin_validate_core_override.py``, run by
``hermes plugins validate``) detects rebinds -- attribute assignment/deletion,
``setattr``/``delattr``, ``sys.modules[...] = ...``, ``mock.patch`` -- but it
does NOT detect writes into a core module's tables. Verified 2026-10-02: a
probe plugin doing ``DANGEROUS_PATTERNS.append(...)``, ``.extend(...)``,
``[0] = ...``, ``del [0]`` and ``DANGEROUS_PATTERNS_COMPILED.insert(...)``
produces ZERO findings from that lint.

Rule 9's supporting text explicitly names "writes into a core module's tables",
so passing ``hermes plugins validate`` is necessary but NOT sufficient. This
guard closes the gap for the plugin's own test suite, which must pass in a
clean checkout with no Hermes installed.

Scope mirrors the linter: the import closure of ``__init__.py``, excluding
tests and tooling.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest
from ruamel.yaml import YAML

PLUGIN_DIR = Path(__file__).resolve().parent.parent

# Top-level Hermes module names this plugin may reference. Kept static so the
# guard works with no Hermes checkout present (CI has none); widened
# automatically when a checkout IS discoverable.
_STATIC_HERMES_TOPLEVEL = frozenset(
    {
        "tools",
        "agent",
        "hermes_cli",
        "model_tools",
        "tui_gateway",
        "gateway",
        "api_server",
        "hermes_constants",
        "hermes_yaml",
        "hermes_plugins",  # rebinding another plugin is the same collision
    }
)

# Core module-level tables this plugin must never write to.
_GUARDED_TABLES = frozenset({"DANGEROUS_PATTERNS", "DANGEROUS_PATTERNS_COMPILED"})

# Top-level keys Hermes's manifest parser recognises, mirroring
# ``_KNOWN_MANIFEST_FIELDS`` in ``hermes_cli/plugins_manifest.py`` (verified
# 2026-10-02). A key outside this set is silently dropped AND logged at WARNING
# on every plugin load when ``manifest_version >= 2`` -- so drift here fails
# safe (a false positive naming the field to add), never silently.
_KNOWN_MANIFEST_FIELDS = frozenset(
    {
        "name", "version", "description", "author", "requires_env", "provides_tools",
        "provides_hooks", "kind", "hooks", "label", "optional_env", "platforms",
        "external_dependencies", "pip_dependencies", "provides_browser_providers",
        "provides_web_providers", "manifest_version", "api_version", "requires_plugins",
        "python_dependencies", "config_schema", "license", "homepage", "tags",
        "capabilities", "emits", "listens", "hermes", "depends", "requires_hermes",
        "python_runtime", "provides_locales",
    }
)

# Fields that must never be declared: they look right but no such field exists.
# ``provides_cli_commands`` shipped from 0.4.0 until 0.5.0 on the belief that the
# CLI group needed declaring. It does not -- ``ctx.register_cli_command`` registers
# it at runtime -- so the key was a no-op that warned on every load.
_NO_SUCH_MANIFEST_FIELD = ("provides_cli_commands",)

_MUTATING_METHODS = frozenset(
    {
        "append",
        "extend",
        "insert",
        "remove",
        "pop",
        "clear",
        "sort",
        "reverse",
        "update",
        "setdefault",
        "__setitem__",
        "__delitem__",
        "__iadd__",
    }
)

_SKIP_DIRS = frozenset(
    {"tests", "test", "node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages"}
)


def _hermes_toplevel() -> frozenset[str]:
    """Static list, widened from a discoverable Hermes checkout when present."""
    names = set(_STATIC_HERMES_TOPLEVEL)
    root = None
    env_dir = os.environ.get("HERMES_AGENT_DIR")
    if env_dir and (Path(env_dir) / "tools").is_dir():
        root = Path(env_dir)
    elif (Path.home() / ".hermes" / "hermes-agent" / "tools").is_dir():
        root = Path.home() / ".hermes" / "hermes-agent"
    if root is not None:
        for entry in root.iterdir():
            if entry.is_dir() and (entry / "__init__.py").is_file():
                names.add(entry.name)
            elif entry.suffix == ".py":
                names.add(entry.stem)
    return frozenset(names)


_HERMES = _hermes_toplevel()


def _is_test_file(path: Path) -> bool:
    return path.name.startswith("test_") or path.name.endswith("_test.py")


def _runtime_files() -> list[Path]:
    """Runtime Python files: the plugin root, excluding tests and tooling."""
    files = []
    for path in sorted(PLUGIN_DIR.rglob("*.py")):
        rel = path.relative_to(PLUGIN_DIR)
        if _SKIP_DIRS.intersection(rel.parts) or _is_test_file(rel):
            continue
        files.append(path)
    return files


def _collect_hermes_names(tree: ast.AST) -> set[str]:
    """Names bound by an absolute import of a Hermes top-level package."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and (node.module or "").split(".")[0] in _HERMES:
                for alias in node.names:
                    names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _HERMES:
                    names.add(alias.asname or root)
    return names


def _scan(source: str, filename: str = "<probe>") -> list[str]:
    """Return rule-9 findings in ``source``.

    Findings are ``"<kind>: <detail>"`` strings. Deliberately a simplified
    structural check rather than a copy of Hermes's taint analysis: the point
    is to catch the obvious violation shapes in a small, known codebase, and
    :func:`test_guard_detects_a_synthetic_violation` proves it is not inert.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"parse: {filename}: {exc}"]

    findings: list[str] = []
    hermes_names = _collect_hermes_names(tree)

    for node in ast.walk(tree):
        # DANGEROUS_PATTERNS.append(...) / [0] = ... / += ...
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _MUTATING_METHODS
            and isinstance(node.func.value, ast.Name)
        ):
            name = node.func.value.id
            if name in _GUARDED_TABLES or name in hermes_names:
                findings.append(f"table-write: {name}.{node.func.attr}(...)")

        if isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del)):
            # The guarded thing is the CONTAINER being subscript-assigned, e.g.
            # DANGEROUS_PATTERNS[0] = ... -- not the index expression.
            base = node.value
            if isinstance(base, ast.Name) and (
                base.id in _GUARDED_TABLES or base.id in hermes_names
            ):
                verb = "del" if isinstance(node.ctx, ast.Del) else "store"
                findings.append(f"table-write: {base.id}[...] {verb}")

        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            if node.target.id in _GUARDED_TABLES or node.target.id in hermes_names:
                findings.append(f"table-write: {node.target.id} +=")

        # Attribute rebinding on a Hermes module object.
        if (
            isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign))
            and isinstance(node, (ast.Assign, ast.AnnAssign))
        ):
            for target in getattr(node, "targets", []) or []:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in hermes_names
                ):
                    findings.append(f"rebind: {target.value.id}.{target.attr} = ...")

        if isinstance(node, ast.Delete):
            for target in node.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in hermes_names
                ):
                    findings.append(f"rebind: del {target.value.id}.{target.attr}")

        # setattr(core_module, ...) / delattr(...)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in ("setattr", "delattr") and node.args:
                first = node.args[0]
                if isinstance(first, ast.Name) and first.id in hermes_names:
                    findings.append(f"rebind: {node.func.id}({first.id}, ...)")

        # sys.modules[...] = ...
        if (
            isinstance(node, ast.Assign)
            and len(getattr(node, "targets", [])) == 1
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].value, ast.Attribute)
            and isinstance(node.targets[0].value.value, ast.Name)
            and node.targets[0].value.value.id == "sys"
            and node.targets[0].value.attr == "modules"
        ):
            findings.append("rebind: sys.modules[...] = ...")

    return findings


def _runtime_findings() -> list[str]:
    findings: list[str] = []
    for path in _runtime_files():
        source = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(PLUGIN_DIR).as_posix()
        for finding in _scan(source, rel):
            findings.append(f"{rel}: {finding}")
    return sorted(set(findings))


# ---------------------------------------------------------------------------
# Rule-9 guard
# ---------------------------------------------------------------------------


def test_no_core_table_writes():
    """No runtime file may write to a Hermes core table.

    This is the check `hermes plugins validate` cannot do.
    """
    findings = [f for f in _runtime_findings() if "table-write" in f]
    assert findings == [], "core table writes (catalog rule 9 violation):\n" + "\n".join(findings)


def test_no_core_attribute_rebinds():
    """No runtime file may rebind an attribute on a Hermes module object."""
    findings = [f for f in _runtime_findings() if "rebind" in f]
    assert findings == [], "Hermes core rebinds (catalog rule 9 violation):\n" + "\n".join(findings)


def test_no_sys_modules_assignment():
    findings = [f for f in _runtime_findings() if "sys.modules" in f]
    assert findings == [], f"sys.modules assignment: {findings}"


def test_runtime_files_were_actually_scanned():
    """Prevents a vacuous pass: the scanner must find real files to check."""
    files = _runtime_files()
    assert files, "no runtime files discovered; the guard is checking nothing"
    names = {p.name for p in files}
    assert {"__init__.py", "cli.py", "config.py", "patterns.py"} <= names
    assert "test_core_surface.py" not in names, "the guard must exclude its own tests"


def test_deleted_patch_helpers_absent():
    """The six monkey-patch helpers were deleted in the hook-only migration."""
    source = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
    for name in (
        "_patch_block_logging",
        "_patch_detect_function",
        "_patch_deny_handler",
        "_patch_detect_function_for_deny",
        "_extract_guard_command",
        "_check_allow_shadowing",
    ):
        assert f"def {name}(" not in source, f"{name} has been reintroduced"
        assert f"def {name} (" not in source, f"{name} has been reintroduced"


def test_single_pre_tool_call_registration():
    """register() registers the pre_tool_call hook exactly once."""
    source = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
    assert source.count('register_hook("pre_tool_call"') == 1


def test_init_imports_no_hermes_modules():
    """__init__.py must not import any Hermes module at all.

    Everything it needs comes through relative imports of the plugin's own
    modules, which in turn import Hermes lazily inside functions.
    """
    tree = ast.parse((PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8"))
    hermes = sorted(_collect_hermes_names(tree))
    assert hermes == [], f"__init__.py imports Hermes modules: {hermes}"


def test_cli_core_imports_are_read_only():
    """cli.py may read Hermes's built-in table, but must not write to it."""
    source = (PLUGIN_DIR / "cli.py").read_text(encoding="utf-8")
    assert "DANGEROUS_PATTERNS" in source, "cli.py should still surface built-ins"
    findings = _scan(source, "cli.py")
    assert [f for f in findings if "table-write" in f] == []
    assert [f for f in findings if "rebind" in f] == []


# ---------------------------------------------------------------------------
# Manifest guard: declare only fields Hermes actually parses
# ---------------------------------------------------------------------------


def _manifest() -> dict:
    return YAML(typ="safe").load((PLUGIN_DIR / "plugin.yaml").read_text(encoding="utf-8"))


def test_manifest_declares_only_fields_hermes_knows():
    """plugin.yaml may not carry a key Hermes's manifest parser drops.

    An unknown key is not an error -- the plugin still loads -- but at
    ``manifest_version: 2`` every parse logs ``unknown manifest field(s)
    ignored: <key>`` at WARNING. That is log noise in the operator's own Hermes
    log on every startup, for a declaration that does nothing.
    """
    data = _manifest()
    assert data, "plugin.yaml parsed empty; this guard would pass vacuously"
    unknown = sorted(set(data) - _KNOWN_MANIFEST_FIELDS)
    assert unknown == [], (
        "plugin.yaml declares field(s) absent from Hermes's _KNOWN_MANIFEST_FIELDS "
        f"({', '.join(unknown)}); each one logs 'unknown manifest field(s) ignored' "
        "at WARNING on every plugin load. If Hermes gained the field, add it to "
        "_KNOWN_MANIFEST_FIELDS in this file."
    )


def test_manifest_declares_no_phantom_cli_field():
    """``provides_cli_commands`` does not exist; declaring it only warns.

    Pinned separately from the check above because it is the one field that was
    shipped on a false premise and is the natural thing for a maintainer to
    "restore" when documenting CLI registration.
    """
    data = _manifest()
    for field in _NO_SUCH_MANIFEST_FIELD:
        assert field not in data, (
            f"plugin.yaml declares {field}, which Hermes does not parse. The CLI "
            "group is registered at runtime by ctx.register_cli_command() and needs "
            "no manifest declaration."
        )


def test_manifest_provides_hooks_matches_the_registered_hook():
    """``provides_hooks`` is load-bearing and must not drift from ``register()``.

    Unlike the phantom CLI field, this one Hermes does read. A mismatch means the
    manifest advertises a capability the plugin does not register, or vice versa.
    """
    data = _manifest()
    declared = list(data.get("provides_hooks") or [])
    source = (PLUGIN_DIR / "__init__.py").read_text(encoding="utf-8")
    registered = _registered_hooks(source)
    assert declared == registered, (
        f"plugin.yaml provides_hooks {declared} != hooks registered in __init__.py "
        f"{registered}"
    )


def test_manifest_declares_the_enforced_hermes_floor():
    """``plugin.yaml`` must declare the Hermes version the plugin actually needs.

    Block patterns escalate with ``{"action": "approve"}``, which
    ``hermes_cli/plugins.py`` only recognizes from 0.18.1; an older core's
    ``if action not in ("block", "approve"): continue`` skips the directive and
    the command runs ungated -- fail-open, which is the opposite of this plugin's
    posture. ``tools.approval_detection`` (imported by ``patterns.py``) first
    ships in 0.21.4, below which matching degrades to the plugin's own weaker
    normalizer. Hermes enforces ``requires_hermes`` by skipping the plugin
    before import, so declaring the floor is what turns that silent fail-open
    into a visible refusal.

    Pinned by value rather than by upstream history: the exact releases are not
    verifiable from this repo, and the floor is the contract that matters.
    """
    data = _manifest()
    assert data, "plugin.yaml parsed empty; this guard would pass vacuously"
    assert "requires_hermes" in data, (
        "plugin.yaml declares no requires_hermes; block patterns would silently "
        "stop gating on a core older than 0.18.1"
    )
    assert "requires_hermes" in _KNOWN_MANIFEST_FIELDS, (
        "the local _KNOWN_MANIFEST_FIELDS mirror has drifted from Hermes; "
        "requires_hermes must be listed or the unknown-field guard is wrong"
    )
    assert "0.21.4" in data["requires_hermes"], (
        f"floor is {data['requires_hermes']!r}, expected >=0.21.4"
    )


def _registered_hooks(source: str) -> list[str]:
    """Hook names passed to ``register_hook("...")``, sorted and de-duplicated."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "register_hook"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            names.add(node.args[0].value)
    return sorted(names)


# ---------------------------------------------------------------------------
# Meta-test: the guard must be capable of failing
# ---------------------------------------------------------------------------


_VIOLATIONS: tuple[tuple[str, str], ...] = (
    (
        "table append",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    DANGEROUS_PATTERNS.append(('a', 'b'))\n",
    ),
    (
        "table subscript store",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    DANGEROUS_PATTERNS[0] = ('a', 'b')\n",
    ),
    (
        "table delete",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    del DANGEROUS_PATTERNS[0]\n",
    ),
    (
        "table insert",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS_COMPILED\n"
        "    DANGEROUS_PATTERNS_COMPILED.insert(0, ('a', 'b'))\n",
    ),
    (
        "table extend",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    DANGEROUS_PATTERNS.extend([('a', 'b')])\n",
    ),
    (
        "table augassign",
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    DANGEROUS_PATTERNS += []\n",
    ),
    (
        "attribute rebind",
        "def f():\n"
        "    from tools import approval\n"
        "    approval.detect_dangerous_command = lambda c: None\n",
    ),
    (
        "attribute delete",
        "def f():\n"
        "    from tools import approval\n"
        "    del approval.detect_dangerous_command\n",
    ),
    (
        "setattr on core",
        "def f():\n"
        "    from tools import approval\n"
        "    setattr(approval, 'x', 1)\n",
    ),
    (
        "sys.modules write",
        "def f():\n"
        "    import sys\n"
        "    sys.modules['tools.approval'] = object()\n",
    ),
)


@pytest.mark.parametrize(("label", "snippet"), _VIOLATIONS)
def test_guard_detects_a_synthetic_violation(label, snippet):
    """The guard MUST flag every known violation shape.

    Without this, the guard could silently become a no-op — for example if the
    Hermes top-level set resolved empty, in which case every other test in this
    file would pass while checking nothing. A guard that cannot fail is worse
    than no guard, because it manufactures false assurance.
    """
    findings = _scan(snippet, label)
    assert findings, f"guard failed to detect a {label}: snippet was not flagged"


def test_guard_flags_nothing_for_compliant_snippet():
    """Sanity check the other direction: compliant code must not be flagged."""
    compliant = (
        "def f():\n"
        "    from tools.approval_detection import DANGEROUS_PATTERNS\n"
        "    return list(DANGEROUS_PATTERNS)\n"
    )
    assert _scan(compliant, "compliant") == []


def test_guard_hermes_set_is_non_empty():
    """Guards against the trivial-pass failure mode: an empty top-level set."""
    assert _HERMES, "Hermes top-level name set resolved empty; the guard is inert"
    assert "tools" in _HERMES
