"""
Guard against the stdin-inheritance hang class across every subprocess spawn.

A stdio MCP server's stdin IS its JSON-RPC pipe. Any child that inherits it and
then reads (a Windows launcher's `pause`, a tool that prompts) blocks forever
AND consumes protocol bytes, corrupting the transport for the whole session --
see the Ghidra launch-hang write-up. The defence is uniform: every spawn must
pass an explicit ``stdin=`` (``DEVNULL`` for non-interactive tools; a real
``PIPE`` only for a genuinely interactive child, which is then a deliberate,
visible choice rather than silent inheritance).

This test parses the source with ``ast`` so it covers the whole module, not
just the lines that exist today: a newly-added ``subprocess.run(...)`` without
``stdin=`` fails here immediately.
"""

import ast
from pathlib import Path

import pytest

# Modules that spawn external analysis/debug tools. Every subprocess spawn in
# these must explicitly set stdin so none can inherit the MCP JSON-RPC pipe.
_HARDENED_MODULES = [
    "src/engines/static/ghidra/runner.py",
    "src/engines/static/dotnet/ilspy_runner.py",
    "src/engines/dynamic/windbg/bridge.py",
]

_SPAWN_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _is_subprocess_spawn(node: ast.Call) -> bool:
    """True for subprocess.run / subprocess.Popen / subprocess.call / ... calls."""
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in _SPAWN_FUNCS
        and isinstance(func.value, ast.Name)
        and func.value.id == "subprocess"
    )


def _spawns_missing_stdin(source: str) -> list[int]:
    """Return the line numbers of subprocess spawns that omit an stdin= kwarg."""
    tree = ast.parse(source)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_subprocess_spawn(node):
            kwarg_names = {kw.arg for kw in node.keywords}
            # **kwargs (kw.arg is None) counts as "explicitly handled".
            if "stdin" not in kwarg_names and None not in kwarg_names:
                offenders.append(node.lineno)
    return offenders


@pytest.mark.parametrize("rel_path", _HARDENED_MODULES)
def test_every_subprocess_spawn_sets_stdin(rel_path):
    source = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
    offenders = _spawns_missing_stdin(source)
    assert not offenders, (
        f"{rel_path}: subprocess spawn(s) at line(s) {offenders} do not pass "
        f"stdin=. A stdio MCP child that inherits stdin can hang on and corrupt "
        f"the JSON-RPC pipe. Pass stdin=subprocess.DEVNULL (or an explicit PIPE "
        f"for a genuinely interactive child)."
    )


def test_guard_detects_a_missing_stdin_spawn():
    """The guard itself must flag an unhardened spawn (so it can't silently
    pass by accident)."""
    bad = "import subprocess\nsubprocess.run(['x'], capture_output=True)\n"
    assert _spawns_missing_stdin(bad) == [2]
    good = "import subprocess\nsubprocess.run(['x'], stdin=subprocess.DEVNULL)\n"
    assert _spawns_missing_stdin(good) == []
