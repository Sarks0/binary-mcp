"""
Tests for the expand_callgraph MCP tool.

Covers:
- BFS terminates at the requested depth.
- External / thunk callees are skipped (not recursed) when their flags
  request it, and counted in the per-classification tally.
- max_functions cap stops the loop early and surfaces partial-cap.
- Root resolution accepts both symbolic name and address.
- Unknown root returns a friendly error string.
- Decompile loop fans out to uncached / no-pseudocode frontier nodes.
- "complete" status only reports when every reachable node is settled.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


def _func(name, address, **extra):
    base = {
        "name": name,
        "address": address,
        "name_source": "USER_DEFINED",
        "is_thunk": False,
        "is_external": False,
        "called_functions": [],
        "call_sites": [],
        "pseudocode": "// stub\n",
        "basic_blocks": [],
        "parameters": [],
        "local_variables": [],
        "signature": "",
        "decompile_status": "success",
        "jump_tables": [],
        "fid_match": None,
        "plate_comment": "",
        "instruction_comments": [],
    }
    base.update(extra)
    return base


def _ctx(functions):
    return {
        "metadata": {"name": "test.exe", "image_base": "0x140000000"},
        "functions": functions,
        "imports": [],
        "strings": [],
        "memory_map": [],
    }


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    """Re-import src.server with stubbed Ghidra detection."""
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod

    return server_mod


class _FakeGetAnalysisContext:
    """Stub for get_analysis_context that simulates incremental decompiles.

    The fake is callable like the real function. Initial cache state
    is provided in ``ctx``. When called with ``incremental=True`` and
    a ``start_address``, the function at that address has its
    ``pseudocode`` and ``called_functions`` filled from a planned
    response in ``decompile_plan`` and the cache state mutates in-place.
    """

    def __init__(self, ctx: dict, decompile_plan: dict[str, dict] | None = None):
        self.ctx = ctx
        self.decompile_plan = decompile_plan or {}
        self.calls: list[dict] = []

    def __call__(self, *args, **kwargs):
        self.calls.append(dict(kwargs))
        if not kwargs.get("incremental"):
            return self.ctx
        target = (kwargs.get("start_address") or "").lower().lstrip("0x") or "0"
        for fn in self.ctx["functions"]:
            fn_addr = (fn.get("address") or "").lower().lstrip("0x") or "0"
            if fn_addr == target:
                planned = self.decompile_plan.get(target, {})
                fn["pseudocode"] = planned.get("pseudocode", "// decompiled\n")
                fn["called_functions"] = planned.get("called_functions", [])
        return self.ctx


def test_expand_terminates_at_depth(server_module, monkeypatch):
    """Root + 1 hop only when depth=1; depth=2 reaches grandchildren."""
    fns = [
        _func("root", "180001000", called_functions=[{"name": "child", "address": "180002000"}]),
        _func("child", "180002000", called_functions=[{"name": "gchild", "address": "180003000"}]),
        _func("gchild", "180003000"),
    ]
    fake = _FakeGetAnalysisContext(_ctx(fns))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=1)
    assert "depth 0: 1" in result
    assert "depth 1: 1" in result
    assert "depth 2:" not in result

    result_d2 = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=2)
    assert "depth 2: 1" in result_d2


def test_expand_skips_external_and_thunk(server_module, monkeypatch):
    fns = [
        _func(
            "root",
            "180001000",
            called_functions=[
                {"name": "imp", "address": "180002000"},
                {"name": "thk", "address": "180003000"},
                {"name": "real", "address": "180004000"},
            ],
        ),
        _func("imp", "180002000", is_external=True),
        _func("thk", "180003000", is_thunk=True),
        _func("real", "180004000"),
    ]
    fake = _FakeGetAnalysisContext(_ctx(fns))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=1)
    assert "Skipped (external/import): 1" in result
    assert "Skipped (thunk): 1" in result
    # external/thunk path doesn't trigger a decompile
    incremental_calls = [c for c in fake.calls if c.get("incremental")]
    assert len(incremental_calls) == 0


def test_expand_decompiles_no_pseudocode_frontier(server_module, monkeypatch):
    """Function in cache but with no pseudocode triggers an incremental decompile."""
    fns = [
        _func(
            "root",
            "180001000",
            called_functions=[
                {"name": "FUN_180002000", "address": "180002000"},
            ],
        ),
        _func("FUN_180002000", "180002000", pseudocode="", name_source="DEFAULT"),
    ]
    plan = {
        "180002000": {
            "pseudocode": "// resolved\nundefined8 FUN_180002000() {}\n",
            "called_functions": [],
        }
    }
    fake = _FakeGetAnalysisContext(_ctx(fns), decompile_plan=plan)
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=1)
    assert "Functions decompiled this run: 1" in result
    incremental_calls = [c for c in fake.calls if c.get("incremental")]
    assert len(incremental_calls) == 1
    assert incremental_calls[0].get("max_functions") == 1


def test_expand_max_functions_cap_returns_partial_cap(server_module, monkeypatch):
    fns = [
        _func(
            "root",
            "180001000",
            called_functions=[
                {"name": "FUN_180002000", "address": "180002000"},
                {"name": "FUN_180003000", "address": "180003000"},
                {"name": "FUN_180004000", "address": "180004000"},
            ],
        ),
        _func("FUN_180002000", "180002000", pseudocode="", name_source="DEFAULT"),
        _func("FUN_180003000", "180003000", pseudocode="", name_source="DEFAULT"),
        _func("FUN_180004000", "180004000", pseudocode="", name_source="DEFAULT"),
    ]
    fake = _FakeGetAnalysisContext(
        _ctx(fns),
        decompile_plan={
            "180002000": {"pseudocode": "// a\n", "called_functions": []},
            "180003000": {"pseudocode": "// b\n", "called_functions": []},
            "180004000": {"pseudocode": "// c\n", "called_functions": []},
        },
    )
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(
        binary_path="dummy.bin", root="root", depth=1, max_functions=2
    )
    assert "**partial-cap**" in result
    assert "max_functions cap of 2" in result
    assert "Functions decompiled this run: 2" in result


def test_expand_root_by_address(server_module, monkeypatch):
    fns = [
        _func("MpContainerOpen", "180447d30"),
    ]
    fake = _FakeGetAnalysisContext(_ctx(fns))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="0x180447d30", depth=0)
    assert "MpContainerOpen" in result
    assert "**complete**" in result


def test_expand_unknown_root_returns_error(server_module, monkeypatch):
    fns = [_func("real", "180001000")]
    fake = _FakeGetAnalysisContext(_ctx(fns))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="does_not_exist", depth=1)
    assert "Root function not found" in result


def test_expand_complete_status_when_all_resolved(server_module, monkeypatch):
    fns = [
        _func(
            "root",
            "180001000",
            called_functions=[
                {"name": "child", "address": "180002000"},
            ],
        ),
        _func("child", "180002000"),
    ]
    fake = _FakeGetAnalysisContext(_ctx(fns))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=2)
    assert "**complete**" in result
    assert "No further crawling needed" in result
    assert "Already cached with pseudocode: 2" in result


def test_expand_no_cache_returns_helpful_message(server_module, monkeypatch):
    fake = _FakeGetAnalysisContext(_ctx([]))
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=1)
    assert "No cached functions" in result
    assert "Run analyze_binary first" in result


def test_expand_propagates_newly_revealed_callees(server_module, monkeypatch):
    """After decompiling a frontier function, its newly-revealed callees
    are walked on the next iteration."""
    fns = [
        _func(
            "root",
            "180001000",
            called_functions=[
                {"name": "FUN_180002000", "address": "180002000"},
            ],
        ),
        _func("FUN_180002000", "180002000", pseudocode="", name_source="DEFAULT"),
        _func("FUN_180003000", "180003000"),
    ]
    plan = {
        "180002000": {
            "pseudocode": "// reveals new callee\n",
            "called_functions": [
                {"name": "FUN_180003000", "address": "180003000"},
            ],
        }
    }
    fake = _FakeGetAnalysisContext(_ctx(fns), decompile_plan=plan)
    monkeypatch.setattr(server_module, "get_analysis_context", fake)

    result = server_module.expand_callgraph(binary_path="dummy.bin", root="root", depth=2)
    assert "depth 2: 1" in result
    assert "**complete**" in result
