"""
Tests for the grouped x64dbg MCP surface.

The 159 individual tools were consolidated into 16 grouped tools, each taking
an `op` plus the union of its operations' parameters. What matters here is
that the grouping loses nothing (every implementation is still reachable),
that arguments reach the right implementation, and that a wrong call gets an
error a caller can act on rather than a silent no-op.
"""

import asyncio
import importlib
import inspect
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import src.tools.dynamic_tools as dynamic_tools
from src.tools.dynamic_tools import _UNSET, build_op_catalog, dispatch_op


def _real_fastmcp():
    """
    Get the genuine FastMCP class.

    Several other test modules install MagicMock stubs for "fastmcp", "mcp",
    "mcp.server" and "mcp.types" at import time and never restore them, so a
    plain import here yields a mock whose get_tools() is not awaitable -- and
    re-importing the real fastmcp fails on the stubbed "mcp" package it needs.
    Drop both trees, import for real, then put every stub back so the modules
    relying on them are unaffected.
    """
    stubbed = {
        name: module for name, module in sys.modules.items()
        if isinstance(module, MagicMock)
        and (name == "fastmcp" or name.startswith("fastmcp.")
             or name == "mcp" or name.startswith("mcp."))
    }
    if not stubbed:
        return importlib.import_module("fastmcp").FastMCP

    for name in stubbed:
        del sys.modules[name]
    try:
        return importlib.import_module("fastmcp").FastMCP
    finally:
        sys.modules.update(stubbed)


SOURCE = Path("src/tools/dynamic_tools.py").read_text()

EXPECTED_GROUPS = {
    "analyze", "annotate", "breakpoint", "context", "disasm", "execution",
    "hooks", "memory", "module", "search", "session", "state", "symbols",
    "thread", "trace", "types",
}


@pytest.fixture(scope="module")
def registered():
    """Register the tools once and return (tools_by_name, op_registry)."""
    app = _real_fastmcp()("test")
    dynamic_tools.register_dynamic_tools(app)
    tools = asyncio.run(app.get_tools())
    return tools, dynamic_tools._OP_REGISTRY


class TestGroupedSurface:
    def test_registers_one_tool_per_group(self, registered):
        tools, _ = registered
        assert set(tools) == {f"x64dbg_{g}" for g in EXPECTED_GROUPS}

    def test_surface_is_16_tools_not_159(self, registered):
        tools, _ = registered
        assert len(tools) == 16

    def test_every_implementation_is_reachable(self, registered):
        """The consolidation must not drop functionality."""
        _, ops = registered
        implemented = set(re.findall(r"^    def (x64dbg_\w+)\(", SOURCE, re.M))
        # The group dispatchers are defined the same way; exclude them.
        dispatchers = {f"x64dbg_{g}" for g in EXPECTED_GROUPS}
        reachable = {
            func.__name__ for group in ops.values() for func in group.values()
        }
        assert implemented - dispatchers == reachable

    def test_operation_count_is_preserved(self, registered):
        _, ops = registered
        assert sum(len(group) for group in ops.values()) == 159

    def test_no_implementation_is_mapped_twice(self, registered):
        _, ops = registered
        names = [f.__name__ for group in ops.values() for f in group.values()]
        assert len(names) == len(set(names))

    def test_no_individual_tools_remain_registered(self, registered):
        tools, _ = registered
        # e.g. x64dbg_read_memory must no longer be its own tool.
        assert "x64dbg_read_memory" not in tools
        assert "x64dbg_set_breakpoint" not in tools


class TestSchemas:
    def test_every_group_takes_op(self, registered):
        tools, _ = registered
        for name, tool in tools.items():
            assert "op" in tool.parameters["properties"], name

    def test_op_is_the_only_required_argument(self, registered):
        """Everything else is optional; the dispatcher enforces per-op needs."""
        tools, _ = registered
        for name, tool in tools.items():
            assert tool.parameters.get("required", []) == ["op"], name

    def test_group_params_cover_their_operations(self, registered):
        """A group must accept every argument its operations can take."""
        tools, ops = registered
        for group, group_ops in ops.items():
            declared = set(tools[f"x64dbg_{group}"].parameters["properties"])
            for op_name, func in group_ops.items():
                needed = set(inspect.signature(func).parameters)
                missing = needed - declared
                assert not missing, f"x64dbg_{group}(op={op_name}) needs {missing}"

    def test_descriptions_list_every_operation(self, registered):
        tools, ops = registered
        for group, group_ops in ops.items():
            description = tools[f"x64dbg_{group}"].description
            for op_name in group_ops:
                assert f"  {op_name} --" in description, (group, op_name)


class TestOpCatalog:
    def test_catalog_lists_args_from_the_real_signature(self):
        def sample(address, size=256):
            """Read process memory."""

        catalog = build_op_catalog({"read": sample})
        assert "read -- Read process memory." in catalog
        assert "args: address, size" in catalog

    def test_catalog_marks_zero_argument_ops(self):
        def sample():
            """List everything."""

        assert "no arguments" in build_op_catalog({"list": sample})

    def test_catalog_is_sorted(self):
        def a():
            """A."""

        def b():
            """B."""

        catalog = build_op_catalog({"zebra": b, "alpha": a})
        assert catalog.index("alpha") < catalog.index("zebra")


class TestDispatch:
    def _ops(self):
        calls = {}

        def read(address, size=256):
            """Read memory."""
            calls["read"] = (address, size)
            return f"read {address} {size}"

        def modules():
            """List modules."""
            calls["modules"] = True
            return "modules"

        return {"read": read, "modules": modules}, calls

    def test_forwards_supplied_arguments(self):
        ops, calls = self._ops()
        result = dispatch_op("memory", ops, "read", {"address": "0x1000", "size": 16})
        assert result == "read 0x1000 16"
        assert calls["read"] == ("0x1000", 16)

    def test_unset_arguments_fall_back_to_the_implementation_default(self):
        """An argument the caller omitted must not arrive as None."""
        ops, calls = self._ops()
        dispatch_op("memory", ops, "read", {"address": "0x1000", "size": _UNSET})
        assert calls["read"] == ("0x1000", 256)

    def test_false_is_forwarded_not_treated_as_missing(self):
        seen = {}

        def op(flag=True):
            """Toggle."""
            seen["flag"] = flag
            return "ok"

        dispatch_op("g", {"op": op}, "op", {"flag": False})
        assert seen["flag"] is False

    def test_missing_op_lists_the_valid_ones(self):
        ops, _ = self._ops()
        result = dispatch_op("memory", ops, "", {})
        assert "needs an 'op'" in result
        assert "modules" in result and "read" in result

    def test_unknown_op_lists_the_valid_ones(self):
        ops, _ = self._ops()
        result = dispatch_op("memory", ops, "readmem", {})
        assert "is not an operation of x64dbg_memory" in result

    def test_unknown_op_suggests_near_misses(self):
        ops, _ = self._ops()
        assert "Did you mean" in dispatch_op("memory", ops, "read_", {})

    def test_argument_the_op_does_not_take_is_rejected(self):
        """Silently dropping it would let a caller believe it took effect."""
        ops, calls = self._ops()
        result = dispatch_op("memory", ops, "modules", {"address": "0x1000"})
        assert "does not take address" in result
        assert "modules" not in calls

    def test_missing_required_argument_names_the_operation(self):
        ops, _ = self._ops()
        result = dispatch_op("memory", ops, "read", {})
        assert 'x64dbg_memory(op="read") is missing address' in result
        # Must not leak the internal implementation's qualified name.
        assert "<locals>" not in result

    def test_implementation_errors_are_not_swallowed(self):
        def boom():
            """Explode."""
            raise RuntimeError("kaboom")

        with pytest.raises(RuntimeError):
            dispatch_op("g", {"boom": boom}, "boom", {})


class TestRoutingThroughRealTools:
    """End-to-end: a grouped call must reach the right implementation."""

    def _bridge(self):
        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge.__new__(X64DbgBridge)
        threads = [{"id": 4816, "is_current": True}, {"id": 9120}]
        modules = [{"base": "400000", "size": 4096, "name": "host.exe",
                    "path": "host.exe", "is_main": True}]
        bridge._request_with_retry = lambda ep, data=None: {
            "success": True, "threads": threads, "modules": modules,
        }
        bridge._request = bridge._request_with_retry
        return bridge

    def test_thread_list_routes_to_get_threads(self, registered):
        tools, _ = registered
        with patch("src.tools.dynamic_tools.get_x64dbg_bridge", return_value=self._bridge()):
            result = tools["x64dbg_thread"].fn(op="list")
        assert "TID 4816" in result and "TID 9120" in result

    def test_module_list_routes_to_get_modules(self, registered):
        tools, _ = registered
        with patch("src.tools.dynamic_tools.get_x64dbg_bridge", return_value=self._bridge()):
            result = tools["x64dbg_module"].fn(op="list")
        assert "host.exe" in result

    def test_thread_op_rejects_an_unknown_thread(self, registered):
        tools, _ = registered
        with patch("src.tools.dynamic_tools.get_x64dbg_bridge", return_value=self._bridge()):
            result = tools["x64dbg_thread"].fn(op="suspend", thread_id="9999")
        assert "No thread with id" in result

    def test_the_two_conditional_families_are_distinguishable(self, registered):
        """The native and manual conditional breakpoints must not read alike."""
        tools, _ = registered
        description = tools["x64dbg_breakpoint"].description
        assert "set_conditional --" in description
        assert "set_manual_conditional --" in description
        manual = description.split("set_manual_conditional --")[1].split("\n")[0]
        assert "does NOT enforce" in manual or "on demand" in manual
