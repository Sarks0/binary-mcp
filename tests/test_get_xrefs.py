"""
Tests for the rewritten get_xrefs tool.

Exercises the in-memory function-to-function xref derivation, string xref
surfacing, pseudocode-mention fallback, and the explicit "no xrefs found"
path (replacing the old "coming soon" placeholder).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server. The FastMCP stub must route
# ``@app.tool()`` through an identity decorator so the bare function is
# callable from tests.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


def _func(name, address, called_functions=None, pseudocode="", is_thunk=False):
    return {
        "name": name,
        "address": address,
        "called_functions": called_functions or [],
        "pseudocode": pseudocode,
        "is_thunk": is_thunk,
        "is_external": False,
        "basic_blocks": [],
        "parameters": [],
        "local_variables": [],
        "signature": "",
        "decompile_status": "success",
        "jump_tables": [],
        "fid_match": None,
    }


def _ctx(functions=None, strings=None):
    return {
        "metadata": {"name": "test.exe"},
        "functions": functions or [],
        "imports": [],
        "strings": strings or [],
        "memory_map": [],
    }


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))

    sys.modules.pop("src.server", None)
    import src.server as server_mod
    return server_mod


def _wire(server_module, context, monkeypatch):
    """Swap get_analysis_context to return our pre-baked context."""
    monkeypatch.setattr(
        server_module, "get_analysis_context", lambda *a, **kw: context
    )


class TestGetXrefsFunctionDirection:
    def test_direction_to_surfaces_callers(self, server_module, monkeypatch):
        target = _func("handler", "0x1000")
        caller_a = _func(
            "dispatch_a", "0x2000",
            called_functions=[{"name": "handler", "address": "0x1000"}],
        )
        caller_b = _func(
            "dispatch_b", "0x3000",
            called_functions=[{"name": "handler", "address": "0x1000"}],
        )
        _wire(server_module, _ctx(functions=[target, caller_a, caller_b]), monkeypatch)

        result = server_module.get_xrefs("/bin/test.exe", function_name="handler")

        assert "dispatch_a" in result
        assert "dispatch_b" in result
        assert "Function calls (2)" in result
        assert "coming soon" not in result

    def test_direction_from_lists_callees(self, server_module, monkeypatch):
        target = _func(
            "handler", "0x1000",
            called_functions=[
                {"name": "strlen", "address": "0x9000"},
                {"name": "malloc", "address": "0x9100"},
            ],
        )
        _wire(server_module, _ctx(functions=[target]), monkeypatch)

        result = server_module.get_xrefs(
            "/bin/test.exe", function_name="handler", direction="from"
        )
        assert "strlen" in result
        assert "malloc" in result
        assert "Function calls (2)" in result


class TestGetXrefsStringRefs:
    def test_string_xrefs_inbound(self, server_module, monkeypatch):
        # "to 0x5000" should show any function that references the string at 0x5000
        strings = [{
            "address": "0x5000",
            "value": "Hello, world",
            "xrefs": [{"from": "0x1020", "type": "READ"}],
        }]
        caller = _func("uses_string", "0x1000")
        _wire(server_module, _ctx(functions=[caller], strings=strings), monkeypatch)

        result = server_module.get_xrefs("/bin/test.exe", address="0x5000")
        assert "Data / string refs" in result
        assert "0x1020" in result
        assert "Hello, world" in result

    def test_string_xrefs_outbound(self, server_module, monkeypatch):
        strings = [{
            "address": "0x5000",
            "value": "ref'd here",
            "xrefs": [{"from": "0x1020", "type": "READ"}],
        }]
        _wire(server_module, _ctx(strings=strings), monkeypatch)

        result = server_module.get_xrefs(
            "/bin/test.exe", address="0x1020", direction="from"
        )
        assert "Data / string refs" in result
        assert "0x5000" in result


class TestGetXrefsEmpty:
    def test_no_xrefs_returns_clear_message(self, server_module, monkeypatch):
        target = _func("orphan", "0x1000")
        _wire(server_module, _ctx(functions=[target]), monkeypatch)

        result = server_module.get_xrefs("/bin/test.exe", function_name="orphan")

        assert "No xrefs found" in result
        # The old placeholder must never appear
        assert "coming soon" not in result

    def test_invalid_direction(self, server_module, monkeypatch):
        _wire(server_module, _ctx(), monkeypatch)
        result = server_module.get_xrefs(
            "/bin/test.exe", address="0x1000", direction="sideways"
        )
        assert "Error" in result
        assert "to" in result and "from" in result


class TestGetXrefsPseudocodeFallback:
    def test_pseudocode_mention_surfaced(self, server_module, monkeypatch):
        """When no call-graph edge exists, a literal address mention in a
        function body should still surface the caller."""
        target = _func("target", "0x1500")
        indirect = _func(
            "indirect_caller", "0x2000",
            pseudocode="fnptr = (func)0x1500; fnptr();",
        )
        _wire(server_module, _ctx(functions=[target, indirect]), monkeypatch)

        result = server_module.get_xrefs("/bin/test.exe", function_name="target")
        assert "Pseudocode mentions" in result
        assert "indirect_caller" in result
