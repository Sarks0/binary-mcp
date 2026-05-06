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


def _ctx(functions=None, strings=None, xrefs_to_function=None, xrefs_to_import=None):
    ctx = {
        "metadata": {"name": "test.exe"},
        "functions": functions or [],
        "imports": [],
        "strings": strings or [],
        "memory_map": [],
    }
    # Only attach the new reverse-index keys when explicitly provided so
    # that legacy-cache code paths (which expect the keys to be absent)
    # remain exercised by the existing tests.
    if xrefs_to_function is not None:
        ctx["xrefs_to_function"] = xrefs_to_function
    if xrefs_to_import is not None:
        ctx["xrefs_to_import"] = xrefs_to_import
    return ctx


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


class TestGetXrefsReverseIndex:
    """Wave 1A: ``get_xrefs(direction='to', ...)`` should consult the
    precomputed ``xrefs_to_function`` map populated by core_analysis.py
    and fall back to the legacy linear scan only when the key is absent.
    """

    def test_reverse_index_used_when_present(self, server_module, monkeypatch):
        # Target and callers exist in the function list, but their
        # ``called_functions`` arrays are deliberately empty -- if the
        # implementation still performed the legacy linear scan it would
        # report zero callers. The reverse index is the only source of
        # truth in this fixture, so any caller surfaced proves the
        # index path executed.
        target = _func("handler", "0x1000")
        caller_a = _func("dispatch_a", "0x2000")
        caller_b = _func("dispatch_b", "0x3000")
        caller_c = _func("dispatch_c", "0x4000")
        xrefs_to_function = {
            # Key is the normalized form (no 0x, no leading zeros).
            "1000": [
                {"from_func_addr": "0x2000", "from_func_name": "dispatch_a",
                 "from_call_site": "0x200a"},
                {"from_func_addr": "0x3000", "from_func_name": "dispatch_b",
                 "from_call_site": "0x3014"},
                {"from_func_addr": "0x4000", "from_func_name": "dispatch_c",
                 "from_call_site": "0x4022"},
            ],
        }
        _wire(
            server_module,
            _ctx(
                functions=[target, caller_a, caller_b, caller_c],
                xrefs_to_function=xrefs_to_function,
            ),
            monkeypatch,
        )

        result = server_module.get_xrefs(
            "/bin/test.exe", function_name="handler"
        )

        assert "Function calls (3)" in result
        assert "dispatch_a" in result
        assert "dispatch_b" in result
        assert "dispatch_c" in result
        # Call-site precision must surface in the formatted output.
        assert "call site: 0x200a" in result
        assert "call site: 0x3014" in result
        assert "call site: 0x4022" in result
        # The always-on indirect-call disclaimer must accompany non-empty
        # direction=to results so a downstream LLM doesn't conclude that
        # the listed callers are exhaustive.
        assert "indirect calls" in result.lower()

    def test_reverse_index_lookup_is_o1(self, server_module, monkeypatch):
        # Build a reverse index where the *only* entry matching the
        # target lives behind the normalized key ``1000``. Populate
        # additional functions with garbage ``called_functions`` data
        # that, if scanned linearly, would either miss or pick the wrong
        # entries. A correct implementation reads from the dict directly
        # and is not affected by the noise.
        target = _func("handler", "0x1000")
        noisy_caller = _func(
            "noisy",
            "0x9000",
            # Linear-scan trap: pretend "noisy" calls "0x1000". The
            # legacy path would emit a CALL row for it; the index path
            # must not, because the index is the source of truth.
            called_functions=[{"name": "handler", "address": "0x1000"}],
        )
        real_caller = _func("real_caller", "0x2000")
        xrefs_to_function = {
            "1000": [
                {"from_func_addr": "0x2000", "from_func_name": "real_caller",
                 "from_call_site": "0x2050"},
            ],
        }
        _wire(
            server_module,
            _ctx(
                functions=[target, noisy_caller, real_caller],
                xrefs_to_function=xrefs_to_function,
            ),
            monkeypatch,
        )

        result = server_module.get_xrefs(
            "/bin/test.exe", function_name="handler"
        )

        assert "Function calls (1)" in result
        assert "real_caller" in result
        assert "noisy" not in result

    def test_legacy_cache_falls_back_to_linear_scan(
        self, server_module, monkeypatch
    ):
        # No ``xrefs_to_function`` key at all -- this is the shape of a
        # cache built before Wave 1A. The legacy linear scan over
        # ``called_functions`` must still produce results.
        target = _func("handler", "0x1000")
        caller = _func(
            "dispatch",
            "0x2000",
            called_functions=[{"name": "handler", "address": "0x1000"}],
        )
        # Critically: do NOT pass xrefs_to_function -- _ctx() omits the
        # key entirely, mirroring a pre-Wave-1A cache.
        _wire(server_module, _ctx(functions=[target, caller]), monkeypatch)

        result = server_module.get_xrefs(
            "/bin/test.exe", function_name="handler"
        )

        assert "Function calls (1)" in result
        assert "dispatch" in result
