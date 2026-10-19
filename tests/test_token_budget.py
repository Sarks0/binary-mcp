"""
Token-budget tripwires for what the server puts in front of a model.

Every byte of ``tools/list``, of the server instructions and of a tool result
is read by the client's model, and most of it is re-read on every later turn
of the conversation. None of the costs these tests pin was chosen on purpose:
FastMCP's defaults doubled every result, and the contributor template grew the
descriptions one tool at a time. A budget nothing enforces comes back the same
way, so each one has a test.

The limits are in characters and bytes, not tokens, because the model's tokenizer
is not public. Decompiled C runs at roughly 2.6 characters per token and prose
at roughly 4, so read a character budget with that ratio in mind.
"""

import asyncio
import sys

import pytest


def _mcp_modules() -> dict:
    return {
        k: v
        for k, v in sys.modules.items()
        if k in ("fastmcp", "mcp") or k.startswith(("fastmcp.", "mcp."))
    }


@pytest.fixture(scope="module")
def roster(tmp_path_factory):
    """Import the server against a stub Ghidra and register every tool.

    Same isolation as tests/test_tool_catalog.py: several modules swap
    ``fastmcp``/``mcp`` for MagicMocks at import time, and these budgets are
    about the real registry.
    """
    saved = _mcp_modules()
    for name in saved:
        del sys.modules[name]
    saved_server = sys.modules.pop("src.server", None)

    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("GHIDRA_HOME", str(fake_ghidra))
            mp.setenv("BINARY_MCP_ALLOWED_DIRS", "")
            from fastmcp import Client

            import src.server as server_module

            server_module.register_all_tools()
            yield server_module, Client
    finally:
        for name in _mcp_modules():
            del sys.modules[name]
        sys.modules.update(saved)
        sys.modules.pop("src.server", None)
        if saved_server is not None:
            sys.modules["src.server"] = saved_server


def _listed(roster):
    server_module, client_cls = roster

    async def go():
        async with client_cls(server_module.app) as client:
            return await client.list_tools()

    return asyncio.run(go())


def _call(roster, tool: str, arguments: dict):
    server_module, client_cls = roster

    async def go():
        async with client_cls(server_module.app) as client:
            return await client.call_tool_mcp(tool, arguments)

    return asyncio.run(go())


class TestNoDuplicateStructuredOutput:
    """A text result is sent once, as text.

    FastMCP wraps a ``-> str`` return in an auto-generated
    ``{"result": string}`` output schema and then sends the result twice. The
    clients that prefer ``structuredContent`` show the model the escaped copy.
    """

    def test_no_tool_advertises_the_string_wrapper(self, roster):
        wrapped = sorted(
            t.name
            for t in _listed(roster)
            if t.outputSchema and t.outputSchema.get("x-fastmcp-wrap-result")
        )
        assert not wrapped, f"text tools still advertise a result wrapper: {wrapped}"

    def test_object_tools_keep_their_schema(self, roster):
        schemas = {t.name: t.outputSchema for t in _listed(roster)}
        # The coverage tools return real objects, and integrators read their
        # fields from structuredContent.
        assert schemas["get_coverage_status"]
        assert "result" not in schemas["get_coverage_status"].get("properties", {})

    def test_text_result_has_no_structured_copy(self, roster):
        result = _call(roster, "diagnose_setup", {})
        assert result.structuredContent is None
        assert any(getattr(block, "text", "") for block in result.content)
