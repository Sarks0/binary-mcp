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


class TestCodeOutputBudget:
    """Code-returning tools share one budget, and say what they left out first.

    Clients cut long results blindly (one past 25,000 tokens or 50,000
    characters, OpenCode at 50 KB, Gemini CLI at 40,000 characters), and they
    cut from the end, which is where a "withheld" note used to sit.
    """

    def test_small_output_is_untouched(self):
        from src.utils.output_budget import cap_output

        assert cap_output("short\ntext", budget=100) == "short\ntext"

    def test_cut_is_on_a_line_boundary_and_reported_first(self):
        from src.utils.output_budget import cap_output

        lines = [f"line {i:05d}" for i in range(5000)]
        out = cap_output("\n".join(lines), budget=2_000)

        notice, _, kept = out.partition("\n\n")
        assert notice.startswith("*Output cut to the first")
        assert set(kept.splitlines()) <= set(lines)
        assert len(kept) <= 2_000

    def test_cut_through_an_envelope_closes_it(self):
        from src.utils.formatters import (
            UNTRUSTED_END_MARKER,
            UNTRUSTED_OPEN_SENTINEL,
            wrap_untrusted,
        )
        from src.utils.output_budget import cap_output

        text = "header\n" + wrap_untrusted("\n".join(["x" * 80] * 2000), "code")
        out = cap_output(text, budget=5_000)

        opens = out.count(f"{UNTRUSTED_OPEN_SENTINEL}BEGIN UNTRUSTED SAMPLE DATA")
        assert opens == 1
        assert out.count(UNTRUSTED_END_MARKER) == 1
        assert out.endswith(UNTRUSTED_END_MARKER)

    def test_every_code_output_tool_is_budgeted(self, roster):
        from src.tool_catalog import CODE, classify

        server_module, _ = roster
        registered = {t.name for t in _listed(roster)}
        code_tools = {
            n for n in registered if (e := classify(n)) and CODE in e.facets
        }
        budgeted = set().union(
            *(getattr(m, "tool_names", set()) for m in server_module.app.middleware)
        )
        assert code_tools
        assert code_tools == budgeted

    def test_middleware_caps_a_real_call(self, roster):
        from fastmcp import FastMCP

        from src.utils.output_budget import code_output_budget_middleware

        _, client_cls = roster
        app = FastMCP("budget-test")

        @app.tool(output_schema=None)
        def big() -> str:
            return "\n".join("y" * 100 for _ in range(1000))

        app.add_middleware(code_output_budget_middleware(["big"], budget=3_000))

        async def go():
            async with client_cls(app) as client:
                return await client.call_tool_mcp("big", {})

        text = asyncio.run(go()).content[0].text
        assert text.startswith("*Output cut to the first")
        assert len(text) < 3_300

    def test_decompile_functions_defaults_to_the_budget(self, roster):
        from src.utils.output_budget import CODE_OUTPUT_CHAR_BUDGET

        tool = next(t for t in _listed(roster) if t.name == "decompile_functions")
        default = tool.inputSchema["properties"]["max_body_chars"]["default"]
        assert default == CODE_OUTPUT_CHAR_BUDGET

    def test_long_function_is_paged_from_start_line(self, roster):
        server_module, _ = roster
        body = "\n".join(f"  x_{i} = {i};" for i in range(10_000))

        window, first, last, total = server_module._pseudocode_window(body, 1)
        assert (first, total) == (1, 10_000)
        assert 1 < last < total
        assert len(window) <= server_module.CODE_OUTPUT_CHAR_BUDGET

        _, first2, last2, _ = server_module._pseudocode_window(body, last + 1)
        assert first2 == last + 1 and last2 > first2

        _, _, last3, _ = server_module._pseudocode_window(body, total)
        assert last3 == total

    def test_batch_decompile_fences_once_and_withholds_whole_bodies(
        self, tmp_path, monkeypatch
    ):
        from unittest.mock import MagicMock

        from src.tools import function_hash_tools
        from src.utils.formatters import UNTRUSTED_END_MARKER, UNTRUSTED_OPEN_SENTINEL

        monkeypatch.setenv("BINARY_MCP_ALLOW_ANY_PATH", "1")
        monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
        sample = tmp_path / "sample.exe"
        sample.write_bytes(b"MZ" + b"\x00" * 512)

        body = "\n".join(["int v = 0;"] * 1000)  # ~11,000 characters
        functions = [
            {"name": f"f{i}", "address": f"0x40{i}000", "pseudocode": body,
             "signature": f"void f{i}(void)"}
            for i in range(3)
        ]
        cache = MagicMock()
        cache.get_cached.return_value = {"functions": functions, "metadata": {}}

        captured = {}
        app = MagicMock()
        app.tool = MagicMock(
            side_effect=lambda *a, **k: lambda fn: captured.setdefault(fn.__name__, fn)
        )
        function_hash_tools.register_function_hash_tools(
            app, MagicMock(), cache, MagicMock()
        )

        out = captured["batch_decompile"](str(sample), "f0,f1,f2")

        opens = out.count(f"{UNTRUSTED_OPEN_SENTINEL}BEGIN UNTRUSTED SAMPLE DATA")
        assert opens == 1 and out.count(UNTRUSTED_END_MARKER) == 1
        assert out.index("withheld") < out.index(UNTRUSTED_OPEN_SENTINEL)
        assert out.count("--- f") == 2
        assert "Withheld: f2" in out
