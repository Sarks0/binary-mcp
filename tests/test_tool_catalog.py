"""
Tests for src/tool_catalog.py -- the category/facet tags every tool carries.

The catalog exists because a downstream guard hard-coded a guessed list of
"decompile" tool names and silently missed ``decompile_functions`` and
``batch_decompile``. These tests are the drift tripwires: a new tool that
isn't catalogued, a stale entry, or a tool that reads pseudocode / launches
an engine without saying so all fail here instead of in someone's hook.
"""

import asyncio
import inspect
import json
import re
import sys
from pathlib import Path

import pytest

from src.tool_catalog import (
    CATEGORIES,
    FACETS,
    TOOL_CATALOG,
    classify,
    manifest_json,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "tool-catalog.json"

# Tools that touch the ``pseudocode`` key only to test for its presence or
# to rewrite it, never to derive a result from it or return it.
PSEUDOCODE_METADATA_ONLY = {
    "analyze_function_completeness": "scores +15 if pseudocode exists",
    "find_dead_code": "reports whether pseudocode exists",
    "get_function_complexity": "reports whether pseudocode exists",
    "rename_function": "rewrites the old name inside cached pseudocode",
    "expand_callgraph": "checks which callees still lack pseudocode",
}

# Calls that can launch Ghidra headless or ILSpy, directly or via the
# per-module "use the cache or run the analysis" helpers.
ENGINE_CALL_RE = re.compile(
    r"\b(get_analysis_context|_get_or_run_analysis|_get_analysis_context|_load_context"
    r"|_run_targeted_decompile|_submit_decompile_job|_submit_analysis_job|_run_or_degrade)\("
    r"|runner\.(analyze|run)"
    r"|ilspy\.(list_types|decompile|search_types|get_il)"
)
PSEUDOCODE_KEY_RE = re.compile(r"""["']pseudocode["']""")


def _mcp_modules() -> dict:
    return {
        k: v
        for k, v in sys.modules.items()
        if k in ("fastmcp", "mcp") or k.startswith(("fastmcp.", "mcp."))
    }


@pytest.fixture(scope="module")
def roster(tmp_path_factory):
    """Import the server against a stub Ghidra and register every tool.

    Several test modules replace ``fastmcp``/``mcp`` in ``sys.modules`` with
    MagicMocks at import time. The catalog is about the real registry, so
    swap the real packages in for this module and put the stubs back after.
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
            tools = asyncio.run(server_module.app.get_tools())
            yield server_module.app, tools, Client
    finally:
        for name in _mcp_modules():
            del sys.modules[name]
        sys.modules.update(saved)
        sys.modules.pop("src.server", None)
        if saved_server is not None:
            sys.modules["src.server"] = saved_server


def _body_source(tool) -> str:
    """Tool function source with its docstring removed."""
    fn = inspect.unwrap(tool.fn)
    src = inspect.getsource(fn)
    doc = fn.__doc__
    if doc:
        src = src.replace(doc, "", 1)
    return src


def test_every_registered_tool_is_classified(roster):
    _, tools, _ = roster
    missing = sorted(name for name in tools if classify(name) is None)
    assert not missing, f"add these to src/tool_catalog.py: {missing}"


def test_catalog_has_no_stale_entries(roster):
    _, tools, _ = roster
    stale = sorted(set(TOOL_CATALOG) - set(tools))
    assert not stale, f"catalog names tools the server no longer registers: {stale}"


def test_entries_use_known_categories_and_facets():
    for name, entry in TOOL_CATALOG.items():
        assert entry.category in CATEGORIES, name
        assert entry.facets <= set(FACETS), name


def test_tags_reach_tools_list(roster):
    app, _, client_cls = roster

    async def listed():
        async with client_cls(app) as client:
            return {t.name: set(t.meta["_fastmcp"]["tags"]) for t in await client.list_tools()}

    tags = asyncio.run(listed())
    assert "category:uncategorized" not in set().union(*tags.values())
    assert {"category:decompile", "code-output"} <= tags["decompile_functions"]
    assert {"category:debugger"} <= tags["x64dbg_execution"]
    assert {"category:debugger", "code-output"} <= tags["x64dbg_disasm"]


def test_tools_the_guard_missed_are_code_gated():
    # The four real tools the kill guard's hand-written list let through,
    # plus the review/scan tools that also return decompiler text.
    for name in (
        "decompile_function",
        "decompile_functions",
        "batch_decompile",
        "decompile_dotnet_type",
        "scan_pseudocode",
        "get_review_package",
        "get_param_sinks",
        "find_inlined_clones",
    ):
        assert "code-output" in TOOL_CATALOG[name].facets, name
    assert TOOL_CATALOG["decompile_dotnet_assembly"].category == "decompile"


def test_decompile_named_tools_are_in_decompile_category(roster):
    _, tools, _ = roster
    for name in tools:
        if "decompile" in name:
            assert classify(name).category == "decompile", name


def test_pseudocode_readers_carry_a_pseudocode_facet(roster):
    _, tools, _ = roster
    offenders = []
    for name, tool in tools.items():
        if name in PSEUDOCODE_METADATA_ONLY:
            continue
        if PSEUDOCODE_KEY_RE.search(_body_source(tool)):
            if not classify(name).facets & {"code-output", "pseudocode-derived"}:
                offenders.append(name)
    assert not offenders, (
        f"these tools read cached pseudocode but carry neither code-output nor "
        f"pseudocode-derived: {sorted(offenders)}"
    )


def test_pseudocode_exemptions_are_still_needed(roster):
    _, tools, _ = roster
    unused = [n for n in PSEUDOCODE_METADATA_ONLY if not PSEUDOCODE_KEY_RE.search(_body_source(tools[n]))]
    assert not unused, f"drop these from PSEUDOCODE_METADATA_ONLY: {unused}"


def test_runs_engine_facet_matches_source(roster):
    _, tools, _ = roster
    untagged, stale = [], []
    for name, tool in tools.items():
        if name.startswith(("x64dbg_", "windbg_")):
            continue
        calls_engine = bool(ENGINE_CALL_RE.search(_body_source(tool)))
        tagged = "runs-engine" in classify(name).facets
        if calls_engine and not tagged:
            untagged.append(name)
        elif tagged and not calls_engine:
            stale.append(name)
    assert not untagged, f"launch an engine but lack runs-engine: {sorted(untagged)}"
    assert not stale, f"tagged runs-engine but no engine call found: {sorted(stale)}"


def test_checked_in_manifest_is_current(roster):
    _, tools, _ = roster
    expected = manifest_json(tools)
    assert MANIFEST_PATH.read_text() == expected, (
        "docs/tool-catalog.json is stale; regenerate with "
        "`GHIDRA_HOME=... uv run python -m src.tool_catalog > docs/tool-catalog.json`"
    )


def test_manifest_by_facet_is_consistent(roster):
    _, tools, _ = roster
    manifest = json.loads(manifest_json(tools))
    for facet, names in manifest["by_facet"].items():
        for name in names:
            assert facet in manifest["tools"][name]["facets"]
