"""Measure the concise modes that already exist (synthetic cache from measure_results.py)."""
import asyncio, sys
sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import SP, count, setup_env
setup_env({"GHIDRA_HOME": f"{SP}/fake_ghidra", "BINARY_MCP_AUTO_PDB": "never"})
import src.server as server
server.register_all_tools()
import synthetic_ctx
from fastmcp import Client
PE = f"{SP}/pe_samples/distlib_t64.exe"
ten = [f["name"] for f in synthetic_ctx.build("x")["functions"][:10]]
async def main():
    async with Client(server.app) as c:
        for name, args, label in [
            ("scan_pseudocode", {"binary_path": PE, "mode": "summary"}, "summary"),
            ("scan_pseudocode", {"binary_path": PE, "limit": 10}, "findings-limit10"),
            ("decompile_functions", {"binary_path": PE, "function_names": ten, "include_bodies": False}, "10-no-bodies"),
            ("decompile_functions", {"binary_path": PE, "function_names": ten, "max_body_chars": 4000}, "10-budget4000"),
            ("find_stack_strings", {"binary_path": PE, "ioc_only": True}, "ioc_only"),
            ("get_functions", {"binary_path": PE, "limit": 20}, "limit20"),
        ]:
            r = await c.call_tool_mcp(name, args)
            t = r.content[0].text
            open(f"{SP}/out/results/{name}__{label}.txt", "w").write(t)
            print(f"{name:22s} {label:18s} text_o200k={count(t)['o200k']:6d} chars={len(t)}")
asyncio.run(main())
