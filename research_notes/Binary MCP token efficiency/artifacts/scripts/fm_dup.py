import asyncio, json
from fastmcp import FastMCP, Client
from fastmcp.tools.tool import ToolResult

mcp = FastMCP("dup-test")
BODY = "int FUN_00401000(int a) {\n    return a + 1;\n}\n"

@mcp.tool
def decompile_str(addr: str) -> str:
    """str-annotated tool"""
    return BODY

@mcp.tool(output_schema=None)
def decompile_noschema(addr: str) -> str:
    """str tool with output_schema=None"""
    return BODY

@mcp.tool
def list_funcs() -> dict:
    """dict tool"""
    return {"functions": [{"name": "main", "addr": "0x401000", "size": 42}]}

@mcp.tool
def decompile_toolresult(addr: str) -> ToolResult:
    """ToolResult text-only"""
    return ToolResult(content=BODY)

async def main():
    async with Client(mcp) as c:
        tools = await c.list_tools()
        for t in tools:
            print("TOOL", t.name, "outputSchema=", json.dumps(t.outputSchema))
        for name, args in [("decompile_str", {"addr": "x"}), ("decompile_noschema", {"addr": "x"}), ("list_funcs", {}), ("decompile_toolresult", {"addr": "x"})]:
            r = await c.call_tool_mcp(name, args)
            d = r.model_dump(exclude_none=True, by_alias=True)
            raw = json.dumps(d)
            print("CALL", name, "bytes=", len(raw), "->", raw)

asyncio.run(main())
