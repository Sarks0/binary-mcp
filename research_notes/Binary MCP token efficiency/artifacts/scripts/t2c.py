import asyncio, json, warnings; warnings.filterwarnings("ignore")
from fastmcp import FastMCP, Client
for kw in [{}, {"include_fastmcp_meta": False}]:
    s = FastMCP("m", exclude_tags={"hidden"}, **kw)
    @s.tool(tags={"category:static"}, meta={"anthropic/maxResultSizeChars": 200000, "anthropic/alwaysLoad": True}, output_schema=None)
    def decompile(fn: str) -> str:
        "Decompile a function."
        return "code"
    @s.tool(tags={"hidden"})
    def secret() -> str:
        "Hidden by tag."
        return "should not run"
    async def run():
        async with Client(s) as c:
            t = (await c.session.list_tools()).tools
            print(kw, "listed:", [x.name for x in t], "| _meta:", json.dumps(t[0].meta))
            r = await c.call_tool_mcp("secret", {})
            print("  call tag-excluded tool -> isError:", r.isError, "|", r.content[0].text[:90])
    asyncio.run(run())
