import asyncio, json, warnings; warnings.filterwarnings("ignore")
from fastmcp import FastMCP, Client, Context
from fastmcp.server.transforms.search import BM25SearchTransform
from fastmcp.server.middleware.response_limiting import ResponseLimitingMiddleware

def mk():
    s = FastMCP("t3", list_page_size=2)
    @s.tool(tags={"category:static","code-output"})
    def disasm(addr: int, count: int = 10) -> str:
        """Disassemble instructions.

        Args:
            addr: Start address
            count: Number of instructions
        """
        return "# listing\n" + "x" * 300
    @s.tool(tags={"category:dynamic"})
    def set_breakpoint(addr: int) -> str:
        "Set a breakpoint in the debugger."
        return "bp set"
    @s.tool(tags={"category:static"})
    def list_strings(min_len: int = 4) -> str:
        "List printable strings in the binary."
        return "strings"
    @s.tool(tags={"meta"})
    async def load_category(cat: str, ctx: Context) -> str:
        "Enable a tool category for this session."
        await ctx.enable_components(tags={f"category:{cat}"})
        return f"enabled {cat}"
    return s

async def main():
    s = mk()
    async with Client(s) as c:
        tl = await c.list_tools()
        d = [t for t in tl if t.name=="disasm"][0].model_dump(exclude_none=True, by_alias=True)
        print("3.x disasm listing:", json.dumps(d))
        r = await c.call_tool_mcp("disasm", {"addr": 1})
        print("3.x str result structured present:", r.structuredContent is not None, "| content blocks:", len(r.content))
        # raw pagination
        p1 = await c.session.list_tools(); print("page1:", [t.name for t in p1.tools], "nextCursor:", bool(p1.nextCursor))
    # session-scoped visibility
    s = mk(); s.disable(tags={"category:dynamic"})
    notes=[]
    async def mh(m): notes.append(getattr(getattr(m,'root',m),'method',type(m).__name__))
    async with Client(s, message_handler=mh) as c:
        print("\nafter server.disable(dynamic):", [t.name for t in await c.list_tools()])
        await c.call_tool("load_category", {"cat": "dynamic"}); await asyncio.sleep(0.2)
        print("after ctx.enable_components(dynamic):", [t.name for t in await c.list_tools()], "notifs:", notes)
    async with Client(s) as c2:
        print("other session still sees:", [t.name for t in await c2.list_tools()])
    # search transform
    s = mk(); s.add_transform(BM25SearchTransform(max_results=2, always_visible=["load_category"]))
    async with Client(s) as c:
        tl = await c.list_tools(); print("\nBM25 listing:", [t.name for t in tl])
        for t in tl:
            if t.name in ("search_tools","call_tool"): print(" ", t.name, json.dumps(t.model_dump(exclude_none=True, by_alias=True))[:600])
        r = await c.call_tool_mcp("search_tools", {"query": "breakpoint debugger"}); print("search result:", r.content[0].text[:700])
        r = await c.call_tool_mcp("call_tool", {"name": "set_breakpoint", "arguments": {"addr": 5}}); print("proxy call:", [b.text for b in r.content], r.structuredContent)
        r = await c.call_tool_mcp("set_breakpoint", {"addr": 5}); print("direct call of hidden tool:", r.content[0].text, r.isError)
    # response limiting
    s = mk(); s.add_middleware(ResponseLimitingMiddleware(max_size=120))
    async with Client(s) as c:
        try:
          r = await c.call_tool_mcp("disasm", {"addr": 1}); print("\nlimited:", repr(r.content[0].text[-60:]), "isError:", r.isError, "structured:", r.structuredContent)
        except Exception as e: print("\nlimited -> client error:", e)
asyncio.run(main())
