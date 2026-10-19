import asyncio, json, warnings
warnings.filterwarnings("ignore")
from typing import Annotated
from pydantic import Field
import mcp.types as mt
from fastmcp import FastMCP, Client, Context
from fastmcp.tools import Tool
from fastmcp.tools.tool_transform import ArgTransform
from fastmcp.tools.tool import ToolResult
from fastmcp.server.middleware import Middleware, MiddlewareContext

srv = FastMCP("t", instructions="Server instructions here")

@srv.tool(tags={"category:static", "code-output"})
def disasm(addr: int, count: int = 10) -> str:
    """Disassemble instructions.

    Longer explanation paragraph.

    Args:
        addr: Start address
        count: Number of instructions

    Returns:
        Markdown listing
    """
    return "# listing\n" + "x" * 50

@srv.tool(tags={"category:dynamic"})
def annotated(addr: Annotated[int, Field(description="Start address (hex ok)")], fmt: Annotated[str, "plain-string annotation"] = "md") -> str:
    "One-liner."
    return "ok"

@srv.tool(output_schema=None, tags={"category:static"})
def nostruct(x: int) -> str:
    "No structured output."
    return "plain"

@srv.tool
def asdict(x: int) -> dict:
    "Returns dict."
    return {"a": x}

@srv.tool
def toolresult(x: int) -> ToolResult:
    "Returns ToolResult."
    return ToolResult(content=[mt.TextContent(type="text", text="summary only")], structured_content={"full": [1,2,3]})

@srv.tool
async def hide_disasm(ctx: Context) -> str:
    "Disable disasm at runtime."
    disasm_tool = await srv.get_tool("disasm")
    disasm_tool.disable()
    return "disabled"

async def main():
    notes = []
    async def mh(msg):
        notes.append(type(msg).__name__ + ":" + repr(getattr(getattr(msg,'root',msg),'method',msg))[:80])
    async with Client(srv, message_handler=mh) as c:
        print("INSTRUCTIONS:", c.initialize_result.instructions)
        print("CAPS tools:", c.initialize_result.capabilities.tools)
        for t in await c.list_tools():
            d = t.model_dump(exclude_none=True, by_alias=True)
            print("\nTOOL", json.dumps(d, indent=None))
        for name, args in [("disasm", {"addr": 1}), ("nostruct", {"x": 1}), ("asdict", {"x": 2}), ("toolresult", {"x": 1})]:
            r = await c.call_tool_mcp(name, args)
            print(f"\nCALL {name}: content={[x.model_dump(exclude_none=True) for x in r.content]} structured={r.structuredContent}")
        r = await c.call_tool_mcp("hide_disasm", {})
        await asyncio.sleep(0.2)
        print("\nNOTIFICATIONS after disable:", notes)
        print("tools now:", [t.name for t in await c.list_tools()])

    # include/exclude tags
    s2 = FastMCP("t2", include_tags={"category:static"})
    s2.add_tool(Tool.from_function(disasm.fn, tags={"category:static"}))
    s2.add_tool(Tool.from_function(annotated.fn, tags={"category:dynamic"}))
    async with Client(s2) as c: print("\ninclude_tags static ->", [t.name for t in await c.list_tools()])
    s3 = FastMCP("t3", exclude_tags={"code-output"})
    s3.add_tool(Tool.from_function(disasm.fn, tags={"category:static","code-output"}))
    s3.add_tool(Tool.from_function(annotated.fn, tags={"category:dynamic"}))
    async with Client(s3) as c: print("exclude_tags code-output ->", [t.name for t in await c.list_tools()])

    # middleware filtering + truncation
    class Filter(Middleware):
        async def on_list_tools(self, context: MiddlewareContext, call_next):
            tools = await call_next(context)
            return [t for t in tools if "category:static" in t.tags]
        async def on_call_tool(self, context, call_next):
            res = await call_next(context)
            for blk in res.content:
                if getattr(blk, "type", None) == "text" and len(blk.text) > 20:
                    blk.text = blk.text[:20] + "...[truncated]"
            if res.structured_content and "result" in res.structured_content:
                res.structured_content = None
            return res
    s4 = FastMCP("t4", middleware=[Filter()])
    s4.add_tool(Tool.from_function(disasm.fn, tags={"category:static"}))
    s4.add_tool(Tool.from_function(annotated.fn, tags={"category:dynamic"}))
    async with Client(s4) as c:
        print("\nmiddleware list ->", [t.name for t in await c.list_tools()])
        r = await c.call_tool_mcp("disasm", {"addr": 1})
        print("middleware call ->", r.content[0].text, "structured:", r.structuredContent)
        try:
            r = await c.call_tool_mcp("annotated", {"addr": 1}); print("hidden-by-middleware tool still callable:", r.content[0].text, r.isError)
        except Exception as e: print("hidden tool call error", e)

    # tool transformation
    base = Tool.from_function(disasm.fn)
    t2 = Tool.from_tool(base, name="dis", description="Disassemble.", transform_args={"count": ArgTransform(hide=True, default=5), "addr": ArgTransform(name="a", description="addr")}, output_schema=None)
    s5 = FastMCP("t5"); s5.add_tool(t2)
    async with Client(s5) as c:
        t = (await c.list_tools())[0]; print("\ntransformed:", json.dumps(t.model_dump(exclude_none=True, by_alias=True)))
        r = await c.call_tool_mcp("dis", {"a": 3}); print("transformed call structured:", r.structuredContent)

    # mount with prefix
    parent = FastMCP("parent"); child = FastMCP("child"); child.add_tool(Tool.from_function(disasm.fn))
    parent.mount(child, prefix="ghidra")
    async with Client(parent) as c: print("\nmounted:", [t.name for t in await c.list_tools()])

asyncio.run(main())
