import asyncio, json, warnings; warnings.filterwarnings("ignore")
from fastmcp import FastMCP, Client
from fastmcp.server.middleware import Middleware
md = "| addr | bytes | insn |\n|---|---|---|\n" + "\n".join(f'| 0x{0x401000+i*4:08x} | 55 48 89 e5 | mov rbp, rsp ; "frame" |' for i in range(200))
class StripStructured(Middleware):
    async def on_list_tools(self, context, call_next):
        tools = await call_next(context)
        return [t.model_copy(update={"output_schema": None}) for t in tools]
    async def on_call_tool(self, context, call_next):
        r = await call_next(context); r.structured_content = None; return r
for label, mw in [("default", []), ("strip-middleware", [StripStructured()])]:
    s = FastMCP("x", middleware=mw)
    @s.tool(tags={"category:static", "code-output"})
    def disasm(addr: int, count: int = 10) -> str:
        "Disassemble."
        return md
    async def run():
        async with Client(s) as c:
            raw = await c.session.list_tools()
            t = raw.tools[0].model_dump(exclude_none=True, by_alias=True)
            r = await c.call_tool_mcp("disasm", {"addr": 1})
            body = r.model_dump(exclude_none=True, by_alias=True)
            print(f"{label}: tool-def bytes={len(json.dumps(t))} outputSchema bytes={len(json.dumps(t.get('outputSchema'))) if t.get('outputSchema') else 0} _meta bytes={len(json.dumps(t.get('_meta',{})))} | result wire bytes={len(json.dumps(body))} isError={r.isError} structured={'yes' if r.structuredContent else 'no'}")
    asyncio.run(run())
print("markdown bytes:", len(md), "| json.dumps({'result': md}) bytes:", len(json.dumps({"result": md})), "| ratio %.3f" % (len(json.dumps({"result": md}))/len(md)))
print("newlines in md:", md.count("\n"), "quotes:", md.count('"'))
