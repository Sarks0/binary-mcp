"""Dump initialize + tools/list exactly as the stdio transport would send them.

Usage: python -I dump_tools_list.py OUT_PREFIX [KEY=VALUE ...]
Extra KEY=VALUE pairs are set as env vars before the server is imported
(used for the determinism check).
"""
import asyncio
import hashlib
import json
import sys

sys.path.insert(0, "/tmp/claude-0/-home-user-binary-mcp/72b3831f-3b41-5165-8cb6-d19747cd4e63/scratchpad/scripts")
from common import SP, setup_env  # noqa: E402

out_prefix = sys.argv[1]
extra = dict(a.split("=", 1) for a in sys.argv[2:])
setup_env(extra)

from mcp.types import JSONRPCMessage, JSONRPCResponse  # noqa: E402

from src.server import app, register_all_tools  # noqa: E402

register_all_tools()

from fastmcp import Client  # noqa: E402


def wire(result_model, rid):
    """Serialize a result model exactly like mcp.shared.session + stdio.py."""
    resp = JSONRPCResponse(
        jsonrpc="2.0",
        id=rid,
        result=result_model.model_dump(by_alias=True, mode="json", exclude_none=True),
    )
    return JSONRPCMessage(resp).model_dump_json(by_alias=True, exclude_none=True)


async def main():
    async with Client(app) as c:
        init = c.initialize_result
        lt = await c.list_tools_mcp()
    init_wire = wire(init, 0)
    tools_wire = wire(lt, 1)
    with open(f"{out_prefix}_init.json", "w") as f:
        f.write(init_wire)
    with open(f"{out_prefix}_tools.json", "w") as f:
        f.write(tools_wire)
    d = json.loads(tools_wire)
    print("tools:", len(d["result"]["tools"]),
          "nextCursor" in d["result"],
          "bytes:", len(tools_wire.encode()),
          "sha256:", hashlib.sha256(tools_wire.encode()).hexdigest()[:16])
    i = json.loads(init_wire)["result"]
    print("init keys:", list(i.keys()), "instructions:", repr(i.get("instructions"))[:200])
    print("serverInfo:", i.get("serverInfo"), "protocolVersion:", i.get("protocolVersion"))


asyncio.run(main())
