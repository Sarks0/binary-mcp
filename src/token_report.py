"""
Measure what this server puts in front of a model before any tool is called.

A client sends the model the server instructions and, unless it defers tool
loading, every tool definition, on every request of every session. Those bytes
are easy to grow one docstring at a time and hard to notice, so this reports
them::

    python -m src.token_report                  # sizes in bytes and characters
    uv run --with anthropic python -m src.token_report --count-tokens --model <model-id>

``--count-tokens`` asks Anthropic's token-counting endpoint (free, but it
needs an API key or an ``ant auth login`` profile) for real token counts.
Character counts are only a proxy: the model's tokenizer is not public, and code
tokenizes far denser than prose. tests/test_token_budget.py enforces the byte
budgets; this is the tool for seeing where the bytes went and for checking a
change against real counts.

Listing tools never runs Ghidra. When none is installed, the server is
imported against an empty stub so the report still works on any machine.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path


def load_server(windows: bool | None = None, raw_windbg: bool | None = None):
    """Import src.server and register its tools, stubbing Ghidra if absent.

    ``windows`` and ``raw_windbg`` pick the host-dependent part of the roster
    (see register_all_tools); left None they follow this machine.
    """
    try:
        import src.server as server_module
    except Exception:
        # GhidraRunner() raises at import when no Ghidra install is found.
        # Listing tools does not need one.
        sys.modules.pop("src.server", None)
        stub = Path(tempfile.mkdtemp(prefix="binary-mcp-ghidra-stub-"))
        (stub / "support").mkdir()
        (stub / "support" / "analyzeHeadless").touch()
        os.environ["GHIDRA_HOME"] = str(stub)
        import src.server as server_module

    server_module.register_all_tools(windows=windows, raw_windbg=raw_windbg)
    return server_module


def wire_tools(app) -> list[dict]:
    """The tools/list entries exactly as an MCP client receives them."""
    from fastmcp import Client

    async def go():
        async with Client(app) as client:
            return await client.list_tools()

    return [t.model_dump(mode="json", by_alias=True, exclude_none=True) for t in asyncio.run(go())]


def wire_size(tools: list[dict]) -> int:
    """Bytes of the tools/list result as compact JSON, as sent on the wire."""
    return len(json.dumps(tools, separators=(",", ":"), ensure_ascii=False).encode())


def model_facing(tool: dict) -> dict:
    """The fields a model-facing tool definition carries: name, description, schema."""
    return {
        "name": tool["name"],
        "description": tool.get("description") or "",
        "input_schema": tool["inputSchema"],
    }


def count_model_tokens(tools: list[dict], instructions: str, model: str) -> dict:
    """Real token counts for the instructions and tool definitions.

    Each figure is the difference from a one-word baseline request, so it is
    what the instructions or tools add to a conversation, not the request.
    """
    try:
        import anthropic
    except ImportError:
        raise SystemExit(
            "--count-tokens needs the anthropic package; run it with\n"
            "  uv run --with anthropic python -m src.token_report --count-tokens"
        ) from None

    client = anthropic.Anthropic()
    messages = [{"role": "user", "content": "x"}]

    def count(**kwargs) -> int:
        return client.messages.count_tokens(
            model=model, messages=messages, **kwargs
        ).input_tokens

    baseline = count()
    with_instructions = count(system=instructions) if instructions else baseline
    definitions = [model_facing(t) for t in tools]
    with_tools = count(system=instructions, tools=definitions) if instructions else count(
        tools=definitions
    )
    return {
        "model": model,
        "instructions": with_instructions - baseline,
        "tool_definitions": with_tools - with_instructions,
        "total": with_tools - baseline,
    }


def report(tools: list[dict], instructions: str, top: int) -> str:
    sizes = sorted(
        (
            (len(json.dumps(model_facing(t), separators=(",", ":"))), t["name"])
            for t in tools
        ),
        reverse=True,
    )
    lines = [
        f"tools: {len(tools)}",
        f"tools/list wire size: {wire_size(tools):,} bytes",
        f"model-facing definitions: {sum(s for s, _ in sizes):,} characters",
        f"server instructions: {len(instructions):,} characters",
        "",
        f"heaviest {top} definitions (characters):",
    ]
    lines += [f"  {size:6,}  {name}" for size, name in sizes[:top]]
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m src.token_report")
    parser.add_argument("--top", type=int, default=15, help="heaviest tools to list")
    parser.add_argument(
        "--count-tokens",
        action="store_true",
        help="also ask the token-counting endpoint for real counts (needs --model)",
    )
    parser.add_argument("--model", help="model ID to count tokens for")
    parser.add_argument(
        "--windows",
        action="store_true",
        help="measure the roster a Windows host lists, whatever this host is",
    )
    args = parser.parse_args(argv)
    if args.count_tokens and not args.model:
        parser.error("--count-tokens needs --model")

    server_module = load_server(windows=True if args.windows else None)
    tools = wire_tools(server_module.app)
    instructions = server_module.app.instructions or ""
    print(report(tools, instructions, args.top))

    if args.count_tokens:
        counts = count_model_tokens(tools, instructions, args.model)
        print()
        print(f"Tokens ({counts['model']}):")
        print(f"  server instructions: {counts['instructions']:,}")
        print(f"  tool definitions:    {counts['tool_definitions']:,}")
        print(f"  total up front:      {counts['total']:,}")


if __name__ == "__main__":
    _main()
