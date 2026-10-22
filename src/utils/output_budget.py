"""
One output budget for every tool that hands code to the model.

The ``code-output`` tools (see src/tool_catalog.py) return decompiled C, C#,
IL, disassembly or replays of earlier tool output, and a single call used to
be able to return 120,000 characters or more. That is past the inline limit
of every common MCP client: one warns above 10,000 tokens, caps output
at 25,000 and moves any text result over 50,000 characters into a file;
OpenCode cuts at 50 KB and Gemini CLI at 40,000 characters. A client that cuts
does so blindly, usually at the end, which is exactly where the server used to
put its "withheld" notes. So the budget is set from the strictest client down,
and anything the server leaves out is reported at the top.

CODE_OUTPUT_CHAR_BUDGET is in characters because the model's tokenizer is
not public. Decompiled C averages roughly 2.6 characters per token, so 24,000
characters is about 9,000 tokens, under every limit above.

The decompile tools page their own output against this budget, so they can
say exactly what to ask for next. code_output_budget_middleware() is the
backstop for the rest: it cuts an oversized result at a line boundary instead
of letting the client cut it.
"""

from __future__ import annotations

from collections.abc import Iterable

from src.utils.formatters import UNTRUSTED_END_MARKER, UNTRUSTED_OPEN_SENTINEL

CODE_OUTPUT_CHAR_BUDGET = 24_000

_ENVELOPE_OPEN = f"{UNTRUSTED_OPEN_SENTINEL}BEGIN UNTRUSTED SAMPLE DATA"

DEFAULT_HINT = (
    "Narrow the request to see the rest: fewer functions or types, a later "
    "start_line, a smaller count, or one session section at a time."
)


def cap_output(
    text: str,
    budget: int = CODE_OUTPUT_CHAR_BUDGET,
    hint: str = DEFAULT_HINT,
) -> str:
    """Cut TEXT to BUDGET characters at a line boundary, saying so at the top.

    The cut never leaves an untrusted-content envelope open. Every sentinel
    inside an envelope body is escaped by wrap_untrusted, so counting openers
    against terminators in the kept text is exact, and an envelope the cut
    went through gets its terminator back. The notice goes first, outside any
    envelope, because it is the server's own text and because clients that
    truncate again cut from the end.
    """
    if len(text) <= budget:
        return text

    cut = text.rfind("\n", 0, budget)
    if cut <= 0:
        cut = budget
    kept = text[:cut].rstrip("\n")
    if kept.count(_ENVELOPE_OPEN) > kept.count(UNTRUSTED_END_MARKER):
        kept += "\n" + UNTRUSTED_END_MARKER

    notice = (
        f"*Output cut to the first {cut:,} of {len(text):,} characters "
        f"(code-output budget {budget:,}). {hint}*"
    )
    return f"{notice}\n\n{kept}"


class CodeOutputBudgetMiddleware:
    """FastMCP middleware applying cap_output to the named tools' text results.

    FastMCP calls a middleware as ``middleware(context, call_next=...)``, so a
    plain callable is enough. Not subclassing ``fastmcp``'s Middleware, and
    importing its types only when a tool call arrives, keeps registration
    free of FastMCP imports: several test modules replace ``fastmcp`` with a
    stub before importing tool code, and registration has to work under it.
    """

    def __init__(self, tool_names: Iterable[str], budget: int = CODE_OUTPUT_CHAR_BUDGET):
        self.tool_names = frozenset(tool_names)
        self.budget = budget

    async def __call__(self, context, call_next):
        result = await call_next(context)
        if getattr(context, "method", None) != "tools/call":
            return result
        if context.message.name not in self.tool_names:
            return result

        from fastmcp.tools.tool import ToolResult
        from mcp.types import TextContent

        changed = False
        content = []
        for block in result.content:
            if isinstance(block, TextContent) and len(block.text) > self.budget:
                block = TextContent(type="text", text=cap_output(block.text, self.budget))
                changed = True
            content.append(block)
        if not changed:
            return result
        return ToolResult(content=content, structured_content=result.structured_content)


def code_output_budget_middleware(
    tool_names: Iterable[str],
    budget: int = CODE_OUTPUT_CHAR_BUDGET,
) -> CodeOutputBudgetMiddleware:
    """The middleware the server registers for its code-output tools."""
    return CodeOutputBudgetMiddleware(tool_names, budget)
