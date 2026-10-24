"""
Turn Google-style tool docstrings into what a model should read.

FastMCP 2.x sends a tool's whole docstring as its description and gives the
parameters no descriptions at all, so the model gets an ``Args:`` block of
prose next to an input schema that says nothing, plus ``Returns:`` and
``Example:`` sections that restate the signature. Across the roster those
sections were about 30% of tools/list.

shape_tool_docs() runs at registration. Each ``Args:`` entry becomes the
schema description of the parameter it documents, which is where clients
and tool search look for it. ``Returns:``, ``Raises:`` and ``Example:``
sections are dropped. Everything else, including ``Note:`` and the x64dbg
``Operations:`` catalogs, stays in the description. The source docstrings
are untouched, so they still read as documentation in the code.

An ``Args:`` entry that names no parameter of the tool is kept in the
description rather than dropped.
"""

from __future__ import annotations

import re

_SECTION_RE = re.compile(r"^(?P<name>[A-Z][A-Za-z ]*):\s*$")
_ARGS_SECTIONS = {"Args", "Arguments", "Parameters"}
_DROPPED_SECTIONS = {"Returns", "Return", "Raises", "Yields", "Example", "Examples"}

# ``name: text``, ``name (type): text`` or ``a / b: text`` for an entry that
# documents two parameters at once.
_ENTRY_RE = re.compile(
    r"^(?P<names>[A-Za-z_]\w*(?:\s*/\s*[A-Za-z_]\w*)*)\s*(?:\([^)]*\))?:\s*(?P<text>.*)$"
)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _split_sections(doc: str) -> list[tuple[str | None, list[str]]]:
    """``[(section_name or None, lines)]`` in order.

    A section is a header line at column 0 (``Args:``) followed by the lines
    indented under it; the first unindented, non-blank line ends it.
    """
    parts: list[tuple[str | None, list[str]]] = [(None, [])]
    for line in doc.splitlines():
        header = _SECTION_RE.match(line)
        if header:
            parts.append((header.group("name"), []))
            continue
        name, lines = parts[-1]
        if name is not None and line.strip() and _indent(line) == 0:
            parts.append((None, [line]))
            continue
        lines.append(line)
    return parts


def _join(lines: list[str]) -> str:
    """Join wrapped lines into prose, keeping paragraph and list breaks."""
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            if out and out[-1] != "":
                out.append("")
            continue
        if out and out[-1] and not re.match(r"^([-*]|\d+\.)\s", line):
            out[-1] = f"{out[-1]} {line}"
        else:
            out.append(line)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


def _parse_args(lines: list[str]) -> list[tuple[list[str], str, list[str]]]:
    """``[(names, description, original_lines)]`` for one ``Args:`` body."""
    body = [line for line in lines if line.strip()]
    if not body:
        return []
    entry_indent = _indent(body[0])
    entries: list[tuple[list[str], list[str], list[str]]] = []
    for line in lines:
        match = _ENTRY_RE.match(line.strip()) if _indent(line) == entry_indent else None
        if match and line.strip():
            names = [n.strip() for n in match.group("names").split("/")]
            entries.append((names, [match.group("text")], [line]))
        elif entries:
            entries[-1][1].append(line)
            entries[-1][2].append(line)
    return [(names, _join(text), original) for names, text, original in entries]


def shape_tool_docs(tools: dict) -> None:
    """Move Args into parameter schemas and drop restating sections, in place."""
    for tool in tools.values():
        doc = tool.description or ""
        properties = (tool.parameters or {}).get("properties", {})
        kept: list[str] = []
        for name, lines in _split_sections(doc):
            if name in _DROPPED_SECTIONS:
                continue
            if name in _ARGS_SECTIONS:
                unmatched: list[str] = []
                for names, text, original in _parse_args(lines):
                    targets = [n for n in names if n in properties]
                    if not targets or not text:
                        unmatched.extend(original)
                        continue
                    for target in targets:
                        properties[target].setdefault("description", text)
                if unmatched:
                    kept.append(f"{name}:")
                    kept.extend(unmatched)
                continue
            if name is not None:
                kept.append(f"{name}:")
            kept.extend(lines)
        shaped = re.sub(r"\n{3,}", "\n\n", "\n".join(line.rstrip() for line in kept)).strip()
        tool.description = shaped
