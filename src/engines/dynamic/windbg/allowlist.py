"""
Token-aware command validator for the WinDbg bridge.

Replaces the legacy substring blocklist (``_BLOCKED_COMMANDS`` matched
case-insensitively against the entire command string), which was
simultaneously over- and under-blocking:

  - Over-blocked: ``.formats``, ``.tlist``, ``.outmask`` (read-only),
    ``.foreach`` (control-flow), and any breakpoint command containing
    ``.printf "..."`` or ``.sympath`` literals in argument text.
  - Under-blocked: ``.dvalloc`` / ``.dvfree`` (RWX in the target,
    documented EDR-bypass technique), ``.process /i`` (invasive
    context switch + resume at attacker-chosen RIP), ``e[bdwqp]``
    memory-write family (bypasses the ``.writevirtmem`` block),
    register write via ``r @rip = ...``, ``a`` (assemble),
    ``!chkimg /f``.

Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/security-during-debugging-of-user-mode

The validator works in two passes:

  1. ``parse_compound`` splits a user-supplied string on ``;`` outside
     quoted regions and curly-brace blocks (so ``.foreach (a {!process})
     {!handle ${a}}`` is one entry, not two).
  2. ``validate_command`` checks each subcommand against deny-tokens
     (matched on first whitespace token, case-insensitive) and
     write-primitive regexes (matched anywhere).

Non-write meta-commands that have a structured replacement (e.g.
``.sympath`` -> :func:`windbg_set_sympath`) stay denied here so callers
are routed through the structured tool.
"""

from __future__ import annotations

import re

# First-token deny set. Compared lower-case against the leading whitespace
# token of each subcommand. Must include the leading dot/bang where
# applicable - "shell" is harmless, ".shell" is not.
_DENY_FIRST_TOKEN = frozenset({
    # Process / session control
    ".shell",
    ".create",
    ".abandon",
    ".kill",
    ".restart",
    ".detach",
    ".reboot",
    ".crash",
    ".attach",
    # File I/O - structured replacements provided by tool layer
    ".dump",
    ".writemem",
    ".writevirtmem",
    ".logopen",
    ".logclose",
    ".open",
    ".opendump",
    # Scripting / execution / control flow that yields RCE primitives
    ".script",
    ".scriptrun",
    ".scriptload",
    "!runscript",
    ".call",
    ".block",
    # Module loading
    ".load",
    ".loadby",
    ".cordll",
    # Network / remote
    ".remote",
    ".netsyms",
    # Symbol path: routed through windbg_set_sympath instead
    ".sympath",
    ".symfix",
    # Active EDR-bypass primitives - allocate RWX in target
    ".dvalloc",
    ".dvfree",
    # Page in / out: target memory state mutation
    ".pagein",
    # Memory write families. dbgeng treats these as the canonical write
    # primitive; without blocking them, .writevirtmem and .writemem are
    # trivially bypassable.
    "eb", "ed", "ew", "eq", "ep", "eu", "ea", "eza", "ezu",
    # Assembler - emits machine code into target memory
    "a",
})

# Argument-form deny rules. Each entry is (regex, reason) and is matched
# case-insensitively against the full subcommand string. Use these for
# patterns where the first token alone cannot decide (e.g. ``r`` is read,
# ``r @rip = 0x1`` is write).
_DENY_ARGFORM: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"^\s*r\s+[^\s,]+\s*=\s*\S", re.IGNORECASE),
        "register write via 'r' is forbidden; use a structured tool",
    ),
    (
        re.compile(r"^\s*\.process\s+/i\b", re.IGNORECASE),
        ".process /i (invasive switch + resume) is forbidden",
    ),
    (
        re.compile(r"^\s*!chkimg\b.*\s/f\b", re.IGNORECASE),
        "!chkimg /f patches the loaded image; only the read-only form is allowed",
    ),
    (
        re.compile(r"^\s*s\s+-[bdwq]\s", re.IGNORECASE),
        "'s -b/-d/-w/-q' search-and-write variants are forbidden",
    ),
    (
        re.compile(r"^\s*\.bugcheck\b\s+\S", re.IGNORECASE),
        ".bugcheck simulator (with code) is forbidden; bare .bugcheck stays allowed",
    ),
    (
        re.compile(r"^\s*\.printf\b.*\s/D\b", re.IGNORECASE),
        ".printf /D (DML output) is forbidden; plain .printf is allowed",
    ),
)


def parse_compound(command: str) -> list[str]:
    """Split a WinDbg command on ``;`` outside quotes and ``{...}`` blocks.

    WinDbg uses ``;`` as a sequencer (e.g. ``g; bp X``) but it also
    appears inside quoted strings (``.printf "a;b"``) and inside ``.foreach``
    bodies (``.foreach (x {!process 0 0}) {!handle ${x}}``). A naive
    ``str.split(";")`` would either over-split (rejecting legitimate
    composite commands) or under-split (letting ``.shell`` slip through
    a quoted argument). This tokenizer tracks quote and brace depth so
    each subcommand is validated independently.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_dq = False
    in_sq = False
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "\\" and i + 1 < len(command):
            current.append(ch)
            current.append(command[i + 1])
            i += 2
            continue
        # ${...} is variable interpolation in .foreach / .for, not a block.
        if (
            not in_dq
            and not in_sq
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                # Unbalanced - copy the rest verbatim and stop.
                current.append(command[i:])
                i = len(command)
                continue
            current.append(command[i:j + 1])
            i = j + 1
            continue
        if not in_sq and ch == '"':
            in_dq = not in_dq
            current.append(ch)
        elif not in_dq and ch == "'":
            in_sq = not in_sq
            current.append(ch)
        elif not in_dq and not in_sq and ch == "{":
            depth += 1
            current.append(ch)
        elif not in_dq and not in_sq and ch == "}":
            depth = max(0, depth - 1)
            current.append(ch)
        elif not in_dq and not in_sq and depth == 0 and ch == ";":
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _first_token(subcommand: str) -> str:
    """Return the lowered first whitespace-delimited token, with leading sigils."""
    s = subcommand.strip()
    if not s:
        return ""
    # Pull off the first run of non-whitespace as the command name.
    m = re.match(r"\S+", s)
    return m.group(0).lower() if m else ""


def validate_command(command: str) -> tuple[bool, str | None]:
    """Validate a (possibly compound) WinDbg command string.

    Returns ``(True, None)`` if every subcommand is allowed, else
    ``(False, reason)`` for the first violation.
    """
    if not command or not command.strip():
        return False, "empty command"

    if len(command) > 4096:
        return False, "command too long (max 4096 chars)"

    parts = parse_compound(command)
    if not parts:
        return False, "empty command"

    # Bound compound depth to keep the validator deterministic.
    if len(parts) > 16:
        return False, f"too many compound subcommands ({len(parts)} > 16)"

    for part in parts:
        first = _first_token(part)
        if not first:
            return False, "empty subcommand in compound"

        if first in _DENY_FIRST_TOKEN:
            return False, f"command {first!r} is denied"

        for pattern, reason in _DENY_ARGFORM:
            if pattern.match(part):
                return False, reason

        # Inner command of .foreach / .for must also pass: recurse into the
        # ``{...}`` block content if present.
        inner = _extract_inner_block(part)
        if inner is not None:
            ok, why = validate_command(inner)
            if not ok:
                return False, f"in compound block: {why}"

    return True, None


def _extract_inner_block(command: str) -> str | None:
    """Pull the body out of a ``.foreach (...) {body}`` or ``.for {init} {cond} {step} {body}``.

    Returns the concatenation of all top-level ``{...}`` block contents,
    separated by ``;``. None if no blocks present.
    """
    blocks: list[str] = []
    depth = 0
    start = -1
    in_dq = False
    in_sq = False
    i = 0
    while i < len(command):
        ch = command[i]
        # Skip ${...} variable interpolation entirely.
        if (
            not in_dq
            and not in_sq
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                break
            i = j + 1
            continue
        if not in_sq and ch == '"':
            in_dq = not in_dq
        elif not in_dq and ch == "'":
            in_sq = not in_sq
        elif not in_dq and not in_sq:
            if ch == "{":
                if depth == 0:
                    start = i + 1
                depth += 1
            elif ch == "}":
                depth = max(0, depth - 1)
                if depth == 0 and start >= 0:
                    blocks.append(command[start:i])
                    start = -1
        i += 1
    if not blocks:
        return None
    return ";".join(b.strip() for b in blocks if b.strip())


__all__ = [
    "parse_compound",
    "validate_command",
]
