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

  1. ``parse_compound`` splits a user-supplied string on every separator
     WinDbg honours -- ``;`` AND raw newlines -- outside quoted regions and
     curly-brace blocks (so ``.foreach (a {!process}) {!handle ${a}}`` is one
     entry, not two, while ``k\n.shell`` is two, not one).
  2. ``validate_command`` checks each subcommand against deny-tokens (matched
     on first whitespace token, case-insensitive, including the alias-defining
     family that WinDbg pre-expands) and write/execute-primitive regexes
     (matched anywhere, including the ``$<`` script-file include operators).
     It then recurses into every *nested subcommand body* -- both ``{...}``
     blocks (``.foreach`` / ``.for``) and ``'...'`` bodies (``j`` / ``z``,
     see :func:`_extract_quoted_bodies`) -- so a denied primitive cannot hide
     one level down. Recursion is depth-capped (audit F-1).

Non-write meta-commands that have a structured replacement (e.g.
``.sympath`` -> :func:`windbg_set_sympath`) stay denied here so callers
are routed through the structured tool.
"""

from __future__ import annotations

import re

# Maximum nesting level validate_command will recurse through. Real analysis
# commands nest one or two levels (a .foreach body, a j body inside it); the
# only thing that reaches double digits is a payload built to exhaust the
# interpreter stack, since each extra ``{...}`` level costs two characters
# against the 4096-char limit but one Python frame. Rejecting past the cap is
# both safe (deny, never allow) and cheap.
_MAX_VALIDATION_DEPTH = 8

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
    # The rest of the Enter/Fill/Move family (audit F-2). These were missing
    # and reached the debugger directly, no 'j' wrapper needed:
    #   'e'  - bare Enter Values, writes using the last-used data type
    #   'ef' - Enter 4-byte floats. NOTE _first_token lowercases, so 'eD'
    #          folds onto the already-denied 'ed'; 'ef' has no such twin and
    #          must be listed explicitly.
    #   'f'  - Fill Memory, writes a repeating pattern over a whole range
    #   'm'  - Move Memory, copies one range over another
    "e", "ef", "f", "m",
    # Assembler - emits machine code into target memory
    "a",
    # Control-flow commands whose subcommands are single-quote delimited.
    # 'j' (Execute If-Else) and 'z' (Execute While) take their bodies as
    # "j <expr> 'cmd1' ; 'cmd2'". parse_compound protects "'" regions from
    # ';' splitting, so before audit F-1 nothing inside those bodies was ever
    # validated and 'j 1 '$$><c:\\evil.txt'' was a straight path to RCE.
    # validate_command now recurses into quoted bodies as well, but neither
    # command has an analysis use the structured tools do not already cover,
    # so the simplest correct answer is to deny the driver command outright.
    "j", "z",
    # Alias definition/deletion. WinDbg expands aliases BEFORE command-name
    # resolution, so 'aS x .shell' then 'x' would smuggle a denied command
    # past first-token validation (audit H3). _first_token lowercases, so
    # 'as' also covers 'aS'. 'al' (list) is denied too for a clean surface.
    "as", "al", "ad",
    # .cmdtree loads a command-tree definition from a file (execution vector).
    ".cmdtree",
})

# Argument-form deny rules. Each entry is (regex, reason) and is matched
# case-insensitively against the full subcommand string. Use these for
# patterns where the first token alone cannot decide (e.g. ``r`` is read,
# ``r @rip = 0x1`` is write).
_DENY_ARGFORM: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        # Script-file include operators: $<, $><, $$<, $$><, $$>a< all run an
        # arbitrary debugger command file from disk (audit H2). The optional
        # '$', '>' and 'a' between the leading '$' and '<' cover every form.
        # Anchored at the subcommand start so it never matches a legitimate
        # pseudo-register/alias use like '@$teb' or '${x}'.
        re.compile(r"^\s*\$\$?>?a?<", re.IGNORECASE),
        "script-file include ($<, $$<, $$>a< ...) is forbidden; "
        "it runs an arbitrary debugger command file",
    ),
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
        elif not in_dq and not in_sq and depth == 0 and ch in ";\n\r":
            # WinDbg honours BOTH ';' and raw newlines as command separators.
            # Splitting on newlines too closes the injection where 'k\n.shell'
            # was validated as a single 'k' subcommand (audit H1). Empty pieces
            # (e.g. from '\r\n' or ';;') are dropped so a separator run does not
            # manufacture an "empty subcommand" rejection.
            piece = "".join(current).strip()
            if piece:
                parts.append(piece)
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


def validate_command(command: str, _depth: int = 0) -> tuple[bool, str | None]:
    """Validate a (possibly compound) WinDbg command string.

    Returns ``(True, None)`` if every subcommand is allowed, else
    ``(False, reason)`` for the first violation.

    ``_depth`` is the internal nesting level: validation recurses into
    ``{...}`` blocks and ``'...'`` subcommand bodies, and a crafted command
    can nest those arbitrarily (``{{{{...}}}}`` costs two characters per
    level, so a 4096-char command buys ~2000 levels -- far past CPython's
    frame limit). The cap turns a would-be RecursionError into a clean
    rejection. Callers never pass it.
    """
    if _depth > _MAX_VALIDATION_DEPTH:
        return False, (
            f"command nesting too deep (max {_MAX_VALIDATION_DEPTH} levels)"
        )

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
            ok, why = validate_command(inner, _depth + 1)
            if not ok:
                return False, f"in compound block: {why}"

        # Same treatment for single-quoted bodies (audit F-1). ``{...}`` is
        # not the only way WinDbg nests a subcommand: ``j`` (Execute If-Else)
        # and ``z`` (Execute While) delimit theirs with single quotes, and
        # parse_compound deliberately protects ``'`` regions so that a ``;``
        # inside a body does not split the command. The consequence was that
        # every byte between the quotes went unvalidated -- ``j 1 '$$><file'``
        # (arbitrary command-file execution -> .shell -> RCE on the analyst
        # host), ``j 1 'eb <kaddr> 90'``, ``j 1 '.dvalloc 1000'`` and
        # ``j 1 'a 401000'`` all reached the debugger. Denying ``j``/``z`` by
        # name is necessary but not sufficient: this recursion is the
        # structural fix, and it covers any other command (present or future)
        # that carries a quoted subcommand.
        for body in _extract_quoted_bodies(part):
            ok, why = validate_command(body, _depth + 1)
            if not ok:
                return False, f"in quoted subcommand: {why}"

    return True, None


def _extract_quoted_bodies(command: str) -> list[str]:
    """Return the bodies of the ``'...'`` regions in ``command``.

    Mirrors :func:`_extract_inner_block` but for single-quoted subcommand
    bodies. The scanning rules are kept deliberately identical to
    :func:`parse_compound` so that what this function hands to the validator
    is exactly what that function treated as an opaque protected region:

      - a ``'`` inside a double-quoted string is literal text, not a body
        opener (``.printf "it's fine"`` yields no bodies);
      - ``${x}`` interpolation is skipped wholesale;
      - a backslash escapes the following character.

    An *unterminated* body is returned to the caller rather than dropped.
    That case is not merely sloppy input: parse_compound stops splitting on
    ``;`` once a quote opens, so ``bp X 'foo ; .shell calc`` is a single
    subcommand whose first token is the harmless ``bp``. Validating the
    remainder keeps that path closed instead of failing open.
    """
    bodies: list[str] = []
    in_dq = False
    start = -1
    i = 0
    while i < len(command):
        ch = command[i]
        if ch == "\\" and i + 1 < len(command):
            i += 2
            continue
        if (
            not in_dq
            and start < 0
            and ch == "$"
            and i + 1 < len(command)
            and command[i + 1] == "{"
        ):
            j = command.find("}", i + 2)
            if j == -1:
                break
            i = j + 1
            continue
        if ch == '"' and start < 0:
            in_dq = not in_dq
        elif ch == "'" and not in_dq:
            if start < 0:
                start = i + 1
            else:
                body = command[start:i]
                if body.strip():
                    bodies.append(body)
                start = -1
        i += 1
    if start >= 0:
        tail = command[start:]
        if tail.strip():
            bodies.append(tail)
    return bodies


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
