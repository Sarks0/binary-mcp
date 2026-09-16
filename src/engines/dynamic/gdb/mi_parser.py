"""
Parser for GDB/MI (machine interface) output records.

GDB speaks MI when launched as ``gdb --interpreter=mi2``. Its output is a
line-oriented grammar, not JSON and not free text::

    ^done,bkpt={number="1",addr="0x00000000004011d4",thread-groups=["i1"]}
    *stopped,reason="breakpoint-hit",frame={addr="0x...",args=[]},thread-id="1"
    ~"Breakpoint 1, target (x=1) at t.c:4\\n"
    (gdb)

This module turns one such line into an :class:`MIRecord`. It is deliberately
pure -- no subprocess, no I/O, no GDB required -- so the whole grammar is
testable on any platform, including the Windows and macOS CI runners where no
debugger is installed.

Two properties of MI drive the design:

**Values are recursive.** A value is a C string, a tuple ``{...}`` of
``name=value`` results, or a list ``[...]`` of either bare values or results.
Lists of *results* may repeat a name -- ``-data-disassemble`` in source mode
emits ``asm_insns=[src_and_asm_line={...},src_and_asm_line={...}]`` -- so a
flat dict would silently drop rows. See :func:`parse_value` for how each shape
is represented.

**Strings are C strings, not UTF-8 text.** GDB escapes non-printable bytes as
octal, so a UTF-8 path arrives as ``\\303\\251`` rather than as characters.
Escapes are therefore decoded into a byte buffer and the buffer is decoded as
UTF-8 once at the end; decoding escape-by-escape would mangle every multi-byte
character in a sample's filename.

A note for callers, learned the hard way against GDB 15.1: a ``^done`` result
class means *the command was accepted*, not *the operation happened*.
``-break-delete *0x401776`` answers ``^done`` and leaves the breakpoint armed.
Anything in the bridge that changes debuggee state must read the state back
rather than trust the result class.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Result classes GDB can attach to a "^" record.
RESULT_CLASSES = frozenset({"done", "running", "connected", "error", "exit"})

# Single-character C escapes. Values are the byte each escape produces.
_SIMPLE_ESCAPES = {
    "a": 0x07,
    "b": 0x08,
    "e": 0x1B,  # GNU extension, emitted by some GDB builds
    "f": 0x0C,
    "n": 0x0A,
    "r": 0x0D,
    "t": 0x09,
    "v": 0x0B,
    "\\": 0x5C,
    '"': 0x22,
    "'": 0x27,
    "?": 0x3F,
}

_OCTAL_DIGITS = "01234567"
_HEX_DIGITS = "0123456789abcdefABCDEF"


class MIParseError(ValueError):
    """Raised when a line looks like a structured MI record but does not parse.

    A line with an unrecognised leading character is *not* an error -- GDB
    interleaves plain text (inferior output, confirmation prompts) with MI, and
    that is reported as :attr:`RecordKind.RAW` instead.
    """


class RecordKind(str, Enum):
    """The kind of MI record a line represents."""

    RESULT = "result"      # ^done, ^error, ^running, ...
    EXEC = "exec"          # *stopped, *running
    STATUS = "status"      # +download progress
    NOTIFY = "notify"      # =library-loaded, =breakpoint-modified, ...
    CONSOLE = "console"    # ~"..."  console stream
    TARGET = "target"      # @"..."  inferior stream
    LOG = "log"            # &"..."  debugger log stream
    PROMPT = "prompt"      # (gdb)
    RAW = "raw"            # anything else GDB printed


_ASYNC_PREFIXES = {
    "*": RecordKind.EXEC,
    "+": RecordKind.STATUS,
    "=": RecordKind.NOTIFY,
}

_STREAM_PREFIXES = {
    "~": RecordKind.CONSOLE,
    "@": RecordKind.TARGET,
    "&": RecordKind.LOG,
}


@dataclass(frozen=True)
class MIRecord:
    """One parsed MI output record."""

    kind: RecordKind
    raw: str
    token: int | None = None
    klass: str | None = None
    results: dict[str, Any] = field(default_factory=dict)
    text: str | None = None

    @property
    def is_async(self) -> bool:
        """True for out-of-band records that arrive without being asked for."""
        return self.kind in (RecordKind.EXEC, RecordKind.STATUS, RecordKind.NOTIFY)

    @property
    def is_stream(self) -> bool:
        """True for the three free-text stream records."""
        return self.kind in (RecordKind.CONSOLE, RecordKind.TARGET, RecordKind.LOG)

    @property
    def is_error(self) -> bool:
        """True for ``^error``."""
        return self.kind is RecordKind.RESULT and self.klass == "error"

    @property
    def error_message(self) -> str | None:
        """The ``msg`` field of a ``^error`` record, if present."""
        if not self.is_error:
            return None
        msg = self.results.get("msg")
        return msg if isinstance(msg, str) else None


def parse_line(line: str) -> MIRecord:
    """Parse a single line of GDB/MI output.

    Args:
        line: One line as read from GDB's stdout, with or without its newline.

    Returns:
        The parsed record. Lines GDB emits that are not MI at all (inferior
        output, ``Kill the program being debugged?`` prompts) come back as
        :attr:`RecordKind.RAW` with the text preserved.

    Raises:
        MIParseError: The line starts as a structured record but its payload is
            malformed -- a truncated read or a parser bug, either of which the
            session layer should surface rather than swallow.
    """
    stripped = line.rstrip("\r\n")
    body = stripped.strip()

    if not body:
        return MIRecord(kind=RecordKind.RAW, raw=stripped, text="")

    if body == "(gdb)":
        return MIRecord(kind=RecordKind.PROMPT, raw=stripped)

    # A leading token is an arbitrary-length decimal echoed back on the reply,
    # and is how a reply is matched to the command that asked for it.
    idx = 0
    while idx < len(body) and body[idx].isdigit():
        idx += 1
    token = int(body[:idx]) if idx else None
    rest = body[idx:]

    if not rest:
        # Digits and nothing else -- not a record.
        return MIRecord(kind=RecordKind.RAW, raw=stripped, text=body)

    prefix, payload = rest[0], rest[1:]

    if prefix in _STREAM_PREFIXES:
        text, consumed = _parse_c_string(payload, 0)
        if consumed != len(payload.rstrip()):
            raise MIParseError(f"trailing data after stream string: {stripped!r}")
        return MIRecord(kind=_STREAM_PREFIXES[prefix], raw=stripped, token=token, text=text)

    if prefix == "^":
        kind = RecordKind.RESULT
    elif prefix in _ASYNC_PREFIXES:
        kind = _ASYNC_PREFIXES[prefix]
    else:
        return MIRecord(kind=RecordKind.RAW, raw=stripped, text=body)

    klass, results = _parse_class_and_results(payload, stripped)

    if kind is RecordKind.RESULT and klass not in RESULT_CLASSES:
        raise MIParseError(f"unknown result class {klass!r} in: {stripped!r}")

    return MIRecord(kind=kind, raw=stripped, token=token, klass=klass, results=results)


def parse_lines(text: str) -> list[MIRecord]:
    """Parse a block of MI output into records, one per line."""
    return [parse_line(line) for line in text.splitlines()]


def parse_value(text: str) -> Any:
    """Parse a single MI value (const, tuple, or list) from a complete string.

    Representation:

    - ``"str"`` -> :class:`str`
    - ``{a="1",b="2"}`` -> ``{"a": "1", "b": "2"}``
    - ``[ "1","2" ]`` (list of values) -> ``["1", "2"]``
    - ``[a="1",a="2"]`` (list of results) -> ``[{"a": "1"}, {"a": "2"}]``

    A list of results keeps one single-key dict per element rather than merging
    into one dict, because MI repeats names in exactly the places where losing
    the repeats would lose rows.
    """
    value, consumed = _parse_value(text, 0)
    if text[consumed:].strip():
        raise MIParseError(f"trailing data after value: {text!r}")
    return value


def _parse_class_and_results(payload: str, raw: str) -> tuple[str, dict[str, Any]]:
    """Split ``done,a="1",b="2"`` into its class and its result dict."""
    end = payload.find(",")
    if end == -1:
        klass = payload.strip()
        if not klass:
            raise MIParseError(f"record has no class: {raw!r}")
        return klass, {}

    klass = payload[:end].strip()
    if not klass:
        raise MIParseError(f"record has no class: {raw!r}")

    results: dict[str, Any] = {}
    pos = end + 1
    while True:
        name, value, pos = _parse_result(payload, pos)
        _accumulate(results, name, value)
        pos = _skip_ws(payload, pos)
        if pos >= len(payload):
            break
        if payload[pos] != ",":
            raise MIParseError(f"expected ',' at offset {pos} in: {raw!r}")
        pos += 1
    return klass, results


def _accumulate(results: dict[str, Any], name: str, value: Any) -> None:
    """Add ``name=value``, folding a repeated name into a list.

    Top-level repeats are rare but real (``-break-insert`` on a symbol with
    several locations). Overwriting would silently drop all but the last.
    """
    if name not in results:
        results[name] = value
        return
    existing = results[name]
    if isinstance(existing, _RepeatedList):
        existing.append(value)
        return
    results[name] = _RepeatedList([existing, value])


class _RepeatedList(list):
    """Marker list produced when one name appears more than once in a record."""


def _skip_ws(text: str, pos: int) -> int:
    while pos < len(text) and text[pos] in " \t":
        pos += 1
    return pos


def _parse_result(text: str, pos: int) -> tuple[str, Any, int]:
    """Parse ``name=value`` starting at *pos*."""
    pos = _skip_ws(text, pos)
    eq = pos
    while eq < len(text) and text[eq] not in "=,{}[]":
        eq += 1
    if eq >= len(text) or text[eq] != "=":
        raise MIParseError(f"expected 'name=' at offset {pos} in: {text!r}")
    name = text[pos:eq].strip()
    if not name:
        raise MIParseError(f"empty result name at offset {pos} in: {text!r}")
    value, consumed = _parse_value(text, eq + 1)
    return name, value, consumed


def _parse_value(text: str, pos: int) -> tuple[Any, int]:
    pos = _skip_ws(text, pos)
    if pos >= len(text):
        raise MIParseError(f"expected a value at offset {pos} in: {text!r}")
    ch = text[pos]
    if ch == '"':
        return _parse_c_string(text, pos)
    if ch == "{":
        return _parse_tuple(text, pos)
    if ch == "[":
        return _parse_list(text, pos)
    raise MIParseError(f"unexpected {ch!r} at offset {pos} in: {text!r}")


def _parse_tuple(text: str, pos: int) -> tuple[dict[str, Any], int]:
    pos += 1  # consume '{'
    out: dict[str, Any] = {}
    pos = _skip_ws(text, pos)
    if pos < len(text) and text[pos] == "}":
        return out, pos + 1
    while True:
        name, value, pos = _parse_result(text, pos)
        _accumulate(out, name, value)
        pos = _skip_ws(text, pos)
        if pos >= len(text):
            raise MIParseError(f"unterminated tuple in: {text!r}")
        if text[pos] == ",":
            pos += 1
            continue
        if text[pos] == "}":
            return out, pos + 1
        raise MIParseError(f"expected ',' or '}}' at offset {pos} in: {text!r}")


def _parse_list(text: str, pos: int) -> tuple[list[Any], int]:
    pos += 1  # consume '['
    out: list[Any] = []
    pos = _skip_ws(text, pos)
    if pos < len(text) and text[pos] == "]":
        return out, pos + 1
    while True:
        pos = _skip_ws(text, pos)
        if _looks_like_result(text, pos):
            name, value, pos = _parse_result(text, pos)
            out.append({name: value})
        else:
            value, pos = _parse_value(text, pos)
            out.append(value)
        pos = _skip_ws(text, pos)
        if pos >= len(text):
            raise MIParseError(f"unterminated list in: {text!r}")
        if text[pos] == ",":
            pos += 1
            continue
        if text[pos] == "]":
            return out, pos + 1
        raise MIParseError(f"expected ',' or ']' at offset {pos} in: {text!r}")


def _looks_like_result(text: str, pos: int) -> bool:
    """Decide whether a list element is ``name=value`` or a bare value.

    Scans for an ``=`` before any delimiter. A quoted string can contain '='
    (``value="a=b"``), so a leading quote settles it as a bare value first.
    """
    if pos < len(text) and text[pos] in '"{[':
        return False
    scan = pos
    while scan < len(text) and text[scan] not in "=,{}[]":
        scan += 1
    return scan < len(text) and text[scan] == "="


def _parse_c_string(text: str, pos: int) -> tuple[str, int]:
    """Parse a quoted MI C string starting at *pos*, returning (value, next)."""
    if pos >= len(text) or text[pos] != '"':
        raise MIParseError(f"expected '\"' at offset {pos} in: {text!r}")
    pos += 1
    buf = bytearray()
    while pos < len(text):
        ch = text[pos]
        if ch == '"':
            return buf.decode("utf-8", errors="replace"), pos + 1
        if ch != "\\":
            buf.extend(ch.encode("utf-8"))
            pos += 1
            continue

        pos += 1
        if pos >= len(text):
            raise MIParseError(f"string ends in a backslash: {text!r}")
        esc = text[pos]
        if esc in _SIMPLE_ESCAPES:
            buf.append(_SIMPLE_ESCAPES[esc])
            pos += 1
        elif esc in _OCTAL_DIGITS:
            digits = ""
            while pos < len(text) and len(digits) < 3 and text[pos] in _OCTAL_DIGITS:
                digits += text[pos]
                pos += 1
            buf.append(int(digits, 8) & 0xFF)
        elif esc in "xX":
            pos += 1
            digits = ""
            while pos < len(text) and len(digits) < 2 and text[pos] in _HEX_DIGITS:
                digits += text[pos]
                pos += 1
            if not digits:
                raise MIParseError(f"\\x with no hex digits in: {text!r}")
            buf.append(int(digits, 16))
        else:
            # Unknown escape: C says undefined, GDB means the literal character.
            buf.extend(esc.encode("utf-8"))
            pos += 1
    raise MIParseError(f"unterminated string in: {text!r}")
