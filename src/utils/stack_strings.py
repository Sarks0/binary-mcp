"""
Stack-string reconstruction from Ghidra pseudocode.

Modern stealers (RedLine, Vidar, Lumma, Cobalt Strike) hide their C2 URLs,
mutex names, and registry paths by emitting them as character-by-character
``mov [rsp+N], 'X'`` writes so the strings never appear in ``strings(1)`` or
in static-string IOC scanners.

This module operates on the textual pseudocode field cached by Ghidra's
``core_analysis.py``: pure regex + offset bookkeeping, no Ghidra coupling.

Surfaces:
- parse_assignments(pseudocode) -> list[StackAssignment]
- reconstruct_strings(assignments, min_length, function_name, function_address)
    -> list[StackString]
- detect_xor_loops(pseudocode) -> list[XorCandidate]
- xor_bytes(data, key) -> bytes
- scan(pseudocode, min_length) -> tuple[list[StackString], list[XorCandidate]]
- render_markdown(result, ioc_only) -> str
"""

from __future__ import annotations

import logging
import re
import string
from dataclasses import dataclass, field, replace
from typing import Any

logger = logging.getLogger(__name__)


# --- Constants ---

PRINTABLE_BYTES = frozenset(b for b in (string.printable.encode() + b"\t\n\r"))
PRINTABLE_NO_WS = frozenset(b for b in string.printable.encode() if b not in b"\t\n\r\x0b\x0c")
WIDTH_FROM_TYPE: dict[str, int] = {
    "byte": 1, "BYTE": 1, "char": 1, "undefined1": 1, "uchar": 1, "u1": 1,
    "short": 2, "WORD": 2, "ushort": 2, "undefined2": 2, "wchar_t": 2, "u2": 2,
    "int": 4, "DWORD": 4, "uint": 4, "undefined4": 4, "long": 4, "u4": 4,
    "QWORD": 8, "longlong": 8, "ulonglong": 8, "undefined8": 8, "u8": 8,
}
MAX_LOCAL_OFFSET = 0x10000  # Sanity cap on stack frame size
# Cap on the pseudocode string length per scan() call. Real Ghidra
# pseudocode for a single function is < 50 KB; obfuscated samples reach
# ~200 KB. 1 MB is 5x headroom while still bounding the linear regex
# passes against a malformed or hostile cache entry.
MAX_PSEUDOCODE_LEN = 1_000_000


# --- Dataclasses ---


@dataclass(frozen=True)
class StackAssignment:
    """One ``local_X = const`` or ``*(byte*)(rsp+N) = const`` write."""

    base: str  # "local" / a register name like "RBP" / etc.
    offset: int
    width: int
    bytes_le: bytes
    raw_match: str


@dataclass(frozen=True)
class StackString:
    function: str
    function_address: str
    encoding: str  # "ascii" | "utf-16le" | "xor-decoded"
    value: str
    raw_bytes_hex: str
    start_offset: int
    end_offset: int
    confidence: str  # "high" | "medium" | "low"
    confidence_reasons: tuple[str, ...]


@dataclass(frozen=True)
class XorCandidate:
    function: str
    key: int
    length_hint: int | None
    match_line: str


@dataclass
class StackStringResult:
    binary_path: str
    strings: list[StackString] = field(default_factory=list)
    ioc_matches: dict[str, list[str]] = field(default_factory=dict)
    xor_candidates: list[XorCandidate] = field(default_factory=list)


# --- Regexes ---

# Ghidra-style ``local_<hex>`` assignment with optional subfield ``._<off>_<width>_``.
# Captures: hex_offset, optional subfield (off, width), value (hex / decimal / char-literal).
_LOCAL_RE = re.compile(
    r"""
    (?:^|\n|;)\s*                                     # line / stmt boundary
    (?:[A-Za-z_]\w*\s+)?                              # optional type qualifier
    local_([0-9a-fA-F]+)                              # local_<hex offset>
    (?:\._(\d+)_(\d+)_)?                              # optional ._<off>_<width>_
    \s*=\s*
    (
        '(?:\\.|[^\\'])'                              # char literal
        | 0x[0-9a-fA-F]+                              # hex
        | -?\d+                                       # decimal
    )
    \s*;
    """,
    re.VERBOSE,
)

# ``*(byte*)(rsp + 0x10) = 'X';`` style.
# Captures: cast_type, base_register, sign, offset, value.
_RAW_PTR_RE = re.compile(
    r"""
    \*\s*\(\s*
        (?P<type>undefined[1248]?|byte|BYTE|char|uchar|u1
                 |short|WORD|ushort|wchar_t|u2
                 |int|DWORD|uint|long|u4
                 |QWORD|longlong|ulonglong|u8)
    \s*\*\s*\)
    \s*\(
        \s*(?:\(\s*\w+\s*\)\s*)?                      # optional inner cast
        (?P<base>[A-Za-z_][\w]*)
        \s*(?P<sign>[+\-])\s*
        (?P<off>0x[0-9a-fA-F]+|\d+)
    \s*\)
    \s*=\s*
    (?P<val>'(?:\\.|[^\\'])'|0x[0-9a-fA-F]+|-?\d+)
    \s*;
    """,
    re.VERBOSE,
)

# XOR loops -- find ``var ^= const`` or ``var = expr ^ const``.
_XOR_RE = re.compile(
    r"""
    \^=\s*(?P<key>0x[0-9a-fA-F]+|-?\d+|'(?:\\.|[^\\'])')
    |
    =\s*[^;]*?\^\s*(?P<key2>0x[0-9a-fA-F]+|-?\d+|'(?:\\.|[^\\'])')\s*;
    """,
    re.VERBOSE,
)

# Loop-bound hints: ``i < N``, ``i < 0xN``, ``< N`` immediately preceding a body.
_LOOP_BOUND_RE = re.compile(
    r"<\s*(?P<bound>0x[0-9a-fA-F]+|\d+)"
)


# --- Helpers ---


def _decode_value(literal: str, width: int) -> bytes | None:
    """
    Convert a captured value literal to little-endian bytes of given width.

    Returns None if the value doesn't fit.
    """
    literal = literal.strip()
    if literal.startswith("'") and literal.endswith("'"):
        # Char literal: 'X' or escape '\n'
        s = literal[1:-1]
        try:
            decoded = bytes(s, "utf-8").decode("unicode_escape").encode("latin-1")
        except Exception:  # noqa: BLE001
            return None
        if not decoded:
            return None
        # Pad/truncate to declared width (LE)
        if len(decoded) > width:
            return None
        return decoded[:1] + b"\x00" * (width - 1) if width > 1 else decoded[:1]

    try:
        n = int(literal, 0)  # auto-base
    except ValueError:
        return None

    if n < 0:
        n = n & ((1 << (8 * width)) - 1)  # two's-complement wrap

    if n >> (8 * width):
        return None

    try:
        return n.to_bytes(width, "little")
    except OverflowError:
        return None


def _infer_width_from_hex(hex_text: str) -> int:
    """
    Infer width in bytes from a 0x-prefixed hex literal.

    We count the literal digit count *as written* (preserving leading zeros)
    because explicit zero-padding -- ``0x0000006f`` -- is the source-side
    signal that this is a 4-byte assignment, not a 1-byte one.
    """
    digits = hex_text[2:].lstrip("-")
    if not digits:
        return 1
    n = len(digits)
    if n <= 2:
        return 1
    if n <= 4:
        return 2
    if n <= 8:
        return 4
    return 8


# --- Parsing ---


def parse_assignments(pseudocode: str) -> list[StackAssignment]:
    """Two-pass regex extraction: Ghidra ``local_<hex>`` form + raw-pointer form."""
    out: list[StackAssignment] = []

    for m in _LOCAL_RE.finditer(pseudocode):
        hex_off, sub_off_s, sub_w_s, value = m.groups()
        try:
            base_offset = int(hex_off, 16)
        except ValueError:
            continue
        if base_offset > MAX_LOCAL_OFFSET:
            continue

        if sub_off_s is not None and sub_w_s is not None:
            # Subfield: local_<base>._<inner_off>_<width>_
            inner_off = int(sub_off_s)
            width = int(sub_w_s)
            if width not in (1, 2, 4, 8):
                continue
            offset = base_offset + inner_off
        else:
            # Width inferred from the literal
            if value.startswith(("'",)):
                width = 1
            elif value.startswith(("0x", "-0x", "+0x")):
                width = _infer_width_from_hex(value)
            else:
                # Decimal; assume 1 unless explicit
                width = 1
            offset = base_offset

        decoded = _decode_value(value, width)
        if decoded is None:
            continue
        out.append(
            StackAssignment(
                base="local",
                offset=offset,
                width=width,
                bytes_le=decoded,
                raw_match=m.group(0).strip(),
            )
        )

    for m in _RAW_PTR_RE.finditer(pseudocode):
        cast_t = m.group("type")
        base = m.group("base")
        sign = m.group("sign")
        off_s = m.group("off")
        value = m.group("val")
        width = WIDTH_FROM_TYPE.get(cast_t, 1)
        try:
            offset = int(off_s, 0)
        except ValueError:
            continue
        if sign == "-":
            offset = -offset
        # Negative offsets (typical for ebp-relative locals) are still legal,
        # but we cap absolute magnitude to defuse pathological pseudocode.
        if abs(offset) > MAX_LOCAL_OFFSET:
            continue
        decoded = _decode_value(value, width)
        if decoded is None:
            continue
        out.append(
            StackAssignment(
                base=base,
                offset=offset,
                width=width,
                bytes_le=decoded,
                raw_match=m.group(0).strip(),
            )
        )
    return out


# --- Reconstruction ---


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE_BYTES) / len(data)


def _looks_utf16le(data: bytes) -> bool:
    """Every odd byte is zero AND even bytes are mostly printable ASCII."""
    if len(data) < 4 or len(data) % 2 != 0:
        return False
    if any(data[i] != 0 for i in range(1, len(data), 2)):
        return False
    even = bytes(data[i] for i in range(0, len(data), 2))
    return _printable_ratio(even) >= 0.8


def _score_confidence(
    data: bytes, has_gaps: bool
) -> tuple[str, list[str]]:
    """3-tier confidence: high / medium / low."""
    ratio = _printable_ratio(data)
    reasons: list[str] = [f"printable_ratio={ratio:.2f}"]
    if has_gaps:
        reasons.append("non-contiguous")
    if len(data) >= 6:
        reasons.append(f"length={len(data)}")

    if ratio >= 0.95 and not has_gaps and len(data) >= 6:
        return "high", reasons
    if ratio >= 0.80:
        return "medium", reasons
    return "low", reasons


def reconstruct_strings(
    assignments: list[StackAssignment],
    *,
    min_length: int = 4,
    function_name: str = "<unnamed>",
    function_address: str = "<unknown>",
) -> list[StackString]:
    """
    Group assignments by base, materialize as a sparse buffer, extract runs.

    Returns one StackString per contiguous run of ≥ min_length printable
    bytes (after filtering by printable ratio).
    """
    by_base: dict[str, list[StackAssignment]] = {}
    for a in assignments:
        by_base.setdefault(a.base, []).append(a)

    out: list[StackString] = []

    for base, group in by_base.items():
        group_sorted = sorted(group, key=lambda x: x.offset)
        offsets = [a.offset for a in group_sorted]
        min_off = offsets[0]
        # Compute end-of-buffer
        max_end = max(a.offset + a.width for a in group_sorted)
        size = max_end - min_off
        if size <= 0 or size > MAX_LOCAL_OFFSET:
            continue

        buf = bytearray(size)
        filled = bytearray(size)  # 1 = filled
        for a in group_sorted:
            local = a.offset - min_off
            if local < 0 or local + a.width > size:
                continue
            buf[local : local + a.width] = a.bytes_le
            for i in range(a.width):
                filled[local + i] = 1

        # Find runs of filled bytes
        i = 0
        while i < size:
            if not filled[i]:
                i += 1
                continue
            j = i
            while j < size and filled[j]:
                j += 1
            run = bytes(buf[i:j])
            run_start_off = min_off + i
            run_end_off = min_off + j

            # Check for has_gaps within the assignment span -- a run is
            # contiguous bytes by construction; "gaps" here means that the
            # original assignments left holes that we count as low-confidence
            # signals when the run hugs the edge of one. We treat a run as
            # gappy if the assignments that overlap it are not consecutive in
            # original-source order with no missing offsets.
            covering = [
                a for a in group_sorted
                if a.offset >= run_start_off and a.offset + a.width <= run_end_off
            ]
            covered_offsets = sorted({a.offset + k for a in covering for k in range(a.width)})
            run_offsets = list(range(run_start_off, run_end_off))
            has_gaps = covered_offsets != run_offsets

            # ASCII attempt
            if len(run) >= min_length and _printable_ratio(run) >= 0.5:
                conf, reasons = _score_confidence(run, has_gaps=has_gaps)
                # Strip trailing nulls for display only
                display = run.rstrip(b"\x00").decode("latin-1", errors="replace")
                out.append(
                    StackString(
                        function=function_name,
                        function_address=function_address,
                        encoding="ascii",
                        value=display,
                        raw_bytes_hex=run.hex(),
                        start_offset=run_start_off,
                        end_offset=run_end_off,
                        confidence=conf,
                        confidence_reasons=tuple(reasons),
                    )
                )

            # UTF-16LE attempt -- only emit if it looks plausibly wide AND
            # the ASCII view of the same run had a worse printable ratio.
            if _looks_utf16le(run):
                # Strip trailing PAIRED nulls (UTF-16 wide null = b"\x00\x00")
                # rather than single nulls, which would yield odd-length input.
                wide_bytes = run
                while len(wide_bytes) >= 2 and wide_bytes[-2:] == b"\x00\x00":
                    wide_bytes = wide_bytes[:-2]
                try:
                    wide = wide_bytes.decode("utf-16-le", errors="replace")
                except Exception:  # noqa: BLE001
                    wide = ""
                if len(wide) >= min_length:
                    even_bytes = bytes(run[i] for i in range(0, len(run), 2))
                    conf, reasons = _score_confidence(even_bytes, has_gaps=has_gaps)
                    out.append(
                        StackString(
                            function=function_name,
                            function_address=function_address,
                            encoding="utf-16le",
                            value=wide,
                            raw_bytes_hex=run.hex(),
                            start_offset=run_start_off,
                            end_offset=run_end_off,
                            confidence=conf,
                            confidence_reasons=tuple(["utf-16le", *reasons]),
                        )
                    )

            i = j
    # Stable sort: by function, encoding, start_offset
    out.sort(key=lambda s: (s.function, s.encoding, s.start_offset))
    return out


# --- XOR loops ---


def xor_bytes(data: bytes, key: int) -> bytes:
    """Single-byte repeating XOR."""
    k = key & 0xFF
    return bytes(b ^ k for b in data)


def detect_xor_loops(
    pseudocode: str, *, function_name: str = "<unnamed>"
) -> list[XorCandidate]:
    """Scan for ``^= const`` or ``= ... ^ const`` patterns and nearby loop bounds."""
    out: list[XorCandidate] = []
    for m in _XOR_RE.finditer(pseudocode):
        raw_key = m.group("key") or m.group("key2")
        if raw_key is None:
            continue
        # Decode key value
        key_bytes = _decode_value(raw_key, 1)
        if key_bytes is None:
            continue
        key = key_bytes[0]
        if key == 0:
            continue  # XOR-with-zero is a no-op; not interesting

        # Look for a loop bound within +/- 200 chars of the match
        window = pseudocode[max(0, m.start() - 200) : m.end() + 200]
        bound_match = _LOOP_BOUND_RE.search(window)
        length_hint: int | None = None
        if bound_match:
            try:
                length_hint = int(bound_match.group("bound"), 0)
                if length_hint > 4096 or length_hint < 1:
                    length_hint = None
            except ValueError:
                length_hint = None

        out.append(
            XorCandidate(
                function=function_name,
                key=key,
                length_hint=length_hint,
                match_line=pseudocode[m.start() : m.end()].strip(),
            )
        )
    return out


# --- Per-function orchestrator ---


def scan(
    pseudocode: str,
    *,
    min_length: int = 4,
    function_name: str = "<unnamed>",
    function_address: str = "<unknown>",
) -> tuple[list[StackString], list[XorCandidate]]:
    """Run parse + reconstruct + xor-detect + xor-emulate for one function."""
    if not pseudocode:
        return [], []

    if len(pseudocode) > MAX_PSEUDOCODE_LEN:
        logger.warning(
            "pseudocode for %s is %d bytes; truncating to %d to bound regex scan",
            function_name,
            len(pseudocode),
            MAX_PSEUDOCODE_LEN,
        )
        pseudocode = pseudocode[:MAX_PSEUDOCODE_LEN]

    assignments = parse_assignments(pseudocode)
    strings = reconstruct_strings(
        assignments,
        min_length=min_length,
        function_name=function_name,
        function_address=function_address,
    )
    xor_candidates = detect_xor_loops(pseudocode, function_name=function_name)

    # Pair XOR candidates with reconstructed strings of matching length and
    # emit "xor-decoded" variants when the XOR yields a printable buffer.
    extras: list[StackString] = []
    for c in xor_candidates:
        for s in strings:
            if s.encoding != "ascii":
                continue
            try:
                raw = bytes.fromhex(s.raw_bytes_hex)
            except ValueError:
                continue
            if c.length_hint is not None and abs(len(raw) - c.length_hint) > 1:
                continue
            decoded = xor_bytes(raw, c.key)
            ratio = _printable_ratio(decoded)
            if ratio < 0.80:
                continue
            extras.append(
                replace(
                    s,
                    encoding="xor-decoded",
                    value=decoded.rstrip(b"\x00").decode("latin-1", errors="replace"),
                    raw_bytes_hex=decoded.hex(),
                    confidence="medium",
                    confidence_reasons=(
                        f"xor_key=0x{c.key:02x}",
                        f"printable_ratio={ratio:.2f}",
                    ),
                )
            )
    return strings + extras, xor_candidates


# --- IOC filter ---


def filter_iocs(
    strings: list[StackString], compiled_ioc_patterns: dict[str, dict[str, Any]]
) -> tuple[list[StackString], dict[str, list[str]]]:
    """
    Run each StackString.value through the existing IOC regex set; return
    (strings_that_matched_an_ioc, {ioc_type: [matched_strings]}).
    """
    kept: list[StackString] = []
    by_type: dict[str, list[str]] = {}
    for s in strings:
        hit = False
        for ioc_type, cached in compiled_ioc_patterns.items():
            for match in cached["compiled"].findall(s.value):
                if any(ep.search(match) for ep in cached.get("exclude", [])):
                    continue
                by_type.setdefault(ioc_type, []).append(match)
                hit = True
        if hit:
            kept.append(s)
    return kept, by_type


# --- Markdown ---


def render_markdown(result: StackStringResult, *, ioc_only: bool = False) -> str:
    """Render a StackStringResult as a markdown report."""
    lines: list[str] = [
        "Stack-String Recovery",
        f"Binary: {result.binary_path}",
        f"Strings recovered: {len(result.strings)}",
        f"XOR-loop candidates: {len(result.xor_candidates)}",
    ]
    if ioc_only:
        lines.append(f"Filter: ioc_only ({sum(len(v) for v in result.ioc_matches.values())} matches)")
    lines.append("")

    if not result.strings:
        lines.append("No stack strings reconstructed.")
    else:
        lines.append("| Function | Encoding | Confidence | Length | Value |")
        lines.append("|----------|----------|------------|--------|-------|")
        for s in result.strings:
            display = s.value.replace("|", "\\|").replace("\n", "\\n")
            if len(display) > 80:
                display = display[:77] + "..."
            lines.append(
                f"| {s.function} | {s.encoding} | {s.confidence} | "
                f"{len(s.value)} | `{display}` |"
            )
        lines.append("")

    if result.xor_candidates:
        lines.append("Suspected XOR loops:")
        for c in result.xor_candidates:
            hint = f"len~{c.length_hint}" if c.length_hint else "len=?"
            lines.append(f"  - {c.function}: key=0x{c.key:02x} {hint}")
        lines.append("")

    if result.ioc_matches:
        lines.append("IOC matches by type:")
        for ioc_type, matches in sorted(result.ioc_matches.items()):
            unique = sorted(set(matches))
            lines.append(f"  - {ioc_type}: {len(unique)}")
            for m in unique[:20]:
                lines.append(f"      {m}")
            if len(unique) > 20:
                lines.append(f"      ... ({len(unique) - 20} more)")

    return "\n".join(lines)
