"""
Find code that references the *base* of a table an address sits in.

Dispatch and function-pointer tables are indexed at runtime:

    lea  rcx, [rip + DispatchTable]     ; the only static reference
    mov  rax, [rcx + rdx*8]
    call rax

Nothing references ``DispatchTable + 0x40`` directly, so an xref lookup on a
slot address finds nothing and reads as "unreachable". This module scans
executable sections for references whose target lands at or just below the
address -- the table base -- and confirms each one by disassembly:

- x64: RIP-relative operands. The disp32 is relative to the next
  instruction, so it can't be byte-searched as a constant; candidates are
  found from ModRM bytes with ``mod=00, rm=101`` and then decoded.
- x86: absolute addresses as 32-bit immediates or displacements.

Pure file read with pefile + capstone; no Ghidra run.
"""

from __future__ import annotations

import logging
import re
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
_MACHINE_AMD64 = 0x8664
_MACHINE_I386 = 0x14C

# ModRM bytes with mod=00 and rm=101: RIP-relative in 64-bit mode.
_RIP_MODRM_RE = re.compile(rb"[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]")
# Longest prefix+opcode run before a ModRM byte worth trying to decode from:
# legacy prefixes, REX, and up to a 3-byte opcode (0F 38 xx / VEX).
_MAX_LEAD = 6
_MAX_INSN = 15


# Resolved on first use and cached: capstone is an optional dependency, so
# this cannot be a plain module constant, and _confirm's inner loop is no
# place for an import statement.
_X86_CONSTS: dict[str, int] | None = None


def _x86_consts() -> dict[str, int]:
    global _X86_CONSTS
    if _X86_CONSTS is None:
        import capstone
        from capstone import x86_const

        _X86_CONSTS = {
            "rip": x86_const.X86_REG_RIP,
            # Control-flow groups. A `call rel32` / `jmp rel32` carries its
            # ABSOLUTE destination in an IMM operand (capstone resolves the
            # displacement for us), so without this an ordinary direct branch
            # into the window is reported as a table-base reference.
            "jump": capstone.CS_GRP_JUMP,
            "call": capstone.CS_GRP_CALL,
            "ret": capstone.CS_GRP_RET,
            "iret": capstone.CS_GRP_IRET,
        }
    return _X86_CONSTS


def capstone_rip() -> int:
    return _x86_consts()["rip"]


def _executable_sections(pe):
    for section in pe.sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            data = section.get_data()
            if data:
                yield section.VirtualAddress, data


_LEGACY_PREFIXES = frozenset(b"\x26\x2e\x36\x3e\x64\x65\x66\x67\xf0\xf2\xf3")


def _is_rex(byte: int) -> bool:
    return 0x40 <= byte <= 0x4F


def _redundant_prefix(chunk: bytes, is_64: bool) -> bool:
    """Does this decode start on a prefix the CPU would ignore?

    Walking back from the ModRM byte, the longest decode can swallow the tail
    of the previous instruction (``push 0x48`` ends in a byte that reads as
    REX.W) and report the reference one byte early. A REX followed by another
    REX or by a legacy prefix is ignored, and a legacy prefix repeated
    back-to-back is redundant; compilers emit neither.
    """
    if len(chunk) < 2:
        return False
    first, second = chunk[0], chunk[1]
    if is_64 and _is_rex(first) and (_is_rex(second) or second in _LEGACY_PREFIXES):
        return True
    return first in _LEGACY_PREFIXES and first == second


def _confirm(md, data, start, section_va, image_base, lo, hi, is_64):
    """Decode at each plausible instruction start before ``start`` and return
    ``(insn_va, target, text)`` for an instruction that really references
    ``[lo, hi]``, or None.

    Longest lead first: every decode that reaches the same displacement
    resolves to the same target, and the shorter ones are the same
    instruction with its prefixes (REX, operand size) shaved off -- a
    ``lea rcx`` read one byte late is a ``lea ecx``.
    """
    consts = _x86_consts()
    rip = consts["rip"]
    control_flow = (consts["jump"], consts["call"], consts["ret"], consts["iret"])
    for lead in range(_MAX_LEAD, 0, -1):
        begin = start - lead
        if begin < 0:
            continue
        chunk = data[begin:begin + _MAX_INSN]
        if _redundant_prefix(chunk, is_64):
            continue
        insn = next(md.disasm(chunk, image_base + section_va + begin, count=1), None)
        if insn is None or insn.address + insn.size <= image_base + section_va + start:
            continue
        # A direct branch's IMM operand is its destination, not a data
        # reference, and reporting one under "the target is a slot in a table
        # these instructions reference" turns a control-flow edge into a
        # dispatch-table claim. Its MEM operands are still real references
        # (`call [rip + IatSlot]`), so only the IMM branch is suppressed.
        is_branch = any(g in control_flow for g in getattr(insn, "groups", ()))
        for op in getattr(insn, "operands", ()):
            target = None
            if op.type == 3:  # X86_OP_MEM
                if is_64 and op.mem.base == rip:
                    target = insn.address + insn.size + op.mem.disp
                elif not is_64 and op.mem.disp:
                    # [disp32] or [reg*scale + table] -- the classic 32-bit
                    # table index carries the table's absolute address.
                    target = op.mem.disp & 0xFFFFFFFF
            elif op.type == 2 and not is_64 and not is_branch:  # X86_OP_IMM
                target = op.imm & 0xFFFFFFFF
            if target is not None and lo <= target <= hi:
                return insn.address, target, f"{insn.mnemonic} {insn.op_str}".strip()
    return None


# One entry is every executable section of one binary held in memory, so the
# cache is deliberately tiny: a session works on one binary at a time, and a
# second slot covers a diff. Keyed on identity AND (mtime, size) so a rebuilt
# binary is never served from a stale parse.
_LAYOUT_CACHE_SIZE = 2
_layout_cache: dict[tuple, tuple | None] = {}


def _binary_key(binary_path: str | Path) -> tuple | None:
    try:
        st = Path(binary_path).stat()
    except OSError:
        return None
    return (str(binary_path), st.st_mtime_ns, st.st_size)


def _pe_layout(binary_path: str | Path, key: tuple):
    """``(is_64, image_base, ((section_va, data), ...))`` or None.

    Cached: this reads the whole file through pefile, and get_xrefs used to
    pay that on every call with a data address.
    """
    if key in _layout_cache:
        return _layout_cache[key]
    try:
        import pefile
    except ImportError:
        return None
    layout = None
    try:
        pe = pefile.PE(str(binary_path), fast_load=True)
    except Exception as e:
        logger.debug(f"table-base scan: not a PE ({e})")
    else:
        try:
            machine = pe.FILE_HEADER.Machine
            if machine in (_MACHINE_AMD64, _MACHINE_I386):
                layout = (
                    machine == _MACHINE_AMD64,
                    pe.OPTIONAL_HEADER.ImageBase,
                    tuple(_executable_sections(pe)),
                )
        except Exception as e:
            logger.debug(f"table-base scan: unusable headers ({e})")
        finally:
            pe.close()
    while len(_layout_cache) >= _LAYOUT_CACHE_SIZE:
        _layout_cache.pop(next(iter(_layout_cache)))
    _layout_cache[key] = layout
    return layout


_RESULT_CACHE_SIZE = 64
_result_cache: dict[tuple, list[dict]] = {}


def find_table_base_refs(
    binary_path: str | Path,
    target_va: int,
    window: int = 0x800,
    max_hits: int = 50,
) -> list[dict]:
    """References to any address in ``[target_va - window, target_va]``.

    Returns dicts with ``insn_address``, ``base``, ``offset`` (target minus
    base), ``instruction`` and ``pointer_size``, nearest base first. Empty on a non-PE, a
    non-x86 machine, or any parse failure -- this is a best-effort hint,
    never a reason to fail the xref lookup.

    The PE read and the per-query result are both cached, keyed on the file's
    (path, mtime, size): a caller walking a table asks about neighbouring
    slots, and each miss used to re-read the binary and re-walk every
    executable section.
    """
    try:
        import capstone
    except ImportError:
        return []

    key = _binary_key(binary_path)
    if key is None:
        return []
    result_key = (key, target_va, window, max_hits)
    cached = _result_cache.get(result_key)
    if cached is not None:
        return list(cached)

    layout = _pe_layout(binary_path, key)
    if layout is None:
        return []
    is_64, image_base, sections = layout

    try:
        md = capstone.Cs(
            capstone.CS_ARCH_X86,
            capstone.CS_MODE_64 if is_64 else capstone.CS_MODE_32,
        )
        md.detail = True
        lo, hi = max(0, target_va - window), target_va

        hits: dict[int, dict] = {}
        for section_va, data in sections:
            if is_64:
                candidates = _rip_candidates(data, section_va, image_base, lo, hi)
            else:
                candidates = _abs_candidates(data, lo, hi)
            for start in candidates:
                found = _confirm(md, data, start, section_va, image_base, lo, hi, is_64)
                if found is None:
                    continue
                insn_va, base, text = found
                hits.setdefault(insn_va, {
                    "insn_address": insn_va,
                    "base": base,
                    "offset": target_va - base,
                    "instruction": text,
                    "pointer_size": 8 if is_64 else 4,
                })
                if len(hits) >= max_hits:
                    break
            if len(hits) >= max_hits:
                break
        found = sorted(
            hits.values(), key=lambda h: (h["offset"], h["insn_address"])
        )
        while len(_result_cache) >= _RESULT_CACHE_SIZE:
            _result_cache.pop(next(iter(_result_cache)))
        _result_cache[result_key] = found
        return list(found)
    except Exception as e:
        logger.debug(f"table-base scan failed for {binary_path}: {e}")
        return []


def _rip_candidates(data, section_va, image_base, lo, hi):
    """Offsets of disp32 fields whose RIP-relative target could be in range.

    The next-instruction address depends on a trailing immediate we haven't
    decoded yet (0, 1, 2 or 4 bytes), so accept any of them here and let the
    disassembler decide.
    """
    limit = len(data) - 5
    base_va = image_base + section_va
    for m in _RIP_MODRM_RE.finditer(data):
        i = m.start()
        if i > limit:
            break
        disp = struct.unpack_from("<i", data, i + 1)[0]
        after_disp = base_va + i + 5
        for imm in (0, 1, 2, 4):
            if lo <= after_disp + imm + disp <= hi:
                yield i
                break


def _abs_candidates(data, lo, hi):
    """Offsets of 32-bit little-endian values in range (x86 absolute refs).

    Anchored on the value's high 16 bits, which a small window pins to one or
    two patterns, so a multi-MB section isn't walked byte by byte in Python.
    """
    found = set()
    for high in range(lo >> 16, (hi >> 16) + 1):
        needle = struct.pack("<H", high)
        j = data.find(needle, 2)
        while j != -1:
            i = j - 2
            if i + 4 <= len(data):
                value = struct.unpack_from("<I", data, i)[0]
                if lo <= value <= hi:
                    found.add(i)
            j = data.find(needle, j + 1)
    for i in sorted(found):
        # _confirm decodes from up to _MAX_LEAD bytes before its argument;
        # passing i+1 makes that search cover opcodes ending right at i.
        yield i + 1
