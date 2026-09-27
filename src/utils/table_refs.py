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


def capstone_rip() -> int:
    from capstone import x86_const

    return x86_const.X86_REG_RIP


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
        for op in getattr(insn, "operands", ()):
            target = None
            if op.type == 3:  # X86_OP_MEM
                if is_64 and op.mem.base == capstone_rip():
                    target = insn.address + insn.size + op.mem.disp
                elif not is_64 and op.mem.disp:
                    # [disp32] or [reg*scale + table] -- the classic 32-bit
                    # table index carries the table's absolute address.
                    target = op.mem.disp & 0xFFFFFFFF
            elif op.type == 2 and not is_64:  # X86_OP_IMM
                target = op.imm & 0xFFFFFFFF
            if target is not None and lo <= target <= hi:
                return insn.address, target, f"{insn.mnemonic} {insn.op_str}".strip()
    return None


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
    """
    try:
        import capstone
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(str(binary_path), fast_load=True)
    except Exception as e:
        logger.debug(f"table-base scan: not a PE ({e})")
        return []

    try:
        machine = pe.FILE_HEADER.Machine
        if machine == _MACHINE_AMD64:
            is_64 = True
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif machine == _MACHINE_I386:
            is_64 = False
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            return []
        md.detail = True
        image_base = pe.OPTIONAL_HEADER.ImageBase
        lo, hi = max(0, target_va - window), target_va

        hits: dict[int, dict] = {}
        for section_va, data in _executable_sections(pe):
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
        return sorted(hits.values(), key=lambda h: (h["offset"], h["insn_address"]))
    except Exception as e:
        logger.debug(f"table-base scan failed for {binary_path}: {e}")
        return []
    finally:
        pe.close()


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
