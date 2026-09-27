"""
Tests for src/utils/table_refs.py and its use in get_xrefs.

A dispatch-table slot is indexed at runtime, so the only static reference
is to the table's base. These build tiny PEs whose code references a table
base and check that a lookup on a *slot* finds that instruction.
"""

from __future__ import annotations

import struct
import sys

import pytest

from src.utils.table_refs import find_table_base_refs

_FILE_ALIGN = 0x200
_SECTION_ALIGN = 0x1000
_TEXT_RVA = 0x1000
_DATA_RVA = 0x2000


def _build_pe(code: bytes, *, is_64: bool, image_base: int) -> bytes:
    """Minimal PE with an executable .text (``code``) and an empty .rdata."""
    text_raw = (len(code) + _FILE_ALIGN - 1) // _FILE_ALIGN * _FILE_ALIGN or _FILE_ALIGN
    data_raw = _FILE_ALIGN
    text_off = 0x400
    data_off = text_off + text_raw
    size_of_image = _DATA_RVA + _SECTION_ALIGN

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    if is_64:
        opt = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 0, text_raw, data_raw, 0, _TEXT_RVA, _TEXT_RVA,
            image_base, _SECTION_ALIGN, _FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x400, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        machine, opt_size = 0x8664, 112 + 128
    else:
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 0, text_raw, data_raw, 0, _TEXT_RVA, _TEXT_RVA, _DATA_RVA,
            image_base, _SECTION_ALIGN, _FILE_ALIGN, 6, 0, 0, 0, 6, 0, 0,
            size_of_image, 0x400, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )
        machine, opt_size = 0x14C, 96 + 128
    file_header = struct.pack("<HHIIIHH", machine, 2, 0, 0, 0, opt_size, 0x0102)
    text = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", text_raw, _TEXT_RVA, text_raw,
                       text_off, 0, 0, 0, 0, 0x60000020)
    rdata = struct.pack("<8sIIIIIIHHI", b".rdata\0\0", data_raw, _DATA_RVA, data_raw,
                        data_off, 0, 0, 0, 0, 0x40000040)
    headers = (bytes(dos) + b"PE\0\0" + file_header + opt + bytes(16 * 8) + text + rdata)
    headers = headers.ljust(0x400, b"\0")
    return headers + code.ljust(text_raw, b"\xcc") + bytes(data_raw)


X64_BASE = 0x140000000
X64_TABLE = X64_BASE + _DATA_RVA


def _x64_code():
    code = bytearray(b"\x90" * 0x10)
    # 0x140001010: lea rcx, [rip + table]   48 8D 0D disp32
    insn_va = X64_BASE + _TEXT_RVA + len(code)
    code += b"\x48\x8d\x0d" + struct.pack("<i", X64_TABLE - (insn_va + 7))
    code += b"\x48\x8b\x04\xd1"  # mov rax, [rcx + rdx*8]
    code += b"\xff\xd0"          # call rax
    # cmp dword ptr [rip + table+0x10], 5  -- a trailing imm8 moves the
    # RIP base past the displacement; the candidate filter must allow it.
    cmp_va = X64_BASE + _TEXT_RVA + len(code)
    code += b"\x83\x3d" + struct.pack("<i", (X64_TABLE + 0x10) - (cmp_va + 7)) + b"\x05"
    # Decoy: RIP-relative lea far away from the table.
    decoy_va = X64_BASE + _TEXT_RVA + len(code)
    code += b"\x48\x8d\x15" + struct.pack("<i", (X64_TABLE + 0x5000) - (decoy_va + 7))
    code += b"\xc3"
    return bytes(code), insn_va, cmp_va


def test_x64_slot_lookup_finds_the_base_reference(tmp_path):
    code, lea_va, cmp_va = _x64_code()
    binary = tmp_path / "drv.sys"
    binary.write_bytes(_build_pe(code, is_64=True, image_base=X64_BASE))

    hits = find_table_base_refs(binary, X64_TABLE + 0x40)

    by_insn = {h["insn_address"]: h for h in hits}
    assert set(by_insn) == {lea_va, cmp_va}
    lea = by_insn[lea_va]
    assert lea["base"] == X64_TABLE and lea["offset"] == 0x40
    assert lea["instruction"].startswith("lea rcx")
    assert lea["pointer_size"] == 8
    assert by_insn[cmp_va]["offset"] == 0x30
    # Nearest base first.
    assert hits[0]["insn_address"] == cmp_va


def test_x64_window_bounds_the_search(tmp_path):
    code, _, _ = _x64_code()
    binary = tmp_path / "drv.sys"
    binary.write_bytes(_build_pe(code, is_64=True, image_base=X64_BASE))
    assert find_table_base_refs(binary, X64_TABLE + 0x900, window=0x800) == []


def test_x64_does_not_swallow_the_previous_instructions_tail(tmp_path):
    # push 0x48 ends in 0x48, which also reads as REX.W in front of the lea.
    code = bytearray(b"\x90" * 0x10 + b"\x6a\x48")
    insn_va = X64_BASE + _TEXT_RVA + len(code)
    code += b"\x48\x8d\x0d" + struct.pack("<i", X64_TABLE - (insn_va + 7)) + b"\xc3"
    binary = tmp_path / "drv.sys"
    binary.write_bytes(_build_pe(bytes(code), is_64=True, image_base=X64_BASE))

    hits = find_table_base_refs(binary, X64_TABLE)

    assert [h["insn_address"] for h in hits] == [insn_va]
    assert hits[0]["instruction"].startswith("lea rcx")


X86_BASE = 0x400000
X86_TABLE = X86_BASE + _DATA_RVA


def test_x86_indexed_table_reference(tmp_path):
    code = bytearray(b"\x90" * 8)
    insn_va = X86_BASE + _TEXT_RVA + len(code)
    code += b"\xff\x24\x8d" + struct.pack("<I", X86_TABLE)  # jmp [ecx*4 + table]
    code += b"\xc3"
    binary = tmp_path / "x.exe"
    binary.write_bytes(_build_pe(bytes(code), is_64=False, image_base=X86_BASE))

    hits = find_table_base_refs(binary, X86_TABLE + 0x10)

    assert len(hits) == 1
    assert hits[0]["insn_address"] == insn_va
    assert hits[0]["offset"] == 0x10 and hits[0]["pointer_size"] == 4


def test_not_a_pe_returns_nothing(tmp_path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"\x7fELF" + b"\0" * 256)
    assert find_table_base_refs(junk, 0x1000) == []
    assert find_table_base_refs(tmp_path / "missing.bin", 0x1000) == []


# get_xrefs wiring


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod

    yield server_mod
    sys.modules.pop("src.server", None)


def _xrefs(server_module):
    fn = server_module.get_xrefs
    return getattr(fn, "fn", fn)


def test_get_xrefs_reports_the_table_base_and_its_function(tmp_path, monkeypatch, server_module):
    code, lea_va, _ = _x64_code()
    binary = tmp_path / "drv.sys"
    binary.write_bytes(_build_pe(code, is_64=True, image_base=X64_BASE))
    dispatcher = {
        "name": "DispatchIoctl",
        "address": f"{X64_BASE + _TEXT_RVA:x}",
        "size": len(code),
        "basic_blocks": [],
        "called_functions": [],
        "pseudocode": "",
    }
    context = {"metadata": {"name": "drv.sys"}, "functions": [dispatcher], "strings": []}
    monkeypatch.setattr(server_module, "get_analysis_context", lambda *a, **k: context)

    out = _xrefs(server_module)(str(binary), address=f"0x{X64_TABLE + 0x40:x}")

    assert "Table-base references" in out
    assert f"0x{lea_va:x}" in out
    assert "in DispatchIoctl" in out
    assert "slot 8 of 8-byte entries" in out


def test_get_xrefs_table_scan_can_be_disabled(tmp_path, monkeypatch, server_module):
    code, _, _ = _x64_code()
    binary = tmp_path / "drv.sys"
    binary.write_bytes(_build_pe(code, is_64=True, image_base=X64_BASE))
    context = {"metadata": {"name": "drv.sys"}, "functions": [], "strings": []}
    monkeypatch.setattr(server_module, "get_analysis_context", lambda *a, **k: context)

    out = _xrefs(server_module)(str(binary), address=f"0x{X64_TABLE + 0x40:x}", table_window=0)

    assert "Table-base references" not in out
    assert "No xrefs found" in out
