"""Tests for triage_tools detection functions."""

import struct

import pytest

from src.tools.triage_tools import detect_file_type, detect_packer


def _make_pe_header(machine: int = 0x14C, characteristics: int = 0, dotnet_marker: bytes = b"") -> bytes:
    """Build a minimal PE binary with optional .NET marker."""
    pe_offset = 0x80
    # DOS header: MZ + padding + PE offset at 0x3C
    dos = bytearray(pe_offset)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_offset)
    # PE signature + COFF header (machine + padding to characteristics)
    pe_sig = b"PE\x00\x00"
    coff = bytearray(20)
    struct.pack_into("<H", coff, 0, machine)  # Machine
    struct.pack_into("<H", coff, 18, characteristics)  # Characteristics
    data = bytes(dos) + pe_sig + bytes(coff) + dotnet_marker
    # Pad to at least 4096 bytes so header_bytes slice works
    return data.ljust(4096, b"\x00")


class TestDetectFileType:
    """Tests for detect_file_type."""

    def test_pe32_detection(self):
        data = _make_pe_header(machine=0x14C)
        result = detect_file_type(data)
        assert result["type"] == "pe"
        assert result["architecture"] == "x86"
        assert result["is_executable"] is True

    def test_pe64_detection(self):
        data = _make_pe_header(machine=0x8664)
        result = detect_file_type(data)
        assert result["type"] == "pe"
        assert result["architecture"] == "x64"

    def test_pe_dll_detection(self):
        data = _make_pe_header(machine=0x14C, characteristics=0x2000)
        result = detect_file_type(data)
        assert "DLL" in result["description"]

    def test_dotnet_detected_via_corexemain(self):
        """Bug 1: .NET assembly with _CorExeMain must be detected as dotnet, not pe."""
        data = _make_pe_header(machine=0x14C, dotnet_marker=b"_CorExeMain")
        result = detect_file_type(data)
        assert result["type"] == "dotnet"
        assert result["description"] == ".NET assembly"
        assert result["is_executable"] is True

    def test_dotnet_detected_via_mscoree(self):
        """Bug 1: .NET assembly with mscoree.dll must be detected as dotnet."""
        data = _make_pe_header(machine=0x8664, dotnet_marker=b"mscoree.dll")
        result = detect_file_type(data)
        assert result["type"] == "dotnet"

    def test_plain_pe_not_dotnet(self):
        """Plain PE without .NET markers should remain type 'pe'."""
        data = _make_pe_header(machine=0x14C)
        result = detect_file_type(data)
        assert result["type"] == "pe"

    def test_ole_document(self):
        """Bug 2: OLE file without MSI markers should be classified as 'ole'."""
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        data = ole_magic + b"\x00" * 4088  # pad to 4096
        result = detect_file_type(data)
        assert result["type"] == "ole"
        assert "OLE" in result["description"]
        assert result["is_executable"] is False

    def test_msi_installer(self):
        """Bug 2: OLE file WITH MSI markers should be classified as 'msi'."""
        ole_magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        msi_marker = b"\x00M\x00S\x00I"
        data = ole_magic + b"\x00" * 100 + msi_marker + b"\x00" * 3000
        result = detect_file_type(data)
        assert result["type"] == "msi"
        assert result["is_executable"] is True

    def test_elf32_detection(self):
        data = b"\x7fELF\x01" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "elf"
        assert result["architecture"] == "x86"

    def test_elf64_detection(self):
        data = b"\x7fELF\x02" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "elf"
        assert result["architecture"] == "x64"

    def test_macho_detection(self):
        data = b"\xfe\xed\xfa\xce" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "macho"

    def test_zip_detection(self):
        data = b"PK\x03\x04" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "zip"

    def test_pdf_detection(self):
        data = b"%PDF-1.7" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "pdf"

    def test_unknown_type(self):
        data = b"\x00\x00\x00\x00" + b"\x00" * 100
        result = detect_file_type(data)
        assert result["type"] == "unknown"

    def test_too_short(self):
        result = detect_file_type(b"\x00\x00")
        assert result["type"] == "unknown"


class TestDetectPacker:
    """Tests for detect_packer."""

    def test_upx_in_header(self):
        """Packer signature in first 64KB should be detected."""
        data = b"\x00" * 100 + b"UPX!" + b"\x00" * 1000
        result = detect_packer(data)
        assert len(result) == 1
        assert result[0]["name"] == "upx"

    def test_signature_beyond_64kb_not_detected(self):
        """Bug 3: Signatures beyond 64KB should NOT be detected."""
        data = b"\x00" * 70000 + b"UPX!" + b"\x00" * 1000
        result = detect_packer(data)
        assert len(result) == 0

    def test_multiple_packers(self):
        data = b"UPX!" + b"\x00" * 100 + b"VMProtect" + b"\x00" * 1000
        result = detect_packer(data)
        names = {p["name"] for p in result}
        assert "upx" in names
        assert "vmprotect" in names

    def test_case_insensitive_matching(self):
        data = b"\x00" * 50 + b"upx!" + b"\x00" * 1000
        result = detect_packer(data)
        assert len(result) == 1
        assert result[0]["name"] == "upx"

    def test_no_packers(self):
        data = b"\x00" * 1000
        result = detect_packer(data)
        assert result == []

    def test_confidence_increases_with_matches(self):
        """Multiple matching signatures should increase confidence."""
        data = b"UPX!" + b"\x00" * 10 + b"UPX0" + b"\x00" * 10 + b"UPX1" + b"\x00" * 1000
        result = detect_packer(data)
        assert len(result) == 1
        assert result[0]["confidence"] > 0.5
