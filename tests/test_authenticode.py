"""Tests for Authenticode parser, hasher, and inspect_authenticode tool."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path

import pytest

from src.utils.authenticode import (
    _hash_pe_regions,
    _strip_win_certificate,
    compute_authentihash,
    inspect,
    parse_pkcs7,
    render_markdown,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_minimal_pe(
    *,
    security_va: int = 0,
    security_size: int = 0,
    cert_data: bytes = b"",
    file_size_pad: int | None = None,
) -> bytes:
    """
    Build a minimal valid PE32+ binary that pefile.PE() can parse.

    Layout (sizes are deliberately exact so offset math in tests is stable):
      DOS header (0x80 bytes), PE sig (4 bytes), File header (20 bytes),
      Optional header (PE32+ standard 112 bytes), DataDirectory (16*8=128 bytes),
      Section header (40 bytes). All padded to SizeOfHeaders=0x400, then a
      0x200-byte .text section, then optional cert data appended at security_va.
    """
    dos_size = 0x80
    dos = bytearray(dos_size)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, dos_size)

    pe_sig = b"PE\x00\x00"

    # IMAGE_FILE_HEADER (20 bytes)
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine = AMD64
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        240,  # SizeOfOptionalHeader = 112 (std PE32+) + 128 (16 directories)
        0x0022,  # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    # IMAGE_OPTIONAL_HEADER64 standard fields (112 bytes), CheckSum at offset 64
    opt_main = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,  # Magic = PE32+
        14,
        0,  # Linker Major/Minor
        0x200,  # SizeOfCode
        0,  # SizeOfInitializedData
        0,  # SizeOfUninitializedData
        0x1000,  # AddressOfEntryPoint
        0x1000,  # BaseOfCode
        0x140000000,  # ImageBase
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        6,
        0,  # OS Major/Minor
        0,
        0,  # Image Major/Minor
        6,
        0,  # Subsystem Major/Minor
        0,  # Win32VersionValue
        0x2000,  # SizeOfImage
        0x400,  # SizeOfHeaders
        0,  # CheckSum (offset 64 within OH)
        3,
        0,  # Subsystem (Console), DllCharacteristics
        0x100000,
        0x1000,  # StackReserve, StackCommit
        0x100000,
        0x1000,  # HeapReserve, HeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )

    # DataDirectory: 16 * 8 bytes
    data_dir = bytearray(16 * 8)
    if security_va or security_size:
        struct.pack_into("<II", data_dir, 4 * 8, security_va, security_size)

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,  # VirtualSize
        0x1000,  # VirtualAddress
        0x200,  # SizeOfRawData
        0x400,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x60000020,  # CODE | EXECUTE | READ
    )

    headers = bytes(dos) + pe_sig + file_header + opt_main + bytes(data_dir) + section
    headers = headers.ljust(0x400, b"\x00")
    body = b"\x90" * 0x200  # NOP sled
    pe_bytes = headers + body

    if cert_data:
        if security_va == 0:
            raise ValueError("cert_data requires non-zero security_va")
        if len(pe_bytes) < security_va:
            pe_bytes = pe_bytes.ljust(security_va, b"\x00")
        elif len(pe_bytes) > security_va:
            raise ValueError(
                f"security_va={security_va} but file already {len(pe_bytes)} bytes long"
            )
        pe_bytes += cert_data

    if file_size_pad is not None and len(pe_bytes) < file_size_pad:
        pe_bytes = pe_bytes.ljust(file_size_pad, b"\x00")

    return pe_bytes


def _checksum_offset_in_minimal_pe() -> int:
    """File offset of CheckSum in the minimal PE built by _build_minimal_pe."""
    # DOS(0x80) + "PE\0\0"(4) + FileHeader(20) + OH offset of CheckSum = 64
    return 0x80 + 4 + 20 + 64


def _security_dd_entry_offset_in_minimal_pe() -> int:
    """File offset of DATA_DIRECTORY[4] (Security) in the minimal PE."""
    # DOS(0x80) + "PE\0\0"(4) + FileHeader(20) + OH std fields(112) + 4*8
    return 0x80 + 4 + 20 + 112 + 4 * 8


# ---------------------------------------------------------------------------
# Hash region math: the off-by-one safety net
# ---------------------------------------------------------------------------


class TestHashRegions:
    """Direct tests of _hash_pe_regions on synthetic byte buffers."""

    def test_unsigned_skips_only_checksum_and_dd_entry(self):
        # 256-byte buffer; checksum at 100, DD entry at 200, no cert table
        data = bytearray(256)
        for i in range(256):
            data[i] = i & 0xFF

        h1 = _hash_pe_regions(
            bytes(data),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )

        # Mutate inside checksum field [100:104] -> hash unchanged
        d2 = bytearray(data)
        d2[101] ^= 0xFF
        h2 = _hash_pe_regions(
            bytes(d2),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )
        assert h1 == h2, "mutation inside checksum field must not change hash"

        # Mutate inside skipped DD entry [200:208] -> hash unchanged
        d3 = bytearray(data)
        d3[205] ^= 0xFF
        h3 = _hash_pe_regions(
            bytes(d3),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )
        assert h1 == h3, "mutation inside security DD entry must not change hash"

        # Mutate at byte 50 (pre-checksum, hashed region) -> hash MUST change
        d4 = bytearray(data)
        d4[50] ^= 0xFF
        h4 = _hash_pe_regions(
            bytes(d4),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )
        assert h1 != h4, "mutation in hashed region must change hash"

        # Mutate at byte 250 (post-DD-entry, hashed-to-EOF region) -> changes
        d5 = bytearray(data)
        d5[250] ^= 0xFF
        h5 = _hash_pe_regions(
            bytes(d5),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )
        assert h1 != h5

    def test_signed_skips_cert_table(self):
        # 512-byte buffer; checksum at 100, DD entry at 200, cert at 400, size 64
        data = bytearray(512)
        for i in range(512):
            data[i] = i & 0xFF

        h1 = _hash_pe_regions(
            bytes(data),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=400,
            cert_size=64,
            digest="sha256",
        )

        # Mutate inside cert table [400:464] -> hash unchanged
        d2 = bytearray(data)
        d2[420] ^= 0xFF
        h2 = _hash_pe_regions(
            bytes(d2),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=400,
            cert_size=64,
            digest="sha256",
        )
        assert h1 == h2, "mutation inside cert table must not change Authentihash"

        # Mutate immediately before cert table (hashed region) -> changes
        d3 = bytearray(data)
        d3[399] ^= 0xFF
        h3 = _hash_pe_regions(
            bytes(d3),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=400,
            cert_size=64,
            digest="sha256",
        )
        assert h1 != h3

        # Mutate immediately after cert table (hashed-to-EOF) -> changes
        d4 = bytearray(data)
        d4[464] ^= 0xFF
        h4 = _hash_pe_regions(
            bytes(d4),
            checksum_offset=100,
            security_dir_entry_offset=200,
            cert_offset=400,
            cert_size=64,
            digest="sha256",
        )
        assert h1 != h4

    def test_oob_offsets_raise(self):
        data = b"\x00" * 100
        with pytest.raises(ValueError):
            _hash_pe_regions(
                data,
                checksum_offset=200,
                security_dir_entry_offset=210,
                cert_offset=0,
                cert_size=0,
                digest="sha256",
            )
        with pytest.raises(ValueError):
            _hash_pe_regions(
                data,
                checksum_offset=10,
                security_dir_entry_offset=12,  # before checksum+4
                cert_offset=0,
                cert_size=0,
                digest="sha256",
            )


# ---------------------------------------------------------------------------
# WIN_CERTIFICATE header parsing
# ---------------------------------------------------------------------------


class TestStripWinCertificate:
    def test_valid_pkcs7_header(self):
        payload = b"\x30\x82\x00\x10" + b"\x00" * 12  # 16-byte fake PKCS#7
        hdr = struct.pack("<IHH", 8 + len(payload), 0x0200, 0x0002)
        result = _strip_win_certificate(hdr + payload)
        assert result is not None
        cert_type, body = result
        assert cert_type == 0x0002
        assert body == payload

    def test_too_short(self):
        assert _strip_win_certificate(b"\x00\x00") is None

    def test_dwlength_past_end(self):
        hdr = struct.pack("<IHH", 999_999, 0x0200, 0x0002)
        assert _strip_win_certificate(hdr + b"\x00" * 4) is None


# ---------------------------------------------------------------------------
# Integration: minimal unsigned PE through inspect()
# ---------------------------------------------------------------------------


class TestInspectUnsigned:
    def test_unsigned_minimal_pe(self, tmp_path: Path):
        pe_bytes = _build_minimal_pe(security_va=0, security_size=0)
        pe_file = tmp_path / "unsigned.exe"
        pe_file.write_bytes(pe_bytes)

        result = inspect(pe_file)
        assert result["signed"] is False
        assert "no security" in result["reason"].lower()

        md = render_markdown(result)
        assert "Signed: no" in md

    def test_unsigned_compute_authentihash_matches_manual(self, tmp_path: Path):
        """compute_authentihash() on a real pefile.PE matches our manual region hash."""
        import pefile

        pe_bytes = _build_minimal_pe(security_va=0, security_size=0)
        pe_file = tmp_path / "unsigned.exe"
        pe_file.write_bytes(pe_bytes)

        pe = pefile.PE(str(pe_file), fast_load=True)
        try:
            via_pe = compute_authentihash(pe, digest="sha256")
        finally:
            pe.close()

        manual = _hash_pe_regions(
            pe_bytes,
            checksum_offset=_checksum_offset_in_minimal_pe(),
            security_dir_entry_offset=_security_dd_entry_offset_in_minimal_pe(),
            cert_offset=0,
            cert_size=0,
            digest="sha256",
        )
        assert via_pe == manual

        # Direct verification: hash-without-skipped-regions matches a
        # hand-rolled "skip checksum, skip DD entry" compute.
        cs_off = _checksum_offset_in_minimal_pe()
        dd_off = _security_dd_entry_offset_in_minimal_pe()
        h = hashlib.sha256()
        h.update(pe_bytes[:cs_off])
        h.update(pe_bytes[cs_off + 4 : dd_off])
        h.update(pe_bytes[dd_off + 8 :])
        assert manual == h.digest()


class TestInspectMalformedSignature:
    def test_unparseable_cert_blob(self, tmp_path: Path):
        """A WIN_CERTIFICATE with garbage PKCS#7 should report parsed=False, not raise."""
        # 16-byte cert body (after 8-byte header) of pure garbage.
        bad = struct.pack("<IHH", 24, 0x0200, 0x0002) + b"\xff" * 16
        pe_bytes = _build_minimal_pe(
            security_va=0x800,
            security_size=len(bad),
            cert_data=bad,
        )
        pe_file = tmp_path / "bad-sig.exe"
        pe_file.write_bytes(pe_bytes)

        result = inspect(pe_file)
        assert result["signed"] is True
        assert result["parsed"] is False
        md = render_markdown(result)
        assert "Signed: yes (signature present, but not parseable)" in md

    def test_non_pkcs7_cert_type(self, tmp_path: Path):
        """wCertificateType != 0x0002 -> parsed=False."""
        body = b"\x00" * 16
        # type 0x0001 = WIN_CERT_TYPE_X509 (not PKCS#7)
        bad = struct.pack("<IHH", 8 + len(body), 0x0200, 0x0001) + body
        pe_bytes = _build_minimal_pe(
            security_va=0x800,
            security_size=len(bad),
            cert_data=bad,
        )
        pe_file = tmp_path / "x509-cert.exe"
        pe_file.write_bytes(pe_bytes)

        result = inspect(pe_file)
        assert result["signed"] is True
        assert result["parsed"] is False


# ---------------------------------------------------------------------------
# Bad input handling
# ---------------------------------------------------------------------------


class TestInspectErrors:
    def test_not_a_pe_file(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        not_pe = tmp_path / "not-a-pe.bin"
        not_pe.write_bytes(b"this is plain text, not a PE")
        with pytest.raises(StructuredBaseError) as excinfo:
            inspect(not_pe)
        assert "Not a valid PE file" in str(excinfo.value)

    def test_missing_file(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        with pytest.raises(StructuredBaseError):
            inspect(tmp_path / "does-not-exist.exe")


# ---------------------------------------------------------------------------
# Signed-PE round-trip (gated on env var; skipped without a fixture)
# ---------------------------------------------------------------------------


def _signed_fixture_path() -> Path | None:
    p = os.environ.get("BINARY_MCP_SIGNED_PE_FIXTURE")
    if not p:
        return None
    candidate = Path(p)
    return candidate if candidate.is_file() else None


@pytest.mark.skipif(
    _signed_fixture_path() is None,
    reason=(
        "Set BINARY_MCP_SIGNED_PE_FIXTURE=/path/to/signed.exe to enable the "
        "Authenticode round-trip test (e.g. signtool-signed binary or "
        r"C:\Windows\System32\notepad.exe)."
    ),
)
class TestSignedPERoundTrip:
    def test_authentihash_matches_embedded(self):
        try:
            import asn1crypto  # noqa: F401
        except ImportError:
            pytest.skip("asn1crypto not installed")

        path = _signed_fixture_path()
        assert path is not None
        result = inspect(path)
        assert result["signed"] is True
        assert result["parsed"] is True, f"failed to parse: {result.get('reason')}"
        ah = result["authentihash"]
        assert ah["computed_hex"] == ah["embedded_hex"]
        assert ah["match"] is True
        assert ah["tampered"] is False

        sig = result["signature"]
        assert sig["signer_cn"], "signer CN should be populated"
        assert sig["chain"], "issuer chain should be populated"

    def test_tampered_pe_detected(self, tmp_path: Path):
        try:
            import asn1crypto  # noqa: F401
        except ImportError:
            pytest.skip("asn1crypto not installed")

        path = _signed_fixture_path()
        assert path is not None
        original = path.read_bytes()

        # Flip one byte well inside the .text section (offset 0x1000 in our
        # minimal PE, but on real Windows binaries SizeOfHeaders is typically
        # 0x400 too). We pick offset 0x800 -- past headers, before any cert
        # table.
        target = 0x800
        if target >= len(original):
            pytest.skip("fixture too small to safely tamper")
        tampered = bytearray(original)
        tampered[target] ^= 0x55

        tampered_path = tmp_path / "tampered.exe"
        tampered_path.write_bytes(bytes(tampered))

        result = inspect(tampered_path)
        if not (result.get("signed") and result.get("parsed")):
            pytest.skip(
                "tampering corrupted PE structure beyond signature parse; "
                "use a different offset"
            )
        ah = result["authentihash"]
        assert ah["match"] is False
        assert ah["tampered"] is True


# ---------------------------------------------------------------------------
# Tool wrapper integration (only the markdown surface, not MCP plumbing)
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_render_unsigned(self):
        md = render_markdown(
            {
                "binary_path": "/tmp/foo.exe",
                "signed": False,
                "reason": "no security data directory present",
            }
        )
        assert "Signed: no" in md
        assert "no security" in md.lower()

    def test_render_unparseable(self):
        md = render_markdown(
            {
                "binary_path": "/tmp/foo.exe",
                "signed": True,
                "parsed": False,
                "reason": "garbage",
                "cert_offset": 0x1000,
                "cert_size": 256,
            }
        )
        assert "not parseable" in md
        assert "0x1000" in md


def test_parse_pkcs7_returns_none_for_garbage():
    """Top-level parse_pkcs7 must not crash on malformed input."""
    assert parse_pkcs7(b"") is None
    assert parse_pkcs7(b"\x00" * 7) is None
    # Valid WIN_CERTIFICATE header, garbage PKCS#7 body
    bad = struct.pack("<IHH", 24, 0x0200, 0x0002) + b"\xff" * 16
    assert parse_pkcs7(bad) is None
