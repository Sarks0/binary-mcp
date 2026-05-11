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

    def test_pkcs7_size_cap_rejects_oversized_cert_table(self, tmp_path: Path):
        """A security data-directory entry advertising > 16 MB is rejected
        before the cert blob ever reaches asn1crypto."""
        from src.utils.authenticode import MAX_PKCS7_BYTES
        from src.utils.structured_errors import StructuredBaseError

        # The DD entry claims a 17 MB cert table, but we don't actually
        # write 17 MB of bytes -- the size cap fires before we get to
        # the "extends past EOF" check.
        oversized = MAX_PKCS7_BYTES + 1
        pe_bytes = _build_minimal_pe(
            security_va=0x800,
            security_size=oversized,
        )
        pe_file = tmp_path / "huge-sig.exe"
        pe_file.write_bytes(pe_bytes)

        with pytest.raises(StructuredBaseError) as excinfo:
            inspect(pe_file)
        msg = str(excinfo.value).lower()
        assert "too large" in msg or "exceeds" in msg
        assert str(oversized) in str(excinfo.value)


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


# ---------------------------------------------------------------------------
# Tri-state digest-extraction (parsed / missing / parse_error)
# ---------------------------------------------------------------------------


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_seq(body: bytes) -> bytes:
    return _der_tlv(0x30, body)


def _der_set(body: bytes) -> bytes:
    return _der_tlv(0x31, body)


def _der_oid(oid_str: str) -> bytes:
    parts = [int(p) for p in oid_str.split(".")]
    first = 40 * parts[0] + parts[1]
    out = bytes([first])
    for p in parts[2:]:
        chunks = []
        while True:
            chunks.insert(0, p & 0x7F)
            p >>= 7
            if not p:
                break
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        out += bytes(chunks)
    return _der_tlv(0x06, out)


def _der_integer(n: int) -> bytes:
    if n == 0:
        return _der_tlv(0x02, b"\x00")
    bs: list[int] = []
    while n:
        bs.insert(0, n & 0xFF)
        n >>= 8
    if bs[0] & 0x80:
        bs.insert(0, 0)
    return _der_tlv(0x02, bytes(bs))


def _der_explicit(tag_num: int, body: bytes) -> bytes:
    return bytes([0xA0 | tag_num]) + _der_len(len(body)) + body


def _der_null() -> bytes:
    return b"\x05\x00"


def _der_octet(b: bytes) -> bytes:
    return _der_tlv(0x04, b)


def _build_signed_data_blob(
    *, encap_content_type_oid: str, encap_content_payload: bytes
) -> bytes:
    """
    Build a minimal CMS SignedData ContentInfo carrying the given
    encap_content_type OID and a [0] EXPLICIT-tagged inner payload.

    Just enough to satisfy parse_pkcs7's "have at least one SignerInfo" check.
    """
    sha256_oid = "2.16.840.1.101.3.4.2.1"
    digest_algo = _der_seq(_der_oid(sha256_oid) + _der_null())
    issuer_name = _der_seq(
        _der_set(_der_seq(_der_oid("2.5.4.3") + _der_tlv(0x13, b"test")))
    )
    issuer_and_sn = _der_seq(issuer_name + _der_integer(1))
    signer_info = _der_seq(
        _der_integer(1)  # version
        + issuer_and_sn
        + digest_algo
        + _der_seq(_der_oid("1.2.840.113549.1.1.1") + _der_null())  # rsa
        + _der_octet(b"\x00" * 4)  # signature
    )
    encap = _der_seq(
        _der_oid(encap_content_type_oid)
        + _der_explicit(0, encap_content_payload)
    )
    sd = _der_seq(
        _der_integer(1)  # SignedData version = v1
        + _der_set(digest_algo)
        + encap
        + _der_set(signer_info)
    )
    return _der_seq(_der_oid("1.2.840.113549.1.7.2") + _der_explicit(0, sd))


def _wrap_win_certificate(pkcs7_blob: bytes) -> bytes:
    return struct.pack("<IHH", 8 + len(pkcs7_blob), 0x0200, 0x0002) + pkcs7_blob


class TestDigestStatusTriState:
    """parse_pkcs7 must distinguish missing vs malformed vs parsed signatures."""

    def test_parse_error_on_malformed_inner(self):
        """
        SpcIndirectDataContent OID present but inner ASN.1 is malformed.
        Must yield digest_status='parse_error' and an empty embedded digest,
        NOT silently fall through to a tampered=False clean bill of health.
        """
        # Encap OID is SpcIndirectDataContent, payload is garbage (just an OID,
        # missing the required DigestInfo field of SpcIndirectDataContent).
        spc_indirect_garbage = _der_seq(_der_seq(_der_oid("1.3.6.1.4.1.311.2.1.15")))
        blob = _build_signed_data_blob(
            encap_content_type_oid="1.3.6.1.4.1.311.2.1.4",
            encap_content_payload=spc_indirect_garbage,
        )
        result = parse_pkcs7(_wrap_win_certificate(blob))
        assert result is not None
        assert result.digest_status == "parse_error"
        assert result.embedded_message_digest == b""

    def test_missing_on_non_spc_indirect_content_type(self):
        """
        encap_content_type is not Authenticode SpcIndirectDataContent.
        Must yield digest_status='missing' (no embedded digest to compare),
        NOT 'parse_error'.
        """
        # Use plain CMS 'data' OID for encap content_type.
        blob = _build_signed_data_blob(
            encap_content_type_oid="1.2.840.113549.1.7.1",  # pkcs7-data
            encap_content_payload=_der_octet(b"\x00" * 4),
        )
        result = parse_pkcs7(_wrap_win_certificate(blob))
        assert result is not None
        assert result.digest_status == "missing"
        assert result.embedded_message_digest == b""


class TestInspectTamperedSemantics:
    """
    The whole point of `tampered`: a deliberately malformed signature must
    NOT report tampered=False.
    """

    def test_malformed_signature_reports_parse_error_and_tampered_true(
        self, tmp_path: Path
    ):
        """
        Embed a CMS SignedData with SpcIndirectDataContent OID but malformed
        inner DigestInfo in a real PE, then inspect() it. The bug being fixed:
        previously tampered=False, defeating the tool's purpose. Now must be
        signature_digest_status='parse_error' and tampered=True.
        """
        spc_indirect_garbage = _der_seq(_der_seq(_der_oid("1.3.6.1.4.1.311.2.1.15")))
        pkcs7 = _build_signed_data_blob(
            encap_content_type_oid="1.3.6.1.4.1.311.2.1.4",
            encap_content_payload=spc_indirect_garbage,
        )
        cert_blob = _wrap_win_certificate(pkcs7)
        pe_bytes = _build_minimal_pe(
            security_va=0x800,
            security_size=len(cert_blob),
            cert_data=cert_blob,
        )
        pe_file = tmp_path / "malformed-spc.exe"
        pe_file.write_bytes(pe_bytes)

        result = inspect(pe_file)
        assert result["signed"] is True
        assert result["parsed"] is True
        assert result["signature_digest_status"] == "parse_error"
        ah = result["authentihash"]
        assert ah["match"] is False
        assert ah["tampered"] is True, (
            "malformed SpcIndirectDataContent must be flagged as tampered, "
            "not silently passed (this regression is the original bug)"
        )

    def test_unsigned_pe_is_not_tampered(self, tmp_path: Path):
        """A PE with no signature at all must not be reported as tampered."""
        pe_bytes = _build_minimal_pe(security_va=0, security_size=0)
        pe_file = tmp_path / "unsigned.exe"
        pe_file.write_bytes(pe_bytes)
        result = inspect(pe_file)
        # Unsigned path doesn't reach authentihash comparison; just ensure
        # the result is explicitly "signed=False" and there's no false-positive.
        assert result["signed"] is False
        assert "authentihash" not in result

    def test_non_spc_indirect_encap_reports_missing_not_tampered(
        self, tmp_path: Path
    ):
        """
        A WIN_CERTIFICATE that holds a valid CMS SignedData but whose encap
        content_type is NOT Authenticode SpcIndirectDataContent has no
        embedded Authentihash to compare. Must be signature_digest_status=
        'missing' and tampered=False (not 'parse_error', not 'tampered').
        """
        pkcs7 = _build_signed_data_blob(
            encap_content_type_oid="1.2.840.113549.1.7.1",  # pkcs7-data
            encap_content_payload=_der_octet(b"\x00" * 4),
        )
        cert_blob = _wrap_win_certificate(pkcs7)
        pe_bytes = _build_minimal_pe(
            security_va=0x800,
            security_size=len(cert_blob),
            cert_data=cert_blob,
        )
        pe_file = tmp_path / "no-spc.exe"
        pe_file.write_bytes(pe_bytes)

        result = inspect(pe_file)
        assert result["signed"] is True
        assert result["parsed"] is True
        assert result["signature_digest_status"] == "missing"
        ah = result["authentihash"]
        assert ah["match"] is False
        assert ah["tampered"] is False


class TestInspectAllowedDirs:
    """`inspect()` must honor BINARY_MCP_ALLOWED_DIRS like every other tool."""

    def test_rejects_binary_outside_allowed_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """A PE outside the allowlist must raise StructuredBaseError."""
        from src.utils.structured_errors import StructuredBaseError

        # Build a valid (unsigned) PE so we don't error for an unrelated reason.
        pe_bytes = _build_minimal_pe(security_va=0, security_size=0)
        pe_file = tmp_path / "outside.exe"
        pe_file.write_bytes(pe_bytes)

        # Allow ONLY a sibling directory, so pe_file falls outside.
        allowed_dir = tmp_path / "allowed_only"
        allowed_dir.mkdir()
        monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(allowed_dir))

        with pytest.raises(StructuredBaseError) as excinfo:
            inspect(pe_file)
        assert "Invalid binary path" in str(excinfo.value)

    def test_accepts_binary_inside_allowed_dirs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        """Sanity check: a PE inside the allowlist must inspect normally."""
        pe_bytes = _build_minimal_pe(security_va=0, security_size=0)
        pe_file = tmp_path / "inside.exe"
        pe_file.write_bytes(pe_bytes)

        monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(tmp_path))
        result = inspect(pe_file)
        assert result["signed"] is False
