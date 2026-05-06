"""Tests for similarity_hashes.py and the compute_similarity_hashes tool."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.utils.similarity_hashes import (
    SectionHash,
    SimilarityHashes,
    compute,
    compute_fuzzy,
    compute_imphash,
    compute_rich_hash,
    compute_section_hashes,
    render_markdown,
)

# ---------------------------------------------------------------------------
# Minimal PE builder (one .text section, no rich header, no imports)
# ---------------------------------------------------------------------------


def _build_minimal_pe() -> bytes:
    """Same shape as tests/test_authenticode.py::_build_minimal_pe but inlined."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe_sig = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        1,
        0,
        0,
        0,
        240,
        0x0022,
    )
    opt_main = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B, 14, 0,
        0x200, 0, 0,
        0x1000,
        0x1000,
        0x140000000,
        0x1000, 0x200,
        6, 0,
        0, 0,
        6, 0, 0,
        0x2000,
        0x400,
        0,
        3, 0,
        0x100000, 0x1000,
        0x100000, 0x1000,
        0,
        16,
    )
    data_dir = bytearray(16 * 8)
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,
        0x1000,
        0x200,
        0x400,
        0, 0, 0, 0,
        0x60000020,
    )
    headers = bytes(dos) + pe_sig + file_header + opt_main + bytes(data_dir) + section
    headers = headers.ljust(0x400, b"\x00")
    body = b"\x90" * 0x200
    return headers + body


# ---------------------------------------------------------------------------
# imphash
# ---------------------------------------------------------------------------


class TestImphash:
    def test_pe_with_no_imports_returns_none(self, tmp_path: Path):
        import pefile

        pe_path = tmp_path / "no-imports.exe"
        pe_path.write_bytes(_build_minimal_pe())
        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            assert compute_imphash(pe) is None
        finally:
            pe.close()

    def test_imphash_matches_pefile_get_imphash(self, tmp_path: Path):
        """When pefile.get_imphash() returns a non-empty string, we return that."""
        # pefile.get_imphash() returns "" for binaries with no imports; assemble
        # a fake pe object that reports a known imphash to prove we pass-through
        # rather than recompute.
        fake_pe = SimpleNamespace(get_imphash=lambda: "abcd1234" * 4)
        assert compute_imphash(fake_pe) == "abcd1234" * 4


# ---------------------------------------------------------------------------
# rich_hash (md5 of clear_data, NOT raw_data)
# ---------------------------------------------------------------------------


class TestRichHash:
    def test_clear_data_is_what_gets_hashed(self):
        """compute_rich_hash hashes ``clear_data``, not ``raw_data``.

        This is the Mandiant / Yara convention. ``raw_data`` is XORed with a
        per-file checksum key and would yield a different hash for every file,
        defeating clustering.
        """
        clear = b"\x12\x34\x56\x78" * 16  # 64 bytes -- arbitrary canonical bytes
        raw = b"\xFF" * 64  # deliberately different from clear_data

        fake_rich = SimpleNamespace(clear_data=clear, raw_data=raw)
        fake_pe = SimpleNamespace(RICH_HEADER=fake_rich)

        expected = hashlib.md5(clear).hexdigest()  # noqa: S324
        assert compute_rich_hash(fake_pe) == expected
        # Also: md5(raw) would NOT match (proves we don't use raw_data)
        assert compute_rich_hash(fake_pe) != hashlib.md5(raw).hexdigest()  # noqa: S324

    def test_no_rich_header(self, tmp_path: Path):
        import pefile

        pe_path = tmp_path / "no-rich.exe"
        pe_path.write_bytes(_build_minimal_pe())
        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            assert compute_rich_hash(pe) is None
        finally:
            pe.close()

    def test_empty_clear_data_returns_none(self):
        fake_pe = SimpleNamespace(RICH_HEADER=SimpleNamespace(clear_data=b""))
        assert compute_rich_hash(fake_pe) is None


# ---------------------------------------------------------------------------
# Per-section hashes
# ---------------------------------------------------------------------------


class TestSectionHashes:
    def test_one_per_section(self, tmp_path: Path):
        import pefile

        pe_path = tmp_path / "one-section.exe"
        pe_path.write_bytes(_build_minimal_pe())
        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            sh = compute_section_hashes(pe)
            assert len(sh) == 1
            assert sh[0].name == ".text"
            assert sh[0].size == 0x200
            # Manually compute: the section data is 0x200 NOPs (0x90)
            expected = hashlib.sha256(b"\x90" * 0x200).hexdigest()
            assert sh[0].sha256 == expected
        finally:
            pe.close()


# ---------------------------------------------------------------------------
# Fuzzy: graceful degradation
# ---------------------------------------------------------------------------


class TestFuzzyDegradation:
    def test_missing_ssdeep_and_tlsh_yields_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        """When neither ssdeep nor tlsh import, both are reported unavailable."""
        # Force ImportError on `import ssdeep` / `import tlsh` even if they are
        # actually installed in the env. Setting sys.modules[name] = None makes
        # subsequent ``import name`` raise ImportError.
        monkeypatch.setitem(sys.modules, "ssdeep", None)
        monkeypatch.setitem(sys.modules, "tlsh", None)

        ssdeep_h, tlsh_h, unavailable = compute_fuzzy(b"some bytes" * 100)
        assert ssdeep_h is None
        assert tlsh_h is None
        assert "ssdeep" in unavailable
        assert "tlsh" in unavailable

    def test_only_ssdeep_missing(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setitem(sys.modules, "ssdeep", None)
        # Don't touch tlsh; if it's installed it'll work, if not it'll be
        # reported as unavailable too. Test asserts only on ssdeep.
        ssdeep_h, _tlsh_h, unavailable = compute_fuzzy(b"x" * 200)
        assert ssdeep_h is None
        assert "ssdeep" in unavailable


def _try_import(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _try_import("ssdeep"), reason="ssdeep not installed")
def test_ssdeep_when_present():
    """When ssdeep IS installed, compute_fuzzy returns a well-formed string."""
    ssdeep_h, _, unavailable = compute_fuzzy(b"hello world this needs to be long enough" * 100)
    assert "ssdeep" not in unavailable
    assert isinstance(ssdeep_h, str)
    assert ssdeep_h.count(":") == 2  # "<blocksize>:<chunk>:<doublechunk>"


@pytest.mark.skipif(not _try_import("tlsh"), reason="tlsh not installed")
def test_tlsh_when_present():
    """When tlsh IS installed, compute_fuzzy returns a TLSH string (or None for tiny inputs)."""
    _, tlsh_h, unavailable = compute_fuzzy(b"\x00" * 1024 + b"\xFF" * 1024 + b"X" * 2048)
    assert "tlsh" not in unavailable
    # TLSH may legitimately return None for low-entropy inputs; just assert
    # the call did not crash and unavailable list didn't grow.


# ---------------------------------------------------------------------------
# compute() integration
# ---------------------------------------------------------------------------


class TestComputeIntegration:
    def test_full_compute_on_minimal_pe(self, tmp_path: Path):
        pe_path = tmp_path / "min.exe"
        pe_path.write_bytes(_build_minimal_pe())
        result = compute(pe_path)
        assert result.binary_size == len(_build_minimal_pe())
        assert result.file_sha256 == hashlib.sha256(_build_minimal_pe()).hexdigest()
        assert result.imphash is None  # no imports
        assert result.rich_hash is None  # no rich header
        # Authentihash always computes for a parseable PE
        assert result.authentihash_sha256 is not None
        assert len(result.authentihash_sha256) == 64
        assert len(result.section_hashes) == 1
        assert result.section_hashes[0].name == ".text"

    def test_authentihash_matches_authenticode_module(self, tmp_path: Path):
        """compute() uses the same Authentihash as authenticode.compute_authentihash()."""
        import pefile

        from src.utils.authenticode import compute_authentihash

        pe_path = tmp_path / "min.exe"
        pe_path.write_bytes(_build_minimal_pe())

        result = compute(pe_path)

        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            expected_ah = compute_authentihash(pe, digest="sha256").hex()
        finally:
            pe.close()

        assert result.authentihash_sha256 == expected_ah

    def test_not_a_pe_file_raises(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        not_pe = tmp_path / "garbage.bin"
        not_pe.write_bytes(b"definitely not a PE")
        with pytest.raises(StructuredBaseError):
            compute(not_pe)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_vt_pivots_present(self):
        r = SimilarityHashes(
            binary_path="/tmp/foo.exe",
            binary_size=4096,
            file_sha256="a" * 64,
            imphash="e87a45c3deadbeef",
            rich_hash="d4f1abcd",
            authentihash_sha256="b" * 64,
            ssdeep="6:abcdef:ABC",
            tlsh="T1A0F2" + "X" * 64,
            section_hashes=[
                SectionHash(name=".text", size=512, sha256="c" * 64),
                SectionHash(name=".rdata", size=256, sha256="d" * 64),
            ],
        )
        md = render_markdown(r)
        assert "VT search: imphash:e87a45c3deadbeef" in md
        assert "VT search: rich_pe_hash:d4f1abcd" in md
        assert f"VT search: authentihash:{'b' * 64}" in md
        assert "VT search: ssdeep:6:abcdef:ABC" in md
        assert "VT search: tlsh:T1A0F2" in md
        assert ".text" in md
        assert ".rdata" in md

    def test_unavailable_footer(self):
        r = SimilarityHashes(
            binary_path="/tmp/foo.exe",
            binary_size=4096,
            file_sha256="a" * 64,
            imphash=None,
            rich_hash=None,
            authentihash_sha256="b" * 64,
            ssdeep=None,
            tlsh=None,
            fuzzy_unavailable=["ssdeep", "tlsh"],
        )
        md = render_markdown(r)
        assert "fuzzy hashing libs unavailable (ssdeep, tlsh)" in md
        assert "pip install ssdeep python-tlsh" in md
        # None values render as "<none>"
        assert "<none>" in md


# ---------------------------------------------------------------------------
# Tool registration smoke
# ---------------------------------------------------------------------------


def test_tool_registers_four_tools(caplog: pytest.LogCaptureFixture):
    import logging

    from fastmcp import FastMCP

    from src.tools.pe_tools import register_pe_tools

    app = FastMCP("test-similarity")
    with caplog.at_level(logging.INFO, logger="src.tools.pe_tools"):
        register_pe_tools(app)
    assert any("Registered 4 PE structure tools" in r.message for r in caplog.records)
