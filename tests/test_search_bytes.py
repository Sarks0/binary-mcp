"""
Tests for the rewritten search_bytes tool and BinaryReader.file_offset_to_va.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Stage a fake Ghidra install so importing src.server doesn't blow up on
# this CI host. Must happen before any import of src.server.
_FAKE_GHIDRA = Path(tempfile.mkdtemp(prefix="ghidra_home_"))
(_FAKE_GHIDRA / "support").mkdir(parents=True, exist_ok=True)
(_FAKE_GHIDRA / "support" / "analyzeHeadless").touch()
os.environ["GHIDRA_HOME"] = str(_FAKE_GHIDRA)

# Stub MCP deps before importing src.server (matches test_get_xrefs pattern).
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


# -- _parse_byte_pattern ----------------------------------------------------


class TestParseBytePattern:
    def _parse(self):
        from src.server import _parse_byte_pattern
        return _parse_byte_pattern

    def test_plain_hex(self):
        needle, mask = self._parse()("4883EC20")
        assert needle == bytes.fromhex("4883EC20")
        assert mask == b"\xff\xff\xff\xff"

    def test_with_spaces(self):
        needle, mask = self._parse()("48 83 EC 20")
        assert needle == bytes.fromhex("4883EC20")
        assert mask == b"\xff\xff\xff\xff"

    def test_wildcard(self):
        needle, mask = self._parse()("48 83 ?? 20")
        assert needle[0] == 0x48
        assert needle[1] == 0x83
        assert needle[3] == 0x20
        assert mask == b"\xff\xff\x00\xff"

    def test_invalid_odd_length(self):
        assert self._parse()("488") is None

    def test_invalid_non_hex(self):
        assert self._parse()("ZZZZ") is None

    def test_empty(self):
        assert self._parse()("") is None


# -- _scan_with_mask --------------------------------------------------------


class TestScanWithMask:
    def _scan(self):
        from src.server import _scan_with_mask
        return _scan_with_mask

    def test_finds_all_exact_matches(self):
        data = b"\x00\xAB\xCD\x00\xAB\xCD\x00"
        offsets = self._scan()(data, b"\xAB\xCD", b"\xff\xff", max_results=10)
        assert offsets == [1, 4]

    def test_max_results_caps(self):
        data = b"\xAB" * 100
        offsets = self._scan()(data, b"\xAB", b"\xff", max_results=3)
        assert len(offsets) == 3

    def test_wildcard_matches(self):
        data = b"\x00\x48\x83\xEC\x20\x00\x48\x83\xFF\x20"
        offsets = self._scan()(
            data, b"\x48\x83\x00\x20", b"\xff\xff\x00\xff", max_results=10
        )
        assert offsets == [1, 6]


# -- BinaryReader.file_offset_to_va ----------------------------------------


class TestFileOffsetToVa:
    def test_raw_format_offset_equals_va(self, tmp_path):
        from src.utils.binary_reader import BinaryReader

        # Unknown magic falls through to raw format
        f = tmp_path / "raw.bin"
        f.write_bytes(b"\x00" * 256)
        with BinaryReader(str(f)) as r:
            assert r.format == "raw"
            assert r.file_offset_to_va(0x10) == 0x10

    def test_elf_segments(self, tmp_path):
        """Mocked ELF segments — file_offset_to_va inverts the segment table."""
        from src.utils.binary_reader import BinaryReader

        # Synthesize a minimal ELF that pyelftools won't actually parse for
        # us; instead we drive the reader through its segment list directly.
        f = tmp_path / "fake.bin"
        f.write_bytes(b"\x00" * 64)
        with BinaryReader(str(f)) as r:
            # Force ELF-style state for the test
            r._format = "elf"
            r._segments = [(0x400000, 0x401000, 0x0), (0x600000, 0x600200, 0x1000)]
            assert r.file_offset_to_va(0x100) == 0x400100
            assert r.file_offset_to_va(0x1050) == 0x600050
            # Outside any segment → None
            assert r.file_offset_to_va(0x9999) is None


# -- search_bytes end-to-end -----------------------------------------------


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))

    sys.modules.pop("src.server", None)
    import src.server as server_mod
    return server_mod


class TestSearchBytes:
    def _make_binary(self, tmp_path, payload: bytes):
        f = tmp_path / "sample.bin"
        # Prefix with a non-PE/ELF/Macho magic so BinaryReader uses 'raw'
        # mode (offset == va), which makes assertions readable.
        f.write_bytes(b"\x00\x00\x00\x00" + payload)
        return f

    def test_invalid_pattern(self, server_module, tmp_path, monkeypatch):
        f = self._make_binary(tmp_path, b"\x00" * 16)
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: None
        )
        result = server_module.search_bytes(str(f), "ZZZZ")
        assert "invalid hex pattern" in result.lower()

    def test_no_matches(self, server_module, tmp_path, monkeypatch):
        f = self._make_binary(tmp_path, b"\x00" * 16)
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: None
        )
        result = server_module.search_bytes(str(f), "DEADBEEF")
        assert "No matches" in result

    def test_finds_matches_reports_va(self, server_module, tmp_path, monkeypatch):
        # 4-byte prefix + needle at offset 4
        f = self._make_binary(tmp_path, b"\xDE\xAD\xBE\xEF\x00\x00")
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: None
        )
        result = server_module.search_bytes(str(f), "DE AD BE EF")
        assert "Found 1 match" in result
        # Raw format → VA == file offset == 4 (after the leading 4 zero bytes)
        assert "0x4" in result
        # Stub message is gone
        assert "coming soon" not in result
        assert "extracted data" not in result

    def test_function_context_enrichment(
        self, server_module, tmp_path, monkeypatch
    ):
        # Pattern at file offset 0x10 → VA 0x10. Pretend a function spans
        # 0x10..0x40 so the result picks up function context.
        payload = b"\x00" * 0x0C + b"\xAB\xCD\xEF\x01" + b"\x00" * 0x30
        f = self._make_binary(tmp_path, payload)

        ctx = {
            "metadata": {},
            "functions": [{
                "name": "candidate_handler",
                "address": "0x10",
                "size": 0x30,
                "basic_blocks": [{"start": "0x10", "end": "0x40"}],
            }],
            "imports": [],
            "strings": [],
            "memory_map": [],
        }
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: ctx
        )

        # Needle starts at file offset 0x10 (4 zero-prefix + 0x0C zero pad)
        result = server_module.search_bytes(str(f), "AB CD EF 01")
        assert "Found 1 match" in result
        assert "candidate_handler" in result
        assert "+0x" in result

    def test_wildcard_pattern(self, server_module, tmp_path, monkeypatch):
        f = self._make_binary(tmp_path, b"\xDE\xAD\xCC\xEF\x00\xDE\xAD\x99\xEF")
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: None
        )
        result = server_module.search_bytes(str(f), "DE AD ?? EF")
        assert "Found 2 match" in result

    def test_max_results_capped(self, server_module, tmp_path, monkeypatch):
        # 100 needles back-to-back
        f = self._make_binary(tmp_path, b"\xAB" * 100)
        monkeypatch.setattr(
            server_module.cache, "get_cached", lambda p: None
        )
        result = server_module.search_bytes(str(f), "AB", max_results=3)
        # 100 total; we asked to see only 3
        assert "showing first 3" in result
