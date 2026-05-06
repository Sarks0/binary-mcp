"""
Tests for the Wave 2 ``find_vtables`` tool and the supporting scanner.

Builds a minimal PE32+ with a custom ``.rdata`` section, populates a
matching ProjectCache function list, then exercises the tool through
its registration entrypoint.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server (re-used pattern from
# tests/test_get_xrefs.py and tests/test_notes_sidecar.py).
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


# ---------------------------------------------------------------------------
# Synthetic PE32+ builder with a custom .rdata payload
# ---------------------------------------------------------------------------


_IMAGE_BASE = 0x140000000
_TEXT_RVA = 0x1000
_TEXT_RAW_OFF = 0x400
_TEXT_RAW_SIZE = 0x200
_RDATA_RVA = 0x2000
_RDATA_RAW_OFF = 0x600
_FILE_ALIGN = 0x200
_SECTION_ALIGN = 0x1000


def _build_pe_with_rdata(rdata_bytes: bytes) -> bytes:
    """Build a minimal PE32+ where ``.rdata`` carries the supplied
    payload. Padded to the file alignment so pefile parses cleanly.
    """
    rdata_raw_size = (
        (len(rdata_bytes) + _FILE_ALIGN - 1) // _FILE_ALIGN * _FILE_ALIGN
    )
    if rdata_raw_size == 0:
        rdata_raw_size = _FILE_ALIGN
    rdata_padded = rdata_bytes.ljust(rdata_raw_size, b"\x00")
    size_of_image = (
        (_RDATA_RVA + rdata_raw_size + _SECTION_ALIGN - 1)
        // _SECTION_ALIGN
        * _SECTION_ALIGN
    )

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe_sig = b"PE\x00\x00"

    num_sections = 2
    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,        # AMD64
        num_sections,
        0,             # TimeDateStamp
        0,             # PointerToSymbolTable
        0,             # NumberOfSymbols
        240,           # SizeOfOptionalHeader (112 + 16*8)
        0x0022,        # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )
    opt_main = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,                # PE32+
        14, 0,                # MajorLinkerVersion, MinorLinkerVersion
        _TEXT_RAW_SIZE,       # SizeOfCode
        rdata_raw_size,       # SizeOfInitializedData
        0,                    # SizeOfUninitializedData
        _TEXT_RVA,            # AddressOfEntryPoint
        _TEXT_RVA,            # BaseOfCode
        _IMAGE_BASE,
        _SECTION_ALIGN, _FILE_ALIGN,
        6, 0, 0, 0,           # MajorOperatingSystemVersion + minor + image versions
        6, 0,                 # MajorSubsystemVersion, minor
        0,                    # Win32VersionValue
        size_of_image,
        0x400,                # SizeOfHeaders
        0,                    # CheckSum
        3, 0,                 # Subsystem (Windows Console), DllCharacteristics
        0x100000, 0x1000,     # SizeOfStackReserve, SizeOfStackCommit
        0x100000, 0x1000,     # SizeOfHeapReserve, SizeOfHeapCommit
        0,                    # LoaderFlags
        16,                   # NumberOfRvaAndSizes
    )
    data_dir = bytes(16 * 8)

    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        _TEXT_RAW_SIZE,
        _TEXT_RVA,
        _TEXT_RAW_SIZE,
        _TEXT_RAW_OFF,
        0, 0, 0, 0,
        0x60000020,
    )
    rdata_section = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        rdata_raw_size,
        _RDATA_RVA,
        rdata_raw_size,
        _RDATA_RAW_OFF,
        0, 0, 0, 0,
        0x40000040,
    )

    headers = (
        bytes(dos) + pe_sig + file_header + opt_main
        + data_dir + text_section + rdata_section
    )
    headers = headers.ljust(0x400, b"\x00")
    text_body = b"\x90" * _TEXT_RAW_SIZE

    return headers + text_body + rdata_padded


def _make_pointer_run(targets: list[int]) -> bytes:
    """Pack a list of absolute 64-bit target addresses as little-endian
    pointers, ready to drop into a vtable test fixture.
    """
    return b"".join(struct.pack("<Q", a) for a in targets)


def _ctx_for_addresses(addresses: list[int]) -> dict:
    """Build a minimal ProjectCache-shaped context whose ``functions``
    list claims entries at every supplied VA.
    """
    return {
        "metadata": {"name": "test.exe", "image_base": f"0x{_IMAGE_BASE:x}"},
        "functions": [
            {
                "name": f"fn_{a:x}",
                "address": f"0x{a:x}",
                "name_source": "USER_DEFINED",
                "is_thunk": False,
                "is_external": False,
            }
            for a in addresses
        ],
        "imports": [],
        "strings": [],
        "memory_map": [],
    }


def _write_pe(tmp_path: Path, pe_bytes: bytes, name: str = "sample.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(pe_bytes)
    return p


# ---------------------------------------------------------------------------
# Fixture: server module + real ProjectCache pinned to tmp_path
# ---------------------------------------------------------------------------


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod
    return server_mod


@pytest.fixture
def find_vtables(server_module, tmp_path, monkeypatch):
    """Return the registered ``find_vtables`` function with the
    server's ``cache`` rerouted to a temp ProjectCache so the test
    owns the cache filesystem.
    """
    from src.engines.static.ghidra.project_cache import ProjectCache
    from src.tools.indirect_call_tools import register_indirect_call_tools

    cache = ProjectCache(cache_dir=str(tmp_path))
    monkeypatch.setattr(server_module, "cache", cache)

    app = MagicMock()
    app.tool = MagicMock(return_value=lambda fn: fn)
    tools = register_indirect_call_tools(app, cache)
    return tools["find_vtables"], cache


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFindVtables:
    def test_positive_run_emits_vtable(self, find_vtables, tmp_path):
        tool, cache = find_vtables
        targets = [_IMAGE_BASE + 0x1000 + i * 0x10 for i in range(5)]
        pe_path = _write_pe(
            tmp_path,
            _build_pe_with_rdata(_make_pointer_run(targets)),
        )
        cache.save_cached(str(pe_path), _ctx_for_addresses(targets))

        result = tool(str(pe_path), min_run=3)

        assert "Tables: 1" in result
        assert "5 slots" in result
        for fn_addr in targets:
            assert f"0x{fn_addr:x}" in result.lower()

    def test_below_min_run_filtered_out(self, find_vtables, tmp_path):
        tool, cache = find_vtables
        targets = [_IMAGE_BASE + 0x1000, _IMAGE_BASE + 0x1010]
        pe_path = _write_pe(
            tmp_path,
            _build_pe_with_rdata(_make_pointer_run(targets)),
        )
        cache.save_cached(str(pe_path), _ctx_for_addresses(targets))

        result = tool(str(pe_path), min_run=3)
        assert "(no fnptr runs found)" in result

    def test_driver_dispatch_table_tagged(self, find_vtables, tmp_path):
        tool, cache = find_vtables
        # Exactly 28 slots -> DRIVER_DISPATCH_TABLE.
        targets = [_IMAGE_BASE + 0x1000 + i * 0x10 for i in range(28)]
        pe_path = _write_pe(
            tmp_path,
            _build_pe_with_rdata(_make_pointer_run(targets)),
        )
        cache.save_cached(str(pe_path), _ctx_for_addresses(targets))

        result = tool(str(pe_path), min_run=3)
        assert "DRIVER_DISPATCH_TABLE" in result
        assert "28 slots" in result

    def test_no_cache_returns_clear_error(self, find_vtables, tmp_path):
        tool, _cache = find_vtables
        # Build a PE but never save_cached.
        pe_path = _write_pe(tmp_path, _build_pe_with_rdata(b""))
        result = tool(str(pe_path), min_run=3)
        assert "Error" in result
        assert "analyze_binary" in result

    def test_persists_to_cache_so_second_call_short_circuits(
        self, find_vtables, tmp_path, monkeypatch
    ):
        tool, cache = find_vtables
        targets = [_IMAGE_BASE + 0x1000 + i * 0x10 for i in range(4)]
        pe_path = _write_pe(
            tmp_path,
            _build_pe_with_rdata(_make_pointer_run(targets)),
        )
        cache.save_cached(str(pe_path), _ctx_for_addresses(targets))

        first = tool(str(pe_path), min_run=3)
        assert "Tables: 1" in first

        # Cached vtables key now lives in the saved context. Patch
        # pefile.PE so a second call would explode if it tried to
        # re-walk the binary; the short-circuit path must succeed.
        import pefile as real_pefile

        def _fail_on_open(*args, **kwargs):
            raise AssertionError(
                "find_vtables re-opened the PE on the second call instead of "
                "honouring the cached result"
            )

        monkeypatch.setattr(real_pefile, "PE", _fail_on_open)
        second = tool(str(pe_path), min_run=3)
        assert "Tables: 1" in second

    def test_invalid_min_run_rejected(self, find_vtables, tmp_path):
        tool, cache = find_vtables
        pe_path = _write_pe(tmp_path, _build_pe_with_rdata(b""))
        cache.save_cached(str(pe_path), _ctx_for_addresses([]))

        result = tool(str(pe_path), min_run=1)
        assert "Error" in result
        assert "min_run" in result


class TestGetXrefsIndirectSurfacing:
    """Wave 2 part C: get_xrefs surfaces the ``Indirect call candidates``
    section when ``xrefs_to_function_indirect`` and/or ``vtables`` carry
    rows for the target.
    """

    def _wire(self, server_module, ctx, monkeypatch):
        monkeypatch.setattr(
            server_module, "get_analysis_context", lambda *a, **kw: ctx
        )

    def _func(self, name, address, name_source="USER_DEFINED"):
        return {
            "name": name,
            "address": address,
            "name_source": name_source,
            "called_functions": [],
            "pseudocode": "",
            "is_thunk": False,
            "is_external": False,
            "basic_blocks": [],
            "parameters": [],
            "local_variables": [],
            "signature": "",
            "decompile_status": "success",
            "jump_tables": [],
            "fid_match": None,
        }

    def test_indirect_xrefs_surface_via_index(self, server_module, monkeypatch):
        target = self._func("handler", "0x1000")
        caller = self._func("dispatch", "0x2000")
        ctx = {
            "metadata": {"name": "x.exe"},
            "functions": [target, caller],
            "imports": [],
            "strings": [],
            "memory_map": [],
            "xrefs_to_function": {},
            "xrefs_to_function_indirect": {
                "1000": [
                    {
                        "from_func_addr": "0x2000",
                        "from_func_name": "dispatch",
                        "from_call_site": "0x202a",
                        "operand": "[RAX+0x18]",
                    },
                ],
            },
        }
        self._wire(server_module, ctx, monkeypatch)

        result = server_module.get_xrefs(
            "/bin/x.exe", function_name="handler"
        )

        assert "Indirect call candidates" in result
        assert "dispatch" in result
        assert "0x202a" in result
        assert "[RAX+0x18]" in result

    def test_vtable_hit_surfaces_with_slot_and_tags(
        self, server_module, monkeypatch
    ):
        target = self._func("handler", "0x1000")
        ctx = {
            "metadata": {"name": "x.exe"},
            "functions": [target],
            "imports": [],
            "strings": [],
            "memory_map": [],
            "vtables": [
                {
                    "section": ".rdata",
                    "address": "0x140030000",
                    "slot_count": 28,
                    "stride": 8,
                    "tags": ["DRIVER_DISPATCH_TABLE"],
                    "targets": [
                        {"slot": 4, "address": "0x1000", "name": "handler"},
                    ],
                },
            ],
        }
        self._wire(server_module, ctx, monkeypatch)

        result = server_module.get_xrefs(
            "/bin/x.exe", function_name="handler"
        )

        assert "Indirect call candidates" in result
        assert "0x140030000" in result
        assert "slot 4" in result
        assert "DRIVER_DISPATCH_TABLE" in result

    def test_indirect_section_appears_alongside_direct(
        self, server_module, monkeypatch
    ):
        target = self._func("handler", "0x1000")
        direct = self._func("direct_caller", "0x3000")
        indirect = self._func("indirect_caller", "0x2000")
        ctx = {
            "metadata": {"name": "x.exe"},
            "functions": [target, direct, indirect],
            "imports": [],
            "strings": [],
            "memory_map": [],
            "xrefs_to_function": {
                "1000": [
                    {
                        "from_func_addr": "0x3000",
                        "from_func_name": "direct_caller",
                        "from_call_site": "0x3010",
                    },
                ],
            },
            "xrefs_to_function_indirect": {
                "1000": [
                    {
                        "from_func_addr": "0x2000",
                        "from_func_name": "indirect_caller",
                        "from_call_site": "0x202a",
                        "operand": "[RAX+0x10]",
                    },
                ],
            },
        }
        self._wire(server_module, ctx, monkeypatch)

        result = server_module.get_xrefs(
            "/bin/x.exe", function_name="handler"
        )

        # Both sections must appear -- the LLM should see all evidence.
        assert "Function calls (1)" in result
        assert "direct_caller" in result
        assert "Indirect call candidates" in result
        assert "indirect_caller" in result
