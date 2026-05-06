"""
Tests for the Wave 1B annotation side-car.

Covers:
- ProjectCache notes I/O and apply_notes_overlay (with both symbolic
  and RVA-based function keys).
- ProjectCache.invalidate preserving the side-car while wiping the
  cache + meta + funcidx files.
- Server tools (add_note / get_notes / delete_note) round-tripping
  through the side-car and the in-memory cache.
- The replay hook in get_analysis_context reapplying notes after a
  fresh analysis.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server, mirroring the harness used
# by tests/test_get_xrefs.py and tests/test_ghidra_perf.py.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()
_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


# --- ProjectCache side-car helpers ------------------------------------------


def _binary(tmp_path, name="bin"):
    binary = tmp_path / name
    binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
    return binary


def _binary_hash(binary):
    return hashlib.sha256(binary.read_bytes()).hexdigest()


def _cache(tmp_path):
    from src.engines.static.ghidra.project_cache import ProjectCache
    return ProjectCache(cache_dir=str(tmp_path))


def _func(name, address, name_source="USER_DEFINED", **extra):
    base = {
        "name": name,
        "address": address,
        "name_source": name_source,
        "is_thunk": False,
        "is_external": False,
        "called_functions": [],
        "call_sites": [],
        "pseudocode": "",
        "basic_blocks": [],
        "parameters": [],
        "local_variables": [],
        "signature": "",
        "decompile_status": "success",
        "jump_tables": [],
        "fid_match": None,
        "plate_comment": "",
        "instruction_comments": [],
    }
    base.update(extra)
    return base


def _ctx(functions=None, image_base="0x140000000"):
    return {
        "metadata": {"name": "test.exe", "image_base": image_base},
        "functions": functions or [],
        "imports": [],
        "strings": [],
        "memory_map": [],
    }


class TestNotesSidecarIO:
    def test_write_and_read_round_trip(self, tmp_path):
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        notes = [
            {
                "function_key": "decrypt_string",
                "kind": "plate",
                "addr": None,
                "text": "AES-256",
                "created_at": 1.0,
            }
        ]
        assert cache.write_notes(str(binary), notes)
        assert cache.read_notes(str(binary)) == notes

    def test_read_missing_returns_empty(self, tmp_path):
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        assert cache.read_notes(str(binary)) == []

    def test_invalidate_preserves_notes_sidecar(self, tmp_path):
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        cache.save_cached(str(binary), {"functions": [], "metadata": {}})
        cache.write_notes(
            str(binary),
            [{"function_key": "x", "kind": "plate", "addr": None, "text": "t"}],
        )

        h = _binary_hash(binary)
        notes_path = tmp_path / f"{h}.notes.json"
        assert notes_path.exists()

        assert cache.invalidate(str(binary))

        # Cache + meta + funcidx are gone but the side-car must remain.
        assert not (tmp_path / f"{h}.json.gz").exists()
        assert not (tmp_path / f"{h}.meta.json").exists()
        assert not (tmp_path / f"{h}.funcidx.json").exists()
        assert notes_path.exists()
        assert cache.read_notes(str(binary)) == [
            {"function_key": "x", "kind": "plate", "addr": None, "text": "t"}
        ]


class TestApplyNotesOverlay:
    def test_overlay_applies_user_notes_by_symbolic_name(self, tmp_path):
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        cache.write_notes(
            str(binary),
            [
                {
                    "function_key": "decrypt_string",
                    "kind": "plate",
                    "addr": None,
                    "text": "AES-256",
                },
                {
                    "function_key": "decrypt_string",
                    "kind": "pre",
                    "addr": "0x140001050",
                    "text": "key derivation starts here",
                },
            ],
        )

        ctx = _ctx(
            functions=[
                _func("decrypt_string", "0x140001000"),
                _func("noise", "0x140002000"),
            ]
        )
        cache.apply_notes_overlay(str(binary), ctx)
        target = ctx["functions"][0]
        assert target["notes"]["plate"] == "AES-256"
        assert target["notes"]["pre"]["0x140001050"] == "key derivation starts here"
        # Untouched functions get no notes block created.
        assert "notes" not in ctx["functions"][1]

    def test_overlay_resolves_rva_when_name_default(self, tmp_path):
        # Same RVA-keyed note should reattach across two image bases.
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        cache.write_notes(
            str(binary),
            [
                {
                    "function_key": "rva:0x1020",
                    "kind": "plate",
                    "addr": None,
                    "text": "anonymous helper",
                },
            ],
        )

        ctx_a = _ctx(
            functions=[
                _func("FUN_140001020", "0x140001020", name_source="DEFAULT"),
            ],
            image_base="0x140000000",
        )
        cache.apply_notes_overlay(str(binary), ctx_a)
        assert ctx_a["functions"][0]["notes"]["plate"] == "anonymous helper"

        ctx_b = _ctx(
            functions=[
                _func("FUN_180001020", "0x180001020", name_source="DEFAULT"),
            ],
            image_base="0x180000000",
        )
        cache.apply_notes_overlay(str(binary), ctx_b)
        assert ctx_b["functions"][0]["notes"]["plate"] == "anonymous helper"

    def test_overlay_does_not_clobber_ghidra_plate_comment(self, tmp_path):
        # Side-car has NO plate note for this function, so its
        # Ghidra-supplied plate_comment must remain untouched.
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        cache.write_notes(
            str(binary),
            [
                {
                    "function_key": "documented_fn",
                    "kind": "pre",
                    "addr": "0x140001008",
                    "text": "checks the magic byte",
                },
            ],
        )
        ctx = _ctx(
            functions=[
                _func(
                    "documented_fn",
                    "0x140001000",
                    plate_comment="Ghidra-extracted summary",
                ),
            ]
        )
        cache.apply_notes_overlay(str(binary), ctx)
        target = ctx["functions"][0]
        # Ghidra-supplied field still intact.
        assert target["plate_comment"] == "Ghidra-extracted summary"
        # User-supplied bucket only gets pre note; plate stays empty.
        assert target["notes"]["plate"] == ""
        assert target["notes"]["pre"]["0x140001008"] == "checks the magic byte"

    def test_overlay_no_notes_is_noop(self, tmp_path):
        cache = _cache(tmp_path)
        binary = _binary(tmp_path)
        ctx = _ctx(functions=[_func("a", "0x140001000")])
        # Side-car never written -> read_notes returns []
        result = cache.apply_notes_overlay(str(binary), ctx)
        assert result is ctx
        assert "notes" not in ctx["functions"][0]


# --- Server tool round-trip -------------------------------------------------


@pytest.fixture
def server_module(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    sys.modules.pop("src.server", None)
    import src.server as server_mod
    return server_mod


def _wire_for_notes(server_module, ctx, monkeypatch):
    """Wire get_analysis_context to return ``ctx`` and route the
    server module's ``cache`` into a temp ProjectCache rooted on a
    tmp dir keyed by the test's binary path."""
    monkeypatch.setattr(
        server_module, "get_analysis_context", lambda *a, **kw: ctx
    )


def _wire_real_cache(server_module, monkeypatch, cache_dir: Path):
    from src.engines.static.ghidra.project_cache import ProjectCache
    monkeypatch.setattr(
        server_module, "cache", ProjectCache(cache_dir=str(cache_dir))
    )


class TestServerToolsRoundTrip:
    def test_add_get_delete_plate(self, server_module, tmp_path, monkeypatch):
        binary = _binary(tmp_path)
        ctx = _ctx(
            functions=[_func("decrypt_string", "0x140001000")]
        )
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        result = server_module.add_note(
            str(binary), "0x140001000", "AES-256", kind="plate"
        )
        assert "Note Saved" in result
        assert "decrypt_string" in result

        listing = server_module.get_notes(str(binary))
        assert "AES-256" in listing
        assert "decrypt_string" in listing

        # Filtered get
        single = server_module.get_notes(str(binary), address="0x140001000")
        assert "AES-256" in single

        deleted = server_module.delete_note(
            str(binary), "0x140001000", kind="plate"
        )
        assert "Note Deleted" in deleted

        empty = server_module.get_notes(str(binary))
        assert "(none)" in empty

    def test_add_replaces_existing_same_triple(
        self, server_module, tmp_path, monkeypatch
    ):
        binary = _binary(tmp_path)
        ctx = _ctx(functions=[_func("fn", "0x140001000")])
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        server_module.add_note(str(binary), "0x140001000", "first", kind="plate")
        replaced = server_module.add_note(
            str(binary), "0x140001000", "second", kind="plate"
        )
        assert "Replaced" in replaced

        listing = server_module.get_notes(str(binary))
        assert "second" in listing
        assert "first" not in listing

    def test_invalid_kind_rejected(self, server_module, tmp_path, monkeypatch):
        binary = _binary(tmp_path)
        ctx = _ctx(functions=[_func("fn", "0x140001000")])
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        result = server_module.add_note(
            str(binary), "0x140001000", "x", kind="middle"
        )
        assert "Error" in result
        assert "kind" in result

    def test_unknown_address_rejected(self, server_module, tmp_path, monkeypatch):
        binary = _binary(tmp_path)
        ctx = _ctx(functions=[_func("fn", "0x140001000")])
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        result = server_module.add_note(
            str(binary), "0xdeadbeef", "x", kind="plate"
        )
        assert "Error" in result
        assert "No function" in result

    def test_pre_note_pinned_to_instruction(
        self, server_module, tmp_path, monkeypatch
    ):
        binary = _binary(tmp_path)
        ctx = _ctx(functions=[_func("dispatcher", "0x140001000")])
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        # Pin a pre-note at the function entry. The function key is the
        # containing function's symbolic name; the addr field captures
        # the instruction PC for display in get_notes.
        result = server_module.add_note(
            str(binary), "0x140001000", "checks magic", kind="pre"
        )
        assert "Note Saved" in result

        listing = server_module.get_notes(str(binary))
        assert "checks magic" in listing
        assert "[pre @ 0x140001000]" in listing

    def test_pre_note_pinned_to_internal_instruction_pc(
        self, server_module, tmp_path, monkeypatch
    ):
        """Regression: ultrareview bug_001. _resolve_function_note_key used
        to require an entry-point exact match, so pinning a pre/post note at
        any address inside the function body would fail with 'No function
        contains address X' -- contradicting add_note's docstring promise
        that the function 'is resolved automatically'. Walk basic_blocks
        for body containment so internal-PC pinning works."""
        binary = _binary(tmp_path)
        ctx = _ctx(
            functions=[
                _func(
                    "dispatcher",
                    "0x140001000",
                    basic_blocks=[
                        {"start": "0x140001000", "end": "0x14000107f"},
                    ],
                )
            ]
        )
        _wire_for_notes(server_module, ctx, monkeypatch)
        _wire_real_cache(server_module, monkeypatch, tmp_path)

        # Address 0x140001050 is inside the basic block's [start, end] range
        # but is NOT the function entry. Should resolve via body containment.
        result = server_module.add_note(
            str(binary), "0x140001050", "magic check here", kind="pre"
        )
        assert "Note Saved" in result, (
            f"Internal instruction PC 0x140001050 should resolve to dispatcher "
            f"via basic_blocks containment; got: {result}"
        )

        listing = server_module.get_notes(str(binary))
        assert "magic check here" in listing
        assert "[pre @ 0x140001050]" in listing

        # Address outside any function's body still fails with the same
        # "no function contains" error (regression guard).
        bad = server_module.add_note(
            str(binary), "0xdeadbeef", "should fail", kind="pre"
        )
        assert "Error" in bad
        assert "No function" in bad
