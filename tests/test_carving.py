"""Tests for carving.py and the extract_embedded_binaries tool."""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.utils.carving import (
    CarvedBlob,
    CarvingResult,
    _default_carve_dir,
    _walk_subtree,
    carve,
    classify_blob,
    render_markdown,
    walk_resources,
)

# ---------------------------------------------------------------------------
# Test PE builder with real resource directory + optional overlay
# ---------------------------------------------------------------------------


def _build_resource_section(
    payloads: list[tuple[int, int, int, bytes]], *, section_rva: int
) -> bytes:
    """
    Build a serialized .rsrc section with a 3-level resource directory
    (type -> id -> language -> data leaf). All payloads share one type_id
    but vary by name_id / lang_id so a single section walks N leaves.
    """
    if not payloads:
        return b""
    type_id = payloads[0][0]
    if not all(p[0] == type_id for p in payloads):
        raise ValueError("all payloads must share type_id")
    n = len(payloads)

    # Layout offsets within the .rsrc section
    type_entry_off = 0x10
    type_subdir_off = 0x18
    name_entries_off = 0x28
    name_subdirs_off = name_entries_off + 8 * n
    data_entries_off = name_subdirs_off + 24 * n
    blobs_off = data_entries_off + 16 * n

    blob_offsets: list[int] = []
    cur = blobs_off
    for _, _, _, data in payloads:
        blob_offsets.append(cur)
        cur += len(data)
    total = cur
    aligned = (total + 0x1FF) & ~0x1FF  # FileAlignment-align

    section = bytearray(aligned)

    # Root resource directory (16 bytes), 0 named, 1 id child
    struct.pack_into("<IIHHHH", section, 0, 0, 0, 0, 0, 0, 1)
    # Type entry -> type subdir
    struct.pack_into("<II", section, type_entry_off, type_id, type_subdir_off | 0x80000000)
    # Type subdir (16 bytes), 0 named, n id children
    struct.pack_into("<IIHHHH", section, type_subdir_off, 0, 0, 0, 0, 0, n)

    for i, (_, name_id, lang_id, data) in enumerate(payloads):
        ne = name_entries_off + 8 * i
        ns = name_subdirs_off + 24 * i
        de = data_entries_off + 16 * i
        bof = blob_offsets[i]
        # Name id entry -> name subdir
        struct.pack_into("<II", section, ne, name_id, ns | 0x80000000)
        # Name subdir (16 bytes) + 1 lang entry (8 bytes)
        struct.pack_into("<IIHHHH", section, ns, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", section, ns + 16, lang_id, de)
        # IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (RVA), Size, CodePage, Reserved
        struct.pack_into("<IIII", section, de, section_rva + bof, len(data), 0, 0)
        section[bof : bof + len(data)] = data

    return bytes(section)


def _build_pe_with_resources(
    payloads: list[tuple[int, int, int, bytes]] | None = None,
    *,
    overlay: bytes = b"",
) -> bytes:
    """
    Build a minimal valid PE32+ with one .text section and (optionally) one
    .rsrc section + (optionally) an overlay appended after the last section.
    """
    payloads = payloads or []

    text_rva = 0x1000
    text_raw_off = 0x400
    text_raw_size = 0x200
    rsrc_rva = 0x2000
    rsrc_raw_off = 0x600

    rsrc_data = _build_resource_section(payloads, section_rva=rsrc_rva)
    rsrc_raw_size = len(rsrc_data) if rsrc_data else 0
    has_rsrc = bool(rsrc_data)
    num_sections = 2 if has_rsrc else 1

    if has_rsrc:
        size_of_image = ((rsrc_rva + rsrc_raw_size) + 0xFFF) & ~0xFFF
    else:
        size_of_image = text_rva + 0x1000

    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe_sig = b"PE\x00\x00"

    file_header = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine = AMD64
        num_sections,
        0,
        0,
        0,
        240,  # SizeOfOptionalHeader = 112 + 16*8
        0x0022,
    )
    opt_main = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        text_raw_size,
        rsrc_raw_size,
        0,
        text_rva,
        text_rva,
        0x140000000,
        0x1000,  # SectionAlignment
        0x200,  # FileAlignment
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        size_of_image,
        0x400,
        0,  # CheckSum
        3,
        0,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    data_dir = bytearray(16 * 8)
    if has_rsrc:
        struct.pack_into("<II", data_dir, 2 * 8, rsrc_rva, rsrc_raw_size)

    text_section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        text_raw_size,
        text_rva,
        text_raw_size,
        text_raw_off,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    section_headers = text_section
    if has_rsrc:
        section_headers += struct.pack(
            "<8sIIIIIIHHI",
            b".rsrc\x00\x00\x00",
            rsrc_raw_size,
            rsrc_rva,
            rsrc_raw_size,
            rsrc_raw_off,
            0,
            0,
            0,
            0,
            0x40000040,
        )

    headers = bytes(dos) + pe_sig + file_header + opt_main + bytes(data_dir) + section_headers
    headers = headers.ljust(0x400, b"\x00")
    text_body = b"\x90" * text_raw_size

    pe_bytes = headers + text_body
    if has_rsrc:
        pe_bytes += rsrc_data
    if overlay:
        pe_bytes += overlay
    return pe_bytes


def _write_pe(tmp_path: Path, pe_bytes: bytes, name: str = "sample.exe") -> Path:
    p = tmp_path / name
    p.write_bytes(pe_bytes)
    return p


# ---------------------------------------------------------------------------
# Sanity: the test PE generator produces something pefile can parse
# ---------------------------------------------------------------------------


class TestPEGenerator:
    def test_minimal_pe_is_parseable(self, tmp_path: Path):
        import pefile

        pe_path = _write_pe(tmp_path, _build_pe_with_resources())
        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            assert pe.FILE_HEADER.NumberOfSections == 1
        finally:
            pe.close()

    def test_pe_with_one_resource_walks(self, tmp_path: Path):
        import pefile

        # type 10 = RT_RCDATA
        payload = b"hello resource"
        pe_bytes = _build_pe_with_resources([(10, 101, 1033, payload)])
        pe_path = _write_pe(tmp_path, pe_bytes)

        pe = pefile.PE(str(pe_path), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            leaves = list(walk_resources(pe))
            assert len(leaves) == 1
            path, file_off, size = leaves[0]
            assert path == "RT_RCDATA/101/1033"
            assert size == len(payload)
            assert pe_bytes[file_off : file_off + size] == payload
        finally:
            pe.close()


# ---------------------------------------------------------------------------
# classify_blob
# ---------------------------------------------------------------------------


class TestClassify:
    def test_pe_magic(self):
        data = b"MZ" + b"\x00" * 1024
        t, _, _, reasons = classify_blob(data)
        assert t == "pe"
        assert "magic:pe" in reasons

    def test_zip_magic(self):
        data = b"PK\x03\x04" + b"\x00" * 1024
        t, _, _, reasons = classify_blob(data)
        assert t == "zip"
        assert "magic:zip" in reasons

    def test_high_entropy_unknown(self):
        data = os.urandom(4096)
        t, _, entropy, reasons = classify_blob(data)
        assert t == "unknown"
        assert entropy > 7.2
        assert any("entropy" in r for r in reasons)

    def test_low_entropy_text_unflagged(self):
        data = (b"hello world\n" * 200)
        t, _, _, reasons = classify_blob(data)
        assert t == "unknown"
        assert reasons == []

    def test_empty_blob(self):
        t, _, entropy, reasons = classify_blob(b"")
        assert t == "empty"
        assert entropy == 0.0
        assert reasons == []

    def test_7z_archive(self):
        data = b"7z\xBC\xAF\x27\x1C" + b"\x00" * 100
        t, _, _, reasons = classify_blob(data)
        assert t == "7z"
        assert "magic:7z" in reasons

    def test_shellcode_prologue_call_pop(self):
        # CALL+pop -- E8 ?? ?? ?? ?? 58 (pop eax)
        sc = b"\xE8\x00\x00\x00\x00\x58" + b"\x90" * 100
        _, _, _, reasons = classify_blob(sc)
        assert any(r.startswith("shellcode:") for r in reasons)


# ---------------------------------------------------------------------------
# walk_resources recursion-depth cap (mock pefile-like tree)
# ---------------------------------------------------------------------------


class TestRecursionDepthCap:
    """_walk_subtree must stop descending once depth > max_depth."""

    def _leaf(self, label: int) -> SimpleNamespace:
        return SimpleNamespace(
            id=label,
            name=None,
            directory=None,
            data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=0x1000, Size=8)),
        )

    def _node_with_child(self, label: int, child) -> SimpleNamespace:
        return SimpleNamespace(
            id=label,
            name=None,
            directory=SimpleNamespace(entries=[child]),
            data=None,
        )

    def test_depth_within_cap_yields_leaf(self):
        # 3 nested directories ending in a leaf
        leaf = self._leaf(1)
        d1 = self._node_with_child(2, leaf)
        d2 = self._node_with_child(3, d1)
        root = SimpleNamespace(entries=[d2])

        leaves = list(_walk_subtree(root, [], depth=1, max_depth=8))
        assert len(leaves) == 1
        assert "3/2/1" == leaves[0][0]

    def test_depth_exceeded_yields_nothing_below_cap(self):
        # 12-level deep tree; cap at 4 => no leaf should escape
        leaf = self._leaf(99)
        cur = leaf
        for i in range(12):
            cur = self._node_with_child(i, cur)
        root = SimpleNamespace(entries=[cur])

        leaves = list(_walk_subtree(root, [], depth=1, max_depth=4))
        assert leaves == [], f"expected zero leaves, got: {leaves}"


# ---------------------------------------------------------------------------
# carve() integration
# ---------------------------------------------------------------------------


class TestCarveIntegration:
    def test_no_resources_no_overlay_empty(self, tmp_path: Path):
        pe_path = _write_pe(tmp_path, _build_pe_with_resources())
        out = tmp_path / "out"
        result = carve(pe_path, out)
        assert result.blobs == []
        md = render_markdown(result)
        assert "No embedded blobs detected." in md

    def test_extract_mz_in_rt_rcdata(self, tmp_path: Path):
        # A 256-byte payload starting with MZ
        payload = b"MZ" + os.urandom(254)
        pe_bytes = _build_pe_with_resources([(10, 101, 1033, payload)])
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"

        result = carve(pe_path, out)
        assert len(result.blobs) == 1
        b = result.blobs[0]
        assert b.source == "resource"
        assert b.resource_path == "RT_RCDATA/101/1033"
        assert b.size == len(payload)
        assert b.detected_type == "pe"
        assert "magic:pe" in b.flag_reasons
        assert b.flagged is True
        assert b.written_path is not None

        # Disk artefacts: dumped file + sidecar JSON
        dumped = Path(b.written_path)
        assert dumped.read_bytes() == payload
        sidecar = dumped.parent / f"{b.sha256}.json"
        meta = json.loads(sidecar.read_text())
        assert meta["sha256"] == b.sha256
        assert meta["resource_path"] == "RT_RCDATA/101/1033"
        assert meta["source"] == "resource"
        assert meta["detected_type"] == "pe"
        assert meta["parent_sha256"] == result.binary_sha256

    def test_high_entropy_unknown_blob_flagged(self, tmp_path: Path):
        random_payload = os.urandom(4096)
        pe_bytes = _build_pe_with_resources([(10, 200, 0, random_payload)])
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"

        result = carve(pe_path, out)
        assert len(result.blobs) == 1
        b = result.blobs[0]
        assert b.detected_type == "unknown"
        assert b.flagged is True
        assert any("entropy" in r for r in b.flag_reasons)
        assert b.written_path is not None

    def test_low_entropy_text_not_flagged(self, tmp_path: Path):
        text_payload = b"hello world\n" * 200
        pe_bytes = _build_pe_with_resources([(10, 300, 0, text_payload)])
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"

        result = carve(pe_path, out)
        assert len(result.blobs) == 1
        b = result.blobs[0]
        assert b.flagged is False
        assert b.written_path is None
        # Output dir should not even exist if nothing was written
        assert not out.exists() or list(out.iterdir()) == []

    def test_overlay_zip_carved(self, tmp_path: Path):
        zip_blob = b"PK\x03\x04" + b"\x00" * 200
        pe_bytes = _build_pe_with_resources(overlay=zip_blob)
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"

        result = carve(pe_path, out)
        # Overlay-only: no resources. We expect exactly one blob.
        overlay_blobs = [b for b in result.blobs if b.source == "overlay"]
        assert len(overlay_blobs) == 1
        b = overlay_blobs[0]
        assert b.detected_type == "zip"
        assert "magic:zip" in b.flag_reasons
        assert b.flagged is True
        assert b.written_path is not None
        assert Path(b.written_path).read_bytes() == zip_blob

    def test_max_total_mb_caps_extraction(self, tmp_path: Path):
        # Two ~600 KB high-entropy payloads, budget 1 MB -> first written, second skipped
        size = 600 * 1024
        p1 = os.urandom(size)
        p2 = os.urandom(size)
        pe_bytes = _build_pe_with_resources(
            [(10, 400, 0, p1), (10, 401, 0, p2)],
        )
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"

        result = carve(pe_path, out, max_total_mb=1)
        flagged = [b for b in result.blobs if b.flagged]
        assert len(flagged) == 2
        written = [b for b in flagged if b.written_path and not b.write_skipped_reason]
        skipped = [
            b
            for b in flagged
            if b.write_skipped_reason and "max_total_mb" in b.write_skipped_reason
        ]
        assert len(written) == 1
        assert len(skipped) == 1
        assert result.truncated is True
        assert "max_total_mb" in result.truncated_reason

    def test_no_overwrite_existing_files(self, tmp_path: Path):
        payload = b"MZ" + os.urandom(254)
        pe_bytes = _build_pe_with_resources([(10, 500, 0, payload)])
        pe_path = _write_pe(tmp_path, pe_bytes)
        out = tmp_path / "out"
        out.mkdir()

        # Pre-create the output file with different bytes
        import hashlib

        sha = hashlib.sha256(payload).hexdigest()
        existing = out / sha
        existing.write_bytes(b"DO NOT OVERWRITE")

        result = carve(pe_path, out)
        b = result.blobs[0]
        assert b.write_skipped_reason == "exists (no overwrite)"
        # Existing bytes must remain untouched
        assert existing.read_bytes() == b"DO NOT OVERWRITE"

    def test_invalid_output_dir_with_parent_traversal(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        pe_path = _write_pe(tmp_path, _build_pe_with_resources())
        with pytest.raises(StructuredBaseError) as excinfo:
            carve(pe_path, Path("foo/../escape"))
        assert "output_dir" in str(excinfo.value).lower()

    def test_not_a_pe_file_raises(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        not_pe = tmp_path / "not.bin"
        not_pe.write_bytes(b"this is plain text, not a PE file")
        with pytest.raises(StructuredBaseError):
            carve(not_pe, tmp_path / "out")

    def test_invalid_max_total_mb(self, tmp_path: Path):
        from src.utils.structured_errors import StructuredBaseError

        pe_path = _write_pe(tmp_path, _build_pe_with_resources())
        with pytest.raises(StructuredBaseError):
            carve(pe_path, tmp_path / "out", max_total_mb=0)


# ---------------------------------------------------------------------------
# Default cache-dir resolution
# ---------------------------------------------------------------------------


class TestDefaultCarveDir:
    def test_env_var_override(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
        monkeypatch.setenv("BINARY_MCP_CARVE_DIR", str(tmp_path / "custom"))
        assert _default_carve_dir() == tmp_path / "custom"

    def test_default_when_no_env(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("BINARY_MCP_CARVE_DIR", raising=False)
        d = _default_carve_dir()
        assert "carved" in d.parts
        assert d.is_absolute()


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_empty_result(self):
        r = CarvingResult(
            binary_path="/tmp/foo.exe",
            binary_sha256="a" * 64,
            output_dir="/tmp/out",
        )
        md = render_markdown(r)
        assert "Blobs found: 0" in md
        assert "No embedded blobs detected." in md

    def test_truncated_warning(self):
        r = CarvingResult(
            binary_path="/tmp/foo.exe",
            binary_sha256="a" * 64,
            output_dir="/tmp/out",
            truncated=True,
            truncated_reason="max_total_mb=1 budget reached",
        )
        r.blobs.append(
            CarvedBlob(
                source="resource",
                resource_path="RT_RCDATA/1/1",
                file_offset=0x1000,
                size=128,
                sha256="b" * 64,
                detected_type="pe",
                detected_description="PE32+",
                entropy=7.5,
                flagged=True,
                flag_reasons=("magic:pe",),
                written_path="/tmp/out/" + "b" * 64,
            )
        )
        md = render_markdown(r)
        assert "WARNING: extraction truncated" in md
        assert "magic:pe" in md
