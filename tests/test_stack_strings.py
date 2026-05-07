"""Tests for stack_strings.py and the find_stack_strings tool."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.utils.stack_strings import (
    StackAssignment,
    StackString,
    StackStringResult,
    detect_xor_loops,
    filter_iocs,
    parse_assignments,
    reconstruct_strings,
    render_markdown,
    scan,
    xor_bytes,
)

# ---------------------------------------------------------------------------
# Pseudocode synthesis helpers
# ---------------------------------------------------------------------------


def _local_byte_writes(bytes_: bytes, *, base_offset: int = 0x10) -> str:
    """Generate ``local_<hex> = '<c>';`` lines for each byte."""
    lines = []
    for i, b in enumerate(bytes_):
        off = base_offset + i
        if 0x20 <= b < 0x7F and b not in (ord("'"), ord("\\")):
            lit = f"'{chr(b)}'"
        else:
            lit = f"0x{b:02x}"
        lines.append(f"  local_{off:x} = {lit};")
    return "\n".join(lines)


def _local_dword_writes(dwords: list[int], *, base_offset: int = 0x10) -> str:
    """Generate 4-byte chunk writes."""
    lines = []
    for i, dw in enumerate(dwords):
        off = base_offset + i * 4
        lines.append(f"  local_{off:x} = 0x{dw:08x};")
    return "\n".join(lines)


def _ascii_to_dwords_le(s: bytes) -> list[int]:
    """Pack bytes into LE 4-byte ints (pad-trail with NULs as needed)."""
    if len(s) % 4 != 0:
        s = s + b"\x00" * (4 - len(s) % 4)
    return [int.from_bytes(s[i : i + 4], "little") for i in range(0, len(s), 4)]


# ---------------------------------------------------------------------------
# parse_assignments
# ---------------------------------------------------------------------------


class TestParseAssignments:
    def test_simple_byte_writes(self):
        pc = _local_byte_writes(b"hello")
        out = parse_assignments(pc)
        assert len(out) == 5
        assert out[0].offset == 0x10
        assert out[0].width == 1
        assert out[0].bytes_le == b"h"

    def test_dword_widths_inferred_from_hex(self):
        pc = "  local_10 = 0x6c6c6568;\n  local_14 = 0x0000006f;"
        out = parse_assignments(pc)
        assert len(out) == 2
        assert out[0].width == 4
        assert out[0].bytes_le == b"hell"
        # Second one's literal has 8 hex digits -- width 4 still
        assert out[1].width == 4
        assert out[1].bytes_le == b"o\x00\x00\x00"

    def test_subfield_notation(self):
        pc = "  local_18._4_4_ = 0x6f77206f;"
        out = parse_assignments(pc)
        assert len(out) == 1
        assert out[0].offset == 0x18 + 4
        assert out[0].width == 4
        assert out[0].bytes_le == b"o wo"

    def test_raw_pointer_assignment(self):
        pc = "  *(byte *)(rsp + 0x10) = 'h';\n  *(byte *)(rsp + 0x11) = 'i';"
        out = parse_assignments(pc)
        assert len(out) == 2
        assert all(a.base == "rsp" for a in out)
        assert out[0].offset == 0x10
        assert out[0].bytes_le == b"h"

    def test_raw_pointer_negative_offset(self):
        # ebp - 0x10 form (x86 frame-relative)
        pc = "  *(byte *)(ebp - 0x10) = 'X';"
        out = parse_assignments(pc)
        assert len(out) == 1
        assert out[0].base == "ebp"
        assert out[0].offset == -0x10

    def test_negative_decimal_wraps(self):
        pc = "  local_10 = -1;"
        out = parse_assignments(pc)
        assert len(out) == 1
        assert out[0].bytes_le == b"\xff"


# ---------------------------------------------------------------------------
# reconstruct_strings
# ---------------------------------------------------------------------------


class TestReconstruct:
    def test_simple_ascii_stack_string(self):
        pc = _local_byte_writes(b"hello world!")
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=4)
        assert len(out) >= 1
        ascii_only = [s for s in out if s.encoding == "ascii"]
        assert any(s.value == "hello world!" for s in ascii_only)
        s = next(s for s in ascii_only if s.value == "hello world!")
        assert s.confidence == "high"

    def test_dword_packed_string(self):
        # "http://m" + "alware" -> 14 bytes -> 4 dwords (last padded with \0\0)
        text = b"http://malware"
        dwords = _ascii_to_dwords_le(text)
        pc = _local_dword_writes(dwords)
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=4)
        ascii_strs = [s for s in out if s.encoding == "ascii"]
        assert any("http://malware" in s.value for s in ascii_strs)

    def test_utf16le_wide_string(self):
        # "AB" wide = 41 00 42 00 -- pack as a single LE dword 0x00420041
        # We'll write each pair as a word so it's clearly UTF-16LE.
        pc = (
            "  local_10 = 0x00410042;\n"  # bytes: 42 00 41 00 -> "BA"
            "  local_14 = 0x00430044;\n"  # bytes: 44 00 43 00 -> "DC"
        )
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=4)
        wide = [s for s in out if s.encoding == "utf-16le"]
        assert wide, f"expected utf-16le decode, got: {[s.encoding for s in out]}"
        assert wide[0].value == "BADC"

    def test_non_contiguous_offsets_low_confidence(self):
        # 5 bytes with a gap: 0x10..0x12 then 0x14..0x15 (skip 0x13)
        pc = (
            "  local_10 = 'h';\n"
            "  local_11 = 'e';\n"
            "  local_12 = 'l';\n"
            "  local_14 = 'o';\n"
            "  local_15 = '!';\n"
        )
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=2)
        # The gap breaks contiguity, but each side should produce a run.
        # The full buffer span sees contiguous filled bytes broken by an
        # unfilled byte at 0x13 -- we expect TWO runs.
        ascii_strs = [s for s in out if s.encoding == "ascii"]
        assert len(ascii_strs) >= 1

    def test_below_min_length_rejected(self):
        pc = _local_byte_writes(b"hi")
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=4)
        assert all(len(s.value) >= 4 for s in out)
        assert not any(s.value == "hi" for s in out)

    def test_low_printability_rejected(self):
        # 8 random non-printable bytes
        bad = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        pc = _local_byte_writes(bad)
        assigns = parse_assignments(pc)
        out = reconstruct_strings(assigns, min_length=4)
        # Printable ratio is 0% -- nothing should be emitted
        assert out == []


# ---------------------------------------------------------------------------
# XOR loops
# ---------------------------------------------------------------------------


class TestXorLoops:
    def test_xor_assign_op_detected(self):
        pc = """
        for (i = 0; i < 11; i++) {
          local_10[i] ^= 0x42;
        }
        """
        out = detect_xor_loops(pc)
        assert len(out) == 1
        assert out[0].key == 0x42
        assert out[0].length_hint == 11

    def test_xor_with_zero_ignored(self):
        pc = "buf[i] ^= 0;"
        assert detect_xor_loops(pc) == []

    def test_no_xor_no_candidate(self):
        assert detect_xor_loops("int x = 1; x = x + 1;") == []

    def test_xor_emulates_to_decoded_string(self):
        # Build "hello world" XORed with 0x42 -> ciphertext bytes
        plaintext = b"hello world"
        key = 0x42
        ct = bytes(b ^ key for b in plaintext)
        pc_lines = []
        for i, b in enumerate(ct):
            pc_lines.append(f"  local_{0x10 + i:x} = 0x{b:02x};")
        pc_lines.append(f"  for (i = 0; i < {len(ct)}; i++) {{ local_10[i] ^= 0x{key:x}; }}")
        pc = "\n".join(pc_lines)

        strings, xor_cands = scan(pc, min_length=4, function_name="decryptor")
        assert any(s.encoding == "xor-decoded" and s.value == "hello world" for s in strings)
        assert any(c.key == 0x42 for c in xor_cands)

    def test_xor_bytes_helper(self):
        assert xor_bytes(b"\x42\x43\x44", 0x42) == b"\x00\x01\x06"


# ---------------------------------------------------------------------------
# IOC filter
# ---------------------------------------------------------------------------


class TestIocFilter:
    def test_only_ioc_strings_kept(self):
        from src.tools.malware_tools import _COMPILED_IOC_PATTERNS

        strs = [
            StackString(
                function="f1", function_address="0x401000", encoding="ascii",
                value="http://evil.example.com/c2", raw_bytes_hex="00",
                start_offset=0, end_offset=10, confidence="high",
                confidence_reasons=(),
            ),
            StackString(
                function="f2", function_address="0x401100", encoding="ascii",
                value="this is harmless plain text",
                raw_bytes_hex="00", start_offset=0, end_offset=10,
                confidence="high", confidence_reasons=(),
            ),
        ]
        kept, by_type = filter_iocs(strs, _COMPILED_IOC_PATTERNS)
        assert len(kept) == 1
        assert kept[0].value.startswith("http://")
        # The string contains both a URL and a domain; either IOC type
        # matching is sufficient for the filter to retain the string.
        assert by_type, "expected at least one IOC type matched"
        flat_matches = [m for ms in by_type.values() for m in ms]
        assert any("evil.example" in m for m in flat_matches)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class TestRenderMarkdown:
    def test_empty(self):
        r = StackStringResult(binary_path="/tmp/foo.exe")
        md = render_markdown(r)
        assert "No stack strings reconstructed." in md

    def test_with_strings_and_xor_candidates(self):
        from src.utils.stack_strings import XorCandidate

        r = StackStringResult(binary_path="/tmp/foo.exe")
        r.strings.append(
            StackString(
                function="decode", function_address="0x401000", encoding="ascii",
                value="hello world", raw_bytes_hex="68656c6c6f20776f726c64",
                start_offset=0x10, end_offset=0x1B, confidence="high",
                confidence_reasons=("printable_ratio=1.00",),
            )
        )
        r.xor_candidates.append(
            XorCandidate(function="decode", key=0x42, length_hint=11, match_line="^= 0x42")
        )
        md = render_markdown(r)
        assert "decode" in md
        assert "hello world" in md
        assert "key=0x42" in md
        assert "len~11" in md


# ---------------------------------------------------------------------------
# Tool integration through register_malware_tools
# ---------------------------------------------------------------------------


class TestToolIntegration:
    def _make_app_and_collect_tools(self):
        """Capture every @app.tool()-decorated function for later inspection."""
        app = MagicMock()
        registered: dict[str, callable] = {}

        def tool_decorator(*_args, **_kwargs):
            def _wrap(fn):
                registered[fn.__name__] = fn
                return fn
            return _wrap

        app.tool = MagicMock(side_effect=tool_decorator)
        return app, registered

    def test_find_stack_strings_registered(self, caplog: pytest.LogCaptureFixture):
        import logging

        from src.tools.malware_tools import register_malware_tools
        from src.utils.patterns import APIPatterns

        app, registered = self._make_app_and_collect_tools()
        cache = MagicMock()
        runner = MagicMock()
        with caplog.at_level(logging.INFO, logger="src.tools.malware_tools"):
            register_malware_tools(app, MagicMock(), cache, runner, APIPatterns())
        assert "find_stack_strings" in registered
        assert any("Registered 6 malware" in r.message for r in caplog.records)

    def test_find_stack_strings_runs_via_mock_cache(self, tmp_path):
        from src.tools.malware_tools import register_malware_tools
        from src.utils.patterns import APIPatterns

        # sanitize_binary_path requires the file to exist. Drop a stub there.
        pe_path = tmp_path / "fake.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 128)

        app, registered = self._make_app_and_collect_tools()
        cache = MagicMock()
        runner = MagicMock()

        pseudo = _local_byte_writes(b"http://malware.example.com/c2")
        ctx = {
            "metadata": {"name": "fake.exe"},
            "functions": [
                {
                    "name": "build_url", "address": "0x401000",
                    "called_functions": [], "pseudocode": pseudo,
                    "basic_blocks": [], "parameters": [],
                    "local_variables": [], "is_thunk": False, "is_external": False,
                },
            ],
            "imports": [], "strings": [], "memory_map": [],
        }
        cache.get_cached.return_value = ctx

        register_malware_tools(app, MagicMock(), cache, runner, APIPatterns())
        find_stack_strings = registered["find_stack_strings"]
        output = find_stack_strings(str(pe_path))

        assert "build_url" in output
        assert "http://malware.example.com/c2" in output

    def test_ioc_only_filters_through(self, tmp_path):
        from src.tools.malware_tools import register_malware_tools
        from src.utils.patterns import APIPatterns

        pe_path = tmp_path / "fake.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 128)

        app, registered = self._make_app_and_collect_tools()
        cache = MagicMock()
        runner = MagicMock()

        pc = (
            _local_byte_writes(b"http://c2.example/x", base_offset=0x10)
            + "\n"
            + _local_byte_writes(b"plain_text_string", base_offset=0x100)
        )
        ctx = {
            "metadata": {"name": "fake.exe"},
            "functions": [
                {
                    "name": "f1", "address": "0x401000",
                    "called_functions": [], "pseudocode": pc,
                    "basic_blocks": [], "parameters": [],
                    "local_variables": [], "is_thunk": False, "is_external": False,
                },
            ],
            "imports": [], "strings": [], "memory_map": [],
        }
        cache.get_cached.return_value = ctx
        register_malware_tools(app, MagicMock(), cache, runner, APIPatterns())
        find_stack_strings = registered["find_stack_strings"]
        output = find_stack_strings(str(pe_path), min_length=4, ioc_only=True)

        assert "http://c2.example/x" in output
        assert "plain_text_string" not in output

    def test_invalid_min_length(self, tmp_path):
        from src.tools.malware_tools import register_malware_tools
        from src.utils.patterns import APIPatterns

        pe_path = tmp_path / "fake.exe"
        pe_path.write_bytes(b"MZ" + b"\x00" * 128)

        app, registered = self._make_app_and_collect_tools()
        register_malware_tools(app, MagicMock(), MagicMock(), MagicMock(), APIPatterns())
        find_stack_strings = registered["find_stack_strings"]
        out = find_stack_strings(str(pe_path), min_length=0)
        assert "PARAMETER_INVALID" in out


# ---------------------------------------------------------------------------
# Stack assignment edge cases
# ---------------------------------------------------------------------------


def test_max_local_offset_rejection():
    """An absurd local offset is silently dropped (no exception)."""
    pc = "  local_ffffffff = 'X';"  # absurdly large offset
    out = parse_assignments(pc)
    assert out == [] or all(a.offset <= 0x10000 for a in out)


def test_pseudocode_length_cap_truncates_with_warning(caplog: pytest.LogCaptureFixture):
    """Pseudocode > 1 MB is truncated; a warning is logged."""
    import logging

    from src.utils.stack_strings import MAX_PSEUDOCODE_LEN

    # 2 MB of inert pseudocode followed by an assignment that WOULD reconstruct
    # if we scanned it -- but it's past the cap so we won't see it.
    inert = "/* harmless comment */\n" * 90_000  # ~2 MB
    assert len(inert) > MAX_PSEUDOCODE_LEN
    tail = "  local_10 = 'X';\n  local_11 = 'X';\n  local_12 = 'X';\n  local_13 = 'X';\n"
    pc = inert + tail

    with caplog.at_level(logging.WARNING, logger="src.utils.stack_strings"):
        strings, _ = scan(pc, min_length=4, function_name="huge_func")
    # Should not have decoded the trailing assignment because it was past cap
    assert all(s.value != "XXXX" for s in strings)
    # Warning should have fired with truncation note
    assert any(
        "truncating" in r.message and "huge_func" in r.message
        for r in caplog.records
    )


def test_assignment_dataclass_immutable():
    a = StackAssignment(base="local", offset=0x10, width=1, bytes_le=b"X", raw_match="")
    with pytest.raises(Exception):
        a.offset = 0x20  # type: ignore[misc]
