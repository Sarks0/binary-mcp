"""
Tests for the BinaryReader context manager.

Uses small fixture data and mocked file reads to verify format detection,
segment caching, and VA-to-bytes translation for PE, ELF, and Mach-O.
"""

from unittest.mock import MagicMock, patch

from src.utils.binary_reader import BinaryReader


class TestFormatDetection:
    """Test that BinaryReader correctly detects binary format from magic bytes."""

    def test_detect_pe_format(self, tmp_path):
        """MZ magic bytes should trigger PE detection."""
        pe_file = tmp_path / "test.exe"
        # Minimal MZ header
        pe_file.write_bytes(b"MZ" + b"\x00" * 100)

        with patch("src.utils.binary_reader.BinaryReader._open_pe") as mock_pe:
            mock_pe.return_value = None
            reader = BinaryReader(pe_file)
            reader._open()
            mock_pe.assert_called_once()
            reader._close()

    def test_detect_elf_format(self, tmp_path):
        """ELF magic bytes should trigger ELF detection."""
        elf_file = tmp_path / "test.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        with patch("src.utils.binary_reader.BinaryReader._open_elf") as mock_elf:
            mock_elf.return_value = None
            reader = BinaryReader(elf_file)
            reader._open()
            mock_elf.assert_called_once()
            reader._close()

    def test_detect_macho_le64_format(self, tmp_path):
        """Mach-O 64-bit LE magic should trigger Mach-O detection."""
        macho_file = tmp_path / "test.macho"
        macho_file.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        with patch("src.utils.binary_reader.BinaryReader._open_macho") as mock_macho:
            mock_macho.return_value = None
            reader = BinaryReader(macho_file)
            reader._open()
            mock_macho.assert_called_once()
            reader._close()

    def test_detect_unknown_format(self, tmp_path):
        """Unknown magic bytes should fall back to raw format."""
        raw_file = tmp_path / "test.bin"
        raw_file.write_bytes(b"\x00\x01\x02\x03" + b"\x00" * 100)

        reader = BinaryReader(raw_file)
        reader._open()
        assert reader.format == "raw"
        reader._close()


class TestContextManager:
    """Test context manager protocol."""

    def test_enter_exit(self, tmp_path):
        """Context manager should open and close cleanly."""
        raw_file = tmp_path / "test.bin"
        raw_file.write_bytes(b"\x00" * 100)

        with BinaryReader(raw_file) as reader:
            assert reader.format is not None

    def test_format_property(self, tmp_path):
        """Format should be None before open, set after."""
        raw_file = tmp_path / "test.bin"
        raw_file.write_bytes(b"\x00" * 100)

        reader = BinaryReader(raw_file)
        assert reader.format is None
        with reader:
            assert reader.format == "raw"


class TestELFSegmentParsing:
    """Test ELF segment parsing and VA translation."""

    def test_read_bytes_from_elf_segment(self, tmp_path):
        """Should read bytes at correct offset from ELF PT_LOAD segment."""
        elf_file = tmp_path / "test.elf"
        # Build a minimal ELF with one PT_LOAD segment
        # The actual ELF parsing is done by pyelftools, so we mock it
        test_data = b"\x7fELF" + b"\x00" * 100

        elf_file.write_bytes(test_data)

        reader = BinaryReader(elf_file)
        # Manually set up segments as if ELF parsing succeeded
        reader._format = "elf"
        reader._file = open(elf_file, "rb")
        reader._segments = [
            (0x400000, 0x401000, 0),  # VA 0x400000-0x401000 -> file offset 0
        ]

        result = reader.read_bytes_at_va(0x400000, 4)
        assert result == b"\x7fELF"

        reader._close()

    def test_read_bytes_outside_segment_returns_none(self, tmp_path):
        """VA outside any segment should return None."""
        elf_file = tmp_path / "test.elf"
        elf_file.write_bytes(b"\x7fELF" + b"\x00" * 100)

        reader = BinaryReader(elf_file)
        reader._format = "elf"
        reader._file = open(elf_file, "rb")
        reader._segments = [
            (0x400000, 0x401000, 0),
        ]

        result = reader.read_bytes_at_va(0x500000, 4)
        assert result is None

        reader._close()


class TestMachoSegmentParsing:
    """Test Mach-O segment parsing and VA translation."""

    def test_read_bytes_from_macho_segment(self, tmp_path):
        """Should read bytes at correct offset from Mach-O segment."""
        macho_file = tmp_path / "test.macho"
        data = b"\xcf\xfa\xed\xfe" + b"\x00" * 200
        macho_file.write_bytes(data)

        reader = BinaryReader(macho_file)
        reader._format = "macho"
        reader._file = open(macho_file, "rb")
        reader._segments = [
            (0x100000, 0x100100, 0),  # VA 0x100000-0x100100 -> file offset 0
        ]

        result = reader.read_bytes_at_va(0x100000, 4)
        assert result == b"\xcf\xfa\xed\xfe"

        reader._close()


class TestPEReading:
    """Test PE reading via pefile."""

    def test_read_bytes_pe_with_mock(self):
        """PE reading should use cached pefile object."""
        reader = BinaryReader("/fake/path.exe")
        reader._format = "pe"

        mock_pe = MagicMock()
        mock_pe.get_data.return_value = b"\xcc\xcc\xcc\xcc"
        reader._pe = mock_pe
        reader._pe_image_base = 0x400000

        result = reader.read_bytes_at_va(0x401000, 4)
        assert result == b"\xcc\xcc\xcc\xcc"
        # Verify it used RVA = VA - image_base
        mock_pe.get_offset_from_rva.assert_called_once_with(0x1000)
        mock_pe.get_data.assert_called_once_with(0x1000, 4)

        reader._pe = None  # Don't try to close real object

    def test_read_bytes_pe_invalid_rva_returns_none(self):
        """Invalid RVA should return None, not raise."""
        reader = BinaryReader("/fake/path.exe")
        reader._format = "pe"

        mock_pe = MagicMock()
        mock_pe.get_offset_from_rva.side_effect = Exception("invalid RVA")
        reader._pe = mock_pe
        reader._pe_image_base = 0x400000

        result = reader.read_bytes_at_va(0xFFFFFFFF, 4)
        assert result is None

        reader._pe = None


class TestRawFallback:
    """Test raw format fallback."""

    def test_raw_treats_va_as_offset(self, tmp_path):
        """Raw format should treat VA as a file offset."""
        raw_file = tmp_path / "test.bin"
        raw_file.write_bytes(b"ABCDEFGHIJ")

        with BinaryReader(raw_file) as reader:
            assert reader.format == "raw"
            result = reader.read_bytes_at_va(4, 3)
            assert result == b"EFG"

    def test_raw_read_past_end(self, tmp_path):
        """Reading past end of file should return short read, not error."""
        raw_file = tmp_path / "test.bin"
        raw_file.write_bytes(b"ABCD")

        with BinaryReader(raw_file) as reader:
            result = reader.read_bytes_at_va(2, 100)
            assert result == b"CD"


class TestMultipleReads:
    """Test that multiple reads from the same reader work correctly."""

    def test_multiple_segment_reads(self, tmp_path):
        """Multiple reads from different segments should all succeed."""
        test_file = tmp_path / "test.elf"
        # Create test data with identifiable patterns at known offsets
        data = bytearray(4096)
        data[0:4] = b"\x7fELF"
        data[0x100:0x104] = b"AAAA"
        data[0x200:0x204] = b"BBBB"
        data[0x300:0x304] = b"CCCC"
        test_file.write_bytes(bytes(data))

        reader = BinaryReader(test_file)
        reader._format = "elf"
        reader._file = open(test_file, "rb")
        reader._segments = [
            (0x400000, 0x401000, 0),  # Maps VA range to file offset 0
        ]

        # Read from multiple VAs within the same segment
        assert reader.read_bytes_at_va(0x400100, 4) == b"AAAA"
        assert reader.read_bytes_at_va(0x400200, 4) == b"BBBB"
        assert reader.read_bytes_at_va(0x400300, 4) == b"CCCC"
        # Re-read first VA to ensure seeking works
        assert reader.read_bytes_at_va(0x400100, 4) == b"AAAA"

        reader._close()
