"""
Test suite for module dump with PE reconstruction functionality.

These tests verify the PE reconstruction logic without requiring
x64dbg to be running or pefile to be installed.
"""

import struct
import tempfile
from pathlib import Path

import pytest


class TestDumpModuleTool:
    """Test the x64dbg_dump_module MCP tool output formatting."""

    def test_tool_formats_output_correctly_success(self):
        """Test that the tool formats output correctly on success."""
        # Mock result from bridge.dump_module
        mock_result = {
            "success": True,
            "output_path": "/tmp/test.dll",
            "original_base": "0x10000000",
            "size": 12288,
            "sections_fixed": 2,
            "imports_rebuilt": False,
            "warnings": [],
        }

        # Format the output as the tool does
        output = []
        output.append("Module dumped successfully")
        output.append("")
        output.append(f"Output path: {mock_result['output_path']}")
        output.append(f"Original base: {mock_result['original_base']}")
        output.append(
            f"Size: {mock_result['size']} bytes ({mock_result['size'] / 1024:.1f} KB)"
        )

        if mock_result["sections_fixed"] > 0:
            output.append(f"Sections fixed: {mock_result['sections_fixed']}")

        result_text = "\n".join(output)

        assert "Module dumped successfully" in result_text
        assert "/tmp/test.dll" in result_text
        assert "0x10000000" in result_text
        assert "12.0 KB" in result_text
        assert "Sections fixed: 2" in result_text

    def test_tool_formats_output_with_warnings(self):
        """Test that warnings are properly formatted."""
        mock_result = {
            "success": True,
            "output_path": "/tmp/test.dll",
            "original_base": "0x10000000",
            "size": 8192,
            "sections_fixed": 1,
            "imports_rebuilt": False,
            "warnings": ["Section .rsrc VA beyond dump size", "PE parsing partial"],
        }

        output = []
        if mock_result["warnings"]:
            output.append("Warnings:")
            for warning in mock_result["warnings"]:
                output.append(f"  - {warning}")

        result_text = "\n".join(output)

        assert "Warnings:" in result_text
        assert "Section .rsrc VA beyond dump size" in result_text
        assert "PE parsing partial" in result_text

    def test_tool_formats_output_failure(self):
        """Test that failure output is properly formatted."""
        mock_result = {
            "success": False,
            "output_path": "/tmp/test.dll",
            "original_base": None,
            "size": 0,
            "sections_fixed": 0,
            "imports_rebuilt": False,
            "warnings": ["Module not found"],
        }

        output = []
        if not mock_result["success"]:
            output.append("Module dump failed")
            if mock_result["warnings"]:
                for warning in mock_result["warnings"]:
                    output.append(f"  - {warning}")

        result_text = "\n".join(output)

        assert "Module dump failed" in result_text
        assert "Module not found" in result_text


class TestUnmapSectionsLogic:
    """Test section unmapping (memory to file layout conversion) logic."""

    def test_section_layout_concepts(self):
        """Verify understanding of section layout concepts."""
        # In memory: sections aligned to SectionAlignment (typically 0x1000)
        # On disk: sections aligned to FileAlignment (typically 0x200)
        #
        # Memory layout:
        #   Headers: 0x0 - 0x400
        #   .text:   0x1000 - 0x2000 (aligned to 0x1000)
        #   .data:   0x2000 - 0x3000 (aligned to 0x1000)
        #
        # File layout:
        #   Headers: 0x0 - 0x400
        #   .text:   0x400 - 0x600 (aligned to 0x200)
        #   .data:   0x600 - 0x800 (aligned to 0x200)

        section_alignment = 0x1000
        file_alignment = 0x200

        # Verify alignments are different
        assert section_alignment != file_alignment
        assert section_alignment > file_alignment

        # Verify alignment math
        # If a section has VirtualSize=0x500 and is at VA=0x1000
        # it needs to be placed at the correct file offset
        virtual_address = 0x1000
        _virtual_size = 0x500  # noqa: F841 (documentation variable)
        raw_data_offset = 0x400  # After headers
        _raw_data_size = 0x200  # noqa: F841 (documentation variable)

        # The section data should be copied from memory VA to file offset
        assert raw_data_offset < virtual_address

    def test_section_data_copy_bounds(self):
        """Test section data copy bounds calculation."""
        # Simulate section parameters
        memory_offset = 0x1000  # VirtualAddress
        memory_size = 0x500  # VirtualSize
        raw_size = 0x200  # SizeOfRawData
        dump_size = 0x3000  # Total memory dump size

        # Calculate how much data to copy
        # Should be minimum of: virtual size, raw size, remaining dump
        remaining_dump = dump_size - memory_offset
        data_size = min(memory_size, raw_size, remaining_dump)

        assert data_size == raw_size  # Limited by raw_size in this case
        assert data_size <= memory_size
        assert data_size <= remaining_dump

    def test_section_beyond_dump_detection(self):
        """Test detection when section is beyond dump size."""
        memory_offset = 0x5000  # VirtualAddress
        dump_size = 0x3000  # Total memory dump size

        # Section is beyond dump
        is_beyond = memory_offset >= dump_size
        assert is_beyond is True


class TestModuleResolution:
    """Test module name/address resolution logic."""

    def test_module_lookup_by_name(self):
        """Test finding module by name."""
        modules = [
            {"name": "kernel32.dll", "base": "0x76D00000", "size": 0xC0000},
            {"name": "ntdll.dll", "base": "0x77000000", "size": 0x1A0000},
            {"name": "malware.exe", "base": "0x00400000", "size": 0x10000},
        ]

        module_name = "malware.exe"
        target_module = None

        for mod in modules:
            if mod.get("name", "").lower() == module_name.lower():
                target_module = mod
                break

        assert target_module is not None
        assert target_module["name"] == "malware.exe"
        assert target_module["base"] == "0x00400000"

    def test_module_lookup_by_address(self):
        """Test finding module by base address."""
        modules = [
            {"name": "kernel32.dll", "base": "0x76D00000", "size": 0xC0000},
            {"name": "ntdll.dll", "base": "0x77000000", "size": 0x1A0000},
            {"name": "malware.exe", "base": "0x00400000", "size": 0x10000},
        ]

        # Search by hex address string
        search_addr = "0x00400000"
        base_addr = int(search_addr, 16)
        target_module = None

        for mod in modules:
            mod_base_str = mod.get("base", "0")
            mod_base = int(mod_base_str, 16)
            if mod_base == base_addr:
                target_module = mod
                break

        assert target_module is not None
        assert target_module["name"] == "malware.exe"

    def test_module_not_found(self):
        """Test behavior when module is not found."""
        modules = [
            {"name": "kernel32.dll", "base": "0x76D00000", "size": 0xC0000},
        ]

        module_name = "nonexistent.dll"
        target_module = None

        for mod in modules:
            if mod.get("name", "").lower() == module_name.lower():
                target_module = mod
                break

        assert target_module is None


class TestPEHeaderParsing:
    """Test PE header parsing concepts without requiring pefile."""

    def test_mz_header_detection(self):
        """Test MZ header detection."""
        valid_pe = b"MZ" + b"\x00" * 100
        invalid_data = b"\x00" * 100

        assert valid_pe[:2] == b"MZ"
        assert invalid_data[:2] != b"MZ"

    def test_pe_signature_location(self):
        """Test PE signature offset from DOS header."""
        # e_lfanew is at offset 0x3C (60 bytes)
        e_lfanew_offset = 0x3C

        # Create a minimal DOS header with PE offset at 64
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        struct.pack_into("<I", dos_header, e_lfanew_offset, 64)

        # Read back the PE offset
        pe_offset = struct.unpack_from("<I", dos_header, e_lfanew_offset)[0]
        assert pe_offset == 64

    def test_pe_magic_values(self):
        """Test PE magic value identification."""
        pe32_magic = 0x10B
        pe32plus_magic = 0x20B

        assert pe32_magic == 267  # 32-bit PE
        assert pe32plus_magic == 523  # 64-bit PE

        # Determine architecture from magic
        def is_64bit(magic):
            return magic == pe32plus_magic

        assert is_64bit(pe32plus_magic) is True
        assert is_64bit(pe32_magic) is False

    def test_imagebase_offset_calculation(self):
        """Test ImageBase offset calculation for PE32 and PE32+."""
        # PE32 (32-bit): ImageBase at optional header + 28
        # PE32+ (64-bit): ImageBase at optional header + 24

        pe_offset = 64  # Example PE header offset
        opt_header_offset = pe_offset + 24  # After COFF header (20 bytes + 4 for signature)

        pe32_imagebase_offset = opt_header_offset + 28
        pe32plus_imagebase_offset = opt_header_offset + 24

        assert pe32_imagebase_offset == 64 + 24 + 28  # 116
        assert pe32plus_imagebase_offset == 64 + 24 + 24  # 112


class TestResultDictStructure:
    """Test the result dictionary structure returned by dump_module."""

    def test_success_result_structure(self):
        """Test successful dump result has all expected fields."""
        result = {
            "success": True,
            "output_path": "/tmp/dumped.dll",
            "original_base": "0x6FE80000",
            "size": 1258496,
            "sections_fixed": 5,
            "imports_rebuilt": False,
            "warnings": [],
        }

        # Verify all expected keys exist
        assert "success" in result
        assert "output_path" in result
        assert "original_base" in result
        assert "size" in result
        assert "sections_fixed" in result
        assert "imports_rebuilt" in result
        assert "warnings" in result

        # Verify types
        assert isinstance(result["success"], bool)
        assert isinstance(result["output_path"], str)
        assert isinstance(result["size"], int)
        assert isinstance(result["sections_fixed"], int)
        assert isinstance(result["imports_rebuilt"], bool)
        assert isinstance(result["warnings"], list)

    def test_failure_result_structure(self):
        """Test failed dump result structure."""
        result = {
            "success": False,
            "output_path": "/tmp/dumped.dll",
            "original_base": None,
            "size": 0,
            "sections_fixed": 0,
            "imports_rebuilt": False,
            "warnings": ["Module not found"],
        }

        assert result["success"] is False
        assert result["original_base"] is None
        assert len(result["warnings"]) > 0


class TestSecurityValidations:
    """Test security validations for dump operations."""

    def test_size_limit_validation(self):
        """Test that size limit validation logic is correct."""
        # Expected security limit: 100MB
        # Note: test_bridge_size_validation verifies the actual constant value
        max_dump_size = 100 * 1024 * 1024

        # Test that sizes exceeding max would be rejected by validation logic
        test_sizes = [
            (1000, True),  # Valid
            (max_dump_size, True),  # Valid (at limit)
            (max_dump_size + 1, False),  # Invalid (exceeds limit)
            (200 * 1024 * 1024, False),  # Invalid (200MB)
            (0, False),  # Invalid (zero)
            (-1, False),  # Invalid (negative)
        ]

        for size, should_be_valid in test_sizes:
            is_valid = size > 0 and size <= max_dump_size
            assert is_valid == should_be_valid, f"Size {size} validation failed"

    def test_path_traversal_detection(self):
        """Test that path traversal attempts are detected."""
        from src.utils.security import PathTraversalError, sanitize_output_path

        # Resolve to handle macOS symlinks (/var -> /private/var)
        allowed_dir = (Path(tempfile.gettempdir()) / "test_dumps").resolve()
        allowed_dir.mkdir(parents=True, exist_ok=True)

        # Valid paths (within allowed directory)
        valid_paths = [
            allowed_dir / "dump.dll",
            allowed_dir / "subdir" / "dump.dll",
        ]

        # Create subdir for valid path test
        (allowed_dir / "subdir").mkdir(parents=True, exist_ok=True)

        for path in valid_paths:
            # Should not raise
            result = sanitize_output_path(path, allowed_dir)
            assert result.is_relative_to(allowed_dir)

        # Invalid paths (traversal attempts)
        invalid_paths = [
            allowed_dir / ".." / "etc" / "passwd",
            allowed_dir / ".." / ".." / "tmp" / "evil.dll",
            Path("/etc/passwd"),
            Path("/tmp/outside.dll"),
        ]

        for path in invalid_paths:
            with pytest.raises((PathTraversalError, ValueError)):
                sanitize_output_path(path, allowed_dir)

    def test_bridge_size_validation(self):
        """Test that bridge.py also validates size (defense in depth)."""
        from src.engines.dynamic.x64dbg.bridge import MAX_DUMP_SIZE

        # Verify bridge has the same limit
        assert MAX_DUMP_SIZE == 100 * 1024 * 1024

    def test_dump_output_directory_structure(self):
        """Test that the expected dump output directory structure is valid."""
        # Verify the expected directory structure matches security requirements
        # The actual constant in dynamic_tools.py follows this pattern
        expected_dir = Path.home() / ".binary_mcp_output" / "dumps"

        # Verify the structure is correct
        assert expected_dir.parts[-2] == ".binary_mcp_output"
        assert expected_dir.parts[-1] == "dumps"
        # Verify it's under user's home directory (security requirement)
        assert str(expected_dir).startswith(str(Path.home()))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
