"""
Test suite for Ghidra MCP Server.
"""

# Mock the MCP imports before importing server
import sys
from unittest.mock import MagicMock

import pytest

sys.modules['mcp'] = MagicMock()
sys.modules['mcp.server'] = MagicMock()
sys.modules['mcp.types'] = MagicMock()


class TestGhidraRunner:
    """Test Ghidra runner functionality."""

    def test_ghidra_detection(self):
        """Test Ghidra auto-detection."""
        from src.ghidra.runner import GhidraRunner

        # This will fail if Ghidra is not installed
        # In a real test, we would mock the filesystem
        try:
            runner = GhidraRunner()
            assert runner.ghidra_path is not None
        except FileNotFoundError:
            pytest.skip("Ghidra not installed")

    def test_normalize_binary_path(self):
        """Test binary path normalization."""
        import platform

        from src.ghidra.runner import GhidraRunner

        try:
            runner = GhidraRunner()
        except FileNotFoundError:
            pytest.skip("Ghidra not installed")

        # Test path normalization
        if platform.system() == "Windows":
            path = runner._normalize_binary_path("test")
            assert path.suffix in ["", ".exe"]
        else:
            path = runner._normalize_binary_path("test.exe")
            # On Unix, should prefer no extension if it exists
            pass


class TestProjectCache:
    """Test project cache functionality."""

    def test_cache_initialization(self, tmp_path):
        """Test cache directory creation."""
        from src.ghidra.project_cache import ProjectCache

        cache = ProjectCache(str(tmp_path / "cache"))
        assert cache.cache_dir.exists()

    def test_cache_operations(self, tmp_path):
        """Test cache save and retrieve."""
        from src.ghidra.project_cache import ProjectCache

        cache = ProjectCache(str(tmp_path / "cache"))

        # Create a temporary test file
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"test content")

        # Test data
        test_data = {
            "metadata": {"name": "test"},
            "functions": [{"name": "main", "address": "0x1000"}]
        }

        # Save to cache
        success = cache.save_cached(str(test_file), test_data)
        assert success

        # Retrieve from cache
        cached_data = cache.get_cached(str(test_file))
        assert cached_data is not None
        assert cached_data["metadata"]["name"] == "test"

        # Check cache metadata
        metadata = cache.get_metadata(str(test_file))
        assert metadata is not None
        assert metadata["binary_name"] == "test_binary"

    def test_cache_invalidation(self, tmp_path):
        """Test cache invalidation."""
        from src.ghidra.project_cache import ProjectCache

        cache = ProjectCache(str(tmp_path / "cache"))

        # Create test file and cache
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"test content")

        test_data = {"test": "data"}
        cache.save_cached(str(test_file), test_data)

        # Verify cached
        assert cache.has_cached(str(test_file))

        # Invalidate
        cache.invalidate(str(test_file))

        # Verify not cached
        assert not cache.has_cached(str(test_file))

    def test_cache_list(self, tmp_path):
        """Test listing cached binaries."""
        from src.ghidra.project_cache import ProjectCache

        cache = ProjectCache(str(tmp_path / "cache"))

        # Create multiple cached binaries
        for i in range(3):
            test_file = tmp_path / f"binary_{i}"
            test_file.write_bytes(b"test")
            cache.save_cached(str(test_file), {"index": i})

        # List cached
        cached = cache.list_cached()
        assert len(cached) == 3

    def test_cache_size(self, tmp_path):
        """Test cache size calculation."""
        from src.ghidra.project_cache import ProjectCache

        cache = ProjectCache(str(tmp_path / "cache"))

        # Create test file
        test_file = tmp_path / "test_binary"
        test_file.write_bytes(b"test content")

        # Cache some data
        cache.save_cached(str(test_file), {"data": "x" * 1000})

        # Check size
        size = cache.get_cache_size()
        assert size > 0


class TestAPIPatterns:
    """Test API pattern database."""

    def test_api_info_retrieval(self):
        """Test retrieving API information."""
        from src.utils.patterns import APIPatterns

        patterns = APIPatterns()

        # Test known API
        info = patterns.get_api_info("CreateRemoteThread")
        assert info is not None
        assert info["category"] == "process"
        assert info["severity"] == "critical"

        # Test unknown API
        info = patterns.get_api_info("UnknownAPI")
        assert info is None

    def test_category_filtering(self):
        """Test filtering by category."""
        from src.utils.patterns import APIPatterns

        patterns = APIPatterns()

        # Get all network APIs
        network_apis = patterns.get_by_category("network")
        assert len(network_apis) > 0
        assert "socket" in network_apis

    def test_severity_filtering(self):
        """Test filtering by severity."""
        from src.utils.patterns import APIPatterns

        patterns = APIPatterns()

        # Get all critical APIs
        critical_apis = patterns.get_by_severity("critical")
        assert len(critical_apis) > 0
        assert "CreateRemoteThread" in critical_apis


class TestCryptoPatterns:
    """Test crypto pattern detection."""

    def test_crypto_pattern_detection(self):
        """Test detecting crypto patterns in context."""
        from src.utils.patterns import CryptoPatterns

        patterns = CryptoPatterns()

        # Mock context with crypto constants
        context = {
            "strings": [
                {
                    "address": "0x1000",
                    "value": "67452301efcdab89"  # MD5 constants
                }
            ],
            "functions": [
                {
                    "name": "aes_encrypt",
                    "address": "0x2000"
                }
            ]
        }

        detected = patterns.detect_in_context(context)
        assert len(detected) > 0

        # Should detect MD5 constant
        md5_detected = any(d["algorithm"] == "MD5" for d in detected)
        assert md5_detected

        # Should detect AES function
        aes_detected = any(d["algorithm"] == "AES" for d in detected)
        assert aes_detected


class TestFormatters:
    """Test formatting utilities."""

    def test_format_function_list(self):
        """Test function list formatting."""
        from src.utils.formatters import format_function_list

        functions = [
            {
                "name": "main",
                "address": "0x1000",
                "signature": "int main(int argc, char **argv)"
            },
            {
                "name": "test",
                "address": "0x2000",
                "signature": "void test(void)"
            }
        ]

        result = format_function_list(functions)
        assert "main" in result
        assert "0x1000" in result
        assert "test" in result

    def test_format_iocs(self):
        """Test IOC formatting."""
        from src.utils.formatters import format_iocs

        iocs = {
            "ip_addresses": ["192.168.1.1", "10.0.0.1"],
            "domains": ["example.com"],
            "urls": []
        }

        result = format_iocs(iocs)
        assert "192.168.1.1" in result
        assert "example.com" in result

    def test_truncate_string(self):
        """Test string truncation."""
        from src.utils.formatters import truncate_string

        long_string = "a" * 200
        truncated = truncate_string(long_string, 100)
        assert len(truncated) == 100
        assert truncated.endswith("...")

        short_string = "short"
        truncated = truncate_string(short_string, 100)
        assert truncated == "short"

    def test_format_bytes(self):
        """Test byte formatting."""
        from src.utils.formatters import format_bytes

        assert "1.0 KB" in format_bytes(1024)
        assert "1.0 MB" in format_bytes(1024 * 1024)
        assert "500.0 B" in format_bytes(500)


@pytest.fixture
def mock_context():
    """Provide a mock Ghidra analysis context."""
    return {
        "metadata": {
            "name": "test_binary",
            "executable_format": "PE",
            "language": "x86:LE:64:default",
            "compiler": "gcc",
            "image_base": "0x400000"
        },
        "functions": [
            {
                "name": "main",
                "address": "0x401000",
                "signature": "int main(int argc, char **argv)",
                "is_thunk": False,
                "is_external": False,
                "parameters": [],
                "local_variables": [],
                "called_functions": [
                    {"name": "printf", "address": "0x402000"}
                ],
                "pseudocode": "int main(void) {\n  printf(\"Hello\");\n  return 0;\n}",
                "basic_blocks": []
            }
        ],
        "imports": [
            {
                "library": "kernel32.dll",
                "name": "CreateProcess",
                "address": "0x403000"
            }
        ],
        "strings": [
            {
                "address": "0x404000",
                "value": "Hello, World!",
                "length": 13,
                "type": "unicode",
                "xrefs": [
                    {"from": "0x401000", "type": "READ"}
                ]
            }
        ],
        "memory_map": [
            {
                "name": ".text",
                "start": "0x401000",
                "end": "0x402000",
                "size": 4096,
                "read": True,
                "write": False,
                "execute": True,
                "initialized": True
            }
        ],
        "data_types": {
            "structures": [],
            "enums": []
        }
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
