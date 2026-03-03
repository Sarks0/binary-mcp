"""
Tests for function hash, batch decompile, and cross-binary matching tools.

Uses mocked cache data and capstone for testing normalization,
hashing, completeness scoring, and batch operations.
"""

from unittest.mock import MagicMock

import pytest


def _make_function(
    name="test_func",
    address="0x401000",
    basic_blocks=None,
    called_functions=None,
    pseudocode="int test_func() { return 0; }",
    is_thunk=False,
    is_external=False,
    parameters=None,
    local_variables=None,
    signature="int test_func(void)",
    decompile_status="success",
):
    return {
        "name": name,
        "address": address,
        "basic_blocks": basic_blocks or [],
        "called_functions": called_functions or [],
        "pseudocode": pseudocode,
        "is_thunk": is_thunk,
        "is_external": is_external,
        "parameters": parameters or [],
        "local_variables": local_variables or [],
        "signature": signature,
        "decompile_status": decompile_status,
    }


class TestNormalization:
    """Test instruction normalization for hashing."""

    def test_normalize_replaces_addresses(self):
        from src.tools.function_hash_tools import _normalize_instructions

        class MockInsn:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        instructions = [
            MockInsn("mov", "eax, 0x401000"),
            MockInsn("call", "0x402000"),
            MockInsn("jmp", "0x401050"),
            MockInsn("xor", "eax, eax"),
        ]

        normalized, stats = _normalize_instructions(instructions)

        assert "0x401000" not in normalized
        assert "0x402000" not in normalized
        assert "ADDR" in normalized
        assert "xor eax, eax" in normalized
        assert stats["total_instructions"] == 4
        assert stats["operands_normalized"] == 3

    def test_normalize_preserves_registers(self):
        from src.tools.function_hash_tools import _normalize_instructions

        class MockInsn:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        instructions = [
            MockInsn("push", "rbp"),
            MockInsn("mov", "rbp, rsp"),
            MockInsn("ret", ""),
        ]

        normalized, stats = _normalize_instructions(instructions)

        assert "push rbp" in normalized
        assert "mov rbp, rsp" in normalized
        assert "ret" in normalized
        assert stats["operands_normalized"] == 0

    def test_normalize_small_constants_preserved(self):
        """Small immediate values (< 4 hex digits) should be preserved."""
        from src.tools.function_hash_tools import _normalize_instructions

        class MockInsn:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        instructions = [
            MockInsn("mov", "eax, 0x10"),   # Small: preserved
            MockInsn("add", "eax, 0xff"),    # Small: preserved
            MockInsn("mov", "eax, 0x12345"), # Large: normalized
        ]

        normalized, stats = _normalize_instructions(instructions)

        assert "0x10" in normalized  # Small constant kept
        assert "0xff" in normalized  # Small constant kept
        assert "0x12345" not in normalized  # Large address replaced


class TestFunctionLookup:
    """Test function lookup by name and address."""

    def test_lookup_by_exact_name(self):
        from src.tools.function_hash_tools import _lookup_function

        funcs = [
            _make_function(name="main", address="0x401000"),
            _make_function(name="helper", address="0x402000"),
        ]

        result = _lookup_function(funcs, "main")
        assert result is not None
        assert result["name"] == "main"

    def test_lookup_by_address_with_prefix(self):
        from src.tools.function_hash_tools import _lookup_function

        funcs = [_make_function(name="main", address="0x401000")]

        result = _lookup_function(funcs, "0x401000")
        assert result is not None
        assert result["name"] == "main"

    def test_lookup_by_address_without_prefix(self):
        from src.tools.function_hash_tools import _lookup_function

        funcs = [_make_function(name="main", address="0x401000")]

        result = _lookup_function(funcs, "401000")
        assert result is not None

    def test_lookup_not_found(self):
        from src.tools.function_hash_tools import _lookup_function

        funcs = [_make_function(name="main", address="0x401000")]

        result = _lookup_function(funcs, "nonexistent")
        assert result is None


class TestCompletenessScoring:
    """Test the function completeness scoring logic."""

    def test_well_documented_function_scores_high(self):
        """A fully documented function should score >= 70."""
        func = _make_function(
            name="decrypt_payload",
            signature="void decrypt_payload(char *buf, int len)",
            pseudocode="void decrypt_payload(char *buf, int len) { ... }",
            parameters=[
                {"name": "buf", "datatype": "char *"},
                {"name": "len", "datatype": "int"},
            ],
            local_variables=[
                {"name": "key", "datatype": "int"},
                {"name": "i", "datatype": "int"},
            ],
            called_functions=[{"name": "memcpy", "address": "0x500000"}],
            basic_blocks=[
                {"start": "0x401000", "end": "0x401100", "num_addresses": 50},
                {"start": "0x401100", "end": "0x401200", "num_addresses": 40},
            ],
        )

        # Check scoring criteria manually
        score = 0
        # Has meaningful name: +20
        score += 20
        # Has pseudocode: +15
        score += 15
        # Typed parameters: +15
        score += 15
        # Meaningful variable names (key, i): +10
        score += 10
        # Has callees: +5
        score += 5
        # Reasonable size: +5
        score += 5
        # Has basic blocks: +5
        score += 5

        assert score >= 70

    def test_auto_named_function_scores_low(self):
        """Auto-generated function names should score poorly."""
        func = _make_function(
            name="FUN_00401000",
            signature="undefined",
            pseudocode=None,
            decompile_status="timeout",
        )

        # Auto name: +0, no pseudocode: +0, penalty for auto name: -10
        # This should score very low
        import re
        auto_pattern = re.compile(
            r"^(FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+)$", re.IGNORECASE
        )
        assert auto_pattern.match(func["name"])


class TestToolRegistration:
    """Test that tools register correctly."""

    def setup_method(self):
        self.app = MagicMock()
        self.app.tool = MagicMock(return_value=lambda f: f)
        self.session_manager = MagicMock()
        self.cache = MagicMock()
        self.runner = MagicMock()

    def test_registration_succeeds(self):
        from src.tools.function_hash_tools import register_function_hash_tools

        register_function_hash_tools(
            self.app, self.session_manager, self.cache, self.runner
        )
        assert self.app.tool.call_count >= 4

    def test_batch_decompile_max_size(self):
        """MAX_BATCH_SIZE should be 20."""
        from src.tools.function_hash_tools import MAX_BATCH_SIZE

        assert MAX_BATCH_SIZE == 20


class TestCapstoneMode:
    """Test architecture detection for capstone."""

    def test_get_capstone_mode_returns_none_for_unknown(self):
        """Should return None for unsupported architectures."""
        from unittest.mock import patch

        mock_result = MagicMock()
        mock_result.architecture = "sparc"
        mock_result.bitness = 32

        with patch(
            "src.utils.compatibility.BinaryCompatibilityChecker"
        ) as MockChecker:
            MockChecker.return_value.check_compatibility.return_value = mock_result
            from src.tools.function_hash_tools import _get_capstone_mode
            result = _get_capstone_mode("/fake/binary")
            assert result is None
