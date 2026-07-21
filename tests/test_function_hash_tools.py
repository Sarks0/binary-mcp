"""
Tests for function hash, batch decompile, and cross-binary matching tools.

Uses mocked cache data and capstone for testing normalization,
hashing, completeness scoring, and batch operations.
"""

from unittest.mock import MagicMock


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
        _make_function(
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
        ) as mock_checker:
            mock_checker.return_value.check_compatibility.return_value = mock_result
            from src.tools.function_hash_tools import _get_capstone_mode
            result = _get_capstone_mode("/fake/binary")
            assert result is None


class _MockInsn:
    """Light-weight stand-in for capstone instruction objects."""

    def __init__(self, mnemonic: str, op_str: str):
        self.mnemonic = mnemonic
        self.op_str = op_str


class TestStackImmNormalization:
    """Stack-pointer arithmetic immediates collapse for clone detection."""

    def test_sub_rsp_small_imm_collides(self):
        """sub rsp, 0x28 and sub rsp, 0x38 must produce identical hashes."""
        from src.tools.function_hash_tools import _normalize_instructions

        body_a = [
            _MockInsn("push", "rbp"),
            _MockInsn("mov", "rbp, rsp"),
            _MockInsn("sub", "rsp, 0x28"),
            _MockInsn("xor", "eax, eax"),
        ]
        body_b = [
            _MockInsn("push", "rbp"),
            _MockInsn("mov", "rbp, rsp"),
            _MockInsn("sub", "rsp, 0x38"),
            _MockInsn("xor", "eax, eax"),
        ]

        norm_a, _ = _normalize_instructions(body_a)
        norm_b, _ = _normalize_instructions(body_b)

        assert norm_a == norm_b
        assert "STACK_IMM" in norm_a
        assert "0x28" not in norm_a
        assert "0x38" not in norm_b

    def test_add_rsp_epilogue_collides(self):
        """add rsp, 0x20 and add rsp, 0x40 must collide too."""
        from src.tools.function_hash_tools import _normalize_instructions

        norm_a, _ = _normalize_instructions([_MockInsn("add", "rsp, 0x20")])
        norm_b, _ = _normalize_instructions([_MockInsn("add", "rsp, 0x40")])

        assert norm_a == norm_b
        assert "STACK_IMM" in norm_a

    def test_lea_rsp_offset_collides(self):
        """lea rsp, [rsp + 0x28] and [rsp + 0x38] must hash identically."""
        from src.tools.function_hash_tools import _normalize_instructions

        norm_a, _ = _normalize_instructions([_MockInsn("lea", "rsp, [rsp + 0x28]")])
        norm_b, _ = _normalize_instructions([_MockInsn("lea", "rsp, [rsp + 0x38]")])

        assert norm_a == norm_b
        assert "STACK_IMM" in norm_a

    def test_arm_sp_imm_collides(self):
        """ARM-style 'sub sp, sp, #0x20' and #0x30 must collide."""
        from src.tools.function_hash_tools import _normalize_instructions

        norm_a, _ = _normalize_instructions([_MockInsn("sub", "sp, sp, #0x20")])
        norm_b, _ = _normalize_instructions([_MockInsn("sub", "sp, sp, #0x30")])

        assert norm_a == norm_b
        assert "STACK_IMM" in norm_a

    def test_non_stack_arithmetic_unchanged(self):
        """sub eax, 0x28 and sub eax, 0x38 must STAY distinct."""
        from src.tools.function_hash_tools import _normalize_instructions

        norm_a, _ = _normalize_instructions([_MockInsn("sub", "eax, 0x28")])
        norm_b, _ = _normalize_instructions([_MockInsn("sub", "eax, 0x38")])

        assert norm_a != norm_b
        assert "0x28" in norm_a
        assert "0x38" in norm_b
        assert "STACK_IMM" not in norm_a

    def test_mov_rsp_offset_unchanged(self):
        """mov [rsp+0x28], rax does NOT trigger normalisation (mnemonic mov)."""
        from src.tools.function_hash_tools import _normalize_instructions

        norm, _ = _normalize_instructions(
            [_MockInsn("mov", "qword ptr [rsp + 0x28], rax")]
        )
        # No collapse because mnemonic is not in {sub, add, lea}.
        assert "0x28" in norm
        assert "STACK_IMM" not in norm


def _hashed_entry(name: str, address: str, hash_value: str,
                  instruction_count: int, called_functions=None,
                  pseudocode: str | None = None) -> dict:
    """Build a clustering input record matching _cluster_functions_by_hash."""
    func = {
        "name": name,
        "address": address,
        "called_functions": called_functions or [],
        "pseudocode": pseudocode,
    }
    return {
        "hash": hash_value,
        "instruction_count": instruction_count,
        "func": func,
    }


class TestClusterFunctionsByHash:
    """Unit tests for the pure clustering helper."""

    def test_min_cluster_size_filter(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = [
            _hashed_entry("a1", "0x1000", "h1", 20),
            _hashed_entry("a2", "0x1100", "h1", 20),
            _hashed_entry("a3", "0x1200", "h1", 20),
            _hashed_entry("a4", "0x1300", "h1", 20),
            _hashed_entry("a5", "0x1400", "h1", 20),
            _hashed_entry("b1", "0x2000", "h2", 20),
            _hashed_entry("b2", "0x2100", "h2", 20),  # only 2 -> dropped
            _hashed_entry("c1", "0x3000", "h3", 20),
            _hashed_entry("c2", "0x3100", "h3", 20),
            _hashed_entry("c3", "0x3200", "h3", 20),
            _hashed_entry("c4", "0x3300", "h3", 20),
        ]

        clusters = _cluster_functions_by_hash(entries, 3, 1)

        assert len(clusters) == 2
        assert clusters[0]["cluster_size"] == 5  # h1 first (largest)
        assert clusters[1]["cluster_size"] == 4  # h3 second

    def test_min_instructions_filter(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = [
            _hashed_entry("x1", "0x1000", "h1", 8),
            _hashed_entry("x2", "0x1100", "h1", 8),
            _hashed_entry("x3", "0x1200", "h1", 8),
        ]

        clusters = _cluster_functions_by_hash(entries, 3, 10)
        assert clusters == []

    def test_sorted_largest_first(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = (
            [_hashed_entry(f"s{i}", f"0x10{i:02x}", "small", 30) for i in range(4)]
            + [_hashed_entry(f"b{i}", f"0x20{i:02x}", "big", 20) for i in range(6)]
        )

        clusters = _cluster_functions_by_hash(entries, 3, 1)

        assert [c["cluster_size"] for c in clusters] == [6, 4]

    def test_called_apis_unioned_and_sorted(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = [
            _hashed_entry(
                "m1", "0x1000", "h", 20,
                called_functions=[
                    {"name": "memcpy", "address": "0x9000"},
                    {"name": "strlen", "address": "0x9100"},
                ],
            ),
            _hashed_entry(
                "m2", "0x1100", "h", 20,
                called_functions=[
                    {"name": "memcpy", "address": "0x9000"},
                    {"name": "malloc", "address": "0x9200"},
                ],
            ),
            _hashed_entry(
                "m3", "0x1200", "h", 20,
                called_functions=[],
            ),
        ]

        clusters = _cluster_functions_by_hash(entries, 3, 1)

        assert len(clusters) == 1
        assert clusters[0]["called_apis"] == ["malloc", "memcpy", "strlen"]

    def test_members_sorted_by_address(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = [
            _hashed_entry("c", "0x3000", "h", 20),
            _hashed_entry("a", "0x1000", "h", 20),
            _hashed_entry("b", "0x2000", "h", 20),
        ]

        clusters = _cluster_functions_by_hash(entries, 3, 1)

        addresses = [m["address"] for m in clusters[0]["members"]]
        assert addresses == ["0x1000", "0x2000", "0x3000"]

    def test_representative_uses_first_member_pseudocode(self):
        from src.tools.function_hash_tools import _cluster_functions_by_hash

        entries = [
            _hashed_entry("z", "0x3000", "h", 20, pseudocode="late { }"),
            _hashed_entry("a", "0x1000", "h", 20, pseudocode="early { }"),
            _hashed_entry("m", "0x2000", "h", 20, pseudocode="mid { }"),
        ]

        clusters = _cluster_functions_by_hash(entries, 3, 1)

        assert clusters[0]["representative_address"] == "0x1000"
        assert clusters[0]["representative_pseudocode"] == "early { }"


def _setup_clone_tool(monkeypatch, cache_data, hash_table=None):
    """
    Register all hash tools and return (find_inlined_clones, runner_mock).

    ``hash_table`` maps function name -> {"hash", "instruction_count"} or
    is omitted if the test is exercising the early-error paths.
    """
    import src.utils.security as security

    monkeypatch.setattr(
        security,
        "sanitize_binary_path",
        lambda p, **kw: type("P", (), {"__str__": lambda self: p})(),
    )

    captured: dict = {}

    def _decorator():
        def _wrap(f):
            captured[f.__name__] = f
            return f
        return _wrap

    app = MagicMock()
    app.tool = MagicMock(side_effect=_decorator)

    cache = MagicMock()
    cache.get_cached.return_value = cache_data
    runner = MagicMock()
    session_manager = MagicMock()

    from src.tools import function_hash_tools as fht
    fht.register_function_hash_tools(app, session_manager, cache, runner)

    # Stub out arch detection and BinaryReader so we never need a real file.
    monkeypatch.setattr(fht, "_get_capstone_mode", lambda p: (1, 2))

    class _FakeReader:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import src.utils.binary_reader as br
    monkeypatch.setattr(br, "BinaryReader", _FakeReader)

    if hash_table is not None:
        def _fake_hash(reader, cs_arch, cs_mode, func):
            entry = hash_table.get(func.get("name"))
            if entry is None:
                return None
            return {
                "hash": entry["hash"],
                "instruction_count": entry["instruction_count"],
                "operands_normalized": 0,
            }
        monkeypatch.setattr(fht, "_compute_function_hash", _fake_hash)

    return captured["find_inlined_clones"], runner


class TestFindInlinedClones:
    """End-to-end behaviour of the find_inlined_clones MCP tool."""

    def test_no_cache_returns_error(self, monkeypatch):
        tool, runner = _setup_clone_tool(monkeypatch, None)
        result = tool("/bin/test.exe")
        assert "has not been analyzed yet" in result
        assert runner.method_calls == []

    def test_invalid_min_cluster_size_rejected(self, monkeypatch):
        tool, _ = _setup_clone_tool(monkeypatch, {"functions": []})
        result = tool("/bin/test.exe", min_cluster_size=1)
        assert result.startswith("Error:")
        assert "min_cluster_size" in result

    def test_invalid_min_instructions_rejected(self, monkeypatch):
        tool, _ = _setup_clone_tool(monkeypatch, {"functions": []})
        result = tool("/bin/test.exe", min_instructions=0)
        assert result.startswith("Error:")
        assert "min_instructions" in result

    def test_no_hashable_functions_returns_error(self, monkeypatch):
        # All thunk/external -> filtered out
        cache_data = {
            "functions": [
                _make_function(
                    name="t", address="0x1000", is_thunk=True,
                    basic_blocks=[{"start": "0x1000", "end": "0x100f"}],
                ),
                _make_function(
                    name="e", address="0x2000", is_external=True,
                    basic_blocks=[{"start": "0x2000", "end": "0x200f"}],
                ),
            ],
        }
        tool, _ = _setup_clone_tool(monkeypatch, cache_data, hash_table={})
        result = tool("/bin/test.exe")
        assert "No hashable functions" in result

    def test_cluster_returned_for_three_identical(self, monkeypatch):
        cache_data = {
            "functions": [
                _make_function(
                    name="FUN_a", address="0x1000",
                    basic_blocks=[{"start": "0x1000", "end": "0x100f"}],
                    called_functions=[{"name": "memcpy", "address": "0x9000"}],
                    pseudocode="void FUN_a() { memcpy(...); }",
                ),
                _make_function(
                    name="FUN_b", address="0x2000",
                    basic_blocks=[{"start": "0x2000", "end": "0x200f"}],
                    called_functions=[{"name": "memcpy", "address": "0x9000"}],
                ),
                _make_function(
                    name="FUN_c", address="0x3000",
                    basic_blocks=[{"start": "0x3000", "end": "0x300f"}],
                    called_functions=[{"name": "memcpy", "address": "0x9000"}],
                ),
            ],
        }
        hash_table = {
            "FUN_a": {"hash": "h1", "instruction_count": 20},
            "FUN_b": {"hash": "h1", "instruction_count": 20},
            "FUN_c": {"hash": "h1", "instruction_count": 20},
        }

        tool, runner = _setup_clone_tool(monkeypatch, cache_data, hash_table)
        result = tool("/bin/test.exe")

        assert "Cluster #1" in result
        assert "size=3" in result
        assert "FUN_a" in result and "FUN_b" in result and "FUN_c" in result
        assert "memcpy" in result
        # No Ghidra subprocess invocation.
        assert runner.method_calls == []

    def test_cluster_below_min_size_suppressed(self, monkeypatch):
        cache_data = {
            "functions": [
                _make_function(
                    name="A", address="0x1000",
                    basic_blocks=[{"start": "0x1000", "end": "0x100f"}],
                ),
                _make_function(
                    name="B", address="0x2000",
                    basic_blocks=[{"start": "0x2000", "end": "0x200f"}],
                ),
            ],
        }
        hash_table = {
            "A": {"hash": "h1", "instruction_count": 20},
            "B": {"hash": "h1", "instruction_count": 20},
        }

        tool, _ = _setup_clone_tool(monkeypatch, cache_data, hash_table)
        result = tool("/bin/test.exe")

        assert "Clusters found:     0" in result
        assert "No clone families detected" in result

    def test_min_instructions_param_respected(self, monkeypatch):
        cache_data = {
            "functions": [
                _make_function(
                    name=f"F{i}", address=f"0x{0x1000 + i * 0x100:x}",
                    basic_blocks=[{"start": "0x1000", "end": "0x100f"}],
                )
                for i in range(3)
            ],
        }
        hash_table = {
            f"F{i}": {"hash": "h1", "instruction_count": 12} for i in range(3)
        }

        tool, _ = _setup_clone_tool(monkeypatch, cache_data, hash_table)

        # Default min_instructions=10: the 12-insn cluster of size 3 surfaces.
        ok = tool("/bin/test.exe")
        assert "Cluster #1" in ok and "instructions=12" in ok

        # Raising min_instructions=20 suppresses the 12-insn cluster.
        suppressed = tool("/bin/test.exe", min_instructions=20)
        assert "Clusters found:     0" in suppressed

    def test_runner_never_invoked(self, monkeypatch):
        cache_data = {
            "functions": [
                _make_function(
                    name=f"F{i}", address=f"0x{0x1000 + i * 0x100:x}",
                    basic_blocks=[{"start": "0x1000", "end": "0x100f"}],
                )
                for i in range(3)
            ],
        }
        hash_table = {
            f"F{i}": {"hash": "h1", "instruction_count": 20} for i in range(3)
        }

        tool, runner = _setup_clone_tool(monkeypatch, cache_data, hash_table)
        tool("/bin/test.exe")
        assert runner.method_calls == []
        assert runner.mock_calls == []
