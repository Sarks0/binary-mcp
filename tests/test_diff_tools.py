"""
Tests for the cross-binary diff_binaries tool.

Cache-only — uses MagicMock cache and monkey-patches BinaryReader /
_compute_function_hash so no real disk file or capstone invocation is
needed.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _restore_module_globals():
    """
    Restore module-level monkey-patches at the end of every test.

    ``_register`` rewrites ``src.utils.binary_reader.BinaryReader`` so
    unrelated test modules (e.g. ``test_search_bytes``) don't inherit
    the fake reader. ``_compute_function_hash`` and
    ``_get_capstone_mode`` are also patched on ``diff_tools``; they are
    real module attributes (imported at the top of ``diff_tools.py``)
    so we save and restore them too.
    """
    import src.tools.diff_tools as dt
    import src.utils.binary_reader as br

    orig_reader = br.BinaryReader
    orig_hash = dt._compute_function_hash
    orig_mode = dt._get_capstone_mode
    try:
        yield
    finally:
        br.BinaryReader = orig_reader
        dt._compute_function_hash = orig_hash
        dt._get_capstone_mode = orig_mode


def _make_function(
    name="func",
    address="0x1000",
    pseudocode="int func() { return 0; }",
    name_source="USER_DEFINED",
    parameters=None,
    called_functions=None,
    basic_blocks=None,
    is_thunk=False,
    is_external=False,
):
    return {
        "name": name,
        "address": address,
        "pseudocode": pseudocode,
        "name_source": name_source,
        "parameters": parameters or [],
        "called_functions": called_functions or [],
        "basic_blocks": basic_blocks or [{"start": address, "end": address, "num_addresses": 8}],
        "is_thunk": is_thunk,
        "is_external": is_external,
        "signature": f"int {name}()",
        "decompile_status": "success",
    }


def _make_context(functions=None, xrefs_to_function=None, name="bin.exe"):
    ctx = {
        "metadata": {"name": name, "executable_format": "PE"},
        "functions": functions or [],
    }
    if xrefs_to_function is not None:
        ctx["xrefs_to_function"] = xrefs_to_function
    return ctx


def _register(monkeypatch, old_ctx, new_ctx, hash_table=None):
    """Register diff tool. ``hash_table`` maps function ``name`` → hash str.

    All module-attribute mutations go through ``monkeypatch.setattr`` so
    they auto-restore at test teardown. Direct assignment leaks across
    pytest's alphabetical test ordering -- a fake ``BinaryReader`` from
    this file would otherwise survive into ``tests/test_search_bytes.py``
    and break it.
    """
    from src.tools import diff_tools

    captured: dict = {}

    def _decorator():
        def _wrap(f):
            captured[f.__name__] = f
            return f

        return _wrap

    app = MagicMock()
    app.tool = MagicMock(side_effect=_decorator)
    cache = MagicMock()

    def _get_cached(p):
        if p == "/old.bin":
            return old_ctx
        if p == "/new.bin":
            return new_ctx
        return None

    cache.get_cached.side_effect = _get_cached
    runner = MagicMock()
    session_manager = MagicMock()

    # Stub sanitize so we don't need a real file on disk.
    import src.utils.security as security

    monkeypatch.setattr(
        security,
        "sanitize_binary_path",
        lambda p, **kw: type("P", (), {"__str__": lambda self: p})(),
    )
    diff_tools.register_diff_tools(app, session_manager, cache, runner)

    # Force capstone mode resolution to a fixed pair so we never touch a
    # real file. Hashing is mocked too — _hash_functions and
    # _confirm_phase1_buckets both call _compute_function_hash directly.
    import src.tools.diff_tools as dt

    monkeypatch.setattr(dt, "_get_capstone_mode", lambda p: (1, 2))

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
                "hash": entry,
                "instruction_count": 10,
                "operands_normalized": 0,
            }

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

    return captured["diff_binaries"], cache, runner


class TestPdbNamePredicate:
    def test_pdb_named_accepts_named_with_user_defined_source(self):
        from src.tools.diff_tools import _is_pdb_named

        assert _is_pdb_named(_make_function(name="CryptDecrypt", name_source="USER_DEFINED"))

    def test_pdb_named_rejects_fun_prefix(self):
        from src.tools.diff_tools import _is_pdb_named

        assert not _is_pdb_named(_make_function(name="FUN_00401000", name_source="USER_DEFINED"))

    def test_pdb_named_rejects_default_source(self):
        from src.tools.diff_tools import _is_pdb_named

        assert not _is_pdb_named(_make_function(name="CryptDecrypt", name_source="DEFAULT"))

    def test_pdb_named_accepts_imported_source(self):
        from src.tools.diff_tools import _is_pdb_named

        assert _is_pdb_named(_make_function(name="memcpy", name_source="IMPORTED"))

    def test_pdb_named_rejects_thunk_prefix(self):
        from src.tools.diff_tools import _is_pdb_named

        assert not _is_pdb_named(
            _make_function(name="thunk_FUN_00401000", name_source="USER_DEFINED")
        )

    def test_pdb_named_accepts_lowercase_fun_prefix_with_non_hex_suffix(self):
        """Regression: ultrareview bug_003. Drop redundant `FUN_.*` alternative
        from _AUTO_NAME_RE so legitimate user symbols starting with 'fun_' or
        'Fun_' (e.g. `fun_init`, `fun_facts`, `Fun_Test`) aren't misclassified
        as Ghidra auto-generated. Real auto-names are FUN_<hex> only."""
        from src.tools.diff_tools import _is_pdb_named

        for legit_name in ("fun_init", "fun_facts", "Fun_Test", "FUN_NaN"):
            assert _is_pdb_named(
                _make_function(name=legit_name, name_source="USER_DEFINED")
            ), f"{legit_name} should be treated as a PDB-named function"


class TestPairingByPdbName:
    def test_one_added_one_removed_one_modified(self, monkeypatch):
        old_ctx = _make_context(
            functions=[
                _make_function(name="kept_unchanged", address="0x1000"),
                _make_function(name="kept_modified", address="0x2000"),
                _make_function(name="will_be_removed", address="0x3000"),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(name="kept_unchanged", address="0x1000"),
                _make_function(
                    name="kept_modified",
                    address="0x2050",
                    pseudocode="int kept_modified() { return 1; }",
                ),
                _make_function(name="newly_added", address="0x4000"),
            ],
        )

        # Phase 1's confirm step calls _compute_function_hash separately
        # on the OLD then NEW reader; map each name to a (old_hash,
        # new_hash) tuple and dispatch by call order so kept_unchanged
        # matches on both sides while kept_modified diverges.
        per_side = {
            "kept_unchanged": ("h_unchanged", "h_unchanged"),
            "kept_modified": ("h_old", "h_new"),
        }

        tool, _cache, runner = _register(monkeypatch, old_ctx, new_ctx)

        # Replace the hash function with the per-side variant.
        import src.tools.diff_tools as dt

        call_counts: dict[str, int] = {}

        def _fake_hash(reader, cs_arch, cs_mode, func):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            # First call for this name uses old, second uses new.
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            h = entry[min(count, len(entry) - 1)]
            return {"hash": h, "instruction_count": 10, "operands_normalized": 0}

        dt._compute_function_hash = _fake_hash

        result = tool("/old.bin", "/new.bin")

        assert "ADDED (1)" in result
        assert "newly_added" in result
        assert "REMOVED (1)" in result
        assert "will_be_removed" in result
        assert "MODIFIED (1)" in result
        assert "kept_modified" in result
        # Unchanged pair is reported as count, not as a section row.
        assert "Unchanged pairs: 1" in result
        # Cache-only contract.
        assert runner.method_calls == []


class TestSecurityRanking:
    def test_bounds_check_addition_ranks_above_cosmetic_rename(self, monkeypatch):
        # Two modified-pending pairs through phase 1: one with new bounds
        # check, one with no body change beyond a comment-equivalent
        # rename.
        old_ctx = _make_context(
            functions=[
                _make_function(
                    name="A_mod",
                    address="0x1000",
                    pseudocode="int A_mod() { return 0; }",
                ),
                _make_function(
                    name="B_mod",
                    address="0x2000",
                    pseudocode="int B_mod() { return 0; }",
                ),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="A_mod",
                    address="0x1000",
                    pseudocode=(
                        "int A_mod(int n) {\n"
                        "  if (n < limit) {\n"
                        "    return n;\n"
                        "  }\n"
                        "  return 0;\n"
                        "}\n"
                    ),
                ),
                _make_function(
                    name="B_mod",
                    address="0x2050",
                    pseudocode="int B_mod() { return 1; }",
                ),
            ],
        )
        per_side = {
            "A_mod": ("h_A_old", "h_A_new"),
            "B_mod": ("h_B_old", "h_B_new"),
        }

        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)

        import src.tools.diff_tools as dt

        call_counts: dict[str, int] = {}

        def _fake_hash(reader, cs_arch, cs_mode, func):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            h = entry[min(count, len(entry) - 1)]
            return {"hash": h, "instruction_count": 10, "operands_normalized": 0}

        dt._compute_function_hash = _fake_hash

        result = tool("/old.bin", "/new.bin", mode="security")

        assert "MODIFIED (2)" in result
        # Find positions of A_mod and B_mod in the report; the one that
        # added bounds checks should appear FIRST.
        a_pos = result.index("A_mod (")
        b_pos = result.index("B_mod (")
        assert a_pos < b_pos
        assert "bounds_delta=+1" in result


class TestModeNoneOrdering:
    def test_mode_none_does_not_score(self, monkeypatch):
        old_ctx = _make_context(
            functions=[
                _make_function(name="A_mod", address="0x1000"),
                _make_function(name="B_mod", address="0x2000"),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="A_mod",
                    address="0x1000",
                    pseudocode=("int A_mod() { if (n < limit) return 1; return 0; }"),
                ),
                _make_function(
                    name="B_mod",
                    address="0x2050",
                    pseudocode="int B_mod() { return 1; }",
                ),
            ],
        )
        per_side = {
            "A_mod": ("ha_old", "ha_new"),
            "B_mod": ("hb_old", "hb_new"),
        }

        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)

        import src.tools.diff_tools as dt

        call_counts: dict[str, int] = {}

        def _fake_hash(reader, cs_arch, cs_mode, func):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            return {
                "hash": entry[min(count, len(entry) - 1)],
                "instruction_count": 10,
                "operands_normalized": 0,
            }

        dt._compute_function_hash = _fake_hash

        result = tool("/old.bin", "/new.bin", mode="none")

        # Score should be reported as 0.0 when mode=none.
        assert "score=0.0" in result
        # bounds_delta should be 0 when mode=none.
        assert "bounds_delta=+0" in result


class TestAslrShiftedAddresses:
    def test_pdb_pairing_works_with_shifted_addresses(self, monkeypatch):
        old_ctx = _make_context(
            functions=[
                _make_function(name="A", address="0x1000"),
                _make_function(name="B", address="0x2000"),
            ],
        )
        # New binary has same names with addresses shifted by ASLR slide.
        new_ctx = _make_context(
            functions=[
                _make_function(name="A", address="0x100001000"),
                _make_function(name="B", address="0x100002000"),
            ],
        )
        per_side = {
            "A": ("ha", "ha"),  # unchanged
            "B": ("hb_old", "hb_new"),  # modified
        }

        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)

        import src.tools.diff_tools as dt

        call_counts: dict[str, int] = {}

        def _fake_hash(reader, cs_arch, cs_mode, func):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            return {
                "hash": entry[min(count, len(entry) - 1)],
                "instruction_count": 10,
                "operands_normalized": 0,
            }

        dt._compute_function_hash = _fake_hash

        result = tool("/old.bin", "/new.bin")

        # Both names paired; nothing in ADDED/REMOVED.
        assert "ADDED (0)" in result
        assert "REMOVED (0)" in result
        # B is modified; A is unchanged.
        assert "MODIFIED (1)" in result
        assert "Unchanged pairs: 1" in result
        # The new address is reported on the right of the arrow.
        assert "→  B (0x100002000)" in result


class TestPhase2HashRename:
    def test_unrelated_names_paired_via_hash(self, monkeypatch):
        # Both functions are FUN_-named so they fail PDB-name pairing,
        # but their bodies hash identically -> phase-2 pairs them.
        old_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00401000",
                    address="0x401000",
                    name_source="DEFAULT",
                ),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00501000",
                    address="0x501000",
                    name_source="DEFAULT",
                ),
            ],
        )
        hash_table = {
            "FUN_00401000": "h_same",
            "FUN_00501000": "h_same",
        }
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx, hash_table=hash_table)
        result = tool("/old.bin", "/new.bin")

        assert "MODIFIED (1)" in result
        assert "[renamed]" in result


class TestPhase3CalleeMatch:
    def test_jaccard_above_threshold_pairs(self, monkeypatch):
        # Two FUN_ functions, identical callee sets, identical bb count.
        callees = [{"name": "memcpy", "address": "0xa00"}, {"name": "free", "address": "0xb00"}]
        old_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00401000",
                    address="0x401000",
                    name_source="DEFAULT",
                    called_functions=callees,
                    basic_blocks=[
                        {"start": "0x401000", "end": "0x401040", "num_addresses": 0x40},
                        {"start": "0x401040", "end": "0x401080", "num_addresses": 0x40},
                    ],
                ),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00501000",
                    address="0x501000",
                    name_source="DEFAULT",
                    called_functions=callees,
                    basic_blocks=[
                        {"start": "0x501000", "end": "0x501040", "num_addresses": 0x40},
                        {"start": "0x501040", "end": "0x501080", "num_addresses": 0x40},
                    ],
                ),
            ],
        )
        # Hashes differ so Phase 2 doesn't pair them; Phase 3 does.
        hash_table = {
            "FUN_00401000": "h_old",
            "FUN_00501000": "h_new",
        }
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx, hash_table=hash_table)
        result = tool("/old.bin", "/new.bin")

        assert "MODIFIED (1)" in result
        assert "[modified-renamed]" in result

    def test_jaccard_below_threshold_falls_through_to_added_removed(self, monkeypatch):
        old_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00401000",
                    address="0x401000",
                    name_source="DEFAULT",
                    called_functions=[{"name": "memcpy", "address": "0xa"}],
                    basic_blocks=[{"start": "0x0", "end": "0x10", "num_addresses": 8}],
                ),
            ],
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="FUN_00501000",
                    address="0x501000",
                    name_source="DEFAULT",
                    called_functions=[{"name": "strcpy", "address": "0xb"}],
                    basic_blocks=[{"start": "0x0", "end": "0x10", "num_addresses": 8}],
                ),
            ],
        )
        hash_table = {
            "FUN_00401000": "h_old",
            "FUN_00501000": "h_new",
        }
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx, hash_table=hash_table)
        result = tool("/old.bin", "/new.bin")

        assert "ADDED (1)" in result
        assert "REMOVED (1)" in result
        assert "MODIFIED (0)" in result


class TestCallerDelta:
    def test_caller_delta_uses_xrefs_index(self, monkeypatch):
        # PDB-named A_mod with callers in old=2, new=4 -> delta=+2.
        old_xrefs = {
            "1000": [
                {"from_func_addr": "0x10", "from_func_name": "x"},
                {"from_func_addr": "0x20", "from_func_name": "y"},
            ],
        }
        new_xrefs = {
            "1000": [
                {"from_func_addr": "0x10", "from_func_name": "x"},
                {"from_func_addr": "0x20", "from_func_name": "y"},
                {"from_func_addr": "0x30", "from_func_name": "z"},
                {"from_func_addr": "0x40", "from_func_name": "w"},
            ],
        }
        old_ctx = _make_context(
            functions=[_make_function(name="A_mod", address="0x1000")],
            xrefs_to_function=old_xrefs,
        )
        new_ctx = _make_context(
            functions=[
                _make_function(
                    name="A_mod",
                    address="0x1000",
                    pseudocode="int A_mod() { return 1; }",
                ),
            ],
            xrefs_to_function=new_xrefs,
        )
        per_side = {"A_mod": ("h_old", "h_new")}

        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)

        import src.tools.diff_tools as dt

        call_counts: dict[str, int] = {}

        def _fake_hash(reader, cs_arch, cs_mode, func):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            return {
                "hash": entry[min(count, len(entry) - 1)],
                "instruction_count": 10,
                "operands_normalized": 0,
            }

        dt._compute_function_hash = _fake_hash

        result = tool("/old.bin", "/new.bin")
        assert "callers=+2" in result


class TestCacheMiss:
    def test_old_cache_miss(self, monkeypatch):
        old_ctx = None
        new_ctx = _make_context(functions=[_make_function()])
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)
        result = tool("/old.bin", "/new.bin")
        assert "Old binary" in result
        assert "has not been analyzed yet" in result

    def test_new_cache_miss(self, monkeypatch):
        old_ctx = _make_context(functions=[_make_function()])
        new_ctx = None
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)
        result = tool("/old.bin", "/new.bin")
        assert "New binary" in result
        assert "has not been analyzed yet" in result

    def test_invalid_mode(self, monkeypatch):
        old_ctx = _make_context(functions=[_make_function()])
        new_ctx = _make_context(functions=[_make_function()])
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)
        result = tool("/old.bin", "/new.bin", mode="bogus")
        assert "Error: mode" in result

    def test_invalid_group_by(self, monkeypatch):
        old_ctx = _make_context(functions=[_make_function()])
        new_ctx = _make_context(functions=[_make_function()])
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx)
        result = tool("/old.bin", "/new.bin", group_by="garbage")
        assert "Error: group_by" in result


class TestRegistration:
    def test_registers_one_tool(self):
        from src.tools.diff_tools import register_diff_tools

        app = MagicMock()
        app.tool = MagicMock(return_value=lambda f: f)
        cache = MagicMock()
        runner = MagicMock()
        session_manager = MagicMock()

        result = register_diff_tools(app, session_manager, cache, runner)

        assert app.tool.call_count >= 1
        assert isinstance(result, tuple) and len(result) == 1
