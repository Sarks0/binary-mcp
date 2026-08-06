"""
Tests for the cross-binary diff_binaries tool.

Cache-only - uses MagicMock cache and monkey-patches BinaryReader /
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
    """Register diff tool. ``hash_table`` maps function ``name`` -> hash str.

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
    # real file. Hashing is mocked too - _hash_functions and
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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            # First call for this name uses old, second uses new.
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            h = entry[min(count, len(entry) - 1)]
            return {"hash": h, "instruction_count": 10, "operands_normalized": 0}

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

        result = tool("/old.bin", "/new.bin")

        assert "ADDED (1)" in result
        assert "newly_added" in result
        assert "REMOVED (1)" in result
        assert "will_be_removed" in result
        assert "MODIFIED (1)" in result
        assert "kept_modified" in result
        # Unchanged pair is reported as count, not as a section row.
        assert "UNCHANGED 1" in result
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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
            n = func.get("name")
            entry = per_side.get(n)
            if entry is None:
                return None
            count = call_counts.get(n, 0)
            call_counts[n] = count + 1
            h = entry[min(count, len(entry) - 1)]
            return {"hash": h, "instruction_count": 10, "operands_normalized": 0}

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
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

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
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

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

        result = tool("/old.bin", "/new.bin")

        # Both names paired; nothing in ADDED/REMOVED.
        assert "ADDED (0)" in result
        assert "REMOVED (0)" in result
        # B is modified; A is unchanged.
        assert "MODIFIED (1)" in result
        assert "UNCHANGED 1" in result
        # The new address is reported on the right of the arrow.
        assert "->  B (0x100002000)" in result


class TestPhase2HashRename:
    def test_unrelated_names_paired_via_hash(self, monkeypatch):
        # Both functions are FUN_-named so they fail PDB-name pairing,
        # but their bodies hash identically -> phase-2 pairs them. Because
        # the opcode hashes are identical the bodies are functionally
        # equivalent, so the pair belongs in the "Renamed (unchanged body)"
        # bucket - NOT MODIFIED.
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

        assert "MODIFIED (0)" in result
        assert "Renamed (unchanged body) (1)" in result
        assert "[unchanged_renamed]" in result

    def test_same_name_hash_match_is_unchanged_not_modified(self, monkeypatch):
        """Hash-identical pair with the same name is fully unchanged -
        it does not appear in MODIFIED or in the renamed bucket; just
        bump the unchanged counter."""
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
                    name="FUN_00401000",
                    address="0x501000",
                    name_source="DEFAULT",
                ),
            ],
        )
        hash_table = {
            "FUN_00401000": "h_same",  # same name in both contexts maps to same hash
        }
        tool, *_ = _register(monkeypatch, old_ctx, new_ctx, hash_table=hash_table)
        result = tool("/old.bin", "/new.bin")

        assert "MODIFIED (0)" in result
        assert "Renamed (unchanged body) (0)" in result
        assert "UNCHANGED 1" in result


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

        def _fake_hash(reader, cs_arch, cs_mode, func, md=None):
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

        monkeypatch.setattr(dt, "_compute_function_hash", _fake_hash)

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


class TestCoverageExamination:
    """A diff run is a machine pass, so it records on the examination axis --
    and only for the MODIFIED entries, the ones it actually analyses per
    function. Recording the ADDED wall would inflate the ledger by thousands
    on a real Patch-Tuesday diff, which is the same dishonesty as inflating
    the review count, one column over.
    """

    @staticmethod
    def _capture(monkeypatch):
        import src.tools.diff_tools as dt

        calls = []

        def _fake(cache, binary_path, addresses, kind, tool, note=None, context=None):
            addrs = list(addresses)
            calls.append(
                {"path": binary_path, "addresses": addrs, "kind": kind,
                 "tool": tool, "note": note}
            )
            return len(addrs)

        monkeypatch.setattr(dt, "auto_examine", _fake)
        return calls

    @staticmethod
    def _hash_per_address(monkeypatch):
        """Hash by address, so a same-named pair on two sides differs and
        lands in MODIFIED. A name-keyed hash table gives both sides the same
        value, which is the UNCHANGED bucket."""
        import src.tools.diff_tools as dt

        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, a, m, func, md=None: {
                "hash": f"h-{func['address']}", "instruction_count": 1,
                "operands_normalized": 0,
            },
        )

    def _one_modified_one_added(self, monkeypatch):
        """Old has Changed; new has Changed (different body) plus BrandNew."""
        old_ctx = _make_context([
            _make_function(name="Changed", address="0x1000", pseudocode="int f(){return 1;}"),
        ])
        new_ctx = _make_context([
            _make_function(name="Changed", address="0x2000", pseudocode="int f(){return 2;}"),
            _make_function(name="BrandNew", address="0x3000"),
        ])
        self._hash_per_address(monkeypatch)
        return _register(monkeypatch, old_ctx, new_ctx)

    def test_modified_pairs_are_recorded_on_both_sides(self, monkeypatch):
        calls = self._capture(monkeypatch)
        # Distinct hashes per side so the PDB-name pair lands in MODIFIED.
        old_ctx = _make_context([
            _make_function(name="Changed", address="0x1000"),
        ])
        new_ctx = _make_context([
            _make_function(name="Changed", address="0x2000"),
            _make_function(name="BrandNew", address="0x3000"),
        ])
        self._hash_per_address(monkeypatch)
        diff, _cache, _runner = _register(monkeypatch, old_ctx, new_ctx)
        diff(old_path="/old.bin", new_path="/new.bin")

        assert len(calls) == 2
        old_call, new_call = calls
        assert old_call["path"] == "/old.bin"
        assert old_call["addresses"] == ["0x1000"]
        assert new_call["path"] == "/new.bin"
        assert new_call["addresses"] == ["0x2000"]
        assert {c["kind"] for c in calls} == {"diff"}
        assert {c["tool"] for c in calls} == {"diff_binaries"}

    def test_added_functions_are_never_recorded(self, monkeypatch):
        """The ADDED bucket is membership, not analysis. On a real diff it is
        thousands of entries and recording them is how a ledger gets inflated.
        """
        calls = self._capture(monkeypatch)
        diff, _cache, _runner = self._one_modified_one_added(monkeypatch)
        report = diff(old_path="/old.bin", new_path="/new.bin")

        assert "BrandNew" in report, "the added function should still be reported"
        recorded = [a for c in calls for a in c["addresses"]]
        assert "0x3000" not in recorded

    def test_unchanged_pairs_are_never_recorded(self, monkeypatch):
        """Hash-identical means this tool concluded nothing happened."""
        calls = self._capture(monkeypatch)
        old_ctx = _make_context([_make_function(name="Same", address="0x1000")])
        new_ctx = _make_context([_make_function(name="Same", address="0x2000")])
        diff, _cache, _runner = _register(
            monkeypatch, old_ctx, new_ctx, hash_table={"Same": "identical"}
        )
        diff(old_path="/old.bin", new_path="/new.bin")
        assert [a for c in calls for a in c["addresses"]] == []

    def test_record_examination_false_is_a_dry_run(self, monkeypatch):
        calls = self._capture(monkeypatch)
        diff, _cache, _runner = self._one_modified_one_added(monkeypatch)
        report = diff(
            old_path="/old.bin", new_path="/new.bin", record_examination=False
        )
        assert calls == []
        assert "not recorded" in report

    def test_header_states_what_was_written(self, monkeypatch):
        self._capture(monkeypatch)
        diff, _cache, _runner = self._one_modified_one_added(monkeypatch)
        report = diff(old_path="/old.bin", new_path="/new.bin")
        header = report.split("### ADDED")[0]
        assert "Coverage:" in header
        assert "examined is not reviewed" in header

    def test_coverage_failure_cannot_break_the_diff(self, monkeypatch):
        """Coverage is a side effect; a broken ledger must not cost the report.
        The real `auto_examine` runs here against a MagicMock cache."""
        diff, _cache, _runner = self._one_modified_one_added(monkeypatch)
        report = diff(old_path="/old.bin", new_path="/new.bin")
        assert "BINARY DIFF" in report
        assert "### MODIFIED" in report


def _reference_pair_by_callees(old_residue, new_residue):
    """The pre-optimization all-pairs scan, kept verbatim as an oracle.

    Phase 3 decides which functions get reported as security-relevant
    modifications, so the fast path is only acceptable if it is *identical*,
    not merely similar. This is what the equivalence test compares against.
    """
    from src.tools.diff_tools import (
        _CALLEE_JACCARD_THRESHOLD,
        _bb_count,
        _callee_name_set,
        _jaccard,
    )

    by_bb: dict[int, list[dict]] = {}
    for f in new_residue:
        by_bb.setdefault(_bb_count(f), []).append(f)
    pairs, paired_old_ids, paired_new_ids = [], set(), set()
    for of in old_residue:
        candidates = by_bb.get(_bb_count(of), [])
        if not candidates:
            continue
        of_set = _callee_name_set(of)
        if not of_set:
            continue
        best, best_score = None, 0.0
        for nf in candidates:
            if id(nf) in paired_new_ids:
                continue
            nf_set = _callee_name_set(nf)
            if not nf_set:
                continue
            score = _jaccard(of_set, nf_set)
            if score > best_score:
                best_score, best = score, nf
        if best is not None and best_score >= _CALLEE_JACCARD_THRESHOLD:
            pairs.append((of, best))
            paired_old_ids.add(id(of))
            paired_new_ids.add(id(best))
    old_remaining = [f for f in old_residue if id(f) not in paired_old_ids]
    new_remaining = [f for f in new_residue if id(f) not in paired_new_ids]
    return pairs, old_remaining, new_remaining


class TestPhase3Equivalence:
    """The indexed phase-3 must return exactly what the all-pairs scan did."""

    @staticmethod
    def _residue(rng, n, pool, max_bb, max_callees):
        out = []
        for i in range(n):
            a = 0x140001000 + i * 0x40
            out.append(_make_function(
                name=f"FUN_{a:x}", address=f"{a:x}", name_source="DEFAULT",
                called_functions=[{"address": "0", "name": nm}
                                  for nm in rng.sample(pool, rng.randint(0, max_callees))],
                basic_blocks=[{"start": f"{a:x}", "end": f"{a + 15:x}",
                               "num_addresses": 16}
                              for _ in range(rng.randint(1, max_bb))],
            ))
        return out

    @pytest.mark.parametrize("trial", range(60))
    def test_matches_the_all_pairs_scan(self, trial):
        import random

        from src.tools.diff_tools import _pair_by_callees

        rng = random.Random(trial)
        # Vary the shape hard. A tiny callee pool forces heavy overlap and
        # exact-score ties; a single bb value forces one enormous bucket --
        # both are where an index-based candidate filter would diverge if the
        # pruning were merely a heuristic.
        pool = [f"api_{i}" for i in range(rng.choice([3, 6, 20, 200]))]
        max_bb = rng.choice([1, 2, 5, 30])
        max_callees = min(len(pool), rng.choice([1, 3, 8, 20]))
        old = self._residue(rng, rng.randint(0, 60), pool, max_bb, max_callees)
        new = self._residue(rng, rng.randint(0, 60), pool, max_bb, max_callees)

        exp_pairs, exp_old, exp_new = _reference_pair_by_callees(old, new)
        got_pairs, got_old, got_new = _pair_by_callees(old, new)

        addr = lambda fs: [f["address"] for f in fs]  # noqa: E731
        assert [(a["address"], b["address"]) for a, b in got_pairs] == \
               [(a["address"], b["address"]) for a, b in exp_pairs]
        assert addr(got_old) == addr(exp_old)
        assert addr(got_new) == addr(exp_new)

    def test_ties_still_go_to_the_earliest_candidate(self):
        """Two identical candidates: the scan took the first in bucket order,
        and the index must not reorder that."""
        from src.tools.diff_tools import _pair_by_callees

        callees = [{"address": "0", "name": n} for n in ("a", "b", "c", "d")]
        old = [_make_function(name="FUN_1", address="0x1000",
                              name_source="DEFAULT", called_functions=callees)]
        new = [
            _make_function(name="FUN_first", address="0x2000",
                           name_source="DEFAULT", called_functions=callees),
            _make_function(name="FUN_second", address="0x3000",
                           name_source="DEFAULT", called_functions=callees),
        ]
        pairs, _, _ = _pair_by_callees(old, new)
        assert [b["address"] for _, b in pairs] == ["0x2000"]

    def test_a_new_function_is_only_paired_once(self):
        from src.tools.diff_tools import _pair_by_callees

        callees = [{"address": "0", "name": n} for n in ("a", "b", "c", "d")]
        old = [_make_function(name=f"FUN_{i}", address=f"0x{i}000",
                              name_source="DEFAULT", called_functions=callees)
               for i in (1, 2)]
        new = [_make_function(name="FUN_only", address="0x9000",
                              name_source="DEFAULT", called_functions=callees)]
        pairs, old_left, new_left = _pair_by_callees(old, new)
        assert len(pairs) == 1
        assert [f["address"] for f in old_left] == ["0x2000"]
        assert new_left == []


class TestProbePrefixLength:
    def test_prefix_covers_every_element_a_match_could_miss(self):
        """At t=0.85 a qualifying B misses at most |A| - ceil(t*|A|) of A's
        elements, so probing one more than that cannot miss it."""
        import math

        from src.tools.diff_tools import _CALLEE_JACCARD_THRESHOLD as T
        from src.tools.diff_tools import _probe_prefix_length

        for size in range(1, 200):
            max_missable = size - math.ceil(T * size)
            assert _probe_prefix_length(size) > max_missable

    def test_stays_within_the_set(self):
        from src.tools.diff_tools import _probe_prefix_length

        for size in range(1, 200):
            assert 1 <= _probe_prefix_length(size) <= size

    def test_empty_set_probes_nothing(self):
        from src.tools.diff_tools import _probe_prefix_length

        assert _probe_prefix_length(0) == 0


class TestReportBounds:
    """An unbounded report on a real pair is 20000 lines and cannot cross an
    MCP client. Bounding it is only honest if the counts stay exact, every cut
    announces itself, and the omitted content is still reachable."""

    @staticmethod
    def _big(monkeypatch, n_modified=100, n_added=80, n_removed=70, tmp_path=None):
        """A pair with enough of everything to trip every bound."""
        import src.tools.diff_tools as dt

        old_funcs, new_funcs = [], []
        for i in range(n_modified):
            a = 0x1000 + i * 0x40
            old_funcs.append(_make_function(name=f"Mod{i}", address=f"{a:#x}",
                                            pseudocode="int f(){return 0;}"))
            new_funcs.append(_make_function(name=f"Mod{i}", address=f"{a:#x}",
                                            pseudocode="int f(){if(n<max){return 1;}}"))
        for i in range(n_removed):
            old_funcs.append(_make_function(name=f"Gone{i}", address=f"{0x90000 + i * 0x40:#x}"))
        for i in range(n_added):
            new_funcs.append(_make_function(name=f"New{i}", address=f"{0xB0000 + i * 0x40:#x}"))

        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, a, m, func, md=None: {
                "hash": f"{reader.path}-{func['address']}-{func['name']}",
                "instruction_count": 10, "operands_normalized": 0},
        )
        tool, cache, _ = _register(monkeypatch,
                                   _make_context(old_funcs), _make_context(new_funcs))
        if tmp_path is not None:
            cache.cache_dir = str(tmp_path)
            cache._get_binary_hash.side_effect = lambda p: ("a" if "old" in p else "b") * 64
        return tool

    def test_counts_stay_exact_when_listings_are_cut(self, monkeypatch):
        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", top_n=5, list_limit=3)
        assert "ADDED     80" in report
        assert "REMOVED   70" in report
        assert "MODIFIED  100" in report

    def test_every_cut_says_how_much_it_omitted(self, monkeypatch):
        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", top_n=5, list_limit=3)
        assert "... 77 more added function(s) not shown" in report
        assert "... 67 more removed function(s) not shown" in report
        assert "... 95 more modified pair(s) not shown" in report

    def test_default_bounds_hold_however_big_the_diff_gets(self, monkeypatch):
        """The whole point: report size must not scale with the binary. A
        1000-modified pair and a 100-modified pair return the same size."""
        small = self._big(monkeypatch, n_modified=100, n_added=80, n_removed=70)
        small_report = small("/old.bin", "/new.bin")

        big = self._big(monkeypatch, n_modified=1000, n_added=900, n_removed=800)
        big_report = big("/old.bin", "/new.bin")
        unbounded = big("/old.bin", "/new.bin", top_n=0, list_limit=0)

        assert len(big_report.splitlines()) == len(small_report.splitlines())
        assert len(big_report.splitlines()) < 260
        assert len(unbounded.splitlines()) > 4000

    def test_zero_means_no_limit(self, monkeypatch):
        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", top_n=0, list_limit=0)
        assert "not shown" not in report
        assert "New79" in report and "Gone69" in report

    def test_modified_are_ordered_by_score_before_truncation(self, monkeypatch):
        """Truncation must keep the *most* likely fixes, so the sort has to
        happen first -- otherwise top_n returns an arbitrary slice."""
        import re

        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", top_n=10, list_limit=0)
        scores = [float(m) for m in re.findall(r"^ +score=([0-9.]+)", report, re.M)]
        assert scores == sorted(scores, reverse=True)
        assert len(scores) == 10

    def test_min_score_filters_and_says_so(self, monkeypatch):
        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", min_score=1000.0, top_n=0, list_limit=0)
        assert "min_score=1000 filtered out" in report

    def test_min_score_is_applied_before_top_n(self, monkeypatch):
        import re

        tool = self._big(monkeypatch)
        report = tool("/old.bin", "/new.bin", min_score=1000.0, top_n=5, list_limit=0)
        assert re.findall(r"^ +score=([0-9.]+)", report, re.M) == []

    def test_full_report_is_written_and_pointed_at(self, monkeypatch, tmp_path):
        import re

        tool = self._big(monkeypatch, tmp_path=tmp_path)
        report = tool("/old.bin", "/new.bin", top_n=5, list_limit=3)

        written = list(tmp_path.glob("*.diff.txt"))
        assert len(written) == 1, "a truncated report must persist the full one"
        assert str(written[0]) in report

        full = written[0].read_text()
        assert "not shown" not in full
        assert "New79" in full and "Gone69" in full
        assert len(re.findall(r"^ +score=", full, re.M)) == 100

    def test_untruncated_run_writes_nothing(self, monkeypatch, tmp_path):
        """An ordinary small diff must not litter the cache with a duplicate
        of output it already returned in full."""
        tool = self._big(monkeypatch, n_modified=2, n_added=1, n_removed=1,
                         tmp_path=tmp_path)
        report = tool("/old.bin", "/new.bin")
        assert list(tmp_path.glob("*.diff.txt")) == []
        assert "not shown" not in report

    def test_same_pair_overwrites_rather_than_accumulating(self, monkeypatch, tmp_path):
        tool = self._big(monkeypatch, tmp_path=tmp_path)
        for _ in range(3):
            tool("/old.bin", "/new.bin", top_n=5, list_limit=3)
        assert len(list(tmp_path.glob("*.diff.txt"))) == 1

    def test_unwritable_full_report_does_not_lose_the_diff(self, monkeypatch):
        """A report we cannot persist must not cost the report we can return."""
        tool = self._big(monkeypatch)  # MagicMock cache dir -> write fails
        report = tool("/old.bin", "/new.bin", top_n=5, list_limit=3)
        assert "### MODIFIED" in report
        assert "... 95 more modified pair(s) not shown" in report

    @pytest.mark.parametrize(
        "kwargs,expected",
        [
            ({"top_n": -1}, "top_n and list_limit must be >= 0"),
            ({"list_limit": -1}, "top_n and list_limit must be >= 0"),
            ({"min_score": -0.5}, "min_score must be >= 0"),
        ],
    )
    def test_negative_bounds_are_rejected(self, monkeypatch, kwargs, expected):
        tool = self._big(monkeypatch, n_modified=1, n_added=0, n_removed=0)
        assert expected in tool("/old.bin", "/new.bin", **kwargs)


class TestNoStrayWrites:
    """The diff must never create files or directories outside a real cache
    directory.

    Regression: `_write_full_report` called `mkdir(parents=True)`, and
    `MagicMock.__fspath__()` returns a plausible relative path
    (`MagicMock/mock.cache_dir/<id>`) instead of raising -- so a test run
    silently built that tree under the working directory, 30+ files of it got
    committed, and Windows CI then failed at checkout because `<` and `>` are
    illegal in Windows filenames.
    """

    def test_mock_cache_creates_nothing_on_disk(self, monkeypatch, tmp_path):
        import src.tools.diff_tools as dt

        old_funcs, new_funcs = [], []
        for i in range(60):
            a = 0x1000 + i * 0x40
            old_funcs.append(_make_function(name=f"Mod{i}", address=f"{a:#x}",
                                            pseudocode="int f(){return 0;}"))
            new_funcs.append(_make_function(name=f"Mod{i}", address=f"{a:#x}",
                                            pseudocode="int f(){if(n<max){return 1;}}"))
        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, a, m, func, md=None: {
                "hash": f"{reader.path}-{func['address']}",
                "instruction_count": 10, "operands_normalized": 0},
        )
        tool, _cache, _ = _register(monkeypatch,
                                    _make_context(old_funcs), _make_context(new_funcs))

        # Run from an empty cwd so anything created is unambiguously ours.
        monkeypatch.chdir(tmp_path)
        report = tool("/old.bin", "/new.bin", top_n=5, list_limit=3)

        assert "### MODIFIED" in report, "the diff itself must still work"
        assert list(tmp_path.iterdir()) == [], (
            f"diff created files outside the cache dir: {list(tmp_path.iterdir())}"
        )

    def test_full_report_is_skipped_when_cache_dir_is_absent(self, tmp_path):
        from src.tools.diff_tools import _write_full_report

        cache = MagicMock()
        cache.cache_dir = str(tmp_path / "does" / "not" / "exist")
        cache._get_binary_hash.side_effect = lambda p: "a" * 64

        assert _write_full_report(cache, "/old.bin", "/new.bin", lambda: "x") is None
        assert not (tmp_path / "does").exists()


class TestPairingProvenance:
    """Only phase 1 can classify a pair as modified-vs-unchanged: phase 2 pairs
    on hash EQUALITY so everything it pairs is unchanged by construction, and
    phase 1 needs PDB names. On a stripped pair the report therefore shows a
    near-empty MODIFIED bucket that reads as "barely anything changed" when the
    truth is "this tool cannot tell you" -- MODIFIED=1/RENAMED=2367 stripped
    versus MODIFIED=106/RENAMED=11 symbolized, on the same binaries.
    """

    @staticmethod
    def _pair(monkeypatch, named):
        source = "USER_DEFINED" if named else "DEFAULT"
        name = (lambda i: f"Method{i}") if named else (lambda i: f"FUN_{0x1000 + i * 64:x}")
        old_funcs, new_funcs = [], []
        for i in range(4):
            a = f"{0x1000 + i * 64:#x}"
            old_funcs.append(_make_function(name=name(i), address=a, name_source=source))
            new_funcs.append(_make_function(name=name(i), address=a, name_source=source))
        import src.tools.diff_tools as dt

        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, ar, m, func, md=None: {
                "hash": f"h-{reader.path}-{func['address']}",
                "instruction_count": 5, "operands_normalized": 0},
        )
        tool, _cache, _ = _register(monkeypatch,
                                    _make_context(old_funcs), _make_context(new_funcs))
        return tool("/old.bin", "/new.bin")

    def test_a_stripped_pair_warns_that_modified_is_under_reported(self, monkeypatch):
        report = self._pair(monkeypatch, named=False)
        assert "WARNING: PDB-named functions -- old=0, new=0" in report
        assert "UNDER-REPORTED" in report
        assert "NOT evidence that little changed" in report

    def test_a_symbolized_pair_does_not_warn(self, monkeypatch):
        report = self._pair(monkeypatch, named=True)
        assert "WARNING: PDB-named functions" not in report

    def test_the_report_says_where_its_pairs_came_from(self, monkeypatch):
        """So the phase-2 tautology is visible rather than inferred."""
        report = self._pair(monkeypatch, named=True)
        assert "Pairs:" in report
        assert "by name" in report and "by opcode hash" in report and "by callee-set" in report

    @staticmethod
    def _mostly_stripped(monkeypatch, named_count, total):
        """A pair where only `named_count` of `total` functions are PDB-named.

        Hashes key on address alone, so the unnamed remainder pairs in phase 2
        and the named few pair in phase 1 -- the real shape of a stripped
        Windows binary, where Ghidra recognizes CRT scaffolding on its own.
        """
        old_funcs, new_funcs = [], []
        for i in range(total):
            a = f"{0x1000 + i * 64:#x}"
            if i < named_count:
                kw = {"name": f"__security_check_cookie_{i}", "name_source": "USER_DEFINED"}
            else:
                kw = {"name": f"FUN_{0x1000 + i * 64:x}", "name_source": "DEFAULT"}
            old_funcs.append(_make_function(address=a, **kw))
            new_funcs.append(_make_function(address=a, **kw))
        import src.tools.diff_tools as dt

        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, ar, m, func, md=None: {
                "hash": f"h-{func['address']}",
                "instruction_count": 5, "operands_normalized": 0},
        )
        tool, _cache, _ = _register(monkeypatch,
                                    _make_context(old_funcs), _make_context(new_funcs))
        return tool("/old.bin", "/new.bin")

    def test_a_barely_symbolized_pair_still_warns(self, monkeypatch):
        """Ghidra names CRT scaffolding even with no PDB, so a stripped binary
        is never at zero PDB-named functions. Measured on the real cscsvc pair
        that motivated this warning: 75 of 2524 (3.0%) on each side, both
        non-zero -- so a presence check stays silent on exactly the pair whose
        MODIFIED=1/RENAMED=2367 it exists to flag. Phase 1 is *effectively*
        inactive at 3%, and the report has to say so.
        """
        report = self._mostly_stripped(monkeypatch, named_count=2, total=40)
        assert "WARNING" in report
        assert "UNDER-REPORTED" in report

    def test_a_mostly_symbolized_pair_does_not_warn(self, monkeypatch):
        """The other side of the threshold: real symbol coverage must stay quiet.

        On the symbolized sdengin2 pair phase 1 supplied 2120 of 3069 pairs
        (69%), against 75 of 2452 (3%) stripped.
        """
        report = self._mostly_stripped(monkeypatch, named_count=36, total=40)
        assert "WARNING" not in report


class TestModuleGrouping:
    """`group_by="module"` was inert on Ghidra-imported PDB names.

    Ghidra puts the class in the NAMESPACE, not the flat name, so splitting the
    flat name on `::` put a whole symbolized Windows binary into one `(global)`
    bucket. Measured on sdengin2: 1 of 3119 functions had an `A::B::method`
    shape, and the 99 containing `::` at all were template arguments.
    """

    def test_the_namespace_is_preferred_over_the_flat_name(self):
        from src.tools.diff_tools import _module_prefix

        func = _make_function(name="_RestoreNonSpannedFile")
        func["namespace"] = "CSdRestoreImpl"
        assert _module_prefix(func) == "CSdRestoreImpl"

    def test_a_flat_name_still_groups_when_there_is_no_namespace(self):
        """Caches written before the field existed, and symbol sources that do
        embed the class in the name, must keep working."""
        from src.tools.diff_tools import _module_prefix

        assert _module_prefix(_make_function(name="A::B::method")) == "A::B"

    def test_a_bare_name_with_no_namespace_is_global(self):
        from src.tools.diff_tools import _module_prefix

        assert _module_prefix(_make_function(name="memcpy")) == "(global)"

    def test_an_empty_namespace_falls_back_rather_than_grouping_on_blank(self):
        from src.tools.diff_tools import _module_prefix

        func = _make_function(name="A::B::method")
        func["namespace"] = "   "
        assert _module_prefix(func) == "A::B"

    def test_grouping_uses_the_namespace_end_to_end(self, monkeypatch):
        import src.tools.diff_tools as dt

        def _named(name, namespace, address):
            f = _make_function(name=name, address=address, name_source="USER_DEFINED")
            f["namespace"] = namespace
            return f

        old_funcs = [_named("Run", "CQuery", "0x1000"), _named("Stop", "CIndex", "0x2000")]
        new_funcs = [_named("Run", "CQuery", "0x1000"), _named("Stop", "CIndex", "0x2000")]
        monkeypatch.setattr(
            dt, "_compute_function_hash",
            lambda reader, a, m, func, md=None: {
                "hash": f"h-{reader.path}-{func['address']}",
                "instruction_count": 5, "operands_normalized": 0},
        )
        tool, _cache, _ = _register(monkeypatch,
                                    _make_context(old_funcs), _make_context(new_funcs))
        report = tool("/old.bin", "/new.bin", group_by="module")

        assert "-- module: CQuery" in report
        assert "-- module: CIndex" in report
        assert "-- module: (global)" not in report


# ---------------------------------------------------------------------------
# F-7: the diff report is sample-derived on both sides
# ---------------------------------------------------------------------------


def _diff_func(name, address, pseudocode=""):
    return {
        "name": name,
        "address": address,
        "pseudocode": pseudocode,
        "basic_blocks": [],
        "called_functions": [],
        "size": 32,
    }


def test_diff_report_fences_every_sample_derived_section():
    """Both inputs to a diff are untrusted, so both sides' names are too.

    The module-level F-7 guard only checks that ``wrap_untrusted`` appears
    somewhere in diff_tools.py. That was enough until the report builder was
    rewritten to merge in bounded output (top_n / list_limit / _name_section),
    at which point a fence could be dropped from one section while the module
    scan still passed. This asserts per section.
    """
    from src.tools.diff_tools import _format_report

    old_ctx = {"functions": [_diff_func("OldOnly", "0x1000")]}
    new_ctx = {"functions": [_diff_func("NewOnly", "0x2000")]}

    report = _format_report(
        old_path="old.dll",
        new_path="new.dll",
        old_ctx=old_ctx,
        new_ctx=new_ctx,
        added=[_diff_func("EvilAdded", "0x2000")],
        removed=[_diff_func("EvilRemoved", "0x1000")],
        modified=[],
        unchanged_count=0,
        mode="security",
        group_by="none",
        unchanged_renamed=[
            (_diff_func("EvilOld", "0x1000"), _diff_func("EvilNew", "0x2000"))
        ],
    )

    # Three name sections, three envelopes -- ADDED, REMOVED, Renamed.
    assert report.count("⟦BEGIN UNTRUSTED SAMPLE DATA") == 3
    assert report.count("⟦END UNTRUSTED SAMPLE DATA⟧") == 3

    # Each name is inside a fence, and the bucket headings are outside it.
    for name in ("EvilAdded", "EvilRemoved", "EvilOld", "EvilNew"):
        assert name in report
    for heading in ("### ADDED (1)", "### REMOVED (1)"):
        assert heading in report
        assert report.index(heading) < report.index(
            "⟦BEGIN UNTRUSTED SAMPLE DATA", report.index(heading)
        )


def test_diff_report_fences_the_modified_bucket_once():
    """The MODIFIED bucket carries pseudocode from both binaries.

    One envelope around the bucket, not one per pair: a bounded report can
    still hold hundreds of entries, and a per-entry fence would cost more
    boilerplate than content -- the failure this branch already hit in
    get_call_graph and in session replay.
    """
    from src.tools.diff_tools import _format_report

    pairs = [
        (
            _diff_func(f"Fn{i}", f"0x{0x1000 + i:x}", "int a(){return 0;}"),
            _diff_func(f"Fn{i}", f"0x{0x2000 + i:x}", "int a(){return 1;}"),
            "modified",
            {
                "score": 1.0,
                "bounds_delta": 1,
                "cookie_delta": 0,
                "caller_delta": 0,
                "size_delta": 4,
            },
        )
        for i in range(4)
    ]

    report = _format_report(
        old_path="old.dll",
        new_path="new.dll",
        old_ctx={"functions": []},
        new_ctx={"functions": []},
        added=[],
        removed=[],
        modified=pairs,
        unchanged_count=0,
        mode="security",
        group_by="none",
    )

    assert "### MODIFIED (4)" in report
    # Empty ADDED/REMOVED/Renamed sections emit no envelope, so the only one
    # here is the MODIFIED bucket's.
    assert report.count("⟦BEGIN UNTRUSTED SAMPLE DATA") == 1
    for i in range(4):
        assert f"Fn{i}" in report
