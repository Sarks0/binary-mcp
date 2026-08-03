"""
Tests for the per-binary review-coverage store.

Covers:
- Address canonicalization (the cross-process function key).
- Forward-BFS scope: export / dispatch / address-taken roots, callee
  propagation, and the mechanical exclusions.
- The six counts and the invariants a consumer asserts on.
- Cold start: an unindexed binary reports null counts, never zero.
- Deterministic worklist ordering and forward progress.
- Auto-mark idempotency and the tools that must NOT auto-mark.
- Side-car lifecycle against ProjectCache.invalidate / clear_all.
"""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock

import pytest

from src.engines.static.ghidra.coverage_store import (
    SCOPE_VERSION,
    CoverageError,
    CoverageStore,
    _assert_invariants,
    auto_mark,
    canon_addr,
    compute_scope,
)
from src.engines.static.ghidra.project_cache import ProjectCache

# Fixtures / builders


def _func(
    name,
    address,
    called=None,
    *,
    is_thunk=False,
    is_external=False,
    decompile_status="success",
    fid_match=None,
    size=64,
    parameters=None,
    pseudocode="",
    jump_tables=None,
):
    """Build a cached-function record in the shape core_analysis.py emits.

    Note the bare, unprefixed address -- that is what Ghidra actually writes,
    and normalizing it is the store's job.
    """
    return {
        "name": name,
        "address": address,
        "size": size,
        "is_thunk": is_thunk,
        "is_external": is_external,
        "decompile_status": decompile_status,
        "fid_match": fid_match,
        "parameters": parameters or [],
        "pseudocode": pseudocode,
        "jump_tables": jump_tables or [],
        "called_functions": [{"address": a, "name": ""} for a in (called or [])],
    }


def _context(functions, exports=None, image_base="140000000", name="test.sys"):
    return {
        "metadata": {
            "name": name,
            "image_base": image_base,
            "analysis_depth": "full",
            "executable_path": f"/tmp/{name}",
        },
        "functions": functions,
        "exports": exports or [],
    }


@pytest.fixture
def lab(tmp_path):
    """A real ProjectCache over tmp_path plus a real binary file.

    Coverage is a disk side-car keyed off a content hash, so the round-trip is
    the thing worth testing; mocking the cache would test nothing.
    """

    class Lab:
        def __init__(self):
            self.cache = ProjectCache(cache_dir=str(tmp_path))
            self.store = CoverageStore(self.cache)
            self.binary = tmp_path / "test.sys"
            self.binary.write_bytes(b"MZ" + b"\x00" * 512)
            self.path = str(self.binary)
            self.binary_id = hashlib.sha256(self.binary.read_bytes()).hexdigest()

        def analyze(self, context):
            self.cache.save_cached(self.path, context)
            return context

    return Lab()


# Address canonicalization


class TestCanonAddr:
    def test_bare_hex_gains_prefix(self):
        assert canon_addr("140006d8c") == "0x140006d8c"

    def test_prefixed_passes_through(self):
        assert canon_addr("0x140006d8c") == "0x140006d8c"

    def test_uppercase_is_lowered(self):
        assert canon_addr("0x140006D8C") == "0x140006d8c"

    def test_zero_padding_is_stripped(self):
        assert canon_addr("0x0000000140006d8c") == "0x140006d8c"

    def test_int_is_accepted(self):
        assert canon_addr(0x140006D8C) == "0x140006d8c"

    def test_external_pseudo_address_is_dropped(self):
        assert canon_addr("EXTERNAL:0000005b") == ""

    def test_garbage_is_dropped(self):
        assert canon_addr("FUN_140006d8c") == ""
        assert canon_addr(None) == ""
        assert canon_addr("") == ""

    def test_output_survives_notes_mcp_normalization(self):
        """notes-mcp emits f"0x{int(body,16):x}"; a naive compare must match."""
        for raw in ("140006d8c", "0x140006D8C", "0x0000000140006d8c", 0x140006D8C):
            canon = canon_addr(raw)
            body = canon[2:]
            assert f"0x{int(body, 16):x}" == canon


# Scope computation


class TestComputeScope:
    def test_export_root_and_callee_propagation(self):
        ctx = _context(
            [
                _func("entry", "140001000", called=["140002000"]),
                _func("helper", "140002000"),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _desc = compute_scope(ctx)
        assert records["0x140001000"]["scope_reason"] == "reachable:export"
        assert records["0x140002000"]["scope_reason"] == "reachable:callee"
        assert all(r["in_scope"] for r in records.values())

    def test_cycle_reachable_subtree_stays_in_scope(self):
        """A callback that recurses must not drop its whole subtree.

        `reachable:indirect_root` means "no direct caller anywhere", and every
        member of a call cycle has one -- so before the fixpoint promotion the
        walk could not enter, and everything below fell out as
        excluded:unreachable. On the real corpus that was silently dropping
        http.sys parsers. Under-counting scope is the dangerous direction.
        """
        ctx = _context(
            [
                _func("entry", "140001000"),
                # DoCollect <-> FinishConcurrent is a cycle reached only
                # indirectly; MarkInterior hangs below it.
                _func("DoCollect", "140002000", called=["140003000"]),
                _func("FinishConcurrent", "140003000",
                      called=["140002000", "140004000"]),
                _func("MarkInterior", "140004000"),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, desc = compute_scope(ctx)
        assert all(
            r["scope_reason"] != "excluded:unreachable" for r in records.values()
        ), records
        assert records["0x140004000"]["in_scope"]
        assert "unreachable from any root" not in desc

    def test_self_recursive_root_still_in_scope(self):
        """The one-line mutation that used to flip a root out of scope."""
        ctx = _context(
            [
                _func("entry", "140001000"),
                # Self-loop: has a direct caller (itself), so never an
                # indirect_root under the old rule.
                _func("BfPreClose", "140002000",
                      called=["140002000", "140003000"]),
                _func("deep", "140003000"),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert records["0x140002000"]["in_scope"]
        assert records["0x140003000"]["in_scope"]

    def test_address_taken_function_is_a_root(self):
        """A registered callback has no direct caller; it must stay in scope.

        Under-counting scope is the dangerous direction -- it shrinks the
        denominator and manufactures false completion.
        """
        ctx = _context(
            [
                _func("entry", "140001000"),
                _func("BfPreClose", "140002000", called=["140003000"]),
                _func("deep", "140003000"),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert records["0x140002000"]["scope_reason"] == "reachable:indirect_root"
        assert records["0x140003000"]["scope_reason"] == "reachable:callee"
        assert records["0x140003000"]["in_scope"]

    def test_dispatcher_candidate_is_an_entry_point(self):
        ctx = _context(
            [
                _func("entry", "140001000", called=["140002000"]),
                _func(
                    "DriverDispatch",
                    "140002000",
                    parameters=[{"name": "param_1", "datatype": "PIRP"}],
                ),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert records["0x140002000"]["scope_reason"] == "reachable:ioctl_dispatch"

    def test_switch_table_targets_are_entry_points(self):
        ctx = _context(
            [
                _func("entry", "140001000", called=["140002000"]),
                _func(
                    "DriverDispatch",
                    "140002000",
                    parameters=[{"name": "param_1", "datatype": "PIRP"}],
                    jump_tables=[{"source_addr": "140002010", "targets": ["140004000"]}],
                ),
                # Reached only through the jump table, and it has a caller
                # recorded nowhere -- without the table join it would still be
                # an indirect_root, so give it one to prove the join fires.
                _func("handler", "140004000"),
                _func("caller_of_handler", "140005000", called=["140004000"]),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert records["0x140004000"]["scope_reason"] == "reachable:ioctl_dispatch"

    @pytest.mark.parametrize(
        "kwargs,reason",
        [
            ({"is_thunk": True}, "excluded:thunk"),
            ({"is_external": True}, "excluded:external"),
            (
                {"decompile_status": "skipped_thunk_or_external"},
                "excluded:thunk_or_external",
            ),
            ({"fid_match": {"library": "vs2019"}}, "excluded:fid_library"),
        ],
    )
    def test_mechanical_exclusions(self, kwargs, reason):
        ctx = _context(
            [
                _func("entry", "140001000", called=["140002000"]),
                _func("lib", "140002000", **kwargs),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert records["0x140002000"]["in_scope"] is False
        assert records["0x140002000"]["scope_reason"] == reason

    def test_excluded_functions_remain_in_the_map(self):
        """scope='all' must still reach them -- an invisible function is work
        that silently disappeared from the ledger."""
        ctx = _context(
            [
                _func("entry", "140001000", called=["140002000"]),
                _func("thunk", "140002000", is_thunk=True),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert "0x140002000" in records

    def test_external_callee_addresses_do_not_create_phantom_functions(self):
        ctx = _context(
            [_func("entry", "140001000", called=["EXTERNAL:00000055"])],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        records, _ = compute_scope(ctx)
        assert list(records) == ["0x140001000"]

    def test_scope_description_records_the_method(self):
        ctx = _context([_func("entry", "140001000")])
        _records, desc = compute_scope(ctx)
        assert "forward BFS" in desc
        assert "Indirect calls are invisible" in desc


# Counts and invariants


class TestCounts:
    def test_counts_derive_from_the_function_map(self, lab):
        lab.analyze(
            _context(
                [
                    _func("entry", "140001000", called=["140002000"]),
                    _func("helper", "140002000"),
                    _func("thunk", "140003000", is_thunk=True),
                ],
                exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
            )
        )
        record = lab.store.index(lab.binary_id, lab.path)
        counts = lab.store.counts(record)
        assert counts == {
            "total": 3,
            "in_scope_total": 2,
            "reviewed": 0,
            "reviewed_in_scope": 0,
            "remaining": 3,
            "remaining_in_scope": 2,
        }

    def test_reviewed_in_scope_tracks_scope(self, lab):
        lab.analyze(
            _context(
                [
                    _func("entry", "140001000"),
                    _func("thunk", "140002000", is_thunk=True),
                ]
            )
        )
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["0x140002000"], tool="t")
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["reviewed"] == 1
        assert counts["reviewed_in_scope"] == 0
        assert counts["remaining_in_scope"] == 1

    @pytest.mark.parametrize(
        "counts",
        [
            {"total": 10, "in_scope_total": 5, "reviewed": 2, "reviewed_in_scope": 1,
             "remaining": 7, "remaining_in_scope": 4},
            {"total": 10, "in_scope_total": 5, "reviewed": 2, "reviewed_in_scope": 1,
             "remaining": 8, "remaining_in_scope": 3},
            {"total": 5, "in_scope_total": 9, "reviewed": 0, "reviewed_in_scope": 0,
             "remaining": 5, "remaining_in_scope": 9},
            {"total": 10, "in_scope_total": 5, "reviewed": 1, "reviewed_in_scope": 3,
             "remaining": 9, "remaining_in_scope": 2},
            {"total": -1, "in_scope_total": 0, "reviewed": 0, "reviewed_in_scope": 0,
             "remaining": -1, "remaining_in_scope": 0},
        ],
    )
    def test_invariant_violations_raise(self, counts):
        with pytest.raises(CoverageError):
            _assert_invariants(counts)


# Marking


class TestMarking:
    def test_mark_is_idempotent(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)

        first = lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a")
        stamp = lab.store.read(lab.binary_id)["functions"]["0x140001000"]["reviewed_at"]
        second = lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="b")

        assert first["marked"] == ["0x140001000"]
        assert second["marked"] == []
        assert second["already"] == ["0x140001000"]
        entry = lab.store.read(lab.binary_id)["functions"]["0x140001000"]
        assert entry["reviewed_at"] == stamp
        assert entry["reviewed_by"] == "a"
        assert lab.store.counts(lab.store.read(lab.binary_id))["reviewed"] == 1

    def test_unknown_address_never_inflates_the_count(self, lab):
        """A phantom entry would push reviewed above total and break the
        invariants the consumer asserts on."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)

        result = lab.store.mark_reviewed(lab.binary_id, ["0xdeadbeef"], tool="a")
        assert result["unknown"] == ["0xdeadbeef"]
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["reviewed"] == 0
        assert counts["total"] == 1

    def test_mark_accepts_any_address_spelling(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        result = lab.store.mark_reviewed(lab.binary_id, ["140001000"], tool="a")
        assert result["marked"] == ["0x140001000"]

    def test_unmark(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a")
        lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a", reviewed=False)
        assert lab.store.counts(lab.store.read(lab.binary_id))["reviewed"] == 0

    def test_findings_note_is_stored(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(
            lab.binary_id, ["0x140001000"], tool="a", note="unchecked length"
        )
        entry = lab.store.read(lab.binary_id)["functions"]["0x140001000"]
        assert entry["findings_note"] == "unchecked length"


# Indexing lifecycle


class TestIndexing:
    def test_reindex_preserves_review_marks(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a", note="keep me")
        stamp = lab.store.read(lab.binary_id)["functions"]["0x140001000"]["reviewed_at"]

        # An incremental Ghidra run grows the function list.
        lab.analyze(
            _context([_func("entry", "140001000"), _func("new", "140002000")])
        )
        record = lab.store.index(lab.binary_id, lab.path)

        entry = record["functions"]["0x140001000"]
        assert entry["reviewed"] is True
        assert entry["reviewed_at"] == stamp
        assert entry["findings_note"] == "keep me"
        assert lab.store.counts(record)["total"] == 2
        assert lab.store.counts(record)["reviewed"] == 1

    def test_growing_analysis_cache_triggers_reindex(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert lab.store.counts(record)["total"] == 1

        lab.analyze(
            _context([_func("entry", "140001000"), _func("new", "140002000")])
        )
        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert lab.store.counts(record)["total"] == 2

    def test_scope_version_bump_triggers_reindex(self, lab, monkeypatch):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)

        stored = lab.store.read(lab.binary_id)
        stored["scope_version"] = "stale-v0"
        lab.store.write(stored)

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["scope_version"] == SCOPE_VERSION

    def test_a_v1_record_is_rebuilt_and_its_shrunken_scope_repaired(self, lab):
        """The scope fix is worthless on existing records without the bump.

        `scope_version` IS the rebuild trigger. A record written under
        `fwd-bfs-v1` carries that version's shrunken scope -- a cycle reached
        only indirectly, and everything below it, flagged out. If the constant
        had stayed at v1 the mismatch would never fire and the shrink would be
        permanent on every already-indexed binary.
        """
        ctx = _context(
            [
                _func("entry", "140001000"),
                _func("DoCollect", "140002000", called=["140003000"]),
                _func("FinishConcurrent", "140003000",
                      called=["140002000", "140004000"]),
                _func("MarkInterior", "140004000"),
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        lab.analyze(ctx)
        lab.store.index(lab.binary_id, lab.path)

        # Rewind to what v1 would have written: the cycle and its subtree out
        # of scope, stamped with the version that produced it.
        stored = lab.store.read(lab.binary_id)
        stored["scope_version"] = "fwd-bfs-v1"
        for addr in ("0x140002000", "0x140003000", "0x140004000"):
            stored["functions"][addr]["in_scope"] = False
            stored["functions"][addr]["scope_reason"] = "excluded:unreachable"
        # A mark taken under v1 must survive the migration.
        stored["functions"]["0x140001000"]["reviewed"] = True
        stored["functions"]["0x140001000"]["reviewed_at"] = "2026-08-03T12:00:00Z"
        stored["functions"]["0x140001000"]["reviewed_by"] = "decompile_function"
        lab.store.write(stored)

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["scope_version"] == SCOPE_VERSION
        assert lab.store.counts(record)["in_scope_total"] == 4
        assert record["functions"]["0x140004000"]["in_scope"]
        assert record["functions"]["0x140001000"]["reviewed"] is True
        assert record["functions"]["0x140001000"]["reviewed_at"] == "2026-08-03T12:00:00Z"

    def test_missing_analysis_cache_reports_stale_not_ready(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        (lab.cache.cache_dir / f"{lab.binary_id}.json.gz").unlink()

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "stale"
        assert lab.store.counts(record)["total"] == 1

    def test_index_by_sha_works_without_the_file(self, lab):
        """The ledger key outlives the staging tree; a consumer holding only a
        sha must still be able to index."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.binary.unlink()

        record, status = lab.store.ensure_indexed(lab.binary_id, None)
        assert status == "ready"
        assert lab.store.counts(record)["total"] == 1

    def test_legacy_uncompressed_cache_is_readable(self, lab):
        ctx = _context([_func("entry", "140001000")])
        gz = lab.cache.cache_dir / f"{lab.binary_id}.json.gz"
        legacy = lab.cache.cache_dir / f"{lab.binary_id}.json"
        legacy.write_text(json.dumps(ctx))
        assert not gz.exists()

        record, status = lab.store.ensure_indexed(lab.binary_id, None)
        assert status == "ready"
        assert lab.store.counts(record)["total"] == 1

    def test_resolve_rejects_a_non_sha_binary_id(self, lab):
        with pytest.raises(ValueError):
            lab.store.resolve(binary_id="not-a-hash")

    def test_image_base_is_canonicalized(self, lab):
        lab.analyze(_context([_func("entry", "140001000")], image_base="140000000"))
        record = lab.store.index(lab.binary_id, lab.path)
        assert record["image_base"] == "0x140000000"


# Side-car lifecycle against the surrounding cache


class TestSidecarLifecycle:
    def test_coverage_survives_invalidate(self, lab):
        """force_reanalyze must not destroy a review history: the key is a
        content hash, so the addresses cannot have shifted."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a")

        lab.cache.invalidate(lab.path)

        record = lab.store.read(lab.binary_id)
        assert record is not None
        assert record["functions"]["0x140001000"]["reviewed"] is True

    def test_clear_all_drops_coverage(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.cache.clear_all()
        assert lab.store.read(lab.binary_id) is None

    def test_legacy_prune_never_eats_the_sidecar(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        # Re-running the constructor triggers _prune_legacy_duplicates.
        ProjectCache(cache_dir=str(lab.cache.cache_dir))
        assert (lab.cache.cache_dir / f"{lab.binary_id}.coverage.json").exists()

    def test_write_is_atomic_and_leaves_no_temp_files(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        leftovers = list(lab.cache.cache_dir.glob("*.tmp"))
        assert leftovers == []


# auto_mark hook


class TestAutoMark:
    def test_auto_mark_indexes_then_marks(self, lab):
        ctx = lab.analyze(_context([_func("entry", "140001000")]))
        auto_mark(lab.cache, lab.path, ["140001000"], tool="decompile_function", context=ctx)
        record = lab.store.read(lab.binary_id)
        assert record["functions"]["0x140001000"]["reviewed"] is True
        assert record["functions"]["0x140001000"]["reviewed_by"] == "decompile_function"

    def test_auto_mark_never_raises(self, lab):
        """Coverage is additive: a ledger failure must not break a decompile."""
        broken = MagicMock()
        broken.cache_dir = lab.cache.cache_dir
        broken._get_binary_hash.side_effect = OSError("boom")
        auto_mark(broken, lab.path, ["140001000"], tool="decompile_function")

    def test_auto_mark_ignores_empty_input(self, lab):
        lab.analyze(_context([_func("entry", "140001000")]))
        auto_mark(lab.cache, lab.path, [], tool="decompile_function")
        assert lab.store.read(lab.binary_id) is None

    def test_auto_mark_on_unanalyzed_binary_is_a_noop(self, lab):
        auto_mark(lab.cache, lab.path, ["140001000"], tool="decompile_function")
        assert lab.store.read(lab.binary_id) is None
