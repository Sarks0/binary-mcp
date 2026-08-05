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
    EXAMINATION_DIFF,
    EXAMINATION_SWEEP,
    SCHEMA_VERSION,
    SCOPE_VERSION,
    CoverageError,
    CoverageStore,
    _assert_invariants,
    auto_examine,
    auto_mark,
    canon_addr,
    compute_scope,
    has_reviewable_body,
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
            "examined": 0,
            "examined_in_scope": 0,
            "examined_unreviewed": 0,
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


# Unparseable addresses and the drop accounting


class TestDroppedAddresses:
    """Functions whose address `canon_addr` rejects are absent from `total`.

    `total` is derived from the normalized map; `source_function_count` comes
    from the pre-normalization list. Nothing used to compare them, and both
    staleness probes agreed with each other, so a denominator that had silently
    lost functions was served as `ready` indefinitely.
    """

    def test_all_addresses_unparseable_is_not_indexed_not_six_zeros(self, lab):
        """`ready` with `total: 0` is the documented terminal condition.

        Reporting it for a binary whose every address failed to parse tells a
        review loop it has finished a binary nobody read.
        """
        lab.analyze(
            _context([_func("a", "EXTERNAL:1"), _func("b", "EXTERNAL:2")])
        )
        assert lab.store.index(lab.binary_id, lab.path) is None
        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert record is None
        assert status == "not_indexed"

    def test_partial_drop_is_recorded_not_silent(self, lab):
        lab.analyze(
            _context(
                [
                    _func("a", "140001000"),
                    _func("b", "140002000"),
                    _func("x", "EXTERNAL:1"),
                    _func("y", "EXTERNAL:2"),
                    _func("z", "EXTERNAL:3"),
                ]
            )
        )
        record = lab.store.index(lab.binary_id, lab.path)
        assert lab.store.counts(record)["total"] == 2
        assert record["dropped_address_count"] == 3
        assert record["source_function_count"] == 5
        assert "under-counts" in record["scope_description"]

    def test_clean_binary_records_a_zero_drop(self, lab):
        """The field must be present and 0, not absent -- absent cannot be told
        apart from 'nobody counted'."""
        lab.analyze(_context([_func("entry", "140001000")]))
        record = lab.store.index(lab.binary_id, lab.path)
        assert record["dropped_address_count"] == 0

    def test_counts_cross_check_catches_a_shrunken_denominator(self, lab):
        """The one invariant that is not a restatement of its own arithmetic.

        `source_function_count` was recorded from the analysis cache's function
        list, so comparing the denominator against it detects a `total` that
        lost functions -- which the remaining/total/reviewed relations cannot.
        """
        lab.analyze(_context([_func("a", "140001000"), _func("b", "140002000")]))
        record = lab.store.index(lab.binary_id, lab.path)
        del record["functions"]["0x140002000"]
        with pytest.raises(CoverageError, match="does not account for every function"):
            lab.store.counts(record)

    def test_a_record_whose_numbers_do_not_add_up_is_rebuilt(self, lab):
        """Corrupts only `dropped_address_count`, so `source_function_count`
        still matches the meta side-car and the pre-existing count/scope/schema
        triggers all pass. The arithmetic cross-check is the only thing that can
        catch it."""
        lab.analyze(_context([_func("a", "140001000"), _func("b", "140002000")]))
        lab.store.index(lab.binary_id, lab.path)

        stored = lab.store.read(lab.binary_id)
        stored["dropped_address_count"] = 5
        assert lab.store._source_function_count(lab.binary_id) == stored[
            "source_function_count"
        ], "the count trigger must NOT be what fires here"
        lab.store.write(stored)

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["dropped_address_count"] == 0
        assert lab.store.counts(record)["total"] == 2

    def test_a_genuine_drop_does_not_rebuild_on_every_query(self, lab):
        """`dropped != 0` must NOT be the rebuild trigger.

        A binary that really does carry unparseable addresses would then
        re-index -- decompressing the whole analysis cache -- on every status
        poll forever, producing the identical record each time.
        """
        lab.analyze(_context([_func("a", "140001000"), _func("x", "EXTERNAL:1")]))
        first, _ = lab.store.ensure_indexed(lab.binary_id, lab.path)
        second, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert second["indexed_at"] == first["indexed_at"]


# On-disk schema versioning


class TestSchemaVersion:
    """`schema_version` was written but never read: a record stamped 999 was
    accepted and served as `ready`."""

    def _corrupt(self, lab, **fields):
        stored = lab.store.read(lab.binary_id)
        stored.update(fields)
        path = lab.cache.cache_dir / f"{lab.binary_id}.coverage.json"
        path.write_text(json.dumps(stored), encoding="utf-8")

    @pytest.mark.parametrize("version", [999, "2", None, True])
    def test_unreadable_schema_version_is_refused(self, lab, version):
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        self._corrupt(lab, schema_version=version)
        assert lab.store.read(lab.binary_id) is None

    def test_a_future_record_reports_not_indexed_not_ready(self, lab):
        """Null counts are the honest answer for a layout we cannot interpret;
        serving it as `ready` puts numbers of unknown provenance in front of a
        closure decision."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        self._corrupt(lab, schema_version=999)
        # Remove the rebuild source so the refusal is what decides the status,
        # rather than an immediate re-index papering over it.
        (lab.cache.cache_dir / f"{lab.binary_id}.json.gz").unlink()
        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert record is None
        assert status == "not_indexed"

    def test_an_older_readable_record_is_rebuilt_with_marks_intact(self, lab):
        """A v1 record has a readable layout, so its review history is
        salvageable -- rebuild, do not discard."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["0x140001000"], tool="a", note="keep")
        stored = lab.store.read(lab.binary_id)
        stored["schema_version"] = 1
        del stored["dropped_address_count"]
        lab.store.write(stored)

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["schema_version"] == SCHEMA_VERSION
        assert record["dropped_address_count"] == 0
        entry = record["functions"]["0x140001000"]
        assert entry["reviewed"] is True
        assert entry["findings_note"] == "keep"

    def test_a_future_scope_version_is_rebuilt_under_current_semantics(self, lab):
        """Documented downgrade behaviour: any scope_version mismatch rebuilds,
        future included, and re-stamps the record with the current string. The
        consumer detects it by reading `scope_version` back."""
        lab.analyze(_context([_func("entry", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        stored = lab.store.read(lab.binary_id)
        stored["scope_version"] = "fwd-bfs-v99"
        lab.store.write(stored)

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["scope_version"] == SCOPE_VERSION


# What `in_scope` actually means


class TestScopeIsProvenanceNotFiltering:
    """The fixpoint drains the residual entirely, so membership is exactly
    "not mechanically excluded" and the walk only supplies `scope_reason`.

    Documenting it the other way round -- "in_scope is real reachability" --
    invites a consumer to believe the call graph narrowed the denominator.
    """

    def test_in_scope_is_total_minus_the_mechanical_exclusions(self, lab):
        lab.analyze(
            _context(
                [
                    _func("entry", "140001000"),
                    _func("thunk", "140002000", is_thunk=True),
                    _func("ext", "140003000", is_external=True),
                    _func("fid", "140004000", fid_match="memcpy"),
                    # Reachable only through a cycle nothing calls into.
                    _func("cyc_a", "140005000", called=["140006000"]),
                    _func("cyc_b", "140006000", called=["140005000"]),
                ]
            )
        )
        record = lab.store.index(lab.binary_id, lab.path)
        counts = lab.store.counts(record)
        excluded = sum(
            1
            for e in record["functions"].values()
            if e["scope_reason"].startswith("excluded:")
        )
        assert excluded == 3
        assert counts["in_scope_total"] == counts["total"] - excluded

    def test_nothing_is_ever_labelled_excluded_unreachable(self, lab):
        lab.analyze(
            _context(
                [
                    _func("cyc_a", "140005000", called=["140006000"]),
                    _func("cyc_b", "140006000", called=["140005000"]),
                    _func("below", "140007000"),
                ]
            )
        )
        record = lab.store.index(lab.binary_id, lab.path)
        reasons = {e["scope_reason"] for e in record["functions"].values()}
        assert "excluded:unreachable" not in reasons

    def test_disjoint_cycles_are_promoted_in_one_pass(self):
        """Guards the fixpoint against going quadratic again.

        Each pass recomputes `residual` and `called_within` over the whole
        graph. Promoting one root per pass therefore costs one full sweep per
        independent cycle -- and every fixpoint pass on the real cached corpus
        is a no-source pass, so this is the path real binaries take, not a
        synthetic corner. Counting `canon_addr` calls measures it without a
        wall clock: linear here, quadratic before (800 nodes: 3200 vs 162800).
        """
        import src.engines.static.ghidra.coverage_store as module

        nodes = 800
        functions = []
        for i in range(0, nodes, 2):
            a = 0x140001000 + i * 0x10
            b = a + 0x10
            functions.append(_func(f"f{a:x}", f"{a:x}", called=[f"{b:x}"]))
            functions.append(_func(f"f{b:x}", f"{b:x}", called=[f"{a:x}"]))

        real = module.canon_addr
        calls = []

        def counting(raw):
            calls.append(1)
            return real(raw)

        module.canon_addr = counting
        try:
            records, _description = module.compute_scope(_context(functions))
        finally:
            module.canon_addr = real

        assert len(records) == nodes
        assert all(r["in_scope"] for r in records.values())
        assert len(calls) < 10 * nodes, (
            f"{len(calls)} canon_addr calls for {nodes} nodes -- the fixpoint is "
            f"promoting one root per pass again"
        )


# The reviewable-body predicate


class TestHasReviewableBody:
    """Auto-marking must not advance the denominator for a function whose code
    nobody saw. Ghidra emits banner-comment-only bodies when it declines to
    decompile, and non-empty alone accepts those."""

    def test_comment_only_body_is_not_a_review(self):
        assert not has_reviewable_body(
            "/* WARNING: Globals starting with '_' overlap smaller symbols */\n"
        )

    def test_genuine_empty_stub_still_marks(self):
        """http.sys FUN_140137c58 and FUN_1401d5530, verbatim. These are real,
        reviewable code -- excluding them would under-mark."""
        assert has_reviewable_body("void FUN_140137c58(void)\n\n{\n  return;\n}")

    def test_ordinary_body_marks(self):
        assert has_reviewable_body("int f(void) { return g(1); }")

    def test_empty_and_non_string_do_not_mark(self):
        assert not has_reviewable_body("")
        assert not has_reviewable_body("   \n ")
        assert not has_reviewable_body(None)


# The examination axis


class TestExamination:
    """`examined` is a machine pass's claim, `reviewed` is a human's. The
    separation is the whole feature: a diff pairs thousands of functions and
    has read none of them, so an examination that could move the review counts
    would manufacture false completion at exactly the scale that matters.
    """

    def _indexed(self, lab):
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
        return lab.store.index(lab.binary_id, lab.path)

    def test_examining_does_not_review(self, lab):
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000", "140002000"],
            kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["examined"] == 2
        assert counts["reviewed"] == 0
        # The load-bearing one: an examination must not shorten the work left.
        assert counts["remaining"] == counts["total"] == 3
        assert counts["remaining_in_scope"] == counts["in_scope_total"] == 2

    def test_examined_unreviewed_is_the_lead_count(self, lab):
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000", "140002000"],
            kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        lab.store.mark_reviewed(lab.binary_id, ["140001000"], tool="decompile_function")
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["examined"] == 2
        assert counts["reviewed"] == 1
        assert counts["examined_unreviewed"] == 1

    def test_reviewing_does_not_examine(self, lab):
        """The axes are orthogonal in both directions -- reading a body is not
        a machine examination of it, so `examined` must stay put."""
        self._indexed(lab)
        lab.store.mark_reviewed(lab.binary_id, ["140001000"], tool="decompile_function")
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["reviewed"] == 1
        assert counts["examined"] == 0

    def test_examination_is_idempotent_and_keeps_the_first_timestamp(self, lab):
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        first = lab.store.read(lab.binary_id)["functions"]["0x140001000"]
        result = lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_SWEEP, tool="other_pass",
        )
        assert result["already"] == ["0x140001000"]
        assert result["marked"] == []
        again = lab.store.read(lab.binary_id)["functions"]["0x140001000"]
        assert again["examined_at"] == first["examined_at"]
        assert again["examined_by"] == "diff_binaries"
        assert again["examination_kind"] == EXAMINATION_DIFF

    def test_unknown_address_is_never_inserted(self, lab):
        """A phantom entry would push `examined` above `total` and break the
        invariant a consumer asserts on."""
        self._indexed(lab)
        result = lab.store.mark_examined(
            lab.binary_id, ["140099999"], kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        assert result["unknown"] == ["0x140099999"]
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["examined"] == 0
        assert counts["total"] == 3

    def test_unknown_kind_is_refused(self, lab):
        """A free-form kind lets a caller invent something that reads like a
        review and park it where the counts do not police it."""
        self._indexed(lab)
        with pytest.raises(CoverageError):
            lab.store.mark_examined(
                lab.binary_id, ["140001000"], kind="audited", tool="whatever",
            )

    def test_examination_survives_a_rebuild_without_a_review(self, lab):
        """The state worth preserving is precisely the one where `reviewed` is
        False: a diff-flagged lead nobody has read yet."""
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140002000"], kind=EXAMINATION_DIFF,
            tool="diff_binaries", note="MODIFIED vs old.sys",
        )
        rebuilt = lab.store.index(lab.binary_id, lab.path)
        entry = rebuilt["functions"]["0x140002000"]
        assert entry["examined"] is True
        assert entry["reviewed"] is False
        assert entry["examination_kind"] == EXAMINATION_DIFF
        assert entry["examination_note"] == "MODIFIED vs old.sys"

    def test_clearing_an_examination(self, lab):
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_DIFF,
            tool="diff_binaries", examined=False,
        )
        entry = lab.store.read(lab.binary_id)["functions"]["0x140001000"]
        assert entry["examined"] is False
        assert entry["examination_kind"] is None
        assert entry["examination_note"] is None

    def test_breakdown_counts_every_kind_including_zero(self, lab):
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        breakdown = lab.store.examination_breakdown(lab.store.read(lab.binary_id))
        assert breakdown[EXAMINATION_DIFF] == 1
        # Present and zero, not absent: a consumer must not have to guard for
        # a key that disappears when its count drops.
        assert breakdown[EXAMINATION_SWEEP] == 0

    def test_reset_axes_are_independent(self, lab):
        """A diff pointed at the wrong pair floods the examinations while the
        reviews stay honest. Clearing one must not cost the other."""
        self._indexed(lab)
        lab.store.mark_examined(
            lab.binary_id, ["140001000"], kind=EXAMINATION_DIFF, tool="diff_binaries",
        )
        lab.store.mark_reviewed(lab.binary_id, ["140002000"], tool="decompile_function")

        assert lab.store.reset_examinations(lab.binary_id) == 1
        counts = lab.store.counts(lab.store.read(lab.binary_id))
        assert counts["examined"] == 0
        assert counts["reviewed"] == 1

        assert lab.store.reset_marks(lab.binary_id) == 1
        assert lab.store.counts(lab.store.read(lab.binary_id))["reviewed"] == 0

    def test_auto_examine_indexes_on_demand_and_reports_what_it_wrote(self, lab):
        context = _context(
            [_func("entry", "140001000")],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        lab.analyze(context)
        assert lab.store.read(lab.binary_id) is None
        written = auto_examine(
            lab.cache, lab.path, ["140001000"],
            kind=EXAMINATION_DIFF, tool="diff_binaries", context=context,
        )
        assert written == 1
        assert lab.store.counts(lab.store.read(lab.binary_id))["examined"] == 1

    def test_auto_examine_swallows_failure_and_reports_zero(self, lab):
        """Coverage must never be able to break an analysis tool."""
        broken = MagicMock()
        broken.cache_dir = "/nonexistent/nope"
        assert auto_examine(
            broken, lab.path, ["140001000"], kind=EXAMINATION_DIFF, tool="diff_binaries"
        ) == 0


class TestExaminationInvariants:
    def test_examined_above_total_raises(self):
        with pytest.raises(CoverageError, match="examined > total"):
            _assert_invariants({
                "total": 2, "in_scope_total": 2, "reviewed": 0, "reviewed_in_scope": 0,
                "remaining": 2, "remaining_in_scope": 2,
                "examined": 3, "examined_in_scope": 0, "examined_unreviewed": 0,
            })

    def test_examined_in_scope_above_examined_raises(self):
        with pytest.raises(CoverageError, match="examined_in_scope > examined"):
            _assert_invariants({
                "total": 2, "in_scope_total": 2, "reviewed": 0, "reviewed_in_scope": 0,
                "remaining": 2, "remaining_in_scope": 2,
                "examined": 1, "examined_in_scope": 2, "examined_unreviewed": 0,
            })

    def test_examined_unreviewed_above_remaining_raises(self):
        """Every examined-and-unreviewed function is one of the unreviewed
        ones; exceeding `remaining` means `examined` counts a phantom."""
        with pytest.raises(CoverageError, match="examined_unreviewed > remaining"):
            _assert_invariants({
                "total": 2, "in_scope_total": 2, "reviewed": 2, "reviewed_in_scope": 2,
                "remaining": 0, "remaining_in_scope": 0,
                "examined": 2, "examined_in_scope": 2, "examined_unreviewed": 2,
            })

    def test_six_count_records_still_validate(self):
        """A caller holding only the review counts must keep working."""
        _assert_invariants({
            "total": 2, "in_scope_total": 2, "reviewed": 1, "reviewed_in_scope": 1,
            "remaining": 1, "remaining_in_scope": 1,
        })


class TestStalenessProbe:
    """The cheap staleness probe compares the analysis cache's
    `.meta.json` function_count against a count stored in the record. Those
    two must be derived the SAME way: `ProjectCache` writes
    `len(_build_function_index(data))`, a dict keyed on the raw address, so a
    falsy address vanishes and duplicates collapse. Comparing that against
    `len(functions)` made the probe read stale forever on such a binary, and
    every status poll decompressed the whole analysis cache to re-index.
    """

    def _poll_stamps(self, lab, times=3):
        import time

        stamps = []
        for _ in range(times):
            time.sleep(1.01)  # indexed_at has one-second resolution
            record, _status = lab.store.ensure_indexed(lab.binary_id, lab.path)
            stamps.append(record["indexed_at"])
        return stamps

    def test_duplicate_addresses_do_not_cause_a_rebuild_loop(self, lab):
        lab.analyze(_context([
            _func("a", "140001000"),
            _func("dup", "140001000"),
            _func("b", "140002000"),
        ]))
        lab.store.index(lab.binary_id, lab.path)
        assert len(set(self._poll_stamps(lab))) == 1

    def test_an_addressless_function_does_not_cause_a_rebuild_loop(self, lab):
        lab.analyze(_context([
            _func("a", "140001000"),
            _func("noaddr", ""),
            _func("b", "140002000"),
        ]))
        lab.store.index(lab.binary_id, lab.path)
        assert len(set(self._poll_stamps(lab))) == 1

    def test_the_stored_count_mirrors_how_meta_derives_its_own(self, lab):
        lab.analyze(_context([
            _func("a", "140001000"),
            _func("dup", "140001000"),
            _func("noaddr", ""),
            _func("b", "140002000"),
        ]))
        record = lab.store.index(lab.binary_id, lab.path)
        assert record["source_index_count"] == lab.store._source_function_count(
            lab.binary_id
        )
        # The honest denominator cross-check still counts the whole list.
        assert record["source_function_count"] == 4

    def test_a_grown_cache_still_rebuilds(self, lab):
        """The probe must keep doing its actual job: an incremental Ghidra run
        that adds functions has to re-index."""
        lab.analyze(_context([_func("a", "140001000")]))
        first = lab.store.index(lab.binary_id, lab.path)
        assert first["total"] if "total" in first else True

        lab.analyze(_context([_func("a", "140001000"), _func("b", "140002000")]))
        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert lab.store.counts(record)["total"] == 2

    def test_a_v3_record_is_rebuilt_to_acquire_the_count(self, lab):
        """A record predating v4 has no comparable count; it must not be
        trusted forever, nor loop."""
        lab.analyze(_context([_func("a", "140001000")]))
        lab.store.index(lab.binary_id, lab.path)
        lab.store.mark_reviewed(lab.binary_id, ["140001000"], tool="decompile_function")

        path = lab.store._coverage_path(lab.binary_id)
        stored = json.loads(path.read_text())
        stored["schema_version"] = 3
        stored.pop("source_index_count", None)
        path.write_text(json.dumps(stored))

        record, status = lab.store.ensure_indexed(lab.binary_id, lab.path)
        assert status == "ready"
        assert record["schema_version"] == SCHEMA_VERSION
        assert "source_index_count" in record
        assert record["functions"]["0x140001000"]["reviewed"] is True
