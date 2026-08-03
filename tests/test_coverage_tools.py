"""
Tests for the coverage MCP tools (the contract surface).

These are the two calls a consumer binds to, so the assertions here are about
the wire shape: exact field names, the six invariants, deterministic worklist
ordering, and the cold-start rule that an unindexed binary reports null counts
rather than zero.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from src.engines.static.ghidra.coverage_store import SCOPE_VERSION, CoverageStore
from src.engines.static.ghidra.project_cache import ProjectCache
from src.tools.coverage_tools import register_coverage_tools

STATUS_FIELDS = {
    "binary_id",
    "binary_path",
    "module_name",
    "image_base",
    "total",
    "in_scope_total",
    "reviewed",
    "reviewed_in_scope",
    "remaining",
    "remaining_in_scope",
    "scope_description",
    "scope_version",
    "indexed_at",
    "status",
}

COUNT_FIELDS = (
    "total",
    "in_scope_total",
    "reviewed",
    "reviewed_in_scope",
    "remaining",
    "remaining_in_scope",
)


def _func(name, address, called=None, *, is_thunk=False, size=64):
    return {
        "name": name,
        "address": address,
        "size": size,
        "is_thunk": is_thunk,
        "is_external": False,
        "decompile_status": "success",
        "parameters": [],
        "pseudocode": "",
        "jump_tables": [],
        "called_functions": [{"address": a, "name": ""} for a in (called or [])],
    }


def _context(functions, exports=None):
    return {
        "metadata": {
            "name": "test.sys",
            "image_base": "140000000",
            "analysis_depth": "full",
        },
        "functions": functions,
        "exports": exports or [],
    }


def _payload(result):
    """Tools return a plain dict; FastMCP serializes it at the boundary.

    Accepting either shape keeps these assertions honest whichever side of the
    protocol they are read from.
    """
    return json.loads(result) if isinstance(result, str) else result


class _App:
    """Minimal FastMCP stand-in that captures the registered callables."""

    def __init__(self):
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorate(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorate


class _Sessions:
    _current_binary_path = None


@pytest.fixture
def tools(tmp_path):
    class Lab:
        def __init__(self):
            self.cache = ProjectCache(cache_dir=str(tmp_path))
            self.store = CoverageStore(self.cache)
            self.sessions = _Sessions()
            self.binary = tmp_path / "test.sys"
            self.binary.write_bytes(b"MZ" + b"\x00" * 512)
            self.path = str(self.binary)
            self.binary_id = hashlib.sha256(self.binary.read_bytes()).hexdigest()
            app = _App()
            register_coverage_tools(app, self.sessions, self.cache, None)
            self.status = app.tools["get_coverage_status"]
            self.next = app.tools["get_next_unreviewed"]
            self.index = app.tools["coverage_index"]
            self.mark = app.tools["mark_function_reviewed"]
            self.reset = app.tools["reset_coverage"]

        def analyze(self, functions, exports=None):
            self.cache.save_cached(self.path, _context(functions, exports))

        def three_functions(self):
            self.analyze(
                [
                    _func("entry", "140001000", called=["140002000"]),
                    _func("helper", "140002000", size=100),
                    _func("thunk", "140003000", is_thunk=True),
                ],
                exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
            )

    return Lab()


def _assert_contract_invariants(payload):
    for field in COUNT_FIELDS:
        value = payload[field]
        assert isinstance(value, int) and value >= 0, f"{field}={value!r}"
    assert payload["remaining"] == payload["total"] - payload["reviewed"]
    assert (
        payload["remaining_in_scope"]
        == payload["in_scope_total"] - payload["reviewed_in_scope"]
    )
    assert payload["in_scope_total"] <= payload["total"]
    assert payload["reviewed_in_scope"] <= payload["reviewed"]


class TestWireShape:
    """The tools must return a dict, not a JSON string.

    FastMCP puts a ``str`` return under ``structuredContent.result`` *as a
    string*, so a consumer that peels one envelope layer lands on a string and
    its flat-object assumption breaks. Returning the object itself keeps every
    transport path flat.
    """

    @pytest.mark.parametrize(
        "call",
        [
            lambda t: t.status(binary_id="f" * 64),
            lambda t: t.next(binary_id="f" * 64),
            lambda t: t.index(binary_path=t.path),
            lambda t: t.mark(functions="0x1", binary_id="f" * 64),
        ],
    )
    def test_tools_return_flat_objects(self, tools, call):
        result = call(tools)
        assert isinstance(result, dict), f"got {type(result).__name__}"
        assert "result" not in result
        assert "data" not in result


class TestColdStart:
    def test_unindexed_binary_returns_null_counts_not_zero(self, tools):
        """Zero here reads as 'complete' and would terminate a review loop on a
        binary nobody has looked at -- the exact bug this store exists to fix.
        """
        payload = _payload(tools.status(binary_id="f" * 64))
        assert payload["status"] == "not_indexed"
        for field in COUNT_FIELDS:
            assert payload[field] is None, f"{field} must be null, got {payload[field]!r}"

    def test_unindexed_response_is_still_well_formed(self, tools):
        payload = _payload(tools.status(binary_id="f" * 64))
        assert STATUS_FIELDS <= set(payload)
        assert payload["binary_id"] == "f" * 64
        assert payload["scope_version"] == SCOPE_VERSION

    def test_worklist_on_unindexed_binary_is_not_terminal(self, tools):
        payload = _payload(tools.next(binary_id="f" * 64))
        assert payload["status"] == "not_indexed"
        assert payload["functions"] == []
        assert payload["remaining_after"] is None

    def test_already_analyzed_binary_indexes_on_first_query(self, tools):
        """Reporting not_indexed for a binary that is already fully analyzed
        would strand every previously-cached target."""
        tools.three_functions()
        payload = _payload(tools.status(binary_id=tools.binary_id))
        assert payload["status"] == "ready"
        assert payload["total"] == 3


class TestStatusShape:
    def test_field_names_and_invariants(self, tools):
        tools.three_functions()
        payload = _payload(tools.status(binary_id=tools.binary_id))
        assert STATUS_FIELDS <= set(payload)
        _assert_contract_invariants(payload)
        assert payload["total"] == 3
        assert payload["in_scope_total"] == 2
        assert payload["reviewed"] == 0
        assert payload["remaining"] == 3
        assert payload["remaining_in_scope"] == 2

    def test_image_base_is_prefixed_hex(self, tools):
        tools.three_functions()
        payload = _payload(tools.status(binary_id=tools.binary_id))
        assert payload["image_base"] == "0x140000000"

    def test_scope_version_is_reported(self, tools):
        tools.three_functions()
        payload = _payload(tools.status(binary_id=tools.binary_id))
        assert payload["scope_version"] == SCOPE_VERSION

    def test_binary_path_resolution(self, tools):
        tools.three_functions()
        payload = _payload(tools.status(binary_path=tools.path))
        assert payload["binary_id"] == tools.binary_id
        assert payload["status"] == "ready"

    def test_active_session_binary_is_the_fallback(self, tools):
        tools.three_functions()
        tools.sessions._current_binary_path = tools.path
        payload = _payload(tools.status())
        assert payload["binary_id"] == tools.binary_id

    def test_no_resolvable_binary_is_an_error(self, tools):
        payload = _payload(tools.status())
        assert "error" in payload

    def test_malformed_binary_id_is_an_error(self, tools):
        payload = _payload(tools.status(binary_id="not-a-sha"))
        assert "error" in payload

    def test_counts_track_marks(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        payload = _payload(tools.status(binary_id=tools.binary_id))
        _assert_contract_invariants(payload)
        assert payload["reviewed"] == 1
        assert payload["reviewed_in_scope"] == 1
        assert payload["remaining"] == 2
        assert payload["remaining_in_scope"] == 1


class TestWorklist:
    def test_ordering_is_ascending_numeric_address(self, tools):
        tools.analyze(
            [
                _func("c", "140003000"),
                _func("a", "140001000"),
                _func("b", "140002000"),
            ]
        )
        payload = _payload(tools.next(binary_id=tools.binary_id, count=10))
        addresses = [f["address"] for f in payload["functions"]]
        assert addresses == ["0x140001000", "0x140002000", "0x140003000"]

    def test_repeated_call_returns_the_same_head(self, tools):
        """A client that crashes mid-batch and re-calls must get the same head
        of the queue."""
        tools.three_functions()
        first = _payload(tools.next(binary_id=tools.binary_id, count=2))
        second = _payload(tools.next(binary_id=tools.binary_id, count=2))
        assert first["functions"] == second["functions"]

    def test_marking_makes_forward_progress(self, tools):
        tools.three_functions()
        first = _payload(tools.next(binary_id=tools.binary_id, count=1))
        head = first["functions"][0]["address"]
        tools.store.mark_reviewed(tools.binary_id, [head], tool="t")
        second = _payload(tools.next(binary_id=tools.binary_id, count=1))
        assert second["functions"][0]["address"] != head

    def test_terminal_condition(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(
            tools.binary_id, ["0x140001000", "0x140002000"], tool="t"
        )
        payload = _payload(tools.next(binary_id=tools.binary_id, count=10))
        assert payload["functions"] == []
        assert payload["remaining_after"] == 0
        assert payload["status"] == "ready"

    def test_remaining_after_accounts_for_the_batch(self, tools):
        tools.three_functions()
        payload = _payload(tools.next(binary_id=tools.binary_id, count=1))
        assert payload["returned"] == 1
        assert payload["remaining_after"] == 1

    def test_function_record_shape(self, tools):
        tools.three_functions()
        payload = _payload(tools.next(binary_id=tools.binary_id, count=1))
        entry = payload["functions"][0]
        assert set(entry) == {"address", "name", "size", "in_scope", "scope_reason"}
        assert entry["address"].startswith("0x")
        assert entry["in_scope"] is True

    def test_scope_all_includes_excluded_functions(self, tools):
        tools.three_functions()
        in_scope = _payload(tools.next(binary_id=tools.binary_id, count=10))
        every = _payload(tools.next(binary_id=tools.binary_id, count=10, scope="all"))
        assert len(in_scope["functions"]) == 2
        assert len(every["functions"]) == 3
        thunk = next(f for f in every["functions"] if f["address"] == "0x140003000")
        assert thunk["in_scope"] is False
        assert thunk["scope_reason"] == "excluded:thunk"

    def test_invalid_scope_is_an_error(self, tools):
        tools.three_functions()
        payload = _payload(tools.next(binary_id=tools.binary_id, scope="sideways"))
        assert "error" in payload

    def test_count_out_of_range_is_an_error(self, tools):
        tools.three_functions()
        assert "error" in _payload(tools.next(binary_id=tools.binary_id, count=0))
        assert "error" in _payload(tools.next(binary_id=tools.binary_id, count=10_000))


class TestIndexTool:
    def test_index_reports_counts(self, tools):
        tools.three_functions()
        payload = _payload(tools.index(binary_path=tools.path))
        assert payload["status"] == "ready"
        _assert_contract_invariants(payload)
        assert payload["total"] == 3

    def test_index_without_analysis_is_an_error(self, tools):
        payload = _payload(tools.index(binary_path=tools.path))
        assert "error" in payload
        assert payload["status"] == "not_indexed"

    def test_force_rebuild_keeps_marks(self, tools):
        tools.three_functions()
        tools.index(binary_path=tools.path)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        payload = _payload(tools.index(binary_path=tools.path, force=True))
        assert payload["reviewed"] == 1


class TestMarkTool:
    def test_manual_mark_round_trip(self, tools):
        tools.three_functions()
        payload = _payload(
            tools.mark(
                functions="0x140002000",
                binary_id=tools.binary_id,
                note="unchecked length",
            )
        )
        assert payload["marked"] == ["0x140002000"]
        assert payload["reviewed"] == 1
        _assert_contract_invariants(payload)
        entry = tools.store.read(tools.binary_id)["functions"]["0x140002000"]
        assert entry["findings_note"] == "unchecked length"

    def test_second_mark_is_idempotent(self, tools):
        tools.three_functions()
        tools.mark(functions="0x140002000", binary_id=tools.binary_id)
        payload = _payload(
            tools.mark(functions="0x140002000", binary_id=tools.binary_id)
        )
        assert payload["marked"] == []
        assert payload["already"] == ["0x140002000"]
        assert payload["reviewed"] == 1

    def test_unknown_address_is_reported_not_counted(self, tools):
        tools.three_functions()
        payload = _payload(tools.mark(functions="0xdeadbeef", binary_id=tools.binary_id))
        assert payload["unknown"] == ["0xdeadbeef"]
        assert payload["reviewed"] == 0

    def test_function_names_are_rejected(self, tools):
        tools.three_functions()
        payload = _payload(tools.mark(functions="helper", binary_id=tools.binary_id))
        assert "error" in payload

    def test_unmark(self, tools):
        tools.three_functions()
        tools.mark(functions="0x140002000", binary_id=tools.binary_id)
        payload = _payload(
            tools.mark(
                functions="0x140002000", binary_id=tools.binary_id, reviewed=False
            )
        )
        assert payload["reviewed"] == 0

    def test_mark_before_analysis_is_an_error(self, tools):
        payload = _payload(tools.mark(functions="0x140002000", binary_id=tools.binary_id))
        assert "error" in payload


class TestResetTool:
    """The undo for a contaminated ledger.

    Marks that don't reflect anyone reading the code are worse than no marks:
    the next campaign reads "fully reviewed" and stops. Operators need a
    documented way to correct that without deleting files out of the cache.
    """

    def test_reset_clears_every_mark(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(
            tools.binary_id, ["0x140001000", "0x140002000"], tool="t", note="bogus"
        )
        assert tools.store.counts(tools.store.read(tools.binary_id))["reviewed"] == 2

        payload = _payload(tools.reset(binary_id=tools.binary_id))

        assert payload["cleared"] == 2
        assert payload["reviewed"] == 0
        assert payload["reviewed_in_scope"] == 0
        assert payload["remaining"] == payload["total"]
        _assert_contract_invariants(payload)

    def test_reset_clears_findings_notes_too(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(
            tools.binary_id, ["0x140002000"], tool="t", note="bogus finding"
        )
        tools.reset(binary_id=tools.binary_id)
        entry = tools.store.read(tools.binary_id)["functions"]["0x140002000"]
        assert entry["findings_note"] is None
        assert entry["reviewed_at"] is None
        assert entry["reviewed_by"] is None

    def test_reset_keeps_the_index_and_scope(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        payload = _payload(tools.reset(binary_id=tools.binary_id))
        assert payload["status"] == "ready"
        assert payload["total"] == 3
        assert payload["in_scope_total"] == 2
        assert payload["dropped"] is False

    def test_reset_is_idempotent(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        tools.reset(binary_id=tools.binary_id)
        payload = _payload(tools.reset(binary_id=tools.binary_id))
        assert payload["cleared"] == 0
        assert payload["reviewed"] == 0

    def test_drop_index_rebuilds_from_the_analysis_cache(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        payload = _payload(tools.reset(binary_id=tools.binary_id, drop_index=True))
        assert payload["dropped"] is True
        assert payload["status"] == "ready"
        assert payload["total"] == 3
        assert payload["reviewed"] == 0

    def test_reset_without_a_record_is_an_error_not_a_silent_success(self, tools):
        tools.three_functions()
        payload = _payload(tools.reset(binary_id=tools.binary_id))
        assert "error" in payload
        assert payload["status"] == "not_indexed"

    def test_reset_by_path(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(tools.binary_id, ["0x140002000"], tool="t")
        payload = _payload(tools.reset(binary_path=tools.path))
        assert payload["cleared"] == 1

    def test_reset_does_not_touch_the_analysis_cache(self, tools):
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.reset(binary_id=tools.binary_id, drop_index=True)
        assert (tools.cache.cache_dir / f"{tools.binary_id}.json.gz").exists()

    def test_worklist_is_full_again_after_a_reset(self, tools):
        """The point of the reset: the loop must have work to do again."""
        tools.three_functions()
        tools.status(binary_id=tools.binary_id)
        tools.store.mark_reviewed(
            tools.binary_id, ["0x140001000", "0x140002000"], tool="t"
        )
        assert _payload(tools.next(binary_id=tools.binary_id))["functions"] == []
        tools.reset(binary_id=tools.binary_id)
        after = _payload(tools.next(binary_id=tools.binary_id))
        assert len(after["functions"]) == 2
        assert after["remaining_after"] == 0


class TestAutoMarkingSet:
    """Locks down which tools advance the denominator as a side effect.

    Over-marking is the dangerous direction: a tool that "reviews" functions
    nobody read manufactures the false completion this store exists to prevent.
    The consumer restates this set in its operator docs, so it must not drift
    silently.
    """

    @pytest.fixture
    def analysis_tools(self, tools):
        from src.tools.function_hash_tools import register_function_hash_tools
        from src.tools.review_tools import register_review_tools

        tools.analyze(
            [
                _func("entry", "140001000", called=["140002000"]),
                {
                    **_func("helper", "140002000"),
                    "pseudocode": "void helper(int *p){ memcpy(p, param_1, 8); }",
                    "parameters": [{"name": "param_1", "datatype": "char *"}],
                    "signature": "void helper(char *param_1)",
                    "basic_blocks": [],
                    "local_variables": [],
                },
            ],
            exports=[{"address": "140001000", "name": "entry", "type": "Function"}],
        )
        app = _App()
        register_function_hash_tools(app, tools.sessions, tools.cache, None)
        register_review_tools(app, tools.sessions, tools.cache, None, None)
        return tools, app.tools

    def _reviewed(self, tools):
        record = tools.store.read(tools.binary_id)
        if record is None:
            return set()
        return {a for a, e in record["functions"].items() if e["reviewed"]}

    def test_batch_decompile_marks(self, analysis_tools):
        tools, api = analysis_tools
        api["batch_decompile"](binary_path=tools.path, functions="0x140002000")
        assert self._reviewed(tools) == {"0x140002000"}

    def test_batch_decompile_does_not_mark_what_it_could_not_decompile(
        self, analysis_tools
    ):
        tools, api = analysis_tools
        # 0x140001000 has no pseudocode in this fixture.
        api["batch_decompile"](binary_path=tools.path, functions="0x140001000")
        assert self._reviewed(tools) == set()

    def test_get_review_package_marks(self, analysis_tools):
        tools, api = analysis_tools
        api["get_review_package"](
            binary_path=tools.path, function_name_or_address="0x140002000"
        )
        assert self._reviewed(tools) == {"0x140002000"}

    def test_get_param_sinks_marks(self, analysis_tools):
        tools, api = analysis_tools
        api["get_param_sinks"](binary_path=tools.path, function="0x140002000")
        assert self._reviewed(tools) == {"0x140002000"}

    def test_get_function_callers_does_not_mark(self, analysis_tools):
        tools, api = analysis_tools
        api["get_function_callers"](
            binary_path=tools.path, function_name_or_address="0x140002000"
        )
        assert self._reviewed(tools) == set()

    def test_scan_pseudocode_does_not_mark(self, analysis_tools):
        """A whole-binary regex sweep is not a review of every function it
        touched."""
        tools, api = analysis_tools
        api["scan_pseudocode"](binary_path=tools.path)
        assert self._reviewed(tools) == set()

    def test_analyze_function_completeness_does_not_mark(self, analysis_tools):
        tools, api = analysis_tools
        api["analyze_function_completeness"](
            binary_path=tools.path, function_name_or_address="0x140002000"
        )
        assert self._reviewed(tools) == set()

    def test_marking_is_idempotent_across_repeated_reads(self, analysis_tools):
        tools, api = analysis_tools
        api["batch_decompile"](binary_path=tools.path, functions="0x140002000")
        first = tools.store.read(tools.binary_id)["functions"]["0x140002000"]
        api["get_review_package"](
            binary_path=tools.path, function_name_or_address="0x140002000"
        )
        second = tools.store.read(tools.binary_id)["functions"]["0x140002000"]
        assert second["reviewed_at"] == first["reviewed_at"]
        assert second["reviewed_by"] == "batch_decompile"
        assert tools.store.counts(tools.store.read(tools.binary_id))["reviewed"] == 1
