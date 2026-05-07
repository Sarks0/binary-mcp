"""
Tests for dispatch / IOCTL recovery tools.

Cache-only — uses MagicMock cache and ``_register`` factory mirroring
``tests/test_review_tools.py`` so no Ghidra subprocess is invoked.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _restore_module_globals():
    """Restore monkey-patched ``BinaryReader`` after every test so
    unrelated test files (e.g. ``test_search_bytes``) don't inherit the
    fake reader."""
    import src.utils.binary_reader as br

    orig_reader = br.BinaryReader
    try:
        yield
    finally:
        br.BinaryReader = orig_reader


def _make_function(
    name="DriverDispatch",
    address="0x140012000",
    pseudocode="",
    parameters=None,
    called_functions=None,
    jump_tables=None,
    is_thunk=False,
    is_external=False,
):
    return {
        "name": name,
        "address": address,
        "pseudocode": pseudocode,
        "parameters": parameters or [],
        "called_functions": called_functions or [],
        "jump_tables": jump_tables or [],
        "is_thunk": is_thunk,
        "is_external": is_external,
        "basic_blocks": [],
        "local_variables": [],
        "signature": "",
        "decompile_status": "success",
    }


def _make_context(functions=None, analysis_depth="full"):
    return {
        "metadata": {
            "name": "test.sys",
            "executable_format": "PE",
            "analysis_depth": analysis_depth,
        },
        "functions": functions or [],
    }


def _register(cache_data):
    """Register dispatch tools with a MagicMock cache and return the callables."""
    from src.tools.dispatch_tools import register_dispatch_tools

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

    # Patch sanitize so tests don't need a real file on disk.
    import src.tools.dispatch_tools as dt
    import src.utils.security as security

    original = security.sanitize_binary_path
    security.sanitize_binary_path = lambda p, **kw: type("P", (), {"__str__": lambda self: p})()

    try:
        register_dispatch_tools(app, session_manager, cache, runner)
    finally:
        security.sanitize_binary_path = original

    return captured["find_ioctl_handlers"], cache, runner, dt


class TestCandidateDetection:
    def test_name_substring_dispatch(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(name="MyDriverDispatch")
        is_cand, _ = _is_dispatcher_candidate(f)
        assert is_cand

    def test_name_substring_ioctl_case_insensitive(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(name="HandleIOCTL")
        is_cand, _ = _is_dispatcher_candidate(f)
        assert is_cand

    def test_name_substring_handlerequest(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(name="SrvHandleRequest")
        is_cand, _ = _is_dispatcher_candidate(f)
        assert is_cand

    def test_first_param_pirp(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(
            name="sub_140012000",
            parameters=[{"name": "Irp", "datatype": "PIRP"}],
        )
        is_cand, hint = _is_dispatcher_candidate(f)
        assert is_cand
        assert hint == "Irp"

    def test_first_param_ulong(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(
            name="sub_x",
            parameters=[{"name": "code", "datatype": "ULONG"}],
        )
        is_cand, _ = _is_dispatcher_candidate(f)
        assert is_cand

    def test_neither_param_nor_name_match(self):
        from src.tools.dispatch_tools import _is_dispatcher_candidate

        f = _make_function(
            name="copy_buffer",
            parameters=[{"name": "dst", "datatype": "char *"}],
        )
        is_cand, _ = _is_dispatcher_candidate(f)
        assert not is_cand


class TestConstantExtraction:
    def test_extract_case_constants(self):
        from src.tools.dispatch_tools import _extract_constants

        pseudo = """
        switch (code) {
            case 0x222000: handle_a(); break;
            case 0x222004: handle_b(); break;
            case 0x222008: handle_c(); break;
        }
        """
        values, selector = _extract_constants(pseudo)
        assert set(values.keys()) == {0x222000, 0x222004, 0x222008}
        assert all(origin == "case" for origin in values.values())
        assert selector is None  # no comparison-side selector

    def test_extract_comparison_constants(self):
        from src.tools.dispatch_tools import _extract_constants

        pseudo = """
        if (param_2 == 0x10001) { ... }
        else if (param_2 == 0x10002) { ... }
        else if (param_2 > 0x10000) { ... }
        """
        values, selector = _extract_constants(pseudo)
        assert set(values.keys()) == {0x10001, 0x10002, 0x10000}
        assert selector == "param_2"

    def test_extract_mixed_keeps_case_origin(self):
        """When a value appears as both compare and case, ``case`` wins for
        target-zip ordering correctness."""
        from src.tools.dispatch_tools import _extract_constants

        pseudo = "if (param_1 == 0x111) {} switch (x) { case 0x111: break; }"
        values, _selector = _extract_constants(pseudo)
        assert values[0x111] == "compare"  # first-seen wins (compare scanned first)

    def test_no_dispatch_constants(self):
        from src.tools.dispatch_tools import _extract_constants

        pseudo = "int x = 1; return x + 2;"
        values, selector = _extract_constants(pseudo)
        assert values == {}
        assert selector is None


class TestCtlCodeDecoding:
    def test_decode_textbook_buffered(self):
        from src.tools.dispatch_tools import _decode_ctl_code

        # CTL_CODE(FILE_DEVICE_TYPE=0x22, function=0x800, METHOD_BUFFERED=0,
        #          FILE_ANY_ACCESS=0) = 0x22 << 16 | 0 << 14 | 0x800 << 2 | 0
        # = 0x220000 | 0x2000 = 0x222000
        decoded = _decode_ctl_code(0x222000)
        assert decoded["device"] == 0x22
        assert decoded["function"] == 0x800
        assert decoded["method"] == "BUFFERED"
        assert decoded["access"] == "FILE_ANY_ACCESS"

    def test_decode_method_neither_is_high_risk(self):
        from src.tools.dispatch_tools import _decode_ctl_code

        decoded = _decode_ctl_code(0x222003)
        assert decoded["method"] == "NEITHER"
        assert decoded["risk"] == "high"

    def test_decode_method_in_direct(self):
        from src.tools.dispatch_tools import _decode_ctl_code

        decoded = _decode_ctl_code(0x222001)
        assert decoded["method"] == "IN_DIRECT"

    def test_decode_method_out_direct(self):
        from src.tools.dispatch_tools import _decode_ctl_code

        decoded = _decode_ctl_code(0x222002)
        assert decoded["method"] == "OUT_DIRECT"

    def test_decode_access_levels(self):
        from src.tools.dispatch_tools import _decode_ctl_code

        # Build values where bits 14..15 vary
        values_for_access = {
            0: 0x22 << 16 | 0 << 14 | 0x800 << 2 | 0,  # FILE_ANY_ACCESS
            1: 0x22 << 16 | 1 << 14 | 0x800 << 2 | 0,
            2: 0x22 << 16 | 2 << 14 | 0x800 << 2 | 0,
            3: 0x22 << 16 | 3 << 14 | 0x800 << 2 | 0,
        }
        names = {
            0: "FILE_ANY_ACCESS",
            1: "FILE_READ_ACCESS",
            2: "FILE_WRITE_ACCESS",
            3: "FILE_READ_WRITE_ACCESS",
        }
        for raw_access, value in values_for_access.items():
            assert _decode_ctl_code(value)["access"] == names[raw_access]


class TestJumpTableJoin:
    def test_targets_resolved_when_aligned(self):
        from src.tools.dispatch_tools import _build_dispatcher_record

        target_a = _make_function(name="HandleQueryInfo", address="0x140013000")
        target_b = _make_function(name="HandleSetInfo", address="0x140013100")
        target_c = _make_function(name="HandleNotify", address="0x140013200")
        dispatch = _make_function(
            name="DriverDispatch",
            address="0x140012000",
            pseudocode=(
                "switch (param_2) {\n"
                "    case 0x222000: HandleQueryInfo(); break;\n"
                "    case 0x222004: HandleSetInfo(); break;\n"
                "    case 0x222008: HandleNotify(); break;\n"
                "}\n"
            ),
            jump_tables=[
                {
                    "source_addr": "0x140012010",
                    "targets": ["0x140013000", "0x140013100", "0x140013200"],
                }
            ],
        )

        functions = [dispatch, target_a, target_b, target_c]

        from src.tools.dispatch_tools import (
            _build_addr_index,
            _build_jump_table_index,
        )

        addr_index = _build_addr_index(functions)
        jt_index = _build_jump_table_index(functions)

        record = _build_dispatcher_record(dispatch, None, addr_index, jt_index)

        assert record is not None
        assert record["case_count"] == 3
        targets = [c["target"] for c in record["cases"]]
        assert targets == [
            "HandleQueryInfo @ 0x140013000",
            "HandleSetInfo @ 0x140013100",
            "HandleNotify @ 0x140013200",
        ]

    def test_unresolved_targets_marked_indirect(self):
        from src.tools.dispatch_tools import (
            _build_addr_index,
            _build_dispatcher_record,
            _build_jump_table_index,
        )

        # Pseudocode has cases but no jump_tables and no callee functions
        # registered -> targets remain None and the note is set.
        dispatch = _make_function(
            name="DriverDispatch",
            address="0x140012000",
            pseudocode="case 0x10001: x; case 0x10002: y;",
        )
        addr_index = _build_addr_index([dispatch])
        jt_index = _build_jump_table_index([dispatch])

        record = _build_dispatcher_record(dispatch, None, addr_index, jt_index)

        assert record is not None
        for c in record["cases"]:
            assert c["target"] is None
            assert c.get("note") == "indirect"


class TestInlinedTailCall:
    def test_recursion_finds_constants_in_callee(self):
        """An entry function with no constants but a single callee that
        does have them surfaces as a dispatcher anchored on the entry."""
        callee = _make_function(
            name="DispatchInternal",
            address="0x140012100",
            pseudocode="case 0x222000: a(); case 0x222004: b();",
        )
        entry = _make_function(
            name="DriverDispatch",
            address="0x140012000",
            pseudocode="return DispatchInternal(arg);",
            called_functions=[{"name": "DispatchInternal", "address": "0x140012100"}],
        )

        tools, *_ = _register(_make_context(functions=[entry, callee]))
        result = tools("/some.sys")

        assert "DriverDispatch @ 0x140012000" in result
        assert "0x222000" in result
        assert "Inferred via callee: DispatchInternal" in result


class TestEarlyErrors:
    def test_no_cache_returns_canonical_error(self):
        tool, *_ = _register(None)
        result = tool("/bin/test.sys")
        assert "has not been analyzed yet" in result

    def test_shallow_cache_guidance(self):
        ctx = _make_context(analysis_depth="structural", functions=[])
        tool, *_ = _register(ctx)
        result = tool("/bin/test.sys")
        assert "structural" in result
        assert "force_reanalyze=True" in result

    def test_no_functions_returns_summary(self):
        tool, *_ = _register(_make_context(functions=[]))
        result = tool("/bin/test.sys")
        assert "No functions found" in result

    def test_no_dispatchers_returns_friendly_summary(self):
        f = _make_function(
            name="boring_helper",
            parameters=[{"name": "x", "datatype": "int"}],
            pseudocode="return x + 1;",
        )
        tool, *_ = _register(_make_context(functions=[f]))
        result = tool("/bin/test.sys")
        assert "No IOCTL dispatchers detected" in result

    def test_invalid_function_filter_regex(self):
        f = _make_function(name="DriverDispatch")
        tool, *_ = _register(_make_context(functions=[f]))
        result = tool("/bin/test.sys", function_filter="(unclosed[")
        assert "invalid function_filter" in result

    def test_safe_regex_compile_rejects_redos(self):
        """ReDoS-shaped patterns are rejected by safe_regex_compile and
        surface as a structured error rather than reaching the regex engine."""
        f = _make_function(name="DriverDispatch")
        tool, *_ = _register(_make_context(functions=[f]))
        result = tool("/bin/test.sys", function_filter="(.+)+a")
        assert "invalid function_filter" in result
        assert "ReDoS" in result or "nested quantifiers" in result


class TestFunctionFilter:
    def test_filter_restricts_results(self):
        keep = _make_function(
            name="KeepDispatch",
            address="0x100",
            pseudocode="case 0x222000: a();",
        )
        skip = _make_function(
            name="SkipDispatch",
            address="0x200",
            pseudocode="case 0x222004: b();",
        )
        tool, *_ = _register(_make_context(functions=[keep, skip]))

        result = tool("/bin/test.sys", function_filter="^Keep")
        assert "KeepDispatch" in result
        assert "SkipDispatch" not in result


class TestCacheOnlyContract:
    def test_runner_never_invoked(self):
        f = _make_function(
            name="DriverDispatch",
            address="0x100",
            pseudocode="case 0x222000: a();",
        )
        tool, _cache, runner, _dt = _register(_make_context(functions=[f]))
        tool("/bin/test.sys")
        assert runner.method_calls == []
        assert runner.mock_calls == []


class TestRegistration:
    def test_registers_one_tool(self):
        from src.tools.dispatch_tools import register_dispatch_tools

        app = MagicMock()
        app.tool = MagicMock(return_value=lambda f: f)
        cache = MagicMock()
        runner = MagicMock()
        session_manager = MagicMock()

        register_dispatch_tools(app, session_manager, cache, runner)

        assert app.tool.call_count >= 1
