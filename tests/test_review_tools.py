"""
Tests for review / pseudocode-analysis tools.

Uses the _make_function() / _make_analysis_context() factory style
established in tests/test_control_flow_tools.py -- tests call tool
functions directly (returned by register_review_tools) with a MagicMock
cache so no Ghidra is needed.
"""

from __future__ import annotations

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
    jump_tables=None,
    fid_match=None,
    name_source="ANALYSIS",
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
        "jump_tables": jump_tables or [],
        "fid_match": fid_match,
        "name_source": name_source,
    }


def _make_context(functions=None, imports=None, strings=None):
    return {
        "metadata": {"name": "test.exe", "executable_format": "PE"},
        "functions": functions or [],
        "imports": imports or [],
        "strings": strings or [],
        "memory_map": [],
    }


def _register(cache_data):
    """Register tools with a cache mock that returns the given context."""
    from src.tools.review_tools import register_review_tools

    app = MagicMock()
    app.tool.return_value = lambda f: f
    cache = MagicMock()
    cache.get_cached.return_value = cache_data
    runner = MagicMock()
    session_manager = MagicMock()

    (
        get_function_callers,
        scan_pseudocode,
        get_review_package,
        get_switch_tables,
    ) = register_review_tools(app, session_manager, cache, runner)

    # Patch sanitize so tests don't need a real file on disk
    import src.tools.review_tools as rt
    rt.sanitize_binary_path = lambda p, **kw: type("P", (), {"__str__": lambda self: p})()

    return {
        "get_function_callers": get_function_callers,
        "scan_pseudocode": scan_pseudocode,
        "get_review_package": get_review_package,
        "get_switch_tables": get_switch_tables,
        "cache": cache,
        "runner": runner,
    }


# -- get_function_callers --------------------------------------------------


class TestGetFunctionCallers:
    def test_callers_inverted_correctly(self):
        a = _make_function(name="target", address="0x1000", pseudocode="")
        b = _make_function(
            name="caller_b", address="0x2000", pseudocode="",
            called_functions=[{"name": "target", "address": "0x1000"}],
        )
        c = _make_function(
            name="caller_c", address="0x3000", pseudocode="",
            called_functions=[{"name": "target", "address": "0x1000"}],
        )
        tools = _register(_make_context(functions=[a, b, c]))

        result = tools["get_function_callers"]("/bin/test.exe", "target")
        assert "caller_b" in result
        assert "caller_c" in result
        assert "Total: 2" in result

    def test_unknown_function(self):
        tools = _register(_make_context(functions=[_make_function()]))
        result = tools["get_function_callers"]("/bin/test.exe", "missing")
        assert "not found" in result.lower()

    def test_limit_honoured(self):
        target = _make_function(name="t", address="0x1000", pseudocode="")
        callers = [
            _make_function(
                name=f"caller_{i}", address=f"0x{2000 + i:x}", pseudocode="",
                called_functions=[{"name": "t", "address": "0x1000"}],
            )
            for i in range(10)
        ]
        tools = _register(_make_context(functions=[target] + callers))
        result = tools["get_function_callers"]("/bin/test.exe", "t", limit=3)
        assert "Total: 10" in result
        assert "showing 3" in result

    def test_address_lookup(self):
        a = _make_function(name="target", address="0x1000", pseudocode="")
        b = _make_function(
            name="b", address="0x2000", pseudocode="",
            called_functions=[{"name": "target", "address": "0x1000"}],
        )
        tools = _register(_make_context(functions=[a, b]))
        result = tools["get_function_callers"]("/bin/test.exe", "0x1000")
        assert "b" in result


# -- scan_pseudocode -------------------------------------------------------


class TestScanPseudocode:
    def test_strcpy_flagged(self):
        fn = _make_function(pseudocode="char buf[16]; strcpy(buf, input);")
        tools = _register(_make_context(functions=[fn]))

        result = tools["scan_pseudocode"]("/bin/test.exe")
        assert "CWE120_STRCPY" in result
        assert "CWE-120" in result

    def test_gets_flagged_as_critical(self):
        fn = _make_function(pseudocode="char buf[16]; gets(buf);")
        tools = _register(_make_context(functions=[fn]))

        result = tools["scan_pseudocode"]("/bin/test.exe")
        assert "CWE120_GETS" in result
        assert "CRITICAL" in result

    def test_severity_floor_filters_low(self):
        fn = _make_function(pseudocode='sscanf(input, "%d", &x);')
        tools = _register(_make_context(functions=[fn]))

        # sscanf is CWE676_DANGEROUS_FN at severity "low" -- floor=high should drop it
        result = tools["scan_pseudocode"]("/bin/test.exe", severity_floor="high")
        assert "CWE676_DANGEROUS_FN" not in result

    def test_no_findings_clean_code(self):
        fn = _make_function(pseudocode="int f() { return 42; }")
        tools = _register(_make_context(functions=[fn]))

        result = tools["scan_pseudocode"]("/bin/test.exe")
        assert "No findings" in result

    def test_function_filter_regex(self):
        hits = _make_function(name="vuln_handler", pseudocode="strcpy(a, b);")
        misses = _make_function(
            name="safe_handler", address="0x2000", pseudocode="strcpy(c, d);"
        )
        tools = _register(_make_context(functions=[hits, misses]))

        result = tools["scan_pseudocode"](
            "/bin/test.exe", function_filter="^vuln_"
        )
        assert "vuln_handler" in result
        assert "safe_handler" not in result

    def test_multiple_cwe_rules_fire(self):
        """Assorted shipped rules each have a positive test case."""
        samples = {
            "CWE120_STRCPY": "strcpy(dst, src);",
            "CWE120_GETS": "gets(buffer);",
            "CWE120_SPRINTF_UNBOUNDED": "sprintf(out, fmt, x);",
            "CWE134_FORMAT_STRING": "printf(user_fmt);",
            "CWE78_COMMAND_INJECTION": "system(cmd_from_user);",
            "CWE798_HARDCODED_PASSWORD": '"password=hunter2"',
            "CWE415_DOUBLE_FREE": "free(p); free(p);",
            "CWE190_MALLOC_ARITHMETIC": "malloc(n * m);",
            "CWE416_USE_AFTER_FREE": "free(p); do_thing(); p->next = 0;",
            "CWE805_MEMCPY_HEADER_DRIVEN_LEN": "memcpy(dst, src, hdr->payload_len);",
            "CWE190_HEADER_LEN_TO_ALLOC": "buf = malloc(hdr->len * 4 + 8);",
            "CWE401_REALLOC_SHADOW": "p = realloc(p, n);",
            "CWE242_ALLOCA_VARIABLE": "tmp = _alloca(user_size);",
            "CWE242_VIRTUALALLOC_RWX": (
                "mem = VirtualAlloc(0, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);"
            ),
            "CWE193_NULL_TERM_OFF_BY_ONE": "buf[buflen] = 0;",
            "CWE822_DEREF_USER_OFFSET": "x = *(buf + idx);",
            "CWE125_STRLEN_UNTRUSTED_PTR": "n = strlen(pkt->name);",
        }
        for rule_id, snippet in samples.items():
            fn = _make_function(pseudocode=snippet)
            tools = _register(_make_context(functions=[fn]))
            result = tools["scan_pseudocode"]("/bin/test.exe")
            assert rule_id in result, (
                f"Rule {rule_id} did not fire on snippet: {snippet}\n"
                f"Output: {result}"
            )


class TestMemoryCorruptionRules:
    """Positive + negative coverage for the parser-shaped rules.

    Negative cases guard against regex over-reach. Each test scans through
    the real PseudocodeRules registry via scan_text, restricted to the
    rule under test, so we exercise the same code path scan_pseudocode uses.
    """

    def _scan(self, snippet: str, rule_id: str):
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text
        rules = PseudocodeRules()
        rule = rules.get(rule_id)
        assert rule is not None, f"rule {rule_id} not registered"
        return scan_text(snippet, [rule]), rule

    def test_uaf_fires_on_member_deref_after_free(self):
        hits, rule = self._scan(
            "free(p); log_event(); p->next = NULL;",
            "CWE416_USE_AFTER_FREE",
        )
        assert len(hits) == 1
        assert rule.severity == "high"

    def test_uaf_no_fire_when_pointer_only_freed(self):
        hits, _ = self._scan("free(p); p = NULL;", "CWE416_USE_AFTER_FREE")
        assert hits == []

    def test_uaf_no_fire_when_different_pointer_used(self):
        hits, _ = self._scan(
            "free(p); q->next = NULL;", "CWE416_USE_AFTER_FREE"
        )
        assert hits == []

    def test_memcpy_header_driven_fires_on_struct_field(self):
        hits, _ = self._scan(
            "memcpy(dst, src, hdr->payload_len);",
            "CWE805_MEMCPY_HEADER_DRIVEN_LEN",
        )
        assert len(hits) == 1

    def test_memcpy_header_driven_fires_on_deref_len(self):
        hits, _ = self._scan(
            "memcpy(dst, src, *len_ptr);",
            "CWE805_MEMCPY_HEADER_DRIVEN_LEN",
        )
        assert len(hits) == 1

    def test_memcpy_header_driven_no_fire_with_literal_len(self):
        hits, _ = self._scan(
            "memcpy(dst, src, 16);", "CWE805_MEMCPY_HEADER_DRIVEN_LEN"
        )
        assert hits == []

    def test_memcpy_header_driven_no_fire_with_local_len(self):
        # plain identifier (not deref/member/index) should not match
        hits, _ = self._scan(
            "memcpy(dst, src, n);", "CWE805_MEMCPY_HEADER_DRIVEN_LEN"
        )
        assert hits == []

    def test_header_len_to_alloc_fires_on_member_with_arithmetic(self):
        hits, _ = self._scan(
            "buf = malloc(hdr->len * 4 + 8);",
            "CWE190_HEADER_LEN_TO_ALLOC",
        )
        assert len(hits) == 1

    def test_header_len_to_alloc_no_fire_on_constant_alloc(self):
        hits, _ = self._scan("malloc(64);", "CWE190_HEADER_LEN_TO_ALLOC")
        assert hits == []

    def test_realloc_shadow_fires(self):
        hits, rule = self._scan(
            "p = realloc(p, n);", "CWE401_REALLOC_SHADOW"
        )
        assert len(hits) == 1
        assert rule.cwe == "CWE-401"

    def test_realloc_shadow_no_fire_with_temp(self):
        hits, _ = self._scan(
            "tmp = realloc(p, n);", "CWE401_REALLOC_SHADOW"
        )
        assert hits == []

    def test_alloca_variable_fires(self):
        hits, _ = self._scan(
            "tmp = _alloca(user_size);", "CWE242_ALLOCA_VARIABLE"
        )
        assert len(hits) == 1

    def test_alloca_variable_no_fire_on_constant_size(self):
        hits, _ = self._scan(
            "tmp = _alloca(0x100);", "CWE242_ALLOCA_VARIABLE"
        )
        assert hits == []

    def test_virtualalloc_rwx_fires(self):
        hits, _ = self._scan(
            "mem = VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);",
            "CWE242_VIRTUALALLOC_RWX",
        )
        assert len(hits) == 1

    def test_virtualalloc_rw_no_fire(self):
        hits, _ = self._scan(
            "mem = VirtualAlloc(NULL, sz, MEM_COMMIT, PAGE_READWRITE);",
            "CWE242_VIRTUALALLOC_RWX",
        )
        assert hits == []

    def test_virtualprotect_to_rwx_fires(self):
        hits, _ = self._scan(
            "VirtualProtect(addr, sz, PAGE_EXECUTE_READWRITE, &old);",
            "CWE242_VIRTUALALLOC_RWX",
        )
        assert len(hits) == 1

    def test_off_by_one_fires_on_len_index(self):
        hits, _ = self._scan(
            "buf[buflen] = 0;", "CWE193_NULL_TERM_OFF_BY_ONE"
        )
        assert len(hits) == 1

    def test_off_by_one_fires_on_size_suffix(self):
        hits, _ = self._scan(
            "out[outSize] = '\\0';", "CWE193_NULL_TERM_OFF_BY_ONE"
        )
        assert len(hits) == 1

    def test_off_by_one_no_fire_on_constant_index(self):
        hits, _ = self._scan(
            "buf[15] = 0;", "CWE193_NULL_TERM_OFF_BY_ONE"
        )
        assert hits == []

    def test_off_by_one_no_fire_on_unrelated_var(self):
        # variable not named like a length/size
        hits, _ = self._scan(
            "buf[idx] = 0;", "CWE193_NULL_TERM_OFF_BY_ONE"
        )
        assert hits == []

    def test_user_offset_deref_fires(self):
        hits, _ = self._scan("x = *(buf + idx);", "CWE822_DEREF_USER_OFFSET")
        assert len(hits) == 1

    def test_user_offset_deref_no_fire_on_constant(self):
        hits, _ = self._scan("x = *(buf + 4);", "CWE822_DEREF_USER_OFFSET")
        assert hits == []

    def test_strlen_untrusted_member_fires(self):
        hits, _ = self._scan(
            "n = strlen(pkt->name);", "CWE125_STRLEN_UNTRUSTED_PTR"
        )
        assert len(hits) == 1

    def test_strlen_untrusted_deref_fires(self):
        hits, _ = self._scan(
            "n = strlen(*pp);", "CWE125_STRLEN_UNTRUSTED_PTR"
        )
        assert len(hits) == 1

    def test_strlen_local_var_no_fire(self):
        hits, _ = self._scan(
            "n = strlen(buf);", "CWE125_STRLEN_UNTRUSTED_PTR"
        )
        assert hits == []


class TestMemoryCorruptionRulesEndToEnd:
    """Drive the new rules through the actual scan_pseudocode tool surface."""

    def test_severity_floor_filters_low_severity_new_rules(self):
        # CWE125_STRLEN_UNTRUSTED_PTR is severity=low; floor=high should drop
        fn = _make_function(pseudocode="n = strlen(pkt->name);")
        tools = _register(_make_context(functions=[fn]))

        low_result = tools["scan_pseudocode"](
            "/bin/test.exe", severity_floor="low"
        )
        assert "CWE125_STRLEN_UNTRUSTED_PTR" in low_result

        high_result = tools["scan_pseudocode"](
            "/bin/test.exe", severity_floor="high"
        )
        assert "CWE125_STRLEN_UNTRUSTED_PTR" not in high_result

    def test_rule_ids_filter_isolates_single_new_rule(self):
        # Pseudocode triggers multiple rules -- rule_ids should isolate one.
        fn = _make_function(
            pseudocode=(
                "free(p); p->next = NULL; "
                "memcpy(dst, src, hdr->len); "
                "buf = malloc(hdr->len * 2);"
            ),
        )
        tools = _register(_make_context(functions=[fn]))

        result = tools["scan_pseudocode"](
            "/bin/test.exe", rule_ids=["CWE416_USE_AFTER_FREE"]
        )
        assert "CWE416_USE_AFTER_FREE" in result
        assert "CWE805_MEMCPY_HEADER_DRIVEN_LEN" not in result
        assert "CWE190_HEADER_LEN_TO_ALLOC" not in result

    def test_summary_mode_groups_findings_per_function(self):
        parser = _make_function(
            name="parse_packet",
            address="0x1000",
            pseudocode=(
                "memcpy(dst, src, hdr->len); "
                "buf = malloc(hdr->len * 2 + 8); "
                "x = *(buf + idx);"
            ),
        )
        tools = _register(_make_context(functions=[parser]))
        result = tools["scan_pseudocode"]("/bin/test.exe", mode="summary")
        assert "parse_packet" in result
        # The malloc snippet legitimately matches both
        # CWE190_HEADER_LEN_TO_ALLOC and the broader CWE190_MALLOC_ARITHMETIC,
        # so we expect 4 findings consolidated under one function row.
        assert "(4 total)" in result
        assert "1 function(s)" in result


class TestScanPseudocodePagination:
    def _build(self):
        # 25 functions, each with one strcpy finding
        fns = [
            _make_function(name=f"f{i:02d}", address=f"0x{0x1000+i:x}",
                           pseudocode="strcpy(a,b);")
            for i in range(25)
        ]
        return _register(_make_context(functions=fns))

    def test_default_limit_returns_first_page(self):
        tools = self._build()
        result = tools["scan_pseudocode"]("/bin/test.exe", limit=10)
        assert "25 finding" in result
        assert "Showing 1-10 of 25" in result
        assert "offset=10" in result

    def test_offset_returns_next_page(self):
        tools = self._build()
        result = tools["scan_pseudocode"]("/bin/test.exe", limit=10, offset=10)
        assert "Showing 11-20 of 25" in result

    def test_offset_past_end(self):
        tools = self._build()
        result = tools["scan_pseudocode"]("/bin/test.exe", offset=999)
        assert "beyond the result set" in result

    def test_summary_mode(self):
        # 2 functions, different finding counts
        a = _make_function(name="hot", address="0x1000",
                           pseudocode="strcpy(a,b); gets(c); system(d);")
        b = _make_function(name="cool", address="0x2000",
                           pseudocode="strcpy(x,y);")
        tools = _register(_make_context(functions=[a, b]))
        result = tools["scan_pseudocode"]("/bin/test.exe", mode="summary")
        assert "SUMMARY" in result
        assert "hot" in result and "cool" in result
        # Hot function has the critical finding -- should appear before cool
        assert result.index("hot") < result.index("cool")
        assert "critical=" in result or "high=" in result

    def test_invalid_mode(self):
        tools = self._build()
        result = tools["scan_pseudocode"]("/bin/test.exe", mode="bogus")
        assert "Invalid mode" in result


# -- get_review_package ----------------------------------------------------


class TestGetReviewPackage:
    def test_bundles_expected_sections(self):
        target = _make_function(
            name="handler",
            address="0x1000",
            signature="int handler(void *ctx)",
            pseudocode="int handler(void *ctx) { return strlen(ctx); }",
            called_functions=[{"name": "strlen", "address": "0x9000"}],
            basic_blocks=[{"start": "0x1000", "end": "0x1010", "num_addresses": 16}],
        )
        caller = _make_function(
            name="dispatcher",
            address="0x2000",
            pseudocode="",
            called_functions=[{"name": "handler", "address": "0x1000"}],
        )
        imports = [{"library": "msvcrt.dll", "name": "strlen", "address": None}]
        ctx = _make_context(functions=[target, caller], imports=imports)
        tools = _register(ctx)

        result = tools["get_review_package"]("/bin/test.exe", "handler")

        # Required sections
        for section in [
            "# Review Package",
            "## Signature",
            "## Metrics",
            "## Callers",
            "## Callees",
            "## Imported APIs referenced in pseudocode",
            "## Pseudocode rule findings",
            "## Pseudocode",
        ]:
            assert section in result, f"Missing section: {section}"

        # Caller identified
        assert "dispatcher" in result
        # Callee identified
        assert "strlen" in result
        # API usage detected
        assert "strlen" in result
        # Pseudocode embedded
        assert "return strlen(ctx)" in result

    def test_partial_package_no_pseudocode(self):
        target = _make_function(
            name="stub",
            address="0x1000",
            pseudocode=None,
            basic_blocks=[{"start": "0x1000", "end": "0x1010", "num_addresses": 16}],
        )
        tools = _register(_make_context(functions=[target]))
        result = tools["get_review_package"]("/bin/test.exe", "stub")
        assert "no pseudocode" in result.lower()

    def test_unknown_function(self):
        tools = _register(_make_context(functions=[_make_function()]))
        result = tools["get_review_package"]("/bin/test.exe", "missing")
        assert "not found" in result.lower()


# -- get_switch_tables -----------------------------------------------------


class TestGetSwitchTables:
    def test_no_field_in_cache(self):
        """Legacy cache without jump_tables key returns guidance."""
        legacy = _make_function()
        del legacy["jump_tables"]
        tools = _register(_make_context(functions=[legacy]))

        result = tools["get_switch_tables"]("/bin/test.exe")
        assert "predates" in result.lower() or "re-run" in result.lower()

    def test_lists_tables(self):
        fn = _make_function(
            name="dispatcher",
            address="0x1000",
            jump_tables=[
                {
                    "source_addr": "0x1020",
                    "targets": ["0x2000", "0x2010", "0x2020"],
                }
            ],
        )
        tools = _register(_make_context(functions=[fn]))
        result = tools["get_switch_tables"]("/bin/test.exe")
        assert "dispatcher" in result
        assert "switch @ 0x1020" in result
        assert "3 cases" in result

    def test_filter_to_one_function(self):
        matching = _make_function(
            name="keep",
            address="0x1000",
            jump_tables=[{"source_addr": "0x1020", "targets": ["0x2000"]}],
        )
        other = _make_function(
            name="skip",
            address="0x3000",
            jump_tables=[{"source_addr": "0x3020", "targets": ["0x4000"]}],
        )
        tools = _register(_make_context(functions=[matching, other]))
        result = tools["get_switch_tables"]("/bin/test.exe", "keep")
        assert "keep" in result
        assert "skip" not in result
