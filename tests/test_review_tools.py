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


class TestCredentialFormatRules:
    """High-confidence token-format rules that should not be down-ranked."""

    def _scan(self, snippet, rule_id):
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text
        rules = PseudocodeRules()
        rule = rules.get(rule_id)
        assert rule is not None, f"rule {rule_id} not registered"
        return scan_text(snippet, [rule]), rule

    def test_aws_access_key_fires(self):
        hits, rule = self._scan(
            'const char *k = "AKIAIOSFODNN7EXAMPLE";',
            "CWE798_AWS_ACCESS_KEY",
        )
        assert len(hits) == 1
        assert rule.severity == "critical"
        assert hits[0]["confidence"] == 90

    def test_aws_access_key_no_fire_on_label(self):
        hits, _ = self._scan('const char *k = "AKIA";', "CWE798_AWS_ACCESS_KEY")
        assert hits == []

    def test_github_pat_fires(self):
        hits, _ = self._scan(
            'token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";',
            "CWE798_GITHUB_TOKEN",
        )
        assert len(hits) == 1

    def test_stripe_secret_fires(self):
        hits, _ = self._scan(
            'k = "sk_live_abcdefghij1234567890ZZZ";',
            "CWE798_STRIPE_SECRET",
        )
        assert len(hits) == 1

    def test_jwt_fires(self):
        hits, _ = self._scan(
            'auth = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
            'eyJzdWIiOiJ1MSJ9.SIG_part_here";',
            "CWE798_JWT_TOKEN",
        )
        assert len(hits) == 1

    def test_jwt_no_fire_on_short_eyj(self):
        hits, _ = self._scan('s = "eyJab";', "CWE798_JWT_TOKEN")
        assert hits == []


class TestConfidenceScoring:
    """Per-finding confidence math: negative pattern, scanner penalty,
    corroboration bonus, sink bonus."""

    def test_baseline_confidence_present(self):
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text
        rules = PseudocodeRules()
        rule = rules.get("CWE120_GETS")
        hits = scan_text("gets(buf);", [rule])
        assert hits[0]["confidence"] == 95

    def test_negative_pattern_penalises_credential_regex_string(self):
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text
        rule = PseudocodeRules().get("CWE798_HARDCODED_PASSWORD")
        # Regex-style literal -- should be penalised by negative_pattern.
        hits = scan_text(r'pat = "(password|secret|api_key)";', [rule])
        assert len(hits) == 1
        assert hits[0]["confidence"] < 30  # baseline 30 minus 40 = floored to 0

    def test_negative_pattern_skips_clean_credential(self):
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text
        rule = PseudocodeRules().get("CWE798_HARDCODED_PASSWORD")
        hits = scan_text('s = "password=hunter2";', [rule])
        assert len(hits) == 1
        assert hits[0]["confidence"] == 30

    def test_corroboration_bonus_applies_when_multiple_rules_hit(self):
        from src.utils.pseudocode_rules import (
            PseudocodeRules,
            adjust_confidences,
            scan_text,
        )
        pseudo = "strcpy(dst, src); free(p); free(p);"
        rules = PseudocodeRules()
        hits = scan_text(pseudo, rules.rules)
        adjust_confidences(hits, pseudo)
        rule_ids = {h["rule_id"] for h in hits}
        # At least CWE120_STRCPY and CWE415_DOUBLE_FREE
        assert "CWE120_STRCPY" in rule_ids
        assert "CWE415_DOUBLE_FREE" in rule_ids
        for h in hits:
            if h["rule_id"] == "CWE415_DOUBLE_FREE":
                # Baseline 70 + corroboration 30 = 100 (clamped)
                assert h["confidence"] >= 90

    def test_scanner_penalty_drops_credential_in_regex_compiler(self):
        from src.utils.pseudocode_rules import (
            PseudocodeRules,
            adjust_confidences,
            scan_text,
        )
        pseudo = (
            'pat = "password|secret|api_key"; '
            'compiled = pcre_compile(pat, 0, &err);'
        )
        rule = PseudocodeRules().get("CWE798_HARDCODED_PASSWORD")
        hits = scan_text(pseudo, [rule])
        adjust_confidences(hits, pseudo)
        assert hits[0]["confidence"] == 0  # negative + scanner penalty

    def test_high_signal_credential_unaffected_by_scanner_penalty(self):
        from src.utils.pseudocode_rules import (
            PseudocodeRules,
            adjust_confidences,
            scan_text,
        )
        pseudo = (
            'k = "AKIAIOSFODNN7EXAMPLE"; pat = pcre_compile("foo", 0, 0);'
        )
        rules = PseudocodeRules()
        rule = rules.get("CWE798_AWS_ACCESS_KEY")
        hits = scan_text(pseudo, [rule])
        adjust_confidences(hits, pseudo)
        # AWS rule keeps its 90 even when in a "scanner" function
        assert hits[0]["confidence"] == 90

    def test_sink_bonus_applies_to_strcpy_with_memcpy_in_function(self):
        from src.utils.pseudocode_rules import (
            PseudocodeRules,
            adjust_confidences,
            scan_text,
        )
        pseudo = "strcpy(dst, src); memcpy(other, x, 16);"
        rule = PseudocodeRules().get("CWE120_STRCPY")
        hits = scan_text(pseudo, [rule])
        adjust_confidences(hits, pseudo)
        # baseline 60 + sink bonus 20 = 80
        assert hits[0]["confidence"] == 80


class TestScanPseudocodeFiltering:
    """exclude_rule_ids and confidence_floor surface tests."""

    def test_exclude_rule_ids_drops_specified_rules(self):
        fn = _make_function(pseudocode="strcpy(a,b); gets(c);")
        tools = _register(_make_context(functions=[fn]))
        result = tools["scan_pseudocode"](
            "/bin/test.exe", exclude_rule_ids=["CWE120_STRCPY"]
        )
        assert "CWE120_STRCPY" not in result
        assert "CWE120_GETS" in result

    def test_confidence_floor_drops_low_confidence_findings(self):
        # CWE798_HARDCODED_PASSWORD with regex-meta literal -> conf 0
        fn = _make_function(pseudocode='p = "(pass|secret|key)";')
        tools = _register(_make_context(functions=[fn]))

        low = tools["scan_pseudocode"](
            "/bin/test.exe", confidence_floor=0
        )
        assert "CWE798_HARDCODED_PASSWORD" in low

        high = tools["scan_pseudocode"](
            "/bin/test.exe", confidence_floor=50
        )
        assert "CWE798_HARDCODED_PASSWORD" not in high
        assert "dropped" in high.lower()

    def test_findings_sorted_by_confidence_within_severity(self):
        # Two critical findings, different functions so corroboration doesn't
        # level them. gets baseline 95 vs system baseline 75.
        a = _make_function(
            name="fa", address="0x1000", pseudocode="gets(buf);",
        )
        b = _make_function(
            name="fb", address="0x2000", pseudocode="system(cmd);",
        )
        tools = _register(_make_context(functions=[a, b]))
        result = tools["scan_pseudocode"]("/bin/test.exe")
        gets_idx = result.find("CWE120_GETS")
        sys_idx = result.find("CWE78_COMMAND_INJECTION")
        assert gets_idx >= 0 and sys_idx >= 0
        assert gets_idx < sys_idx, "Higher confidence should appear first"

    def test_summary_shows_max_confidence_per_function(self):
        fn = _make_function(pseudocode='k = "AKIAIOSFODNN7EXAMPLE";')
        tools = _register(_make_context(functions=[fn]))
        result = tools["scan_pseudocode"]("/bin/test.exe", mode="summary")
        assert "conf=90" in result


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
        assert "4 total" in result
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


def _ctx_rule(
    rid: str,
    severity: str,
    confidence: int,
    fn,
    cwe: str = "CWE-000",
    description: str = "synthetic context rule",
    recommendation: str = "synthetic recommendation",
):
    """Build a synthetic context rule for the tests below."""
    from src.utils.pseudocode_rules import PseudocodeRule, RuleKind

    return PseudocodeRule(
        id=rid,
        cwe=cwe,
        severity=severity,
        confidence=confidence,
        description=description,
        recommendation=recommendation,
        kind=RuleKind.CONTEXT,
        context_fn=fn,
    )


def _regex_rule(
    rid: str,
    severity: str,
    confidence: int,
    pattern: str,
    cwe: str = "CWE-000",
    description: str = "synthetic regex rule",
    recommendation: str = "synthetic recommendation",
):
    """Build a synthetic regex rule for the tests below."""
    import re as _re

    from src.utils.pseudocode_rules import PseudocodeRule, RuleKind

    return PseudocodeRule(
        id=rid,
        cwe=cwe,
        severity=severity,
        confidence=confidence,
        description=description,
        recommendation=recommendation,
        pattern=_re.compile(pattern, _re.MULTILINE),
        kind=RuleKind.REGEX,
    )


class TestSplitStatements:
    """Statement-splitter is the foundation for context-rule line ranges."""

    def test_returns_empty_for_none(self):
        from src.utils.pseudocode_rules import _split_statements

        assert _split_statements(None) == []

    def test_returns_empty_for_blank(self):
        from src.utils.pseudocode_rules import _split_statements

        assert _split_statements("") == []
        assert _split_statements("   \n\n  ") == []

    def test_simple_statements(self):
        from src.utils.pseudocode_rules import _split_statements

        stmts = _split_statements("a = 1; b = 2; c = a + b;")

        assert [s.text for s in stmts] == ["a = 1", "b = 2", "c = a + b"]
        assert all(s.start_line == 1 and s.end_line == 1 for s in stmts)

    def test_brace_block(self):
        from src.utils.pseudocode_rules import _split_statements

        stmts = _split_statements("if (x) { a = 1; b = 2; }")

        # Splits on '(', ';', '{', '}' -> keeps non-empty fragments.
        assert "if (x)" in [s.text for s in stmts]
        assert "a = 1" in [s.text for s in stmts]
        assert "b = 2" in [s.text for s in stmts]

    def test_line_numbers_track_newlines(self):
        from src.utils.pseudocode_rules import _split_statements

        pseudo = "a = 1;\nb = 2;\nc = 3;\n"
        stmts = _split_statements(pseudo)

        assert [s.start_line for s in stmts] == [1, 2, 3]
        assert [s.end_line for s in stmts] == [1, 2, 3]

    def test_multiline_statement_spans_lines(self):
        from src.utils.pseudocode_rules import _split_statements

        pseudo = "a =\n  foo(\n    bar\n  );"
        stmts = _split_statements(pseudo)

        assert len(stmts) == 1
        assert stmts[0].start_line == 1
        assert stmts[0].end_line == 4


class TestPseudocodeRulePostInit:
    """__post_init__ guards prevent half-built rules at registration time."""

    def test_regex_rule_requires_pattern(self):
        import pytest

        from src.utils.pseudocode_rules import PseudocodeRule, RuleKind

        with pytest.raises(ValueError, match="MISSING_PATTERN.*requires a 'pattern'"):
            PseudocodeRule(
                id="MISSING_PATTERN",
                cwe="CWE-000",
                severity="low",
                confidence=10,
                description="x",
                recommendation="x",
                pattern=None,
                kind=RuleKind.REGEX,
            )

    def test_context_rule_requires_context_fn(self):
        import pytest

        from src.utils.pseudocode_rules import PseudocodeRule, RuleKind

        with pytest.raises(ValueError, match="MISSING_FN.*requires a 'context_fn'"):
            PseudocodeRule(
                id="MISSING_FN",
                cwe="CWE-000",
                severity="low",
                confidence=10,
                description="x",
                recommendation="x",
                kind=RuleKind.CONTEXT,
                context_fn=None,
            )


class TestContextRuleDispatch:
    """Context rules dispatched through scan_text alongside regex rules."""

    def test_regex_rule_unchanged(self):
        """Existing regex rules emit the historical finding shape."""
        from src.utils.pseudocode_rules import PseudocodeRules, scan_text

        rule = PseudocodeRules().get("CWE120_STRCPY")
        hits = scan_text("strcpy(dest, src);", [rule])

        assert len(hits) == 1
        assert hits[0]["rule_id"] == "CWE120_STRCPY"
        assert hits[0]["cwe"] == "CWE-120"
        assert "excerpt" in hits[0]
        assert "description" in hits[0]
        assert "recommendation" in hits[0]
        assert "confidence" in hits[0]
        assert "severity" in hits[0]

    def test_context_rule_fires_with_message_and_lines(self):
        """A synthetic context rule emits findings carrying its own line range."""
        from src.utils.pseudocode_rules import ContextFinding, scan_text

        pseudo = (
            "int handler() {\n"
            "  copy_from_user(buf, in, n);\n"
            "  *p = a;\n"
            "  *q = b;\n"
            "  *r = c;\n"
            "}\n"
        )

        def detect_post_probe_derefs(pcode, statements):
            findings: list[ContextFinding] = []
            seen_probe = False
            deref_count = 0
            first_line = 0
            last_line = 0
            for stmt in statements:
                if "copy_from_user" in stmt.text:
                    seen_probe = True
                    continue
                if seen_probe and "*" in stmt.text and "=" in stmt.text:
                    deref_count += 1
                    if first_line == 0:
                        first_line = stmt.start_line
                    last_line = stmt.end_line
            if deref_count >= 3:
                findings.append(
                    ContextFinding(
                        message=f"{deref_count} dereferences after probe call",
                        confidence=85,
                        start_line=first_line,
                        end_line=last_line,
                    )
                )
            return findings

        rule = _ctx_rule("DEREF_AFTER_PROBE", "high", 50, detect_post_probe_derefs)

        hits = scan_text(pseudo, [rule])

        assert len(hits) == 1
        assert hits[0]["rule_id"] == "DEREF_AFTER_PROBE"
        assert hits[0]["severity"] == "high"  # inherited from rule baseline
        assert hits[0]["confidence"] == 85  # finding overrides rule baseline
        assert "3 dereferences" in hits[0]["description"]
        assert "*p = a" in hits[0]["excerpt"]

    def test_context_finding_can_promote_severity(self):
        """ContextFinding(severity='critical') overrides rule.severity."""
        from src.utils.pseudocode_rules import ContextFinding, scan_text

        def fn(pcode, statements):
            return [
                ContextFinding(
                    message="elevated",
                    confidence=70,
                    start_line=1,
                    end_line=1,
                    severity="critical",
                )
            ]

        rule = _ctx_rule("PROMOTE", "low", 10, fn)
        hits = scan_text("foo;", [rule])

        assert hits[0]["severity"] == "critical"

    def test_context_finding_confidence_clamped(self):
        from src.utils.pseudocode_rules import ContextFinding, scan_text

        def fn(pcode, statements):
            return [
                ContextFinding(
                    message="overflow", confidence=999, start_line=1, end_line=1
                ),
                ContextFinding(
                    message="underflow", confidence=-50, start_line=1, end_line=1
                ),
            ]

        rule = _ctx_rule("CLAMP", "low", 10, fn)
        hits = scan_text("foo;", [rule])

        assert [h["confidence"] for h in hits] == [100, 0]

    def test_context_rule_no_findings_returns_empty(self):
        from src.utils.pseudocode_rules import scan_text

        def fn(pcode, statements):
            return []

        rule = _ctx_rule("EMPTY", "low", 10, fn)
        assert scan_text("foo;", [rule]) == []

    def test_context_rule_skipped_on_empty_pseudocode(self):
        from src.utils.pseudocode_rules import scan_text

        def fn(pcode, statements):  # pragma: no cover - should not be called
            raise AssertionError("context_fn invoked on empty pseudocode")

        rule = _ctx_rule("SKIP", "low", 10, fn)
        assert scan_text("", [rule]) == []
        assert scan_text(None, [rule]) == []  # type: ignore[arg-type]

    def test_mixed_kinds_compose_under_adjust_confidences(self):
        """Both kinds in one scan: corroboration bonus applies across kinds."""
        from src.utils.pseudocode_rules import (
            CORROBORATION_BONUS,
            ContextFinding,
            adjust_confidences,
            scan_text,
        )

        def fn(pcode, statements):
            return [
                ContextFinding(
                    message="ctx hit", confidence=40, start_line=1, end_line=1
                )
            ]

        ctx_rule = _ctx_rule("CTX", "medium", 40, fn)
        rx_rule = _regex_rule("RX", "high", 50, r"\bdanger\b")

        pseudo = "danger;"
        hits = scan_text(pseudo, [ctx_rule, rx_rule])
        adjust_confidences(hits, pseudo)

        assert {h["rule_id"] for h in hits} == {"CTX", "RX"}
        # Two distinct rules fired -> corroboration bonus applied to both.
        for h in hits:
            assert h["confidence"] >= 40 + CORROBORATION_BONUS - 1  # post-clamp


class TestContextRuleScanPseudocodeIntegration:
    """End-to-end via scan_pseudocode with monkey-patched rule registry."""

    def _install_rules(self, monkeypatch, rules):
        from src.utils.pseudocode_rules import PseudocodeRules

        registry = PseudocodeRules()
        # Replace the loaded rules with our synthetic set.
        registry.rules = list(rules)
        registry._rules_by_id = {r.id: r for r in registry.rules}

        import src.tools.review_tools as rt

        monkeypatch.setattr(rt, "_RULES", registry)

    def test_context_rule_surfaces_in_scan_pseudocode(self, monkeypatch):
        from src.utils.pseudocode_rules import ContextFinding

        def fn(pcode, statements):
            if any("FETCH_USER" in s.text for s in statements):
                return [
                    ContextFinding(
                        message="user fetch detected",
                        confidence=90,
                        start_line=1,
                        end_line=1,
                    )
                ]
            return []

        rule = _ctx_rule("USER_FETCH", "high", 70, fn)
        self._install_rules(monkeypatch, [rule])

        fn_dict = _make_function(
            name="vuln", address="0x1000", pseudocode="FETCH_USER(buf);"
        )
        tools = _register(_make_context(functions=[fn_dict]))

        result = tools["scan_pseudocode"]("/bin/test.exe")

        assert "USER_FETCH" in result
        assert "vuln" in result
        assert "user fetch detected" in result

    def test_severity_floor_filters_context_rule(self, monkeypatch):
        from src.utils.pseudocode_rules import ContextFinding

        def fn(pcode, statements):
            return [
                ContextFinding(
                    message="info-level chatter",
                    confidence=99,
                    start_line=1,
                    end_line=1,
                )
            ]

        rule = _ctx_rule("INFO_RULE", "info", 99, fn)
        self._install_rules(monkeypatch, [rule])

        fn_dict = _make_function(
            name="any", address="0x1000", pseudocode="anything;"
        )
        tools = _register(_make_context(functions=[fn_dict]))

        # severity_floor=medium suppresses an info-severity context rule.
        result = tools["scan_pseudocode"](
            "/bin/test.exe", severity_floor="medium"
        )
        assert "INFO_RULE" not in result

    def test_rule_ids_filter_context_rule(self, monkeypatch):
        from src.utils.pseudocode_rules import ContextFinding

        def fn_a(pcode, statements):
            return [
                ContextFinding(
                    message="a fired", confidence=80, start_line=1, end_line=1
                )
            ]

        def fn_b(pcode, statements):
            return [
                ContextFinding(
                    message="b fired", confidence=80, start_line=1, end_line=1
                )
            ]

        rule_a = _ctx_rule("CTX_A", "high", 50, fn_a)
        rule_b = _ctx_rule("CTX_B", "high", 50, fn_b)
        self._install_rules(monkeypatch, [rule_a, rule_b])

        fn_dict = _make_function(
            name="z", address="0x1000", pseudocode="anything;"
        )
        tools = _register(_make_context(functions=[fn_dict]))

        result = tools["scan_pseudocode"](
            "/bin/test.exe", rule_ids=["CTX_A"]
        )
        assert "CTX_A" in result
        assert "CTX_B" not in result
