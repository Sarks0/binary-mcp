"""
Tests for the static -> dynamic crossover layer.

Covers the seam where Ghidra analysis results are handed to x64dbg: resolving a
caller-supplied binary reference to a cache entry, matching a loaded module, and
rebasing static addresses to runtime ones. These paths used to fail silently --
producing a plausible but wrong address, or reporting an analyzed binary as
never analyzed -- so the assertions here are mostly about *refusing* to guess.
"""

from unittest.mock import MagicMock, patch

import pytest

from src.engines.dynamic.x64dbg.bridge import (
    FeatureUnavailableError,
    normalize_module,
    normalize_thread,
)
from src.tools.dynamic_tools import (
    AddressRebaseError,
    BinaryResolutionError,
    _load_function_mappings,
    _lookup_function,
    _resolve_function_to_runtime,
    _resolve_module_for_binary,
    rebase_static_address,
    resolve_cached_binary,
)


class TestNormalizeModule:
    """The plugin's wire format must land on stable keys."""

    def test_derives_name_from_path_when_plugin_omits_it(self):
        # Older plugin builds send the module name under "path" and no "name".
        mod = normalize_module({"base": "140000000", "size": 4096, "path": "sample.exe"})
        assert mod["name"] == "sample.exe"
        assert mod["display_name"] == "sample.exe"

    def test_derives_name_from_full_windows_path(self):
        mod = normalize_module({"base": 0, "path": r"C:\Windows\System32\kernel32.dll"})
        assert mod["name"] == "kernel32.dll"

    def test_prefers_explicit_name(self):
        mod = normalize_module({"base": 0, "name": "Evil.dll", "path": r"C:\tmp\Evil.dll"})
        assert mod["name"] == "evil.dll"
        assert mod["display_name"] == "Evil.dll"

    def test_coerces_bare_hex_base(self):
        # The plugin streams base as hex with no 0x prefix.
        assert normalize_module({"base": "140000000"})["base"] == 0x140000000

    def test_coerces_prefixed_hex_base(self):
        assert normalize_module({"base": "0x400000"})["base"] == 0x400000

    def test_missing_name_does_not_become_empty_string(self):
        # An empty name is what made `name in binary_name` match everything.
        mod = normalize_module({"base": 0})
        assert mod["display_name"] == "unknown"


def make_bridge(modules):
    """A real X64DbgBridge with only the HTTP layer stubbed out.

    Mocking get_modules/find_module directly would skip the very normalization
    and matching logic these tests exist to cover.
    """
    from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

    bridge = X64DbgBridge.__new__(X64DbgBridge)
    bridge._request_with_retry = lambda endpoint, data=None: {
        "success": True,
        "modules": list(modules),
    }
    return bridge


class TestFindModule:
    """Module matching must be strict -- a wrong match rebases everything wrong."""

    def _bridge(self, modules):
        return make_bridge(modules)

    def test_exact_name_match(self):
        bridge = self._bridge([{"base": 1, "path": "host.exe"}, {"base": 2, "path": "evil.dll"}])
        assert bridge.find_module("evil.dll")["base"] == 2

    def test_matches_by_basename_of_a_path(self):
        bridge = self._bridge([{"base": 2, "path": "evil.dll"}])
        assert bridge.find_module(r"C:\samples\evil.dll")["base"] == 2

    def test_matches_ignoring_extension(self):
        bridge = self._bridge([{"base": 2, "path": "evil.dll"}])
        assert bridge.find_module("evil")["base"] == 2

    def test_does_not_substring_match(self):
        # "a.dll" must not match "dataa.dll".
        bridge = self._bridge([{"base": 9, "path": "dataa.dll"}])
        assert bridge.find_module("a.dll") is None

    def test_unknown_module_returns_none_not_first_module(self):
        bridge = self._bridge([{"base": 1, "path": "host.exe"}])
        assert bridge.find_module("evil.dll") is None

    def test_main_module_flagged_when_plugin_omits_it(self):
        bridge = self._bridge([{"base": 1, "path": "host.exe"}, {"base": 2, "path": "b.dll"}])
        assert bridge.get_modules()[0]["is_main"] is True


class TestRebaseStaticAddress:
    def test_applies_the_formula(self):
        assert rebase_static_address(0x4025B0, 0x400000, 0x1200000) == 0x12025B0

    def test_identity_when_loaded_at_preferred_base(self):
        assert rebase_static_address(0x4025B0, 0x400000, 0x400000) == 0x4025B0

    def test_rejects_address_below_image_base(self):
        # Previously formatted as negative hex and returned as a real address.
        with pytest.raises(AddressRebaseError) as exc:
            rebase_static_address(0x1000, 0x400000, 0x1200000)
        assert "below the image base" in str(exc.value)

    def test_handles_64bit_bases(self):
        assert rebase_static_address(0x140001000, 0x140000000, 0x7FF600000000) == 0x7FF600001000


class TestResolveModuleForBinary:
    def _bridge(self, modules):
        return make_bridge(modules)

    def test_returns_the_matching_module(self):
        bridge = self._bridge([{"base": 0x1000, "path": "evil.dll"}])
        assert _resolve_module_for_binary("evil.dll", bridge)["base"] == 0x1000

    def test_raises_rather_than_falling_back_to_first_module(self):
        # The old code rebased a DLL's addresses against the host executable.
        bridge = self._bridge([{"base": 0x400000, "path": "host.exe"}])
        with pytest.raises(AddressRebaseError) as exc:
            _resolve_module_for_binary("evil.dll", bridge)
        assert "not loaded" in str(exc.value)
        assert "host.exe" in str(exc.value)

    def test_raises_when_nothing_is_loaded(self):
        bridge = self._bridge([])
        with pytest.raises(AddressRebaseError) as exc:
            _resolve_module_for_binary("evil.dll", bridge)
        assert "No modules are loaded" in str(exc.value)


class TestResolveCachedBinary:
    def test_existing_path_passes_through(self, tmp_path):
        binary = tmp_path / "sample.exe"
        binary.write_bytes(b"MZ")
        assert resolve_cached_binary(str(binary)) == str(binary)

    def test_bare_name_resolves_via_cache_index(self, tmp_path):
        binary = tmp_path / "EchoManager32.exe"
        binary.write_bytes(b"MZ")
        cache = MagicMock()
        cache.list_cached.return_value = [
            {"binary_path": str(binary), "binary_name": "EchoManager32.exe"}
        ]
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            # This is the exact call shape the tool docstrings advertise.
            assert resolve_cached_binary("EchoManager32.exe") == str(binary)

    def test_bare_name_match_is_case_insensitive(self, tmp_path):
        binary = tmp_path / "Sample.EXE"
        binary.write_bytes(b"MZ")
        cache = MagicMock()
        cache.list_cached.return_value = [
            {"binary_path": str(binary), "binary_name": "Sample.EXE"}
        ]
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            assert resolve_cached_binary("sample.exe") == str(binary)

    def test_ambiguous_name_is_reported_without_leaking_paths(self, tmp_path):
        a = tmp_path / "a" / "dup.exe"
        b = tmp_path / "b" / "dup.exe"
        for path in (a, b):
            path.parent.mkdir(parents=True)
            path.write_bytes(b"MZ")
        cache = MagicMock()
        cache.list_cached.return_value = [
            {"binary_path": str(a), "binary_name": "dup.exe"},
            {"binary_path": str(b), "binary_name": "dup.exe"},
        ]
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with pytest.raises(BinaryResolutionError) as exc:
                resolve_cached_binary("dup.exe")
        message = str(exc.value)
        assert "matches 2" in message
        # Audit F-10: the candidates' absolute paths must not be echoed back.
        assert str(a) not in message and str(b) not in message
        assert "analyze_binary" in message

    def test_unknown_name_lists_what_is_analyzed(self, tmp_path):
        known = tmp_path / "known.exe"
        known.write_bytes(b"MZ")
        cache = MagicMock()
        cache.list_cached.return_value = [
            {"binary_path": str(known), "binary_name": "known.exe"}
        ]
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with pytest.raises(BinaryResolutionError) as exc:
                resolve_cached_binary("missing.exe")
        assert "known.exe" in str(exc.value)

    def test_moved_binary_says_so(self, tmp_path):
        cache = MagicMock()
        cache.list_cached.return_value = [
            {"binary_path": str(tmp_path / "gone.exe"), "binary_name": "gone.exe"}
        ]
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with pytest.raises(BinaryResolutionError) as exc:
                resolve_cached_binary("gone.exe")
        assert "no longer" in str(exc.value)

    def test_empty_reference_rejected(self):
        with pytest.raises(BinaryResolutionError):
            resolve_cached_binary("")


class TestFunctionMappings:
    """The mapping table must not be polluted with lowercase duplicates."""

    def _cache(self, functions, image_base="0x400000"):
        cache = MagicMock()
        cache.get_cached.return_value = {
            "functions": functions,
            "metadata": {"image_base": image_base},
        }
        return cache

    def test_keeps_only_real_names(self, tmp_path):
        binary = str(tmp_path / "s.exe")
        cache = self._cache([
            {"name": "DecryptPayload", "address": "0x401000"},
            {"name": "main", "address": "0x402000"},
        ])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                mappings = _load_function_mappings(binary)
        assert set(mappings) == {"DecryptPayload", "main"}

    def test_case_differing_names_do_not_collide(self, tmp_path):
        binary = str(tmp_path / "s.exe")
        cache = self._cache([
            {"name": "Handler", "address": "0x401000"},
            {"name": "handler", "address": "0x402000"},
        ])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                mappings = _load_function_mappings(binary)
        # Merging a lowercased copy used to drop one of these entirely.
        assert mappings["Handler"]["address"] == "0x401000"
        assert mappings["handler"]["address"] == "0x402000"

    def test_lookup_is_case_insensitive(self):
        mappings = {"DecryptPayload": {"address": "0x401000"}}
        assert _lookup_function(mappings, "decryptpayload")["address"] == "0x401000"

    def test_lookup_prefers_exact_match(self):
        mappings = {"Handler": {"address": "0x1"}, "handler": {"address": "0x2"}}
        assert _lookup_function(mappings, "handler")["address"] == "0x2"

    def test_lookup_misses_return_none(self):
        assert _lookup_function({"a": {}}, "b") is None


class TestResolveFunctionToRuntime:
    def _bridge(self, modules):
        return make_bridge(modules)

    def _cache(self, image_base):
        cache = MagicMock()
        cache.get_cached.return_value = {
            "functions": [{"name": "DecryptPayload", "address": "0x401000"}],
            "metadata": ({"image_base": image_base} if image_base else {}),
        }
        return cache

    def test_resolves_against_the_named_module(self, tmp_path):
        binary = str(tmp_path / "evil.dll")
        bridge = self._bridge([
            {"base": 0x400000, "path": "host.exe"},
            {"base": 0x1200000, "path": "evil.dll"},
        ])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=self._cache("0x400000")):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                result = _resolve_function_to_runtime("DecryptPayload", binary, bridge)
        # Not the host executable's base, which is what the old fallback used.
        assert result["runtime_address"] == "0x01201000"
        assert result["module_name"] == "evil.dll"

    def test_refuses_when_module_not_loaded(self, tmp_path):
        binary = str(tmp_path / "evil.dll")
        bridge = self._bridge([{"base": 0x400000, "path": "host.exe"}])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=self._cache("0x400000")):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                with pytest.raises(AddressRebaseError):
                    _resolve_function_to_runtime("DecryptPayload", binary, bridge)

    def test_refuses_to_guess_a_missing_image_base(self, tmp_path):
        binary = str(tmp_path / "evil.dll")
        bridge = self._bridge([{"base": 0x1200000, "path": "evil.dll"}])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=self._cache(None)):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                with pytest.raises(AddressRebaseError) as exc:
                    _resolve_function_to_runtime("DecryptPayload", binary, bridge)
        assert "image base" in str(exc.value)

    def test_unknown_function_returns_none(self, tmp_path):
        binary = str(tmp_path / "evil.dll")
        bridge = self._bridge([{"base": 0x1200000, "path": "evil.dll"}])
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=self._cache("0x400000")):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                result = _resolve_function_to_runtime("NoSuchFunction", binary, bridge)
        assert result is None

    def test_widens_formatting_for_64bit_addresses(self, tmp_path):
        binary = str(tmp_path / "s.exe")
        bridge = self._bridge([{"base": 0x7FF600000000, "path": "s.exe"}])
        cache = MagicMock()
        cache.get_cached.return_value = {
            "functions": [{"name": "f", "address": "0x140001000"}],
            "metadata": {"image_base": "0x140000000"},
        }
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                result = _resolve_function_to_runtime("f", binary, bridge)
        assert result["runtime_address"] == "0x00007FF600001000"


class TestMappingCacheKey:
    """The in-process mapping cache must be keyed consistently."""

    def test_same_binary_via_different_path_spellings_shares_one_entry(self, tmp_path):
        binary = tmp_path / "s.exe"
        binary.write_bytes(b"MZ")
        cache = MagicMock()
        cache.get_cached.return_value = {
            "functions": [{"name": "f", "address": "0x401000"}],
            "metadata": {"image_base": "0x400000"},
        }
        with patch("src.tools.dynamic_tools.get_ghidra_cache", return_value=cache):
            with patch.dict("src.tools.dynamic_tools._function_mappings", {}, clear=True):
                _load_function_mappings(str(binary))
                _load_function_mappings(str(tmp_path / "." / "s.exe"))
                from src.tools.dynamic_tools import _function_mappings

                assert len(_function_mappings) == 1
        # Second call must have been served from the cache, not re-read.
        assert cache.get_cached.call_count == 1


class TestNormalizeThread:
    """Thread dicts must distinguish "not reported" from a real zero."""

    def test_full_thread_from_current_plugin(self):
        t = normalize_thread({
            "id": 4816, "number": 0, "entry": "7ff61a2b1000",
            "teb": "1a2000", "cip": "7ff61a2b1240", "suspend_count": 0,
            "priority": 0, "wait_reason": 13, "last_error": 0,
            "name": "worker", "is_current": True,
        })
        assert t["id"] == 4816
        assert t["entry"] == 0x7FF61A2B1000
        assert t["cip"] == 0x7FF61A2B1240
        assert t["wait_reason_name"] == "WrUserRequest"
        assert t["is_current"] is True

    def test_thread_id_is_decimal_not_hex(self):
        # The plugin sends id as a JSON number; it must not be read as hex.
        assert normalize_thread({"id": 1234})["id"] == 1234

    def test_legacy_thread_leaves_detail_unreported(self):
        # Older builds send only id and is_current. Absent fields must be None
        # so callers can say "not reported" instead of printing "0xunknown".
        t = normalize_thread({"id": 4816, "is_current": True})
        assert t["entry"] is None
        assert t["cip"] is None
        assert t["suspend_count"] is None
        assert t["wait_reason_name"] is None

    def test_suspend_count_zero_is_not_none(self):
        assert normalize_thread({"id": 1, "suspend_count": 0})["suspend_count"] == 0

    def test_unknown_wait_reason_has_no_name(self):
        assert normalize_thread({"id": 1, "wait_reason": 999})["wait_reason_name"] is None


def make_thread_bridge(threads):
    """A real X64DbgBridge with only the HTTP layer stubbed out."""
    from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

    bridge = X64DbgBridge.__new__(X64DbgBridge)
    bridge._request_with_retry = lambda endpoint, data=None: {
        "success": True,
        "threads": list(threads),
    }
    return bridge


class TestFindThread:
    def test_finds_by_decimal_id(self):
        bridge = make_thread_bridge([{"id": 4816}, {"id": 1234}])
        assert bridge.find_thread("1234")["id"] == 1234

    def test_finds_by_hex_id(self):
        # x64dbg's own thread view shows ids in hex.
        bridge = make_thread_bridge([{"id": 4816}])
        assert bridge.find_thread("0x12D0")["id"] == 4816

    def test_accepts_an_int(self):
        bridge = make_thread_bridge([{"id": 4816}])
        assert bridge.find_thread(4816)["id"] == 4816

    def test_unknown_id_returns_none(self):
        bridge = make_thread_bridge([{"id": 4816}])
        assert bridge.find_thread("9999") is None

    def test_garbage_id_returns_none(self):
        bridge = make_thread_bridge([{"id": 4816}])
        assert bridge.find_thread("not-a-tid") is None


class TestFeatureUnavailable:
    """A 404 is a missing feature, not a dead connection."""

    def _bridge(self, status):
        import requests

        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge.__new__(X64DbgBridge)
        bridge.base_url = "http://127.0.0.1:8765"
        bridge.timeout = 5
        bridge._auth_token = "token"
        bridge._error_logger = MagicMock()

        response = MagicMock()
        response.status_code = status
        response.json.return_value = {}
        response.text = ""
        error = requests.HTTPError(f"{status} Client Error")
        error.response = response
        response.raise_for_status.side_effect = error
        return bridge, response

    def test_404_raises_feature_unavailable(self):
        bridge, response = self._bridge(404)
        with patch("requests.post", return_value=response):
            with pytest.raises(FeatureUnavailableError) as exc:
                bridge._request("/api/thread/suspend", {"thread_id": "1"})
        assert "no handler" in str(exc.value)
        # Must not read as a connection problem -- that is what sent callers
        # into reconnect loops against an endpoint that never existed.
        assert "Failed to connect" not in str(exc.value)

    def test_other_http_errors_stay_connection_errors(self):
        bridge, response = self._bridge(500)
        with patch("requests.post", return_value=response):
            with pytest.raises(ConnectionError):
                bridge._request("/api/thread/suspend", {"thread_id": "1"})

    def test_feature_unavailable_is_not_retried(self):
        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge.__new__(X64DbgBridge)
        bridge._max_retries = 3
        bridge._max_reconnects = 2
        bridge._retry_delay = 0
        calls = []

        def boom(endpoint, data=None):
            calls.append(endpoint)
            raise FeatureUnavailableError(endpoint)

        bridge._request = boom
        with pytest.raises(FeatureUnavailableError):
            bridge._request_with_retry("/api/thread/suspend")
        assert len(calls) == 1
