"""Tests for Function ID (FID) result-reader tool."""

from __future__ import annotations

from unittest.mock import MagicMock


def _register(cache_data):
    from src.tools.fid_tools import register_fid_tools

    app = MagicMock()
    app.tool.return_value = lambda f: f
    cache = MagicMock()
    cache.get_cached.return_value = cache_data
    runner = MagicMock()
    session_manager = MagicMock()

    (fid_match,) = register_fid_tools(app, session_manager, cache, runner)

    import src.tools.fid_tools as ft
    ft.sanitize_binary_path = lambda p, **kw: type(
        "P", (), {"__str__": lambda self: p}
    )()

    return fid_match


def _func(name, address, fid_match=None, include_field=True):
    d = {
        "name": name,
        "address": address,
        "is_thunk": False,
        "is_external": False,
    }
    if include_field:
        d["fid_match"] = fid_match
    return d


class TestFidMatch:
    def test_no_cache(self):
        fid_match = _register(None)
        result = fid_match("/bin/test.exe")
        assert "No cached analysis" in result
        assert "enable_fid=True" in result

    def test_cache_without_fid_field(self):
        fid_match = _register({
            "functions": [_func("a", "0x1000", include_field=False)],
        })
        result = fid_match("/bin/test.exe")
        assert "no fid_match data" in result.lower()

    def test_empty_matches(self):
        fid_match = _register({
            "functions": [_func("a", "0x1000", fid_match=None)],
        })
        result = fid_match("/bin/test.exe")
        # Field exists but nothing matched — we get the summary and guidance
        assert "0 matched" in result

    def test_matched_rendered(self):
        fid_match = _register({
            "functions": [
                _func(
                    "FUN_00401000",
                    "0x1000",
                    fid_match={
                        "name": "memcpy",
                        "library": "msvcrt_md_v142",
                        "confidence": 78.5,
                    },
                ),
                _func("unmatched", "0x2000", fid_match=None),
            ],
        })
        result = fid_match("/bin/test.exe", filter_unmatched=True)
        assert "memcpy" in result
        assert "msvcrt_md_v142" in result
        # Header line mentions "unmatched" in the summary — check the row body
        assert "`unmatched`" not in result
        assert "1 matched" in result

    def test_filter_unmatched_false(self):
        fid_match = _register({
            "functions": [
                _func("a", "0x1000", fid_match=None),
                _func(
                    "b",
                    "0x2000",
                    fid_match={
                        "name": "strlen",
                        "library": "libc",
                        "confidence": 95.0,
                    },
                ),
            ],
        })
        result = fid_match("/bin/test.exe", filter_unmatched=False)
        assert "no match" in result
        assert "strlen" in result

    def test_limit_applied(self):
        fid_match = _register({
            "functions": [
                _func(
                    f"f{i}",
                    f"0x{1000 + i:x}",
                    fid_match={
                        "name": f"sym_{i}",
                        "library": "libx",
                        "confidence": 90.0,
                    },
                )
                for i in range(5)
            ],
        })
        result = fid_match("/bin/test.exe", limit=2)
        assert "Showing 2 of 5" in result
