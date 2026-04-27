"""Tests for src/utils/pdb_fetcher.py — CodeView extraction, URL building,
and the cache-first fetch_pdb path.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_build_symbol_server_url():
    from src.utils.pdb_fetcher import build_symbol_server_url

    cv = {
        "guid": "8F9B5A0E5C9D4C3F8B7A6E5D4C3B2A1B",
        "age": 1,
        "pdb_filename": "diagtrack.pdb",
    }
    url = build_symbol_server_url(cv)
    assert url == (
        "https://msdl.microsoft.com/download/symbols/"
        "diagtrack.pdb/8F9B5A0E5C9D4C3F8B7A6E5D4C3B2A1B1/"
        "diagtrack.pdb"
    )


def test_build_symbol_server_url_age_hex_uppercase():
    """Age must be uppercase hex without 0x prefix."""
    from src.utils.pdb_fetcher import build_symbol_server_url

    cv = {
        "guid": "AABBCCDDEEFF00112233445566778899",
        "age": 0xab,
        "pdb_filename": "x.pdb",
    }
    url = build_symbol_server_url(cv)
    assert url.endswith("/AABBCCDDEEFF00112233445566778899AB/x.pdb")


def test_extract_codeview_no_pefile(tmp_path, monkeypatch):
    """When pefile is unavailable the function returns None gracefully."""
    import builtins

    from src.utils import pdb_fetcher as mod

    real_import = builtins.__import__

    def block_pefile(name, *args, **kwargs):
        if name == "pefile":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", block_pefile)
    f = tmp_path / "fake.exe"
    f.write_bytes(b"\x00")
    assert mod.extract_codeview_record(f) is None


def test_extract_codeview_non_pe_returns_none(tmp_path):
    from src.utils.pdb_fetcher import extract_codeview_record

    f = tmp_path / "garbage.bin"
    f.write_bytes(b"\x00" * 256)
    # Not a PE file -- pefile raises, function swallows and returns None
    assert extract_codeview_record(f) is None


def test_fetch_pdb_cache_hit(tmp_path):
    """If the canonical cache path already exists, no download happens."""
    from src.utils import pdb_fetcher as mod

    cv = {
        "guid": "DEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        "age": 1,
        "pdb_filename": "fake.pdb",
    }
    cache_dir = tmp_path / "cache"
    cached = cache_dir / "fake.pdb" / "DEADBEEFDEADBEEFDEADBEEFDEADBEEF1" / "fake.pdb"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"FAKE-PDB-CONTENT")

    binary = tmp_path / "fake.exe"
    binary.write_bytes(b"MZ")

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch("urllib.request.urlopen") as urlopen:
            result = mod.fetch_pdb(binary, cache_dir=cache_dir)
            urlopen.assert_not_called()
    assert result == cached
    assert result.read_bytes() == b"FAKE-PDB-CONTENT"


def test_fetch_pdb_downloads_when_not_cached(tmp_path):
    from src.utils import pdb_fetcher as mod

    cv = {
        "guid": "AAAA1111BBBB2222CCCC3333DDDD4444",
        "age": 2,
        "pdb_filename": "test.pdb",
    }
    cache_dir = tmp_path / "cache"
    binary = tmp_path / "test.exe"
    binary.write_bytes(b"MZ")

    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.read.return_value = b"PDB-DOWNLOADED"
    fake_resp.__enter__ = lambda self: self
    fake_resp.__exit__ = lambda self, *a: False

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch("urllib.request.urlopen", return_value=fake_resp) as urlopen:
            result = mod.fetch_pdb(binary, cache_dir=cache_dir)
            urlopen.assert_called_once()
            req = urlopen.call_args[0][0]
            assert "test.pdb/AAAA1111BBBB2222CCCC3333DDDD44442/test.pdb" in req.full_url
            assert req.headers["User-agent"].startswith("Microsoft-Symbol-Server")

    expected = cache_dir / "test.pdb" / "AAAA1111BBBB2222CCCC3333DDDD44442" / "test.pdb"
    assert result == expected
    assert result.read_bytes() == b"PDB-DOWNLOADED"


def test_fetch_pdb_no_codeview_raises(tmp_path):
    from src.utils import pdb_fetcher as mod

    binary = tmp_path / "stripped.exe"
    binary.write_bytes(b"MZ")
    with patch.object(mod, "extract_codeview_record", return_value=None):
        with pytest.raises(ValueError, match="No CodeView"):
            mod.fetch_pdb(binary, cache_dir=tmp_path / "cache")


class TestParseSymbolPath:
    def test_default_when_unset(self, monkeypatch):
        from src.utils.pdb_fetcher import (
            DEFAULT_SYMBOL_CACHE,
            DEFAULT_SYMBOL_SERVER,
            parse_symbol_path,
        )

        monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
        monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)
        cache, servers = parse_symbol_path()
        assert cache == DEFAULT_SYMBOL_CACHE
        assert servers == [DEFAULT_SYMBOL_SERVER]

    def test_srv_with_cache_and_url(self):
        from src.utils.pdb_fetcher import parse_symbol_path

        cache, servers = parse_symbol_path(
            "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"
        )
        assert cache == Path("C:\\symbols")
        assert servers == ["https://msdl.microsoft.com/download/symbols"]

    def test_chained_entries(self):
        from src.utils.pdb_fetcher import parse_symbol_path

        cache, servers = parse_symbol_path(
            "cache*/tmp/sym;srv*https://internal.example/sym;"
            "srv*https://msdl.microsoft.com/download/symbols"
        )
        assert cache == Path("/tmp/sym")
        assert servers == [
            "https://internal.example/sym",
            "https://msdl.microsoft.com/download/symbols",
        ]

    def test_env_var_fallback(self, monkeypatch):
        from src.utils.pdb_fetcher import parse_symbol_path

        monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
        monkeypatch.setenv(
            "_NT_SYMBOL_PATH",
            "srv*/var/sym*https://example.com/sym",
        )
        cache, servers = parse_symbol_path()
        assert cache == Path("/var/sym")
        assert servers == ["https://example.com/sym"]

    def test_binary_mcp_var_takes_precedence(self, monkeypatch):
        from src.utils.pdb_fetcher import parse_symbol_path

        monkeypatch.setenv("_NT_SYMBOL_PATH", "srv*https://nt-default")
        monkeypatch.setenv(
            "BINARY_MCP_SYMBOL_PATH", "srv*https://binmcp-pref"
        )
        _, servers = parse_symbol_path()
        assert servers == ["https://binmcp-pref"]

    def test_multi_url_within_single_srv(self):
        from src.utils.pdb_fetcher import parse_symbol_path

        cache, servers = parse_symbol_path(
            "srv*/tmp/c*https://primary.example*https://secondary.example"
        )
        assert cache == Path("/tmp/c")
        assert servers == [
            "https://primary.example",
            "https://secondary.example",
        ]


def test_fetch_pdb_falls_back_to_second_server(tmp_path, monkeypatch):
    """First server 404s, second server returns 200 -- PDB cached."""
    import urllib.error

    from src.utils import pdb_fetcher as mod

    monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
    monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)

    cv = {
        "guid": "12345678123456781234567812345678",
        "age": 1,
        "pdb_filename": "fb.pdb",
    }
    binary = tmp_path / "fb.exe"
    binary.write_bytes(b"MZ")

    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.read.return_value = b"FROM-FALLBACK"
    fake_resp.__enter__ = lambda self: self
    fake_resp.__exit__ = lambda self, *a: False

    err = urllib.error.HTTPError(
        url="http://primary", code=404, msg="Not Found",
        hdrs=None, fp=None,
    )

    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if "primary" in req.full_url:
            raise err
        return fake_resp

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = mod.fetch_pdb(
                binary,
                cache_dir=tmp_path / "cache",
                symbol_path="srv*https://primary.example;"
                            "srv*https://secondary.example",
            )

    assert len(calls) == 2
    assert "primary" in calls[0]
    assert "secondary" in calls[1]
    assert result.read_bytes() == b"FROM-FALLBACK"


def test_fetch_pdb_all_servers_fail(tmp_path, monkeypatch):
    import urllib.error

    from src.utils import pdb_fetcher as mod

    monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
    monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)

    cv = {
        "guid": "AAAA" * 8,
        "age": 1,
        "pdb_filename": "x.pdb",
    }
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    err = urllib.error.HTTPError(
        url="http://x", code=404, msg="Not Found", hdrs=None, fp=None,
    )

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError, match="All configured symbol servers failed"):
                mod.fetch_pdb(
                    binary,
                    cache_dir=tmp_path / "cache",
                    symbol_path="srv*https://a.example;srv*https://b.example",
                )


def test_fetch_pdb_http_error_wraps_as_runtime(tmp_path):
    import urllib.error

    from src.utils import pdb_fetcher as mod

    cv = {
        "guid": "11112222333344445555666677778888",
        "age": 1,
        "pdb_filename": "missing.pdb",
    }
    binary = tmp_path / "x.exe"
    binary.write_bytes(b"MZ")
    err = urllib.error.HTTPError(
        url="http://x", code=404, msg="Not Found", hdrs=None, fp=None
    )
    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch("urllib.request.urlopen", side_effect=err):
            with pytest.raises(RuntimeError, match="404"):
                mod.fetch_pdb(
                    binary,
                    cache_dir=tmp_path / "cache",
                    symbol_path="srv*https://msdl.microsoft.com/download/symbols",
                )
