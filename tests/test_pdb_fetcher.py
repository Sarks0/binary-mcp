"""Tests for src/utils/pdb_fetcher.py - CodeView extraction, URL building,
and the cache-first fetch_pdb path.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def _streaming_response(payload: bytes, status: int = 200):
    """Build a context-manager mock that streams ``payload`` like urlopen()."""
    buf = io.BytesIO(payload)
    resp = MagicMock()
    resp.getcode.return_value = status
    resp.read = buf.read
    resp.headers = {"Content-Length": str(len(payload))}
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *a: False
    return resp


def _opener_returning(*responses):
    """Build a mock opener whose .open() returns each response in turn.

    ``fetch_pdb`` constructs an opener via ``urllib.request.build_opener``
    and then calls ``opener.open(req, timeout=...)``. Tests patch
    ``build_opener`` to return this mock so they can simulate the network
    without touching the real stack.
    """
    opener = MagicMock()
    if len(responses) == 1:
        opener.open.return_value = responses[0]
    else:
        opener.open.side_effect = responses
    return opener


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


def test_decode_codeview_uses_signature_string():
    """pefile exposes the GUID as Signature_String -- verify we use it."""
    from src.utils.pdb_fetcher import _decode_codeview

    inner = MagicMock()
    inner.Signature_String = "FF0B0EA442E5A3444AE9E116143233F5"
    inner.Age = 1
    inner.PdbFileName = b"sample.pdb\x00"

    entry = MagicMock()
    entry.struct.Type = 2
    entry.entry = inner

    result = _decode_codeview(entry, MagicMock())
    assert result == {
        "guid": "FF0B0EA442E5A3444AE9E116143233F5",
        "age": 1,
        "pdb_filename": "sample.pdb",
    }


def test_decode_codeview_skips_non_codeview_type():
    from src.utils.pdb_fetcher import _decode_codeview

    entry = MagicMock()
    entry.struct.Type = 12  # VC Feature, not CodeView
    assert _decode_codeview(entry, MagicMock()) is None


def test_decode_codeview_falls_back_to_file_bytes():
    """When pefile didn't parse the entry, read raw bytes from file."""
    from src.utils.pdb_fetcher import _decode_codeview

    rsds = (
        b"RSDS"
        + bytes.fromhex("A442E50BFFA3444A4AE9E116143233F5"[:32])
        + (1).to_bytes(4, "little")
        + b"sample.pdb\x00"
    )

    pe = MagicMock()
    pe.__data__ = b"\x00" * 0x100 + rsds + b"\x00" * 0x10

    entry = MagicMock()
    entry.struct.Type = 2
    entry.struct.PointerToRawData = 0x100
    entry.struct.SizeOfData = len(rsds)
    entry.entry = None  # pefile didn't parse it

    result = _decode_codeview(entry, pe)
    assert result is not None
    assert result["age"] == 1
    assert result["pdb_filename"] == "sample.pdb"
    assert len(result["guid"]) == 32


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
        with patch.object(mod.urllib.request, "build_opener") as bo:
            result = mod.fetch_pdb(binary, cache_dir=cache_dir)
            bo.assert_not_called()
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

    fake_resp = _streaming_response(b"PDB-DOWNLOADED")
    opener = _opener_returning(fake_resp)

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(mod.urllib.request, "build_opener", return_value=opener):
            result = mod.fetch_pdb(binary, cache_dir=cache_dir)
            opener.open.assert_called_once()
            req = opener.open.call_args[0][0]
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

    err = urllib.error.HTTPError(
        url="http://primary", code=404, msg="Not Found",
        hdrs=None, fp=None,
    )

    calls = []

    def fake_open(req, timeout=None):
        calls.append(req.full_url)
        if "primary" in req.full_url:
            raise err
        return _streaming_response(b"FROM-FALLBACK")

    opener = MagicMock()
    opener.open.side_effect = fake_open

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(mod.urllib.request, "build_opener", return_value=opener):
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

    opener = MagicMock()
    opener.open.side_effect = err

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(mod.urllib.request, "build_opener", return_value=opener):
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
    opener = MagicMock()
    opener.open.side_effect = err
    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(mod.urllib.request, "build_opener", return_value=opener):
            with pytest.raises(RuntimeError, match="404"):
                mod.fetch_pdb(
                    binary,
                    cache_dir=tmp_path / "cache",
                    symbol_path="srv*https://msdl.microsoft.com/download/symbols",
                )


# --- Sanitisation / hardening tests --------------------------------------

class TestSanitisePdbName:
    def test_rejects_path_traversal(self):
        from src.utils.pdb_fetcher import _sanitize_pdb_name

        assert _sanitize_pdb_name("..\\evil.pdb") is None
        assert _sanitize_pdb_name("/etc/passwd") is None
        assert _sanitize_pdb_name("foo/bar.pdb") is None
        assert _sanitize_pdb_name("..") is None
        assert _sanitize_pdb_name(".") is None
        assert _sanitize_pdb_name("") is None
        assert _sanitize_pdb_name(None) is None

    def test_strips_nul_bytes(self):
        from src.utils.pdb_fetcher import _sanitize_pdb_name

        assert _sanitize_pdb_name("ok.pdb\x00") == "ok.pdb"
        assert _sanitize_pdb_name(b"ok.pdb\x00\x00\x00") == "ok.pdb"

    def test_requires_pdb_extension(self):
        from src.utils.pdb_fetcher import _sanitize_pdb_name

        assert _sanitize_pdb_name("file.txt") is None
        assert _sanitize_pdb_name("noext") is None

    def test_allows_legit_names(self):
        from src.utils.pdb_fetcher import _sanitize_pdb_name

        assert _sanitize_pdb_name("ntdll.pdb") == "ntdll.pdb"
        assert _sanitize_pdb_name("Foo-bar_v2.pdb") == "Foo-bar_v2.pdb"

    def test_caps_length(self):
        from src.utils.pdb_fetcher import _sanitize_pdb_name

        assert _sanitize_pdb_name("a" * 300 + ".pdb") is None


class TestSanitiseGuid:
    def test_rejects_non_hex(self):
        from src.utils.pdb_fetcher import _sanitize_guid

        assert _sanitize_guid("XYZ") is None
        assert _sanitize_guid("AABB") is None  # too short
        assert _sanitize_guid("Z" * 32) is None
        assert _sanitize_guid(None) is None

    def test_accepts_canonical_and_dashed(self):
        from src.utils.pdb_fetcher import _sanitize_guid

        canonical = "AABBCCDDEEFF00112233445566778899"
        assert _sanitize_guid(canonical) == canonical
        assert _sanitize_guid("aabbccdd-eeff-0011-2233-445566778899") == canonical


def test_decode_codeview_rejects_oversized_size_of_data():
    """SizeOfData > 64 KB cap returns None without reading the slice."""
    from src.utils.pdb_fetcher import _decode_codeview

    pe = MagicMock()
    pe.__data__ = b""

    entry = MagicMock()
    entry.struct.Type = 2
    entry.struct.PointerToRawData = 0x100
    entry.struct.SizeOfData = 1 << 30
    entry.entry = None

    assert _decode_codeview(entry, pe) is None


def test_decode_codeview_rejects_traversal_pdb_name():
    """RSDS bytes with a '..' filename are rejected via _sanitize_pdb_name."""
    from src.utils.pdb_fetcher import _decode_codeview

    rsds = (
        b"RSDS"
        + bytes.fromhex("A442E50BFFA3444A4AE9E116143233F5"[:32])
        + (1).to_bytes(4, "little")
        + b"..\\evil.pdb\x00"
    )
    pe = MagicMock()
    pe.__data__ = b"\x00" * 0x100 + rsds

    entry = MagicMock()
    entry.struct.Type = 2
    entry.struct.PointerToRawData = 0x100
    entry.struct.SizeOfData = len(rsds)
    entry.entry = None

    assert _decode_codeview(entry, pe) is None


class TestParseSymbolPathHttpHardening:
    def test_http_dropped_without_optin(self, monkeypatch):
        from src.utils.pdb_fetcher import (
            DEFAULT_SYMBOL_SERVER,
            parse_symbol_path,
        )

        monkeypatch.delenv("BINARY_MCP_ALLOW_HTTP_SYMBOLS", raising=False)
        _, servers = parse_symbol_path("srv*/tmp/c*http://untrusted.example/p")
        assert servers == [DEFAULT_SYMBOL_SERVER]  # http dropped, default added

    def test_http_kept_with_optin(self, monkeypatch):
        from src.utils.pdb_fetcher import parse_symbol_path

        monkeypatch.setenv("BINARY_MCP_ALLOW_HTTP_SYMBOLS", "1")
        _, servers = parse_symbol_path("srv*http://internal.example/p")
        assert servers == ["http://internal.example/p"]

    def test_unrecognised_entry_warns(self, caplog):
        import logging

        from src.utils.pdb_fetcher import parse_symbol_path

        caplog.set_level(logging.WARNING, logger="src.utils.pdb_fetcher")
        parse_symbol_path("garbage-token")
        assert any("Ignoring unrecognized" in r.message for r in caplog.records)


def test_build_symbol_server_url_encodes_filename():
    from src.utils.pdb_fetcher import build_symbol_server_url

    cv = {
        "guid": "AABBCCDDEEFF00112233445566778899",
        "age": 1,
        "pdb_filename": "weird name.pdb",
    }
    url = build_symbol_server_url(cv)
    assert "weird%20name.pdb" in url
    assert " " not in url


def test_fetch_pdb_writes_full_file_no_part_left(tmp_path):
    """Streaming download lands a complete file and removes .part on success."""
    from src.utils import pdb_fetcher as mod

    cv = {
        "guid": "11112222333344445555666677778888",
        "age": 3,
        "pdb_filename": "stream.pdb",
    }
    binary = tmp_path / "stream.exe"
    binary.write_bytes(b"MZ")
    payload = b"X" * (256 * 1024 + 17)  # spans many chunks

    fake_resp = _streaming_response(payload)
    opener = _opener_returning(fake_resp)
    cache_dir = tmp_path / "cache"

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(mod.urllib.request, "build_opener", return_value=opener):
            result = mod.fetch_pdb(binary, cache_dir=cache_dir)

    assert result.read_bytes() == payload
    leftovers = list(cache_dir.rglob("*.part"))
    assert leftovers == []


def test_fetch_pdb_raises_on_unwritable_cache(tmp_path, monkeypatch):
    """When mkdir succeeds but writes fail, surface a clear RuntimeError."""
    from src.utils import pdb_fetcher as mod

    cv = {
        "guid": "AAAA" * 8,
        "age": 1,
        "pdb_filename": "ro.pdb",
    }
    binary = tmp_path / "ro.exe"
    binary.write_bytes(b"MZ")

    def boom(self, data):
        raise OSError("read-only fs")

    with patch.object(mod, "extract_codeview_record", return_value=cv):
        with patch.object(Path, "write_bytes", boom):
            with pytest.raises(RuntimeError, match="not writable"):
                mod.fetch_pdb(binary, cache_dir=tmp_path / "cache")


# --- SSRF hardening tests ------------------------------------------------

class TestIsSafeSymbolServerHost:
    """Direct tests of the host-validation predicate.

    The helper is exposed at module level so tests don't have to round-trip
    through urlopen to exercise the policy.
    """

    def test_rejects_loopback_v4(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        assert _is_safe_symbol_server_host("127.0.0.1") is False
        assert _is_safe_symbol_server_host("127.5.6.7") is False

    def test_rejects_loopback_v6(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        assert _is_safe_symbol_server_host("::1") is False
        # Hostname form (with brackets) should be tolerated by the caller,
        # but the bare helper also accepts the bracketed form.
        assert _is_safe_symbol_server_host("[::1]") is False

    def test_rejects_rfc1918(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        assert _is_safe_symbol_server_host("10.0.0.1") is False
        assert _is_safe_symbol_server_host("172.16.5.5") is False
        assert _is_safe_symbol_server_host("192.168.1.1") is False

    def test_rejects_cloud_metadata(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        # 169.254.169.254 is the AWS/Azure/GCP metadata service. It also
        # falls inside the link-local /16 so the IPv6 fe80::/10 logic in
        # the helper covers analogous cases.
        assert _is_safe_symbol_server_host("169.254.169.254") is False

    def test_rejects_dns_name_resolving_to_private(self, monkeypatch):
        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)

        def fake_getaddrinfo(host, *_a, **_kw):
            # (family, type, proto, canonname, sockaddr)
            return [(0, 0, 0, "", ("10.0.0.5", 0))]

        monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)
        assert mod._is_safe_symbol_server_host("evil.example.com") is False

    def test_rejects_dns_name_with_any_private_answer(self, monkeypatch):
        """Even one private answer in a multi-record set must trip the gate."""
        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)

        def fake_getaddrinfo(host, *_a, **_kw):
            return [
                (0, 0, 0, "", ("8.8.8.8", 0)),       # public
                (0, 0, 0, "", ("127.0.0.1", 0)),     # loopback
            ]

        monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)
        assert mod._is_safe_symbol_server_host("split.example.com") is False

    def test_allows_public_ip(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        assert _is_safe_symbol_server_host("8.8.8.8") is True

    def test_allows_public_dns(self, monkeypatch):
        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)

        def fake_getaddrinfo(host, *_a, **_kw):
            return [(0, 0, 0, "", ("23.45.67.89", 0))]

        monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)
        assert mod._is_safe_symbol_server_host("msdl.microsoft.com") is True

    def test_optin_env_var_allows_private(self, monkeypatch):
        from src.utils.pdb_fetcher import _is_safe_symbol_server_host

        monkeypatch.setenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", "1")
        assert _is_safe_symbol_server_host("127.0.0.1") is True
        assert _is_safe_symbol_server_host("10.0.0.5") is True
        assert _is_safe_symbol_server_host("169.254.169.254") is True


class TestParseSymbolPathSsrf:
    def test_private_server_dropped(self, monkeypatch, caplog):
        import logging

        from src.utils.pdb_fetcher import DEFAULT_SYMBOL_SERVER, parse_symbol_path

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        caplog.set_level(logging.WARNING, logger="src.utils.pdb_fetcher")
        _, servers = parse_symbol_path("srv*https://127.0.0.1/sym")
        # Falls back to the default since the configured server was dropped.
        assert servers == [DEFAULT_SYMBOL_SERVER]
        joined = " ".join(r.message for r in caplog.records)
        assert "BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS" in joined

    def test_private_server_kept_with_optin(self, monkeypatch):
        from src.utils.pdb_fetcher import parse_symbol_path

        monkeypatch.setenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", "1")
        _, servers = parse_symbol_path("srv*https://10.0.0.1/sym")
        assert servers == ["https://10.0.0.1/sym"]

    def test_cloud_metadata_dropped(self, monkeypatch):
        from src.utils.pdb_fetcher import DEFAULT_SYMBOL_SERVER, parse_symbol_path

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)
        _, servers = parse_symbol_path(
            "srv*http://169.254.169.254/latest/meta-data/"
        )
        # Both the http-without-optin and the SSRF gate would reject this,
        # but the result must not contain the metadata URL.
        assert "169.254.169.254" not in " ".join(servers)
        assert servers == [DEFAULT_SYMBOL_SERVER]


class TestSafeRedirectHandler:
    def test_redirect_to_private_ip_is_rejected(self, monkeypatch, tmp_path):
        """A 302 pointing at 127.0.0.1 must fail the fetch loop."""
        import urllib.error
        import urllib.request

        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)

        handler = mod._SafeRedirectHandler()
        req = urllib.request.Request("https://msdl.microsoft.com/x")
        fp = io.BytesIO(b"")
        # Mimic urllib's call to redirect_request when handling a 302.
        with pytest.raises(urllib.error.HTTPError):
            handler.redirect_request(
                req, fp, 302, "Found", {}, "http://127.0.0.1/leak"
            )

    def test_redirect_to_public_ip_is_allowed(self, monkeypatch):
        """Redirect to a public host returns a new Request object."""
        import urllib.request

        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS", raising=False)

        # Force the DNS path to resolve to a public IP so we don't rely on
        # real DNS during the test.
        def fake_getaddrinfo(host, *_a, **_kw):
            return [(0, 0, 0, "", ("23.45.67.89", 0))]

        monkeypatch.setattr(mod.socket, "getaddrinfo", fake_getaddrinfo)

        handler = mod._SafeRedirectHandler()
        req = urllib.request.Request("https://msdl.microsoft.com/x")
        fp = io.BytesIO(b"")
        new_req = handler.redirect_request(
            req, fp, 302, "Found",
            {"location": "https://cdn.example.com/y"},
            "https://cdn.example.com/y",
        )
        assert new_req is not None
        assert new_req.full_url == "https://cdn.example.com/y"


class TestDownloadSizeCap:
    def test_rejects_oversized_content_length(self, tmp_path, monkeypatch):
        """Server advertising > 256 MB Content-Length is dropped pre-stream."""
        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
        monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)

        cv = {
            "guid": "AAAA" * 8,
            "age": 1,
            "pdb_filename": "huge.pdb",
        }
        binary = tmp_path / "huge.exe"
        binary.write_bytes(b"MZ")

        resp = MagicMock()
        resp.getcode.return_value = 200
        resp.headers = {"Content-Length": str(mod.MAX_PDB_DOWNLOAD_BYTES + 1)}
        resp.read.return_value = b""
        resp.__enter__ = lambda self: self
        resp.__exit__ = lambda self, *a: False

        fake_opener = MagicMock()
        fake_opener.open.return_value = resp

        with patch.object(mod, "extract_codeview_record", return_value=cv):
            with patch.object(
                mod.urllib.request, "build_opener", return_value=fake_opener
            ):
                with pytest.raises(RuntimeError, match="exceeds cap|exceeded size cap"):
                    mod.fetch_pdb(binary, cache_dir=tmp_path / "cache")

    def test_rejects_streamed_oversize(self, tmp_path, monkeypatch):
        """No Content-Length, but the response keeps streaming past the cap."""
        from src.utils import pdb_fetcher as mod

        monkeypatch.delenv("BINARY_MCP_SYMBOL_PATH", raising=False)
        monkeypatch.delenv("_NT_SYMBOL_PATH", raising=False)

        # Patch the cap down so the test doesn't actually have to stream
        # 256 MB through memory.
        monkeypatch.setattr(mod, "MAX_PDB_DOWNLOAD_BYTES", 1024)

        cv = {
            "guid": "BBBB" * 8,
            "age": 1,
            "pdb_filename": "stream.pdb",
        }
        binary = tmp_path / "stream.exe"
        binary.write_bytes(b"MZ")

        chunks = [b"X" * 512, b"X" * 512, b"X" * 512, b""]
        idx = {"i": 0}

        def fake_read(n=-1):
            i = idx["i"]
            idx["i"] += 1
            if i >= len(chunks):
                return b""
            return chunks[i]

        resp = MagicMock()
        resp.getcode.return_value = 200
        resp.headers = {}
        resp.read = fake_read
        resp.__enter__ = lambda self: self
        resp.__exit__ = lambda self, *a: False

        fake_opener = MagicMock()
        fake_opener.open.return_value = resp

        with patch.object(mod, "extract_codeview_record", return_value=cv):
            with patch.object(
                mod.urllib.request, "build_opener", return_value=fake_opener
            ):
                with pytest.raises(RuntimeError, match="exceeded size cap"):
                    mod.fetch_pdb(binary, cache_dir=tmp_path / "cache")
