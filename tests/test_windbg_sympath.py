"""Tests for the WinDbg symbol-path management module."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())


class TestComputeNtSymbolPath:
    def test_default_form_is_srv_cache_server(self, monkeypatch):
        monkeypatch.delenv("BINARY_MCP_SYMBOL_OFFLINE", raising=False)
        from src.engines.dynamic.windbg.sympath import compute_nt_symbol_path

        path = compute_nt_symbol_path()
        assert path.startswith("srv*")
        assert path.count("*") == 2  # srv*<cache>*<server>

    def test_offline_drops_upstream(self, monkeypatch):
        monkeypatch.setenv("BINARY_MCP_SYMBOL_OFFLINE", "1")
        from src.engines.dynamic.windbg.sympath import compute_nt_symbol_path

        path = compute_nt_symbol_path()
        assert path.startswith("cache*")
        assert "http" not in path


class TestValidateSympathElement:
    @pytest.fixture(autouse=True)
    def _no_http_optin(self, monkeypatch):
        monkeypatch.delenv("BINARY_MCP_ALLOW_HTTP_SYMBOLS", raising=False)

    def test_empty_rejected(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        assert validate_sympath_element("") is not None
        assert validate_sympath_element("   ") is not None

    def test_unc_rejected(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        assert "UNC" in validate_sympath_element(r"\\server\share\sym")

    def test_http_rejected_without_optin(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        reason = validate_sympath_element("http://untrusted.example/sym")
        assert reason is not None and "http://" in reason

    def test_http_allowed_with_optin(self, monkeypatch):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        monkeypatch.setenv("BINARY_MCP_ALLOW_HTTP_SYMBOLS", "1")
        assert validate_sympath_element("http://internal.example/sym") is None

    def test_https_srv_form_allowed(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        assert validate_sympath_element(
            "srv*https://msdl.microsoft.com/download/symbols"
        ) is None

    def test_srv_cache_must_live_under_root(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        reason = validate_sympath_element(
            "srv*/etc/passwd*https://msdl.microsoft.com/download/symbols"
        )
        assert reason is not None
        assert "cache must be under" in reason

    def test_srv_cache_under_root_accepted(self, tmp_path, monkeypatch):
        # Make tmp_path the cache root and pass a sub-directory.
        monkeypatch.setenv("BINARY_MCP_SYMBOL_CACHE", str(tmp_path))
        # Force re-resolve of the default by clearing module-level constants.
        import importlib

        from src.utils import pdb_fetcher
        importlib.reload(pdb_fetcher)
        from src.engines.dynamic.windbg import sympath
        importlib.reload(sympath)

        sub = tmp_path / "sub"
        sub.mkdir()
        result = sympath.validate_sympath_element(
            f"srv*{sub}*https://msdl.microsoft.com/download/symbols"
        )
        assert result is None

    def test_shell_metacharacters_rejected(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        assert validate_sympath_element("/sym;rm -rf /") is not None
        assert validate_sympath_element("/sym|cat /etc/passwd") is not None

    def test_malformed_srv_rejected(self):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        assert validate_sympath_element("srv*ftp://nope") is not None

    def test_local_path_allowed(self, tmp_path):
        from src.engines.dynamic.windbg.sympath import validate_sympath_element

        # Bare local path is allowed - private symbol stores are common.
        assert validate_sympath_element(str(tmp_path)) is None


class TestSetEngineSympath:
    def test_returns_false_without_dbg(self):
        from src.engines.dynamic.windbg.sympath import set_engine_sympath

        assert set_engine_sympath(None, "srv*c*https://x") is False

    def test_returns_false_without_symbols_handle(self):
        from src.engines.dynamic.windbg.sympath import set_engine_sympath

        dbg = MagicMock(spec=[])  # no _symbols
        assert set_engine_sympath(dbg, "srv*c*https://x") is False

    def test_calls_set_symbol_path(self):
        from src.engines.dynamic.windbg.sympath import set_engine_sympath

        dbg = MagicMock()
        path = "srv*/tmp/cache*https://msdl.microsoft.com/download/symbols"
        assert set_engine_sympath(dbg, path) is True
        dbg._symbols.SetSymbolPath.assert_called_once_with(path)

    def test_swallows_set_symbol_path_errors(self):
        from src.engines.dynamic.windbg.sympath import set_engine_sympath

        dbg = MagicMock()
        dbg._symbols.SetSymbolPath.side_effect = RuntimeError("boom")
        assert set_engine_sympath(dbg, "srv*c*https://x") is False


class TestSubprocessEnvWithSympath:
    def test_injects_when_unset(self):
        from src.engines.dynamic.windbg.sympath import subprocess_env_with_sympath

        env = subprocess_env_with_sympath({})
        assert "_NT_SYMBOL_PATH" in env
        assert env["_NT_SYMBOL_PATH"]

    def test_preserves_existing(self):
        from src.engines.dynamic.windbg.sympath import subprocess_env_with_sympath

        env = subprocess_env_with_sympath({"_NT_SYMBOL_PATH": "preset"})
        assert env["_NT_SYMBOL_PATH"] == "preset"


class TestBridgeIntegration:
    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_set_sympath_rejects_bad_elements(self, _system):
        from src.engines.dynamic.windbg.bridge import (
            WinDbgBridge,
            WinDbgBridgeError,
        )

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._state = bridge._state.__class__.PAUSED  # any non-NOT_LOADED

        with pytest.raises(WinDbgBridgeError, match="rejected entries"):
            bridge.set_sympath([r"\\evil-host\sym"])

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_set_sympath_calls_engine_setter(self, _system):
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._state = bridge._state.__class__.PAUSED

        result = bridge.set_sympath(
            ["srv*https://msdl.microsoft.com/download/symbols"]
        )
        assert "msdl.microsoft.com" in result
        bridge._dbg._symbols.SetSymbolPath.assert_called_once()

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_get_sympath_returns_engine_value(self, _system):
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._dbg._symbols.GetSymbolPath.return_value = "srv*c*https://x"
        bridge._state = bridge._state.__class__.PAUSED

        assert bridge.get_sympath() == "srv*c*https://x"
