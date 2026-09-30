"""
Automatic PDB fetch on first analysis, and the fetcher's failure taxonomy.

The lab kept grinding through FUN_* names on System32 DLLs whose PDBs are
published, and once read a redirect that served nothing as "not published".
"""

import json
import sys
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.utils import pdb_fetcher as mod

CV = {"guid": "AAAA1111BBBB2222CCCC3333DDDD4444", "age": 1, "pdb_filename": "t.pdb"}


def _pe(tmp_path, name="t.dll"):
    binary = tmp_path / name
    binary.write_bytes(b"MZ" + b"\x00" * 128)
    return binary


def _opener_raising(*errors):
    opener = MagicMock()
    opener.open.side_effect = list(errors)
    return opener


def _http(code):
    return urllib.error.HTTPError(url="http://x", code=code, msg="x", hdrs=None, fp=None)


# fetch_pdb failure taxonomy


class TestFetchFailures:
    SERVERS = "srv*https://a.example;srv*https://b.example"

    def _fetch(self, tmp_path, opener):
        with patch.object(mod, "extract_codeview_record", return_value=CV):
            with patch.object(mod.urllib.request, "build_opener", return_value=opener):
                return mod.fetch_pdb(
                    _pe(tmp_path), cache_dir=tmp_path / "cache", symbol_path=self.SERVERS
                )

    def test_every_server_404_is_not_published(self, tmp_path):
        with pytest.raises(mod.PdbNotPublishedError):
            self._fetch(tmp_path, _opener_raising(_http(404), _http(404)))

    def test_a_network_error_is_not_not_published(self, tmp_path):
        opener = _opener_raising(_http(404), urllib.error.URLError("timed out"))
        with pytest.raises(RuntimeError) as excinfo:
            self._fetch(tmp_path, opener)
        assert not isinstance(excinfo.value, mod.PdbNotPublishedError)

    def test_a_server_error_is_not_not_published(self, tmp_path):
        with pytest.raises(RuntimeError) as excinfo:
            self._fetch(tmp_path, _opener_raising(_http(404), _http(503)))
        assert not isinstance(excinfo.value, mod.PdbNotPublishedError)

    def test_empty_body_is_a_failure_and_caches_nothing(self, tmp_path):
        resp = MagicMock()
        resp.__enter__ = MagicMock(return_value=resp)
        resp.__exit__ = MagicMock(return_value=False)
        resp.getcode.return_value = 200
        resp.headers = {}
        resp.read.return_value = b""
        resp.geturl.return_value = "https://blob.example/redirected"
        opener = MagicMock()
        opener.open.return_value = resp

        with pytest.raises(RuntimeError, match="empty response body") as excinfo:
            self._fetch(tmp_path, opener)
        assert not isinstance(excinfo.value, mod.PdbNotPublishedError)
        assert not [p for p in (tmp_path / "cache").rglob("*") if p.is_file()]


# auto_fetch_pdb policy


class TestAutoFetch:
    def test_non_pe_says_nothing(self, tmp_path):
        elf = tmp_path / "x.so"
        elf.write_bytes(b"\x7fELF" + b"\x00" * 64)
        assert mod.auto_fetch_pdb(elf, policy="always") == (None, None)

    def test_never(self, tmp_path):
        path, note = mod.auto_fetch_pdb(_pe(tmp_path), policy="never")
        assert path is None and note["status"] == "skipped"

    def test_no_codeview(self, tmp_path):
        with patch.object(mod, "extract_codeview_record", return_value=None):
            path, note = mod.auto_fetch_pdb(_pe(tmp_path), policy="always")
        assert path is None and note["status"] == "no_codeview"

    def test_microsoft_policy_skips_third_party(self, tmp_path):
        with patch.object(mod, "extract_codeview_record", return_value=CV), \
                patch.object(mod, "version_info_company", return_value="Evil Corp"), \
                patch.object(mod, "fetch_pdb") as fetch:
            path, note = mod.auto_fetch_pdb(_pe(tmp_path), policy="microsoft")
        fetch.assert_not_called()
        assert path is None and note["status"] == "skipped"
        assert "Evil Corp" in note["detail"]

    def test_microsoft_policy_fetches_microsoft(self, tmp_path):
        with patch.object(mod, "extract_codeview_record", return_value=CV), \
                patch.object(mod, "version_info_company", return_value="Microsoft Corporation"), \
                patch.object(mod, "fetch_pdb", return_value=tmp_path / "t.pdb"):
            path, note = mod.auto_fetch_pdb(_pe(tmp_path), policy="microsoft")
        assert path == str(tmp_path / "t.pdb")
        assert note["status"] == "fetched"

    @pytest.mark.parametrize(
        ("error", "status"),
        [
            (mod.PdbNotPublishedError("404s"), "not_published"),
            (RuntimeError("network error"), "fetch_failed"),
            (ValueError("bad path"), "fetch_failed"),
        ],
    )
    def test_failures_are_classified_and_never_raise(self, tmp_path, error, status):
        with patch.object(mod, "extract_codeview_record", return_value=CV), \
                patch.object(mod, "fetch_pdb", side_effect=error):
            path, note = mod.auto_fetch_pdb(_pe(tmp_path), policy="always")
        assert path is None and note["status"] == status

    def test_bad_policy_value_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv(mod.AUTO_PDB_ENV, "sometimes")
        assert mod.auto_pdb_policy() == mod.AUTO_PDB_DEFAULT

    def test_suite_default_is_never(self):
        assert mod.auto_pdb_policy() == "never"


# get_analysis_context wiring


@pytest.fixture
def server(tmp_path, tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))
    sys.modules.pop("src.server", None)
    import src.server as server_mod
    from src.engines.static.ghidra.project_cache import ProjectCache

    cache_obj = ProjectCache(cache_dir=str(tmp_path / "cache"))
    monkeypatch.setattr(server_mod, "cache", cache_obj)
    monkeypatch.setattr(server_mod, "get_allowed_dirs", lambda: [tmp_path])
    captured = {}

    def fake_analyze(**kwargs):
        captured.update(kwargs)
        Path(kwargs["output_path"]).write_text(json.dumps({
            "metadata": {"name": "t.dll", "executable_format": "PE"},
            "functions": [{"address": "0x401000", "name": "Parse"}],
            "imports": [], "strings": [], "memory_map": [],
            "analysis_stats": {},
        }))
        return {"elapsed_time": 1.0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(server_mod.runner, "analyze", fake_analyze)
    yield server_mod, cache_obj, captured
    sys.modules.pop("src.server", None)


FETCHED = ("/symbols/t.pdb", {"source": "auto", "status": "fetched", "pdb_path": "/symbols/t.pdb"})


class TestAnalysisWiring:
    def test_first_import_applies_a_fetched_pdb(self, server, tmp_path, monkeypatch):
        server_mod, cache_obj, captured = server
        binary = _pe(tmp_path)
        auto = MagicMock(return_value=FETCHED)
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", auto)

        context = server_mod.get_analysis_context(str(binary))

        auto.assert_called_once()
        assert captured["pdb_path"] == "/symbols/t.pdb"
        assert context["metadata"]["pdb"]["status"] == "fetched"
        assert cache_obj.get_cached(str(binary))["metadata"]["pdb"]["status"] == "fetched"
        state = cache_obj.read_project_state(cache_obj.project_name_for(str(binary)))
        assert state["pdb_applied"] is True
        summary = server_mod._format_analysis_summary(context, None)
        assert "PDB fetched from the symbol server and applied" in summary

    def test_a_failed_fetch_still_analyzes_and_says_so(self, server, tmp_path, monkeypatch):
        server_mod, _, captured = server
        note = {"source": "auto", "status": "fetch_failed",
                "detail": "All configured symbol servers failed:\n  https://msdl -> network error: timed out"}
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", MagicMock(return_value=(None, note)))

        context = server_mod.get_analysis_context(str(_pe(tmp_path)))

        assert captured["pdb_path"] is None
        summary = server_mod._format_analysis_summary(context, None)
        assert "fetch FAILED" in summary and "timed out" in summary
        assert "not evidence the PDB is unpublished" in summary

    def test_shallow_import_does_not_fetch(self, server, tmp_path, monkeypatch):
        server_mod, _, _ = server
        auto = MagicMock(return_value=FETCHED)
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", auto)
        server_mod.get_analysis_context(str(_pe(tmp_path)), analysis_depth="shallow")
        auto.assert_not_called()

    def test_explicit_pdb_is_recorded_and_not_refetched(self, server, tmp_path, monkeypatch):
        server_mod, _, captured = server
        auto = MagicMock(return_value=FETCHED)
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", auto)
        context = server_mod.get_analysis_context(str(_pe(tmp_path)), pdb_path="/mine/t.pdb")
        auto.assert_not_called()
        assert captured["pdb_path"] == "/mine/t.pdb"
        assert context["metadata"]["pdb"] == {
            "source": "explicit", "status": "applied", "pdb_path": "/mine/t.pdb",
        }

    def test_delta_run_does_not_fetch_and_keeps_the_note(self, server, tmp_path, monkeypatch):
        server_mod, cache_obj, _ = server
        binary = _pe(tmp_path)
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", MagicMock(return_value=FETCHED))
        server_mod.get_analysis_context(str(binary))

        auto = MagicMock(return_value=FETCHED)
        monkeypatch.setattr(server_mod, "auto_fetch_pdb", auto)
        context = server_mod.get_analysis_context(str(binary), incremental=True)
        auto.assert_not_called()
        assert context["metadata"]["pdb"]["status"] == "fetched"


# Vendor gate: the public Microsoft symbol server only has Microsoft's PDBs


@pytest.fixture
def clean_symbol_env(monkeypatch):
    """No inherited symbol-path config, so the default server list applies."""
    for var in ("BINARY_MCP_SYMBOL_PATH", "_NT_SYMBOL_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(
        mod, "DEFAULT_SYMBOL_SERVER", "https://msdl.microsoft.com/download/symbols"
    )


class TestSymbolServerScope:
    def test_the_default_server_is_microsoft_only(self, clean_symbol_env):
        assert mod.symbol_servers_are_microsoft_only() is True

    def test_a_third_party_server_is_not(self, clean_symbol_env):
        assert mod.symbol_servers_are_microsoft_only(
            "srv*C:\\sym*https://symbols.mozilla.org/"
        ) is False

    def test_one_non_microsoft_server_in_the_chain_is_enough(self, clean_symbol_env):
        assert mod.symbol_servers_are_microsoft_only(
            "srv*C:\\sym*https://msdl.microsoft.com/download/symbols;"
            "srv*C:\\sym*https://symbols.vendor.example/"
        ) is False


class TestPrognosis:
    def test_a_microsoft_binary_is_worth_fetching(self, tmp_path, clean_symbol_env):
        with patch.object(mod, "version_info_company", return_value="Microsoft Corporation"):
            p = mod.symbol_server_prognosis(_pe(tmp_path))
        assert p["is_microsoft"] and p["likely"]

    def test_a_third_party_binary_on_the_microsoft_server_is_not(self, tmp_path, clean_symbol_env):
        with patch.object(mod, "version_info_company", return_value="Valve Corporation"):
            p = mod.symbol_server_prognosis(_pe(tmp_path, "steam.exe"))
        assert not p["is_microsoft"] and not p["likely"]
        assert p["microsoft_only_servers"] is True
        assert "Valve" in p["reason"]

    def test_a_third_party_binary_is_worth_trying_on_a_third_party_server(
        self, tmp_path, clean_symbol_env
    ):
        with patch.object(mod, "version_info_company", return_value="Valve Corporation"):
            p = mod.symbol_server_prognosis(
                _pe(tmp_path, "steam.exe"),
                symbol_path="srv*C:\\sym*https://symbols.vendor.example/",
            )
        assert p["likely"] and p["microsoft_only_servers"] is False

    def test_no_version_resource_reads_as_not_worth_fetching(self, tmp_path, clean_symbol_env):
        with patch.object(mod, "version_info_company", return_value=None):
            p = mod.symbol_server_prognosis(_pe(tmp_path))
        assert not p["likely"] and "no CompanyName" in p["reason"]

    def test_a_missing_pefile_does_not_become_a_refusal(self, tmp_path, clean_symbol_env):
        with patch.object(mod, "version_info_company", return_value=None), \
                patch.object(mod, "_pefile_available", return_value=False):
            p = mod.symbol_server_prognosis(_pe(tmp_path))
        assert p["likely"] and "pefile" in p["reason"]


class TestAutoNoteWording:
    def test_the_skip_note_does_not_send_the_model_to_load_pdb(self, tmp_path, clean_symbol_env):
        with patch.object(mod, "extract_codeview_record", return_value=CV), \
                patch.object(mod, "version_info_company", return_value="Valve Corporation"), \
                patch.object(mod, "fetch_pdb") as fetch:
            _, note = mod.auto_fetch_pdb(_pe(tmp_path, "steam.exe"), policy="microsoft")
        fetch.assert_not_called()
        assert note["status"] == "skipped"
        assert "do NOT retry with load_pdb" in note["detail"]
        assert "Valve Corporation" in note["detail"]


def _tool_fn(tool):
    """The underlying function of a registered tool.

    Some test modules stub out fastmcp, so ``@app.tool()`` sometimes leaves a
    FunctionTool behind and sometimes the plain function.
    """
    return getattr(tool, "fn", tool)


class TestLoadPdbGate:
    def _prognosis(self, monkeypatch, likely, reason="CompanyName='Valve Corporation'"):
        monkeypatch.setattr(
            mod,
            "symbol_server_prognosis",
            MagicMock(return_value={
                "is_microsoft": likely,
                "company": "Valve Corporation",
                "microsoft_only_servers": True,
                "likely": likely,
                "reason": reason,
            }),
        )

    def test_a_third_party_binary_is_refused_before_any_network_call(
        self, server, tmp_path, monkeypatch, clean_symbol_env
    ):
        server_mod, cache_obj, _ = server
        binary = _pe(tmp_path, "steam.exe")
        self._prognosis(monkeypatch, likely=False)
        fetch = MagicMock()
        monkeypatch.setattr(mod, "fetch_pdb", fetch)
        invalidate = MagicMock()
        monkeypatch.setattr(cache_obj, "invalidate", invalidate)

        out = _tool_fn(server_mod.load_pdb)(str(binary))

        fetch.assert_not_called()
        invalidate.assert_not_called()
        assert "No PDB fetch attempted for steam.exe" in out
        assert "Valve Corporation" in out
        assert "allow_non_microsoft=True" in out
        assert "analysis_depth=" in out

    def test_the_override_lets_the_fetch_through(
        self, server, tmp_path, monkeypatch, clean_symbol_env
    ):
        server_mod, _, captured = server
        binary = _pe(tmp_path, "steam.exe")
        prognosis = MagicMock()
        monkeypatch.setattr(mod, "symbol_server_prognosis", prognosis)
        monkeypatch.setattr(mod, "fetch_pdb", MagicMock(return_value=tmp_path / "steam.pdb"))

        out = _tool_fn(server_mod.load_pdb)(str(binary), allow_non_microsoft=True)

        prognosis.assert_not_called()
        assert captured["pdb_path"] == str(tmp_path / "steam.pdb")
        assert "PDB applied" in out

    def test_a_microsoft_binary_still_fetches(
        self, server, tmp_path, monkeypatch, clean_symbol_env
    ):
        server_mod, _, captured = server
        binary = _pe(tmp_path)
        self._prognosis(monkeypatch, likely=True)
        monkeypatch.setattr(mod, "fetch_pdb", MagicMock(return_value=tmp_path / "t.pdb"))

        out = _tool_fn(server_mod.load_pdb)(str(binary))

        assert captured["pdb_path"] == str(tmp_path / "t.pdb")
        assert "PDB applied" in out

    def test_a_vendor_symbol_path_reopens_the_door(
        self, server, tmp_path, monkeypatch, clean_symbol_env
    ):
        """Real prognosis, not a stub: pointing at a non-Microsoft server is
        the caller saying the PDB might be there, and the gate steps aside."""
        server_mod, _, captured = server
        binary = _pe(tmp_path, "steam.exe")
        monkeypatch.setattr(mod, "version_info_company", lambda _p: "Valve Corporation")
        monkeypatch.setattr(mod, "fetch_pdb", MagicMock(return_value=tmp_path / "steam.pdb"))

        out = _tool_fn(server_mod.load_pdb)(
            str(binary), symbol_path="srv*C:\\sym*https://symbols.vendor.example/"
        )

        assert captured["pdb_path"] == str(tmp_path / "steam.pdb")
        assert "PDB applied" in out

    def test_an_explicit_pdb_path_is_never_gated(
        self, server, tmp_path, monkeypatch, clean_symbol_env
    ):
        server_mod, _, captured = server
        binary = _pe(tmp_path, "steam.exe")
        pdb = tmp_path / "steam.pdb"
        pdb.write_bytes(b"pdb")
        prognosis = MagicMock()
        monkeypatch.setattr(mod, "symbol_server_prognosis", prognosis)

        out = _tool_fn(server_mod.load_pdb)(str(binary), pdb_path=str(pdb))

        prognosis.assert_not_called()
        assert captured["pdb_path"] == str(pdb)
        assert "PDB applied" in out
