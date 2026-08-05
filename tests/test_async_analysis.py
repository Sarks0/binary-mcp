"""
Tests for the async (job-backed) paths on analyze_binary and decompile_function.

The property under test is not "does it return a job id" -- it is that going
async does not change what the tools mean. Specifically: the fast path must
stay synchronous, two callers must share one Ghidra run, and the coverage
ledger must not gain a mark for a body nobody was handed.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# Stub MCP deps before importing src.server, matching tests/test_get_xrefs.py.
sys.modules["mcp"] = MagicMock()
sys.modules["mcp.server"] = MagicMock()
sys.modules["mcp.types"] = MagicMock()

_identity_decorator = lambda fn: fn  # noqa: E731
_fastmcp_instance = MagicMock()
_fastmcp_instance.tool = MagicMock(return_value=_identity_decorator)
_fastmcp_stub = MagicMock()
_fastmcp_stub.FastMCP = MagicMock(return_value=_fastmcp_instance)
sys.modules["fastmcp"] = _fastmcp_stub


def _func(name, address, pseudocode="", is_thunk=False, is_external=False):
    return {
        "name": name,
        "address": address,
        "pseudocode": pseudocode,
        "is_thunk": is_thunk,
        "is_external": is_external,
        "basic_blocks": [],
        "parameters": [],
        "local_variables": [],
        "signature": f"int {name}(void)",
        "decompile_status": "success",
        "called_functions": [],
        "jump_tables": [],
        "fid_match": None,
        "size": 64,
    }


def _ctx(functions, depth="structural"):
    return {
        "metadata": {"name": "test.dll", "analysis_depth": depth},
        "functions": functions,
        "imports": [],
        "strings": [],
        "memory_map": [],
    }


@pytest.fixture
def server(tmp_path_factory, monkeypatch):
    fake_ghidra = tmp_path_factory.mktemp("ghidra_home")
    (fake_ghidra / "support").mkdir()
    (fake_ghidra / "support" / "analyzeHeadless").touch()
    monkeypatch.setenv("GHIDRA_HOME", str(fake_ghidra))
    monkeypatch.setenv("BINARY_CACHE_DIR", str(tmp_path_factory.mktemp("cache")))

    sys.modules.pop("src.server", None)
    import src.server as server_mod

    return server_mod


def _wait_done(server, job_id, timeout=5.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        record = server.jobs.read(job_id)
        if record and record["state"] != "running":
            return record
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never finished")


def _job_id(report: str) -> str:
    for line in report.splitlines():
        if line.startswith("job_id:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError(f"no job_id in report:\n{report}")


class TestDecompileFastPath:
    """Async must not change the meaning of a call that has nothing to wait on."""

    def test_cached_pseudocode_returns_synchronously_even_when_not_waiting(
        self, server, monkeypatch
    ):
        context = _ctx([_func("Parse", "0x1000", pseudocode="int Parse(void){return 1;}")],
                       depth="full")
        monkeypatch.setattr(server.cache, "get_cached", lambda p: context)
        monkeypatch.setattr(server, "get_analysis_context", lambda *a, **kw: context)

        result = server.decompile_function("/bin/test.dll", "Parse", wait=False)

        assert "job_id" not in result
        assert "int Parse(void){return 1;}" in result

    def test_a_missing_function_still_errors_rather_than_queueing(self, server, monkeypatch):
        context = _ctx([_func("Parse", "0x1000")])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: context)

        result = server.decompile_function("/bin/test.dll", "Nope", wait=False)
        assert "not found" in result
        assert "job_id" not in result

    def test_a_thunk_is_refused_rather_than_queued(self, server, monkeypatch):
        context = _ctx([_func("thunk_x", "0x1000", is_thunk=True)])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: context)

        result = server.decompile_function("/bin/test.dll", "thunk_x", wait=False)
        assert "thunk" in result
        assert "job_id" not in result


class TestDecompileJobPath:
    @staticmethod
    def _structural(server, monkeypatch, decompiled="int Parse(void){return 1;}"):
        """A structural cache: the function exists, its pseudocode does not."""
        cold = _ctx([_func("Parse", "0x1000")])
        warm = _ctx([_func("Parse", "0x1000", pseudocode=decompiled)])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: cold)
        calls = []

        def _analysis(binary_path, *a, **kw):
            calls.append(kw)
            return warm

        monkeypatch.setattr(server, "get_analysis_context", _analysis)
        return calls

    def test_structural_cache_returns_a_job_instead_of_blocking(self, server, monkeypatch):
        self._structural(server, monkeypatch)
        result = server.decompile_function("/bin/test.dll", "Parse", wait=False)

        assert "job_id:" in result
        assert "0x1000" in result, "the report should say what it is decompiling"
        record = _wait_done(server, _job_id(result))
        assert record["state"] == "succeeded"
        assert record["result"]["decompiled"] is True
        assert record["result"]["pseudocode"] == "int Parse(void){return 1;}"

    def test_the_job_runs_a_targeted_decompile_not_a_reanalysis(self, server, monkeypatch):
        """A whole-binary re-analysis here would be minutes of Ghidra for one
        function -- the exact cost the incremental path exists to avoid."""
        calls = self._structural(server, monkeypatch)
        result = server.decompile_function("/bin/test.dll", "Parse", wait=False)
        _wait_done(server, _job_id(result))

        assert len(calls) == 1
        assert calls[0]["incremental"] is True
        assert calls[0]["max_functions"] == 1
        assert calls[0]["start_address"] == "0x1000"

    def test_a_second_caller_attaches_to_the_running_decompile(self, server, monkeypatch):
        import threading

        cold = _ctx([_func("Parse", "0x1000")])
        warm = _ctx([_func("Parse", "0x1000", pseudocode="int Parse(void){return 1;}")])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: cold)
        release = threading.Event()
        started = []

        def _analysis(binary_path, *a, **kw):
            started.append(1)
            release.wait(5)
            return warm

        monkeypatch.setattr(server, "get_analysis_context", _analysis)

        first = server.decompile_function("/bin/test.dll", "Parse", wait=False)
        import time

        deadline = time.time() + 5
        while not started and time.time() < deadline:
            time.sleep(0.02)

        second = server.decompile_function("/bin/test.dll", "Parse", wait=False)
        assert "Attached to a decompile already running" in second
        assert _job_id(second) == _job_id(first)

        release.set()
        _wait_done(server, _job_id(first))
        assert started == [1], "the decompile must have run exactly once"

    def test_a_different_function_gets_its_own_job(self, server, monkeypatch):
        cold = _ctx([_func("Parse", "0x1000"), _func("Other", "0x2000")])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: cold)
        monkeypatch.setattr(server, "get_analysis_context", lambda *a, **kw: cold)

        a = server.decompile_function("/bin/test.dll", "Parse", wait=False)
        b = server.decompile_function("/bin/test.dll", "Other", wait=False)
        assert _job_id(a) != _job_id(b)


class TestAsyncCoverageSemantics:
    """The ledger rule is that a function is marked reviewed only once its body
    has been handed to the caller. A background decompile hands it to nobody --
    it warms the cache and finishes -- so it must not mark. Under-marking costs
    a re-mark; over-marking manufactures false completion."""

    def test_the_background_decompile_does_not_mark(self, server, monkeypatch):
        cold = _ctx([_func("Parse", "0x1000")])
        warm = _ctx([_func("Parse", "0x1000", pseudocode="int Parse(void){return 1;}")])
        monkeypatch.setattr(server.cache, "get_cached", lambda p: cold)
        monkeypatch.setattr(server, "get_analysis_context", lambda *a, **kw: warm)

        marked = []
        monkeypatch.setattr(
            server, "auto_mark_reviewed",
            lambda *a, **kw: marked.append(a),
        )

        result = server.decompile_function("/bin/test.dll", "Parse", wait=False)
        _wait_done(server, _job_id(result))

        assert marked == [], "a body nobody was handed must not be marked reviewed"

    def test_the_warm_call_that_returns_the_body_does_mark(self, server, monkeypatch):
        """The other half: once the cache is warm and the body is genuinely
        returned, the mark lands as it always did."""
        warm = _ctx([_func("Parse", "0x1000", pseudocode="int Parse(void){return 1;}")],
                    depth="full")
        monkeypatch.setattr(server.cache, "get_cached", lambda p: warm)
        monkeypatch.setattr(server, "get_analysis_context", lambda *a, **kw: warm)

        marked = []
        monkeypatch.setattr(
            server, "auto_mark_reviewed",
            lambda *a, **kw: marked.append(kw.get("tool") or a),
        )

        server.decompile_function("/bin/test.dll", "Parse", wait=False)
        assert marked == ["decompile_function"]


class TestAnalyzeJobKey:
    """Two agents asking for the same analysis must share a run; an agent
    asking to redo it must not silently attach to the run it meant to bypass."""

    def test_same_parameters_produce_the_same_key(self, server):
        kwargs = {"skip_decompile": False, "analysis_depth": "full"}
        a = server._analysis_job_key("/bin/x.dll", False, None, None, kwargs)
        b = server._analysis_job_key("/bin/x.dll", False, None, None, dict(kwargs))
        assert a == b

    def test_force_reanalyze_is_part_of_the_key(self, server):
        kwargs = {"analysis_depth": "full"}
        assert server._analysis_job_key("/bin/x.dll", False, None, None, kwargs) != \
               server._analysis_job_key("/bin/x.dll", True, None, None, kwargs)

    def test_different_depth_produces_a_different_key(self, server):
        assert server._analysis_job_key("/bin/x.dll", False, None, None,
                                        {"analysis_depth": "full"}) != \
               server._analysis_job_key("/bin/x.dll", False, None, None,
                                        {"analysis_depth": "structural"})

    def test_key_survives_an_unhashable_parameter(self, server):
        """The key is built from whatever kwargs analyze_binary was given;
        a value json cannot serialize must not take the tool down."""
        key = server._analysis_job_key(
            "/bin/x.dll", False, None, None, {"weird": object()}
        )
        assert key.startswith("analyze-")
