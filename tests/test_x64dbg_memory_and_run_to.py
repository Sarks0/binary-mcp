"""
Tests for the x64dbg memory dump / search bridge methods and run_to_address.

The plugin side (HandleDumpMemory / HandleSearchMemory in plugin.cpp) needs a
live x64dbg, so these drive the bridge with _request mocked and check what it
sends and how it handles what comes back.
"""

from unittest.mock import MagicMock

import pytest

from src.engines.dynamic.x64dbg import bridge as bridge_mod
from src.engines.dynamic.x64dbg.bridge import (
    DUMP_CHUNK_SIZE,
    SEARCH_TIME_LIMIT_S,
    X64DbgAPIError,
    X64DbgBridge,
)
from src.engines.dynamic.x64dbg.commands import X64DbgCommands


@pytest.fixture
def bridge():
    return X64DbgBridge()


@pytest.fixture
def dump_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path / ".binary_mcp_output" / "dumps"


# --- dump_memory ---------------------------------------------------------


def test_dump_is_chunked_and_streamed(bridge, dump_home):
    size = DUMP_CHUNK_SIZE * 2 + 100
    calls = []

    def fake_request(endpoint, data):
        calls.append((endpoint, dict(data)))
        return {"data": "ab" * data["size"], "unreadable_bytes": 10}

    bridge._request = fake_request
    result = bridge.dump_memory("0x401000", size, "out.bin")

    assert [c[0] for c in calls] == ["/api/memory/dump"] * 3
    assert [c[1]["size"] for c in calls] == [DUMP_CHUNK_SIZE, DUMP_CHUNK_SIZE, 100]
    assert [int(c[1]["address"], 16) for c in calls] == [
        0x401000,
        0x401000 + DUMP_CHUNK_SIZE,
        0x401000 + 2 * DUMP_CHUNK_SIZE,
    ]
    assert result["bytes_written"] == size
    assert result["unreadable_bytes"] == 30
    with open(result["output_file"], "rb") as f:
        assert f.read() == b"\xab" * size


def test_failed_dump_leaves_no_partial_file(bridge, dump_home):
    responses = iter([{"data": "00" * DUMP_CHUNK_SIZE}, RuntimeError("pipe gone")])

    def fake_request(endpoint, data):
        item = next(responses)
        if isinstance(item, Exception):
            raise item
        return item

    bridge._request = fake_request
    with pytest.raises(RuntimeError):
        bridge.dump_memory("401000", DUMP_CHUNK_SIZE * 2, "partial.bin")
    assert not (dump_home / "partial.bin").exists()


def test_short_chunk_is_an_error(bridge, dump_home):
    bridge._request = MagicMock(return_value={"data": "00" * 4})
    with pytest.raises(RuntimeError, match="returned 4 bytes"):
        bridge.dump_memory("401000", 16, "short.bin")
    assert not (dump_home / "short.bin").exists()


@pytest.mark.parametrize("size", [0, -1, bridge_mod.MAX_DUMP_SIZE + 1])
def test_dump_rejects_bad_sizes(bridge, dump_home, size):
    bridge._request = MagicMock()
    with pytest.raises(ValueError):
        bridge.dump_memory("401000", size, "x.bin")
    bridge._request.assert_not_called()


# --- search_memory -------------------------------------------------------


def test_search_normalises_pattern_and_extends_timeout(bridge):
    seen = {}

    def fake_request(endpoint, data):
        seen["endpoint"] = endpoint
        seen["data"] = data
        seen["timeout"] = bridge.timeout
        return {
            "count": 1,
            "matches": [{"address": "401000", "context": "a.exe"}],
            "truncated": False,
            "stop_reason": "",
            "regions_scanned": 3,
            "bytes_scanned": 4096,
        }

    bridge._request = fake_request
    before = bridge.timeout
    result = bridge.search_memory("0x4D 0x5A ?? 90", "Executable")

    assert seen["endpoint"] == "/api/memory/search"
    assert seen["data"] == {"pattern": "4D5A??90", "region": "executable", "max_matches": 1000}
    assert seen["timeout"] >= SEARCH_TIME_LIMIT_S
    assert bridge.timeout == before
    assert result["matches"] == [{"address": "401000", "context": "a.exe"}]
    assert result["regions_scanned"] == 3


@pytest.mark.parametrize(
    "pattern, region",
    [
        ("90 90", "heap"),       # unknown region
        ("?? ??", "all"),        # nothing but wildcards
        ("9", "all"),            # odd nibble count
        ("zz", "all"),           # not hex
        ("", "all"),
    ],
)
def test_search_rejects_bad_input_locally(bridge, pattern, region):
    bridge._request = MagicMock()
    with pytest.raises(ValueError):
        bridge.search_memory(pattern, region)
    bridge._request.assert_not_called()


def test_wait_until_paused_outlasts_its_own_timeout(bridge):
    seen = {}

    def fake_request(endpoint, data, raise_on_api_error=True):
        seen["timeout"] = bridge.timeout
        seen["raise_on_api_error"] = raise_on_api_error
        return {"success": True}

    bridge._request = fake_request
    bridge.wait_until_paused(timeout=120000)
    assert seen["timeout"] > 120
    assert bridge.timeout == 30
    # The timeout body must come back as data, not an exception (X64M-03).
    assert seen["raise_on_api_error"] is False


def test_wait_until_paused_returns_structured_timeout(bridge):
    """A wait that times out is a result, not an exception (X64M-03)."""
    timeout_body = {
        "success": False,
        "error": "Timeout waiting for debugger to pause",
        "timeout_ms": 3000,
        "elapsed_ms": 3000,
        "current_state": "running",
    }
    bridge._request = MagicMock(return_value=timeout_body)
    result = bridge.wait_until_paused(timeout=3000)
    assert result["success"] is False
    assert result["current_state"] == "running"
    _, kwargs = bridge._request.call_args
    assert kwargs.get("raise_on_api_error") is False


def test_run_reports_failure_to_resume(bridge):
    """X64M-02: a debuggee that will not resume is not reported as success."""
    bridge._request = MagicMock(return_value={
        "success": False,
        "is_running": False,
        "state": "paused",
        "current_address": "7ff895408a34",
        "message": "run issued but the debuggee did not resume",
    })
    result = bridge.run()
    assert result["resumed"] is False
    assert "did not resume" in result["message"]
    _, kwargs = bridge._request.call_args
    assert kwargs.get("raise_on_api_error") is False


def test_run_reports_success(bridge):
    bridge._request = MagicMock(return_value={
        "success": True, "is_running": True, "state": "running",
        "current_address": "401000", "message": "Execution resumed",
    })
    result = bridge.run()
    assert result["resumed"] is True
    assert result["state"] == "running"


def test_pause_reports_still_running(bridge):
    """X64M-02: pause that does not take effect is not a false success."""
    bridge._request = MagicMock(return_value={
        "success": False, "is_running": True, "state": "running",
        "current_address": "401000",
        "message": "pause issued but the debuggee is still running",
    })
    result = bridge.pause()
    assert result["paused"] is False
    assert result["is_running"] is True


def test_get_current_location_surfaces_running_state(bridge):
    bridge._request_with_retry = MagicMock(return_value={
        "state": "running", "is_running": True, "thread_id": 1808,
        "current_address": "7ff895408a34", "binary_path": "C:/msdtc.exe",
    })
    loc = bridge.get_current_location()
    assert loc["is_running"] is True
    assert loc["thread_id"] == 1808
    assert loc["state"] == "running"


# --- run_to_address ------------------------------------------------------


def _commands(bp_list=(), wait=None, location=None):
    b = MagicMock()
    b.is_connected.return_value = True
    b._normalize_address.side_effect = lambda a: a.lower().removeprefix("0x")
    b.list_breakpoints.return_value = list(bp_list)
    if isinstance(wait, Exception):
        b.wait_until_paused.side_effect = wait
    else:
        b.wait_until_paused.return_value = wait or {}
    b.get_current_location.return_value = location or {}
    return X64DbgCommands(bridge=b), b


def test_run_to_address_waits_and_removes_temp_breakpoint():
    cmds, b = _commands(
        wait={"success": True, "current_address": "401000", "elapsed_ms": 12},
        location={"address": "401000", "state": "paused"},
    )
    result = cmds.run_to_address("0x401000", timeout=5000)

    b.set_breakpoint.assert_called_once_with("401000")
    b.run.assert_called_once()
    b.wait_until_paused.assert_called_once_with(timeout=5000)
    b.delete_breakpoint.assert_called_once_with("401000")
    assert result["reached"] is True
    assert result["elapsed_ms"] == 12


def test_run_to_address_reports_stopping_elsewhere():
    cmds, b = _commands(
        wait={"success": True, "current_address": "402000"},
        location={"address": "402000", "state": "paused"},
    )
    result = cmds.run_to_address("401000")
    assert result["reached"] is False
    assert result["address"] == "402000"
    assert "error" not in result
    b.delete_breakpoint.assert_called_once_with("401000")


def test_run_to_address_timeout_is_an_outcome_not_an_exception():
    timeout = X64DbgAPIError("paused", "Timeout waiting for debugger to pause")
    cmds, b = _commands(wait=timeout, location={"address": "0", "state": "paused"})
    result = cmds.run_to_address("401000")
    assert result["reached"] is False
    assert result["state"] == "running"
    assert "Timeout" in result["error"]
    b.delete_breakpoint.assert_called_once_with("401000")


def test_run_to_address_keeps_an_existing_breakpoint():
    cmds, b = _commands(
        bp_list=[{"address": "00401000"}],
        wait={"success": True, "current_address": "401000"},
        location={"address": "401000", "state": "paused"},
    )
    result = cmds.run_to_address("0x401000")
    b.set_breakpoint.assert_not_called()
    b.delete_breakpoint.assert_not_called()
    assert result["reached"] is True


def test_run_to_address_cleans_up_when_run_fails():
    cmds, b = _commands()
    b.run.side_effect = ConnectionError("plugin gone")
    with pytest.raises(ConnectionError):
        cmds.run_to_address("401000")
    b.delete_breakpoint.assert_called_once_with("401000")
