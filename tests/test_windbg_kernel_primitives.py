"""Tests for the structured kernel-primitives bridge methods.

Covers: get_stack, get_thread, get_process, dump_type,
set_hardware_breakpoint, switch_thread.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())

from src.engines.dynamic.base import DebuggerState  # noqa: E402
from src.engines.dynamic.windbg.bridge import (  # noqa: E402
    WinDbgBridge,
    WinDbgBridgeError,
)


@pytest.fixture()
def bridge():
    """Bridge with a mocked engine in a connected/paused state."""
    b = WinDbgBridge()
    b._dbg = MagicMock()
    b._state = DebuggerState.PAUSED
    b._mode = b._mode.__class__.KERNEL_MODE
    return b


class TestGetStack:
    def test_parses_kn_output(self, bridge):
        bridge._dbg.cmd.return_value = (
            "00 fffff800`00001000 fffff800`00002000 nt!KeBugCheckEx+0x0\n"
            "01 fffff800`00001100 fffff800`00002200 module!Func+0x42\n"
        )
        frames = bridge.get_stack(frames=8)
        assert len(frames) == 2
        assert frames[0]["call_site"] == "nt!KeBugCheckEx+0x0"
        assert frames[1]["child_sp"] == "fffff80000001100"
        bridge._dbg.cmd.assert_called_with("kn 0x8")

    def test_thread_switch_before_stack(self, bridge):
        bridge._dbg.cmd.return_value = ""
        bridge.get_stack(thread_id=5, frames=4)
        # First call switches thread, second walks stack.
        calls = [c.args[0] for c in bridge._dbg.cmd.call_args_list]
        assert calls[0] == "~5s"
        assert calls[1] == "kn 0x4"
        assert bridge._session.current_thread_id == 5

    def test_frames_clamped(self, bridge):
        bridge._dbg.cmd.return_value = ""
        bridge.get_stack(frames=10000)
        assert "kn 0x100" in bridge._dbg.cmd.call_args.args[0]

    def test_thread_switch_failure_raises(self, bridge):
        bridge._dbg.cmd.side_effect = RuntimeError("no such thread")
        with pytest.raises(WinDbgBridgeError, match="thread switch"):
            bridge.get_stack(thread_id=99)


class TestGetThreadProcess:
    def test_get_thread_current(self, bridge):
        bridge._dbg.cmd.return_value = "THREAD info..."
        result = bridge.get_thread()
        assert result["command"] == "!thread"
        assert "THREAD info" in result["output"]

    def test_get_thread_specific(self, bridge):
        bridge._dbg.cmd.return_value = "..."
        bridge.get_thread(thread="0xfffffa8012345678")
        bridge._dbg.cmd.assert_called_with("!thread 0xfffffa8012345678")

    def test_get_process_default_flags(self, bridge):
        bridge._dbg.cmd.return_value = "PROCESS info..."
        result = bridge.get_process()
        assert result["command"] == "!process 0 0x7"

    def test_get_process_specific(self, bridge):
        bridge._dbg.cmd.return_value = "..."
        bridge.get_process(process="0xfffffa80abcd", flags=0)
        bridge._dbg.cmd.assert_called_with("!process 0xfffffa80abcd 0x0")


class TestDumpType:
    def test_parses_top_level_fields(self, bridge):
        bridge._dbg.cmd.return_value = (
            "   +0x000 UniqueProcess    : 0x00000000`00000004\n"
            "   +0x008 ActiveProcessLinks : _LIST_ENTRY\n"
            "      +0x000 Locked           : 0y0\n"
            "   +0x010 Token            : _EX_FAST_REF\n"
        )
        result = bridge.dump_type("nt!_EPROCESS", address="0x1000", depth=2)
        names = [f["name"] for f in result["fields"]]
        assert names == ["UniqueProcess", "ActiveProcessLinks", "Token"]
        # Nested +0x000 Locked should NOT be in top-level fields.
        assert "Locked" not in names
        assert result["fields"][0]["offset"] == "0x000"
        assert "0x00000000" in result["fields"][0]["value"]
        bridge._dbg.cmd.assert_called_with("dt -r2 nt!_EPROCESS 0x1000")

    def test_clamps_depth(self, bridge):
        bridge._dbg.cmd.return_value = ""
        bridge.dump_type("nt!_FOO", depth=99)
        assert "-r3" in bridge._dbg.cmd.call_args.args[0]
        bridge.dump_type("nt!_FOO", depth=-5)
        assert "-r0" in bridge._dbg.cmd.call_args.args[0]

    def test_rejects_shell_metacharacters_in_type(self, bridge):
        with pytest.raises(WinDbgBridgeError, match="invalid type_name"):
            bridge.dump_type("nt!_FOO; .shell calc")

    def test_rejects_shell_metacharacters_in_address(self, bridge):
        with pytest.raises(WinDbgBridgeError, match="invalid address"):
            bridge.dump_type("nt!_FOO", address="0x1000; rm -rf /")

    def test_no_address_omits_arg(self, bridge):
        bridge._dbg.cmd.return_value = ""
        bridge.dump_type("nt!_FOO")
        cmd = bridge._dbg.cmd.call_args.args[0]
        assert cmd == "dt -r1 nt!_FOO"


class TestHardwareBreakpoint:
    def test_emits_ba_command(self, bridge):
        bridge.set_hardware_breakpoint(address="0xfffff80012340000", kind="w", size=4)
        bridge._dbg.cmd.assert_called_with("ba w 4 0xfffff80012340000")

    def test_default_kind_is_execute(self, bridge):
        bridge.set_hardware_breakpoint(address="nt!NtSetInformationToken")
        bridge._dbg.cmd.assert_called_with("ba e 1 nt!NtSetInformationToken")

    @pytest.mark.parametrize("kind", ["x", "X", "z", ""])
    def test_rejects_invalid_kind(self, bridge, kind):
        with pytest.raises(WinDbgBridgeError, match="invalid kind"):
            bridge.set_hardware_breakpoint(address="0x1000", kind=kind)

    @pytest.mark.parametrize("size", [0, 3, 5, 16])
    def test_rejects_invalid_size(self, bridge, size):
        with pytest.raises(WinDbgBridgeError, match="invalid size"):
            bridge.set_hardware_breakpoint(address="0x1000", kind="w", size=size)


class TestSwitchThread:
    def test_emits_tilde_n_s_and_updates_tracker(self, bridge):
        bridge._dbg.cmd.return_value = "thread switched"
        result = bridge.switch_thread(thread_id=42)
        bridge._dbg.cmd.assert_called_with("~42s")
        assert result["thread_id"] == 42
        assert bridge._session.current_thread_id == 42

    def test_propagates_engine_error(self, bridge):
        bridge._dbg.cmd.side_effect = RuntimeError("no such thread")
        with pytest.raises(WinDbgBridgeError):
            bridge.switch_thread(thread_id=999)
