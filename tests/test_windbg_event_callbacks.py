"""Cross-platform tests for the WinDbg event-callback layer.

The DbgEng/comtypes COM machinery is Windows-only and exercised on the
windows-latest CI runner. These tests drive the pure-Python handlers and
the bridge integration directly, so they run on Linux/macOS too.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())

from src.engines.dynamic.windbg.event_callbacks import (  # noqa: E402
    DEBUG_CES_EXECUTION_STATUS,
    DEBUG_SESSION_ACTIVE,
    DEBUG_SESSION_END,
    DEBUG_SESSION_FAILURE,
    DEBUG_SESSION_REBOOT,
    DEBUG_STATUS_BREAK_AT_TARGET,
    DEBUG_STATUS_GO,
    BinaryMcpEventCallbacks,
)
from src.engines.dynamic.windbg.session_state import (  # noqa: E402
    KernelSessionState,
    SessionTracker,
)


@pytest.fixture
def tracker():
    return SessionTracker()


@pytest.fixture
def callbacks(tracker):
    return BinaryMcpEventCallbacks(tracker)


class TestSessionStatus:
    def test_active_lifts_listening_to_established(self, tracker, callbacks):
        tracker.set_state(KernelSessionState.LISTENING)
        callbacks.on_session_status(DEBUG_SESSION_ACTIVE)
        assert tracker.state == KernelSessionState.ESTABLISHED

    def test_active_does_not_clobber_broken(self, tracker, callbacks):
        tracker.record_break(thread_id=1)
        callbacks.on_session_status(DEBUG_SESSION_ACTIVE)
        assert tracker.state == KernelSessionState.BROKEN

    def test_reboot_sets_gone(self, tracker, callbacks):
        tracker.record_break()
        callbacks.on_session_status(DEBUG_SESSION_REBOOT)
        assert tracker.state == KernelSessionState.GONE

    def test_failure_sets_gone(self, tracker, callbacks):
        callbacks.on_session_status(DEBUG_SESSION_FAILURE)
        assert tracker.state == KernelSessionState.GONE

    def test_end_sets_gone(self, tracker, callbacks):
        tracker.record_break()
        callbacks.on_session_status(DEBUG_SESSION_END)
        assert tracker.state == KernelSessionState.GONE


class TestChangeEngineState:
    def test_break_at_target_marks_broken(self, tracker, callbacks):
        tracker.set_state(KernelSessionState.RUNNING)
        callbacks.on_change_engine_state(
            DEBUG_CES_EXECUTION_STATUS, DEBUG_STATUS_BREAK_AT_TARGET
        )
        assert tracker.state == KernelSessionState.BROKEN

    def test_go_marks_running(self, tracker, callbacks):
        tracker.record_break()
        callbacks.on_change_engine_state(
            DEBUG_CES_EXECUTION_STATUS, DEBUG_STATUS_GO
        )
        assert tracker.state == KernelSessionState.RUNNING

    def test_unrelated_flag_ignored(self, tracker, callbacks):
        tracker.record_break()
        callbacks.on_change_engine_state(0, DEBUG_STATUS_GO)
        assert tracker.state == KernelSessionState.BROKEN


class TestBreakpointAndException:
    def test_breakpoint_marks_broken(self, tracker, callbacks):
        tracker.set_state(KernelSessionState.RUNNING)
        callbacks.on_breakpoint(0, 0xFFFFFFFF12345678)
        assert tracker.state == KernelSessionState.BROKEN

    def test_exception_marks_broken(self, tracker, callbacks):
        tracker.set_state(KernelSessionState.RUNNING)
        callbacks.on_exception(0xC0000005, 0x0, True)
        assert tracker.state == KernelSessionState.BROKEN


class TestModuleAndSystemError:
    def test_load_module_records_name(self, tracker, callbacks):
        callbacks.on_load_module(0x1000, 0x100, "ntoskrnl.exe")
        assert tracker.last_loaded_module == "ntoskrnl.exe"

    def test_system_error_records_bugcheck(self, tracker, callbacks):
        callbacks.on_system_error(0x7E, 0)
        assert tracker.state == KernelSessionState.BUGCHECK
        assert tracker.last_bugcheck_code == 0x7E


class TestHandlerExceptionsSwallowed:
    """COM contract: handlers must never raise out of the engine."""

    def test_session_status_swallows_exceptions(self, tracker):
        broken = MagicMock(spec=SessionTracker)
        broken.state = KernelSessionState.LISTENING
        broken.set_state.side_effect = RuntimeError("boom")
        cb = BinaryMcpEventCallbacks(broken)
        # Must not raise.
        cb.on_session_status(DEBUG_SESSION_ACTIVE)


class TestRegisterCallbacks:
    def test_returns_false_when_no_comtypes(self, callbacks):
        from src.engines.dynamic.windbg.event_callbacks import register_callbacks

        # On non-Windows, comtypes is unavailable and the function returns
        # False without raising.
        try:
            import comtypes  # noqa: F401
            pytest.skip("comtypes available - this test runs on POSIX only")
        except ImportError:
            pass
        assert register_callbacks(MagicMock(), callbacks) is False

    def test_returns_false_when_dbg_has_no_client(self, callbacks):
        from src.engines.dynamic.windbg.event_callbacks import register_callbacks

        # Even with comtypes, a degenerate dbg without _client must not crash.
        with patch(
            "src.engines.dynamic.windbg.event_callbacks.comtypes",
            create=True,
        ):
            stub = MagicMock(spec=[])  # no _client attribute
            assert register_callbacks(stub, callbacks) is False


class TestBridgeIntegration:
    """Bridge-side wiring: tracker + break_in + safe_disconnect."""

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_bridge_creates_tracker_and_callbacks(self, _system):
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        assert bridge._session.state == KernelSessionState.DISCONNECTED
        assert isinstance(bridge._event_callbacks, BinaryMcpEventCallbacks)
        assert bridge._callbacks_registered is False

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_safe_disconnect_resets_tracker(self, _system):
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._session.record_break(thread_id=42)
        bridge._safe_disconnect()
        assert bridge._dbg is None
        assert bridge._session.state == KernelSessionState.DISCONNECTED
        assert bridge._session.current_thread_id is None

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_break_in_succeeds_when_setinterrupt_breaks(self, _system):
        from src.engines.dynamic.base import DebuggerState
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._state = DebuggerState.RUNNING

        # Simulate the engine driving our event callback during wait().
        def _fake_wait(_ms):
            bridge._session.record_break(thread_id=7)

        bridge._dbg.wait.side_effect = _fake_wait
        bridge.break_in(timeout=1)

        assert bridge._session.is_broken()
        bridge._dbg._control.SetInterrupt.assert_called_once_with(0)

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_break_in_legacy_mode_uses_wait_return_as_break_signal(
        self, _system
    ):
        """Without event callbacks (comtypes unavailable, legacy pybag),
        a clean wait() return must be treated as broken-in. Otherwise
        the tracker is never populated and break_in always fails -
        exactly the regression PR #115 review caught.
        """
        from src.engines.dynamic.base import DebuggerState
        from src.engines.dynamic.windbg.bridge import WinDbgBridge

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._state = DebuggerState.RUNNING
        bridge._callbacks_registered = False  # legacy mode
        bridge._dbg.wait.return_value = None  # clean wait, no callback fires

        assert bridge.break_in(timeout=1) is True
        assert bridge._session.is_broken()

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_break_in_with_callbacks_falls_back_to_dotbreak_then_raises(
        self, _system
    ):
        from src.engines.dynamic.base import DebuggerState
        from src.engines.dynamic.windbg.bridge import (
            WinDbgBridge,
            WinDbgBridgeError,
        )

        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._state = DebuggerState.RUNNING
        # With callbacks registered the legacy short-circuit does not apply,
        # so a wait() that returns without driving the tracker is genuinely
        # a non-break and we must fall through to .break and then raise.
        bridge._callbacks_registered = True
        bridge._dbg.wait.return_value = None

        with pytest.raises(WinDbgBridgeError, match="did not break"):
            bridge.break_in(timeout=1)

        bridge._dbg._control.SetInterrupt.assert_called_once_with(0)
        bridge._dbg.cmd.assert_called_with(".break")
