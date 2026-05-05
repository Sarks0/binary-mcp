"""
DbgEng IDebugEventCallbacks bridge.

Subscribes to the engine's event stream and translates each event into a
state transition on a :class:`SessionTracker`. This is the missing piece
behind the KDNET "half-handshake" class of bug: ``wait()`` alone cannot
distinguish "handshake completed, target still running" from "target
broke in". The ``SessionStatus`` and ``Breakpoint``/``Exception`` events
make the difference observable.

DbgEng/comtypes are Windows-only. To keep tests cross-platform, the
class is plain Python and exposes one entry point per event type. On
Windows the bridge wires a thin ``comtypes.COMObject`` shim that
forwards real engine events to these handlers; on POSIX (CI runners,
dev boxes) tests instantiate the class directly and call the handlers
in-process. No comtypes dependency is required at import time.

Reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nn-dbgeng-idebugeventcallbacks
"""

from __future__ import annotations

import logging
from typing import Any

from .session_state import KernelSessionState, SessionTracker

logger = logging.getLogger(__name__)

# DbgEng DEBUG_STATUS_* return codes (subset we use)
DEBUG_STATUS_NO_CHANGE = 0
DEBUG_STATUS_BREAK = 4

# DbgEng DEBUG_SESSION_* values surfaced via SessionStatus().
# https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugeventcallbacks-sessionstatus
DEBUG_SESSION_ACTIVE = 0
DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE = 1
DEBUG_SESSION_END_SESSION_ACTIVE_DETACH = 2
DEBUG_SESSION_END_SESSION_PASSIVE = 3
DEBUG_SESSION_END = 4
DEBUG_SESSION_REBOOT = 5
DEBUG_SESSION_HIBERNATE = 6
DEBUG_SESSION_FAILURE = 7

# DbgEng DEBUG_CES_* (ChangeEngineState bits we care about)
DEBUG_CES_EXECUTION_STATUS = 0x00000001

# DEBUG_STATUS_* values for ExecutionStatus
DEBUG_STATUS_BREAK_AT_TARGET = 4
DEBUG_STATUS_GO = 0x10
DEBUG_STATUS_GO_NOT_HANDLED = 0x11
DEBUG_STATUS_GO_HANDLED = 0x12
DEBUG_STATUS_STEP_OVER = 0x13
DEBUG_STATUS_STEP_INTO = 0x14


class BinaryMcpEventCallbacks:
    """Pure-Python event handlers; Windows comtypes shim forwards to them.

    Each method mirrors a DbgEng ``IDebugEventCallbacks`` method but takes
    only the fields we need. They are intentionally cheap and never raise:
    DbgEng's COM contract treats handler exceptions as engine-fatal, and
    we'd rather degrade to "best-effort tracking" than crash the session.
    """

    def __init__(self, tracker: SessionTracker):
        self._tracker = tracker

    def on_session_status(self, status: int) -> int:
        """SessionStatus: lifecycle transitions (active/reboot/end/...)."""
        try:
            if status == DEBUG_SESSION_ACTIVE:
                # Target is now reachable. We don't yet know if it's broken
                # in or still running; ChangeEngineState/Breakpoint/Exception
                # will refine the state. Mark as ESTABLISHED for now.
                if self._tracker.state in (
                    KernelSessionState.DISCONNECTED,
                    KernelSessionState.LISTENING,
                    KernelSessionState.HANDSHAKING,
                    KernelSessionState.GONE,
                ):
                    self._tracker.set_state(KernelSessionState.ESTABLISHED)
            elif status in (
                DEBUG_SESSION_REBOOT,
                DEBUG_SESSION_HIBERNATE,
                DEBUG_SESSION_FAILURE,
                DEBUG_SESSION_END,
                DEBUG_SESSION_END_SESSION_ACTIVE_TERMINATE,
                DEBUG_SESSION_END_SESSION_ACTIVE_DETACH,
                DEBUG_SESSION_END_SESSION_PASSIVE,
            ):
                self._tracker.set_state(KernelSessionState.GONE)
        except Exception as exc:
            logger.debug("on_session_status handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE

    def on_change_engine_state(self, flags: int, argument: int) -> int:
        """ChangeEngineState: execution status flips (RUNNING <-> BROKEN)."""
        try:
            if flags & DEBUG_CES_EXECUTION_STATUS:
                if argument == DEBUG_STATUS_BREAK_AT_TARGET:
                    self._tracker.record_break()
                elif argument in (
                    DEBUG_STATUS_GO,
                    DEBUG_STATUS_GO_HANDLED,
                    DEBUG_STATUS_GO_NOT_HANDLED,
                ):
                    if self._tracker.state in (
                        KernelSessionState.BROKEN,
                        KernelSessionState.ESTABLISHED,
                    ):
                        self._tracker.set_state(KernelSessionState.RUNNING)
        except Exception as exc:
            logger.debug("on_change_engine_state handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE

    def on_breakpoint(self, bp_id: int, address: int) -> int:
        """Breakpoint hit: implies the target is broken in."""
        try:
            self._tracker.record_break()
        except Exception as exc:
            logger.debug("on_breakpoint handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE

    def on_exception(self, code: int, address: int, first_chance: bool) -> int:
        """Exception (incl. INT3): also implies broken-in state."""
        try:
            self._tracker.record_break()
        except Exception as exc:
            logger.debug("on_exception handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE

    def on_load_module(self, base: int, size: int, name: str) -> int:
        """LoadModule: useful for opportunistic PDB prefetch later."""
        try:
            self._tracker.record_module_load(name)
        except Exception as exc:
            logger.debug("on_load_module handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE

    def on_unload_module(self, base: int, name: str) -> int:
        return DEBUG_STATUS_NO_CHANGE

    def on_system_error(self, error: int, level: int) -> int:
        """SystemError: bugcheck and similar engine-level errors."""
        try:
            self._tracker.record_bugcheck(error)
        except Exception as exc:
            logger.debug("on_system_error handler error: %s", exc)
        return DEBUG_STATUS_NO_CHANGE


def register_callbacks(dbg: Any, callbacks: BinaryMcpEventCallbacks) -> bool:
    """Attach ``callbacks`` to a pybag debugger object.

    Best-effort. Drops to ``comtypes`` to wrap our pure-Python handler in
    a real COM object the engine can call. Returns False (and logs a
    warning) on any failure - the bridge will continue to function in
    degraded mode using just ``wait()``.

    The wiring is Windows-only by design. On non-Windows platforms there
    is no DbgEng to register against, so callers should skip this call.
    """
    try:
        import comtypes  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        logger.debug("comtypes unavailable; skipping IDebugEventCallbacks")
        return False

    client = getattr(dbg, "_client", None)
    if client is None:
        logger.warning(
            "pybag debugger has no _client attribute; "
            "IDebugEventCallbacks not registered. "
            "Half-handshake detection will be unavailable."
        )
        return False

    try:
        # Building a full IDebugEventCallbacks COMObject requires the
        # DbgEng IDL types. We import lazily and on failure degrade
        # gracefully - the rest of the bridge still works.
        from ._dbgeng_callbacks_shim import build_event_callbacks_com_object
        com_obj = build_event_callbacks_com_object(callbacks)
        client.SetEventCallbacks(com_obj)
        logger.info("IDebugEventCallbacks registered with DbgEng")
        return True
    except Exception as exc:
        logger.warning(
            "Failed to register IDebugEventCallbacks: %s. "
            "Half-handshake detection will be unavailable; bridge "
            "continues in wait()-poll mode.",
            exc,
        )
        return False
