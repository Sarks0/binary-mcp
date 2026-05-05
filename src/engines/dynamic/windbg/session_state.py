"""
Kernel debugging session state machine.

Tracks the live state of a kernel-debug target as observed via DbgEng's
``IDebugEventCallbacks``. Existence of this state machine is what lets the
bridge tell the difference between:

  - "wait() returned because the target broke in" (BROKEN: a current
    thread/process exists, commands work),
  - "wait() returned because handshake completed but the target is still
    running" (ESTABLISHED/RUNNING: no current thread; commands fail with
    'debugger does not have a current process or thread'), and
  - "wait() returned because the target dropped" (GONE).

The first two are indistinguishable from ``wait()`` alone, which is the
KDNET half-handshake bug. Subscribing to ``SessionStatus`` /
``ChangeEngineState`` events resolves it.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class KernelSessionState(StrEnum):
    """Lifecycle states for a kernel-debug session."""

    DISCONNECTED = "disconnected"
    LISTENING = "listening"
    HANDSHAKING = "handshaking"
    ESTABLISHED = "established"
    RUNNING = "running"
    BROKEN = "broken"
    GONE = "gone"
    BUGCHECK = "bugcheck"


_LIVE_STATES = frozenset({
    KernelSessionState.ESTABLISHED,
    KernelSessionState.RUNNING,
    KernelSessionState.BROKEN,
    KernelSessionState.BUGCHECK,
})


@dataclass
class SessionTracker:
    """Thread-safe accessor for the current kernel-session state.

    The DbgEng event-callback thread updates the fields; the bridge thread
    reads them. A single ``RLock`` guards every mutation so reads observe a
    consistent snapshot.
    """

    state: KernelSessionState = KernelSessionState.DISCONNECTED
    last_bugcheck_code: int | None = None
    last_bugcheck_args: tuple[int, ...] = ()
    last_bugcheck_analysis: str | None = None
    current_thread_id: int | None = None
    last_loaded_module: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def set_state(self, new_state: KernelSessionState) -> None:
        with self._lock:
            self.state = new_state

    def is_live(self) -> bool:
        with self._lock:
            return self.state in _LIVE_STATES

    def is_broken(self) -> bool:
        with self._lock:
            return self.state == KernelSessionState.BROKEN

    def record_bugcheck(self, code: int, args: tuple[int, ...] = ()) -> None:
        with self._lock:
            self.state = KernelSessionState.BUGCHECK
            self.last_bugcheck_code = code
            self.last_bugcheck_args = args

    def record_module_load(self, name: str) -> None:
        with self._lock:
            self.last_loaded_module = name

    def record_break(self, thread_id: int | None = None) -> None:
        with self._lock:
            self.state = KernelSessionState.BROKEN
            if thread_id is not None:
                self.current_thread_id = thread_id

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot for tools to surface."""
        with self._lock:
            return {
                "state": self.state.value,
                "last_bugcheck_code": self.last_bugcheck_code,
                "last_bugcheck_args": list(self.last_bugcheck_args),
                "current_thread_id": self.current_thread_id,
                "last_loaded_module": self.last_loaded_module,
            }

    def reset(self) -> None:
        with self._lock:
            self.state = KernelSessionState.DISCONNECTED
            self.last_bugcheck_code = None
            self.last_bugcheck_args = ()
            self.last_bugcheck_analysis = None
            self.current_thread_id = None
            self.last_loaded_module = None
            self.extra.clear()
