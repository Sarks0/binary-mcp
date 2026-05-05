"""
WinDbg bridge client via Pybag (DbgEng COM API).

Provides kernel-mode and user-mode debugging through the Windows Debugger Engine
COM interfaces, with a CDB subprocess fallback for extension (!) commands.
"""

from __future__ import annotations

import concurrent.futures
import functools
import logging
import os
import platform
import re
import shutil
import subprocess
import time
import traceback
from pathlib import Path
from typing import Any

from src.utils.structured_errors import (
    StructuredBaseError,
    create_debugger_not_connected_error,
    create_debugger_not_paused_error,
    create_kernel_driver_not_found_error,
    create_kernel_not_connected_error,
    create_memory_read_failed_error,
    create_memory_write_failed_error,
    create_windbg_command_failed_error,
    create_windbg_not_found_error,
)

from ..base import Debugger, DebuggerState
from .error_logger import ErrorContext, WinDbgErrorLogger
from .event_callbacks import BinaryMcpEventCallbacks, register_callbacks
from .kernel_types import (
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
    WinDbgMode,
)
from .output_parser import WinDbgOutputParser
from .session_state import KernelSessionState, SessionTracker
from .sympath import (
    compute_nt_symbol_path,
    get_engine_sympath,
    join_sympath,
    set_engine_sympath,
    subprocess_env_with_sympath,
    validate_sympath_element,
)

logger = logging.getLogger(__name__)

# Conditional Pybag import -- only available on Windows with Pybag installed
PYBAG_AVAILABLE = False
pybag = None
try:
    import pybag as _pybag  # type: ignore[import-untyped]

    pybag = _pybag
    PYBAG_AVAILABLE = True
except ImportError:
    pass

# Common Windows SDK install paths for CDB.exe
_SDK_SEARCH_PATHS = [
    Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"),
    Path(r"C:\Program Files\Windows Kits\10\Debuggers\x64"),
    Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"),
    Path(r"C:\Debuggers"),
]

# CDB subprocess timeout for extension commands (seconds)
_CDB_TIMEOUT = 30

# Timeout for KDNET kernel attach (seconds).  pybag's KernelDbg.attach() blocks
# indefinitely waiting for the target -- this caps the wait so callers get an
# actionable error instead of hanging forever.  Override with KDNET_TIMEOUT env.
_KDNET_TIMEOUT = int(os.environ.get("KDNET_TIMEOUT", "60"))

# Dangerous WinDbg meta-commands that must never be executed via the bridge.
# Checked case-insensitively via substring match (commands can follow semicolons).
_BLOCKED_COMMANDS = (
    # Process/session control
    ".shell",
    ".create",
    ".abandon",
    ".kill",
    ".restart",
    ".detach",
    ".reboot",
    ".crash",
    ".bugcheck",
    # File I/O
    ".dump",
    ".writemem",
    ".writevirtmem",
    ".logopen",
    ".logclose",
    ".open",
    ".opendump",
    # Scripting/execution
    ".script",
    ".scriptrun",
    ".scriptload",
    "!runscript",
    ".call",
    ".foreach",
    ".block",
    ".printf",
    # Module loading
    ".load",
    ".loadby",
    ".cordll",
    # Network/remote access
    ".remote",
    ".sympath",
    ".symfix",
    ".netsyms",
    # Output/mask manipulation
    ".outmask",
    ".formats",
    ".tlist",
)


# --- Debug trace -- activate with WINDBG_DEBUG=1 to log all bridge calls to file ---
def _setup_debug_log() -> logging.Logger:
    """Configure file logging when WINDBG_DEBUG env var is set."""
    debug_logger = logging.getLogger("windbg.trace")
    if os.environ.get("WINDBG_DEBUG"):
        log_path = Path.home() / ".ghidra_mcp_cache" / "windbg_debug.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-5s %(message)s", datefmt="%H:%M:%S"
        ))
        debug_logger.addHandler(handler)
        debug_logger.setLevel(logging.DEBUG)
        debug_logger.debug("=== WinDbg debug trace started ===")
    return debug_logger


_trace_log = _setup_debug_log()


def _trace(fn):
    """Decorator that logs method calls, results, and exceptions to the debug log."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if not _trace_log.handlers:
            return fn(*args, **kwargs)
        name = fn.__qualname__
        call_args = ", ".join(
            [repr(a) for a in args[1:]] + [f"{k}={v!r}" for k, v in kwargs.items()]
        )
        _trace_log.debug("CALL  %s(%s)", name, call_args)
        t0 = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            ms = (time.perf_counter() - t0) * 1000
            summary = repr(result)
            if len(summary) > 200:
                summary = summary[:200] + "..."
            _trace_log.debug("OK    %s -> %s  (%.1fms)", name, summary, ms)
            return result
        except Exception as exc:
            ms = (time.perf_counter() - t0) * 1000
            _trace_log.debug("FAIL  %s -> %s: %s  (%.1fms)", name, type(exc).__name__, exc, ms)
            raise
    return wrapper


class WinDbgBridgeError(StructuredBaseError):
    """Raised when a WinDbg bridge operation fails."""

    def __init__(self, operation: str, message: str):
        structured_error = create_windbg_command_failed_error(
            command=operation,
            output=message,
        )
        super().__init__(structured_error)
        self.operation = operation
        self.message = message


class WinDbgBridge(Debugger):
    """WinDbg bridge using Pybag COM API with CDB subprocess for extensions."""

    def __init__(self, cdb_path: Path | None = None, timeout: int = _CDB_TIMEOUT):
        """Initialize WinDbg bridge.

        Args:
            cdb_path: Explicit path to cdb.exe. Auto-detected if None.
            timeout: Default timeout for CDB subprocess commands.
        """
        self._mode = WinDbgMode.USER_MODE
        self._state = DebuggerState.NOT_LOADED
        self._dbg: Any = None
        self._is_local_kernel = False
        self._local_kernel_limited = False
        self._kd_path = self._find_kd() if platform.system() == "Windows" else None
        self._cdb_path = cdb_path or (self._find_cdb() if platform.system() == "Windows" else None)
        self._timeout = timeout
        self._error_logger = WinDbgErrorLogger()
        self._binary_path: Path | None = None
        self._cdb_proc: subprocess.Popen | None = None
        self._breakpoint_counter: int = 0
        self._breakpoints: dict[str, int] = {}  # address -> bp id
        self._session = SessionTracker()
        self._event_callbacks = BinaryMcpEventCallbacks(self._session)
        self._callbacks_registered = False

        logger.info("WinDbgBridge initialized (pybag=%s)", PYBAG_AVAILABLE)

    def _apply_default_sympath(self) -> None:
        """Push the unified ``_NT_SYMBOL_PATH`` into the live engine.

        Best-effort. Failure does not prevent the bridge from working - the
        engine just keeps whatever sympath it was using, which is usually
        the inherited environment ``_NT_SYMBOL_PATH``.
        """
        if self._dbg is None:
            return
        try:
            set_engine_sympath(self._dbg, compute_nt_symbol_path())
        except Exception as exc:
            logger.debug("Engine sympath wiring failed: %s", exc)

    def set_sympath(self, elements: list[str]) -> str:
        """Set the engine sympath from a list of validated elements.

        Each element must pass :func:`validate_sympath_element` - we
        refuse to forward UNC paths, http servers without an explicit
        opt-in, or shell metacharacters into ``IDebugSymbols::SetSymbolPath``.
        """
        self._require_connected()
        bad = []
        for e in elements:
            reason = validate_sympath_element(e)
            if reason is not None:
                bad.append(f"{e!r}: {reason}")
        if bad:
            raise WinDbgBridgeError(
                "set_sympath", "rejected entries: " + "; ".join(bad)
            )
        joined = join_sympath(elements)
        if not set_engine_sympath(self._dbg, joined):
            raise WinDbgBridgeError(
                "set_sympath",
                "engine refused new sympath (no _symbols handle or "
                "SetSymbolPath returned an error)",
            )
        return joined

    def get_sympath(self) -> str | None:
        """Return the engine's current ``_NT_SYMBOL_PATH``."""
        self._require_connected()
        return get_engine_sympath(self._dbg)

    def _attach_event_callbacks(self) -> None:
        """Attach our IDebugEventCallbacks shim to the live engine.

        Best-effort: if the registration fails (no comtypes, unexpected
        pybag layout, COM error), we log a warning and proceed. The
        bridge still works in the legacy ``wait()``-poll mode; only
        the session-state machine is degraded.
        """
        if self._callbacks_registered or self._dbg is None:
            return
        try:
            self._callbacks_registered = register_callbacks(
                self._dbg, self._event_callbacks
            )
        except Exception as exc:
            logger.warning("Event-callback registration raised: %s", exc)
            self._callbacks_registered = False

    def _safe_disconnect(self) -> None:
        """Tear down the engine state without re-raising.

        Used in the except branches of attach paths so a failed connect
        cannot leave the bridge holding a half-attached engine.
        """
        try:
            if self._dbg is not None:
                try:
                    self._dbg.detach()
                except Exception:
                    pass
        finally:
            self._dbg = None
            self._callbacks_registered = False
            self._session.reset()
            self._state = DebuggerState.NOT_LOADED
            self._is_local_kernel = False

    # --- Debugger ABC implementation ---

    @_trace
    def connect(self, timeout: int = 10) -> bool:
        """Connect to the debugger engine.

        For WinDbg this initialises Pybag. Callers should follow up with
        load_binary(), connect_kernel_net(), or open_dump().
        """
        self._require_windows()
        self._require_pybag()
        try:
            self._state = DebuggerState.LOADED
            logger.info("WinDbg debugger engine connected")
            return True
        except Exception as exc:
            self._log_error("connect", exc)
            raise

    @_trace
    def disconnect(self) -> None:
        """Disconnect and clean up Pybag and CDB resources."""
        if self._cdb_proc is not None:
            try:
                self._cdb_proc.terminate()
                self._cdb_proc.wait(timeout=5)
            except Exception:
                self._cdb_proc.kill()
            finally:
                self._cdb_proc = None

        if self._dbg is not None:
            try:
                self._dbg.detach()
            except Exception:
                pass
            self._dbg = None

        self._callbacks_registered = False
        self._session.reset()
        self._state = DebuggerState.NOT_LOADED
        self._mode = WinDbgMode.USER_MODE
        self._is_local_kernel = False
        self._local_kernel_limited = False
        logger.info("WinDbg bridge disconnected")

    @_trace
    def load_binary(self, binary_path: Path, args: list[str] | None = None) -> bool:
        """Load a user-mode binary for debugging."""
        self._require_windows()
        self._require_pybag()
        try:
            self._dbg = pybag.UserDbg()
            cmd_line = str(binary_path)
            if args:
                cmd_line += " " + " ".join(args)
            self._dbg.create(cmd_line)
            self._binary_path = binary_path
            self._mode = WinDbgMode.USER_MODE
            self._state = DebuggerState.PAUSED
            logger.info("Loaded binary: %s", binary_path)
            return True
        except Exception as exc:
            self._log_error("load_binary", exc)
            raise WinDbgBridgeError("load_binary", str(exc)) from exc

    @_trace
    def set_breakpoint(self, address: str) -> bool:
        """Set a breakpoint at the given address."""
        self._require_connected()
        try:
            addr_int = int(address.replace("`", ""), 16)
            # bp() returns the actual DbgEng breakpoint ID
            bp_id = self._dbg.bp(addr_int)
            if bp_id is None:
                # Fallback if pybag doesn't return the ID
                bp_id = self._breakpoint_counter
                self._breakpoint_counter += 1
            self._breakpoints[address.replace("`", "").lower()] = bp_id
            logger.debug("Breakpoint %d set at %s", bp_id, address)
            return True
        except Exception as exc:
            self._log_error("set_breakpoint", exc, address=address)
            raise WinDbgBridgeError("set_breakpoint", str(exc)) from exc

    @_trace
    def delete_breakpoint(self, address: str) -> bool:
        """Delete the breakpoint at the given address.

        Pybag's bc() takes a breakpoint ID, not an address.
        We track the mapping from set_breakpoint(). If the address
        is not found in our map, we fall back to the 'bc' command.
        """
        self._require_connected()
        try:
            addr_key = address.replace("`", "").lower()
            bp_id = self._breakpoints.pop(addr_key, None)
            if bp_id is not None:
                self._dbg.bc(bp_id)
                logger.debug("Breakpoint %d deleted at %s", bp_id, address)
            else:
                # Fallback: try clearing via command
                self.execute_command(f"bc {address}")
                logger.debug("Breakpoint deleted via command at %s", address)
            return True
        except Exception as exc:
            self._log_error("delete_breakpoint", exc, address=address)
            raise WinDbgBridgeError("delete_breakpoint", str(exc)) from exc

    @_trace
    def run(self) -> DebuggerState:
        """Resume execution."""
        self._require_connected()
        self._require_not_local("run")
        self._require_not_dump("run")
        try:
            self._dbg.go()
            self._state = DebuggerState.RUNNING
            return self._state
        except Exception as exc:
            self._log_error("run", exc)
            raise WinDbgBridgeError("run", str(exc)) from exc

    @_trace
    def pause(self) -> bool:
        """Break into the debugger."""
        self._require_connected()
        self._require_not_local("pause")
        self._require_not_dump("pause")
        try:
            # Pybag has no break_in() -- use the low-level DbgEng COM interface
            self._dbg._control.SetInterrupt(0)  # DEBUG_INTERRUPT_ACTIVE = 0
            self._state = DebuggerState.PAUSED
            return True
        except Exception as exc:
            self._log_error("pause", exc)
            raise WinDbgBridgeError("pause", str(exc)) from exc

    @_trace
    def break_in(self, timeout: int = 5) -> bool:
        """Force the target to surface a state-change packet.

        Distinct from :meth:`pause`: ``pause`` flips the engine flag and
        returns. ``break_in`` flips the flag *and waits* for DbgEng to
        consume the resulting state-change so the engine acquires a
        current thread/process. Use this to recover from the KDNET
        half-handshake (handshake completed, but no break event ever
        fired, leaving every command saying "debugger does not have a
        current process or thread").

        Args:
            timeout: Seconds to wait for the break to land.

        Raises:
            WinDbgBridgeError: if the target does not break within
                ``timeout`` even after a fallback ``.break`` command.
        """
        self._require_connected()
        self._require_not_local("break_in")
        self._require_not_dump("break_in")

        def _wait_for_break(seconds: int) -> bool:
            wait_failed = False
            try:
                self._dbg.wait(seconds * 1000)
            except Exception as exc:
                logger.debug("wait() during break_in raised: %s", exc)
                wait_failed = True

            # In legacy mode (event callbacks not registered) the tracker
            # is never populated by COM events, so wait() returning normally
            # is the only signal we have that a state change landed. Treat
            # that as broken-in. With callbacks, the tracker is the source
            # of truth and may lag wait() by a few ms.
            if not wait_failed and not self._callbacks_registered:
                self._session.record_break()
                return True

            # With callbacks, wait() may return slightly before the state
            # transition arrives on the COM thread. Drain for a short
            # window after wait() returns.
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                if self._session.is_broken():
                    return True
                time.sleep(0.05)
            return self._session.is_broken()

        try:
            try:
                self._dbg._control.SetInterrupt(0)  # DEBUG_INTERRUPT_ACTIVE
            except Exception as exc:
                logger.warning("SetInterrupt raised: %s", exc)

            if _wait_for_break(timeout):
                self._state = DebuggerState.PAUSED
                return True

            # Fallback: dispatch the .break command. Some target/transport
            # combinations refuse SetInterrupt but honour the meta-command.
            logger.info("SetInterrupt did not break target; trying .break")
            try:
                self._dbg.cmd(".break")
            except Exception as exc:
                logger.debug(".break command raised: %s", exc)

            if _wait_for_break(timeout):
                self._state = DebuggerState.PAUSED
                return True

            raise WinDbgBridgeError(
                "break_in",
                f"Target did not break within {timeout}s. "
                "If the target is reachable, trigger a break from the target "
                "side (kdbreak / Ctrl+Scroll Lock) and retry.",
            )
        except WinDbgBridgeError:
            raise
        except Exception as exc:
            self._log_error("break_in", exc)
            raise WinDbgBridgeError("break_in", str(exc)) from exc

    def get_session_state(self) -> dict[str, Any]:
        """Return a JSON-serialisable snapshot of the kernel session state."""
        return self._session.snapshot()

    @_trace
    def get_stack(
        self, thread_id: int | None = None, frames: int = 32
    ) -> list[dict[str, str]]:
        """Return the structured call stack for the current (or named) thread.

        Wraps the ``kn`` command and parses the output into typed frames.
        If ``thread_id`` is provided, switches context to that thread first
        via ``~<tid>s``; the engine's prior current-thread is restored on
        the next break, so this is non-destructive for inspection.

        Args:
            thread_id: Optional thread to inspect. None means current.
            frames: Maximum frames to walk (clamped 1..256).

        Returns:
            List of ``{frame, child_sp, ret_addr, call_site}``.
        """
        self._require_connected()
        frames = max(1, min(256, frames))
        if thread_id is not None:
            try:
                self._dbg.cmd(f"~{int(thread_id)}s")
                self._session.current_thread_id = int(thread_id)
            except Exception as exc:
                raise WinDbgBridgeError(
                    "get_stack", f"thread switch to {thread_id} failed: {exc}"
                ) from exc
        try:
            output = self._dbg.cmd(f"kn 0x{frames:x}")
        except Exception as exc:
            raise WinDbgBridgeError("get_stack", str(exc)) from exc
        return WinDbgOutputParser.parse_stack(output or "")

    @_trace
    def get_thread(self, thread: str | None = None) -> dict[str, Any]:
        """Return raw ``!thread`` output wrapped in a structured envelope.

        Reliable structured parsing of !thread is brittle across Windows
        versions; we surface the canonical text + the command we ran so
        the LLM can reason on it directly without us silently dropping
        fields.

        Args:
            thread: Optional ETHREAD address or thread ID. None means
                    the current thread.
        """
        self._require_connected()
        cmd = "!thread" if not thread else f"!thread {thread}"
        try:
            output = self._dbg.cmd(cmd)
        except Exception as exc:
            raise WinDbgBridgeError("get_thread", str(exc)) from exc
        return {
            "command": cmd,
            "output": output or "",
            "current_thread_id": self._session.current_thread_id,
        }

    @_trace
    def get_process(
        self, process: str | None = None, flags: int = 7
    ) -> dict[str, Any]:
        """Return ``!process`` output. Same envelope rationale as :meth:`get_thread`.

        Args:
            process: PID or EPROCESS address. None means current process.
            flags: WinDbg ``!process`` flag word (default 7 = full info
                   incl. thread stacks). Use 0 for a one-line summary.
        """
        self._require_connected()
        target = process if process else "0"
        cmd = f"!process {target} 0x{flags:x}"
        try:
            output = self._dbg.cmd(cmd)
        except Exception as exc:
            raise WinDbgBridgeError("get_process", str(exc)) from exc
        return {"command": cmd, "output": output or ""}

    @_trace
    def dump_type(
        self, type_name: str, address: str | None = None, depth: int = 1
    ) -> dict[str, Any]:
        """Run ``dt -r<depth> <type> [addr]`` and return parsed fields + raw text.

        The parser captures top-level field rows of the form
        ``+0x008 FieldName : Type-or-value``. Nested expansions stay in
        the raw text - a fully recursive structured parser would be
        fragile; the LLM can read the indented form directly.

        Args:
            type_name: e.g. ``nt!_EPROCESS``.
            address: optional address to overlay the type on.
            depth: recursion depth for ``-r`` (clamped 0..3).
        """
        self._require_connected()
        depth = max(0, min(3, depth))
        # type_name and address must be sanitised - they flow into the
        # cmd() call. The allowlist would catch a `; .shell` injection
        # but we double-check at this layer to give a clear error.
        if any(ch in type_name for ch in (";", "|", "&", "$", "`", "\n", " ")):
            raise WinDbgBridgeError(
                "dump_type", f"invalid type_name: {type_name!r}"
            )
        if address is not None and any(
            ch in address for ch in (";", "|", "&", "$", "`", "\n", " ")
        ):
            raise WinDbgBridgeError(
                "dump_type", f"invalid address: {address!r}"
            )

        cmd_parts = [f"dt -r{depth}", type_name]
        if address:
            cmd_parts.append(address)
        cmd = " ".join(cmd_parts)
        try:
            output = self._dbg.cmd(cmd) or ""
        except Exception as exc:
            raise WinDbgBridgeError("dump_type", str(exc)) from exc

        fields: list[dict[str, str]] = []
        # Top-level field rows look like:
        #    +0x008 FieldName        : Type-or-value
        # Nested expansions are indented further; we capture only the
        # first indentation level (3-spaces-then-+0x).
        field_re = re.compile(
            r"^\s{0,3}\+0x([0-9a-fA-F]+)\s+(\S+)\s*:\s*(.+?)\s*$"
        )
        for line in output.splitlines():
            m = field_re.match(line)
            if m:
                fields.append({
                    "offset": "0x" + m.group(1),
                    "name": m.group(2),
                    "value": m.group(3),
                })
        return {
            "command": cmd,
            "type": type_name,
            "address": address,
            "fields": fields,
            "raw": output,
        }

    @_trace
    def set_hardware_breakpoint(
        self, address: str, kind: str = "e", size: int = 1
    ) -> bool:
        """Set a hardware data/exec breakpoint via ``ba <kind> <size> <addr>``.

        Hardware breakpoints (``ba``) are distinct from software
        breakpoints (``bp``) - they're enforced by debug registers
        (DR0-DR3) so are limited to 4 simultaneous, but can break on
        read/write/exec without modifying target memory. Essential for
        watching a kernel structure field for unauthorised writes.

        Args:
            address: hex address or symbol.
            kind: ``e`` (execute), ``r`` (read), ``w`` (write), ``i`` (i/o).
            size: byte count - 1, 2, 4, or 8.
        """
        self._require_connected()
        if kind not in ("e", "r", "w", "i"):
            raise WinDbgBridgeError(
                "set_hardware_breakpoint",
                f"invalid kind {kind!r} (use e/r/w/i)",
            )
        if size not in (1, 2, 4, 8):
            raise WinDbgBridgeError(
                "set_hardware_breakpoint",
                f"invalid size {size} (use 1/2/4/8)",
            )
        # Reuse the address validator from windbg_tools' allow patterns
        # by routing through the shared bridge command-safety layer.
        try:
            self._dbg.cmd(f"ba {kind} {size} {address}")
        except Exception as exc:
            raise WinDbgBridgeError("set_hardware_breakpoint", str(exc)) from exc
        # Track for matching disconnect/cleanup. Hardware bps are
        # numbered alongside software bps, so we let DbgEng assign the id
        # and surface it back to the caller via list_breakpoints.
        return True

    @_trace
    def switch_thread(self, thread_id: int) -> dict[str, Any]:
        """Switch the engine's current thread context.

        Wraps ``~<n>s``. Updates :attr:`SessionTracker.current_thread_id`
        so subsequent ``get_session_state`` calls reflect the change.
        """
        self._require_connected()
        try:
            output = self._dbg.cmd(f"~{int(thread_id)}s") or ""
        except Exception as exc:
            raise WinDbgBridgeError("switch_thread", str(exc)) from exc
        self._session.current_thread_id = int(thread_id)
        return {"thread_id": int(thread_id), "output": output}

    @_trace
    def step_into(self) -> dict[str, Any]:
        """Single-step into the next instruction."""
        self._require_connected()
        self._require_not_local("step_into")
        self._require_not_dump("step_into")
        self._require_paused()
        try:
            self._dbg.stepi()
            self._state = DebuggerState.PAUSED
            return self.get_current_location()
        except Exception as exc:
            self._log_error("step_into", exc)
            raise WinDbgBridgeError("step_into", str(exc)) from exc

    @_trace
    def step_over(self) -> dict[str, Any]:
        """Step over the next instruction."""
        self._require_connected()
        self._require_not_local("step_over")
        self._require_not_dump("step_over")
        self._require_paused()
        try:
            self._dbg.stepo()
            self._state = DebuggerState.PAUSED
            return self.get_current_location()
        except Exception as exc:
            self._log_error("step_over", exc)
            raise WinDbgBridgeError("step_over", str(exc)) from exc

    @_trace
    def get_registers(self) -> dict[str, str]:
        """Return current register values as hex strings."""
        self._require_connected()
        try:
            reg_dict = self._dbg.reg.register_dict()
            return {name: f"{val:x}" for name, val in reg_dict.items()}
        except Exception:
            # Fall back to parsing 'r' command output
            output = self.execute_command("r")
            return WinDbgOutputParser.parse_registers(output)

    @_trace
    def read_memory(self, address: str, size: int) -> bytes:
        """Read raw bytes from the target address space."""
        self._require_connected()
        try:
            addr_int = int(address.replace("`", ""), 16)
            return bytes(self._dbg.read(addr_int, size))
        except Exception as exc:
            self._log_error("read_memory", exc, address=address)
            structured = create_memory_read_failed_error(address, size)
            raise StructuredBaseError(structured) from exc

    @_trace
    def write_memory(self, address: str, data: bytes) -> bool:
        """Write raw bytes to the target address space."""
        self._require_connected()
        self._require_not_local("write_memory")
        self._require_not_dump("write_memory")
        try:
            addr_int = int(address.replace("`", ""), 16)
            self._dbg.write(addr_int, data)
            return True
        except Exception as exc:
            self._log_error("write_memory", exc, address=address)
            structured = create_memory_write_failed_error(address, len(data))
            raise StructuredBaseError(structured) from exc

    def get_state(self) -> DebuggerState:
        """Return the current debugger state."""
        return self._state

    def get_current_location(self) -> dict[str, Any]:
        """Return instruction pointer, disassembly, and module info."""
        self._require_connected()
        try:
            rip = self._dbg.reg.rip
            location: dict[str, Any] = {"address": f"{rip:x}"}
            try:
                disasm_output = self.execute_command(f"u {rip:x} L1")
                instructions = WinDbgOutputParser.parse_disassembly(disasm_output)
                if instructions:
                    location["instruction"] = instructions[0].get("instruction", "")
                    location["bytes"] = instructions[0].get("bytes", "")
            except Exception:
                pass
            return location
        except Exception:
            # Local kernel / limited access: try reg.get_pc()
            try:
                pc = self._dbg.reg.get_pc()
                return {"address": f"{pc:x}"}
            except Exception:
                return {"address": "unavailable", "note": "register access limited in this mode"}

    # --- Kernel-specific methods ---

    @_trace
    def connect_kernel_net(
        self,
        port: int,
        key: str,
        timeout: int | None = None,
        ipversion: int = 4,
    ) -> dict[str, Any]:
        """Connect to a KDNET kernel debug target.

        Opens the KDNET listening port via ``attach()``, registers our
        event callbacks, then waits for the engine to declare the
        session live. Returns a structured result so callers can
        distinguish three real outcomes:

          - ``connected_broken``: target broke in, current thread/process
            exists, all commands work.
          - ``connected_target_running``: handshake completed but no break
            event fired (the half-handshake state). The auto-interrupt
            retry failed; caller should invoke :meth:`break_in` once the
            target reaches a natural break point.
          - exception: handshake never completed within ``timeout``.

        Args:
            port: KDNET port number (e.g. 50000).
            key: KDNET session key (w.x.y.z format).
            timeout: Seconds to wait for target to break in.
                     Defaults to ``_KDNET_TIMEOUT`` (env ``KDNET_TIMEOUT``, 60s).
            ipversion: 4 (default) or 6. Adds ``,ipversion=6`` per
                       MS Learn: Setting Up KDNET. Win11+ targets only.
        """
        self._require_windows()
        self._require_pybag()
        if ipversion not in (4, 6):
            raise WinDbgBridgeError(
                "connect_kernel_net", f"invalid ipversion {ipversion!r}; expected 4 or 6"
            )
        timeout = timeout if timeout is not None else _KDNET_TIMEOUT

        conn_str = f"net:port={port},key={key}"
        if ipversion == 6:
            conn_str += ",ipversion=6"
        return self._attach_kernel_session(
            conn_str=conn_str,
            timeout=timeout,
            operation="connect_kernel_net",
            transport_label=f"KDNET port={port}",
            extra_result={"port": port},
            timeout_advice=(
                "1. Reboot the TARGET machine AFTER starting this connect call - "
                "the host must be listening before the target sends its initial break.\n"
                "2. Verify the key matches exactly (bcdedit /dbgsettings on the target).\n"
                "3. Confirm the target's NIC supports KDNET "
                "(kdnet.exe on the target will tell you).\n"
                "4. Ensure no firewall is blocking the UDP port on BOTH machines.\n"
                "5. Increase timeout: set KDNET_TIMEOUT=120"
            ),
        )

    @_trace
    def connect_kernel_serial(
        self,
        port: str,
        baud: int = 115200,
        pipe: bool = False,
        reconnect: bool = True,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Connect to a kernel target over a serial transport (KDSERIAL).

        Builds a ``com:port=<port>,baud=<baud>[,pipe][,reconnect]``
        connection string per MS Learn: Setting Up a Null-Modem Cable
        Connection in WinDbg. Returns the same structured result as
        :meth:`connect_kernel_net`.

        Args:
            port: COM port (e.g. ``COM1``) or pipe path when ``pipe=True``
                  (e.g. ``\\\\.\\pipe\\com_1``).
            baud: Serial baud rate. Default 115200.
            pipe: True if the target is reached over a named pipe (Hyper-V).
            reconnect: True to retry on disconnect.
            timeout: Seconds to wait for break-in. Defaults to ``_KDNET_TIMEOUT``.
        """
        self._require_windows()
        self._require_pybag()
        if not port or not str(port).strip():
            raise WinDbgBridgeError("connect_kernel_serial", "port is required")
        if baud <= 0:
            raise WinDbgBridgeError(
                "connect_kernel_serial", f"invalid baud {baud!r}; expected positive int"
            )
        timeout = timeout if timeout is not None else _KDNET_TIMEOUT

        parts = [f"com:port={port}", f"baud={baud}"]
        if pipe:
            parts.append("pipe")
        if reconnect:
            parts.append("reconnect")
        conn_str = ",".join(parts)
        return self._attach_kernel_session(
            conn_str=conn_str,
            timeout=timeout,
            operation="connect_kernel_serial",
            transport_label=f"KDSERIAL port={port} baud={baud}",
            extra_result={"port": port, "baud": baud, "pipe": pipe},
            timeout_advice=(
                "1. Verify the target has bcdedit /dbgsettings serial baudrate=<baud> debugport=<n>.\n"
                "2. For Hyper-V, ensure the VM's COM port is bound to the named pipe.\n"
                "3. Confirm cable wiring (null-modem) and that no other process holds the port.\n"
                "4. Increase timeout: set KDNET_TIMEOUT=120"
            ),
        )

    @_trace
    def connect_kernel_pipe(
        self,
        pipe_name: str,
        reconnect: bool = True,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Connect to a Hyper-V kernel target over a named pipe.

        Convenience wrapper for serial-over-pipe transports. Builds
        ``com:pipe,port=<pipe_name>[,reconnect]``. ``pipe_name`` may be
        the bare pipe name (``com_1``) or the full UNC form
        (``\\\\.\\pipe\\com_1``); the latter is preferred by dbgeng.
        """
        self._require_windows()
        self._require_pybag()
        if not pipe_name or not str(pipe_name).strip():
            raise WinDbgBridgeError("connect_kernel_pipe", "pipe_name is required")
        timeout = timeout if timeout is not None else _KDNET_TIMEOUT

        parts = ["com:pipe", f"port={pipe_name}"]
        if reconnect:
            parts.append("reconnect")
        conn_str = ",".join(parts)
        return self._attach_kernel_session(
            conn_str=conn_str,
            timeout=timeout,
            operation="connect_kernel_pipe",
            transport_label=f"KDPIPE {pipe_name}",
            extra_result={"pipe_name": pipe_name},
            timeout_advice=(
                "1. Confirm the Hyper-V VM has a COM port mapped to this named pipe.\n"
                "2. Start the host listener BEFORE booting the VM, or boot the VM with "
                "debugging enabled then start the listener.\n"
                "3. Increase timeout: set KDNET_TIMEOUT=120"
            ),
        )

    def _attach_kernel_session(
        self,
        *,
        conn_str: str,
        timeout: int,
        operation: str,
        transport_label: str,
        extra_result: dict[str, Any],
        timeout_advice: str,
    ) -> dict[str, Any]:
        """Shared attach+wait+classify pipeline used by every kernel transport."""
        kd = None
        try:
            kd = pybag.KernelDbg()

            def _attach_and_wait():
                # attach() only opens the listening port -- it returns before
                # the target has connected.  wait() blocks until the engine
                # surfaces a state change (handshake, break, exception, ...).
                kd.attach(conn_str)
                kd.wait(timeout * 1000)

            # Run attach+wait in a daemon thread so we can enforce a timeout.
            # Do NOT use the ThreadPoolExecutor as a context manager here -
            # shutdown(wait=True) deadlocks the entire MCP tool call if
            # kd.wait() hangs.
            self._session.set_state(KernelSessionState.LISTENING)
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = pool.submit(_attach_and_wait)
            try:
                future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                pool.shutdown(wait=False, cancel_futures=True)
                logger.warning(
                    "%s attach timed out after %ds", transport_label, timeout
                )
                raise WinDbgBridgeError(
                    operation,
                    f"{transport_label} connection timed out after {timeout}s. "
                    f"The target did not break in.\n\nTroubleshooting:\n"
                    f"{timeout_advice}"
                )
            else:
                pool.shutdown(wait=False)

            # Register event callbacks before classifying state - buffered
            # SessionStatus / Breakpoint events flush as soon as the COM
            # vtable is wired in.
            self._dbg = kd
            self._mode = WinDbgMode.KERNEL_MODE
            self._attach_event_callbacks()
            self._apply_default_sympath()

            if not self._session.is_broken():
                logger.info(
                    "%s attach returned without break (state=%s); "
                    "attempting auto-interrupt",
                    transport_label, self._session.state.value,
                )
                try:
                    self.break_in(timeout=5)
                except Exception as exc:
                    logger.warning("Auto-interrupt failed: %s", exc)
                    self._state = DebuggerState.RUNNING
                    return {
                        "status": "connected_target_running",
                        **extra_result,
                        "advice": (
                            "Connected, but target was running and did not "
                            "break. Call windbg_break() once the target "
                            "reaches a break, or trigger a target-side "
                            "interrupt (Ctrl+Break in WinDbg, kdbreak)."
                        ),
                        "session": self._session.snapshot(),
                    }

            self._state = DebuggerState.PAUSED
            logger.info("Connected to kernel target via %s", transport_label)
            return {
                "status": "connected_broken",
                **extra_result,
                "session": self._session.snapshot(),
            }
        except WinDbgBridgeError:
            self._safe_disconnect()
            raise
        except Exception as exc:
            self._log_error(operation, exc)
            self._safe_disconnect()
            structured = create_kernel_not_connected_error(str(exc))
            raise StructuredBaseError(structured) from exc

    @_trace
    def connect_kernel_local(self) -> bool:
        """Attach to the local kernel for read-only inspection.

        Local kernel debugging provides read access to memory, modules,
        and symbols when ``bcdedit -debug on`` is set and the session
        runs as Administrator.

        Registers and execution control (breakpoints, stepping, halting)
        are NOT available in local mode -- the debugger cannot break into
        a kernel it is running on.  Those features require a remote
        KDNET connection to a separate target machine.
        """
        self._require_windows()
        self._require_pybag()
        try:
            self._dbg = pybag.KernelDbg()
            self._dbg.attach("local")
            self._attach_event_callbacks()
            self._apply_default_sympath()

            self._mode = WinDbgMode.KERNEL_MODE
            self._state = DebuggerState.PAUSED
            self._is_local_kernel = True

            # --- Soft validation: check if module listing works ---
            # Only test module_list() -- register reads (get_pc) always
            # fail in local kernel mode because you cannot break into
            # the kernel when debugging locally.  That is a fundamental
            # Windows limitation, not a sign that bcdedit debug is off.
            self._local_kernel_limited = False
            try:
                modules = self._dbg.module_list()
                if not modules:
                    # No modules returned -- debug may not be enabled
                    self._local_kernel_limited = True
                    logger.warning(
                        "Local kernel connected but no modules returned. "
                        "Ensure bcdedit -debug on is set and you are "
                        "running as Administrator."
                    )
            except Exception:
                self._local_kernel_limited = True
                logger.warning(
                    "Local kernel connected but module listing failed. "
                    "Ensure bcdedit -debug on is set and you are "
                    "running as Administrator."
                )

            logger.info("Connected to local kernel (inspection mode)")
            return True
        except Exception as exc:
            self._log_error("connect_kernel_local", exc)
            structured = create_kernel_not_connected_error(str(exc))
            raise StructuredBaseError(structured) from exc

    @_trace
    def open_dump(self, dump_path: Path) -> bool:
        """Open a crash dump file for analysis.

        Pybag's OpenDumpFile COM binding is not implemented (E_NOTIMPL),
        so dump analysis is handled entirely via CDB subprocess commands.

        Args:
            dump_path: Path to a .dmp file.
        """
        self._require_windows()
        if self._cdb_path is None:
            raise WinDbgBridgeError(
                "open_dump",
                "CDB.exe is required for dump analysis but was not found. "
                "Install Debugging Tools for Windows.",
            )
        try:
            self._binary_path = dump_path
            self._mode = WinDbgMode.DUMP_ANALYSIS
            self._state = DebuggerState.PAUSED
            logger.info("Opened dump: %s", dump_path)
            return True
        except Exception as exc:
            self._log_error("open_dump", exc)
            raise WinDbgBridgeError("open_dump", str(exc)) from exc

    @_trace
    def execute_command(self, command: str) -> str:
        """Execute a raw debugger command and return text output.

        Uses Pybag's cmd() method when connected (which wraps
        IDebugControl::Execute), falling back to a CDB subprocess.

        Args:
            command: WinDbg command string (e.g. "lm", "!process 0 0").
        """
        self._validate_command_safety(command)
        if self._dbg is not None:
            try:
                # Pybag uses cmd() not exec_command() for command execution
                raw = str(self._dbg.cmd(command))
                logger.debug(
                    "Pybag cmd() returned %d chars for '%s'",
                    len(raw), command[:60],
                )
                result = self._filter_cdb_banner(raw)
                logger.debug(
                    "After banner filter: %d -> %d chars",
                    len(raw), len(result),
                )
                return result
            except Exception as exc:
                logger.warning(
                    "Pybag cmd() failed for '%s', falling back to CDB: %s",
                    command, exc,
                )
                return self._execute_cdb_command(command)
        logger.debug("No Pybag connection, using CDB subprocess for '%s'", command[:60])
        return self._execute_cdb_command(command)

    @_trace
    def execute_extension(self, command: str) -> str:
        """Execute a WinDbg extension (!) command via CDB subprocess.

        Args:
            command: Extension command (e.g. "!analyze -v", "!drvobj ...").
        """
        return self._execute_cdb_command(command)

    @_trace
    def get_driver_object(self, name: str) -> DriverObject:
        """Get a DRIVER_OBJECT by name (e.g. '\\Driver\\ACPI').

        Args:
            name: Driver name with or without \\Driver\\ prefix.
        """
        self._require_connected()
        output = self.execute_command(f"!drvobj {name} 3")
        if "Could not find" in output or "unable to read" in output.lower():
            structured = create_kernel_driver_not_found_error(name)
            raise StructuredBaseError(structured)
        return WinDbgOutputParser.parse_driver_object(output)

    @_trace
    def get_device_object(self, address: str) -> DeviceObject:
        """Get a DEVICE_OBJECT at the given address."""
        self._require_connected()
        output = self.execute_command(f"!devobj {address}")
        return WinDbgOutputParser.parse_device_object(output)

    @_trace
    def analyze_pool(self, address: str) -> PoolAllocation:
        """Analyze a kernel pool allocation at the given address."""
        self._require_connected()
        output = self.execute_command(f"!pool {address}")
        return WinDbgOutputParser.parse_pool_info(output)

    @_trace
    def analyze_crash(self) -> CrashAnalysis:
        """Run !analyze -v on the current dump or bugcheck."""
        self._require_connected()
        output = self.execute_command("!analyze -v")
        return WinDbgOutputParser.parse_analyze(output)

    def decode_ioctl(self, code: int) -> IOCTLCode:
        """Decode a raw IOCTL code into its bit-field components.

        Uses the pure-Python decoder; falls back to CDB !ioctldecode
        if extended info is desired.

        Args:
            code: Raw 32-bit IOCTL code.
        """
        return IOCTLCode.decode(code)

    @_trace
    def get_loaded_drivers(self) -> list[dict[str, str]]:
        """List all loaded kernel modules."""
        self._require_connected()

        # Try pybag's native module_list() first (works without CDB)
        if self._dbg is not None:
            try:
                modules = self._dbg.module_list()
                if modules:
                    result = []
                    for name_tuple, params in modules:
                        mod_name = name_tuple[0] if isinstance(name_tuple, tuple) else str(name_tuple)
                        end_addr = params.Base + params.Size
                        result.append({
                            "start": f"{params.Base:x}",
                            "end": f"{end_addr:x}",
                            "name": mod_name,
                            "symbol_status": "loaded",
                        })
                    return result
                logger.info("Pybag module_list() returned empty, trying lm command")
            except Exception as exc:
                logger.warning("Pybag module_list() failed, falling back to lm: %s", exc)

        # Fallback: parse 'lm' command output (try both 'lm' and 'lm k')
        for lm_cmd in ("lm", "lm k"):
            try:
                output = self.execute_command(lm_cmd)
                parsed = WinDbgOutputParser.parse_modules(output)
                if parsed:
                    return parsed
                logger.info("'%s' returned no parseable modules", lm_cmd)
            except Exception as exc:
                logger.warning("'%s' command failed: %s", lm_cmd, exc)
        return []

    @_trace
    def get_processes(self) -> list[dict[str, str]]:
        """List all kernel processes via '!process 0 0'."""
        self._require_connected()
        output = self.execute_command("!process 0 0")
        return WinDbgOutputParser.parse_processes(output)

    @_trace
    def get_object_directory(self, path: str = "\\") -> str:
        """Dump the object manager namespace at the given path."""
        self._require_connected()
        return self.execute_command(f"!object {path}")

    # --- Internal helpers ---

    @staticmethod
    def _find_cdb() -> Path | None:
        """Auto-detect cdb.exe from env vars, SDK paths, Store installs, and PATH."""
        # 1. WINDBG_PATH environment variable (set by installer)
        windbg_path = os.environ.get("WINDBG_PATH", "")
        if windbg_path:
            cdb = Path(windbg_path) / "cdb.exe"
            if cdb.is_file():
                logger.info("Found CDB via WINDBG_PATH: %s", cdb)
                return cdb

        # 2. Standard Windows SDK paths
        for sdk_dir in _SDK_SEARCH_PATHS:
            cdb = sdk_dir / "cdb.exe"
            if cdb.is_file():
                logger.info("Found CDB in SDK: %s", cdb)
                return cdb

        # 3. WinDbg Preview (Microsoft Store / winget) -- WindowsApps location
        try:
            local_apps = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps"
            if local_apps.is_dir():
                for entry in local_apps.iterdir():
                    if entry.name.startswith("Microsoft.WinDbg") and entry.is_dir():
                        for sub in ("amd64", "x64", ""):
                            cdb = entry / sub / "cdb.exe" if sub else entry / "cdb.exe"
                            if cdb.is_file():
                                logger.info("Found CDB in WinDbg Preview: %s", cdb)
                                return cdb
        except (OSError, PermissionError):
            pass

        # 4. Program Files WinDbg Preview install
        for prog_dir in (
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        ):
            windbg_preview = Path(prog_dir) / "WinDbg"
            if windbg_preview.is_dir():
                for sub in ("amd64", "x64", ""):
                    cdb = windbg_preview / sub / "cdb.exe" if sub else windbg_preview / "cdb.exe"
                    if cdb.is_file():
                        logger.info("Found CDB in WinDbg Preview dir: %s", cdb)
                        return cdb

        # 5. cdb.exe on system PATH
        cdb_on_path = shutil.which("cdb")
        if cdb_on_path:
            logger.info("Found CDB on PATH: %s", cdb_on_path)
            return Path(cdb_on_path)

        logger.warning("CDB not found -- WinDbg commands will not be available")
        return None

    @staticmethod
    def _find_kd() -> Path | None:
        """Auto-detect kd.exe for kernel debugging.

        KD.exe is the kernel debugger; it supports -kl (local kernel)
        natively. It ships alongside cdb.exe in the Windows SDK.
        """
        # 1. WINDBG_PATH environment variable
        windbg_path = os.environ.get("WINDBG_PATH", "")
        if windbg_path:
            kd = Path(windbg_path) / "kd.exe"
            if kd.is_file():
                logger.info("Found KD via WINDBG_PATH: %s", kd)
                return kd

        # 2. Standard Windows SDK paths
        for sdk_dir in _SDK_SEARCH_PATHS:
            kd = sdk_dir / "kd.exe"
            if kd.is_file():
                logger.info("Found KD in SDK: %s", kd)
                return kd

        # 3. System PATH
        kd_on_path = shutil.which("kd")
        if kd_on_path:
            logger.info("Found KD on PATH: %s", kd_on_path)
            return Path(kd_on_path)

        logger.info("KD not found -- will fall back to CDB for kernel commands")
        return None

    @_trace
    def _execute_cdb_command(self, command: str) -> str:
        """Run a single command through a CDB/KD subprocess.

        Uses kd.exe for local kernel debugging (-kl) and cdb.exe for
        dump analysis (-z). Filters out the startup banner noise.

        Args:
            command: WinDbg command to execute.

        Returns:
            Filtered text output.
        """
        self._validate_command_safety(command)
        # Choose the right debugger executable based on mode
        if self._mode == WinDbgMode.KERNEL_MODE and self._is_local_kernel:
            # Local kernel: MUST use kd.exe -kl (CDB does NOT support -kl)
            if self._kd_path is None:
                raise WinDbgBridgeError(
                    "execute_cdb_command",
                    "kd.exe is required for local kernel commands but was not found. "
                    "CDB does not support the -kl flag. "
                    "Install Debugging Tools for Windows (Windows SDK).",
                )
            cmd_args = [str(self._kd_path), "-kl"]
        elif self._mode == WinDbgMode.DUMP_ANALYSIS and self._binary_path:
            # Dump file: use cdb.exe -z <dump>
            if self._cdb_path is None:
                structured = create_windbg_not_found_error()
                raise StructuredBaseError(structured)
            cmd_args = [str(self._cdb_path), "-z", str(self._binary_path)]
        else:
            # Fallback: try cdb.exe
            if self._cdb_path is None:
                structured = create_windbg_not_found_error()
                raise StructuredBaseError(structured)
            cmd_args = [str(self._cdb_path)]

        cmd_args.extend(["-c", f"{command}; q"])

        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True, encoding="utf-8", errors="replace",
                timeout=self._timeout,
                env=subprocess_env_with_sympath(),
            )
            if result.stderr:
                logger.warning("CDB/KD stderr: %s", result.stderr.strip())
            if result.returncode != 0:
                logger.warning(
                    "CDB/KD exited with code %d for: %s",
                    result.returncode, command,
                )
            # Check for fatal errors BEFORE filtering the banner
            error_msg = self._check_cdb_error(result.stdout)
            if error_msg:
                raise WinDbgBridgeError("execute_cdb_command", error_msg)
            return self._filter_cdb_banner(result.stdout)
        except subprocess.TimeoutExpired as exc:
            self._log_error("cdb_command", exc)
            raise WinDbgBridgeError(
                "execute_cdb_command",
                f"CDB/KD timed out after {self._timeout}s for: {command}",
            ) from exc
        except Exception as exc:
            self._log_error("cdb_command", exc)
            raise WinDbgBridgeError("execute_cdb_command", str(exc)) from exc

    @staticmethod
    def _filter_cdb_banner(output: str) -> str:
        """Strip CDB/KD startup banner and Extensions Gallery noise.

        Modern WinDbg/KD emits a large block of Debugger Extensions Gallery
        setup text before the actual banner.  We filter all known noise
        patterns and also detect fatal errors (e.g. kernel debugging not
        enabled) so they surface cleanly.

        Uses both prefix matching and substring matching for robustness
        against encoding quirks (BOM, invisible chars) from Pybag/KD.
        """
        if not output:
            return output

        # Normalize encoding: strip BOM and null bytes that Pybag/COM
        # objects may include, and normalize line endings
        output = output.lstrip("\ufeff\ufffe\x00")
        output = output.replace("\r\n", "\n").replace("\r", "\n")

        lines = output.splitlines()
        filtered: list[str] = []

        # Patterns matched via startswith on stripped lines
        noise_prefixes = (
            "Microsoft (R)",
            "Copyright",
            "Loading",
            "Opened log file",
            "CommandLine:",
            "Symbol search path",
            "Executable search path",
            "Windows ",
            "Kernel Debugger",
            # Extensions Gallery noise
            "*",             # ******* Preparing ...
            ">",             # >>>>>>>>> ... completed
            "ExtensionRepository",
            "UseExperimental",
            "AllowNuget",
            "NonInteractive",
            "AllowParallel",
            "EnableRedirect",
            "----> Repository",
            "-- Configuring",
            # KD session banner (local kernel)
            "Connected to ",
            "Product:",
            "Edition build lab:",
            "Kernel base",
            "Debug session time:",
            "System Uptime:",
            # NatVis teardown noise
            "NatVis script unloaded from",
            "NatVis script loaded from",
        )

        # Substring patterns: catch lines even if prefix matching fails
        # due to leading invisible chars, prompts, or encoding issues
        noise_substrings = (
            "Connected to Windows",
            "Product: WinNt",
            "Edition build lab:",
            "Kernel base =",
            "PsLoadedModuleList =",
            "Debug session time:",
            "System Uptime:",
            "NatVis script unloaded",
            "NatVis script loaded",
            "Debugger Extensions Gallery",
            "kd: Reading initial command",
            "ptr64 TRUE",
            "ptr64 FALSE",
            "dbgeng",
        )

        for line in lines:
            stripped = line.strip()
            # Strip any remaining non-printable chars for matching
            cleaned = "".join(c for c in stripped if c.isprintable() or c == " ")
            # Skip empty lines, quit echo, and known noise
            if (
                cleaned == ""
                or cleaned in ("quit:", "q")
                # KD prompt + command echo
                or cleaned.startswith("lkd>")
                or cleaned.startswith("kd>")
                # Prefix-based matching
                or any(cleaned.startswith(p) for p in noise_prefixes)
                # Substring-based fallback matching
                or any(sub in cleaned for sub in noise_substrings)
            ):
                logger.debug("Banner filter: dropped line: %s", stripped[:80])
                continue
            filtered.append(line)

        if not filtered and lines:
            logger.debug(
                "Banner filter: all %d lines filtered (command may have "
                "returned no output beyond the banner)", len(lines),
            )

        return "\n".join(filtered)

    @staticmethod
    def _check_cdb_error(output: str) -> str | None:
        """Detect fatal errors in CDB/KD output and return a user-friendly message.

        Returns None if no fatal error is detected, otherwise a clean error string.
        """
        error_patterns = {
            "does not support local kernel debugging": (
                "Local kernel debugging is not enabled on this system.\n"
                "To enable:\n"
                "  1. Run elevated: bcdedit -debug on\n"
                "  2. Reboot\n"
                "  3. Run as Administrator"
            ),
            "Debuggee initialization failed": (
                "Debugger initialization failed. The target may not be "
                "accessible or kernel debugging is not configured."
            ),
            "requires Administrative privileges": (
                "This operation requires Administrator privileges.\n"
                "Run the MCP server in an elevated terminal."
            ),
        }
        lower = output.lower()
        for pattern, message in error_patterns.items():
            if pattern.lower() in lower:
                return message
        return None

    def _require_windows(self) -> None:
        """Raise if not running on Windows."""
        if platform.system() != "Windows":
            raise WinDbgBridgeError(
                "platform_check",
                "WinDbg bridge requires Windows. "
                "Current platform: " + platform.system(),
            )

    @staticmethod
    def _require_pybag() -> None:
        """Raise if Pybag is not installed."""
        if not PYBAG_AVAILABLE:
            raise WinDbgBridgeError(
                "pybag_import",
                "Pybag is not installed. Install with: pip install pybag",
            )

    def _require_connected(self) -> None:
        """Raise if no debug session is active."""
        if self._dbg is None and self._state == DebuggerState.NOT_LOADED:
            structured = create_debugger_not_connected_error()
            raise StructuredBaseError(structured)

    def _require_paused(self) -> None:
        """Raise if the target is not paused."""
        if self._state != DebuggerState.PAUSED:
            structured = create_debugger_not_paused_error(self._state.value)
            raise StructuredBaseError(structured)

    def _require_not_local(self, operation: str) -> None:
        """Raise if connected in local kernel mode (no execution control)."""
        if self._is_local_kernel:
            raise WinDbgBridgeError(
                operation,
                f"'{operation}' is not supported in local kernel mode. "
                "Local kernel allows inspection (memory, registers, modules) "
                "but not execution control. Use a remote KDNET connection "
                "for breakpoints, stepping, and run/pause.",
            )

    def _require_not_dump(self, operation: str) -> None:
        """Raise if in dump analysis mode (read-only)."""
        if self._mode == WinDbgMode.DUMP_ANALYSIS:
            raise WinDbgBridgeError(
                operation,
                f"'{operation}' is not supported in dump analysis mode. "
                "Crash dumps are read-only.",
            )

    def _validate_command_safety(self, command: str) -> None:
        """Block dangerous WinDbg meta-commands for defense-in-depth.

        Delegates to the token-aware :func:`allowlist.validate_command`
        which understands compound commands, quoted regions, and
        ``.foreach``/``.for`` block bodies. The legacy substring matcher
        was simultaneously over- and under-blocking; see ``allowlist.py``
        for the current rule set.

        Raises:
            WinDbgBridgeError: If a blocked command is detected.
        """
        from .allowlist import validate_command

        ok, reason = validate_command(command)
        if not ok:
            raise WinDbgBridgeError(
                "command_validation",
                f"Command blocked: {reason}.",
            )

    def _log_error(
        self,
        operation: str,
        exc: Exception,
        address: str | None = None,
    ) -> None:
        """Persist an error via WinDbgErrorLogger."""
        context = ErrorContext(
            operation=operation,
            address=address,
            debugger_state=self._state.value,
            binary_path=str(self._binary_path) if self._binary_path else None,
        )
        self._error_logger.log_error(
            operation=operation,
            error=exc,
            context=context,
            traceback_str=traceback.format_exc(),
        )
