"""
WinDbg bridge client via Pybag (DbgEng COM API).

Provides kernel-mode and user-mode debugging through the Windows Debugger Engine
COM interfaces, with a CDB subprocess fallback for extension (!) commands.
"""

from __future__ import annotations

import logging
import platform
import subprocess
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
from .kernel_types import (
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
    WinDbgMode,
)
from .output_parser import WinDbgOutputParser

logger = logging.getLogger(__name__)

# Conditional Pybag import — only available on Windows with Pybag installed
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
        self._cdb_path = cdb_path or self._find_cdb()
        self._cdb_proc: subprocess.Popen[str] | None = None
        self._timeout = timeout
        self._error_logger = WinDbgErrorLogger()
        self._binary_path: Path | None = None

        logger.info("WinDbgBridge initialized (pybag=%s)", PYBAG_AVAILABLE)

    # ------------------------------------------------------------------
    # Debugger ABC implementation
    # ------------------------------------------------------------------

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

        self._state = DebuggerState.NOT_LOADED
        self._mode = WinDbgMode.USER_MODE
        self._is_local_kernel = False
        logger.info("WinDbg bridge disconnected")

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

    def set_breakpoint(self, address: str) -> bool:
        """Set a breakpoint at the given address."""
        self._require_connected()
        try:
            addr_int = int(address.replace("`", ""), 16)
            self._dbg.bp(addr_int)
            logger.debug("Breakpoint set at %s", address)
            return True
        except Exception as exc:
            self._log_error("set_breakpoint", exc, address=address)
            raise WinDbgBridgeError("set_breakpoint", str(exc)) from exc

    def delete_breakpoint(self, address: str) -> bool:
        """Delete the breakpoint at the given address."""
        self._require_connected()
        try:
            addr_int = int(address.replace("`", ""), 16)
            self._dbg.bc(addr_int)
            logger.debug("Breakpoint deleted at %s", address)
            return True
        except Exception as exc:
            self._log_error("delete_breakpoint", exc, address=address)
            raise WinDbgBridgeError("delete_breakpoint", str(exc)) from exc

    def run(self) -> DebuggerState:
        """Resume execution."""
        self._require_connected()
        try:
            self._dbg.go()
            self._state = DebuggerState.RUNNING
            return self._state
        except Exception as exc:
            self._log_error("run", exc)
            raise WinDbgBridgeError("run", str(exc)) from exc

    def pause(self) -> bool:
        """Break into the debugger."""
        self._require_connected()
        try:
            self._dbg.break_in()
            self._state = DebuggerState.PAUSED
            return True
        except Exception as exc:
            self._log_error("pause", exc)
            raise WinDbgBridgeError("pause", str(exc)) from exc

    def step_into(self) -> dict[str, Any]:
        """Single-step into the next instruction."""
        self._require_connected()
        self._require_paused()
        try:
            self._dbg.step_into()
            self._state = DebuggerState.PAUSED
            return self.get_current_location()
        except Exception as exc:
            self._log_error("step_into", exc)
            raise WinDbgBridgeError("step_into", str(exc)) from exc

    def step_over(self) -> dict[str, Any]:
        """Step over the next instruction."""
        self._require_connected()
        self._require_paused()
        try:
            self._dbg.step_over()
            self._state = DebuggerState.PAUSED
            return self.get_current_location()
        except Exception as exc:
            self._log_error("step_over", exc)
            raise WinDbgBridgeError("step_over", str(exc)) from exc

    def get_registers(self) -> dict[str, str]:
        """Return current register values as hex strings."""
        self._require_connected()
        try:
            regs = self._dbg.regs
            return {name: f"{val:x}" for name, val in regs.items()}
        except Exception as exc:
            self._log_error("get_registers", exc)
            raise WinDbgBridgeError("get_registers", str(exc)) from exc

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

    def write_memory(self, address: str, data: bytes) -> bool:
        """Write raw bytes to the target address space."""
        self._require_connected()
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
        except Exception as exc:
            self._log_error("get_current_location", exc)
            raise WinDbgBridgeError("get_current_location", str(exc)) from exc

    # ------------------------------------------------------------------
    # Kernel-specific methods
    # ------------------------------------------------------------------

    def connect_kernel_net(self, port: int, key: str) -> bool:
        """Connect to a KDNET kernel debug target.

        Args:
            port: KDNET port number (e.g. 50000).
            key: KDNET session key (w.x.y.z format).
        """
        self._require_windows()
        self._require_pybag()
        try:
            conn_str = f"net:port={port},key={key}"
            self._dbg = pybag.KernelDbg()
            self._dbg.attach(conn_str)
            self._mode = WinDbgMode.KERNEL_MODE
            self._state = DebuggerState.PAUSED
            logger.info("Connected to kernel target via KDNET port=%d", port)
            return True
        except Exception as exc:
            self._log_error("connect_kernel_net", exc)
            structured = create_kernel_not_connected_error(str(exc))
            raise StructuredBaseError(structured) from exc

    def connect_kernel_local(self) -> bool:
        """Attach to the local kernel in read-only mode."""
        self._require_windows()
        self._require_pybag()
        try:
            self._dbg = pybag.KernelDbg()
            self._dbg.attach("local")
            self._mode = WinDbgMode.KERNEL_MODE
            self._state = DebuggerState.PAUSED
            self._is_local_kernel = True
            logger.info("Connected to local kernel (read-only)")
            return True
        except Exception as exc:
            self._log_error("connect_kernel_local", exc)
            structured = create_kernel_not_connected_error(str(exc))
            raise StructuredBaseError(structured) from exc

    def open_dump(self, dump_path: Path) -> bool:
        """Open a crash dump file for analysis.

        Args:
            dump_path: Path to a .dmp file.
        """
        self._require_windows()
        self._require_pybag()
        try:
            self._dbg = pybag.DbgEng()
            self._dbg.open_dump(str(dump_path))
            self._binary_path = dump_path
            self._mode = WinDbgMode.DUMP_ANALYSIS
            self._state = DebuggerState.PAUSED
            logger.info("Opened dump: %s", dump_path)
            return True
        except Exception as exc:
            self._log_error("open_dump", exc)
            raise WinDbgBridgeError("open_dump", str(exc)) from exc

    def execute_command(self, command: str) -> str:
        """Execute a raw debugger command and return text output.

        Uses Pybag's exec_command when connected, otherwise falls back to CDB.
        Local kernel connections always use CDB since pybag's local mode
        does not support exec_command.

        Args:
            command: WinDbg command string (e.g. "lm", "!process 0 0").
        """
        # Local kernel mode: pybag doesn't support exec_command, use CDB
        if self._is_local_kernel:
            return self._execute_cdb_command(command)

        if self._dbg is not None:
            try:
                return str(self._dbg.exec_command(command))
            except Exception as exc:
                # Fall back to CDB if pybag exec_command fails
                logger.warning(
                    "Pybag exec_command failed for '%s', falling back to CDB: %s",
                    command, exc,
                )
                return self._execute_cdb_command(command)
        return self._execute_cdb_command(command)

    def execute_extension(self, command: str) -> str:
        """Execute a WinDbg extension (!) command via CDB subprocess.

        Args:
            command: Extension command (e.g. "!analyze -v", "!drvobj ...").
        """
        return self._execute_cdb_command(command)

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

    def get_device_object(self, address: str) -> DeviceObject:
        """Get a DEVICE_OBJECT at the given address."""
        self._require_connected()
        output = self.execute_command(f"!devobj {address}")
        return WinDbgOutputParser.parse_device_object(output)

    def analyze_pool(self, address: str) -> PoolAllocation:
        """Analyze a kernel pool allocation at the given address."""
        self._require_connected()
        output = self.execute_command(f"!pool {address}")
        return WinDbgOutputParser.parse_pool_info(output)

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

    def get_loaded_drivers(self) -> list[dict[str, str]]:
        """List all loaded kernel modules via 'lm k'."""
        self._require_connected()
        output = self.execute_command("lm k")
        return WinDbgOutputParser.parse_modules(output)

    def get_processes(self) -> list[dict[str, str]]:
        """List all kernel processes via '!process 0 0'."""
        self._require_connected()
        output = self.execute_command("!process 0 0")
        return WinDbgOutputParser.parse_processes(output)

    def get_object_directory(self, path: str = "\\") -> str:
        """Dump the object manager namespace at the given path."""
        self._require_connected()
        return self.execute_command(f"!object {path}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_cdb() -> Path | None:
        """Auto-detect cdb.exe from common Windows SDK paths."""
        for sdk_dir in _SDK_SEARCH_PATHS:
            cdb = sdk_dir / "cdb.exe"
            if cdb.is_file():
                logger.info("Found CDB: %s", cdb)
                return cdb
        return None

    def _execute_cdb_command(self, command: str) -> str:
        """Run a single command through a CDB subprocess.

        Args:
            command: WinDbg command to execute.

        Returns:
            Raw text output from CDB.
        """
        if self._cdb_path is None:
            structured = create_windbg_not_found_error()
            raise StructuredBaseError(structured)

        cdb_args = [str(self._cdb_path), "-z"]
        if self._binary_path:
            cdb_args.append(str(self._binary_path))
        else:
            cdb_args.append("-kl")  # local kernel

        cdb_args.extend(["-c", f"{command}; q"])

        try:
            result = subprocess.run(
                cdb_args,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            return result.stdout
        except subprocess.TimeoutExpired as exc:
            self._log_error("cdb_command", exc)
            raise WinDbgBridgeError(
                "execute_cdb_command",
                f"CDB timed out after {self._timeout}s for: {command}",
            ) from exc
        except Exception as exc:
            self._log_error("cdb_command", exc)
            raise WinDbgBridgeError("execute_cdb_command", str(exc)) from exc

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
