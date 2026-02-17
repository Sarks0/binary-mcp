"""
WinDbg bridge client via Pybag (DbgEng COM API).

Provides kernel-mode and user-mode debugging through the Windows Debugger Engine
COM interfaces, with a CDB subprocess fallback for extension (!) commands.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
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


# ---------------------------------------------------------------------------
# Debug trace — activate with WINDBG_DEBUG=1 to log all bridge calls to file
# ---------------------------------------------------------------------------
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

        logger.info("WinDbgBridge initialized (pybag=%s)", PYBAG_AVAILABLE)

    # ------------------------------------------------------------------
    # Debugger ABC implementation
    # ------------------------------------------------------------------

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
            # Pybag has no break_in() — use the low-level DbgEng COM interface
            self._dbg._control.SetInterrupt(0)  # DEBUG_INTERRUPT_ACTIVE = 0
            self._state = DebuggerState.PAUSED
            return True
        except Exception as exc:
            self._log_error("pause", exc)
            raise WinDbgBridgeError("pause", str(exc)) from exc

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

    # ------------------------------------------------------------------
    # Kernel-specific methods
    # ------------------------------------------------------------------

    @_trace
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

    @_trace
    def connect_kernel_local(self) -> bool:
        """Attach to the local kernel for inspection.

        Local kernel debugging provides full read access to memory,
        registers, modules, and symbols when ``bcdedit -debug on`` is
        set and the session runs as Administrator.  Execution control
        (breakpoints, stepping, halting) is not available — that
        requires a remote KDNET connection to a separate target.

        Pybag's KernelDbg.attach("local") can partially succeed even
        without ``bcdedit -debug on``.  We allow the connection and
        log a warning if data access appears limited, rather than
        rejecting the session outright.
        """
        self._require_windows()
        self._require_pybag()
        try:
            self._dbg = pybag.KernelDbg()
            self._dbg.attach("local")

            self._mode = WinDbgMode.KERNEL_MODE
            self._state = DebuggerState.PAUSED
            self._is_local_kernel = True

            # --- Soft validation: warn if data access is limited ---
            self._local_kernel_limited = False
            try:
                modules = self._dbg.module_list()
                if not modules:
                    self._dbg.reg.get_pc()
            except Exception:
                self._local_kernel_limited = True
                logger.warning(
                    "Local kernel connected but data access is limited. "
                    "For full access: bcdedit -debug on, reboot, run as Admin."
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
        if self._dbg is not None:
            try:
                # Pybag uses cmd() not exec_command() for command execution
                return str(self._dbg.cmd(command))
            except Exception as exc:
                logger.warning(
                    "Pybag cmd() failed for '%s', falling back to CDB: %s",
                    command, exc,
                )
                return self._execute_cdb_command(command)
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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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

        # 3. WinDbg Preview (Microsoft Store / winget) — WindowsApps location
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

        logger.warning("CDB not found — WinDbg commands will not be available")
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

        logger.info("KD not found — will fall back to CDB for kernel commands")
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
                text=True,
                timeout=self._timeout,
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
        """
        if not output:
            return output

        lines = output.splitlines()
        filtered: list[str] = []

        # Patterns that are always noise (anywhere in output)
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

        for line in lines:
            stripped = line.strip()
            # Skip empty lines, quit echo, and known noise
            if (
                stripped == ""
                or stripped in ("quit:", "q")
                or "dbgeng" in stripped.lower()
                or "Debugger Extensions Gallery" in stripped
                # KD prompt + command echo: "lkd> kd: Reading initial command '...'"
                or stripped.startswith("lkd>")
                or stripped.startswith("kd>")
                or "kd: Reading initial command" in stripped
                or any(stripped.startswith(p) for p in noise_prefixes)
            ):
                continue
            filtered.append(line)

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
