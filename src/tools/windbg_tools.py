"""
WinDbg kernel debugging MCP tools.

Provides kernel-mode analysis capabilities through WinDbg/Pybag integration.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
import re

from fastmcp import FastMCP

from src.engines.dynamic.windbg.bridge import WinDbgBridge, WinDbgBridgeError
from src.engines.dynamic.windbg.commands import WinDbgCommands
from src.engines.session import AnalysisType, UnifiedSessionManager
from src.utils.structured_errors import StructuredBaseError

logger = logging.getLogger(__name__)

# Session manager reference (set during registration)
_session_manager: UnifiedSessionManager | None = None

# Global WinDbg instances (initialized on first use)
_windbg_bridge: WinDbgBridge | None = None
_windbg_commands: WinDbgCommands | None = None

_PLATFORM_MSG = (
    "WinDbg tools require Windows with Pybag installed.\n"
    "Install with: pip install binary-mcp[windbg]"
)


def _is_windows() -> bool:
    return platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Input validation helpers for command-injection prevention
# ---------------------------------------------------------------------------

_SAFE_ADDRESS_RE = re.compile(r'^[0-9a-fA-F`x]+$')  # Hex addresses with optional backticks and 0x prefix
_SAFE_SYMBOL_RE = re.compile(r'^[a-zA-Z0-9_!.*+:]+$')  # Symbol names like nt!NtCreateFile or module!*
_SAFE_CONDITION_RE = re.compile(r'^[a-zA-Z0-9_!=<>&|+\-*/()@$.\s,]+$')  # WinDbg expressions


def _validate_address(address: str) -> str:
    """Validate address is a hex value or symbol name, not an injection payload."""
    addr = address.strip()
    if not addr:
        return "Error: Address cannot be empty."
    if _SAFE_ADDRESS_RE.match(addr) or _SAFE_SYMBOL_RE.match(addr):
        return ""  # Valid
    return f"Error: Invalid address format '{addr}'. Use hex (e.g. 0x401000) or symbol (e.g. nt!NtCreateFile)."


def _validate_condition(condition: str) -> str:
    """Validate breakpoint condition expression."""
    cond = condition.strip()
    if not cond:
        return "Error: Condition cannot be empty."
    if len(cond) > 200:
        return "Error: Condition too long (max 200 characters)."
    if not _SAFE_CONDITION_RE.match(cond):
        return "Error: Invalid condition expression. Only comparison expressions are allowed (e.g. 'rcx==0x100')."
    # Extra check for dangerous commands that might slip through
    cond_lower = cond.lower()
    for blocked in ('.shell', '.create', '.script', '!runscript', '.writemem'):
        if blocked in cond_lower:
            return f"Error: Condition contains blocked command '{blocked}'."
    return ""  # Valid


def get_windbg_bridge() -> WinDbgBridge:
    """Get or create the WinDbg bridge singleton."""
    global _windbg_bridge
    if _windbg_bridge is None:
        timeout = int(os.environ.get("WINDBG_TIMEOUT", "30"))
        _windbg_bridge = WinDbgBridge(timeout=timeout)
    return _windbg_bridge


def get_windbg_commands() -> WinDbgCommands:
    """Get or create the WinDbg commands wrapper."""
    global _windbg_commands
    if _windbg_commands is None:
        _windbg_commands = WinDbgCommands(get_windbg_bridge())
    return _windbg_commands


def log_windbg_tool(func):
    """Decorator to log WinDbg tool calls to the active session."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if _session_manager and _session_manager.active_session_id:
            _session_manager.log_tool_call(
                tool_name=func.__name__,
                arguments=kwargs,
                output=result,
                analysis_type=AnalysisType.KERNEL,
            )
        return result
    return wrapper


def register_windbg_tools(
    app: FastMCP, session_manager: UnifiedSessionManager | None = None
) -> None:
    """Register all WinDbg kernel debugging tools with the MCP server.

    Args:
        app: FastMCP server instance.
        session_manager: Optional session manager for logging tool calls.
    """
    global _session_manager
    _session_manager = session_manager

    # ------------------------------------------------------------------
    # Connection tools (4)
    # ------------------------------------------------------------------

    @app.tool()
    @log_windbg_tool
    def windbg_status() -> str:
        """Get WinDbg debugger status.

        Returns the current debugger state, mode (user/kernel/dump), target
        binary or dump path, and current instruction pointer.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            commands = get_windbg_commands()
            return commands.get_status_summary()
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_connect_kernel(port: int = 50000, key: str = "") -> str:
        """Connect to a kernel debug target via KDNET.

        Args:
            port: KDNET port number (default 50000).
            key: KDNET session key in w.x.y.z format.

        Returns:
            Connection status message.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            if key:
                bridge.connect_kernel_net(port=port, key=key)
                return f"Connected to kernel target via KDNET (port={port})"
            else:
                bridge.connect_kernel_local()
                return "Connected to local kernel (read-only)"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return (
                f"Error: {e}\n\nTroubleshooting:\n"
                "1. Ensure target is configured for kernel debugging\n"
                "2. Verify KDNET port and key are correct\n"
                "3. Check network connectivity to the target"
            )

    @app.tool()
    @log_windbg_tool
    def windbg_open_dump(dump_path: str) -> str:
        """Open a Windows crash dump file for analysis.

        Args:
            dump_path: Path to a .dmp crash dump file.

        Returns:
            Status message with dump info.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            from pathlib import Path

            bridge = get_windbg_bridge()
            bridge.open_dump(Path(dump_path))
            return f"Opened crash dump: {dump_path}\nMode: dump_analysis"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error opening dump: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_disconnect() -> str:
        """Disconnect from the current WinDbg session.

        Cleans up Pybag connections and CDB subprocesses.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            bridge.disconnect()
            global _windbg_bridge, _windbg_commands
            _windbg_bridge = None
            _windbg_commands = None
            return "Disconnected from WinDbg"
        except Exception as e:
            return f"Error: {e}"

    # ------------------------------------------------------------------
    # Execution tools (6)
    # ------------------------------------------------------------------

    @app.tool()
    @log_windbg_tool
    def windbg_run() -> str:
        """Resume execution in the debugger.

        Execution continues until a breakpoint, exception, or target termination.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            state = bridge.run()
            return f"Execution resumed. State: {state.value}"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_pause() -> str:
        """Break into the debugger, pausing execution."""
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            bridge.pause()
            return "Execution paused"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_step_into() -> str:
        """Single-step into the next instruction.

        Returns the new instruction pointer and disassembly.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            loc = bridge.step_into()
            parts = [f"Address: 0x{loc.get('address', '?')}"]
            if loc.get("instruction"):
                parts.append(f"Instruction: {loc['instruction']}")
            return "\n".join(parts)
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_step_over() -> str:
        """Step over the next instruction (skip into calls).

        Returns the new instruction pointer and disassembly.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            loc = bridge.step_over()
            parts = [f"Address: 0x{loc.get('address', '?')}"]
            if loc.get("instruction"):
                parts.append(f"Instruction: {loc['instruction']}")
            return "\n".join(parts)
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_run_and_wait(timeout: int = 30) -> str:
        """Resume execution and wait for the target to break.

        Args:
            timeout: Maximum seconds to wait for a break event.

        Returns:
            Status after break or timeout.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            from src.engines.dynamic.base import DebuggerState
            from src.engines.dynamic.windbg.kernel_types import WinDbgMode

            bridge = get_windbg_bridge()
            bridge.run()
            # Live kernel targets require INFINITE timeout per MS docs
            wait_ms = 0xFFFFFFFF if bridge._mode == WinDbgMode.KERNEL_MODE else timeout * 1000
            try:
                bridge._dbg.wait(wait_ms)
                bridge._state = DebuggerState.PAUSED
                loc = bridge.get_current_location()
                return f"Break at 0x{loc.get('address', '?')}"
            except Exception:
                return f"Timeout after {timeout}s — target still running"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_wait_paused(timeout: int = 30) -> str:
        """Wait for the target to reach a paused state.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            Current location when paused, or timeout message.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            from src.engines.dynamic.base import DebuggerState
            from src.engines.dynamic.windbg.kernel_types import WinDbgMode

            bridge = get_windbg_bridge()
            # Live kernel targets require INFINITE timeout per MS docs
            wait_ms = 0xFFFFFFFF if bridge._mode == WinDbgMode.KERNEL_MODE else timeout * 1000
            try:
                bridge._dbg.wait(wait_ms)
                bridge._state = DebuggerState.PAUSED
                loc = bridge.get_current_location()
                return f"Paused at 0x{loc.get('address', '?')}"
            except Exception:
                return f"Timeout after {timeout}s — target not paused"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    # ------------------------------------------------------------------
    # Breakpoint tools (4)
    # ------------------------------------------------------------------

    @app.tool()
    @log_windbg_tool
    def windbg_set_breakpoint(address: str) -> str:
        """Set a software breakpoint at the given address.

        Args:
            address: Hex address or symbol (e.g. "0x401000" or "nt!NtCreateFile").
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        try:
            bridge = get_windbg_bridge()
            bridge.set_breakpoint(address)
            return f"Breakpoint set at {address}"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_delete_breakpoint(address: str) -> str:
        """Delete a breakpoint at the given address.

        Args:
            address: Hex address of the breakpoint to remove.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        try:
            bridge = get_windbg_bridge()
            bridge.delete_breakpoint(address)
            return f"Breakpoint deleted at {address}"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_list_breakpoints() -> str:
        """List all active breakpoints.

        Returns:
            Formatted list of breakpoints from 'bl' command output.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            output = bridge.execute_command("bl")
            return output or "No breakpoints set"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_set_conditional_breakpoint(address: str, condition: str) -> str:
        """Set a conditional breakpoint using a WinDbg expression.

        Args:
            address: Hex address for the breakpoint.
            condition: WinDbg condition expression (e.g. "rcx==0x100").
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        cond_err = _validate_condition(condition)
        if cond_err:
            return cond_err
        try:
            bridge = get_windbg_bridge()
            cmd = f'bp {address} ".if ({condition}) {{}} .else {{gc}}"'
            bridge.execute_command(cmd)
            return f"Conditional breakpoint set at {address} when {condition}"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    # ------------------------------------------------------------------
    # Inspection tools (6)
    # ------------------------------------------------------------------

    @app.tool()
    @log_windbg_tool
    def windbg_get_registers() -> str:
        """Get current CPU register values.

        Returns:
            Formatted register dump with general-purpose and extended registers.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            commands = get_windbg_commands()
            return commands.dump_registers()
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_read_memory(address: str, size: int = 64) -> str:
        """Read memory from the target address space.

        Args:
            address: Hex address to read from.
            size: Number of bytes to read (default 64, max 4096).

        Returns:
            Hex dump of memory contents.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        try:
            size = min(size, 4096)
            bridge = get_windbg_bridge()
            # Strip backtick separators (WinDbg uses fffff800`12340000 format)
            clean_addr = address.replace("`", "")
            data = bridge.read_memory(clean_addr, size)
            base_addr = int(clean_addr, 16)
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hex_part = " ".join(f"{b:02x}" for b in chunk)
                ascii_part = "".join(
                    chr(b) if 32 <= b < 127 else "." for b in chunk
                )
                lines.append(f"{base_addr + i:016x}  {hex_part:<48}  {ascii_part}")
            return "\n".join(lines)
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_write_memory(address: str, data: str) -> str:
        """Write hex bytes to the target address space.

        Args:
            address: Hex address to write to.
            data: Hex string of bytes to write (e.g. "90 90 cc").

        Returns:
            Confirmation of bytes written.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        try:
            raw = bytes.fromhex(data.replace(" ", ""))
            bridge = get_windbg_bridge()
            bridge.write_memory(address, raw)
            return f"Wrote {len(raw)} bytes to {address}"
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_disassemble(address: str, count: int = 10) -> str:
        """Disassemble instructions at the given address.

        Args:
            address: Hex address to start disassembly.
            count: Number of instructions to disassemble (default 10).

        Returns:
            Disassembly listing.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        addr_err = _validate_address(address)
        if addr_err:
            return addr_err
        try:
            bridge = get_windbg_bridge()
            output = bridge.execute_command(f"u {address} L{count}")
            return output
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_get_modules() -> str:
        """List all loaded modules.

        Returns:
            Module list with base addresses, sizes, and symbol status.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        try:
            bridge = get_windbg_bridge()
            modules = bridge.get_loaded_drivers()
            if not modules:
                return "No modules loaded"
            lines = [f"{'Start':<20} {'End':<20} {'Name':<20} {'Symbols'}"]
            lines.append("-" * 80)
            for mod in modules:
                lines.append(
                    f"{mod['start']:<20} {mod['end']:<20} "
                    f"{mod['name']:<20} {mod['symbol_status']}"
                )
            return "\n".join(lines)
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"

    @app.tool()
    @log_windbg_tool
    def windbg_execute_command(command: str) -> str:
        """Execute a raw WinDbg command.

        Supports both regular commands (lm, r, k) and extension commands
        (!analyze, !process, !drvobj). Use this for any WinDbg command not
        covered by the dedicated tools.

        Args:
            command: WinDbg command string.

        Returns:
            Raw command output text.
        """
        if not _is_windows():
            return _PLATFORM_MSG
        # Tool-layer blocklist for dangerous WinDbg meta-commands
        cmd_lower = command.strip().lower()
        from src.engines.dynamic.windbg.bridge import _BLOCKED_COMMANDS
        for blocked in _BLOCKED_COMMANDS:
            if blocked in cmd_lower:
                return f"Error: Command '{blocked}' is blocked for security reasons."
        try:
            bridge = get_windbg_bridge()
            return bridge.execute_command(command)
        except (WinDbgBridgeError, StructuredBaseError) as e:
            return f"Error: {e}"
