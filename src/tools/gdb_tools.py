"""
GDB/MI Linux debugging MCP tools.

The tool layer over ``src/engines/dynamic/gdb``: it owns argument validation,
path confinement, output fencing and error hygiene, and leaves every MI detail
to :class:`~src.engines.dynamic.gdb.bridge.GdbBridge`.

Linux only, and deliberately not macOS. The engine drives a real
``gdb --interpreter=mi2`` and macOS GDB needs a codesigning entitlement to
ptrace anything at all, so a macOS user would reach a hardening or attach
failure rather than a working debugger. Claiming support we cannot test is
worse than naming the gap, so the platform message says Linux and points
elsewhere on every other OS.

Audit F-7: every tool that returns text derived from the debugged process
fences it through :func:`_fence`. On this engine that is a wider surface than
it first looks -- a hexdump's ASCII column, a disassembly operand, a breakpoint
row's function and file, a shared-library path out of the target's own link
map, and all console output -- because each of those is rendered from bytes the
sample controls. ``gdb_resolve_static_address`` is the one exception and says so
at its return.

Audit F-10: no handler returns ``f"...{e}"``. Failures go through
``error_hygiene.safe_tool_error``, which keeps the curated half of a structured
error and logs the rest against a reference ID. ``GdbBridgeError`` routinely
carries GDB's own diagnostic text, which quotes the sample path and the
server's working directory, so this is not a formality here.
"""

from __future__ import annotations

import functools
import logging
import os
import platform
from pathlib import Path

from fastmcp import FastMCP

from src.engines.dynamic.base import DebuggerState
from src.engines.dynamic.gdb.bridge import GdbBridge, GdbBridgeError
from src.engines.dynamic.gdb.mi_session import MISessionError
from src.engines.session import AnalysisType, UnifiedSessionManager
from src.tools.error_hygiene import safe_path_error, safe_tool_error
from src.utils.formatters import wrap_untrusted
from src.utils.security import (
    FileSizeError,
    PathTraversalError,
    sanitize_binary_path,
)
from src.utils.structured_errors import StructuredBaseError

logger = logging.getLogger(__name__)

_session_manager: UnifiedSessionManager | None = None

# The bridge is a singleton because a GDB session is stateful: breakpoint
# numbers, the cached register-name list and the resolved PIE load base all
# live on it, and a second bridge would silently debug a different inferior.
_gdb_bridge: GdbBridge | None = None

_PLATFORM_MSG = (
    "GDB tools require Linux.\n"
    "On Windows use the x64dbg tools for user-mode debugging, or the WinDbg "
    "tools for kernel debugging. macOS is not supported: its GDB cannot "
    "ptrace without a codesigning entitlement."
)

# Raised by the engine for every expected failure. MISessionError is in the
# tuple because constructing the bridge resolves the GDB executable, so "gdb is
# not installed" surfaces from the getter rather than from a command.
_ENGINE_ERRORS = (GdbBridgeError, MISessionError, StructuredBaseError)

_MAX_WRITE_BYTES = 4096


def _fence(text: str, kind: str) -> str:
    """Fence output rendered from the debugged process (audit F-7).

    Empty output is returned unchanged, because an empty envelope is noise
    that still costs the model a paragraph of reading.
    """
    if not text or not text.strip():
        return text
    return wrap_untrusted(text, kind=kind)


def _is_linux() -> bool:
    return platform.system() == "Linux"


def get_gdb_bridge() -> GdbBridge:
    """Get or create the GDB bridge singleton.

    May raise ``MISessionError`` if no GDB executable can be found, which is
    why every call site is already inside a handler.
    """
    global _gdb_bridge
    if _gdb_bridge is None:
        _gdb_bridge = GdbBridge()
    return _gdb_bridge


def reset_gdb_bridge() -> None:
    """Drop the singleton, stopping its GDB if one is running.

    Used by ``gdb_disconnect`` and by tests. Failure to stop is logged and
    swallowed: the point is that the next getter builds a fresh bridge, and a
    GDB that cannot be stopped must not make that impossible.
    """
    global _gdb_bridge
    bridge = _gdb_bridge
    _gdb_bridge = None
    if bridge is not None:
        try:
            bridge.disconnect()
        except Exception as exc:
            logger.warning("Could not stop the GDB session cleanly", exc_info=exc)


def log_gdb_tool(func):
    """Log GDB tool calls to the active session as dynamic analysis.

    The analysis type is passed explicitly rather than left to
    ``UnifiedSessionManager.log_tool_call``, whose fallback infers the type
    from an ``x64dbg_`` name prefix and would file every GDB call as static.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        if _session_manager and _session_manager.active_session_id:
            _session_manager.log_tool_call(
                tool_name=func.__name__,
                arguments=kwargs,
                output=result,
                analysis_type=AnalysisType.DYNAMIC,
            )
        return result
    return wrapper


def _format_location(location: dict) -> str:
    """Render a bridge location dict, fencing the sample-derived half.

    ``state`` and ``stop_reason`` are GDB's own vocabulary and stay outside the
    envelope; the function name, source file and next instruction are rendered
    from the binary's symbols and code, so they go inside it.
    """
    header = [f"State: {location.get('state', 'unknown')}"]
    if location.get("stop_reason"):
        header.append(f"Stop reason: {location['stop_reason']}")
    if location.get("address"):
        header.append(f"Address: {location['address']}")

    body = []
    for label, key in (("Function", "function"), ("File", "file"), ("Line", "line")):
        if location.get(key):
            body.append(f"{label}: {location[key]}")
    if location.get("instruction"):
        body.append(f"Next instruction: {location['instruction']}")

    if not body:
        return "\n".join(header)
    return "\n".join(header) + "\n" + _fence(
        "\n".join(body), kind="symbol and instruction text from the debugged process"
    )


def _hexdump(data: bytes, base: int) -> str:
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + offset:016x}: {hex_str:<47}  {ascii_str}")
    return "\n".join(lines)


def register_gdb_tools(
    app: FastMCP, session_manager: UnifiedSessionManager | None = None
) -> None:
    """Register the GDB Linux debugging tools with the MCP server.

    Registration is unconditional, matching ``register_windbg_tools``: the
    roster an integrator sees must not depend on the host OS, or a cached tool
    list taken on one platform would be wrong on another. Each handler refuses
    at call time instead.

    Args:
        app: FastMCP server instance.
        session_manager: Optional session manager for logging tool calls.
    """
    global _session_manager
    _session_manager = session_manager

    # Session lifecycle (5)

    @app.tool()
    @log_gdb_tool
    def gdb_status() -> str:
        """Get GDB engine status.

        Reports whether a GDB session exists, the debugger state, and -- when
        the target is stopped -- where it is stopped and what it will execute
        next.

        Safe to call first: it does not start GDB, so it answers even when no
        GDB is installed.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        if _gdb_bridge is None:
            return (
                "No GDB session. Use gdb_load_binary to debug a file, or "
                "gdb_attach to attach to a running process."
            )
        try:
            bridge = _gdb_bridge
            state = bridge.get_state()
            if state in (DebuggerState.PAUSED, DebuggerState.RUNNING):
                return _format_location(bridge.get_current_location())
            return f"State: {state.value}"
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_status", e)

    @app.tool()
    @log_gdb_tool
    def gdb_load_binary(binary_path: str, args: list[str] | None = None) -> str:
        """Load an ELF binary into a new GDB session without running it.

        Loading is inert on purpose. GDB with no breakpoints and a bare run
        command executes a sample to completion, so this tool only loads
        symbols and records arguments; use gdb_run to start execution, which
        stops at the entry point by default.

        The path is confined to the configured sample directories before GDB
        is told about it.

        Args:
            binary_path: Path to the ELF binary, inside an allowed directory.
            args: Optional argv for the target.

        Returns:
            Confirmation with the loaded file's name.

        Example:
            gdb_load_binary("/samples/mal.elf", ["--verbose"])
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            # Confinement first, before the path reaches GDB or the ELF reader.
            # The engine's link-base read opens the file, so a check after the
            # fact would already have followed a traversal.
            safe = sanitize_binary_path(binary_path)
        except (PathTraversalError, FileSizeError, FileNotFoundError, ValueError) as e:
            return safe_path_error("gdb_load_binary", e, "binary path")

        try:
            bridge = get_gdb_bridge()
            if not bridge.is_connected():
                bridge.connect()
            bridge.load_binary(Path(safe), args)
            # os.path.basename, not the resolved path: audit F-10 forbids
            # echoing a path the server resolved on the caller's behalf.
            return (
                f"Loaded {os.path.basename(str(safe))}. Set breakpoints, then "
                f"gdb_run to start at the entry point."
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_load_binary", e)

    @app.tool()
    @log_gdb_tool
    def gdb_attach(pid: int) -> str:
        """Attach to a running Linux process.

        Checks the kernel's Yama ptrace_scope first and explains it if it
        blocks the attach, because GDB's own error for that case does not say
        what is wrong.

        Args:
            pid: Process ID to attach to.

        Returns:
            Where the process is stopped after the attach.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            bridge = get_gdb_bridge()
            if not bridge.is_connected():
                bridge.connect()
            bridge.attach(pid)
            return _format_location(bridge.get_current_location())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_attach", e)

    @app.tool()
    @log_gdb_tool
    def gdb_detach() -> str:
        """Detach from the attached process, leaving it running.

        The GDB session stays up and can load or attach again.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            get_gdb_bridge().detach()
            return "Detached. The process continues running."
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_detach", e)

    @app.tool()
    @log_gdb_tool
    def gdb_disconnect() -> str:
        """End the GDB session and reap the subprocess.

        Breakpoints and the resolved load base are session state and do not
        survive this. A target still being debugged is killed with the
        session, so detach first if it should outlive the debugger.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        reset_gdb_bridge()
        return "GDB session ended."

    # Execution control (6)

    @app.tool()
    @log_gdb_tool
    def gdb_run(stop_at: str = "entry") -> str:
        """Start the loaded target.

        Args:
            stop_at: Where to stop. "entry" (default) stops before any user
                code runs, which is the only safe default for a malware
                sample. "main" stops at main, skipping the dynamic loader and
                any ELF constructors -- note that constructors are a common
                place for a sample to act early. "none" lets the sample run
                free, supervised only by whatever breakpoints are already set.

        Returns:
            Where the target stopped, or a note that it is running.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            bridge = get_gdb_bridge()
            state = bridge.run(stop_at=stop_at)
            if state is DebuggerState.RUNNING:
                return (
                    "Target is running unsupervised. Use gdb_pause to "
                    "interrupt it."
                )
            return _format_location(bridge.get_current_location())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_run", e)

    @app.tool()
    @log_gdb_tool
    def gdb_continue() -> str:
        """Resume a stopped target and wait for the next stop.

        Returns when the target hits a breakpoint, takes a signal or exits.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            bridge = get_gdb_bridge()
            if bridge.get_state() is not DebuggerState.PAUSED:
                return (
                    "The target is not stopped, so there is nothing to "
                    "resume. Use gdb_run to start it, or gdb_status to see "
                    "the current state."
                )
            bridge.run()
            return _format_location(bridge.get_current_location())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_continue", e)

    @app.tool()
    @log_gdb_tool
    def gdb_pause() -> str:
        """Interrupt a running target.

        Works while the inferior is running because the session enables MI
        async mode at startup.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            bridge = get_gdb_bridge()
            bridge.pause()
            return _format_location(bridge.get_current_location())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_pause", e)

    @app.tool()
    @log_gdb_tool
    def gdb_step_into() -> str:
        """Execute one instruction, entering calls."""
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            return _format_location(get_gdb_bridge().step_into())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_step_into", e)

    @app.tool()
    @log_gdb_tool
    def gdb_step_over() -> str:
        """Execute one instruction, stepping over calls."""
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            return _format_location(get_gdb_bridge().step_over())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_step_over", e)

    @app.tool()
    @log_gdb_tool
    def gdb_step_out() -> str:
        """Run until the current function returns."""
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            return _format_location(get_gdb_bridge().step_out())
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_step_out", e)

    # Breakpoints (3)

    @app.tool()
    @log_gdb_tool
    def gdb_set_breakpoint(address: str) -> str:
        """Set a breakpoint at a runtime address.

        The address must be a runtime address, not a link-time one from static
        analysis. For a PIE binary the two differ by the load base; use
        gdb_resolve_static_address to convert.

        Args:
            address: Hex runtime address, e.g. "0x401236".

        Returns:
            Confirmation, or the reason GDB refused.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            get_gdb_bridge().set_breakpoint(address)
            return f"Breakpoint set at {address}."
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_set_breakpoint", e)

    @app.tool()
    @log_gdb_tool
    def gdb_delete_breakpoint(address: str) -> str:
        """Delete a breakpoint previously set at an address.

        Only addresses set through gdb_set_breakpoint in this session can be
        deleted, because MI deletes by breakpoint number and the number is
        what this engine records. The deletion is read back afterwards: GDB
        answers the delete-by-address form with success and deletes nothing.

        Args:
            address: The address passed to gdb_set_breakpoint.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            get_gdb_bridge().delete_breakpoint(address)
            return f"Breakpoint at {address} deleted."
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_delete_breakpoint", e)

    @app.tool()
    @log_gdb_tool
    def gdb_list_breakpoints() -> str:
        """List every breakpoint GDB currently holds.

        Includes breakpoints this session did not set, which is how a stale
        .gdbinit or an earlier attach shows up.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            found = get_gdb_bridge().list_breakpoints()
            if not found:
                return "No breakpoints set."
            rows = []
            for bkpt in found:
                parts = [f"#{bkpt.get('number', '?')}"]
                for key in ("type", "disp", "enabled", "addr", "func", "file", "line"):
                    if bkpt.get(key):
                        parts.append(f"{key}={bkpt[key]}")
                if bkpt.get("times"):
                    parts.append(f"hits={bkpt['times']}")
                rows.append(" ".join(parts))
            # func/file/line are the binary's own symbol text.
            return f"{len(found)} breakpoint(s):\n" + _fence(
                "\n".join(rows), kind="breakpoint symbols from the debugged binary"
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_list_breakpoints", e)

    # Target state (7)

    @app.tool()
    @log_gdb_tool
    def gdb_get_registers() -> str:
        """Read the target's registers.

        Returns every register GDB reports for the architecture, in hex.
        On x86-64 the SysV argument order is RDI, RSI, RDX, RCX, R8, R9 --
        not the Windows order the x64dbg tools document.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            registers = get_gdb_bridge().get_registers()
            if not registers:
                return "No registers reported. Is the target running?"
            rows = [f"{name}={value}" for name, value in registers.items()]
            return _fence(
                "\n".join(rows), kind="register values from the debugged process"
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_get_registers", e)

    @app.tool()
    @log_gdb_tool
    def gdb_read_memory(address: str, size: int = 256) -> str:
        """Read memory from the debugged process as a hexdump.

        Args:
            address: Hex runtime address, e.g. "0x401000".
            size: Bytes to read, up to the engine's read limit.

        Returns:
            A hexdump with an ASCII column.

        Example:
            gdb_read_memory("0x401000", 64)
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            bridge = get_gdb_bridge()
            data = bridge.read_memory(address, size)
            header = f"Memory at {address} ({len(data)} bytes read):"
            # The ASCII column is the most direct sample-authored channel in
            # this module: a decrypted buffer holding instruction-shaped text
            # reaches the model looking like tool output unless it is fenced.
            return header + "\n" + _fence(
                _hexdump(data, int(address, 16)),
                kind="raw memory read from the debugged process",
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_read_memory", e)

    @app.tool()
    @log_gdb_tool
    def gdb_write_memory(address: str, data: str) -> str:
        """Write bytes into the debugged process.

        The write is read back and compared before this reports success,
        because GDB acknowledges a write to unwritable memory.

        Args:
            address: Hex runtime address, e.g. "0x401000".
            data: Bytes as a hex string, e.g. "9090c3". Whitespace and a
                leading 0x are accepted.

        Returns:
            Confirmation of how many bytes were written and verified.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        cleaned = "".join(data.split())
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if not cleaned:
            return "Error: No bytes to write."
        if len(cleaned) % 2:
            return "Error: Hex data must have an even number of digits."
        try:
            payload = bytes.fromhex(cleaned)
        except ValueError:
            return "Error: Data is not valid hex. Use a form like '9090c3'."
        if len(payload) > _MAX_WRITE_BYTES:
            return (
                f"Error: Refusing to write {len(payload)} bytes; the limit is "
                f"{_MAX_WRITE_BYTES}."
            )
        try:
            get_gdb_bridge().write_memory(address, payload)
            return f"Wrote and verified {len(payload)} byte(s) at {address}."
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_write_memory", e)

    @app.tool()
    @log_gdb_tool
    def gdb_disassemble(address: str, count: int = 20) -> str:
        """Disassemble instructions at a runtime address.

        Args:
            address: Hex runtime address, e.g. "0x401000".
            count: Instructions to disassemble (default 20).

        Returns:
            A disassembly listing.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            instructions = get_gdb_bridge().disassemble(address, count)
            if not instructions:
                return f"No instructions returned for {address}."
            rows = []
            for instr in instructions:
                addr = instr.get("address", "")
                offset = instr.get("offset", "")
                func = instr.get("func-name", "")
                text = instr.get("inst", "")
                label = f"<{func}+{offset}>" if func else ""
                rows.append(f"{addr} {label} {text}".strip())
            # Operands carry symbol names and GDB's rendering of referenced
            # data, so attacker-controlled bytes reach the model here.
            return f"Disassembly at {address}:\n" + _fence(
                "\n".join(rows), kind="disassembly of the debugged process"
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_disassemble", e)

    @app.tool()
    @log_gdb_tool
    def gdb_get_modules() -> str:
        """List the shared objects loaded into the target.

        Reports each object's runtime range, which is what makes an address
        seen in a register or on the stack attributable to a library.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            modules = get_gdb_bridge().get_modules()
            if not modules:
                return (
                    "No shared libraries reported. A static binary has none, "
                    "and a dynamic one has none until the loader has run."
                )
            rows = []
            for mod in modules:
                from_addr = mod.get("from", "?")
                to_addr = mod.get("to", "?")
                name = mod.get("target-name") or mod.get("host-name") or "?"
                read = mod.get("symbols-loaded")
                suffix = " (symbols loaded)" if read in ("1", 1, True) else ""
                rows.append(f"{from_addr}-{to_addr} {name}{suffix}")
            # Paths come out of the target's own link map, which a sample can
            # populate with whatever it chooses to dlopen.
            return f"{len(modules)} shared object(s):\n" + _fence(
                "\n".join(rows), kind="module paths from the debugged process"
            )
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_get_modules", e)

    @app.tool()
    @log_gdb_tool
    def gdb_resolve_static_address(static_address: str) -> str:
        """Convert a link-time address from static analysis to a runtime one.

        Ghidra reports addresses as linked. For a PIE binary -- the default for
        years on every mainstream Linux toolchain -- the running process is
        mapped somewhere else entirely, so a Ghidra address set as a breakpoint
        verbatim lands on unrelated code or nothing at all. This applies
        runtime = static - link_base + load_base. For a non-PIE ET_EXEC the two
        bases are equal and the result is the input.

        The target must be started for the load base to exist: a PIE binary has
        no load base until it is mapped.

        Args:
            static_address: Hex link-time address, e.g. "0x1136".

        Returns:
            The runtime address, ready for gdb_set_breakpoint.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            runtime = get_gdb_bridge().resolve_static_address(static_address)
            # Not fenced: the result is this server's own arithmetic over two
            # integers, and carries no text from the target.
            return f"{static_address} (static) maps to {runtime} (runtime)."
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_resolve_static_address", e)

    @app.tool()
    @log_gdb_tool
    def gdb_execute_console(command: str) -> str:
        """Run a read-only GDB console command through the allowlist.

        GDB's console is a programming language, not a command set: `shell`
        and `!` spawn a shell, `python` runs arbitrary code, and `print` and
        `x` evaluate expressions in which `$_shell("...")` is a function call.
        So this is an allowlist, not a filter, and anything unrecognised is
        refused rather than sanitized. No expression-evaluating command is
        admitted, which is why `print`, `x`, `call` and `set` are absent.

        Permitted: backtrace, bt, where, frame, thread, list, show, version,
        and `info` with one of its read-only subcommands (registers,
        all-registers, locals, args, frame, stack, threads, breakpoints,
        proc, sharedlibrary, functions, variables, types, sources, target,
        signals, handle, inferiors, program, scope, display, watchpoints,
        architecture, files, source, terminal, auto-load).

        Args:
            command: The console command, e.g. "info proc mappings".

        Returns:
            The command's console output.
        """
        if not _is_linux():
            return _PLATFORM_MSG
        try:
            output = get_gdb_bridge().execute_console(command)
            if not output.strip():
                return "Command produced no output."
            return _fence(output, kind="GDB console output for the debugged process")
        except _ENGINE_ERRORS as e:
            return safe_tool_error("gdb_execute_console", e)
