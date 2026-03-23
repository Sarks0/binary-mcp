"""
Dynamic analysis MCP tools using x64dbg.

Provides debugger-based analysis capabilities with session logging.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import time
from pathlib import Path

from fastmcp import FastMCP

from src.engines.dynamic.x64dbg.bridge import (
    X64DbgBridge,
)
from src.engines.dynamic.x64dbg.commands import X64DbgCommands
from src.engines.session import AnalysisType, UnifiedSessionManager
from src.engines.static.ghidra.project_cache import ProjectCache
from src.utils.security import (
    PathTraversalError,
    safe_error_message,
    sanitize_output_path,
    validate_state_id,
)
from src.utils.structured_errors import StructuredBaseError

logger = logging.getLogger(__name__)

# Session manager reference (set during registration)
_session_manager: UnifiedSessionManager | None = None

# Global x64dbg instances (initialized on first use)
_x64dbg_bridge: X64DbgBridge | None = None
_x64dbg_commands: X64DbgCommands | None = None

# Global Ghidra project cache (for static/dynamic cross-reference)
_ghidra_cache: ProjectCache | None = None

# Track the binary being debugged (for session correlation)
_current_debug_binary: str | None = None

# Cache for function mappings (binary_path -> {function_name -> static_address})
_function_mappings: dict[str, dict[str, dict]] = {}

# Security: Allowed output directory for memory/module dumps
DUMP_OUTPUT_DIR = Path.home() / ".binary_mcp_output" / "dumps"

# Security: Maximum size for memory dumps (100MB) to prevent memory exhaustion
MAX_DUMP_SIZE = 100 * 1024 * 1024


def _format_log_template(bridge, template: str) -> str:
    """
    Format a log template by substituting register values.

    Supports format specifiers:
    - {reg} or {reg:hex} - hex value
    - {reg:dec} - decimal value
    - {reg:str} - dereference as string pointer
    - {reg:ptr} - dereference as pointer

    Args:
        bridge: X64DbgBridge instance
        template: Template string with {register:format} placeholders

    Returns:
        Formatted string with register values substituted
    """
    try:
        # Get current registers
        registers = bridge.get_registers()

        # Pattern to match {register:format} or {register}
        pattern = r'\{(\w+)(?::(\w+))?\}'

        def replace_match(match):
            reg_name = match.group(1).lower()
            format_spec = match.group(2) or "hex"

            # Get register value
            reg_value = None
            for key in [reg_name, reg_name.upper(), f"r{reg_name}", f"R{reg_name}"]:
                if key in registers:
                    reg_value = registers[key]
                    break

            if reg_value is None:
                # Try to evaluate as expression
                try:
                    result = bridge.evaluate_expression(reg_name)
                    if result.get("valid"):
                        reg_value = result.get("value", "0")
                except Exception:
                    return f"<{reg_name}:unknown>"

            # Parse value if string
            if isinstance(reg_value, str):
                try:
                    if reg_value.startswith("0x"):
                        int_value = int(reg_value, 16)
                    else:
                        int_value = int(reg_value)
                except ValueError:
                    int_value = 0
            else:
                int_value = reg_value

            # Format based on specifier
            if format_spec == "dec":
                return str(int_value)
            elif format_spec == "str":
                # Try to read as string pointer
                try:
                    # Read up to 256 bytes and find null terminator
                    mem = bridge.read_memory(f"0x{int_value:X}", 256)
                    if mem:
                        # Try UTF-16 first (common for Windows APIs)
                        try:
                            null_pos = mem.find(b'\x00\x00')
                            if null_pos > 0 and null_pos < 100:
                                decoded = mem[:null_pos+1].decode('utf-16-le', errors='replace')
                                if decoded and len(decoded) > 1:
                                    return f'"{decoded.rstrip(chr(0))}"'
                        except Exception:
                            pass
                        # Fall back to ASCII
                        null_pos = mem.find(b'\x00')
                        if null_pos > 0:
                            return f'"{mem[:null_pos].decode("ascii", errors="replace")}"'
                    return f"0x{int_value:X}"
                except Exception:
                    return f"0x{int_value:X}"
            elif format_spec == "ptr":
                # Dereference as pointer
                try:
                    mem = bridge.read_memory(f"0x{int_value:X}", 8)
                    if mem:
                        ptr_value = int.from_bytes(mem[:8], 'little')
                        return f"0x{ptr_value:X}"
                    return f"0x{int_value:X}"
                except Exception:
                    return f"0x{int_value:X}"
            else:  # hex (default)
                return f"0x{int_value:X}"

        return re.sub(pattern, replace_match, template)

    except Exception as e:
        return f"<format error: {e}>"


def _convert_log_template_to_x64dbg(template: str) -> str:
    """
    Convert Python-style log template to x64dbg format.

    Python format: {register:format}
    x64dbg format: {format:register}

    Format mapping:
        Python      -> x64dbg
        {rcx}       -> {x:rcx}      (hex, default)
        {rcx:hex}   -> {x:rcx}
        {rcx:dec}   -> {d:rcx}
        {rcx:unicode} -> {s:rcx}    (UTF-16 string)
        {rcx:str}   -> {s:rcx}      (UTF-16 string)
        {rcx:ascii} -> {a:rcx}      (ASCII string)
        {rcx:ptr}   -> {p:rcx}      (pointer dereference)

    Args:
        template: Python-style log template

    Returns:
        x64dbg-style log template
    """
    # Format mapping from Python style to x64dbg style
    format_map = {
        "hex": "x",
        "dec": "d",
        "unicode": "s",
        "str": "s",
        "ascii": "a",
        "ptr": "p",
    }

    # Pattern to match {register:format} or {register}
    pattern = r'\{(\w+)(?::(\w+))?\}'

    def convert_match(match):
        reg_name = match.group(1).lower()
        format_spec = match.group(2) or "hex"

        # Convert format specifier
        x64dbg_format = format_map.get(format_spec.lower(), "x")

        return f"{{{x64dbg_format}:{reg_name}}}"

    return re.sub(pattern, convert_match, template)


def _check_inline_hook(
    first_bytes: bytes,
    func_addr: int,
    mod_base: int,
    mod_size: int,
    func_name: str,
    module_name: str
) -> dict | None:
    """
    Check if function entry bytes indicate an inline hook.

    Looks for JMP (E9, FF 25) or CALL (E8) instructions that redirect
    to addresses outside the module.

    Args:
        first_bytes: First bytes of the function
        func_addr: Function address
        mod_base: Module base address
        mod_size: Module size
        func_name: Function name for reporting
        module_name: Module name for reporting

    Returns:
        Hook info dict if hook detected, None otherwise
    """
    if len(first_bytes) < 5:
        return None

    redirect_to = None
    hook_type = None

    # Check for relative JMP (E9 xx xx xx xx)
    if first_bytes[0] == 0xE9:
        # Calculate target: next_addr + offset
        offset = int.from_bytes(first_bytes[1:5], 'little', signed=True)
        next_addr = func_addr + 5
        redirect_to = next_addr + offset
        hook_type = "inline_jmp"

    # Check for relative CALL (E8 xx xx xx xx)
    elif first_bytes[0] == 0xE8:
        offset = int.from_bytes(first_bytes[1:5], 'little', signed=True)
        next_addr = func_addr + 5
        redirect_to = next_addr + offset
        hook_type = "inline_call"

    # Check for absolute JMP via memory (FF 25 xx xx xx xx) - 6 bytes for 32-bit
    elif len(first_bytes) >= 6 and first_bytes[0] == 0xFF and first_bytes[1] == 0x25:
        # This is RIP-relative in x64
        offset = int.from_bytes(first_bytes[2:6], 'little', signed=True)
        next_addr = func_addr + 6
        ptr_addr = next_addr + offset
        # Would need to read the pointer at ptr_addr to get actual target
        # For now, just flag it as suspicious
        redirect_to = ptr_addr  # This is the pointer location, not final target
        hook_type = "inline_jmp_indirect"

    # Check for push + ret pattern (68 xx xx xx xx C3) - 6 bytes
    elif len(first_bytes) >= 6 and first_bytes[0] == 0x68 and first_bytes[5] == 0xC3:
        redirect_to = int.from_bytes(first_bytes[1:5], 'little')
        hook_type = "push_ret"

    # Check for mov rax + jmp rax pattern (48 B8 ... FF E0) - 12 bytes for 64-bit
    elif len(first_bytes) >= 12 and first_bytes[0] == 0x48 and first_bytes[1] == 0xB8:
        # mov rax, imm64
        redirect_to = int.from_bytes(first_bytes[2:10], 'little')
        # Check if followed by jmp rax (FF E0)
        if first_bytes[10] == 0xFF and first_bytes[11] == 0xE0:
            hook_type = "mov_jmp"

    if redirect_to is None:
        return None

    # Check if redirect is outside the module
    mod_end = mod_base + mod_size
    if mod_base <= redirect_to < mod_end:
        # Redirect is within module - probably not a hook
        # (could be normal code flow)
        return None

    # Looks like a hook
    return {
        "type": hook_type,
        "function": func_name,
        "module": module_name,
        "address": func_addr,
        "redirect_to": redirect_to,
        "original_bytes": "unknown",
        "hooked_bytes": first_bytes[:12].hex().upper()
    }


def format_structured_error(error: StructuredBaseError) -> str:
    """
    Format a structured error for MCP tool output.

    Provides rich, actionable error messages with suggestions for users.

    Args:
        error: A StructuredBaseError (includes AddressValidationError, X64DbgAPIError)

    Returns:
        Formatted error string suitable for tool output
    """
    return error.structured_error.to_user_message()


def format_error_response(
    error: Exception,
    operation: str = "",
    include_json: bool = False,
) -> str:
    """
    Format any error for MCP tool output.

    Handles both structured errors and generic exceptions.

    Args:
        error: The exception to format
        operation: Optional operation name for context
        include_json: If True, include JSON representation at the end

    Returns:
        Formatted error string
    """
    if isinstance(error, StructuredBaseError):
        message = format_structured_error(error)
        if include_json:
            message += f"\n\n--- JSON ---\n{error.to_json()}"
        return message
    else:
        # Legacy error format for non-structured errors
        return f"Error: {error}"


def log_dynamic_tool(func):
    """
    Decorator to log dynamic tool calls to the active session.

    Automatically logs tool name, arguments, and output for dynamic analysis tools.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)

        # Log to session if available
        if _session_manager and _session_manager.active_session_id:
            _session_manager.log_tool_call(
                tool_name=func.__name__,
                arguments=kwargs,
                output=result,
                analysis_type=AnalysisType.DYNAMIC
            )

        return result

    return wrapper


def get_x64dbg_bridge() -> X64DbgBridge:
    """Get or create x64dbg bridge instance."""
    global _x64dbg_bridge
    if _x64dbg_bridge is None:
        # Support custom connection via environment variables (useful for testing)
        host = os.getenv("X64DBG_HOST", "127.0.0.1")
        port = int(os.getenv("X64DBG_PORT", "8765"))
        timeout = int(os.getenv("X64DBG_TIMEOUT", "30"))

        _x64dbg_bridge = X64DbgBridge(host=host, port=port, timeout=timeout)
        logger.info(f"Initialized x64dbg bridge: {host}:{port} (timeout: {timeout}s)")
    return _x64dbg_bridge


def get_x64dbg_commands() -> X64DbgCommands:
    """Get or create x64dbg commands instance."""
    global _x64dbg_commands
    if _x64dbg_commands is None:
        _x64dbg_commands = X64DbgCommands(get_x64dbg_bridge())
        logger.info("Initialized x64dbg commands")
    return _x64dbg_commands


def get_ghidra_cache() -> ProjectCache:
    """Get or create Ghidra project cache instance."""
    global _ghidra_cache
    if _ghidra_cache is None:
        _ghidra_cache = ProjectCache()
        logger.info("Initialized Ghidra project cache")
    return _ghidra_cache


def _load_function_mappings(binary_path: str) -> dict[str, dict]:
    """
    Load function mappings from Ghidra cache for a binary.

    Args:
        binary_path: Path to the binary file

    Returns:
        Dictionary mapping function names to their info (address, signature, etc.)
    """
    global _function_mappings

    # Check if already cached
    if binary_path in _function_mappings:
        return _function_mappings[binary_path]

    cache = get_ghidra_cache()
    cached_data = cache.get_cached(binary_path)

    if not cached_data:
        logger.warning(f"No Ghidra cache found for {binary_path}")
        return {}

    # Build function mapping
    functions = cached_data.get("functions", [])
    mappings = {}

    for func in functions:
        func_name = func.get("name", "")
        func_addr = func.get("address", "")

        if func_name and func_addr:
            # Clean up address format
            if isinstance(func_addr, str):
                # Remove any leading zeros and normalize
                func_addr = func_addr.strip()
                if not func_addr.startswith("0x"):
                    func_addr = f"0x{func_addr}"

            mappings[func_name] = {
                "address": func_addr,
                "signature": func.get("signature", ""),
                "is_thunk": func.get("is_thunk", False),
                "is_external": func.get("is_external", False),
                "size": func.get("size", 0),
            }

    # Also add lowercase versions for case-insensitive lookup
    lowercase_mappings = {}
    for name, info in mappings.items():
        lowercase_mappings[name.lower()] = info

    mappings.update(lowercase_mappings)

    _function_mappings[binary_path] = mappings
    logger.info(f"Loaded {len(functions)} function mappings from Ghidra cache for {binary_path}")
    return mappings


def _get_image_base_from_cache(binary_path: str) -> int | None:
    """
    Get the image base from Ghidra cache metadata.

    Args:
        binary_path: Path to the binary file

    Returns:
        Image base as integer, or None if not found
    """
    cache = get_ghidra_cache()
    cached_data = cache.get_cached(binary_path)

    if not cached_data:
        return None

    metadata = cached_data.get("metadata", {})
    image_base = metadata.get("image_base")

    if image_base:
        if isinstance(image_base, str):
            # Parse hex string
            image_base = image_base.strip()
            if image_base.startswith("0x"):
                return int(image_base, 16)
            else:
                try:
                    return int(image_base, 16)
                except ValueError:
                    return int(image_base)
        return int(image_base)

    return None


def _resolve_function_to_runtime(
    function_name: str,
    binary_path: str,
    bridge: X64DbgBridge
) -> dict[str, str | int] | None:
    """
    Resolve a function name from static analysis to its runtime address.

    Uses Ghidra cache for static address and x64dbg for module base.

    Formula: runtime = static - image_base + module_base

    Args:
        function_name: Function name from Ghidra analysis
        binary_path: Path to the binary file
        bridge: X64DbgBridge instance

    Returns:
        Dictionary with static_address, runtime_address, module_base, image_base
        or None if resolution failed
    """
    # Load function mappings from Ghidra cache
    mappings = _load_function_mappings(binary_path)

    if not mappings:
        return None

    # Look up function (case-insensitive)
    func_info = mappings.get(function_name) or mappings.get(function_name.lower())

    if not func_info:
        return None

    static_addr_str = func_info.get("address", "")
    if not static_addr_str:
        return None

    # Parse static address
    if static_addr_str.startswith("0x"):
        static_addr = int(static_addr_str, 16)
    else:
        static_addr = int(static_addr_str, 16)

    # Get image base from Ghidra cache
    image_base = _get_image_base_from_cache(binary_path)
    if image_base is None:
        # Default to common values
        if binary_path.lower().endswith(".dll"):
            image_base = 0x10000000
        else:
            image_base = 0x400000

    # Get module base from x64dbg
    modules = bridge.get_modules()
    binary_name = os.path.basename(binary_path).lower()

    module_base = None
    module_name = None
    for mod in modules:
        mod_name = mod.get("name", "").lower()
        if binary_name in mod_name or mod_name in binary_name:
            base = mod.get("base", 0)
            if isinstance(base, str):
                module_base = int(base, 16) if base.startswith("0x") else int(base)
            else:
                module_base = base
            module_name = mod.get("name", "unknown")
            break

    if module_base is None:
        # Try using first module as fallback
        if modules:
            mod = modules[0]
            base = mod.get("base", 0)
            if isinstance(base, str):
                module_base = int(base, 16) if base.startswith("0x") else int(base)
            else:
                module_base = base
            module_name = mod.get("name", "unknown")
        else:
            return None

    # Calculate runtime address
    offset = static_addr - image_base
    runtime_addr = module_base + offset

    return {
        "function_name": function_name,
        "static_address": f"0x{static_addr:08X}",
        "image_base": f"0x{image_base:08X}",
        "module_base": f"0x{module_base:08X}",
        "module_name": module_name,
        "offset": f"0x{offset:08X}",
        "runtime_address": f"0x{runtime_addr:08X}",
        "signature": func_info.get("signature", ""),
    }


def register_dynamic_tools(app: FastMCP, session_manager: UnifiedSessionManager | None = None) -> None:
    """
    Register all dynamic analysis tools with the MCP server.

    Args:
        app: FastMCP Server instance
        session_manager: Optional session manager for logging tool calls
    """
    global _session_manager
    _session_manager = session_manager

    @app.tool()
    @log_dynamic_tool
    def x64dbg_status() -> str:
        """
        Get x64dbg debugger status.

        Returns:
            Current debugger state including loaded binary,
            execution state, and current address.

        Example output:
            State: paused
            Address: 0x00401234
            Binary: malware.exe
        """
        try:
            commands = get_x64dbg_commands()
            return commands.get_status_summary()
        except Exception as e:
            logger.error(f"x64dbg_status failed: {e}")
            return f"Error: {e}\n\nNote: Ensure x64dbg is running with the MCP plugin loaded."

    @app.tool()
    @log_dynamic_tool
    def x64dbg_connect(host: str = "127.0.0.1", port: int = 8765) -> str:
        """
        Connect to x64dbg debugger.

        Args:
            host: x64dbg plugin host (default: localhost)
            port: x64dbg plugin port (default: 8765)

        Returns:
            Connection status message
        """
        try:
            bridge = X64DbgBridge(host, port)
            bridge.connect()

            # Update global instance
            global _x64dbg_bridge, _x64dbg_commands
            _x64dbg_bridge = bridge
            _x64dbg_commands = X64DbgCommands(bridge)

            location = bridge.get_current_location()
            return f"Connected to x64dbg at {host}:{port}\nState: {location['state']}"

        except Exception as e:
            logger.error(f"x64dbg_connect failed: {e}")
            return f"Error: {e}\n\nTroubleshooting:\n" \
                   f"1. Ensure x64dbg is running\n" \
                   f"2. Verify MCP plugin is loaded (Plugins menu)\n" \
                   f"3. Check plugin log for errors\n" \
                   f"4. Verify port {port} is not blocked"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_attach(pid: int) -> str:
        """
        Attach x64dbg to a running process.

        Args:
            pid: Process ID to attach to

        Returns:
            Connection status after attaching

        Example:
            x64dbg_attach(1234)

        Use Cases:
            - Debug a running service or malware sample
            - Attach to a process spawned by another tool
            - Inspect a process without restarting it
        """
        try:
            if not isinstance(pid, int) or pid <= 0:
                return f"Error: Invalid PID '{pid}'. Must be a positive integer."

            bridge = get_x64dbg_bridge()
            result = bridge.attach_process(pid)

            # Update global commands instance
            global _x64dbg_commands
            _x64dbg_commands = X64DbgCommands(bridge)

            state = result.get("state", "unknown")
            return (
                f"Attached to process PID {pid}\n"
                f"State: {state}"
            )

        except Exception as e:
            logger.error(f"x64dbg_attach failed: {e}")
            return (
                f"Error: {e}\n\n"
                f"Troubleshooting:\n"
                f"1. Verify PID {pid} exists and is accessible\n"
                f"2. Ensure x64dbg is running with MCP plugin\n"
                f"3. Check that no other debugger is attached to the process"
            )

    @app.tool()
    @log_dynamic_tool
    def x64dbg_detach() -> str:
        """
        Detach from the current process without terminating it.

        Returns:
            Confirmation that debugger has detached

        Use Cases:
            - Release a process after analysis
            - Allow a process to continue running unmonitored
            - Switch to debugging a different process
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.detach_process()
            return "Detached from process. Debugger is now idle."

        except Exception as e:
            logger.error(f"x64dbg_detach failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_create_minidump(output_path: str = "") -> str:
        """
        Create a minidump of the debuggee process.

        Args:
            output_path: Path for the minidump file (default: auto-generated in dump directory)

        Returns:
            Confirmation with minidump file path

        Example:
            x64dbg_create_minidump("crash.dmp")

        Use Cases:
            - Capture process state for offline analysis
            - Save crash dumps for later investigation
            - Archive malware memory state at a specific point
        """
        try:
            resolved_path = None
            if output_path:
                # Security: Validate output path to prevent directory traversal
                DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                out_path = Path(output_path)
                if not out_path.is_absolute():
                    out_path = DUMP_OUTPUT_DIR / out_path
                safe_path = sanitize_output_path(out_path, DUMP_OUTPUT_DIR)
                resolved_path = str(safe_path)

            bridge = get_x64dbg_bridge()
            result = bridge.create_minidump(resolved_path)

            dump_path = result.get("path", resolved_path or "default location")
            return (
                f"Minidump created successfully\n"
                f"Path: {dump_path}"
            )

        except PathTraversalError as e:
            return f"Error: Invalid output path - {e}"
        except ValueError as e:
            return f"Error: Invalid path - {e}"
        except Exception as e:
            logger.error(f"x64dbg_create_minidump failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run() -> str:
        """
        Start or resume execution in x64dbg.

        Returns:
            Execution status

        Note: Execution will run until breakpoint hit or program terminates.
        Use x64dbg_run_and_wait() to run and wait for a breakpoint hit.
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.run()
            return "Debugger running...\nUse x64dbg_pause to pause or x64dbg_wait_paused to wait for breakpoint."
        except Exception as e:
            logger.error(f"x64dbg_run failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_wait_paused(timeout_seconds: int = 30) -> str:
        """
        Wait until debugger is paused (breakpoint hit, exception, etc.).

        This is essential for automation - blocks until the debugger stops
        instead of requiring manual polling.

        Args:
            timeout_seconds: Maximum wait time in seconds (default: 30)

        Returns:
            Wait result with state and elapsed time

        Example:
            x64dbg_set_breakpoint("0x401000")
            x64dbg_run()
            x64dbg_wait_paused(60)  # Wait up to 60 seconds for breakpoint

        Use Cases:
            - Wait for breakpoint to hit after run()
            - Wait for exception to occur
            - Synchronize automation scripts
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.wait_until_paused(timeout=timeout_seconds * 1000)

            if result.get("success"):
                return (
                    f"Debugger paused\n"
                    f"Address: {result.get('current_address', 'unknown')}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms"
                )
            else:
                return (
                    f"Timeout waiting for debugger to pause\n"
                    f"Timeout: {timeout_seconds}s\n"
                    f"Current state: {result.get('current_state', 'unknown')}\n"
                    f"Error: {result.get('error', 'Unknown error')}"
                )

        except Exception as e:
            logger.error(f"x64dbg_wait_paused failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_wait_running(timeout_seconds: int = 10) -> str:
        """
        Wait until debugger is running.

        Useful after calling run() to confirm execution has started.

        Args:
            timeout_seconds: Maximum wait time in seconds (default: 10)

        Returns:
            Wait result with state and elapsed time
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.wait_until_running(timeout=timeout_seconds * 1000)

            if result.get("success"):
                return (
                    f"Debugger is running\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms"
                )
            else:
                return (
                    f"Timeout waiting for debugger to run\n"
                    f"Timeout: {timeout_seconds}s\n"
                    f"Current state: {result.get('current_state', 'unknown')}"
                )

        except Exception as e:
            logger.error(f"x64dbg_wait_running failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_wait_debugging(timeout_seconds: int = 30) -> str:
        """
        Wait until debugging has started (binary is loaded).

        Useful after loading a binary to confirm it's ready for debugging.

        Args:
            timeout_seconds: Maximum wait time in seconds (default: 30)

        Returns:
            Wait result with state and elapsed time
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.wait_until_debugging(timeout=timeout_seconds * 1000)

            if result.get("success"):
                state = "running" if result.get("is_running") else "paused"
                return (
                    f"Debugging active\n"
                    f"State: {state}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms"
                )
            else:
                return (
                    f"Timeout waiting for debugging to start\n"
                    f"Timeout: {timeout_seconds}s\n"
                    f"Current state: {result.get('current_state', 'unknown')}"
                )

        except Exception as e:
            logger.error(f"x64dbg_wait_debugging failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_and_wait(timeout_seconds: int = 30) -> str:
        """
        Run execution and wait until it pauses (breakpoint, exception, etc.).

        This is a convenience function combining run() and wait_paused().
        Essential for automation scripts.

        Args:
            timeout_seconds: Maximum wait time in seconds (default: 30)

        Returns:
            Execution result with address where stopped

        Example:
            x64dbg_set_breakpoint("0x401000")
            result = x64dbg_run_and_wait(60)
            # Now at breakpoint, can inspect registers, memory, etc.

        Use Cases:
            - Run to breakpoint and inspect state
            - Automate stepping through code
            - Wait for specific program state
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.run_and_wait(timeout=timeout_seconds * 1000)

            if result.get("success"):
                return (
                    f"Execution stopped\n"
                    f"Address: {result.get('current_address', 'unknown')}\n"
                    f"State: paused\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms\n\n"
                    f"Use x64dbg_get_registers() to see register values."
                )
            else:
                return (
                    f"Timeout waiting for execution to stop\n"
                    f"Timeout: {timeout_seconds}s\n"
                    f"Current state: {result.get('current_state', 'unknown')}\n"
                    f"Error: {result.get('error', 'Unknown error')}\n\n"
                    f"The program may still be running. Use x64dbg_pause() to stop it."
                )

        except Exception as e:
            logger.error(f"x64dbg_run_and_wait failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_pause() -> str:
        """
        Pause execution in x64dbg.

        Returns:
            Current execution state after pausing
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.pause()

            location = bridge.get_current_location()
            return f"Execution paused\nCurrent address: 0x{location['address']}"

        except Exception as e:
            logger.error(f"x64dbg_pause failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_step_into(steps: int = 1) -> str:
        """
        Step into next instruction(s).

        Args:
            steps: Number of instructions to step (default: 1)

        Returns:
            Current execution state after stepping
        """
        try:
            bridge = get_x64dbg_bridge()

            for i in range(steps):
                bridge.step_into()

            registers = bridge.get_registers()
            location = bridge.get_current_location()

            result = [
                f"Stepped {steps} instruction(s)",
                f"Current address: 0x{location['address']}",
                f"RIP: 0x{registers.get('rip', 'unknown')}",
                f"RAX: 0x{registers.get('rax', 'unknown')}"
            ]

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_step_into failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_step_over(steps: int = 1) -> str:
        """
        Step over next instruction(s).

        Steps over CALL instructions (doesn't enter functions).

        Args:
            steps: Number of instructions to step (default: 1)

        Returns:
            Current execution state
        """
        try:
            bridge = get_x64dbg_bridge()

            for i in range(steps):
                bridge.step_over()

            location = bridge.get_current_location()
            return f"Stepped over {steps} instruction(s)\nCurrent address: 0x{location['address']}"

        except Exception as e:
            logger.error(f"x64dbg_step_over failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_registers() -> str:
        """
        Get current CPU register values.

        Returns:
            Formatted register dump showing all general-purpose registers

        Example output:
            Registers:
            ----------------------------------------
            RAX  = 0x0000000000000000
            RBX  = 0x0000000000000001
            ...
        """
        try:
            commands = get_x64dbg_commands()
            return commands.dump_registers()

        except Exception as e:
            logger.error(f"x64dbg_get_registers failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_breakpoint(address: str) -> str:
        """
        Set breakpoint at address.

        Args:
            address: Memory address (hex, e.g., "0x401000" or "401000")

        Returns:
            Confirmation message

        Example:
            x64dbg_set_breakpoint("0x00401234")
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_breakpoint(address)
            return f"Breakpoint set at {address}"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_set_breakpoint failed: {e}")
            return format_error_response(e, "set_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_breakpoint(address: str) -> str:
        """
        Delete breakpoint at address.

        Args:
            address: Memory address of breakpoint

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_breakpoint(address)
            return f"Breakpoint deleted at {address}"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_delete_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "delete_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_delete_breakpoint failed: {e}")
            return format_error_response(e, "delete_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_breakpoints(breakpoints: list[dict]) -> str:
        """
        Set multiple breakpoints in a single call.

        Efficient batch operation that reduces round-trips for setting up
        analysis environments.

        Args:
            breakpoints: List of breakpoint specifications, each containing:
                - address: Memory address (hex string, required)
                - type: "software" (default), "hardware", or "memory"
                - hw_type: For hardware BPs: "execute", "read", "write", "access"
                - size: For hardware/memory BPs: 1, 2, 4, or 8 bytes

        Returns:
            Summary of breakpoints set with success/failure count

        Examples:
            x64dbg_set_breakpoints([
                {"address": "0x401000"},
                {"address": "0x401100"},
                {"address": "0x7FFD12340000", "type": "hardware", "hw_type": "execute"}
            ])

        Use Cases:
            - Set up multiple API breakpoints quickly
            - Configure analysis environment in one call
            - Batch set breakpoints from a list of addresses
        """
        try:
            bridge = get_x64dbg_bridge()
            results = {"success": 0, "failed": 0, "errors": []}

            for i, bp in enumerate(breakpoints):
                address = bp.get("address")
                bp_type = bp.get("type", "software")

                if not address:
                    results["failed"] += 1
                    results["errors"].append(f"Breakpoint {i}: Missing address")
                    continue

                try:
                    if bp_type == "software":
                        bridge.set_breakpoint(address)
                    elif bp_type == "hardware":
                        hw_type = bp.get("hw_type", "execute")
                        size = bp.get("size", 1)
                        bridge.set_hardware_breakpoint(address, hw_type, size)
                    elif bp_type == "memory":
                        mem_type = bp.get("hw_type", "access")  # reuse hw_type for memory type
                        size = bp.get("size", 1)
                        bridge.set_memory_breakpoint(address, mem_type, size)
                    else:
                        results["failed"] += 1
                        results["errors"].append(f"Breakpoint {i}: Invalid type '{bp_type}'")
                        continue

                    results["success"] += 1

                except Exception as e:
                    results["failed"] += 1
                    results["errors"].append(f"Breakpoint at {address}: {e}")

            # Format output
            output = [
                "Batch breakpoint results:",
                f"  Success: {results['success']}",
                f"  Failed: {results['failed']}"
            ]

            if results["errors"]:
                output.append("")
                output.append("Errors:")
                for err in results["errors"][:10]:  # Limit error messages
                    output.append(f"  - {err}")
                if len(results["errors"]) > 10:
                    output.append(f"  ... and {len(results['errors']) - 10} more")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_set_breakpoints failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_breakpoints(addresses: list[str]) -> str:
        """
        Delete multiple breakpoints in a single call.

        Efficient batch operation for clearing breakpoints.

        Args:
            addresses: List of memory addresses to delete breakpoints from

        Returns:
            Summary of breakpoints deleted with success/failure count

        Examples:
            x64dbg_delete_breakpoints(["0x401000", "0x401100", "0x7FFD12340000"])
        """
        try:
            bridge = get_x64dbg_bridge()
            results = {"success": 0, "failed": 0, "errors": []}

            for address in addresses:
                try:
                    bridge.delete_breakpoint(address)
                    results["success"] += 1
                except Exception as e:
                    results["failed"] += 1
                    results["errors"].append(f"{address}: {e}")

            # Format output
            output = [
                "Batch delete results:",
                f"  Success: {results['success']}",
                f"  Failed: {results['failed']}"
            ]

            if results["errors"]:
                output.append("")
                output.append("Errors:")
                for err in results["errors"][:10]:
                    output.append(f"  - {err}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_delete_breakpoints failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_breakpoints() -> str:
        """
        List all breakpoints.

        Returns:
            List of active breakpoints with addresses
        """
        try:
            bridge = get_x64dbg_bridge()
            breakpoints = bridge.list_breakpoints()

            if not breakpoints:
                return "No breakpoints set"

            result = ["Breakpoints:", "-" * 40]
            for i, bp in enumerate(breakpoints, 1):
                result.append(f"{i}. 0x{bp.get('address', 'unknown')}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_list_breakpoints failed: {e}")
            return f"Error: {e}"

    # ── Exception handling control tools ────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_exception_breakpoint(
        exception_code: str, chance: str = "first"
    ) -> str:
        """
        Set breakpoint on an exception code.

        Args:
            exception_code: Exception code (hex, e.g., "0xC0000005" for access violation)
            chance: When to break - "first", "second", or "all"

        Returns:
            Confirmation message

        Example:
            x64dbg_set_exception_breakpoint("0xC0000005", "first")
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_exception_breakpoint(exception_code, chance)
            return (
                f"Exception breakpoint set on {exception_code} "
                f"(chance={chance})"
            )

        except StructuredBaseError as e:
            logger.error(
                f"x64dbg_set_exception_breakpoint failed: "
                f"{e.structured_error.error.value}"
            )
            return format_error_response(e, "set_exception_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_set_exception_breakpoint failed: {e}")
            return format_error_response(e, "set_exception_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_exception_breakpoint(exception_code: str) -> str:
        """
        Delete an exception breakpoint.

        Args:
            exception_code: Exception code (hex, e.g., "0xC0000005")

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_exception_breakpoint(exception_code)
            return f"Exception breakpoint deleted for {exception_code}"

        except StructuredBaseError as e:
            logger.error(
                f"x64dbg_delete_exception_breakpoint failed: "
                f"{e.structured_error.error.value}"
            )
            return format_error_response(e, "delete_exception_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_delete_exception_breakpoint failed: {e}")
            return format_error_response(e, "delete_exception_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_exception_breakpoints() -> str:
        """
        List all exception breakpoints.

        Returns:
            List of exception breakpoints with codes and chance types
        """
        try:
            bridge = get_x64dbg_bridge()
            exceptions = bridge.list_exception_breakpoints()

            if not exceptions:
                return "No exception breakpoints set"

            result = ["Exception Breakpoints:", "-" * 40]
            for i, exc in enumerate(exceptions, 1):
                code = exc.get("code", "unknown")
                chance = exc.get("chance", "unknown")
                result.append(f"{i}. 0x{code} (chance={chance})")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_list_exception_breakpoints failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_skip_exception(exception_code: str) -> str:
        """
        Add exception to ignore list so debugger passes it to the application.

        Args:
            exception_code: Exception code (hex, e.g., "0xC0000005")

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.skip_exception(exception_code)
            return (
                f"Exception {exception_code} added to ignore list "
                f"(will be passed to application)"
            )

        except StructuredBaseError as e:
            logger.error(
                f"x64dbg_skip_exception failed: "
                f"{e.structured_error.error.value}"
            )
            return format_error_response(e, "skip_exception")
        except Exception as e:
            logger.error(f"x64dbg_skip_exception failed: {e}")
            return format_error_response(e, "skip_exception")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_read_memory(address: str, size: int = 256) -> str:
        """
        Read memory from debugged process.

        Args:
            address: Memory address to read from
            size: Number of bytes to read (default: 256)

        Returns:
            Hexdump of memory contents

        Example:
            x64dbg_read_memory("0x00401000", 64)
        """
        try:
            bridge = get_x64dbg_bridge()
            data = bridge.read_memory(address, size)

            # Format as hexdump
            result = [f"Memory at {address} ({size} bytes):", "-" * 60]

            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_str = " ".join(f"{b:02x}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                result.append(f"{i:08x}: {hex_str:<48}  {ascii_str}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_read_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_disassemble(address: str, count: int = 20) -> str:
        """
        Disassemble instructions at address.

        Uses x64dbg plugin API with capstone library fallback for reliability.

        Args:
            address: Start address (hex, e.g., "0x401000")
            count: Number of instructions to disassemble (default: 20)

        Returns:
            Disassembly listing

        Example output:
            00401000: push rbp
            00401001: mov rbp, rsp
            ...

        Note:
            If the x64dbg API returns empty results, the tool will automatically
            attempt to read raw memory and disassemble using capstone library.
        """
        try:
            bridge = get_x64dbg_bridge()
            instructions = bridge.disassemble(address, count)

            result = [f"Disassembly at {address}:", "-" * 60]

            for instr in instructions:
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operand = instr.get("operand", "")
                instr_bytes = instr.get("bytes", "")

                line = f"{addr}: {mnemonic} {operand}".strip()
                if instr_bytes:
                    line = f"{addr}: {instr_bytes:20} {mnemonic} {operand}".strip()
                result.append(line)

            return "\n".join(result)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_disassemble failed: {e.structured_error.error.value}")
            return format_error_response(e, "disassemble")
        except Exception as e:
            logger.error(f"x64dbg_disassemble failed: {e}")
            return format_error_response(e, "disassemble")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_trace_execution(steps: int = 10) -> str:
        """
        Trace execution for N steps.

        Records register state at each step for analysis.

        Args:
            steps: Number of steps to trace (default: 10)

        Returns:
            Execution trace with addresses and register values

        Example output:
            Step 0: 0x00401234 RIP=00401234
            Step 1: 0x00401235 RIP=00401235
            ...
        """
        try:
            commands = get_x64dbg_commands()
            trace = commands.trace_execution(steps)

            result = [f"Execution trace ({steps} steps):", "-" * 60]

            for entry in trace:
                step = entry["step"]
                addr = entry["address"]
                ip = entry.get("rip", entry.get("eip", "unknown"))
                ip_label = "RIP" if "rip" in entry else "EIP"
                result.append(f"Step {step}: 0x{addr} {ip_label}={ip}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_trace_execution failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_trace_api_calls(
        apis: list[str],
        max_calls: int = 100,
        include_stack: bool = False
    ) -> str:
        """
        Trace specific API calls with parameter capture.

        Sets breakpoints on specified APIs and logs call information including
        parameters and return values.

        Args:
            apis: List of API names to trace (e.g., ["CreateFileW", "VirtualAlloc"])
            max_calls: Maximum number of calls to capture (default: 100)
            include_stack: Include call stack for each call (slower)

        Returns:
            Structured trace of API calls with parameters

        Examples:
            x64dbg_trace_api_calls(["CreateFileW", "CreateProcessW"])
            x64dbg_trace_api_calls(["VirtualAlloc", "WriteProcessMemory"], max_calls=50)

        Common APIs to trace:
            File: CreateFileW, ReadFile, WriteFile, DeleteFileW
            Process: CreateProcessW, OpenProcess, WriteProcessMemory
            Memory: VirtualAlloc, VirtualProtect, MapViewOfFile
            Registry: RegOpenKeyExW, RegSetValueExW, RegQueryValueExW
            Network: connect, send, recv, InternetOpenW

        Note:
            This sets temporary breakpoints on the APIs. Use x64dbg_run() to
            start execution and collect trace data. Call this function again
            to retrieve accumulated calls.
        """
        try:
            bridge = get_x64dbg_bridge()

            # API name to module mapping (common Windows APIs)
            api_modules = {
                # Kernel32
                "CreateFileW": "kernel32",
                "CreateFileA": "kernel32",
                "ReadFile": "kernel32",
                "WriteFile": "kernel32",
                "DeleteFileW": "kernel32",
                "CreateProcessW": "kernel32",
                "CreateProcessA": "kernel32",
                "OpenProcess": "kernel32",
                "VirtualAlloc": "kernel32",
                "VirtualAllocEx": "kernel32",
                "VirtualProtect": "kernel32",
                "VirtualProtectEx": "kernel32",
                "WriteProcessMemory": "kernel32",
                "ReadProcessMemory": "kernel32",
                "LoadLibraryW": "kernel32",
                "LoadLibraryA": "kernel32",
                "GetProcAddress": "kernel32",
                "CreateRemoteThread": "kernel32",
                "CreateThread": "kernel32",
                # Ntdll
                "NtCreateFile": "ntdll",
                "NtWriteFile": "ntdll",
                "NtAllocateVirtualMemory": "ntdll",
                "NtProtectVirtualMemory": "ntdll",
                "NtCreateSection": "ntdll",
                "NtMapViewOfSection": "ntdll",
                # Advapi32
                "RegOpenKeyExW": "advapi32",
                "RegSetValueExW": "advapi32",
                "RegQueryValueExW": "advapi32",
                "RegCreateKeyExW": "advapi32",
                # WinInet/WinHTTP
                "InternetOpenW": "wininet",
                "InternetConnectW": "wininet",
                "HttpOpenRequestW": "wininet",
                "HttpSendRequestW": "wininet",
                # Ws2_32
                "connect": "ws2_32",
                "send": "ws2_32",
                "recv": "ws2_32",
                "socket": "ws2_32",
            }

            results = {
                "apis_configured": [],
                "apis_failed": [],
                "breakpoints_set": 0
            }

            for api_name in apis:
                try:
                    # Try to resolve API address
                    module = api_modules.get(api_name, "kernel32")

                    # Use x64dbg's expression evaluation to get API address
                    # Format: module!apiname (x64dbg symbol syntax)
                    api_expr = f"{module}!{api_name}"

                    # Set conditional breakpoint that logs and continues
                    # This uses x64dbg's logging breakpoint feature
                    resolved = bridge.resolve_symbol(api_expr)
                    if not resolved.get("success"):
                        raise ValueError(
                            f"Could not resolve symbol '{api_expr}': "
                            f"{resolved.get('error', 'unknown error')}"
                        )
                    resolved_addr = resolved["address"]
                    bridge.set_breakpoint(resolved_addr)
                    results["apis_configured"].append({
                        "name": api_name,
                        "module": module,
                        "expression": api_expr,
                        "address": resolved_addr
                    })
                    results["breakpoints_set"] += 1

                except Exception as e:
                    results["apis_failed"].append({
                        "name": api_name,
                        "error": str(e)
                    })

            # Format output
            output = [
                f"API trace configured for {len(results['apis_configured'])} APIs",
                ""
            ]

            if results["apis_configured"]:
                output.append("APIs being traced:")
                for api in results["apis_configured"]:
                    output.append(f"  - {api['name']} ({api['module']})")

            if results["apis_failed"]:
                output.append("")
                output.append("Failed to configure:")
                for api in results["apis_failed"]:
                    output.append(f"  - {api['name']}: {api['error']}")

            output.append("")
            output.append("Next steps:")
            output.append("  1. Run x64dbg_run() to start execution")
            output.append("  2. Execution will pause at each API call")
            output.append("  3. Use x64dbg_get_registers() to inspect parameters")
            output.append("  4. Use x64dbg_run() to continue to next call")
            output.append("")
            output.append(f"Max calls to capture: {max_calls}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_trace_api_calls failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_start_trace(
        trace_into: bool = True,
        max_entries: int = 100000,
        log_file: str = ""
    ) -> str:
        """
        Start recording an instruction execution trace.

        Records each instruction executed with address, disassembly, and timing.
        Use x64dbg_run() to begin execution, then x64dbg_stop_trace() and
        x64dbg_get_trace() to retrieve results.

        Args:
            trace_into: If True, trace into function calls. If False, trace over.
            max_entries: Maximum trace entries to keep in memory (default: 100000)
            log_file: Optional file path to write trace log (for large traces)

        Returns:
            Trace configuration summary

        Example workflow:
            1. x64dbg_start_trace(trace_into=True)
            2. x64dbg_run()
            3. x64dbg_stop_trace()
            4. x64dbg_get_trace(max_entries=50)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.start_trace(
                trace_into=trace_into,
                max_entries=max_entries,
                log_file=log_file if log_file else None,
            )

            mode = "trace into" if trace_into else "trace over"
            output = (
                f"Trace started\n"
                f"  Mode: {mode}\n"
                f"  Max entries: {max_entries}"
            )
            if log_file:
                output += f"\n  Log file: {log_file}"

            return output

        except StructuredBaseError as e:
            logger.error(f"x64dbg_start_trace failed: {e.structured_error.error.value}")
            return format_error_response(e, "start_trace")
        except Exception as e:
            logger.error(f"x64dbg_start_trace failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_stop_trace() -> str:
        """
        Stop recording the instruction execution trace.

        Returns:
            Trace statistics including entry count and duration
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.stop_trace()

            entry_count = result.get("entry_count", "unknown")
            duration = result.get("duration", "unknown")

            return (
                f"Trace stopped\n"
                f"  Entries recorded: {entry_count}\n"
                f"  Duration: {duration}"
            )

        except StructuredBaseError as e:
            logger.error(f"x64dbg_stop_trace failed: {e.structured_error.error.value}")
            return format_error_response(e, "stop_trace")
        except Exception as e:
            logger.error(f"x64dbg_stop_trace failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_trace(max_entries: int = 100) -> str:
        """
        Get recorded trace data formatted as a listing.

        Args:
            max_entries: Maximum number of trace entries to return (default: 100)

        Returns:
            Formatted trace listing with addresses and instructions

        Example output:
            Trace: 500 total entries (showing 100)
            ------------------------------------------------------------
            0x00401234: mov eax, [ebp+8]  [main.exe]
            0x00401238: call 0x00402000    [main.exe]
            ...
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.get_trace_data(offset=0, limit=max_entries)

            total = result.get("total", 0)
            entries = result.get("entries", [])
            enabled = result.get("enabled", False)

            output = [
                f"Trace: {total} total entries (showing {len(entries)})",
                f"  Recording: {'active' if enabled else 'stopped'}",
                "-" * 60,
            ]

            for entry in entries:
                addr = entry.get("address", "?")
                instr = entry.get("instruction", "?")
                module = entry.get("module", "")
                line = f"0x{addr}: {instr}"
                if module:
                    line += f"  [{module}]"
                output.append(line)

            if not entries:
                output.append("(no trace entries)")

            return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_get_trace failed: {e.structured_error.error.value}")
            return format_error_response(e, "get_trace")
        except Exception as e:
            logger.error(f"x64dbg_get_trace failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_clear_trace() -> str:
        """
        Clear trace data from memory.

        Use this to free memory after retrieving trace data, or before
        starting a new trace session.

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.clear_trace()
            return "Trace data cleared"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_clear_trace failed: {e.structured_error.error.value}")
            return format_error_response(e, "clear_trace")
        except Exception as e:
            logger.error(f"x64dbg_clear_trace failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_api_params(api_name: str) -> str:
        """
        Get parameters for current API call based on calling convention.

        Call this when paused at an API breakpoint to decode parameters.

        Args:
            api_name: Name of the API to decode parameters for

        Returns:
            Decoded parameters based on API signature

        Common APIs supported:
            - CreateFileW: lpFileName, dwDesiredAccess, dwShareMode, ...
            - VirtualAlloc: lpAddress, dwSize, flAllocationType, flProtect
            - WriteProcessMemory: hProcess, lpBaseAddress, lpBuffer, nSize
            - CreateProcessW: lpApplicationName, lpCommandLine, ...

        Example:
            x64dbg_set_breakpoint("kernel32.CreateFileW")
            x64dbg_run()
            # ... breakpoint hit ...
            x64dbg_get_api_params("CreateFileW")  # Decode parameters
        """
        try:
            bridge = get_x64dbg_bridge()

            # Get current register state
            regs = bridge.get_registers()

            # x64 Windows calling convention: RCX, RDX, R8, R9, then stack
            # x86 would use stack for __stdcall

            # API parameter definitions (x64 calling convention)
            api_params = {
                "CreateFileW": [
                    ("lpFileName", "rcx", "unicode_ptr"),
                    ("dwDesiredAccess", "rdx", "hex"),
                    ("dwShareMode", "r8", "hex"),
                    ("lpSecurityAttributes", "r9", "ptr"),
                    ("dwCreationDisposition", "stack+0x28", "hex"),
                    ("dwFlagsAndAttributes", "stack+0x30", "hex"),
                    ("hTemplateFile", "stack+0x38", "ptr"),
                ],
                "CreateFileA": [
                    ("lpFileName", "rcx", "ascii_ptr"),
                    ("dwDesiredAccess", "rdx", "hex"),
                    ("dwShareMode", "r8", "hex"),
                    ("lpSecurityAttributes", "r9", "ptr"),
                ],
                "VirtualAlloc": [
                    ("lpAddress", "rcx", "ptr"),
                    ("dwSize", "rdx", "hex"),
                    ("flAllocationType", "r8", "hex"),
                    ("flProtect", "r9", "hex"),
                ],
                "VirtualAllocEx": [
                    ("hProcess", "rcx", "handle"),
                    ("lpAddress", "rdx", "ptr"),
                    ("dwSize", "r8", "hex"),
                    ("flAllocationType", "r9", "hex"),
                ],
                "WriteProcessMemory": [
                    ("hProcess", "rcx", "handle"),
                    ("lpBaseAddress", "rdx", "ptr"),
                    ("lpBuffer", "r8", "ptr"),
                    ("nSize", "r9", "hex"),
                ],
                "CreateProcessW": [
                    ("lpApplicationName", "rcx", "unicode_ptr"),
                    ("lpCommandLine", "rdx", "unicode_ptr"),
                    ("lpProcessAttributes", "r8", "ptr"),
                    ("lpThreadAttributes", "r9", "ptr"),
                ],
                "OpenProcess": [
                    ("dwDesiredAccess", "rcx", "hex"),
                    ("bInheritHandle", "rdx", "bool"),
                    ("dwProcessId", "r8", "dec"),
                ],
                "LoadLibraryW": [
                    ("lpLibFileName", "rcx", "unicode_ptr"),
                ],
                "LoadLibraryA": [
                    ("lpLibFileName", "rcx", "ascii_ptr"),
                ],
                "GetProcAddress": [
                    ("hModule", "rcx", "handle"),
                    ("lpProcName", "rdx", "ascii_ptr"),
                ],
            }

            if api_name not in api_params:
                return (
                    f"Unknown API: {api_name}\n\n"
                    f"Supported APIs: {', '.join(sorted(api_params.keys()))}\n\n"
                    f"For unsupported APIs, use x64dbg_get_registers() to inspect:\n"
                    f"  x64: RCX=param1, RDX=param2, R8=param3, R9=param4"
                )

            params = api_params[api_name]
            output = [f"API: {api_name}", "Parameters:", ""]

            for param_name, reg_or_stack, param_type in params:
                try:
                    # Get register value
                    if reg_or_stack.startswith("stack"):
                        # Stack parameter - would need memory read
                        value = "(stack parameter - use x64dbg_read_memory)"
                    else:
                        value = regs.get(reg_or_stack.upper(), regs.get(reg_or_stack, "N/A"))

                    # Format based on type
                    if param_type == "unicode_ptr" and value != "N/A":
                        try:
                            # Try to read unicode string from pointer
                            str_data = bridge.read_memory(f"0x{value}", 512)
                            if str_data:
                                # Decode as UTF-16LE
                                decoded = str_data.decode('utf-16-le', errors='ignore').split('\x00')[0]
                                value = f"0x{value} -> \"{decoded}\""
                            else:
                                value = f"0x{value}"
                        except Exception:
                            value = f"0x{value}"
                    elif param_type == "ascii_ptr" and value != "N/A":
                        try:
                            str_data = bridge.read_memory(f"0x{value}", 256)
                            if str_data:
                                decoded = str_data.decode('ascii', errors='ignore').split('\x00')[0]
                                value = f"0x{value} -> \"{decoded}\""
                            else:
                                value = f"0x{value}"
                        except Exception:
                            value = f"0x{value}"
                    elif param_type == "hex":
                        value = f"0x{value}"
                    elif param_type == "ptr" or param_type == "handle":
                        value = f"0x{value}"
                    elif param_type == "bool":
                        value = "TRUE" if int(value, 16) != 0 else "FALSE"

                    output.append(f"  {param_name}: {value}")

                except Exception as e:
                    output.append(f"  {param_name}: (error: {e})")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_api_params failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_to_address(address: str) -> str:
        """
        Run until reaching specified address.

        Sets temporary breakpoint and runs until hit.

        Args:
            address: Target address

        Returns:
            Execution state when address reached
        """
        try:
            commands = get_x64dbg_commands()
            state = commands.run_to_address(address)

            return f"Reached address: 0x{state['address']}\nState: {state['state']}"

        except Exception as e:
            logger.error(f"x64dbg_run_to_address failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_step_out() -> str:
        """
        Step out of current function.

        Executes until the current function returns.

        Returns:
            Current execution state after returning

        Example:
            Useful for skipping over function internals
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.step_out()

            return f"Stepped out of function\nCurrent address: 0x{result['address']}\nState: {result['state']}"

        except Exception as e:
            logger.error(f"x64dbg_step_out failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_stack(depth: int = 20) -> str:
        """
        Get call stack trace.

        Shows the chain of function calls leading to current location.

        Args:
            depth: Number of stack frames to retrieve (default: 20)

        Returns:
            Formatted call stack with return addresses

        Example output:
            Call Stack (20 frames):
            ----------------------------------------
            0. 0x00401234 (return to)
            1. 0x00402000 (return to)
            ...
        """
        try:
            bridge = get_x64dbg_bridge()
            stack_result = bridge.get_stack(depth)
            frames = stack_result.get("frames", [])
            is_raw = stack_result.get("raw", False)

            if not frames:
                return "No stack frames available"

            if is_raw:
                header = f"Stack contents (raw dump, not unwound call stack) — {len(frames)} entries:"
            else:
                header = f"Call Stack ({len(frames)} frames):"

            result = [header, "-" * 60]

            for i, frame in enumerate(frames):
                addr = frame.get("address", "unknown")
                comment = frame.get("comment", "")
                if comment and comment != "raw stack":
                    result.append(f"{i}. 0x{addr} ({comment})")
                else:
                    result.append(f"{i}. 0x{addr}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_stack failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_modules() -> str:
        r"""
        Get list of loaded modules/DLLs.

        Shows all libraries loaded in the debugged process.

        Returns:
            List of modules with base address, size, and path

        Example output:
            Loaded Modules:
            ----------------------------------------
            malware.exe
              Base: 0x00400000
              Size: 0x00010000
              Path: C:\malware.exe

            kernel32.dll
              Base: 0x76D00000
              Size: 0x000C0000
              Path: C:\Windows\System32\kernel32.dll
        """
        try:
            bridge = get_x64dbg_bridge()
            modules = bridge.get_modules()

            if not modules:
                return "No modules loaded"

            result = ["Loaded Modules:", "-" * 60]

            for mod in modules:
                name = mod.get("name", "unknown")
                base = mod.get("base", "unknown")
                size = mod.get("size", "unknown")
                path = mod.get("path", "")

                result.append(f"\n{name}")
                result.append(f"  Base: 0x{base}")
                result.append(f"  Size: 0x{size}")
                if path:
                    result.append(f"  Path: {path}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_modules failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_threads() -> str:
        """
        Get list of process threads.

        Shows all threads in the debugged process.

        Returns:
            List of threads with ID, entry point, and status

        Example output:
            Threads:
            ----------------------------------------
            Thread 1234 (Main)
              Entry: 0x00401000
              Status: Running

            Thread 5678
              Entry: 0x76D12340
              Status: Suspended
        """
        try:
            bridge = get_x64dbg_bridge()
            threads = bridge.get_threads()

            if not threads:
                return "No threads found"

            result = ["Threads:", "-" * 60]

            for thread in threads:
                tid = thread.get("id", "unknown")
                entry = thread.get("entry", "unknown")
                status = thread.get("status", "unknown")
                is_main = thread.get("main", False)

                main_marker = " (Main)" if is_main else ""
                result.append(f"\nThread {tid}{main_marker}")
                result.append(f"  Entry: 0x{entry}")
                result.append(f"  Status: {status}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_threads failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_switch_thread(thread_id: str) -> str:
        """
        Switch active thread in the debugger.

        Changes the debugger's active thread context to the specified thread.

        Args:
            thread_id: Thread ID to switch to

        Returns:
            New thread context information

        Example:
            x64dbg_switch_thread("1234")  # Switch to thread 1234
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.switch_thread(thread_id)

            lines = [f"Switched to thread {thread_id}"]

            # Include thread context if returned by API
            if "registers" in result:
                regs = result["registers"]
                for reg, val in regs.items():
                    lines.append(f"  {reg}: 0x{val}")
            if "entry" in result:
                lines.append(f"  Entry: 0x{result['entry']}")
            if "status" in result:
                lines.append(f"  Status: {result['status']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_switch_thread failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_suspend_thread(thread_id: str) -> str:
        """
        Suspend a thread in the debugged process.

        Args:
            thread_id: Thread ID to suspend

        Returns:
            Confirmation message

        Example:
            x64dbg_suspend_thread("1234")  # Suspend thread 1234
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.suspend_thread(thread_id)
            return f"Thread {thread_id} suspended"

        except Exception as e:
            logger.error(f"x64dbg_suspend_thread failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_resume_thread(thread_id: str) -> str:
        """
        Resume a suspended thread in the debugged process.

        Args:
            thread_id: Thread ID to resume

        Returns:
            Confirmation message

        Example:
            x64dbg_resume_thread("1234")  # Resume thread 1234
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.resume_thread(thread_id)
            return f"Thread {thread_id} resumed"

        except Exception as e:
            logger.error(f"x64dbg_resume_thread failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_suspend_all_threads() -> str:
        """
        Suspend all threads in the debugged process.

        Returns:
            Confirmation with thread count

        Example:
            x64dbg_suspend_all_threads()  # Suspend all threads
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.suspend_all_threads()
            count = result.get("count", "unknown")
            return f"All threads suspended (count: {count})"

        except Exception as e:
            logger.error(f"x64dbg_suspend_all_threads failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_resume_all_threads() -> str:
        """
        Resume all threads in the debugged process.

        Returns:
            Confirmation with thread count

        Example:
            x64dbg_resume_all_threads()  # Resume all threads
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.resume_all_threads()
            count = result.get("count", "unknown")
            return f"All threads resumed (count: {count})"

        except Exception as e:
            logger.error(f"x64dbg_resume_all_threads failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_write_memory(address: str, data: str) -> str:
        """
        Write bytes to process memory.

        Modify memory in the debugged process.

        Args:
            address: Memory address to write to (hex string)
            data: Hex string of bytes to write (e.g., "90 90 90" for 3 NOPs)

        Returns:
            Confirmation message

        Example:
            x64dbg_write_memory("0x00401000", "90 90 90")  # Write 3 NOP instructions
            x64dbg_write_memory("0x00402000", "C3")        # Write RET instruction

        Warning:
            Writing to wrong addresses can crash the debugged process!
        """
        try:
            bridge = get_x64dbg_bridge()

            # Parse hex string to bytes
            hex_data = data.replace(" ", "").replace("0x", "")
            byte_data = bytes.fromhex(hex_data)

            bridge.write_memory(address, byte_data)

            return f"Wrote {len(byte_data)} bytes to {address}\nData: {data}"

        except ValueError as e:
            return f"Error: Invalid hex data format. Use format like '90 90 90' or '909090'\nDetails: {e}"
        except Exception as e:
            logger.error(f"x64dbg_write_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_dump_memory(address: str, size: int, output_file: str) -> str:
        """
        Dump memory region to file.

        Essential for unpacking malware and extracting payloads.

        Args:
            address: Start address (hex, e.g., "0x400000")
            size: Number of bytes to dump
            output_file: Path to save dumped memory (e.g., "/tmp/unpacked.bin")

        Returns:
            Confirmation with file path

        Example:
            x64dbg_dump_memory("0x400000", 4096, "/tmp/dump.bin")

        Use Cases:
            - Dump unpacked malware from memory
            - Extract injected code
            - Save decrypted payloads
            - Reconstruct PE files

        Note:
            Requires x64dbg plugin C++ implementation
        """
        # Security: Validate size to prevent memory exhaustion
        if size <= 0:
            return "Error: Size must be positive"
        if size > MAX_DUMP_SIZE:
            return (f"Error: Dump size {size} bytes exceeds maximum "
                    f"{MAX_DUMP_SIZE} bytes (100MB). "
                    "Use chunked reads for larger regions.")

        # Security: Validate output path to prevent directory traversal
        try:
            DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            output_path = Path(output_file)
            # If relative path, resolve within dump directory
            if not output_path.is_absolute():
                output_path = DUMP_OUTPUT_DIR / output_path
            safe_path = sanitize_output_path(output_path, DUMP_OUTPUT_DIR)
        except PathTraversalError as e:
            return f"Error: Invalid output path - {e}"
        except ValueError as e:
            return f"Error: Invalid path - {e}"

        try:
            bridge = get_x64dbg_bridge()
            bridge.dump_memory(address, size, str(safe_path))

            return f"Memory dumped successfully\n" \
                   f"Address: {address}\n" \
                   f"Size: {size} bytes ({size / 1024:.2f} KB)\n" \
                   f"Output: {safe_path}"

        except Exception as e:
            logger.error(f"x64dbg_dump_memory failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory dump requires C++ plugin implementation\n"
                        "This feature is planned but not yet available in the plugin.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_search_memory(pattern: str, region: str = "all") -> str:
        """
        Search memory for byte pattern.

        Find encryption keys, shellcode, or specific byte sequences.

        Args:
            pattern: Hex bytes to search for (e.g., "90 90 90" for NOPs)
            region: Memory region ("all", "executable", "writable")

        Returns:
            List of addresses where pattern was found

        Example:
            x64dbg_search_memory("90 90 90")  # Find NOP sleds
            x64dbg_search_memory("4D 5A", "executable")  # Find PE headers

        Use Cases:
            - Find encryption keys in memory
            - Locate shellcode (NOP sleds, specific instructions)
            - Search for strings/patterns
            - Find injected code

        Note:
            Requires x64dbg plugin C++ implementation
        """
        try:
            bridge = get_x64dbg_bridge()
            matches = bridge.search_memory(pattern, region)

            if not matches:
                return f"No matches found for pattern: {pattern}"

            result = [
                "Memory Search Results:",
                f"Pattern: {pattern}",
                f"Region: {region}",
                f"Found {len(matches)} match(es)",
                "-" * 60
            ]

            for i, match in enumerate(matches[:50]):  # Limit to 50 results
                addr = match.get("address", "unknown")
                context = match.get("context", "")
                result.append(f"{i+1}. 0x{addr} {context}")

            if len(matches) > 50:
                result.append(f"\n... and {len(matches) - 50} more matches")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_search_memory failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory search requires C++ plugin implementation\n"
                        "This feature is planned but not yet available in the plugin.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    # ── Advanced search tools ────────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_find_assembly(instruction: str, address: str = "", size: int = 0) -> str:
        """
        Search for assembly instruction patterns in memory.

        Find all occurrences of a specific assembly instruction in the debugged binary.

        Args:
            instruction: Assembly instruction pattern (e.g., "push ebp", "call eax", "jmp dword ptr [eax]")
            address: Start address (hex string, optional). Empty = current location.
            size: Number of bytes to search (0 = default x64dbg range)

        Returns:
            Command result from findasm search

        Examples:
            x64dbg_find_assembly("call eax")
            x64dbg_find_assembly("push ebp", address="00401000", size=65536)

        Use Cases:
            - Find all indirect calls (call eax, call [eax])
            - Locate function prologues (push ebp)
            - Find specific instruction patterns for hooking
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.find_assembly(instruction, address=address, size=size)

            lines = [
                "Assembly Search Results:",
                f"Instruction: {instruction}",
            ]
            if address:
                lines.append(f"Start address: 0x{address}")
            if size:
                lines.append(f"Search size: {size:#x}")
            lines.append("-" * 60)
            lines.append(f"Success: {result.get('success', False)}")
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_find_assembly failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_find_guid(address: str = "", size: int = 0) -> str:
        """
        Find GUIDs/UUIDs in memory.

        Scan a memory region for GUID patterns. Useful for identifying
        COM interfaces, class IDs, and protocol identifiers.

        Args:
            address: Start address (hex string, optional). Empty = current location.
            size: Number of bytes to search (0 = default x64dbg range)

        Returns:
            GUIDs found in the specified memory region

        Examples:
            x64dbg_find_guid()
            x64dbg_find_guid(address="00401000", size=327680)

        Use Cases:
            - Identify COM interfaces used by malware
            - Find class IDs for COM object creation
            - Discover protocol/interface identifiers
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.find_guid(address=address, size=size)

            lines = ["GUID Search Results:"]
            if address:
                lines.append(f"Start address: 0x{address}")
            if size:
                lines.append(f"Search size: {size:#x}")
            lines.append("-" * 60)
            lines.append(f"Success: {result.get('success', False)}")
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_find_guid failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_find_module_calls(module: str = "") -> str:
        """
        Find all calls to a specific module.

        Locate inter-module call instructions targeting the specified module.
        Useful for understanding API usage and dependencies.

        Args:
            module: Module name (e.g., "kernel32.dll"). Empty = find all inter-module calls.

        Returns:
            List of call instructions targeting the module

        Examples:
            x64dbg_find_module_calls("kernel32.dll")
            x64dbg_find_module_calls("ws2_32.dll")
            x64dbg_find_module_calls()  # All inter-module calls

        Use Cases:
            - Map all Windows API calls from a binary
            - Find networking calls (ws2_32, wininet, winhttp)
            - Identify crypto library usage
            - Discover process manipulation calls
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.find_module_calls(module=module)

            lines = [
                "Module Call Search Results:",
                f"Module: {module or '(all modules)'}",
                "-" * 60,
                f"Success: {result.get('success', False)}",
            ]
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_find_module_calls failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_find_references_range(address: str, size: int) -> str:
        """
        Find all references within an address range.

        Search for code and data references pointing to addresses within
        the specified range.

        Args:
            address: Start address of range (hex string, required)
            size: Size of range in bytes

        Returns:
            References found within the address range

        Examples:
            x64dbg_find_references_range("00401000", 4096)
            x64dbg_find_references_range("0x00401000", 65536)

        Use Cases:
            - Find all references to a function's code range
            - Identify cross-references to a data section
            - Map references within a specific memory region
        """
        try:
            if not address:
                return "Error: address parameter is required"
            if size <= 0:
                return "Error: size must be a positive integer"

            bridge = get_x64dbg_bridge()
            result = bridge.find_references_range(address, size)

            # Normalize for display
            addr_display = address.strip()
            if not addr_display.lower().startswith("0x"):
                addr_display = f"0x{addr_display}"

            lines = [
                "Reference Range Search Results:",
                f"Range: {addr_display} - {addr_display}+{size:#x}",
                "-" * 60,
                f"Success: {result.get('success', False)}",
            ]
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_find_references_range failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_find_string_references(address: str = "") -> str:
        """
        Find string references in the current module or at an address.

        Locate all references to string constants. Essential for understanding
        program behavior through its string usage.

        Args:
            address: Address or module base (hex string, optional). Empty = current module.

        Returns:
            String references found

        Examples:
            x64dbg_find_string_references()
            x64dbg_find_string_references("00401000")

        Use Cases:
            - Find error messages and debug strings
            - Locate URLs, file paths, registry keys
            - Identify command strings and configuration values
            - Discover encrypted/encoded string references
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.find_string_references(address=address)

            lines = ["String Reference Search Results:"]
            if address:
                lines.append(f"Address: 0x{address}")
            else:
                lines.append("Scope: current module")
            lines.append("-" * 60)
            lines.append(f"Success: {result.get('success', False)}")
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_find_string_references failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_memory_map() -> str:
        """
        Get memory map showing all regions.

        Essential for understanding memory layout and finding code sections.

        Returns:
            List of memory regions with base address, size, permissions, and type

        Example output:
            Memory Map (15 regions):
            ----------------------------------------
            0x00400000  Size: 0x10000   RWX  Image (malware.exe)
            0x76D00000  Size: 0xC0000   R-X  Image (kernel32.dll)
            0x00B00000  Size: 0x1000    RW-  Private (Heap)

        Use Cases:
            - Find executable regions (potential unpacked code)
            - Locate RWX regions (injected code)
            - Understand memory layout
            - Find heap/stack regions

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            regions = bridge.get_memory_map()

            if not regions:
                return "No memory regions found"

            result = [f"Memory Map ({len(regions)} regions):", "-" * 70]

            for region in regions:
                base = region.get("base", "unknown")
                size = region.get("size", "0")
                perms = region.get("permissions", "---")
                reg_type = region.get("type", "unknown")
                module = region.get("module", "")

                size_kb = int(size, 16) // 1024 if size != "0" else 0
                size_str = f"{size} ({size_kb} KB)" if size_kb > 0 else size

                line = f"0x{base:}  Size: {size_str:20}  {perms:4}  {reg_type}"
                if module:
                    line += f" ({module})"
                result.append(line)

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_memory_map failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory map requires C++ plugin implementation\n"
                        "This P0 feature is critical for analysis.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_memory_info(address: str) -> str:
        """
        Get information about memory at specific address.

        Check if address is readable/writable/executable before accessing.

        Args:
            address: Memory address to query (hex string)

        Returns:
            Memory region info including permissions and type

        Example:
            x64dbg_get_memory_info("0x00401000")

        Use Cases:
            - Check if address is valid before reading
            - Verify write permissions before patching
            - Find which module owns an address

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            info = bridge.get_memory_info(address)

            result = [
                f"Memory Info for {address}:",
                "-" * 60,
                f"Base: 0x{info['base']}",
                f"Size: 0x{info['size']:X} ({info['size']} bytes)",
                f"Permissions: {info['permissions']}",
                f"Type: {info['type']}"
            ]

            if info.get("module"):
                result.append(f"Module: {info['module']}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_memory_info failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory info requires C++ plugin implementation\n"
                        "This P1 feature significantly improves workflow.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_instruction(address: str = "") -> str:
        """
        Get current or specific instruction details.

        Know exactly what instruction you're at and analyze it.

        Args:
            address: Optional address (uses current RIP if not specified)

        Returns:
            Instruction details including mnemonic, operands, bytes, type

        Example output:
            Instruction at 0x00401234:
            Bytes: 48 8B 45 08
            Mnemonic: mov
            Operands: rax, [rbp+8]
            Size: 4 bytes
            Type: data_transfer

        Use Cases:
            - Know what instruction you're looking at
            - Analyze instruction type (is it a call? jump? return?)
            - See instruction bytes for pattern matching

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            instr = bridge.get_instruction(address if address else None)

            result = [
                f"Instruction at 0x{instr['address']}:",
                "-" * 60,
                f"Bytes: {instr['bytes']}",
                f"Mnemonic: {instr['mnemonic']}",
                f"Operands: {instr['operands']}",
                f"Size: {instr['size']} bytes"
            ]

            if instr.get("type"):
                result.append(f"Type: {instr['type']}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_instruction failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Get instruction requires C++ plugin implementation\n"
                        "This P0 feature is critical for understanding execution.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_evaluate_expression(expression: str) -> str:
        """
        Evaluate expression to get value.

        Calculate addresses, resolve symbols, dereference pointers.

        Args:
            expression: Expression to evaluate (e.g., "[rsp+8]", "kernel32.CreateFileA", "rax+10")

        Returns:
            Evaluated value and type

        Examples:
            x64dbg_evaluate_expression("[rsp+8]")  # Dereference stack
            x64dbg_evaluate_expression("kernel32.CreateFileA")  # Resolve symbol
            x64dbg_evaluate_expression("rax+10")  # Calculate address

        Use Cases:
            - Calculate addresses dynamically
            - Resolve API symbols to addresses
            - Dereference pointers
            - Evaluate stack/register expressions

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            result_dict = bridge.evaluate_expression(expression)

            if not result_dict.get("valid", False):
                return f"Invalid expression: {expression}"

            result = [
                f"Expression: {expression}",
                "-" * 60,
                f"Value: {result_dict['value']}",
                f"Type: {result_dict['type']}"
            ]

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_evaluate_expression failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Expression evaluation requires C++ plugin implementation\n"
                        "This P0 feature is critical for address calculations.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_comment(address: str, comment: str) -> str:
        """
        Set comment at address.

        Document your findings during analysis.

        Args:
            address: Address for comment
            comment: Comment text

        Returns:
            Confirmation message

        Example:
            x64dbg_set_comment("0x401000", "Entry point - checks debugger")
            x64dbg_set_comment("0x402500", "Decryption routine for C2 address")

        Use Cases:
            - Document what code does
            - Mark important locations
            - Track analysis progress
            - Share findings with team

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_comment(address, comment)

            return f"Comment set at {address}\n\"{comment}\""

        except Exception as e:
            logger.error(f"x64dbg_set_comment failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Set comment requires C++ plugin implementation\n"
                        "This P1 feature improves documentation workflow.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_comment(address: str) -> str:
        """
        Get comment at address.

        Retrieve previously documented findings.

        Args:
            address: Address to query

        Returns:
            Comment text or message if none exists

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            comment = bridge.get_comment(address)

            if not comment:
                return f"No comment at {address}"

            return f"Comment at {address}:\n\"{comment}\""

        except Exception as e:
            logger.error(f"x64dbg_get_comment failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Get comment requires C++ plugin implementation\n"
                        "This P1 feature improves documentation workflow.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_bookmark(address: str) -> str:
        """
        Set bookmark at address.

        Mark important locations for quick navigation during analysis.

        Args:
            address: Address to bookmark

        Returns:
            Confirmation message

        Example:
            x64dbg_set_bookmark("0x401000")
            x64dbg_set_bookmark("0x402500")

        Use Cases:
            - Mark interesting code locations
            - Create navigation points during analysis
            - Tag addresses for later review

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_bookmark(address)

            return f"Bookmark set at {address}"

        except Exception as e:
            logger.error(f"x64dbg_set_bookmark failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Set bookmark requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_bookmark(address: str) -> str:
        """
        Delete bookmark at address.

        Remove a previously set bookmark.

        Args:
            address: Address of bookmark to delete

        Returns:
            Confirmation message

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_bookmark(address)

            return f"Bookmark deleted at {address}"

        except Exception as e:
            logger.error(f"x64dbg_delete_bookmark failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Delete bookmark requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_bookmarks() -> str:
        """
        List all bookmarks.

        View all bookmarked addresses in the debugger.

        Returns:
            Formatted list of all bookmarks

        Use Cases:
            - Review marked locations
            - Navigate between analysis points
            - Export analysis markers

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bookmarks = bridge.list_bookmarks()

            if not bookmarks:
                return "No bookmarks set"

            lines = [f"Bookmarks ({len(bookmarks)}):"]
            lines.append("-" * 40)
            for bm in bookmarks:
                addr = bm.get("address", "unknown")
                module = bm.get("module", "")
                if module:
                    lines.append(f"  {addr}  ({module})")
                else:
                    lines.append(f"  {addr}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_list_bookmarks failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: List bookmarks requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_add_function(start: str, end: str) -> str:
        """
        Define function boundary.

        Tell x64dbg where a function starts and ends for better analysis.

        Args:
            start: Function start address
            end: Function end address

        Returns:
            Confirmation message

        Example:
            x64dbg_add_function("0x401000", "0x401050")
            x64dbg_add_function("0x402000", "0x402200")

        Use Cases:
            - Define functions missed by auto-analysis
            - Correct wrong function boundaries
            - Mark unpacked or decrypted code as functions
            - Improve disassembly listing

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.add_function(start, end)

            return f"Function defined: {start} - {end}"

        except Exception as e:
            logger.error(f"x64dbg_add_function failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Add function requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_function(address: str) -> str:
        """
        Delete function boundary definition.

        Remove a previously defined function boundary.

        Args:
            address: Address within the function to delete

        Returns:
            Confirmation message

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_function(address)

            return f"Function deleted at {address}"

        except Exception as e:
            logger.error(f"x64dbg_delete_function failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Delete function requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_functions() -> str:
        """
        List all defined functions.

        View all function boundaries defined in the debugger.

        Returns:
            Formatted list of all functions with start/end addresses

        Use Cases:
            - Review defined function boundaries
            - Verify auto-analysis results
            - Audit analysis coverage

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            functions = bridge.list_functions()

            if not functions:
                return "No functions defined"

            lines = [f"Functions ({len(functions)}):"]
            lines.append("-" * 60)
            for fn in functions:
                start = fn.get("start", "unknown")
                end = fn.get("end", "unknown")
                name = fn.get("name", "")
                if name:
                    lines.append(f"  {start} - {end}  {name}")
                else:
                    lines.append(f"  {start} - {end}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_list_functions failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: List functions requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_module_imports(module_name: str) -> str:
        """
        Get import address table (IAT) for module.

        See what Windows APIs the malware can call.

        Args:
            module_name: Module name (e.g., "malware.exe", "kernel32.dll")

        Returns:
            List of imported functions with addresses

        Example output:
            Imports for malware.exe (47 functions):
            ----------------------------------------
            kernel32.dll:
              0x00401000  CreateFileA
              0x00401004  WriteFile
              0x00401008  ReadFile

            advapi32.dll:
              0x00401010  RegSetValueExA

        Use Cases:
            - Understand malware capabilities
            - Find interesting API calls to breakpoint
            - Identify suspicious imports
            - Detect IAT hooking

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            imports = bridge.get_module_imports(module_name)

            if not imports:
                return f"No imports found for {module_name}"

            result = [f"Imports for {module_name} ({len(imports)} functions):", "-" * 70]

            # Group by DLL
            by_dll: dict[str, list] = {}
            for imp in imports:
                dll = imp.get("module", "unknown")
                if dll not in by_dll:
                    by_dll[dll] = []
                by_dll[dll].append(imp)

            for dll, funcs in by_dll.items():
                result.append(f"\n{dll}:")
                for func in funcs:
                    addr = func.get("address", "unknown")
                    name = func.get("function", "unknown")
                    result.append(f"  0x{addr}  {name}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_module_imports failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Module imports requires C++ plugin implementation\n"
                        "This P1 feature is essential for capability analysis.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_module_exports(module_name: str) -> str:
        """
        Get export address table (EAT) for module.

        See what functions a DLL provides.

        Args:
            module_name: Module name (e.g., "kernel32.dll")

        Returns:
            List of exported functions with addresses and ordinals

        Use Cases:
            - See available DLL functions
            - Find hooking targets
            - Understand module capabilities

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            exports = bridge.get_module_exports(module_name)

            if not exports:
                return f"No exports found for {module_name}"

            result = [f"Exports for {module_name} ({len(exports)} functions):", "-" * 70]

            for exp in exports:
                addr = exp.get("address", "unknown")
                name = exp.get("name", "unknown")
                ordinal = exp.get("ordinal", "")

                line = f"0x{addr}  {name}"
                if ordinal:
                    line += f" (ordinal {ordinal})"
                result.append(line)

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_module_exports failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Module exports requires C++ plugin implementation\n"
                        "This P1 feature helps with module analysis.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_dump_module(
        module_name: str,
        output_path: str,
        fix_pe: bool = True,
        unmap_sections: bool = True,
        rebuild_iat: bool = False
    ) -> str:
        """
        Dump a module from memory with PE header reconstruction.

        Dumps the specified module from memory and fixes PE headers so the dump
        can be analyzed in IDA, Ghidra, or other tools. Uses pefile library for
        proper PE manipulation.

        Args:
            module_name: Module name (e.g., "ForOps_v17.dll") or base address (e.g., "0x6FE80000")
            output_path: Where to save the dumped module (e.g., "/tmp/dumped.dll")
            fix_pe: Fix PE headers (ImageBase, section characteristics)
            unmap_sections: Convert sections from memory layout to file layout
            rebuild_iat: Attempt to rebuild Import Address Table (experimental)

        Returns:
            Dump status with details about fixes applied

        Examples:
            x64dbg_dump_module("unpacked.dll", "/tmp/dumped.dll")
            x64dbg_dump_module("ForOps_v17.dll", "/tmp/dumped.dll", fix_pe=True, unmap_sections=True)
            x64dbg_dump_module("0x140000000", "/tmp/dump.bin", fix_pe=False)

        Use Cases:
            - Dump unpacked malware after runtime unpacking
            - Extract injected DLLs from memory
            - Save decrypted code regions
            - Analyze memory-only payloads
            - Create analyzable dumps from packed binaries

        PE Reconstruction Features:
            - ImageBase updated to match memory location
            - Section alignment: converts memory layout (0x1000) to file layout (0x200)
            - Section characteristics preserved
            - Import/export tables preserved
            - Optional IAT validation and reconstruction

        Output Format:
            {
                "success": True,
                "output_path": "/tmp/dumped.dll",
                "original_base": "0x6FE80000",
                "size": 1258496,
                "sections_fixed": 5,
                "imports_rebuilt": False,
                "warnings": []
            }
        """
        # Security: Validate output path to prevent directory traversal
        try:
            DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            out_path = Path(output_path)
            # If relative path, resolve within dump directory
            if not out_path.is_absolute():
                out_path = DUMP_OUTPUT_DIR / out_path
            safe_path = sanitize_output_path(out_path, DUMP_OUTPUT_DIR)
        except PathTraversalError as e:
            return f"Error: Invalid output path - {e}"
        except ValueError as e:
            return f"Error: Invalid path - {e}"

        try:
            bridge = get_x64dbg_bridge()

            # Call the bridge method which handles PE reconstruction
            result = bridge.dump_module(
                module_name=module_name,
                output_path=str(safe_path),
                fix_pe=fix_pe,
                unmap_sections=unmap_sections,
                rebuild_iat=rebuild_iat
            )

            # Format output for user
            output = []

            if result["success"]:
                output.append("Module dumped successfully")
                output.append("")
                output.append(f"Output path: {result['output_path']}")
                output.append(f"Original base: {result['original_base']}")
                output.append(f"Size: {result['size']} bytes ({result['size'] / 1024:.1f} KB)")

                if result["sections_fixed"] > 0:
                    output.append(f"Sections fixed: {result['sections_fixed']}")

                if result["imports_rebuilt"]:
                    output.append("IAT validated: Yes")

                # Show warnings
                if result["warnings"]:
                    output.append("")
                    output.append("Warnings:")
                    for warning in result["warnings"]:
                        output.append(f"  - {warning}")

                output.append("")
                output.append("PE fixes applied:")
                if fix_pe:
                    output.append("  - ImageBase updated to match memory location")
                if unmap_sections:
                    output.append("  - Sections converted from memory to file layout")
                if rebuild_iat:
                    output.append("  - IAT validation attempted")

                output.append("")
                output.append("Next steps:")
                output.append("  1. Open in IDA/Ghidra for static analysis")
                output.append("  2. Use analyze_binary() to scan with Ghidra")
                output.append("  3. If imports are broken, use external tools like Scylla/ImpREC")
            else:
                output.append("Module dump failed")
                if result["warnings"]:
                    for warning in result["warnings"]:
                        output.append(f"  - {warning}")

            return "\n".join(output)

        except RuntimeError as e:
            logger.error(f"x64dbg_dump_module failed: {e}")
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_dump_module failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_hardware_bp(address: str, bp_type: str = "execute", size: int = 1) -> str:
        """
        Set hardware breakpoint using debug registers.

        Stealth breakpoints that anti-debug malware can't detect via INT3 checks.

        Args:
            address: Address for breakpoint
            bp_type: Type ("execute", "read", "write", "access")
            size: Size in bytes (1, 2, 4, 8) - for memory breakpoints

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_hardware_bp("0x401000", "execute")  # Break on execution
            x64dbg_set_hardware_bp("0x500000", "write", 4)  # Break on 4-byte write

        Use Cases:
            - Bypass INT3 detection (malware scanning for 0xCC bytes)
            - Set breakpoints on APIs without modifying code
            - Monitor memory access (read/write breakpoints)
            - Limited to 4 total hardware breakpoints (DR0-DR7)

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_hardware_breakpoint(address, bp_type, size)

            return (f"Hardware breakpoint set\n"
                    f"Address: {address}\n"
                    f"Type: {bp_type}\n"
                    f"Size: {size} bytes\n\n"
                    f"Note: Maximum 4 hardware breakpoints can be active.")

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_hardware_bp failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_hardware_breakpoint")
        except ValueError as e:
            logger.error(f"x64dbg_set_hardware_bp parameter validation failed: {e}")
            return (
                f"Error: Invalid parameter\n"
                f"Details: {e}\n\n"
                f"Valid types: execute, read, write, access\n"
                f"Valid sizes: 1, 2, 4, 8"
            )
        except Exception as e:
            logger.error(f"x64dbg_set_hardware_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Hardware breakpoints require C++ plugin implementation\n"
                        "This P1 feature is essential for anti-debug bypass.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return format_error_response(e, "set_hardware_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_register(register: str, value: str) -> str:
        """
        Set register value.

        Modify CPU register contents.

        Args:
            register: Register name (e.g., "rax", "eip", "rsp", "rflags")
            value: New value (hex string, e.g., "0x401000" or "401000")

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_register("rip", "0x401000")  # Jump to address
            x64dbg_set_register("rax", "0")         # Clear RAX
            x64dbg_set_register("rflags", "0x246")  # Modify flags

        Use Cases:
            - Modify execution flow (change RIP)
            - Manipulate function parameters
            - Control conditional branches (modify flags)
            - Patch register values for testing

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_register(register, value)

            return f"Register {register.upper()} set to {value}"

        except Exception as e:
            logger.error(f"x64dbg_set_register failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Set register requires C++ plugin implementation\n"
                        "This P0 feature is critical for register manipulation.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_skip(count: int = 1) -> str:
        """
        Skip N instructions without executing them.

        Advance RIP past instructions without running them.

        Args:
            count: Number of instructions to skip (default: 1)

        Returns:
            Confirmation with new address

        Examples:
            x64dbg_skip(1)   # Skip one instruction
            x64dbg_skip(10)  # Skip 10 instructions

        Use Cases:
            - Skip anti-debug checks
            - Bypass problematic code
            - Skip over loops
            - Avoid crashes during analysis

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.skip_instruction(count)

            location = bridge.get_current_location()
            return f"Skipped {count} instruction(s)\nCurrent address: 0x{location['address']}"

        except Exception as e:
            logger.error(f"x64dbg_skip failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Skip instruction requires C++ plugin implementation\n"
                        "This P1 feature is useful for bypassing code.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_until_return() -> str:
        """
        Run until current function returns.

        Execute until RET instruction encountered.

        Returns:
            Execution state after return

        Use Cases:
            - Skip to end of function
            - Bypass complex function internals
            - Return from function quickly

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.run_until_return()

            return f"Returned from function\nAddress: 0x{result['address']}\nState: {result['state']}"

        except Exception as e:
            logger.error(f"x64dbg_run_until_return failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Run until return requires C++ plugin implementation\n"
                        "This P1 feature speeds up function analysis.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_to_user_code() -> str:
        """
        Run to user code (skip system/library code).

        Executes until the debugger pauses in a user module, skipping past
        system DLLs and library code. Useful after hitting a breakpoint in
        ntdll or kernel32 to quickly return to the analysed binary's code.

        Returns:
            Current location after pausing in user code

        Use Cases:
            - Skip past system library calls
            - Return to main module after exception handlers
            - Navigate to user code from entry point
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.run_to_user_code()

            if not result.get("success"):
                return f"Error: {result.get('error', 'Timeout waiting for user code')}"

            lines = [
                "Paused in user code",
                f"Address: 0x{result['address']}",
                f"Module: {result.get('module', 'unknown')}",
                f"Wait time: {result.get('elapsed_ms', 0)}ms",
            ]
            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_run_to_user_code failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_undo_instruction() -> str:
        """
        Undo the last executed instruction.

        Reverses the effect of the last single-stepped instruction using
        x64dbg's InstrUndo command. Useful for correcting accidental steps
        or re-examining state before an instruction executed.

        Returns:
            New execution state after undo

        Use Cases:
            - Undo accidental step-into
            - Re-examine state before instruction
            - Reverse single-step for analysis
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.undo_instruction()

            location = bridge.get_current_location()
            lines = [
                "Instruction undone",
                f"Current address: 0x{location.get('address', 'unknown')}",
                f"Module: {location.get('module', 'unknown')}",
            ]
            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_undo_instruction failed: {e}")
            return f"Error: {e}"

    # Security: allowlist of safe x64dbg command prefixes.
    # Only commands starting with these words are permitted through execute_command.
    # This prevents arbitrary code execution via ScriptDll, loadlib, savedata, etc.
    # Internal bridge methods (watches, types, trace, etc.) bypass this check since
    # they construct commands from validated parameters with known-safe prefixes.
    _ALLOWED_COMMAND_PREFIXES = frozenset({
        # Analysis & navigation
        "dis", "dis.prev", "dis.next", "dis.iscall", "dis.isbranch",
        "findall", "find", "findmem", "findallmem",
        "log", "msg",
        "graph", "graphit",
        # Breakpoint listing/info (setting is handled by dedicated tools)
        "bplist", "bphitcount",
        # Analysis commands
        "cfanalyze", "analxrefs", "analrecur", "analadv", "analyse",
        "exhandlers", "exinfo",
        "rtu",
        "instrundo",
        # Search & reference
        "ref", "refstr", "refsearch", "refinfo",
        "modcallfind",
        # Expression evaluation (read-only)
        "eval",
        # Labels and comments (annotation, not code exec)
        "lbl", "lblset", "lbldel", "lbllist",
        "cmt", "cmtset", "cmtdel", "cmtlist",
        # Bookmarks
        "bm", "bmset", "bmdel", "bmlist",
        # Variable inspection (read-only)
        "varlist", "var",
        # Type system
        "addstruct", "addunion", "addmember", "addtype",
        "visittype", "sizeoftype", "removetype",
        "enumtypes", "cleartypes", "loadtypes", "parsetypes",
        # Watch expressions
        "addwatch", "delwatch", "setwatchdog",
        "setwatchexpression", "setwatchname",
        # DLL breakpoints
        "bpdll", "bcdll", "bpedll", "bpddll",
        # Trace configuration (setting trace params, not loading code)
        "tracesetcommand", "tracesetlog", "tracesetlogfile",
        "tracesetcondition",
        # Dump/view (read-only inspection)
        "dump", "sdump",
    })

    @app.tool()
    @log_dynamic_tool
    def x64dbg_execute_command(command: str) -> str:
        """
        Execute a generic x64dbg command.

        Sends a command string to x64dbg for execution. Only commands from
        a curated allowlist of safe analysis/navigation commands are permitted.
        Commands that could load external code (ScriptDll, loadlib), write
        arbitrary files (savedata), or disrupt the session (quit, detach)
        are rejected.

        Args:
            command: x64dbg command string (e.g. "dis.prev(rip, 5)", "findall 0, E8")

        Returns:
            Command execution result

        Use Cases:
            - Run analysis commands not covered by other tools
            - Navigate disassembly
            - Search for patterns and references

        Examples:
            x64dbg_execute_command("dis.prev(rip, 5)")
            x64dbg_execute_command("findall 0, E8")
            x64dbg_execute_command("log \\"hello\\"")
        """
        try:
            if not command or not command.strip():
                return "Error: Command cannot be empty"

            # Security: only allow commands from the curated safe allowlist.
            # Extract the command name (first word, before any space/paren/comma).
            cmd_stripped = command.strip()
            # Handle commands like "dis.prev(rip, 5)" -> "dis.prev"
            first_token = cmd_stripped.split()[0].split("(")[0].split(",")[0].lower()
            if first_token not in _ALLOWED_COMMAND_PREFIXES:
                return (
                    f"Error: Command '{first_token}' is not in the allowed command list. "
                    f"Only safe analysis and navigation commands are permitted. "
                    f"Use dedicated tools (x64dbg_set_breakpoint, x64dbg_read_memory, etc.) "
                    f"for other operations."
                )

            bridge = get_x64dbg_bridge()
            result = bridge.execute_command(command.strip())

            lines = [
                f"Command executed: {command.strip()}",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("message"):
                lines.append(f"Result: {result['message']}")
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_execute_command failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_memory_bp(address: str, bp_type: str = "access", size: int = 1) -> str:
        """
        Set memory breakpoint.

        Break on memory access/read/write/execute. For large ranges (>4096 bytes),
        automatically splits into multiple breakpoints for reliability.

        Args:
            address: Memory address
            bp_type: Type ("access", "read", "write", "execute")
            size: Size in bytes (positive integer)

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_memory_bp("0x500000", "write", 4)    # Break on 4-byte write
            x64dbg_set_memory_bp("0x401000", "access", 1)   # Break on any access
            x64dbg_set_memory_bp("0x600000", "read", 8)     # Break on 8-byte read
            x64dbg_set_memory_bp("0x089A9020", "write", 4096)  # Auto-splits large range

        Use Cases:
            - Monitor variable changes (write breakpoint)
            - Track memory access patterns
            - Find where data is used (read breakpoint)
            - Detect code execution in data regions
            - Monitor decryption buffers (large write breakpoint)

        Note:
            For ranges >4096 bytes, breakpoints are auto-split for reliability.
            Hardware breakpoints are limited to 1/2/4/8 bytes by CPU.
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.set_memory_breakpoint(address, bp_type, size)

            output = [
                f"Memory breakpoint{'s' if result['breakpoints_set'] > 1 else ''} set",
                f"Address: {address}",
                f"Type: {bp_type}",
                f"Size: {size} bytes",
                f"Breakpoints created: {result['breakpoints_set']}"
            ]

            # Include warning if present
            if result.get("warning"):
                output.append("")
                output.append(f"Warning: {result['warning']}")

            # If split into multiple, show addresses
            if result['breakpoints_set'] > 1:
                output.append("")
                output.append("Breakpoint addresses:")
                for addr in result.get("addresses", [])[:10]:  # Limit to first 10
                    output.append(f"  - {addr}")
                if len(result.get("addresses", [])) > 10:
                    output.append(f"  ... and {len(result['addresses']) - 10} more")

            return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_memory_bp failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_memory_breakpoint")
        except ValueError as e:
            logger.error(f"x64dbg_set_memory_bp parameter validation failed: {e}")
            return (
                f"Error: Invalid parameter\n"
                f"Details: {e}\n\n"
                f"Valid types: access, read, write, execute\n"
                f"Size must be a positive integer"
            )
        except Exception as e:
            logger.error(f"x64dbg_set_memory_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory breakpoints require C++ plugin implementation\n"
                        "This P0 feature is essential for monitoring memory access.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return format_error_response(e, "set_memory_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_memory_bp(address: str) -> str:
        """
        Delete memory breakpoint.

        Remove memory breakpoint at address.

        Args:
            address: Address of breakpoint to delete

        Returns:
            Confirmation message

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_memory_breakpoint(address)

            return f"Memory breakpoint deleted at {address}"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_delete_memory_bp failed: {e.structured_error.error.value}")
            return format_error_response(e, "delete_memory_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_delete_memory_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Delete memory breakpoint requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return format_error_response(e, "delete_memory_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_hide_debugger() -> str:
        """
        Hide debugger presence in Process Environment Block.

        Bypass IsDebuggerPresent and PEB-based anti-debug checks.

        Returns:
            Confirmation message

        Use Cases:
            - Analyze anti-debug malware
            - Bypass IsDebuggerPresent checks
            - Hide from PEB.BeingDebugged checks
            - Essential for modern ransomware/packers

        Anti-Debug Techniques Bypassed:
            - IsDebuggerPresent() API
            - PEB.BeingDebugged flag
            - PEB.NtGlobalFlag checks

        Priority: P0 (Critical - Anti-Debug)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.hide_debugger_peb()

            return ("Debugger hidden in PEB\n\n"
                    "Bypassed:\n"
                    "- IsDebuggerPresent()\n"
                    "- PEB.BeingDebugged\n"
                    "- PEB.NtGlobalFlag\n\n"
                    "Note: Does not bypass all anti-debug techniques.\n"
                    "Some malware uses additional checks (timing, exceptions, etc.)")

        except Exception as e:
            logger.error(f"x64dbg_hide_debugger failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Hide debugger requires C++ plugin implementation\n"
                        "This P0 feature is CRITICAL for anti-debug malware.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_apply_antidebug_bypass(
        profile: str = "standard",
        hide_peb: bool = True,
        patch_ntquery: bool = True,
        fix_heap_flags: bool = True,
        hide_threads: bool = False
    ) -> str:
        """
        Apply pre-configured anti-anti-debug bypass profile.

        Patches multiple anti-debug checks to allow debugging of protected malware.

        Args:
            profile: Bypass profile to apply:
                - "minimal": PEB only (fastest, least invasive)
                - "standard": PEB + NtQuery + Heap (recommended)
                - "aggressive": All checks + timing (for heavily protected samples)
                - "custom": Use individual option flags below
            hide_peb: Patch PEB.BeingDebugged and NtGlobalFlag
            patch_ntquery: Hook NtQueryInformationProcess for debug port checks
            fix_heap_flags: Patch heap debug flags
            hide_threads: Hide debugger threads from enumeration

        Returns:
            Summary of applied bypasses

        Examples:
            x64dbg_apply_antidebug_bypass("standard")  # Recommended for most malware
            x64dbg_apply_antidebug_bypass("aggressive")  # For Themida/VMProtect
            x64dbg_apply_antidebug_bypass("custom", hide_peb=True, patch_ntquery=True)

        Anti-Debug Techniques Bypassed:
            Minimal:
                - IsDebuggerPresent() / PEB.BeingDebugged
                - PEB.NtGlobalFlag checks

            Standard (adds):
                - NtQueryInformationProcess (ProcessDebugPort, ProcessDebugFlags)
                - CheckRemoteDebuggerPresent()
                - Heap flags (ProcessHeap.Flags, ForceFlags)

            Aggressive (adds):
                - Thread hiding (GetThreadContext detection)
                - x64dbg's full hiding mechanism
        """
        try:
            bridge = get_x64dbg_bridge()
            results = []
            bypasses_applied = []

            # Define profile settings
            profiles = {
                "minimal": {"peb": True, "ntquery": False, "heap": False, "threads": False},
                "standard": {"peb": True, "ntquery": True, "heap": True, "threads": False},
                "aggressive": {"peb": True, "ntquery": True, "heap": True, "threads": True},
                "custom": {"peb": hide_peb, "ntquery": patch_ntquery, "heap": fix_heap_flags, "threads": hide_threads}
            }

            if profile not in profiles:
                return f"Error: Unknown profile '{profile}'. Valid: minimal, standard, aggressive, custom"

            settings = profiles[profile]

            # Apply PEB bypass
            if settings["peb"]:
                try:
                    bridge.hide_debugger_peb()
                    bypasses_applied.append("PEB.BeingDebugged")
                    bypasses_applied.append("PEB.NtGlobalFlag")
                    results.append("PEB bypass applied")
                except Exception as e:
                    results.append(f"PEB bypass failed: {e}")

            # Apply full bypass (includes NtQuery and heap)
            if settings["ntquery"] or settings["heap"] or settings["threads"]:
                try:
                    bridge.hide_debugger_full()
                    if settings["ntquery"]:
                        bypasses_applied.append("NtQueryInformationProcess")
                        bypasses_applied.append("CheckRemoteDebuggerPresent")
                    if settings["heap"]:
                        bypasses_applied.append("ProcessHeap.Flags")
                        bypasses_applied.append("ProcessHeap.ForceFlags")
                    if settings["threads"]:
                        bypasses_applied.append("Thread enumeration hiding")
                    results.append("Full bypass applied")
                except Exception as e:
                    results.append(f"Full bypass failed: {e}")

            # Format output
            output = [
                f"Anti-debug bypass applied (profile: {profile})",
                "",
                "Techniques bypassed:"
            ]
            for bypass in bypasses_applied:
                output.append(f"  - {bypass}")

            output.append("")
            output.append("Results:")
            for result in results:
                output.append(f"  - {result}")

            output.append("")
            output.append("Note: Run target to verify bypass effectiveness.")
            output.append("Some packers may use additional checks (timing, exceptions).")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_apply_antidebug_bypass failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Anti-debug bypass requires C++ plugin implementation\n"
                        "This feature needs plugin support for memory patching.")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_antidebug_status() -> str:
        """
        Query current anti-debug bypass status.

        Check which anti-debug bypasses are currently active.

        Returns:
            Status of each anti-debug bypass mechanism

        Use Cases:
            - Verify bypasses are applied before analysis
            - Debug issues with malware detection
            - Check if bypasses were reset after module load
        """
        try:
            bridge = get_x64dbg_bridge()
            status = bridge.get_antidebug_status()

            output = ["Anti-debug bypass status:", ""]

            # Format status items
            status_items = [
                ("PEB.BeingDebugged patched", status.get("peb_patched", False)),
                ("NtGlobalFlag patched", status.get("ntglobalflag_patched", False)),
                ("Heap flags patched", status.get("heap_patched", False)),
                ("Timing functions hooked", status.get("timing_hooked", False)),
                ("Thread hiding active", status.get("threads_hidden", False)),
            ]

            for name, active in status_items:
                icon = "+" if active else "-"
                state = "Active" if active else "Not applied"
                output.append(f"  [{icon}] {name}: {state}")

            # Summary
            active_count = sum(1 for _, active in status_items if active)
            output.append("")
            output.append(f"Active bypasses: {active_count}/{len(status_items)}")

            if active_count == 0:
                output.append("")
                output.append("Tip: Use x64dbg_apply_antidebug_bypass() to enable bypasses")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_antidebug_status failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Anti-debug status requires C++ plugin implementation")
            return f"Error: {e}"

    # =========================================================================
    # Event System Tools
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_events(max_events: int = 50) -> str:
        """
        Get pending debug events from the event queue.

        The event system captures debug events as they occur:
        - breakpoint_hit: Breakpoint was triggered
        - exception: Exception occurred
        - paused: Debugger paused
        - running: Debugger resumed
        - stepped: Single step completed
        - process_started: Process created
        - process_exited: Process terminated
        - thread_created: New thread created
        - thread_exited: Thread terminated
        - module_loaded: DLL/module loaded
        - module_unloaded: DLL/module unloaded
        - debug_string: OutputDebugString message

        Args:
            max_events: Maximum number of events to return (default: 50)

        Returns:
            List of debug events with details

        Example:
            x64dbg_run()
            # ... wait for execution ...
            x64dbg_get_events()  # See what happened
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.get_events(max_events=max_events)

            events = result.get("events", [])
            queue_size = result.get("queue_size", 0)

            if not events:
                return f"No events in queue (queue size: {queue_size})"

            output = [
                f"Debug Events ({len(events)} returned, {queue_size} remaining):",
                "-" * 60
            ]

            for event in events:
                event_id = event.get("id", "?")
                event_type = event.get("type", "unknown")
                timestamp = event.get("timestamp", 0)
                address = event.get("address", "0")
                thread_id = event.get("thread_id", 0)
                module = event.get("module", "")
                details = event.get("details", "")

                line = f"[{event_id}] {event_type}"
                if address != "0":
                    line += f" @ 0x{address}"
                if thread_id:
                    line += f" (thread {thread_id})"
                if module:
                    line += f" [{module}]"
                line += f" +{timestamp}ms"

                output.append(line)
                if details:
                    output.append(f"    {details}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_events failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_clear_events() -> str:
        """
        Clear all pending events from the event queue.

        Use this before starting a new analysis to get a clean event history.

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.clear_events()
            return "Event queue cleared"

        except Exception as e:
            logger.error(f"x64dbg_clear_events failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_event_status() -> str:
        """
        Get event system status.

        Shows whether event collection is enabled and queue size.

        Returns:
            Event system status information
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.get_event_status()

            enabled = result.get("enabled", False)
            queue_size = result.get("queue_size", 0)
            next_id = result.get("next_event_id", 0)

            return (
                f"Event System Status:\n"
                f"  Enabled: {enabled}\n"
                f"  Queue Size: {queue_size}\n"
                f"  Next Event ID: {next_id}"
            )

        except Exception as e:
            logger.error(f"x64dbg_event_status failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_until_event(
        event_types: str = "breakpoint_hit,exception,paused",
        timeout_seconds: int = 30
    ) -> str:
        """
        Run execution and wait for a specific event type.

        This is the recommended way to run and wait for events.
        More reliable than run_and_wait() for complex scenarios.

        Args:
            event_types: Comma-separated event types to wait for
                        Default: "breakpoint_hit,exception,paused"
            timeout_seconds: Maximum wait time (default: 30 seconds)

        Returns:
            Event details when triggered, or timeout message

        Example:
            x64dbg_set_breakpoint("0x401000")
            x64dbg_run_until_event("breakpoint_hit", 60)

        Event Types:
            - breakpoint_hit: Breakpoint triggered
            - exception: Exception occurred
            - paused: Debugger paused (any reason)
            - system_breakpoint: Initial break on load
            - stepped: Single step completed
        """
        try:
            bridge = get_x64dbg_bridge()

            # Parse event types
            types_list = [t.strip() for t in event_types.split(",")]

            result = bridge.run_until_event(
                event_types=types_list,
                timeout=timeout_seconds * 1000
            )

            if result.get("success"):
                event = result.get("event", {})
                event_type = event.get("type", "unknown")
                address = event.get("address", "0")
                details = event.get("details", "")

                output = (
                    f"Event received: {event_type}\n"
                    f"Address: 0x{address}\n"
                )
                if details:
                    output += f"Details: {details}\n"

                output += "\nUse x64dbg_get_registers() to inspect state."
                return output
            else:
                error = result.get("error", "Unknown error")
                return f"Timeout waiting for events\n{error}"

        except Exception as e:
            logger.error(f"x64dbg_run_until_event failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # Memory Allocation Tools (Phase 3)
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_alloc_memory(size: int = 4096, address: str = "") -> str:
        """
        Allocate memory in the debugee's address space.

        Uses VirtualAllocEx to allocate memory with read/write permissions.
        Useful for injecting shellcode, storing analysis data, or code patches.

        Args:
            size: Number of bytes to allocate (default: 4096 = one page)
            address: Optional preferred address (hex string). If empty, OS chooses.

        Returns:
            Address of allocated memory region

        Examples:
            x64dbg_alloc_memory(4096)  # Allocate one page
            x64dbg_alloc_memory(0x10000, "0x10000000")  # 64KB at preferred address

        Use Cases:
            - Allocate memory for shellcode injection
            - Create scratch space for analysis data
            - Store patched code before writing to original location
            - Allocate buffers for hooking trampolines

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.virt_alloc(size, address if address else None)

            if result.get("success"):
                alloc_addr = result.get("address", "unknown")
                alloc_size = result.get("size", size)
                return (
                    f"Memory allocated successfully\n"
                    f"Address: 0x{alloc_addr}\n"
                    f"Size: {alloc_size} bytes ({alloc_size // 1024} KB)\n\n"
                    f"Use x64dbg_write_memory() to write data to this region."
                )
            else:
                return f"Failed to allocate memory: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_alloc_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_free_memory(address: str) -> str:
        """
        Free memory allocated in the debugee's address space.

        Args:
            address: Address of memory to free (hex string)

        Returns:
            Confirmation message

        Example:
            x64dbg_free_memory("0x12340000")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.virt_free(address)

            if result.get("success"):
                return f"Memory freed at {address}"
            else:
                return f"Failed to free memory: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_free_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_protect_memory(address: str, protection: str, size: int = 4096) -> str:
        """
        Change memory protection.

        Modify page permissions for a memory region. Essential for:
        - Making code regions writable for patching
        - Making data regions executable for shellcode
        - Restoring original permissions after patching

        Args:
            address: Address of memory region (hex string)
            protection: New protection string:
                - "rwx": Read/Write/Execute
                - "rx": Read/Execute
                - "rw": Read/Write
                - "r": Read only
                - "x": Execute only
                - "n" or "none": No access
            size: Size of region to change (default: 4096)

        Returns:
            Confirmation message

        Examples:
            # Make code region writable for patching
            x64dbg_protect_memory("0x401000", "rwx", 0x1000)
            x64dbg_write_memory("0x401000", "90909090")  # Write NOPs
            x64dbg_protect_memory("0x401000", "rx", 0x1000)  # Restore

        Use Cases:
            - Patch code in .text section (needs writable)
            - Execute shellcode in data region (needs executable)
            - Protect sensitive data from reading

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.virt_protect(address, protection, size)

            if result.get("success"):
                return (
                    f"Memory protection changed\n"
                    f"Address: 0x{result.get('address', address)}\n"
                    f"Protection: {protection}\n"
                    f"Size: {size} bytes"
                )
            else:
                return f"Failed to change protection: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_protect_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_memset(address: str, value: int, size: int) -> str:
        """
        Fill memory with a byte value.

        Write repeated byte values to memory - useful for clearing buffers,
        writing NOP sleds, or initializing memory regions.

        Args:
            address: Start address (hex string)
            value: Byte value to fill (0-255)
            size: Number of bytes to fill

        Returns:
            Confirmation message

        Examples:
            # Zero out a buffer
            x64dbg_memset("0x12340000", 0, 1024)

            # Fill with NOPs (0x90) for NOP sled
            x64dbg_memset("0x401000", 0x90, 100)

            # Fill with INT3 (0xCC) for breakpoint trap
            x64dbg_memset("0x401000", 0xCC, 10)

        Use Cases:
            - Clear memory before writing shellcode
            - Create NOP sleds for shellcode alignment
            - Fill regions with INT3 to catch unexpected execution
            - Zero out sensitive data

        Priority: P1 (High Value)
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.memset(address, value, size)

            if result.get("success"):
                return (
                    f"Memory filled\n"
                    f"Address: 0x{result.get('address', address)}\n"
                    f"Value: 0x{value & 0xFF:02X}\n"
                    f"Size: {size} bytes"
                )
            else:
                return f"Failed to fill memory: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_memset failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_check_memory(address: str) -> str:
        """
        Check if address is a valid readable memory address.

        Use before reading memory to avoid errors.

        Args:
            address: Address to check (hex string)

        Returns:
            Validity status

        Example:
            x64dbg_check_memory("0x401000")
            # If valid, then:
            x64dbg_read_memory("0x401000", 16)
        """
        try:
            bridge = get_x64dbg_bridge()
            is_valid = bridge.check_valid_read_ptr(address)

            if is_valid:
                return f"Address {address} is valid and readable"
            else:
                return f"Address {address} is NOT valid (not mapped or not readable)"

        except Exception as e:
            logger.error(f"x64dbg_check_memory failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # Enhanced Breakpoint Tools (Phase 3)
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_toggle_breakpoint(address: str, enable: bool = True) -> str:
        """
        Enable or disable a software breakpoint without deleting it.

        Temporarily disable breakpoints to skip them, then re-enable later.
        More efficient than delete/recreate for frequently toggled BPs.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Confirmation message

        Example:
            x64dbg_set_breakpoint("0x401000")
            x64dbg_toggle_breakpoint("0x401000", False)  # Temporarily disable
            x64dbg_run()
            x64dbg_toggle_breakpoint("0x401000", True)   # Re-enable
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.toggle_breakpoint(address, enable)

            if result.get("success"):
                status = "enabled" if enable else "disabled"
                return f"Breakpoint at {address} {status}"
            else:
                return f"Failed to toggle breakpoint: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_toggle_breakpoint failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_hardware_bp(address: str) -> str:
        """
        Delete a hardware breakpoint.

        Frees up one of the 4 hardware breakpoint slots.

        Args:
            address: Breakpoint address (hex string)

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.delete_hardware_breakpoint(address)

            if result.get("success"):
                return f"Hardware breakpoint deleted at {address}"
            else:
                return f"Failed to delete hardware breakpoint: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_delete_hardware_bp failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_toggle_hardware_bp(address: str, enable: bool = True) -> str:
        """
        Enable or disable a hardware breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.toggle_hardware_breakpoint(address, enable)

            if result.get("success"):
                status = "enabled" if enable else "disabled"
                return f"Hardware breakpoint at {address} {status}"
            else:
                return f"Failed to toggle hardware breakpoint: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_toggle_hardware_bp failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_toggle_memory_bp(address: str, enable: bool = True) -> str:
        """
        Enable or disable a memory breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.toggle_memory_breakpoint(address, enable)

            if result.get("success"):
                status = "enabled" if enable else "disabled"
                return f"Memory breakpoint at {address} {status}"
            else:
                return f"Failed to toggle memory breakpoint: {result.get('error', 'Unknown error')}"

        except Exception as e:
            logger.error(f"x64dbg_toggle_memory_bp failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_all_breakpoints() -> str:
        """
        List all breakpoints of all types (software, hardware, memory).

        Comprehensive view of all active breakpoints in the debugger.

        Returns:
            Categorized list of all breakpoints with their status

        Example output:
            All Breakpoints:
            ================

            Software Breakpoints (3):
              0x00401000  enabled  (single-shot: no)
              0x00401234  disabled (single-shot: no)
              0x00405000  enabled  (single-shot: yes)

            Hardware Breakpoints (1):
              0x00500000  enabled  type=write  size=4

            Memory Breakpoints (0):
              (none)
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.list_all_breakpoints()

            if not result.get("success"):
                return f"Failed to list breakpoints: {result.get('error', 'Unknown error')}"

            bps = result.get("breakpoints", {})
            software = bps.get("software", [])
            hardware = bps.get("hardware", [])
            memory = bps.get("memory", [])

            output = ["All Breakpoints:", "=" * 60, ""]

            # Software breakpoints
            output.append(f"Software Breakpoints ({len(software)}):")
            if software:
                for bp in software:
                    addr = bp.get("address", "unknown")
                    enabled = "enabled" if bp.get("enabled") else "disabled"
                    singleshot = "yes" if bp.get("singleshoot") else "no"
                    output.append(f"  0x{addr}  {enabled:8}  (single-shot: {singleshot})")
            else:
                output.append("  (none)")

            output.append("")

            # Hardware breakpoints
            output.append(f"Hardware Breakpoints ({len(hardware)}):")
            if hardware:
                for bp in hardware:
                    addr = bp.get("address", "unknown")
                    enabled = "enabled" if bp.get("enabled") else "disabled"
                    hw_type = bp.get("type", "unknown")
                    size = bp.get("size", 1)
                    output.append(f"  0x{addr}  {enabled:8}  type={hw_type}  size={size}")
            else:
                output.append("  (none)")

            output.append("")

            # Memory breakpoints
            output.append(f"Memory Breakpoints ({len(memory)}):")
            if memory:
                for bp in memory:
                    addr = bp.get("address", "unknown")
                    enabled = "enabled" if bp.get("enabled") else "disabled"
                    bp_type = bp.get("type", "access")
                    output.append(f"  0x{addr}  {enabled:8}  type={bp_type}")
            else:
                output.append("  (none)")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_list_all_breakpoints failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # P2: Conditional Breakpoint Logging
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_conditional_breakpoint(
        address: str,
        condition: str | None = None,
        log_template: str | None = None,
        action: str = "break"
    ) -> str:
        """
        Set a breakpoint with optional condition and logging.

        Sets a breakpoint that can evaluate a condition and log formatted
        messages when hit. Supports three modes: break, log_and_break, log_and_continue.

        Args:
            address: Breakpoint address (hex string, e.g., "0x401000")
            condition: Optional condition expression to evaluate. Breakpoint only
                      triggers if condition evaluates to non-zero.
                      Examples: "rax > 0x1000", "[rsp] == 0x12345678"
            log_template: Optional log message template. Use {reg} for register values.
                         Examples: "CreateFileW: path={rcx:str}", "alloc size={rdx:hex}"
                         Format specifiers:
                           - {reg} or {reg:hex} - hex value
                           - {reg:dec} - decimal value
                           - {reg:str} - dereference as string pointer
                           - {reg:ptr} - dereference as pointer
            action: What to do when condition matches:
                   - "break" - Break execution (default)
                   - "log_and_break" - Log message then break
                   - "log_and_continue" - Log message and continue execution

        Returns:
            Status message with breakpoint configuration

        Example:
            # Break only when rax > 0x1000
            x64dbg_set_conditional_breakpoint("0x401234", condition="rax > 0x1000")

            # Log CreateFileW calls without breaking
            x64dbg_set_conditional_breakpoint(
                "kernel32!CreateFileW",
                log_template="CreateFileW({rcx:str}, {rdx:hex})",
                action="log_and_continue"
            )

            # Log and break when specific value seen
            x64dbg_set_conditional_breakpoint(
                "0x405000",
                condition="[rsp+8] == 0xDEADBEEF",
                log_template="Magic value found! rax={rax:hex}",
                action="log_and_break"
            )

        Note:
            Conditional breakpoints are implemented in software and may have
            slight performance overhead. For high-frequency breakpoints,
            consider using hardware breakpoints with conditions.
        """
        try:
            bridge = get_x64dbg_bridge()

            # Resolve symbol if needed (e.g., "kernel32!CreateFileW")
            if "!" in address or not address.replace("0x", "").replace("0X", "").isalnum():
                result = bridge.resolve_symbol(address)
                if result.get("success"):
                    resolved_addr = result.get("address", address)
                    if not resolved_addr.startswith("0x"):
                        resolved_addr = f"0x{resolved_addr}"
                    address = resolved_addr
                else:
                    return f"Failed to resolve symbol '{address}': {result.get('error', 'Unknown error')}"

            # Set the breakpoint
            bridge.set_breakpoint(address)

            # Store conditional breakpoint metadata in session
            bp_config = {
                "address": address,
                "condition": condition,
                "log_template": log_template,
                "action": action,
                "hit_count": 0,
                "logs": []
            }

            # Store in session manager if available
            if _session_manager and _session_manager.active_session_id:
                # Use session data to track conditional breakpoints
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                if "conditional_breakpoints" not in session_data:
                    session_data["conditional_breakpoints"] = {}
                session_data["conditional_breakpoints"][address] = bp_config

            output = [
                f"Conditional breakpoint set at {address}",
                f"  Condition: {condition if condition else 'None (always triggers)'}",
                f"  Log template: {log_template if log_template else 'None'}",
                f"  Action: {action}",
                "",
                "Note: Use x64dbg_check_conditional_breakpoint() when breakpoint hits",
                "to evaluate condition and generate log entry."
            ]

            return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_conditional_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_conditional_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_set_conditional_breakpoint failed: {e}")
            return format_error_response(e, "set_conditional_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_check_conditional_breakpoint(address: str | None = None) -> str:
        """
        Evaluate condition and generate log for a conditional breakpoint.

        Call this when a breakpoint hits to check if the condition matches
        and generate a formatted log entry. If action is "log_and_continue",
        the debugger will automatically resume execution.

        Args:
            address: Breakpoint address to check. If None, uses current RIP.

        Returns:
            Evaluation result with condition match status and log entry

        Example:
            # Set conditional breakpoint
            x64dbg_set_conditional_breakpoint(
                "0x401234",
                condition="rax > 0x100",
                log_template="Function called: rax={rax:hex}",
                action="log_and_continue"
            )
            x64dbg_run()
            # ... breakpoint hits ...
            x64dbg_check_conditional_breakpoint()  # Evaluates and logs
        """
        try:
            bridge = get_x64dbg_bridge()

            # Get current address if not specified
            if address is None:
                location = bridge.get_current_location()
                address = location.get("address", "0x0")
                if not address.startswith("0x"):
                    address = f"0x{address}"

            # Get conditional breakpoint config from session
            bp_config = None
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                bp_config = session_data.get("conditional_breakpoints", {}).get(address)

            if not bp_config:
                return f"No conditional breakpoint registered at {address}. Use x64dbg_set_conditional_breakpoint() first."

            condition = bp_config.get("condition")
            log_template = bp_config.get("log_template")
            action = bp_config.get("action", "break")

            # Evaluate condition if specified
            condition_matched = True
            condition_result = None
            if condition:
                result = bridge.evaluate_expression(condition)
                if result.get("valid"):
                    # Check if result is non-zero (condition matched)
                    value = result.get("value", "0")
                    if isinstance(value, str):
                        value = int(value, 16) if value.startswith("0x") else int(value)
                    condition_matched = value != 0
                    condition_result = f"0x{value:X}" if isinstance(value, int) else str(value)
                else:
                    return f"Failed to evaluate condition '{condition}': Invalid expression"

            # Generate log entry if condition matched and log template provided
            log_entry = None
            if condition_matched and log_template:
                log_entry = _format_log_template(bridge, log_template)
                bp_config["logs"].append({
                    "entry": log_entry,
                    "address": address,
                    "condition_value": condition_result
                })

            # Update hit count
            bp_config["hit_count"] += 1

            # Build output
            output = [
                f"Conditional breakpoint at {address}:",
                f"  Hit count: {bp_config['hit_count']}",
            ]

            if condition:
                output.append(f"  Condition: {condition} = {condition_result}")
                output.append(f"  Matched: {'Yes' if condition_matched else 'No'}")

            if log_entry:
                output.append(f"  Log: {log_entry}")

            output.append(f"  Action: {action}")

            # Handle action
            if condition_matched:
                if action == "log_and_continue":
                    bridge.run()
                    output.append("")
                    output.append("Execution resumed (log_and_continue)")
                elif action == "log_and_break":
                    output.append("")
                    output.append("Execution paused (log_and_break)")
                # "break" action - already paused, do nothing

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_check_conditional_breakpoint failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_breakpoint_logs(address: str | None = None, limit: int = 50) -> str:
        """
        Get logs from conditional breakpoints.

        Retrieves log entries generated by conditional breakpoints with
        log templates. Optionally filter by specific breakpoint address.

        Args:
            address: Filter logs to specific breakpoint address. If None, show all.
            limit: Maximum number of log entries to return (default: 50)

        Returns:
            Formatted log entries from conditional breakpoints

        Example:
            # Get all logs
            x64dbg_get_breakpoint_logs()

            # Get logs for specific breakpoint
            x64dbg_get_breakpoint_logs(address="0x401234")
        """
        try:
            if not _session_manager or not _session_manager.active_session_id:
                return "No active session. Start debugging first."

            session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
            conditional_bps = session_data.get("conditional_breakpoints", {})

            if not conditional_bps:
                return "No conditional breakpoints registered."

            all_logs = []

            for bp_addr, bp_config in conditional_bps.items():
                if address and bp_addr != address:
                    continue

                for log in bp_config.get("logs", []):
                    all_logs.append({
                        "breakpoint": bp_addr,
                        "entry": log.get("entry", ""),
                        "condition_value": log.get("condition_value")
                    })

            if not all_logs:
                if address:
                    return f"No logs for breakpoint at {address}."
                return "No log entries recorded yet."

            # Limit results
            all_logs = all_logs[-limit:]

            output = [
                f"Breakpoint Logs ({len(all_logs)} entries):",
                "=" * 60,
                ""
            ]

            for i, log in enumerate(all_logs, 1):
                bp = log["breakpoint"]
                entry = log["entry"]
                cond_val = log.get("condition_value", "N/A")
                output.append(f"[{i}] {bp}: {entry}")
                if cond_val:
                    output.append(f"     Condition value: {cond_val}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_breakpoint_logs failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_clear_breakpoint_logs(address: str | None = None) -> str:
        """
        Clear logs from conditional breakpoints.

        Clears accumulated log entries. Optionally clear only for specific address.

        Args:
            address: Clear logs for specific breakpoint. If None, clear all.

        Returns:
            Confirmation message
        """
        try:
            if not _session_manager or not _session_manager.active_session_id:
                return "No active session."

            session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
            conditional_bps = session_data.get("conditional_breakpoints", {})

            if address:
                if address in conditional_bps:
                    conditional_bps[address]["logs"] = []
                    conditional_bps[address]["hit_count"] = 0
                    return f"Cleared logs for breakpoint at {address}"
                return f"No conditional breakpoint at {address}"
            else:
                for bp_config in conditional_bps.values():
                    bp_config["logs"] = []
                    bp_config["hit_count"] = 0
                return f"Cleared logs for {len(conditional_bps)} conditional breakpoints"

        except Exception as e:
            logger.error(f"x64dbg_clear_breakpoint_logs failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # P2: Native Conditional Breakpoint with Logging (Enhanced)
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_conditional_bp(
        address: str,
        condition: str | None = None,
        log_template: str | None = None,
        action: str = "break"
    ) -> str:
        """
        Set a conditional breakpoint with native x64dbg logging support.

        Uses x64dbg's native conditional breakpoint features for better performance
        and automatic logging without manual polling.

        Args:
            address: Breakpoint address (hex string, symbol, or api name)
                    Examples: "0x7670EDC0", "kernel32!CreateFileW", "CreateFileW"
            condition: Break condition expression. Breakpoint triggers only if non-zero.
                      Examples: "rcx > 0x1000", "[rsp] == 0xDEADBEEF", "rax != 0"
            log_template: Log message template using register format specifiers.
                         Format: "text {register:format} more text"
                         Format specifiers:
                           - {rcx:hex} or {rcx} - hex value (default)
                           - {rcx:dec} - decimal value
                           - {rcx:unicode} or {rcx:str} - UTF-16 string pointer
                           - {rcx:ascii} - ASCII string pointer
                           - {rcx:ptr} - dereference pointer
                         Examples:
                           - "CreateFileW: path={rcx:unicode}, access={rdx:hex}"
                           - "VirtualAlloc: addr={rcx:hex}, size={rdx:hex}"
            action: Action to take when breakpoint hits:
                   - "break" - Break execution (default)
                   - "log_and_break" - Log message then break
                   - "log_and_continue" - Log and continue (tracing mode)

        Returns:
            Status message with breakpoint configuration

        Examples:
            # Break only when condition is true
            x64dbg_set_conditional_bp(
                address="0x401234",
                condition="rax > 0x1000"
            )

            # Log CreateFileW calls without breaking
            x64dbg_set_conditional_bp(
                address="0x7670EDC0",
                condition="rcx > 0x1000",
                log_template="CreateFileW called: path={rcx:unicode}, access={rdx:hex}",
                action="log_and_continue"
            )

            # Log and break on specific condition
            x64dbg_set_conditional_bp(
                address="kernel32!VirtualAlloc",
                condition="r9 == 0x40",  # PAGE_EXECUTE_READWRITE
                log_template="Suspicious VirtualAlloc: size={rdx:hex}, protect={r9:hex}",
                action="log_and_break"
            )

        Note:
            Use x64dbg_get_bp_logs() to retrieve logged messages.
        """
        try:
            bridge = get_x64dbg_bridge()

            # Convert log_template format from Python-style to x64dbg format
            # Python: {rcx:unicode} -> x64dbg: {s:rcx}
            x64dbg_log = None
            if log_template:
                x64dbg_log = _convert_log_template_to_x64dbg(log_template)

            # Determine break behavior
            break_on_hit = action != "log_and_continue"
            silent = action == "log_and_continue"

            # Try native conditional breakpoint first
            try:
                result = bridge.set_conditional_breakpoint(
                    address=address,
                    condition=condition,
                    log_text=x64dbg_log,
                    break_on_hit=break_on_hit,
                    fast_resume=not break_on_hit,
                    silent=silent
                )

                output = [
                    f"Conditional breakpoint set at {address}",
                    f"  Condition: {condition if condition else 'None (always triggers)'}",
                    f"  Log template: {log_template if log_template else 'None'}",
                    f"  Action: {action}",
                ]

                if result.get("resolved_address"):
                    output.insert(1, f"  Resolved: 0x{result['resolved_address']}")

                output.extend([
                    "",
                    "Use x64dbg_get_bp_logs() to retrieve logged messages.",
                    "Use x64dbg_run() to start execution."
                ])

                return "\n".join(output)

            except Exception as native_err:
                # Fall back to Python-side implementation
                logger.debug(f"Native conditional BP not available: {native_err}, using fallback")

                # Set regular breakpoint
                bridge.set_breakpoint(address)

                # Store config in session
                bp_config = {
                    "address": address,
                    "condition": condition,
                    "log_template": log_template,
                    "action": action,
                    "hit_count": 0,
                    "logs": [],
                    "native": False
                }

                if _session_manager and _session_manager.active_session_id:
                    session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                    if "conditional_breakpoints" not in session_data:
                        session_data["conditional_breakpoints"] = {}
                    session_data["conditional_breakpoints"][address] = bp_config

                output = [
                    f"Conditional breakpoint set at {address} (fallback mode)",
                    f"  Condition: {condition if condition else 'None (always triggers)'}",
                    f"  Log template: {log_template if log_template else 'None'}",
                    f"  Action: {action}",
                    "",
                    "Note: Using Python-side condition evaluation.",
                    "Call x64dbg_check_conditional_breakpoint() when breakpoint hits."
                ]

                return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_conditional_bp failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_conditional_bp")
        except Exception as e:
            logger.error(f"x64dbg_set_conditional_bp failed: {e}")
            return format_error_response(e, "set_conditional_bp")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_log_api_params(
        api: str,
        log_file: str | None = None,
        max_calls: int = 1000
    ) -> str:
        """
        Set up parameter logging for a Windows API function.

        Creates a breakpoint on the API that automatically logs call parameters
        without breaking execution. Ideal for tracing API usage patterns.

        Args:
            api: API function name
                Examples: "WriteProcessMemory", "CreateFileW", "VirtualAlloc"
                Can also use module!function format: "kernel32!CreateFileW"
            log_file: Optional file path to write logs to
                     Example: "/tmp/wpm_calls.txt"
            max_calls: Maximum number of calls to log (default: 1000)
                      Prevents runaway logging in high-frequency APIs

        Returns:
            Configuration status with API address

        Examples:
            # Log WriteProcessMemory calls to file
            x64dbg_log_api_params(
                api="WriteProcessMemory",
                log_file="/tmp/wpm_calls.txt",
                max_calls=1000
            )

            # Log CreateFileW calls to session storage
            x64dbg_log_api_params(api="CreateFileW")

        Use Cases:
            - Track file operations: CreateFileW, ReadFile, WriteFile
            - Monitor process injection: WriteProcessMemory, VirtualAllocEx
            - Detect network activity: connect, send, recv
            - Track registry changes: RegSetValueExW, RegCreateKeyExW

        Note:
            Use x64dbg_get_bp_logs() to retrieve logged calls.
            Logs are also written to log_file if specified.
        """
        try:
            bridge = get_x64dbg_bridge()

            # API parameter templates for common APIs
            api_templates = {
                # Process/Memory
                "WriteProcessMemory": "WriteProcessMemory: hProc={rcx:hex}, addr={rdx:hex}, buf={r8:hex}, size={r9:hex}",
                "ReadProcessMemory": "ReadProcessMemory: hProc={rcx:hex}, addr={rdx:hex}, buf={r8:hex}, size={r9:hex}",
                "VirtualAlloc": "VirtualAlloc: addr={rcx:hex}, size={rdx:hex}, type={r8:hex}, protect={r9:hex}",
                "VirtualAllocEx": "VirtualAllocEx: hProc={rcx:hex}, addr={rdx:hex}, size={r8:hex}, protect=stack",
                "VirtualProtect": "VirtualProtect: addr={rcx:hex}, size={rdx:hex}, protect={r8:hex}",
                "VirtualProtectEx": "VirtualProtectEx: hProc={rcx:hex}, addr={rdx:hex}, size={r8:hex}",
                "CreateRemoteThread": "CreateRemoteThread: hProc={rcx:hex}, start={r8:hex}",

                # File operations
                "CreateFileW": "CreateFileW: path={rcx:unicode}, access={rdx:hex}, share={r8:hex}",
                "CreateFileA": "CreateFileA: path={rcx:ascii}, access={rdx:hex}, share={r8:hex}",
                "ReadFile": "ReadFile: handle={rcx:hex}, buf={rdx:hex}, size={r8:hex}",
                "WriteFile": "WriteFile: handle={rcx:hex}, buf={rdx:hex}, size={r8:hex}",
                "DeleteFileW": "DeleteFileW: path={rcx:unicode}",
                "DeleteFileA": "DeleteFileA: path={rcx:ascii}",

                # Process creation
                "CreateProcessW": "CreateProcessW: app={rcx:unicode}, cmd={rdx:unicode}",
                "CreateProcessA": "CreateProcessA: app={rcx:ascii}, cmd={rdx:ascii}",
                "OpenProcess": "OpenProcess: access={rcx:hex}, pid={r8:dec}",

                # DLL loading
                "LoadLibraryW": "LoadLibraryW: path={rcx:unicode}",
                "LoadLibraryA": "LoadLibraryA: path={rcx:ascii}",
                "GetProcAddress": "GetProcAddress: module={rcx:hex}, proc={rdx:ascii}",

                # Registry
                "RegOpenKeyExW": "RegOpenKeyExW: key={rcx:hex}, subkey={rdx:unicode}",
                "RegSetValueExW": "RegSetValueExW: key={rcx:hex}, value={rdx:unicode}, type={r9:hex}",
                "RegCreateKeyExW": "RegCreateKeyExW: key={rcx:hex}, subkey={rdx:unicode}",

                # Network
                "connect": "connect: socket={rcx:hex}, addr={rdx:hex}, len={r8:dec}",
                "send": "send: socket={rcx:hex}, buf={rdx:hex}, len={r8:dec}",
                "recv": "recv: socket={rcx:hex}, buf={rdx:hex}, len={r8:dec}",
                "WSAConnect": "WSAConnect: socket={rcx:hex}, addr={rdx:hex}",

                # HTTP
                "InternetOpenW": "InternetOpenW: agent={rcx:unicode}",
                "InternetConnectW": "InternetConnectW: session={rcx:hex}, server={rdx:unicode}, port={r8:dec}",
                "HttpOpenRequestW": "HttpOpenRequestW: connect={rcx:hex}, verb={rdx:unicode}, path={r8:unicode}",
            }

            # Get the bare API name (strip module prefix if present)
            bare_api = api.split("!")[-1] if "!" in api else api
            log_template = api_templates.get(bare_api, f"{bare_api}: rcx={{rcx:hex}}, rdx={{rdx:hex}}, r8={{r8:hex}}, r9={{r9:hex}}")

            # Try native API logging first
            try:
                result = bridge.set_api_logging_breakpoint(
                    api_name=api,
                    log_file=log_file,
                    max_calls=max_calls,
                    log_template=log_template,
                    break_on_hit=False
                )

                output = [
                    f"API parameter logging enabled for {api}",
                    f"  Address: 0x{result.get('address', 'unknown')}",
                    f"  Template: {log_template}",
                    f"  Max calls: {max_calls}",
                ]

                if log_file:
                    output.append(f"  Log file: {log_file}")
                else:
                    output.append("  Log file: None (session storage only)")

                output.extend([
                    "",
                    "Use x64dbg_get_bp_logs() to retrieve logged calls.",
                    "Use x64dbg_run() to start execution."
                ])

                return "\n".join(output)

            except Exception as native_err:
                logger.debug(f"Native API logging not available: {native_err}, using fallback")

                # Fall back to conditional breakpoint approach
                # Resolve API module if not specified
                api_modules = {
                    "WriteProcessMemory": "kernel32", "ReadProcessMemory": "kernel32",
                    "VirtualAlloc": "kernel32", "VirtualAllocEx": "kernel32",
                    "VirtualProtect": "kernel32", "VirtualProtectEx": "kernel32",
                    "CreateFileW": "kernel32", "CreateFileA": "kernel32",
                    "ReadFile": "kernel32", "WriteFile": "kernel32",
                    "DeleteFileW": "kernel32", "DeleteFileA": "kernel32",
                    "CreateProcessW": "kernel32", "CreateProcessA": "kernel32",
                    "OpenProcess": "kernel32", "CreateRemoteThread": "kernel32",
                    "LoadLibraryW": "kernel32", "LoadLibraryA": "kernel32",
                    "GetProcAddress": "kernel32",
                    "RegOpenKeyExW": "advapi32", "RegSetValueExW": "advapi32",
                    "RegCreateKeyExW": "advapi32",
                    "connect": "ws2_32", "send": "ws2_32", "recv": "ws2_32",
                    "WSAConnect": "ws2_32",
                    "InternetOpenW": "wininet", "InternetConnectW": "wininet",
                    "HttpOpenRequestW": "wininet",
                }

                if "!" not in api:
                    module = api_modules.get(api, "kernel32")
                    full_api = f"{module}!{api}"
                else:
                    full_api = api

                # Set conditional breakpoint that logs and continues
                bridge.set_breakpoint(full_api)

                # Store config
                bp_config = {
                    "address": full_api,
                    "api_name": api,
                    "condition": None,
                    "log_template": log_template,
                    "action": "log_and_continue",
                    "log_file": log_file,
                    "max_calls": max_calls,
                    "hit_count": 0,
                    "logs": [],
                    "native": False
                }

                if _session_manager and _session_manager.active_session_id:
                    session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                    if "api_loggers" not in session_data:
                        session_data["api_loggers"] = {}
                    session_data["api_loggers"][api] = bp_config

                output = [
                    f"API parameter logging enabled for {api} (fallback mode)",
                    f"  Expression: {full_api}",
                    f"  Template: {log_template}",
                    f"  Max calls: {max_calls}",
                ]

                if log_file:
                    output.append(f"  Log file: {log_file}")

                output.extend([
                    "",
                    "Note: Using Python-side logging. Breakpoint will pause execution.",
                    "Call x64dbg_check_conditional_breakpoint() when hit, then x64dbg_run()."
                ])

                return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_log_api_params failed: {e.structured_error.error.value}")
            return format_error_response(e, "log_api_params")
        except Exception as e:
            logger.error(f"x64dbg_log_api_params failed: {e}")
            return format_error_response(e, "log_api_params")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_bp_logs(
        address: str | None = None,
        limit: int = 50
    ) -> str:
        """
        Get logged messages from conditional breakpoints.

        Retrieves log entries captured by breakpoints set with x64dbg_set_conditional_bp
        or x64dbg_log_api_params.

        Args:
            address: Filter to specific breakpoint address (optional)
                    Example: "0x7670EDC0"
            limit: Maximum number of entries to return (default: 50)

        Returns:
            List of log entries with timestamps

        Example:
            # Get all logs
            x64dbg_get_bp_logs()

            # Get logs for specific breakpoint
            x64dbg_get_bp_logs(address="0x7670EDC0", limit=50)

        Output format:
            [{"timestamp": "...", "message": "CreateFileW called: ..."}]
        """
        try:
            bridge = get_x64dbg_bridge()

            # Try native breakpoint log first
            try:
                result = bridge.get_breakpoint_log(
                    address=address,
                    offset=0,
                    limit=limit
                )

                entries = result.get("entries", [])
                total = result.get("total", len(entries))

                if not entries:
                    return "No log entries found."

                output = [
                    f"Breakpoint Logs ({len(entries)} of {total} entries):",
                    "=" * 70,
                    ""
                ]

                for i, entry in enumerate(entries, 1):
                    ts = entry.get("timestamp", "N/A")
                    msg = entry.get("message", "")
                    addr = entry.get("address", "unknown")
                    tid = entry.get("thread_id", "?")

                    output.append(f"[{i}] {ts} | Thread {tid}")
                    output.append(f"    Address: 0x{addr}")
                    output.append(f"    Message: {msg}")
                    output.append("")

                return "\n".join(output)

            except Exception as native_err:
                logger.debug(f"Native log retrieval not available: {native_err}, using session storage")

                # Fall back to session storage
                if not _session_manager or not _session_manager.active_session_id:
                    return "No active session. Start debugging first."

                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})

                # Collect logs from both conditional breakpoints and API loggers
                all_logs = []

                # From conditional breakpoints
                conditional_bps = session_data.get("conditional_breakpoints", {})
                for bp_addr, bp_config in conditional_bps.items():
                    if address and bp_addr != address:
                        continue
                    for log in bp_config.get("logs", []):
                        all_logs.append({
                            "address": bp_addr,
                            "timestamp": log.get("timestamp", "N/A"),
                            "message": log.get("entry", ""),
                            "source": "conditional_bp"
                        })

                # From API loggers
                api_loggers = session_data.get("api_loggers", {})
                for api_name, logger_config in api_loggers.items():
                    bp_addr = logger_config.get("address", api_name)
                    if address and bp_addr != address:
                        continue
                    for log in logger_config.get("logs", []):
                        all_logs.append({
                            "address": bp_addr,
                            "timestamp": log.get("timestamp", "N/A"),
                            "message": log.get("entry", ""),
                            "source": "api_logger"
                        })

                if not all_logs:
                    if address:
                        return f"No logs found for address {address}."
                    return "No log entries found. Run the program and trigger some breakpoints."

                # Limit results
                all_logs = all_logs[-limit:]

                output = [
                    f"Breakpoint Logs ({len(all_logs)} entries, from session storage):",
                    "=" * 70,
                    ""
                ]

                for i, log in enumerate(all_logs, 1):
                    output.append(f"[{i}] {log['timestamp']}")
                    output.append(f"    Address: {log['address']}")
                    output.append(f"    Message: {log['message']}")
                    output.append("")

                return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_bp_logs failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # P2: Static/Dynamic Cross-Reference
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_resolve_static_address(
        static_address: str,
        binary_path: str | None = None,
        image_base: str | None = None
    ) -> str:
        """
        Convert a static analysis address to runtime address.

        Takes an address from static analysis (Ghidra, IDA) and converts it
        to the actual runtime address based on the loaded module base.

        Formula: runtime_address = static_address - image_base + module_base

        Args:
            static_address: Address from static analysis (hex string, e.g., "0x401234")
            binary_path: Optional binary name or path. If None, uses main module.
            image_base: Optional static image base. If None, auto-detect from PE header.
                       Common values: 0x400000 (EXE), 0x10000000 (DLL)

        Returns:
            Runtime address and conversion details

        Example:
            # Function identified in Ghidra at 0x004025B0
            x64dbg_resolve_static_address("0x004025B0")
            # Returns: "Runtime address: 0x012425B0 (module base: 0x01200000)"

            # DLL with custom image base
            x64dbg_resolve_static_address("0x10001234", binary_path="evil.dll")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Parse static address
            if static_address.startswith("0x") or static_address.startswith("0X"):
                static_addr = int(static_address, 16)
            else:
                static_addr = int(static_address, 16)

            # Get modules
            modules = bridge.get_modules()

            # Find target module
            target_module = None
            if binary_path:
                # Search by name
                binary_name = os.path.basename(binary_path).lower()
                for mod in modules:
                    mod_name = mod.get("name", "").lower()
                    if binary_name in mod_name or mod_name in binary_name:
                        target_module = mod
                        break
            else:
                # Use first module (main executable)
                if modules:
                    target_module = modules[0]

            if not target_module:
                return f"Module not found: {binary_path if binary_path else 'main module'}"

            module_base = target_module.get("base", 0)
            if isinstance(module_base, str):
                module_base = int(module_base, 16) if module_base.startswith("0x") else int(module_base)

            module_name = target_module.get("name", "unknown")

            # Determine image base (from PE header or provided)
            if image_base:
                if isinstance(image_base, str):
                    img_base = int(image_base, 16) if image_base.startswith("0x") else int(image_base)
                else:
                    img_base = image_base
            else:
                # Try to read PE header to get image base
                try:
                    # Read DOS header to find PE header
                    dos_header = bridge.read_memory(f"0x{module_base:X}", 64)
                    if dos_header and len(dos_header) >= 64:
                        # Get e_lfanew (offset to PE header) at offset 0x3C
                        e_lfanew = int.from_bytes(dos_header[0x3C:0x40], 'little')
                        # Read PE header
                        pe_header = bridge.read_memory(f"0x{module_base + e_lfanew:X}", 256)
                        if pe_header and len(pe_header) >= 256:
                            # Image base is at offset 0x30 from PE signature in PE32+
                            # Check PE signature
                            if pe_header[0:4] == b'PE\x00\x00':
                                # Check machine type at offset 4
                                # Optional header offset is at 0x18
                                opt_header = pe_header[0x18:]
                                magic = int.from_bytes(opt_header[0:2], 'little')
                                if magic == 0x20B:  # PE32+ (64-bit)
                                    img_base = int.from_bytes(opt_header[24:32], 'little')
                                else:  # PE32 (32-bit)
                                    img_base = int.from_bytes(opt_header[28:32], 'little')
                            else:
                                img_base = 0x400000  # Default
                        else:
                            img_base = 0x400000
                    else:
                        img_base = 0x400000  # Default for EXE
                except Exception:
                    # Default image bases
                    if module_name.lower().endswith(".dll"):
                        img_base = 0x10000000
                    else:
                        img_base = 0x400000

            # Calculate runtime address
            offset = static_addr - img_base
            runtime_addr = module_base + offset

            output = [
                "Address Conversion:",
                f"  Static address:  0x{static_addr:08X}",
                f"  Image base:      0x{img_base:08X}",
                f"  Offset:          0x{offset:08X}",
                f"  Module:          {module_name}",
                f"  Module base:     0x{module_base:08X}",
                f"  Runtime address: 0x{runtime_addr:08X}",
                "",
                f"Use 0x{runtime_addr:X} for breakpoints in x64dbg"
            ]

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_resolve_static_address failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_breakpoint_by_name(
        function_name: str,
        module: str | None = None
    ) -> str:
        """
        Set a breakpoint by function name.

        Resolves the function name to an address and sets a breakpoint.
        Supports exported functions and debug symbols.

        Args:
            function_name: Name of the function. Can be:
                          - Simple name: "CreateFileW" (searches common modules)
                          - Full path: "kernel32!CreateFileW"
            module: Optional module name. If not specified and function_name
                   doesn't include module, searches common modules.

        Returns:
            Breakpoint address and status

        Example:
            # Set breakpoint on Windows API
            x64dbg_set_breakpoint_by_name("CreateFileW")

            # Set breakpoint with explicit module
            x64dbg_set_breakpoint_by_name("NtCreateFile", module="ntdll")

            # Full path format
            x64dbg_set_breakpoint_by_name("kernel32!WriteProcessMemory")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Pre-check: verify target module is loaded before attempting resolution
            target_module = None
            if module:
                target_module = module
            elif "!" in function_name:
                target_module = function_name.split("!", 1)[0]

            if target_module:
                loaded_modules = bridge.get_modules()
                loaded_names = set()
                for mod in loaded_modules:
                    name = mod.get("name", "").lower()
                    loaded_names.add(name)
                    # Also add without extension for flexible matching
                    if "." in name:
                        loaded_names.add(name.rsplit(".", 1)[0])

                if target_module.lower() not in loaded_names:
                    return (
                        f"Module '{target_module}' is not currently loaded. "
                        f"The module must be loaded before symbols can be resolved.\n\n"
                        f"Suggestions:\n"
                        f"  - Run to entry point first to let DLLs load\n"
                        f"  - Use x64dbg_set_breakpoint('address') with a direct address instead\n"
                        f"  - Use x64dbg_get_modules() to see currently loaded modules"
                    )

            # Build full expression
            if "!" in function_name:
                expression = function_name
            elif module:
                expression = f"{module}!{function_name}"
            else:
                # Try common modules
                common_modules = ["kernel32", "ntdll", "kernelbase", "user32", "advapi32"]
                resolved = None

                for mod in common_modules:
                    expr = f"{mod}!{function_name}"
                    result = bridge.resolve_symbol(expr)
                    if result.get("success"):
                        resolved = result
                        expression = expr
                        break

                if not resolved:
                    # Try without module prefix (might find in main module)
                    result = bridge.resolve_symbol(function_name)
                    if result.get("success"):
                        resolved = result
                        expression = function_name
                    else:
                        return (
                            f"Function '{function_name}' not found.\n\n"
                            f"Suggestions:\n"
                            f"  - Use full path: kernel32!{function_name}\n"
                            f"  - Check module is loaded: x64dbg_get_modules()\n"
                            f"  - List exports: x64dbg_get_module_exports('kernel32')"
                        )

            # Resolve symbol
            result = bridge.resolve_symbol(expression)

            if not result.get("success"):
                error = result.get("error", "Unknown error")
                return f"Failed to resolve '{expression}': {error}"

            address = result.get("address")
            if not address:
                return f"Resolution succeeded but no address returned for '{expression}'"

            if not address.startswith("0x"):
                address = f"0x{address}"

            # Set breakpoint
            bridge.set_breakpoint(address)

            module_name = result.get("module", "unknown")
            symbol_name = result.get("symbol", function_name)

            output = [
                f"Breakpoint set on {symbol_name}",
                f"  Address: {address}",
                f"  Module: {module_name}",
                f"  Expression: {expression}"
            ]

            return "\n".join(output)

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_breakpoint_by_name failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_breakpoint_by_name")
        except Exception as e:
            logger.error(f"x64dbg_set_breakpoint_by_name failed: {e}")
            return format_error_response(e, "set_breakpoint_by_name")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_goto_address(
        address: str | None = None,
        function_name: str | None = None,
        module: str | None = None
    ) -> str:
        """
        Navigate debugger to an address or function.

        Sets the disassembly view to show the specified location.
        Can use direct address or resolve by function name.

        Args:
            address: Direct address to navigate to (hex string)
            function_name: Function name to resolve and navigate to
            module: Module for function name resolution

        Returns:
            Navigation result with address info

        Example:
            # Go to address
            x64dbg_goto_address(address="0x401234")

            # Go to function by name
            x64dbg_goto_address(function_name="CreateFileW")
        """
        try:
            bridge = get_x64dbg_bridge()

            target_address = None

            if address:
                target_address = address
            elif function_name:
                # Resolve function name
                if "!" in function_name:
                    expression = function_name
                elif module:
                    expression = f"{module}!{function_name}"
                else:
                    expression = function_name

                result = bridge.resolve_symbol(expression)
                if result.get("success"):
                    target_address = result.get("address")
                    if target_address and not target_address.startswith("0x"):
                        target_address = f"0x{target_address}"
                else:
                    return f"Failed to resolve '{expression}': {result.get('error', 'Unknown')}"
            else:
                return "Provide either 'address' or 'function_name'"

            # Use goto command via comment (x64dbg will parse addresses in comments)
            # Actually, we can use the disassemble API to get info about the target
            disasm = bridge.disassemble(target_address, 5)

            output = [
                f"Address: {target_address}",
                "",
                "Disassembly:"
            ]

            if disasm:
                for instr in disasm[:5]:
                    addr = instr.get("address", "")
                    mnemonic = instr.get("mnemonic", "")
                    output.append(f"  {addr}: {mnemonic}")
            else:
                output.append("  (Could not disassemble)")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_goto_address failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_runtime_function_address(
        static_address: str,
        function_name: str | None = None,
        binary_path: str | None = None
    ) -> str:
        """
        Get the runtime address of a function identified in static analysis.

        Combines static analysis information with runtime module base to
        calculate the actual address where a function is loaded.

        Args:
            static_address: Address from Ghidra/IDA analysis
            function_name: Optional function name for verification
            binary_path: Binary containing the function

        Returns:
            Runtime address and module information

        Example:
            # Ghidra shows function at 0x004025B0
            # In x64dbg, the module is loaded at 0x01200000
            x64dbg_get_runtime_function_address(
                "0x004025B0",
                function_name="decrypt_payload",
                binary_path="malware.exe"
            )
            # Returns: "Runtime address: 0x012025B0"
        """
        # This is an alias/wrapper around resolve_static_address with
        # additional verification
        try:
            bridge = get_x64dbg_bridge()

            # First, get the runtime address
            result = x64dbg_resolve_static_address(
                static_address=static_address,
                binary_path=binary_path
            )

            # Parse the runtime address from the result
            lines = result.split("\n")
            runtime_addr = None
            for line in lines:
                if "Runtime address:" in line:
                    parts = line.split("0x")
                    if len(parts) > 1:
                        runtime_addr = "0x" + parts[-1].strip()
                        break

            if not runtime_addr:
                return result  # Return original result if parsing failed

            # Verify by disassembling at that address
            output = [result, ""]

            try:
                disasm = bridge.disassemble(runtime_addr, 3)
                if disasm:
                    output.append("Verification (first 3 instructions):")
                    for instr in disasm[:3]:
                        addr = instr.get("address", "")
                        mnemonic = instr.get("mnemonic", "")
                        output.append(f"  {addr}: {mnemonic}")
                else:
                    output.append("Warning: Could not disassemble at runtime address")
            except Exception:
                pass

            if function_name:
                output.insert(0, f"Function: {function_name}")
                output.insert(1, "")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_get_runtime_function_address failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # Static/Dynamic Cross-Reference (Ghidra Cache Integration)
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_resolve_function(
        binary_path: str,
        function_name: str
    ) -> str:
        """
        Get runtime address of a statically-identified function from Ghidra.

        Queries the Ghidra analysis cache for the function's static address
        and calculates the runtime address based on where the module is loaded.

        Formula: runtime = static - image_base + module_base

        Args:
            binary_path: Path to the binary file (must have Ghidra analysis)
            function_name: Function name from Ghidra (e.g., "MemoryLoadLibrary")

        Returns:
            JSON-like output with static_address, runtime_address, module_base

        Example:
            x64dbg_resolve_function(
                binary_path="EchoManager32.exe",
                function_name="MemoryLoadLibrary"
            )

        Prerequisites:
            - Binary must be analyzed with Ghidra (use ghidra_analyze first)
            - Binary must be loaded in x64dbg debugger
        """
        try:
            bridge = get_x64dbg_bridge()
            result = _resolve_function_to_runtime(function_name, binary_path, bridge)

            if not result:
                cache = get_ghidra_cache()
                if not cache.has_cached(binary_path):
                    return (
                        f"No Ghidra analysis cache found for '{binary_path}'.\n\n"
                        f"To analyze this binary:\n"
                        f"  1. Use ghidra_analyze(binary_path=\"{binary_path}\")\n"
                        f"  2. Wait for analysis to complete\n"
                        f"  3. Try this command again"
                    )
                mappings = _load_function_mappings(binary_path)
                similar = []
                search_lower = function_name.lower()
                for name in mappings.keys():
                    if search_lower in name.lower() or name.lower() in search_lower:
                        if name != name.lower():
                            similar.append(name)
                suggestion = ""
                if similar:
                    suggestion = "\n\nSimilar function names found:\n"
                    for name in similar[:10]:
                        suggestion += f"  - {name}\n"
                return (
                    f"Function '{function_name}' not found in Ghidra cache.{suggestion}\n"
                    f"Use x64dbg_list_function_mappings to see all functions."
                )

            output = [
                f"Function: {result['function_name']}",
                f"  Static address:  {result['static_address']}",
                f"  Image base:      {result['image_base']}",
                f"  Offset:          {result['offset']}",
                f"  Module:          {result['module_name']}",
                f"  Module base:     {result['module_base']}",
                f"  Runtime address: {result['runtime_address']}",
            ]
            if result.get("signature"):
                output.append(f"  Signature:       {result['signature']}")
            output.append("")
            output.append(f"Use {result['runtime_address']} for breakpoints")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_resolve_function failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_breakpoint_by_function(
        binary_path: str,
        function_name: str,
        breakpoint_type: str = "software"
    ) -> str:
        """
        Set a breakpoint on a function identified in Ghidra static analysis.

        Args:
            binary_path: Path to the binary file
            function_name: Function name from Ghidra analysis
            breakpoint_type: "software" (default) or "hardware"

        Returns:
            Breakpoint confirmation with address details

        Example:
            x64dbg_set_breakpoint_by_function(
                binary_path="EchoManager32.exe",
                function_name="load_script_resource"
            )
        """
        try:
            bridge = get_x64dbg_bridge()
            result = _resolve_function_to_runtime(function_name, binary_path, bridge)

            if not result:
                cache = get_ghidra_cache()
                if not cache.has_cached(binary_path):
                    return f"No Ghidra cache found for '{binary_path}'."
                return f"Function '{function_name}' not found in Ghidra cache."

            runtime_addr = result["runtime_address"]
            if breakpoint_type == "hardware":
                bridge.set_hardware_breakpoint(runtime_addr, "execute", 1)
            else:
                bridge.set_breakpoint(runtime_addr)

            output = [
                f"Breakpoint set on {function_name}",
                f"  Type: {breakpoint_type}",
                f"  Static address:  {result['static_address']}",
                f"  Runtime address: {runtime_addr}",
                f"  Module: {result['module_name']}",
            ]
            if result.get("signature"):
                output.append(f"  Signature: {result['signature']}")
            return "\n".join(output)

        except StructuredBaseError as e:
            return format_error_response(e, "set_breakpoint_by_function")
        except Exception as e:
            logger.error(f"x64dbg_set_breakpoint_by_function failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_goto_function(binary_path: str, function_name: str) -> str:
        """
        Navigate the debugger to a function identified in Ghidra analysis.

        Args:
            binary_path: Path to the binary file
            function_name: Function name from Ghidra analysis

        Returns:
            Function location and disassembly preview
        """
        try:
            bridge = get_x64dbg_bridge()
            result = _resolve_function_to_runtime(function_name, binary_path, bridge)

            if not result:
                cache = get_ghidra_cache()
                if not cache.has_cached(binary_path):
                    return f"No Ghidra cache found for '{binary_path}'."
                return f"Function '{function_name}' not found in Ghidra cache."

            runtime_addr = result["runtime_address"]
            try:
                disasm = bridge.disassemble(runtime_addr, 10)
            except Exception:
                disasm = []

            output = [
                f"Function: {function_name}",
                f"  Runtime address: {runtime_addr}",
                f"  Static address:  {result['static_address']}",
                f"  Module: {result['module_name']}",
                "",
            ]
            if result.get("signature"):
                output.append(f"Signature: {result['signature']}")
                output.append("")
            output.append("Disassembly:")
            output.append("-" * 60)
            if disasm:
                for instr in disasm:
                    addr = instr.get("address", "")
                    mnemonic = instr.get("mnemonic", "")
                    operand = instr.get("operand", "")
                    output.append(f"  {addr}: {mnemonic} {operand}".strip())
            else:
                output.append("  (Could not disassemble)")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_goto_function failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_function_mappings(
        binary_path: str,
        filter_pattern: str | None = None,
        limit: int = 50,
        show_external: bool = False
    ) -> str:
        """
        List function mappings from Ghidra cache with their static addresses.

        Args:
            binary_path: Path to the binary file
            filter_pattern: Optional pattern to filter function names
            limit: Maximum number of functions to display (default: 50)
            show_external: Include external/imported functions (default: False)

        Returns:
            List of functions with their static addresses
        """
        try:
            cache = get_ghidra_cache()
            if not cache.has_cached(binary_path):
                return f"No Ghidra analysis cache found for '{binary_path}'."

            mappings = _load_function_mappings(binary_path)
            if not mappings:
                return f"No functions found in Ghidra cache for '{binary_path}'."

            image_base = _get_image_base_from_cache(binary_path)
            filtered = []
            seen_names: set = set()

            for name, info in mappings.items():
                if name.lower() in seen_names:
                    continue
                seen_names.add(name.lower())
                if not show_external and info.get("is_external", False):
                    continue
                if filter_pattern and filter_pattern.lower() not in name.lower():
                    continue
                filtered.append((name, info))

            def sort_key(item):
                addr = item[1].get("address", "0x0")
                if isinstance(addr, str):
                    try:
                        return int(addr, 16)
                    except ValueError:
                        return 0
                return addr

            filtered.sort(key=sort_key)
            total_count = len(filtered)
            filtered = filtered[:limit]

            output = [
                f"Function Mappings for {os.path.basename(binary_path)}",
                f"Image base: 0x{image_base:08X}" if image_base else "Image base: unknown",
                f"Total functions: {total_count}",
                "",
            ]
            if filter_pattern:
                output.append(f"Filter: '{filter_pattern}'")
                output.append("")
            output.append("-" * 70)
            output.append(f"{'Address':<14} {'Name':<40} {'Type'}")
            output.append("-" * 70)

            for name, info in filtered:
                addr = info.get("address", "unknown")
                func_type = []
                if info.get("is_thunk"):
                    func_type.append("thunk")
                if info.get("is_external"):
                    func_type.append("external")
                type_str = ", ".join(func_type) if func_type else ""
                output.append(f"{addr:<14} {name:<40} {type_str}")

            if total_count > limit:
                output.append("")
                output.append(f"... and {total_count - limit} more functions")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_list_function_mappings failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_search_function(binary_path: str, pattern: str) -> str:
        """
        Search for functions by name pattern in Ghidra cache.

        Args:
            binary_path: Path to the binary file
            pattern: Search pattern (substring match, case-insensitive)

        Returns:
            List of matching functions with address information
        """
        try:
            cache = get_ghidra_cache()
            if not cache.has_cached(binary_path):
                return f"No Ghidra analysis cache found for '{binary_path}'."

            mappings = _load_function_mappings(binary_path)
            pattern_lower = pattern.lower()
            matches = []
            seen_names: set = set()

            for name, info in mappings.items():
                if name.lower() in seen_names:
                    continue
                seen_names.add(name.lower())
                if pattern_lower in name.lower():
                    matches.append((name, info))

            if not matches:
                return f"No functions matching '{pattern}' found."

            def sort_key(item):
                name = item[0]
                if name.lower() == pattern_lower:
                    return (0, 0)
                elif name.lower().startswith(pattern_lower):
                    return (1, 0)
                addr = item[1].get("address", "0x0")
                try:
                    return (2, int(addr, 16) if isinstance(addr, str) else addr)
                except ValueError:
                    return (2, 0)

            matches.sort(key=sort_key)
            output = [
                f"Functions matching '{pattern}' in {os.path.basename(binary_path)}:",
                f"Found {len(matches)} matches",
                "",
                "-" * 70,
            ]
            for name, info in matches[:30]:
                addr = info.get("address", "unknown")
                output.append(f"{addr}: {name}")
            if len(matches) > 30:
                output.append(f"... and {len(matches) - 30} more matches")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_search_function failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_bulk_resolve_functions(
        binary_path: str,
        function_names: list[str]
    ) -> str:
        """
        Resolve multiple function names to runtime addresses at once.

        Args:
            binary_path: Path to the binary file
            function_names: List of function names to resolve

        Returns:
            Table of function names with static and runtime addresses
        """
        try:
            bridge = get_x64dbg_bridge()
            cache = get_ghidra_cache()
            if not cache.has_cached(binary_path):
                return f"No Ghidra analysis cache found for '{binary_path}'."

            results = []
            for func_name in function_names:
                result = _resolve_function_to_runtime(func_name, binary_path, bridge)
                if result:
                    results.append({
                        "name": func_name,
                        "static": result["static_address"],
                        "runtime": result["runtime_address"],
                        "found": True
                    })
                else:
                    results.append({
                        "name": func_name,
                        "static": "N/A",
                        "runtime": "N/A",
                        "found": False
                    })

            found_count = sum(1 for r in results if r["found"])
            output = [
                f"Bulk Function Resolution for {os.path.basename(binary_path)}",
                f"Requested: {len(function_names)} functions",
                f"Resolved: {found_count} functions",
                "",
                "-" * 80,
                f"{'Function':<30} {'Static':<16} {'Runtime':<16} {'Status'}",
                "-" * 80,
            ]
            for r in results:
                status = "OK" if r["found"] else "NOT FOUND"
                output.append(f"{r['name']:<30} {r['static']:<16} {r['runtime']:<16} {status}")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_bulk_resolve_functions failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_breakpoints_by_functions(
        binary_path: str,
        function_names: list[str],
        breakpoint_type: str = "software"
    ) -> str:
        """
        Set breakpoints on multiple functions from Ghidra analysis.

        Args:
            binary_path: Path to the binary file
            function_names: List of function names to set breakpoints on
            breakpoint_type: "software" (default) or "hardware"

        Returns:
            Summary of breakpoints set with success/failure count
        """
        try:
            bridge = get_x64dbg_bridge()
            cache = get_ghidra_cache()
            if not cache.has_cached(binary_path):
                return f"No Ghidra analysis cache found for '{binary_path}'."

            results = {"success": 0, "failed": 0, "not_found": 0, "details": []}
            for func_name in function_names:
                resolution = _resolve_function_to_runtime(func_name, binary_path, bridge)
                if not resolution:
                    results["not_found"] += 1
                    results["details"].append(f"  {func_name}: not found")
                    continue
                try:
                    runtime_addr = resolution["runtime_address"]
                    if breakpoint_type == "hardware":
                        bridge.set_hardware_breakpoint(runtime_addr, "execute", 1)
                    else:
                        bridge.set_breakpoint(runtime_addr)
                    results["success"] += 1
                    results["details"].append(f"  {func_name}: {runtime_addr}")
                except Exception as e:
                    results["failed"] += 1
                    results["details"].append(f"  {func_name}: failed - {e}")

            output = [
                f"Bulk Breakpoint Results for {os.path.basename(binary_path)}",
                f"  Type: {breakpoint_type}",
                f"  Requested: {len(function_names)}",
                f"  Success: {results['success']}",
                f"  Not found: {results['not_found']}",
                f"  Failed: {results['failed']}",
                "",
                "Details:",
            ]
            output.extend(results["details"][:20])
            if len(results["details"]) > 20:
                output.append(f"  ... and {len(results['details']) - 20} more")
            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_set_breakpoints_by_functions failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_refresh_function_cache(binary_path: str) -> str:
        """
        Refresh the function mapping cache for a binary.

        Forces a reload of function mappings from the Ghidra cache.
        Use this if the Ghidra analysis has been updated.

        Args:
            binary_path: Path to the binary file

        Returns:
            Confirmation with count of functions loaded
        """
        try:
            global _function_mappings
            if binary_path in _function_mappings:
                del _function_mappings[binary_path]
            cache = get_ghidra_cache()
            if not cache.has_cached(binary_path):
                return f"No Ghidra analysis cache found for '{binary_path}'."
            mappings = _load_function_mappings(binary_path)
            unique_count = len(set(name.lower() for name in mappings.keys()))
            return (
                f"Function cache refreshed for {os.path.basename(binary_path)}.\n"
                f"Loaded {unique_count} unique functions from Ghidra cache."
            )
        except Exception as e:
            logger.error(f"x64dbg_refresh_function_cache failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # P2: Session State Persistence
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_save_debug_state(
        state_name: str | None = None,
        include_breakpoints: bool = True,
        include_comments: bool = True,
        include_labels: bool = True,
        include_watches: bool = True
    ) -> str:
        """
        Save the current x64dbg debugging state for later restoration.

        Captures breakpoints, comments, labels, and other debug state that
        can be restored in a future session. Useful for resuming analysis
        across multiple conversations.

        Args:
            state_name: Optional name for this state snapshot. If None, uses
                       binary name + timestamp.
            include_breakpoints: Save all breakpoints (software, hardware, memory)
            include_comments: Save address comments
            include_labels: Save custom labels
            include_watches: Save watch expressions

        Returns:
            State ID and summary of saved items

        Example:
            # Save current state
            x64dbg_save_debug_state(state_name="before_unpacking")

            # Later restore
            x64dbg_restore_debug_state(state_id="...")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Get current debug info
            status = bridge.get_current_location()
            modules = bridge.get_modules()

            binary_name = "unknown"
            if modules:
                binary_name = modules[0].get("name", "unknown")

            # Generate state name if not provided
            if not state_name:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                state_name = f"{binary_name}_{timestamp}"

            # Collect debug state
            debug_state = {
                "state_name": state_name,
                "binary_name": binary_name,
                "created_at": time.time(),
                "debugger_state": status.get("state", "unknown"),
                "breakpoints": {"software": [], "hardware": [], "memory": []},
                "comments": [],
                "labels": [],
                "watches": []
            }

            # Collect breakpoints
            if include_breakpoints:
                try:
                    bp_result = bridge.list_all_breakpoints()
                    if bp_result.get("success"):
                        bps = bp_result.get("breakpoints", {})
                        debug_state["breakpoints"]["software"] = bps.get("software", [])
                        debug_state["breakpoints"]["hardware"] = bps.get("hardware", [])
                        debug_state["breakpoints"]["memory"] = bps.get("memory", [])
                except Exception as e:
                    logger.warning(f"Failed to collect breakpoints: {e}")

            # Generate state ID
            import hashlib
            state_id = hashlib.sha256(
                f"{state_name}_{time.time()}".encode()
            ).hexdigest()[:16]
            debug_state["state_id"] = state_id

            # Save to session if available
            if _session_manager:
                session_dir = _session_manager.store_dir / "debug_states"
                session_dir.mkdir(parents=True, exist_ok=True)

                state_file = session_dir / f"{state_id}.json"
                import json
                with open(state_file, "w") as f:
                    json.dump(debug_state, f, indent=2, default=str)

            # Also store in active session data
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                if "debug_states" not in session_data:
                    session_data["debug_states"] = {}
                session_data["debug_states"][state_id] = debug_state

            # Build summary

            output = [
                "Debug state saved:",
                f"  State ID: {state_id}",
                f"  Name: {state_name}",
                f"  Binary: {binary_name}",
                "",
                "Items saved:",
                f"  Software breakpoints: {len(debug_state['breakpoints']['software'])}",
                f"  Hardware breakpoints: {len(debug_state['breakpoints']['hardware'])}",
                f"  Memory breakpoints: {len(debug_state['breakpoints']['memory'])}",
                "",
                f"Use x64dbg_restore_debug_state(state_id=\"{state_id}\") to restore"
            ]

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_save_debug_state failed: {e}")
            return safe_error_message("Failed to save debug state", e)

    @app.tool()
    @log_dynamic_tool
    def x64dbg_restore_debug_state(
        state_id: str,
        restore_breakpoints: bool = True,
        restore_comments: bool = True,
        restore_labels: bool = True,
        clear_existing: bool = False
    ) -> str:
        """
        Restore a previously saved x64dbg debugging state.

        Recreates breakpoints, comments, and labels from a saved state.
        Use after loading the same binary to resume analysis.

        Args:
            state_id: ID of the state to restore (from x64dbg_save_debug_state)
            restore_breakpoints: Restore all breakpoints
            restore_comments: Restore address comments
            restore_labels: Restore custom labels
            clear_existing: Clear existing breakpoints before restoring

        Returns:
            Restoration summary

        Example:
            # List available states
            x64dbg_list_debug_states()

            # Restore specific state
            x64dbg_restore_debug_state(state_id="abc123...")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Validate state_id to prevent path traversal
            try:
                state_id = validate_state_id(state_id)
            except ValueError as e:
                return f"Error: Invalid state ID - {e}"

            # Load state from file
            import json
            debug_state = None

            if _session_manager:
                state_file = _session_manager.store_dir / "debug_states" / f"{state_id}.json"
                if state_file.exists():
                    with open(state_file) as f:
                        debug_state = json.load(f)

            # Also check active session data
            if not debug_state and _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                debug_state = session_data.get("debug_states", {}).get(state_id)

            if not debug_state:
                return f"Debug state not found: {state_id}\n\nUse x64dbg_list_debug_states() to see available states."

            restored = {
                "software_bp": 0,
                "hardware_bp": 0,
                "memory_bp": 0,
                "comments": 0,
                "labels": 0,
                "failed": 0
            }

            # Clear existing breakpoints if requested
            if clear_existing:
                try:
                    # Get all current breakpoints and delete them
                    current_bps = bridge.list_all_breakpoints()
                    if current_bps.get("success"):
                        for bp in current_bps.get("breakpoints", {}).get("software", []):
                            try:
                                bridge.delete_breakpoint(f"0x{bp.get('address', '0')}")
                            except Exception:
                                pass
                except Exception:
                    pass

            # Restore software breakpoints
            if restore_breakpoints:
                for bp in debug_state.get("breakpoints", {}).get("software", []):
                    try:
                        addr = bp.get("address", "")
                        if addr:
                            bridge.set_breakpoint(f"0x{addr}")
                            restored["software_bp"] += 1
                    except Exception as e:
                        logger.debug(f"Failed to restore software BP: {e}")
                        restored["failed"] += 1

                # Restore hardware breakpoints
                for bp in debug_state.get("breakpoints", {}).get("hardware", []):
                    try:
                        addr = bp.get("address", "")
                        hw_type = bp.get("type", "execute")
                        hw_size = bp.get("size", 1)
                        if addr:
                            bridge.set_hardware_breakpoint(f"0x{addr}", hw_type, hw_size)
                            restored["hardware_bp"] += 1
                    except Exception as e:
                        logger.debug(f"Failed to restore hardware BP: {e}")
                        restored["failed"] += 1

                # Restore memory breakpoints
                for bp in debug_state.get("breakpoints", {}).get("memory", []):
                    try:
                        addr = bp.get("address", "")
                        bp_type = bp.get("type", "access")
                        if addr:
                            bridge.set_memory_breakpoint(f"0x{addr}", bp_type=bp_type)
                            restored["memory_bp"] += 1
                    except Exception as e:
                        logger.debug(f"Failed to restore memory BP: {e}")
                        restored["failed"] += 1

            output = [
                f"Debug state restored: {debug_state.get('state_name', state_id)}",
                f"  Original binary: {debug_state.get('binary_name', 'unknown')}",
                "",
                "Restored items:",
                f"  Software breakpoints: {restored['software_bp']}",
                f"  Hardware breakpoints: {restored['hardware_bp']}",
                f"  Memory breakpoints: {restored['memory_bp']}",
            ]

            if restored["failed"] > 0:
                output.append(f"  Failed to restore: {restored['failed']}")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_restore_debug_state failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_debug_states(binary_filter: str | None = None) -> str:
        """
        List all saved x64dbg debug states.

        Shows available states that can be restored. Optionally filter
        by binary name.

        Args:
            binary_filter: Optional filter for binary name (case-insensitive)

        Returns:
            List of available debug states with summaries

        Example:
            # List all states
            x64dbg_list_debug_states()

            # Filter by binary
            x64dbg_list_debug_states(binary_filter="malware")
        """
        try:
            import json
            from datetime import datetime

            states = []

            # Load from files
            if _session_manager:
                state_dir = _session_manager.store_dir / "debug_states"
                if state_dir.exists():
                    for state_file in state_dir.glob("*.json"):
                        try:
                            with open(state_file) as f:
                                state = json.load(f)

                            # Apply filter
                            if binary_filter:
                                binary_name = state.get("binary_name", "").lower()
                                if binary_filter.lower() not in binary_name:
                                    continue

                            states.append(state)
                        except Exception as e:
                            logger.debug(f"Failed to load state file {state_file}: {e}")

            if not states:
                if binary_filter:
                    return f"No debug states found matching '{binary_filter}'."
                return "No debug states saved yet. Use x64dbg_save_debug_state() to save current state."

            # Sort by creation time (newest first)
            states.sort(key=lambda x: x.get("created_at", 0), reverse=True)

            output = [
                f"Saved Debug States ({len(states)}):",
                "=" * 60,
                ""
            ]

            for state in states:
                state_id = state.get("state_id", "unknown")
                state_name = state.get("state_name", "unnamed")
                binary_name = state.get("binary_name", "unknown")
                created_at = state.get("created_at", 0)

                # Format timestamp
                if created_at:
                    created_str = datetime.fromtimestamp(created_at).strftime("%Y-%m-%d %H:%M")
                else:
                    created_str = "unknown"

                # Count breakpoints
                bps = state.get("breakpoints", {})
                bp_count = (
                    len(bps.get("software", [])) +
                    len(bps.get("hardware", [])) +
                    len(bps.get("memory", []))
                )

                output.append(f"State: {state_name}")
                output.append(f"  ID: {state_id}")
                output.append(f"  Binary: {binary_name}")
                output.append(f"  Created: {created_str}")
                output.append(f"  Breakpoints: {bp_count}")
                output.append("")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_list_debug_states failed: {e}")
            return safe_error_message("Failed to list debug states", e)

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_debug_state(state_id: str) -> str:
        """
        Delete a saved debug state.

        Args:
            state_id: ID of the state to delete

        Returns:
            Deletion confirmation
        """
        try:
            # Validate state_id to prevent path traversal
            try:
                state_id = validate_state_id(state_id)
            except ValueError as e:
                return f"Error: Invalid state ID - {e}"

            deleted = False

            if _session_manager:
                state_file = _session_manager.store_dir / "debug_states" / f"{state_id}.json"
                if state_file.exists():
                    state_file.unlink()
                    deleted = True

            # Also remove from active session data
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                if state_id in session_data.get("debug_states", {}):
                    del session_data["debug_states"][state_id]
                    deleted = True

            if deleted:
                return f"Debug state deleted: {state_id}"
            else:
                return f"Debug state not found: {state_id}"

        except Exception as e:
            logger.error(f"x64dbg_delete_debug_state failed: {e}")
            return safe_error_message("Failed to delete debug state", e)

    # =========================================================================
    # P2: API Hook Detection
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_detect_hooks(
        modules: list[str] | None = None,
        methods: list[str] | None = None,
        check_inline: bool = True,
        check_iat: bool = True,
        check_eat: bool = False
    ) -> str:
        """
        Detect API hooks in loaded modules.

        Scans for inline hooks (JMP/CALL patches), IAT hooks (import table
        modifications), and EAT hooks (export table redirects).

        Args:
            modules: List of module names to scan. If None, scans common
                    system modules (ntdll, kernel32, kernelbase).
            methods: List of detection methods: "inline", "iat", "eat".
                    Overrides individual check_* flags if provided.
            check_inline: Check for inline hooks (first bytes patched)
            check_iat: Check for IAT hooks (import table redirects)
            check_eat: Check for EAT hooks (export table redirects)

        Returns:
            Detected hooks with details including:
            - Hook type (inline_hook, iat_hook, eat_hook)
            - Function and module name
            - Address and redirect target
            - Modified bytes

        Example:
            # Scan common modules with all detection methods
            x64dbg_detect_hooks()

            # Scan specific modules
            x64dbg_detect_hooks(modules=["ntdll.dll", "kernel32.dll"])

            # Use specific detection methods
            x64dbg_detect_hooks(methods=["inline", "iat", "eat"])

            # Check only inline hooks
            x64dbg_detect_hooks(check_inline=True, check_iat=False, check_eat=False)

        Detection Methods:
            - inline: Check first 5-10 bytes for JMP/CALL to non-module memory
            - iat: Compare IAT entries to actual export addresses
            - eat: Check export table for redirects outside module

        Note:
            Inline hook detection looks for JMP (E9, FF 25) or CALL (E8)
            instructions at function entry points that redirect outside
            the module. This is a common hooking technique used by both
            malware and security software.
        """
        try:
            bridge = get_x64dbg_bridge()

            # Build methods list from flags or use provided list
            if methods is None:
                methods = []
                if check_inline:
                    methods.append("inline")
                if check_iat:
                    methods.append("iat")
                if check_eat:
                    methods.append("eat")

            # Use the bridge's detect_hooks method
            result = bridge.detect_hooks(
                modules=modules,
                methods=methods,
                max_functions=200
            )

            hooks_found = result.get("hooks_found", [])
            summary = result.get("summary", {})
            modules_scanned = result.get("modules_scanned", 0)
            functions_checked = result.get("functions_checked", 0)

            # Build output
            output = [
                "Hook Detection Results:",
                f"  Modules scanned: {modules_scanned}",
                f"  Functions checked: {functions_checked}",
                f"  Total hooks found: {summary.get('total_hooks', len(hooks_found))}",
                "",
                "Hook Summary:",
                f"  Inline hooks: {summary.get('inline_hooks', 0)}",
                f"  IAT hooks: {summary.get('iat_hooks', 0)}",
                f"  EAT hooks: {summary.get('eat_hooks', 0)}",
                ""
            ]

            if hooks_found:
                output.append("Detected Hooks:")
                output.append("=" * 60)
                output.append("")

                for hook in hooks_found:
                    hook_type = hook.get('type', 'unknown').upper()
                    hook_subtype = hook.get('hook_subtype', '')
                    if hook_subtype:
                        hook_type = f"{hook_type} ({hook_subtype})"

                    output.append(f"[{hook_type}] {hook['module']}!{hook['function']}")
                    output.append(f"  Address: {hook.get('address', 'unknown')}")
                    output.append(f"  Redirect to: {hook.get('redirect_to', 'unknown')}")

                    # Add expected address for IAT hooks
                    if hook.get('expected_address'):
                        output.append(f"  Expected: {hook.get('expected_address')}")

                    # Add target module for EAT hooks
                    if hook.get('target_module'):
                        output.append(f"  Target module: {hook.get('target_module')}")

                    bytes_modified = hook.get('bytes_modified', 0)
                    if bytes_modified > 0:
                        output.append(f"  Bytes modified: {bytes_modified}")

                    original_bytes = hook.get('original_bytes', 'unknown')
                    hooked_bytes = hook.get('hooked_bytes', '')
                    if original_bytes != 'N/A':
                        output.append(f"  Original bytes: {original_bytes}")
                    if hooked_bytes and hooked_bytes != 'N/A':
                        output.append(f"  Hooked bytes: {hooked_bytes}")

                    output.append("")
            else:
                output.append("No hooks detected in scanned modules.")
                output.append("")
                output.append("Note: Some legitimate security software may use hooks.")
                output.append("Absence of hooks doesn't guarantee the binary is safe.")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_detect_hooks failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_check_function_hook(
        function_name: str,
        module: str | None = None
    ) -> str:
        """
        Check if a specific function is hooked.

        Examines the function entry point for inline hooks (JMP/CALL patches)
        that redirect execution elsewhere.

        Args:
            function_name: Name of the function to check
            module: Optional module name (e.g., "kernel32", "ntdll")

        Returns:
            Hook status and details

        Example:
            # Check specific API
            x64dbg_check_function_hook("NtCreateFile", module="ntdll")

            # Auto-resolve module
            x64dbg_check_function_hook("CreateFileW")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Resolve function address
            if "!" in function_name:
                expression = function_name
            elif module:
                expression = f"{module}!{function_name}"
            else:
                # Try common modules
                for mod in ["ntdll", "kernel32", "kernelbase"]:
                    expr = f"{mod}!{function_name}"
                    result = bridge.resolve_symbol(expr)
                    if result.get("success"):
                        expression = expr
                        module = mod
                        break
                else:
                    return f"Could not resolve function '{function_name}'. Try specifying the module."

            result = bridge.resolve_symbol(expression)
            if not result.get("success"):
                return f"Failed to resolve '{expression}': {result.get('error', 'Unknown error')}"

            func_addr = result.get("address", "")
            if isinstance(func_addr, str):
                func_addr_int = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr, 16)
            else:
                func_addr_int = func_addr

            # Get module info
            modules = bridge.get_modules()
            mod_base = 0
            mod_size = 0
            for mod in modules:
                if module and module.lower() in mod.get("name", "").lower():
                    base = mod.get("base")
                    mod_base = int(base, 16) if isinstance(base, str) else base
                    size = mod.get("size", 0)
                    mod_size = int(size, 16) if isinstance(size, str) else size
                    break

            # Read function entry bytes
            first_bytes = bridge.read_memory(f"0x{func_addr_int:X}", 32)
            if not first_bytes:
                return f"Could not read memory at {expression}"

            # Check for hook
            hook_info = _check_inline_hook(
                first_bytes,
                func_addr_int,
                mod_base,
                mod_size,
                function_name,
                module or "unknown"
            )

            # Disassemble first few instructions
            disasm = bridge.disassemble(f"0x{func_addr_int:X}", 5)

            output = [
                f"Function: {expression}",
                f"Address: 0x{func_addr_int:X}",
                f"Module base: 0x{mod_base:X}",
                "",
                f"First bytes: {first_bytes[:16].hex().upper()}",
                ""
            ]

            if disasm:
                output.append("Disassembly:")
                for instr in disasm[:5]:
                    addr = instr.get("address", "")
                    mnemonic = instr.get("mnemonic", "")
                    output.append(f"  {addr}: {mnemonic}")
                output.append("")

            if hook_info:
                output.append("⚠️  HOOK DETECTED!")
                output.append(f"  Type: {hook_info['type']}")
                output.append(f"  Redirect to: 0x{hook_info['redirect_to']:X}")
                output.append(f"  Hooked bytes: {hook_info['hooked_bytes']}")
                output.append("")
                output.append("This function has been patched to redirect execution.")
            else:
                output.append("✓ No hook detected")
                output.append("")
                output.append("Function entry point appears unmodified.")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_check_function_hook failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_unhook_function(
        function_name: str,
        module: str | None = None,
        original_bytes: str | None = None
    ) -> str:
        """
        Remove an inline hook from a function.

        Restores the original bytes at the function entry point.
        Use with caution - this modifies the target process memory.

        Args:
            function_name: Name of the function to unhook
            module: Module name (required, e.g., "ntdll.dll", "kernel32.dll")
            original_bytes: Original bytes to restore (hex string).
                           If not provided, returns instructions for obtaining them.

        Returns:
            Unhook result with:
            - success: Whether unhook succeeded
            - address: Function address
            - previous_bytes: Bytes before unhooking
            - restored_bytes: Bytes after unhooking

        Example:
            # Unhook with known original bytes
            x64dbg_unhook_function(
                "NtCreateFile",
                module="ntdll.dll",
                original_bytes="4C8BD1B8550000"
            )

            # Get common syscall stub bytes from clean system
            # NtCreateFile typically starts with: 4C 8B D1 B8 55 00 00 00

        Warning:
            Incorrect original bytes can crash the target process.
            Always verify the bytes are correct before unhooking.

        Common Syscall Prologues (Windows 10/11 x64):
            - 4C 8B D1 B8 xx xx 00 00  (mov r10, rcx; mov eax, syscall_num)
            - 48 89 5C 24 08           (mov [rsp+8], rbx)
            - 40 53 48 83 EC 20        (push rbx; sub rsp, 20h)
        """
        try:
            bridge = get_x64dbg_bridge()

            # Determine module name
            if "!" in function_name:
                # Parse module!function format
                parts = function_name.split("!", 1)
                module_name = parts[0]
                func_name = parts[1]
            elif module:
                module_name = module
                func_name = function_name
            else:
                return "Please specify the module for unhooking (e.g., module='ntdll.dll')."

            # Use the bridge's unhook_function method
            result = bridge.unhook_function(
                module_name=module_name,
                function_name=func_name,
                original_bytes=original_bytes
            )

            # Build output based on result
            if result.get("success"):
                output = [
                    f"Function unhooked: {module_name}!{func_name}",
                    f"Address: {result.get('address', 'unknown')}",
                    "",
                    f"Previous bytes: {result.get('previous_bytes', 'unknown')}",
                    f"Restored bytes: {result.get('restored_bytes', 'unknown')}",
                ]

                # Check if it was already unhooked
                if result.get("error") and "not hooked" in result.get("error", "").lower():
                    output.append("")
                    output.append("Note: Function was not hooked (bytes already matched original).")
                else:
                    output.append("")
                    output.append("Warning: Memory was modified. Verify the binary behaves correctly.")

                return "\n".join(output)
            else:
                error = result.get("error", "Unknown error")
                output = [
                    f"Failed to unhook: {module_name}!{func_name}",
                    "",
                    f"Error: {error}",
                ]

                if result.get("address"):
                    output.insert(1, f"Address: {result.get('address')}")

                if result.get("previous_bytes"):
                    output.append("")
                    output.append(f"Current bytes: {result.get('previous_bytes')}")

                return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_unhook_function failed: {e}")
            return f"Error: {e}"

    # =========================================================================
    # P2: Memory Watch and Diff
    # =========================================================================

    @app.tool()
    @log_dynamic_tool
    def x64dbg_watch_memory(
        address: str,
        size: int = 4096,
        name: str | None = None
    ) -> str:
        """
        Start watching a memory region for changes.

        Takes a snapshot of the memory region that can be compared later
        to detect modifications. Useful for catching in-memory decryption
        and code injection.

        Args:
            address: Start address to watch (hex string)
            size: Number of bytes to watch (default: 4096, max: 1MB)
            name: Optional name for this watch point

        Returns:
            Watch ID for use with x64dbg_memory_diff

        Example:
            # Watch encrypted payload buffer
            watch_id = x64dbg_watch_memory("0x089A9020", size=4096, name="payload_buffer")

            # Run until decryption happens
            x64dbg_run()

            # Check for changes
            x64dbg_memory_diff(watch_id="...")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Validate size
            max_size = 1024 * 1024  # 1MB limit
            if size > max_size:
                return f"Size too large. Maximum is {max_size} bytes (1MB)."

            # Normalize address
            if address.startswith("0x") or address.startswith("0X"):
                addr_int = int(address, 16)
            else:
                addr_int = int(address, 16)

            # Read initial snapshot
            snapshot = bridge.read_memory(f"0x{addr_int:X}", size)
            if not snapshot:
                return f"Failed to read memory at {address}"

            # Generate watch ID
            import hashlib
            watch_id = hashlib.sha256(
                f"{address}_{size}_{time.time()}".encode()
            ).hexdigest()[:12]

            # Create watch record
            watch_record = {
                "watch_id": watch_id,
                "name": name or f"watch_{watch_id}",
                "address": addr_int,
                "size": size,
                "created_at": time.time(),
                "initial_snapshot": snapshot.hex(),
                "initial_hash": hashlib.sha256(snapshot).hexdigest(),
                "snapshots": []  # For storing intermediate snapshots
            }

            # Store in session
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                if "memory_watches" not in session_data:
                    session_data["memory_watches"] = {}
                session_data["memory_watches"][watch_id] = watch_record

            output = [
                "Memory watch started:",
                f"  Watch ID: {watch_id}",
                f"  Name: {watch_record['name']}",
                f"  Address: 0x{addr_int:X}",
                f"  Size: {size} bytes",
                f"  Initial hash: {watch_record['initial_hash'][:16]}...",
                "",
                f"Use x64dbg_memory_diff(watch_id=\"{watch_id}\") to check for changes"
            ]

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_watch_memory failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_memory_diff(
        watch_id: str,
        show_bytes: bool = False,
        max_diff_bytes: int = 256
    ) -> str:
        """
        Compare current memory state against a watched snapshot.

        Shows what bytes have changed since the watch was started.

        Args:
            watch_id: Watch ID from x64dbg_watch_memory
            show_bytes: Show actual byte values that changed
            max_diff_bytes: Maximum changed bytes to display (default: 256)

        Returns:
            Diff results showing changed regions

        Example:
            # After running the program
            x64dbg_memory_diff(watch_id="abc123...", show_bytes=True)
        """
        try:
            bridge = get_x64dbg_bridge()

            # Get watch record
            watch_record = None
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                watch_record = session_data.get("memory_watches", {}).get(watch_id)

            if not watch_record:
                return f"Watch not found: {watch_id}\n\nUse x64dbg_list_memory_watches() to see active watches."

            address = watch_record["address"]
            size = watch_record["size"]
            initial_hex = watch_record["initial_snapshot"]

            # Read current memory
            current = bridge.read_memory(f"0x{address:X}", size)
            if not current:
                return f"Failed to read current memory at 0x{address:X}"

            # Convert initial snapshot from hex
            initial = bytes.fromhex(initial_hex)

            # Compare
            import hashlib
            current_hash = hashlib.sha256(current).hexdigest()
            initial_hash = watch_record["initial_hash"]

            if current_hash == initial_hash:
                return (
                    f"Memory unchanged:\n"
                    f"  Watch: {watch_record['name']}\n"
                    f"  Address: 0x{address:X}\n"
                    f"  Size: {size} bytes\n"
                    f"  Hash: {current_hash[:16]}..."
                )

            # Find differences
            changed_ranges = []
            change_start = None
            changed_bytes = 0

            for i in range(min(len(initial), len(current))):
                if initial[i] != current[i]:
                    changed_bytes += 1
                    if change_start is None:
                        change_start = i
                else:
                    if change_start is not None:
                        changed_ranges.append((change_start, i))
                        change_start = None

            if change_start is not None:
                changed_ranges.append((change_start, min(len(initial), len(current))))

            # Build output
            output = [
                "Memory CHANGED:",
                f"  Watch: {watch_record['name']}",
                f"  Address: 0x{address:X}",
                f"  Size: {size} bytes",
                f"  Changed bytes: {changed_bytes}",
                f"  Changed regions: {len(changed_ranges)}",
                "",
                f"  Initial hash: {initial_hash[:16]}...",
                f"  Current hash: {current_hash[:16]}...",
                ""
            ]

            if changed_ranges:
                output.append("Changed Regions:")
                output.append("-" * 50)

                bytes_shown = 0
                for start, end in changed_ranges[:20]:  # Limit regions shown
                    region_addr = address + start
                    region_size = end - start
                    output.append(f"  0x{region_addr:X} - 0x{region_addr + region_size:X} ({region_size} bytes)")

                    if show_bytes and bytes_shown < max_diff_bytes:
                        # Show byte-level diff
                        show_count = min(region_size, max_diff_bytes - bytes_shown, 32)
                        old_bytes = initial[start:start + show_count].hex().upper()
                        new_bytes = current[start:start + show_count].hex().upper()
                        output.append(f"    Old: {old_bytes}")
                        output.append(f"    New: {new_bytes}")
                        bytes_shown += show_count

                if len(changed_ranges) > 20:
                    output.append(f"  ... and {len(changed_ranges) - 20} more regions")

            # Calculate entropy change
            def calc_entropy(data):
                if not data:
                    return 0
                import math
                from collections import Counter
                counts = Counter(data)
                length = len(data)
                entropy = 0
                for count in counts.values():
                    p = count / length
                    entropy -= p * math.log2(p)
                return entropy

            initial_entropy = calc_entropy(initial)
            current_entropy = calc_entropy(current)

            output.append("")
            output.append("Entropy analysis:")
            output.append(f"  Initial: {initial_entropy:.2f} bits/byte")
            output.append(f"  Current: {current_entropy:.2f} bits/byte")
            output.append(f"  Change: {current_entropy - initial_entropy:+.2f}")

            if current_entropy < initial_entropy - 1.0:
                output.append("")
                output.append("⚠️  Entropy decreased significantly - possible decryption detected!")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_memory_diff failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_run_until_memory_changed(
        watch_id: str,
        timeout_seconds: int = 60,
        poll_interval_ms: int | None = None
    ) -> str:
        """
        Run execution until watched memory region changes.

        Starts execution and polls the watched memory region at regular intervals
        until a change is detected or timeout is reached. This is useful for
        catching in-memory decryption, code modification, or unpacking operations.

        Args:
            watch_id: Watch ID from x64dbg_watch_memory
            timeout_seconds: Maximum time to wait in seconds (default: 60)
            poll_interval_ms: Override poll interval in milliseconds.
                             If None, uses the watch's configured interval.

        Returns:
            Change detection results including:
            - Whether memory changed
            - Address and offset of first change
            - Hashes before and after
            - RIP when change was detected
            - Elapsed time

        Example:
            # Set up a watch on encrypted payload buffer
            watch_id = x64dbg_watch_memory("0x089A9020", size=4096)

            # Run until decryption happens (or timeout)
            result = x64dbg_run_until_memory_changed(watch_id, timeout_seconds=60)

            # If changed, get detailed diff
            if "changed: True" in result:
                x64dbg_memory_diff(watch_id)

        Use Cases:
            - Detecting in-memory decryption of payloads
            - Catching self-modifying code
            - Monitoring for unpacking completion
            - Detecting code injection into watched regions

        Note:
            This function pauses and resumes execution repeatedly to check memory.
            For very short poll intervals, this may affect timing-sensitive code.
            The debugger will be paused when the function returns.
        """
        try:
            bridge = get_x64dbg_bridge()

            # First check if we have a session-based watch
            watch_record = None
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                watch_record = session_data.get("memory_watches", {}).get(watch_id)

            # Try bridge-level watch if session watch not found
            if not watch_record:
                # Try using the bridge's run_until_memory_changed directly
                result = bridge.run_until_memory_changed(
                    watch_id,
                    timeout_ms=timeout_seconds * 1000,
                    poll_interval_ms=poll_interval_ms
                )

                if result.get("error") and "Watch not found" in result.get("error", ""):
                    return (
                        f"Watch not found: {watch_id}\n\n"
                        f"Use x64dbg_watch_memory() to create a watch first, or "
                        f"x64dbg_list_memory_watches() to see active watches."
                    )

                # Format result for display
                output = [
                    "Memory Watch Result:",
                    "=" * 60,
                    ""
                ]

                if result.get("changed"):
                    output.append("MEMORY CHANGED!")
                    output.append("")
                    output.append(f"  Address: {result.get('address', 'unknown')}")
                    output.append(f"  Change offset: {result.get('change_offset', 0)} bytes")
                    output.append(f"  Bytes changed: {result.get('change_size', 0)}")
                    output.append(f"  Triggered at RIP: {result.get('triggered_at', 'unknown')}")
                    output.append("")
                    output.append(f"  Before hash: {result.get('before_hash', '')[:16]}...")
                    output.append(f"  After hash: {result.get('after_hash', '')[:16]}...")
                    output.append("")
                    output.append(f"  Elapsed: {result.get('elapsed_ms', 0)}ms")
                    output.append("")
                    output.append(f"Use x64dbg_memory_diff(watch_id=\"{watch_id}\") for byte-level diff")
                else:
                    output.append("No memory change detected")
                    output.append("")
                    output.append(f"  Address: {result.get('address', 'unknown')}")
                    output.append(f"  Elapsed: {result.get('elapsed_ms', 0)}ms")
                    if result.get("error"):
                        output.append(f"  Reason: {result.get('error')}")

                return "\n".join(output)

            # Use session-based watch with manual polling
            import hashlib

            address = watch_record["address"]
            size = watch_record["size"]
            initial_hex = watch_record["initial_snapshot"]
            initial = bytes.fromhex(initial_hex)
            initial_hash = watch_record["initial_hash"]

            interval = poll_interval_ms or 100
            timeout_ms = timeout_seconds * 1000

            start_time = time.time()
            timeout_sec = timeout_ms / 1000

            # Start execution
            bridge.run()

            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed >= timeout_sec:
                    bridge.pause()
                    return (
                        f"Memory Watch Result:\n"
                        f"{'=' * 60}\n\n"
                        f"No memory change detected (timeout)\n\n"
                        f"  Address: 0x{address:X}\n"
                        f"  Watch: {watch_record['name']}\n"
                        f"  Elapsed: {int(elapsed * 1000)}ms\n"
                        f"  Timeout: {timeout_seconds}s\n\n"
                        f"Consider increasing timeout or checking if the target code was reached."
                    )

                # Sleep for poll interval
                time.sleep(interval / 1000)

                # Pause to read memory
                bridge.pause()

                # Read current memory
                try:
                    current = bridge.read_memory(f"0x{address:X}", size)
                except Exception as e:
                    # Memory became unreadable - could indicate significant changes
                    location = bridge.get_current_location()
                    return (
                        f"Memory Watch Result:\n"
                        f"{'=' * 60}\n\n"
                        f"MEMORY CHANGED (became unreadable)!\n\n"
                        f"  Address: 0x{address:X}\n"
                        f"  Watch: {watch_record['name']}\n"
                        f"  Triggered at RIP: 0x{location.get('address', '0')}\n"
                        f"  Elapsed: {int((time.time() - start_time) * 1000)}ms\n"
                        f"  Error: {e}\n\n"
                        f"The memory region may have been deallocated or remapped."
                    )

                # Calculate current hash
                current_hash = hashlib.sha256(current).hexdigest()

                if current_hash != initial_hash:
                    # Memory changed! Find details
                    change_offset = None
                    change_count = 0

                    for i in range(min(len(initial), len(current))):
                        if initial[i] != current[i]:
                            if change_offset is None:
                                change_offset = i
                            change_count += 1

                    # Get current RIP
                    location = bridge.get_current_location()
                    triggered_at = location.get('address', '0')

                    # Update the watch record with new data
                    watch_record["snapshots"].append({
                        "timestamp": time.time(),
                        "hash": initial_hash,
                        "snapshot": initial_hex
                    })

                    return (
                        f"Memory Watch Result:\n"
                        f"{'=' * 60}\n\n"
                        f"MEMORY CHANGED!\n\n"
                        f"  Address: 0x{address:X}\n"
                        f"  Watch: {watch_record['name']}\n"
                        f"  Change offset: {change_offset or 0} bytes\n"
                        f"  Bytes changed: {change_count}\n"
                        f"  Triggered at RIP: 0x{triggered_at}\n\n"
                        f"  Before hash: {initial_hash[:16]}...\n"
                        f"  After hash: {current_hash[:16]}...\n\n"
                        f"  Elapsed: {int((time.time() - start_time) * 1000)}ms\n\n"
                        f"Use x64dbg_memory_diff(watch_id=\"{watch_id}\") for byte-level diff"
                    )

                # No change, resume execution
                bridge.run()

        except Exception as e:
            logger.error(f"x64dbg_run_until_memory_changed failed: {e}")
            try:
                bridge = get_x64dbg_bridge()
                bridge.pause()
            except Exception:
                pass
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_update_memory_snapshot(watch_id: str) -> str:
        """
        Update the baseline snapshot for a memory watch.

        Takes a new snapshot of the watched memory region. Useful for
        tracking incremental changes.

        Args:
            watch_id: Watch ID to update

        Returns:
            Update confirmation

        Example:
            # After first decryption stage
            x64dbg_update_memory_snapshot(watch_id="...")

            # Continue and check for next stage
            x64dbg_run()
            x64dbg_memory_diff(watch_id="...")
        """
        try:
            bridge = get_x64dbg_bridge()

            # Get watch record
            watch_record = None
            if _session_manager and _session_manager.active_session_id:
                session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
                watch_record = session_data.get("memory_watches", {}).get(watch_id)

            if not watch_record:
                return f"Watch not found: {watch_id}"

            address = watch_record["address"]
            size = watch_record["size"]

            # Save old snapshot to history
            watch_record["snapshots"].append({
                "timestamp": time.time(),
                "hash": watch_record["initial_hash"],
                "snapshot": watch_record["initial_snapshot"]
            })

            # Read new snapshot
            new_snapshot = bridge.read_memory(f"0x{address:X}", size)
            if not new_snapshot:
                return f"Failed to read memory at 0x{address:X}"

            import hashlib
            new_hash = hashlib.sha256(new_snapshot).hexdigest()

            # Update record
            watch_record["initial_snapshot"] = new_snapshot.hex()
            watch_record["initial_hash"] = new_hash
            watch_record["updated_at"] = time.time()

            output = [
                "Memory snapshot updated:",
                f"  Watch: {watch_record['name']}",
                f"  Address: 0x{address:X}",
                f"  New hash: {new_hash[:16]}...",
                f"  Snapshot history: {len(watch_record['snapshots'])} entries"
            ]

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_update_memory_snapshot failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_memory_watches() -> str:
        """
        List all active memory watches.

        Returns:
            List of active watches with their status
        """
        try:
            if not _session_manager or not _session_manager.active_session_id:
                return "No active session."

            session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
            watches = session_data.get("memory_watches", {})

            if not watches:
                return "No active memory watches. Use x64dbg_watch_memory() to start watching."

            output = [
                f"Active Memory Watches ({len(watches)}):",
                "=" * 60,
                ""
            ]

            for watch_id, watch in watches.items():
                from datetime import datetime
                created = datetime.fromtimestamp(watch["created_at"]).strftime("%H:%M:%S")
                output.append(f"Watch: {watch['name']}")
                output.append(f"  ID: {watch_id}")
                output.append(f"  Address: 0x{watch['address']:X}")
                output.append(f"  Size: {watch['size']} bytes")
                output.append(f"  Created: {created}")
                output.append(f"  Snapshots: {len(watch.get('snapshots', []))}")
                output.append("")

            return "\n".join(output)

        except Exception as e:
            logger.error(f"x64dbg_list_memory_watches failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_memory_watch(watch_id: str) -> str:
        """
        Delete a memory watch.

        Args:
            watch_id: Watch ID to delete

        Returns:
            Deletion confirmation
        """
        try:
            if not _session_manager or not _session_manager.active_session_id:
                return "No active session."

            session_data = _session_manager._sessions.get(_session_manager.active_session_id, {})
            watches = session_data.get("memory_watches", {})

            if watch_id in watches:
                name = watches[watch_id]["name"]
                del watches[watch_id]
                return f"Deleted memory watch: {name} ({watch_id})"
            else:
                return f"Watch not found: {watch_id}"

        except Exception as e:
            logger.error(f"x64dbg_delete_memory_watch failed: {e}")
            return f"Error: {e}"

    # ── Watch expression tools ───────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_add_watch(expression: str, name: str = "") -> str:
        """
        Add a watch expression to the x64dbg watch view.

        Watches evaluate expressions each time the debugger pauses,
        useful for monitoring registers, memory, or computed values.

        Args:
            expression: Expression to watch (e.g. "eax", "[esp+4]", "eax+ebx*2")
            name: Optional display name for the watch entry

        Returns:
            Confirmation message

        Examples:
            x64dbg_add_watch("eax")
            x64dbg_add_watch("[esp+4]", name="stack_arg1")
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.add_watch(expression, name=name)
            msg = f"Watch added: {expression}"
            if name:
                msg += f" (name={name})"
            return msg

        except StructuredBaseError as e:
            logger.error(f"x64dbg_add_watch failed: {e.structured_error.error.value}")
            return format_error_response(e, "add_watch")
        except Exception as e:
            logger.error(f"x64dbg_add_watch failed: {e}")
            return format_error_response(e, "add_watch")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_watch(index: int) -> str:
        """
        Delete a watch expression by index.

        Args:
            index: Zero-based index of the watch entry to delete

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_watch(index)
            return f"Watch deleted at index {index}"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_delete_watch failed: {e.structured_error.error.value}")
            return format_error_response(e, "delete_watch")
        except Exception as e:
            logger.error(f"x64dbg_delete_watch failed: {e}")
            return format_error_response(e, "delete_watch")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_watchdog(index: int, mode: str = "changed") -> str:
        """
        Set watchdog trigger mode on a watch expression.

        The watchdog monitors a watch entry and triggers when the
        specified condition is met.

        Args:
            index: Zero-based watch index
            mode: Trigger mode. One of:
                  "changed" — value changed (default)
                  "disabled" — watchdog off
                  "unchanged" — value unchanged
                  "istrue" — value is non-zero
                  "isfalse" — value is zero
                  "isgreater" — value increased
                  "isless" — value decreased
                  "isnotequal" — value differs from initial

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_watchdog(0, "changed")
            x64dbg_set_watchdog(1, "istrue")
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_watchdog(index, mode=mode)
            return f"Watchdog set on index {index}: mode={mode}"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_watchdog failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_watchdog")
        except Exception as e:
            logger.error(f"x64dbg_set_watchdog failed: {e}")
            return format_error_response(e, "set_watchdog")

    # ── DLL breakpoint tools ─────────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_dll_breakpoint(
        dll_name: str, singleshoot: bool = False
    ) -> str:
        """
        Set a breakpoint that triggers when a DLL is loaded.

        Useful for intercepting DLL loading during malware analysis
        or for breaking when specific libraries are mapped.

        Args:
            dll_name: DLL name (e.g. "kernel32.dll", "ws2_32.dll")
            singleshoot: If True, breakpoint fires only once then auto-deletes

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_dll_breakpoint("ws2_32.dll")
            x64dbg_set_dll_breakpoint("advapi32.dll", singleshoot=True)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_dll_breakpoint(dll_name, singleshoot=singleshoot)
            msg = f"DLL breakpoint set on '{dll_name}'"
            if singleshoot:
                msg += " (singleshoot)"
            return msg

        except StructuredBaseError as e:
            logger.error(f"x64dbg_set_dll_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "set_dll_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_set_dll_breakpoint failed: {e}")
            return format_error_response(e, "set_dll_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_dll_breakpoint(dll_name: str) -> str:
        """
        Delete a DLL load breakpoint.

        Args:
            dll_name: DLL name to remove breakpoint from

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.delete_dll_breakpoint(dll_name)
            return f"DLL breakpoint deleted for '{dll_name}'"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_delete_dll_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "delete_dll_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_delete_dll_breakpoint failed: {e}")
            return format_error_response(e, "delete_dll_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_enable_dll_breakpoint(dll_name: str) -> str:
        """
        Enable a previously disabled DLL load breakpoint.

        Args:
            dll_name: DLL name to enable breakpoint for

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.enable_dll_breakpoint(dll_name)
            return f"DLL breakpoint enabled for '{dll_name}'"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_enable_dll_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "enable_dll_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_enable_dll_breakpoint failed: {e}")
            return format_error_response(e, "enable_dll_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_disable_dll_breakpoint(dll_name: str) -> str:
        """
        Disable a DLL load breakpoint without deleting it.

        Args:
            dll_name: DLL name to disable breakpoint for

        Returns:
            Confirmation message
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.disable_dll_breakpoint(dll_name)
            return f"DLL breakpoint disabled for '{dll_name}'"

        except StructuredBaseError as e:
            logger.error(f"x64dbg_disable_dll_breakpoint failed: {e.structured_error.error.value}")
            return format_error_response(e, "disable_dll_breakpoint")
        except Exception as e:
            logger.error(f"x64dbg_disable_dll_breakpoint failed: {e}")
            return format_error_response(e, "disable_dll_breakpoint")

    @app.tool()
    @log_dynamic_tool
    def x64dbg_analyze_control_flow() -> str:
        """
        Runs control flow analysis on the current module.

        Builds the control flow graph (CFG) for the current module using
        the x64dbg cfanalyze command. This identifies basic blocks,
        branches, and function boundaries.

        Returns:
            Analysis execution result
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.analyze_control_flow()

            lines = [
                "Control flow analysis executed",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_analyze_control_flow failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_analyze_xrefs() -> str:
        """
        Runs cross-reference analysis.

        Finds cross-references (xrefs) in the current module using
        the x64dbg analxrefs command. This identifies where functions
        and data are referenced from.

        Returns:
            Analysis execution result
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.analyze_cross_references()

            lines = [
                "Cross-reference analysis executed",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_analyze_xrefs failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_analyze_recursive() -> str:
        """
        Runs recursive function analysis.

        Performs recursive analysis starting from the current location
        using the x64dbg analrecur command. This discovers functions
        by following call chains.

        Returns:
            Analysis execution result
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.analyze_recursive()

            lines = [
                "Recursive analysis executed",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("result"):
                lines.append(f"Output: {result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_analyze_recursive failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_exception_handlers() -> str:
        """
        Shows SEH exception handler chain.

        Retrieves the structured exception handler (SEH) chain for
        the current thread using the x64dbg exhandlers command.

        Returns:
            Exception handler chain information
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.get_exception_handlers()

            lines = [
                "Exception handlers retrieved",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("result"):
                lines.append(f"Handlers:\n{result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_get_exception_handlers failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_get_exception_info() -> str:
        """
        Shows current exception details.

        Retrieves details about the current exception (code, address,
        flags) using the x64dbg exinfo command.

        Returns:
            Current exception information
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.get_exception_info()

            lines = [
                "Exception info retrieved",
                f"Success: {result.get('success', 'unknown')}",
            ]
            if result.get("result"):
                lines.append(f"Details:\n{result['result']}")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_get_exception_info failed: {e}")
            return f"Error: {e}"

    # ── Variable management tools ─────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_variable(name: str, value: str) -> str:
        """
        Set a debugger variable.

        Create or update a named variable in x64dbg's variable system.

        Args:
            name: Variable name (letters, digits, underscores; must start with letter/underscore)
            value: Value to assign (numeric or expression)

        Returns:
            Confirmation message

        Example:
            x64dbg_set_variable("my_addr", "0x401000")
            x64dbg_set_variable("counter", "5")

        Use Cases:
            - Store addresses for later reference
            - Create counters for conditional breakpoints
            - Save intermediate analysis values
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.set_variable(name, value)

            lines = [f"Variable set: {name} = {value}"]
            if result.get("result"):
                lines.append(f"Result: {result['result']}")
            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_set_variable failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_delete_variable(name: str) -> str:
        """
        Delete a debugger variable.

        Remove a named variable from x64dbg's variable system.

        Args:
            name: Variable name to delete

        Returns:
            Confirmation message

        Example:
            x64dbg_delete_variable("my_addr")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.delete_variable(name)

            lines = [f"Variable deleted: {name}"]
            if result.get("result"):
                lines.append(f"Result: {result['result']}")
            return "\n".join(lines)

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_delete_variable failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_variables() -> str:
        """
        List all debugger variables.

        Show all variables currently defined in x64dbg's variable system.

        Returns:
            Variable listing

        Use Cases:
            - Review stored analysis values
            - Check variable state during debugging
            - Verify variable assignments
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.list_variables()

            lines = ["Variables:"]
            if result.get("result"):
                lines.append(result["result"])
            elif result.get("message"):
                lines.append(result["message"])
            else:
                lines.append("(no variables or empty result)")

            return "\n".join(lines)

        except Exception as e:
            logger.error(f"x64dbg_list_variables failed: {e}")
            return f"Error: {e}"

    # ── GUI navigation tools ───────────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_navigate_disasm(address: str) -> str:
        """
        Navigate disassembly view to address.

        Move the disassembly window to show code at the specified address.

        Args:
            address: Target address (hex, e.g., "0x401000")

        Returns:
            Confirmation message

        Example:
            x64dbg_navigate_disasm("0x401000")
            x64dbg_navigate_disasm("0x7FF600000000")

        Use Cases:
            - Jump to a function entry point
            - Navigate to a suspicious code location
            - Follow cross-references
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.navigate_disasm(address)
            return f"Disassembly navigated to {address}"

        except Exception as e:
            logger.error(f"x64dbg_navigate_disasm failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_navigate_dump(address: str) -> str:
        """
        Navigate dump view to address.

        Move the hex dump window to show memory at the specified address.

        Args:
            address: Target address (hex, e.g., "0x401000")

        Returns:
            Confirmation message

        Example:
            x64dbg_navigate_dump("0x401000")

        Use Cases:
            - Inspect data at a specific address
            - View string or buffer contents
            - Examine memory structures
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.navigate_dump(address)
            return f"Dump navigated to {address}"

        except Exception as e:
            logger.error(f"x64dbg_navigate_dump failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_show_graph(address: str = "") -> str:
        """
        Show function graph.

        Display the control flow graph for the function at the specified address,
        or the current function if no address is provided.

        Args:
            address: Target address (hex), empty for current function

        Returns:
            Confirmation message

        Example:
            x64dbg_show_graph("0x401000")
            x64dbg_show_graph()

        Use Cases:
            - Visualize function control flow
            - Understand branching logic
            - Analyze complex functions
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.show_graph(address)

            if address and address.strip():
                return f"Graph shown at {address}"
            return "Graph shown at current location"

        except Exception as e:
            logger.error(f"x64dbg_show_graph failed: {e}")
            return f"Error: {e}"

    # ── Privilege management tools ─────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_enable_privilege(name: str) -> str:
        """
        Enable a process privilege.

        Enable a Windows privilege for the debugged process.

        Args:
            name: Privilege name (e.g., "SeDebugPrivilege", "SeShutdownPrivilege")

        Returns:
            Confirmation message

        Example:
            x64dbg_enable_privilege("SeDebugPrivilege")
            x64dbg_enable_privilege("SeShutdownPrivilege")

        Use Cases:
            - Grant debug privileges for process manipulation
            - Enable privileges needed by analyzed malware
            - Escalate process capabilities for testing
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.enable_privilege(name)
            return f"Privilege enabled: {name}"

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_enable_privilege failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_disable_privilege(name: str) -> str:
        """
        Disable a process privilege.

        Disable a Windows privilege for the debugged process.

        Args:
            name: Privilege name (e.g., "SeDebugPrivilege", "SeShutdownPrivilege")

        Returns:
            Confirmation message

        Example:
            x64dbg_disable_privilege("SeDebugPrivilege")

        Use Cases:
            - Restrict process capabilities
            - Test behavior without specific privileges
            - Harden process security posture
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.disable_privilege(name)
            return f"Privilege disabled: {name}"

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_disable_privilege failed: {e}")
            return f"Error: {e}"

    # ── Type System Tools ──────────────────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_add_struct(name: str) -> str:
        """
        Define a new struct type in x64dbg's type system.

        Creates an empty struct that can have members added via x64dbg_add_member.

        Args:
            name: Struct name (valid C identifier, e.g. "IMAGE_DOS_HEADER")

        Returns:
            Confirmation or error message

        Example:
            x64dbg_add_struct("MY_STRUCT")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.add_struct(name)
            success = result.get("success", False)
            if success:
                return f"Struct '{name}' created successfully."
            return f"Failed to create struct '{name}': {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_add_struct failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_add_union(name: str) -> str:
        """
        Define a new union type in x64dbg's type system.

        Creates an empty union that can have members added via x64dbg_add_member.
        Union members share the same memory offset (overlapping layout).

        Args:
            name: Union name (valid C identifier, e.g. "MY_UNION")

        Returns:
            Confirmation or error message

        Example:
            x64dbg_add_union("VALUE_UNION")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.add_union(name)
            success = result.get("success", False)
            if success:
                return f"Union '{name}' created successfully."
            return f"Failed to create union '{name}': {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_add_union failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_add_member(parent: str, type_name: str, member_name: str) -> str:
        """
        Add a member field to an existing struct or union.

        Args:
            parent: Parent struct/union name (e.g. "MY_STRUCT")
            type_name: Type of the member (e.g. "DWORD", "BYTE", "PVOID", "WORD")
            member_name: Name of the member field (e.g. "dwSize", "lpBuffer")

        Returns:
            Confirmation or error message

        Example:
            x64dbg_add_member("MY_STRUCT", "DWORD", "dwSize")
            x64dbg_add_member("MY_STRUCT", "PVOID", "lpBuffer")

        Use Cases:
            - Building struct definitions for Windows API structures
            - Defining custom data structures found in malware
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.add_member(parent, type_name, member_name)
            success = result.get("success", False)
            if success:
                return f"Member '{member_name}' ({type_name}) added to '{parent}'."
            return f"Failed to add member: {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_add_member failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_view_type(type_name: str, address: str) -> str:
        """
        Overlay a struct/type on a memory address for structured viewing.

        This is the key type system tool — it interprets raw memory at the
        given address as the specified struct type, showing field names and values.

        Args:
            type_name: Name of the type to overlay (e.g. "IMAGE_DOS_HEADER")
            address: Memory address to interpret (hex, e.g. "0x00400000")

        Returns:
            Structured memory interpretation showing field values

        Example:
            x64dbg_view_type("IMAGE_DOS_HEADER", "0x00400000")
            x64dbg_view_type("MY_STRUCT", "0x7FFE0000")

        Use Cases:
            - Viewing PE headers as structured data
            - Inspecting Windows API structures in memory
            - Examining custom data structures at known addresses
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.visit_type(type_name, address)
            success = result.get("success", False)
            lines = [f"Type: {type_name}", f"Address: {address}"]
            if success:
                if result.get("result"):
                    lines.append(f"Result:\n{result['result']}")
                if result.get("message"):
                    lines.append(result["message"])
            else:
                lines.append(f"Error: {result.get('message', 'unknown error')}")
            return "\n".join(lines)
        except (ValueError, StructuredBaseError) as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_view_type failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_sizeof_type(type_name: str) -> str:
        """
        Get the size of a type in bytes.

        Args:
            type_name: Name of the type (e.g. "IMAGE_DOS_HEADER", "DWORD")

        Returns:
            Size information for the type

        Example:
            x64dbg_sizeof_type("IMAGE_DOS_HEADER")
            x64dbg_sizeof_type("DWORD")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.sizeof_type(type_name)
            success = result.get("success", False)
            if success:
                msg = result.get("result", result.get("message", ""))
                return f"sizeof({type_name}) = {msg}"
            return f"Failed to get size of '{type_name}': {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_sizeof_type failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_remove_type(type_name: str) -> str:
        """
        Remove a type definition from x64dbg's type system.

        Args:
            type_name: Name of the type to remove

        Returns:
            Confirmation or error message

        Example:
            x64dbg_remove_type("MY_STRUCT")
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.remove_type(type_name)
            success = result.get("success", False)
            if success:
                return f"Type '{type_name}' removed."
            return f"Failed to remove type '{type_name}': {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_remove_type failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_list_types() -> str:
        """
        List all defined types in x64dbg's type system.

        Returns:
            Listing of all registered types

        Example:
            x64dbg_list_types()
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.enum_types()
            success = result.get("success", False)
            lines = ["Defined Types:"]
            if success:
                if result.get("result"):
                    lines.append(result["result"])
                elif result.get("message"):
                    lines.append(result["message"])
                else:
                    lines.append("(no types defined)")
            else:
                lines.append(f"Error: {result.get('message', 'unknown error')}")
            return "\n".join(lines)
        except Exception as e:
            logger.error(f"x64dbg_list_types failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_clear_types() -> str:
        """
        Clear all user-defined types from x64dbg's type system.

        This removes all custom structs, unions, and typedefs.
        Built-in types are not affected.

        Returns:
            Confirmation or error message

        Example:
            x64dbg_clear_types()
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.clear_types()
            success = result.get("success", False)
            if success:
                return "All user-defined types cleared."
            return f"Failed to clear types: {result.get('message', 'unknown error')}"
        except Exception as e:
            logger.error(f"x64dbg_clear_types failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_load_types(filename: str) -> str:
        """
        Load type definitions from a JSON or C header file.

        The file must be within the allowed output directory for security.

        Args:
            filename: Path to the types file (JSON or .h)

        Returns:
            Confirmation or error message

        Example:
            x64dbg_load_types("ntapi.h")
            x64dbg_load_types("types.json")

        Use Cases:
            - Loading Windows SDK type definitions
            - Importing custom type databases for malware analysis
        """
        try:
            if not filename or not filename.strip():
                return "Error: Filename cannot be empty"

            # Security: validate path is within allowed directory
            safe_path = sanitize_output_path(Path(filename.strip()), DUMP_OUTPUT_DIR)
            resolved_path = str(safe_path)

            bridge = get_x64dbg_bridge()
            result = bridge.load_types(resolved_path)
            success = result.get("success", False)
            if success:
                return f"Types loaded from: {resolved_path}"
            return f"Failed to load types: {result.get('message', 'unknown error')}"
        except PathTraversalError as e:
            return f"Error: Invalid file path - {e}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_load_types failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_parse_types(definition: str) -> str:
        """
        Parse C header text to define types inline.

        Accepts C-style type definitions and registers them in
        x64dbg's type system without needing a file.

        Args:
            definition: C header text with type definitions

        Returns:
            Confirmation or error message

        Example:
            x64dbg_parse_types("typedef struct { DWORD cb; LPSTR lpReserved; } STARTUPINFOA;")
            x64dbg_parse_types("struct MyData { int x; int y; char name[32]; };")

        Use Cases:
            - Quickly defining structures from documentation
            - Parsing struct definitions found in decompiled code
        """
        try:
            if not definition or not definition.strip():
                return "Error: Type definition text cannot be empty"

            bridge = get_x64dbg_bridge()
            result = bridge.parse_types(definition.strip())
            success = result.get("success", False)
            if success:
                return "Types parsed successfully."
            return f"Failed to parse types: {result.get('message', 'unknown error')}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_parse_types failed: {e}")
            return f"Error: {e}"

    # ── Conditional Tracing Tools ───────────────────────────────────

    @app.tool()
    @log_dynamic_tool
    def x64dbg_trace_into_conditional(
        condition: str,
        max_steps: int = 50000,
        log_text: str = "",
        log_condition: str = "",
        command_text: str = "",
        command_condition: str = "",
        log_file: str = "",
    ) -> str:
        """
        Trace into (following calls) until a condition is met.

        This is the most powerful x64dbg automation feature. It single-steps
        into calls, evaluating an expression at each step, and stops when the
        condition becomes true. Optionally logs register/memory state per step.

        Args:
            condition: Break condition expression (e.g. "rax==1", "rip>=0x500000")
            max_steps: Maximum trace steps before aborting (default: 50000)
            log_text: Format string logged per step (e.g. "RIP={rip} RAX={rax}")
            log_condition: Only log when this condition is true
            command_text: x64dbg command to run per step
            command_condition: Only run command when this condition is true
            log_file: File path to write trace log (relative paths resolve under dump dir)

        Returns:
            Trace result with address where stopped

        Examples:
            x64dbg_trace_into_conditional("rax==1")
            x64dbg_trace_into_conditional("rip>=0x500000", log_text="RIP={rip}")
            x64dbg_trace_into_conditional("eax!=0", max_steps=100000, log_file="trace.log")

        Use Cases:
            - Find where a register gets a specific value
            - Trace until execution reaches a module/address range
            - Log execution path with register values at each step
            - Trace through unpacking stubs
        """
        try:
            if not condition or not condition.strip():
                return "Error: Condition cannot be empty"

            resolved_log_file = ""
            if log_file:
                try:
                    DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    log_path = Path(log_file)
                    if not log_path.is_absolute():
                        log_path = DUMP_OUTPUT_DIR / log_path
                    safe_path = sanitize_output_path(log_path, DUMP_OUTPUT_DIR)
                    resolved_log_file = str(safe_path)
                except PathTraversalError as e:
                    return f"Error: Invalid log file path - {e}"
                except ValueError as e:
                    return f"Error: Invalid path - {e}"

            bridge = get_x64dbg_bridge()
            result = bridge.trace_into_conditional(
                condition=condition,
                max_steps=max_steps,
                log_text=log_text,
                log_condition=log_condition,
                command_text=command_text,
                command_condition=command_condition,
                log_file=resolved_log_file,
            )

            if result.get("success"):
                lines = [
                    "Trace into completed (condition met)",
                    f"Condition: {result.get('condition', condition)}",
                    f"Stopped at: {result.get('current_address', 'unknown')}",
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms",
                ]
                if resolved_log_file:
                    lines.append(f"Log file: {resolved_log_file}")
                lines.append("\nUse x64dbg_get_registers() to inspect state.")
                return "\n".join(lines)
            else:
                return (
                    f"Trace into did not complete (timeout or max steps reached)\n"
                    f"Condition: {condition}\n"
                    f"Max steps: {max_steps}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms\n\n"
                    f"Try increasing max_steps or use x64dbg_pause() to stop."
                )

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_trace_into_conditional failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_trace_over_conditional(
        condition: str,
        max_steps: int = 50000,
        log_text: str = "",
        log_condition: str = "",
        command_text: str = "",
        command_condition: str = "",
        log_file: str = "",
    ) -> str:
        """
        Trace over (skipping calls) until a condition is met.

        Like trace_into_conditional but steps OVER function calls instead of
        following them. Faster for high-level tracing when you don't need to
        enter subroutines.

        Args:
            condition: Break condition expression (e.g. "rax==1", "rip>=0x500000")
            max_steps: Maximum trace steps before aborting (default: 50000)
            log_text: Format string logged per step (e.g. "RIP={rip} RAX={rax}")
            log_condition: Only log when this condition is true
            command_text: x64dbg command to run per step
            command_condition: Only run command when this condition is true
            log_file: File path to write trace log (relative paths resolve under dump dir)

        Returns:
            Trace result with address where stopped

        Examples:
            x64dbg_trace_over_conditional("rax==1")
            x64dbg_trace_over_conditional("eip<module.base", max_steps=100000)

        Use Cases:
            - High-level tracing without entering library calls
            - Find where a value changes in the main module
            - Faster alternative to trace_into when call depth is irrelevant
        """
        try:
            if not condition or not condition.strip():
                return "Error: Condition cannot be empty"

            resolved_log_file = ""
            if log_file:
                try:
                    DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
                    log_path = Path(log_file)
                    if not log_path.is_absolute():
                        log_path = DUMP_OUTPUT_DIR / log_path
                    safe_path = sanitize_output_path(log_path, DUMP_OUTPUT_DIR)
                    resolved_log_file = str(safe_path)
                except PathTraversalError as e:
                    return f"Error: Invalid log file path - {e}"
                except ValueError as e:
                    return f"Error: Invalid path - {e}"

            bridge = get_x64dbg_bridge()
            result = bridge.trace_over_conditional(
                condition=condition,
                max_steps=max_steps,
                log_text=log_text,
                log_condition=log_condition,
                command_text=command_text,
                command_condition=command_condition,
                log_file=resolved_log_file,
            )

            if result.get("success"):
                lines = [
                    "Trace over completed (condition met)",
                    f"Condition: {result.get('condition', condition)}",
                    f"Stopped at: {result.get('current_address', 'unknown')}",
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms",
                ]
                if resolved_log_file:
                    lines.append(f"Log file: {resolved_log_file}")
                lines.append("\nUse x64dbg_get_registers() to inspect state.")
                return "\n".join(lines)
            else:
                return (
                    f"Trace over did not complete (timeout or max steps reached)\n"
                    f"Condition: {condition}\n"
                    f"Max steps: {max_steps}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms\n\n"
                    f"Try increasing max_steps or use x64dbg_pause() to stop."
                )

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_trace_over_conditional failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_trace_to_oep(max_steps: int = 50000) -> str:
        """
        Trace execution to find the Original Entry Point (OEP) of a packed binary.

        Uses x64dbg's trace-into-beyond-record (tibt) which tracks all executed
        addresses and stops when execution reaches a never-before-seen address
        region — typically the OEP after unpacking completes.

        Args:
            max_steps: Maximum trace steps (default: 50000, increase for complex packers)

        Returns:
            Likely OEP address where execution landed

        Examples:
            x64dbg_trace_to_oep()
            x64dbg_trace_to_oep(max_steps=200000)

        Use Cases:
            - Unpack UPX, Themida, VMProtect, and other packers
            - Find the real entry point of packed malware
            - Automated unpacking workflows
        """
        try:
            bridge = get_x64dbg_bridge()
            result = bridge.trace_into_beyond_record(max_steps=max_steps)

            if result.get("success"):
                return (
                    f"Trace to OEP completed\n"
                    f"Likely OEP: {result.get('current_address', 'unknown')}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms\n\n"
                    f"Use x64dbg_dump_module() to dump the unpacked binary.\n"
                    f"Use x64dbg_get_registers() to verify execution context."
                )
            else:
                return (
                    f"Trace to OEP did not complete (max steps reached)\n"
                    f"Max steps: {max_steps}\n"
                    f"Elapsed: {result.get('elapsed_ms', 0)}ms\n\n"
                    f"Try increasing max_steps for complex packers."
                )

        except Exception as e:
            logger.error(f"x64dbg_trace_to_oep failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_trace_log(text: str, condition: str = "") -> str:
        """
        Configure what gets logged at each trace step.

        Sets the log format string for subsequent trace operations
        (trace_into_conditional, trace_over_conditional).

        Args:
            text: Log format string with x64dbg specifiers
            condition: Optional condition — only log when this expression is true

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_trace_log("RIP={rip} RAX={rax}")
            x64dbg_set_trace_log("{rip}: {dis.sel()}", "rax!=0")
            x64dbg_set_trace_log("ESP={esp} [ESP]={[esp]}")

        Format Specifiers:
            {rax}, {rbx}, etc. — register values
            {[esp]}, {[rax+8]} — memory dereference
            {dis.sel()} — disassembly at current address
            {mem;addr;size} — memory dump
        """
        try:
            if not text or not text.strip():
                return "Error: Log text cannot be empty"

            bridge = get_x64dbg_bridge()
            bridge.set_trace_log(text, condition)

            msg = f"Trace log configured: {text.strip()}"
            if condition:
                msg += f"\nCondition: {condition.strip()}"
            return msg

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_set_trace_log failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_trace_command(command: str, condition: str = "") -> str:
        """
        Configure a command to execute at each trace step.

        Sets an x64dbg command that runs at every step during subsequent
        trace operations.

        Args:
            command: x64dbg command to execute per step
            condition: Optional condition — only run when this expression is true

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_trace_command("log \\"Step at {rip}\\"")
            x64dbg_set_trace_command("SetBreakpointCondition rip, \\"rax==0\\"", "rip>=0x500000")
        """
        try:
            if not command or not command.strip():
                return "Error: Command cannot be empty"

            bridge = get_x64dbg_bridge()
            bridge.set_trace_command(command, condition)

            msg = f"Trace command configured: {command.strip()}"
            if condition:
                msg += f"\nCondition: {condition.strip()}"
            return msg

        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_set_trace_command failed: {e}")
            return f"Error: {e}"

    @app.tool()
    @log_dynamic_tool
    def x64dbg_set_trace_log_file(path: str) -> str:
        """
        Set the output file for trace logging.

        Trace log output from subsequent trace operations will be written
        to this file. Relative paths resolve under the dump output directory.

        Args:
            path: File path for trace log output

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_trace_log_file("trace_output.log")
            x64dbg_set_trace_log_file("/tmp/malware_trace.log")
        """
        try:
            if not path or not path.strip():
                return "Error: Path cannot be empty"

            DUMP_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            log_path = Path(path)
            if not log_path.is_absolute():
                log_path = DUMP_OUTPUT_DIR / log_path
            safe_path = sanitize_output_path(log_path, DUMP_OUTPUT_DIR)

            bridge = get_x64dbg_bridge()
            bridge.set_trace_log_file(str(safe_path))

            return f"Trace log file set: {safe_path}"

        except PathTraversalError as e:
            return f"Error: Invalid path - {e}"
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            logger.error(f"x64dbg_set_trace_log_file failed: {e}")
            return f"Error: {e}"

    logger.info("Registered 112 dynamic analysis tools")
