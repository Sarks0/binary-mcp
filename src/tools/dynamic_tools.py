"""
Dynamic analysis MCP tools using x64dbg.

Provides debugger-based analysis capabilities.
"""

import logging
import os

from fastmcp import FastMCP

from src.engines.dynamic.x64dbg.bridge import X64DbgBridge
from src.engines.dynamic.x64dbg.commands import X64DbgCommands

logger = logging.getLogger(__name__)

# Global x64dbg instances (initialized on first use)
_x64dbg_bridge: X64DbgBridge | None = None
_x64dbg_commands: X64DbgCommands | None = None


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


def register_dynamic_tools(app: FastMCP) -> None:
    """
    Register all dynamic analysis tools with the MCP server.

    Args:
        app: FastMCP Server instance
    """

    @app.tool()
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

        except Exception as e:
            logger.error(f"x64dbg_set_breakpoint failed: {e}")
            return f"Error: {e}"

    @app.tool()
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

        except Exception as e:
            logger.error(f"x64dbg_delete_breakpoint failed: {e}")
            return f"Error: {e}"

    @app.tool()
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

    @app.tool()
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
    def x64dbg_disassemble(address: str, count: int = 20) -> str:
        """
        Disassemble instructions at address.

        Args:
            address: Start address
            count: Number of instructions to disassemble (default: 20)

        Returns:
            Disassembly listing

        Example output:
            00401000: push rbp
            00401001: mov rbp, rsp
            ...
        """
        try:
            bridge = get_x64dbg_bridge()
            instructions = bridge.disassemble(address, count)

            result = [f"Disassembly at {address}:", "-" * 60]

            for instr in instructions:
                addr = instr.get("address", "")
                mnemonic = instr.get("mnemonic", "")
                operand = instr.get("operand", "")
                result.append(f"{addr}: {mnemonic} {operand}".strip())

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_disassemble failed: {e}")
            return f"Error: {e}"

    @app.tool()
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
                rip = entry["rip"]
                result.append(f"Step {step}: 0x{addr} RIP={rip}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_trace_execution failed: {e}")
            return f"Error: {e}"

    @app.tool()
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
            frames = bridge.get_stack(depth)

            if not frames:
                return "No stack frames available"

            result = [f"Call Stack ({len(frames)} frames):", "-" * 60]

            for i, frame in enumerate(frames):
                addr = frame.get("address", "unknown")
                comment = frame.get("comment", "")
                if comment:
                    result.append(f"{i}. 0x{addr} ({comment})")
                else:
                    result.append(f"{i}. 0x{addr}")

            return "\n".join(result)

        except Exception as e:
            logger.error(f"x64dbg_get_stack failed: {e}")
            return f"Error: {e}"

    @app.tool()
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
        try:
            bridge = get_x64dbg_bridge()
            bridge.dump_memory(address, size, output_file)

            return f"Memory dumped successfully\n" \
                   f"Address: {address}\n" \
                   f"Size: {size} bytes ({size / 1024:.2f} KB)\n" \
                   f"Output: {output_file}"

        except Exception as e:
            logger.error(f"x64dbg_dump_memory failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory dump requires C++ plugin implementation\n"
                        "This feature is planned but not yet available in the plugin.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
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

    @app.tool()
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

        except Exception as e:
            logger.error(f"x64dbg_set_hardware_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Hardware breakpoints require C++ plugin implementation\n"
                        "This P1 feature is essential for anti-debug bypass.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
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
    def x64dbg_set_memory_bp(address: str, bp_type: str = "access", size: int = 1) -> str:
        """
        Set memory breakpoint.

        Break on memory access/read/write/execute.

        Args:
            address: Memory address
            bp_type: Type ("access", "read", "write", "execute")
            size: Size in bytes (1, 2, 4, 8)

        Returns:
            Confirmation message

        Examples:
            x64dbg_set_memory_bp("0x500000", "write", 4)    # Break on 4-byte write
            x64dbg_set_memory_bp("0x401000", "access", 1)   # Break on any access
            x64dbg_set_memory_bp("0x600000", "read", 8)     # Break on 8-byte read

        Use Cases:
            - Monitor variable changes (write breakpoint)
            - Track memory access patterns
            - Find where data is used (read breakpoint)
            - Detect code execution in data regions

        Priority: P0 (Critical)
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.set_memory_breakpoint(address, bp_type, size)

            return (f"Memory breakpoint set\n"
                    f"Address: {address}\n"
                    f"Type: {bp_type}\n"
                    f"Size: {size} bytes")

        except Exception as e:
            logger.error(f"x64dbg_set_memory_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Memory breakpoints require C++ plugin implementation\n"
                        "This P0 feature is essential for monitoring memory access.\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
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

        except Exception as e:
            logger.error(f"x64dbg_delete_memory_bp failed: {e}")
            if "Not yet implemented" in str(e):
                return ("Error: Delete memory breakpoint requires C++ plugin implementation\n"
                        "See FUTURE_FEATURES.md for implementation status.")
            return f"Error: {e}"

    @app.tool()
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

    # =========================================================================
    # Event System Tools
    # =========================================================================

    @app.tool()
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

    logger.info("Registered 45 dynamic analysis tools")
