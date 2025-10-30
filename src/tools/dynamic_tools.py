"""
Dynamic analysis MCP tools using x64dbg.

Provides debugger-based analysis capabilities.
"""

import logging

from mcp.server import Server

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
        _x64dbg_bridge = X64DbgBridge()
        logger.info("Initialized x64dbg bridge")
    return _x64dbg_bridge


def get_x64dbg_commands() -> X64DbgCommands:
    """Get or create x64dbg commands instance."""
    global _x64dbg_commands
    if _x64dbg_commands is None:
        _x64dbg_commands = X64DbgCommands(get_x64dbg_bridge())
        logger.info("Initialized x64dbg commands")
    return _x64dbg_commands


def register_dynamic_tools(app: Server) -> None:
    """
    Register all dynamic analysis tools with the MCP server.

    Args:
        app: MCP Server instance
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
        """
        try:
            bridge = get_x64dbg_bridge()
            bridge.run()
            return "Debugger running...\nUse x64dbg_pause to pause execution."
        except Exception as e:
            logger.error(f"x64dbg_run failed: {e}")
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

    logger.info("Registered 14 dynamic analysis tools")
