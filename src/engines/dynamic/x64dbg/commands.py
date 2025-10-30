"""
High-level x64dbg command wrappers for MCP tools.

Provides convenient functions for common debugging workflows.
"""

import logging
from pathlib import Path
from typing import Any

from .bridge import X64DbgBridge

logger = logging.getLogger(__name__)


class X64DbgCommands:
    """High-level command interface for x64dbg."""

    def __init__(self, bridge: X64DbgBridge | None = None):
        """
        Initialize commands interface.

        Args:
            bridge: X64DbgBridge instance (creates new if None)
        """
        self.bridge = bridge or X64DbgBridge()

    def ensure_connected(self) -> None:
        """Ensure bridge is connected to x64dbg."""
        if not self.bridge.is_connected():
            self.bridge.connect()

    def get_status_summary(self) -> str:
        """
        Get formatted status summary.

        Returns:
            Human-readable status string
        """
        self.ensure_connected()
        location = self.bridge.get_current_location()

        status = []
        status.append(f"State: {location['state']}")
        status.append(f"Address: 0x{location['address']}")

        if location['binary_path']:
            status.append(f"Binary: {Path(location['binary_path']).name}")

        return "\n".join(status)

    def run_to_address(self, address: str) -> dict[str, Any]:
        """
        Run until reaching specified address.

        Sets temporary breakpoint, runs, then removes breakpoint.

        Args:
            address: Target address

        Returns:
            Execution state when breakpoint hit
        """
        self.ensure_connected()

        # Set breakpoint
        self.bridge.set_breakpoint(address)

        # Run
        self.bridge.run()

        # TODO: Wait for breakpoint hit (needs event system)

        # Remove breakpoint
        self.bridge.delete_breakpoint(address)

        return self.bridge.get_current_location()

    def dump_registers(self) -> str:
        """
        Get formatted register dump.

        Returns:
            Formatted register string
        """
        self.ensure_connected()
        registers = self.bridge.get_registers()

        # Format in columns
        lines = []
        lines.append("Registers:")
        lines.append("-" * 40)

        # Group by category
        general = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"]
        extended = [f"r{i}" for i in range(8, 16)]

        for reg in general:
            if reg in registers:
                lines.append(f"{reg.upper():4} = 0x{registers[reg]}")

        lines.append("")
        for reg in extended:
            if reg in registers:
                lines.append(f"{reg.upper():4} = 0x{registers[reg]}")

        return "\n".join(lines)

    def trace_execution(self, steps: int = 10) -> list[dict[str, str]]:
        """
        Trace execution for N steps.

        Args:
            steps: Number of steps to trace

        Returns:
            List of execution states
        """
        self.ensure_connected()

        trace = []
        for i in range(steps):
            state = self.bridge.step_into()
            registers = self.bridge.get_registers()

            trace.append({
                "step": i,
                "address": state["address"],
                "rip": registers.get("rip", "unknown")
            })

        return trace

    def find_function_calls(self, start_address: str, count: int = 100) -> list[str]:
        """
        Find CALL instructions starting from address.

        Args:
            start_address: Start address
            count: Number of instructions to scan

        Returns:
            List of call target addresses
        """
        self.ensure_connected()

        instructions = self.bridge.disassemble(start_address, count)
        calls = []

        for instr in instructions:
            if instr.get("mnemonic", "").startswith("call"):
                target = instr.get("operand", "")
                if target:
                    calls.append(target)

        return calls

    def search_pattern(self, pattern: bytes, start: str | None = None) -> list[str]:
        """
        Search for byte pattern in memory.

        Args:
            pattern: Byte pattern to search
            start: Optional start address

        Returns:
            List of addresses where pattern found
        """
        # This would require more sophisticated memory scanning
        # For now, return placeholder
        logger.warning("Pattern search not yet fully implemented")
        return []

    def set_breakpoints_on_apis(self, api_names: list[str]) -> int:
        """
        Set breakpoints on Windows API functions.

        Args:
            api_names: List of API function names

        Returns:
            Number of breakpoints set
        """
        self.ensure_connected()

        # This requires resolving API addresses
        # Would need to query module exports
        logger.warning("API breakpoint setting not yet fully implemented")
        return 0
