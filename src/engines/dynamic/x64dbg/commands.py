"""
High-level x64dbg command wrappers for MCP tools.

Provides convenient functions for common debugging workflows.
"""

import logging
from pathlib import Path
from typing import Any

from src.utils.formatters import neutralise_untrusted_delimiters

from .bridge import X64DbgAPIError, X64DbgBridge

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
        # When the target is running, the address is the last captured context,
        # not a live value, so the caller must not read it as "where we are now"
        # (operator report X64M-01). Older plugin builds send no is_running;
        # there the field is None and this note is correctly omitted.
        if location.get("is_running"):
            status.append(
                f"Address: 0x{location['address']} "
                "(last captured context -- debuggee is RUNNING, not paused here)"
            )
        else:
            status.append(f"Address: 0x{location['address']}")
        tid = location.get("thread_id")
        if tid:
            status.append(f"Thread: {tid}")

        # A build that cannot report its version is one from before the module
        # and thread fixes, so say so rather than omitting the line: a missing
        # field would read as "fine" when it is the thing to act on.
        version = location.get("plugin_version")
        if version:
            status.append(f"Plugin: v{version}")
        else:
            status.append(
                "Plugin: version not reported -- this build predates the "
                "module/thread fixes. Rebuild and reinstall the plugin and "
                "obsidian_server.exe together."
            )

        if location['binary_path']:
            status.append(f"Binary: {Path(location['binary_path']).name}")

        # The main module's name and base are what every static->runtime
        # address conversion needs; surfacing them here saves a round trip and
        # tells the caller straight away whether a process is loaded at all.
        try:
            main_module = self.bridge.get_main_module()
        except Exception:
            main_module = None

        if main_module:
            # Audit F-7: the module name is the sample's own filename, so it is
            # attacker text. It is one inline field rather than a block, so
            # neutralise the envelope sentinels rather than fencing. The base
            # is a number the debugger computed and needs no treatment.
            status.append(
                f"Main module: "
                f"{neutralise_untrusted_delimiters(main_module['display_name'])} "
                f"@ 0x{main_module['base']:X}"
            )
        else:
            status.append("Main module: none (no process loaded)")

        return "\n".join(status)

    def run_to_address(self, address: str, timeout: int = 30000) -> dict[str, Any]:
        """
        Run until execution reaches ``address``.

        Sets a temporary breakpoint (unless one is already there), resumes,
        and waits for the debugger to pause. The temporary breakpoint is
        removed afterwards whatever happened; a breakpoint the caller had
        already set at that address is left alone.

        Execution can pause somewhere else first -- another breakpoint, an
        exception -- or not pause before the timeout. Both are reported
        rather than raised, because the debuggee's state after them is
        exactly what the caller needs to know.

        Args:
            address: Target address (hex string)
            timeout: Maximum wait in milliseconds

        Returns:
            Dictionary with ``reached`` (paused at the target), ``target``,
            ``address`` (where execution is now), ``state``, ``elapsed_ms``,
            and ``error`` when it did not pause in time.
        """
        self.ensure_connected()

        target_hex = self.bridge._normalize_address(address)
        target = int(target_hex, 16)

        def _same_address(value: Any) -> bool:
            try:
                return int(str(value), 16) == target
            except (TypeError, ValueError):
                return False

        already_set = any(
            _same_address(bp.get("address"))
            for bp in self.bridge.list_breakpoints()
        )
        if not already_set:
            self.bridge.set_breakpoint(target_hex)

        wait_result: dict[str, Any] = {}
        wait_error: str | None = None
        try:
            self.bridge.run()
            try:
                wait_result = self.bridge.wait_until_paused(timeout=timeout)
            except X64DbgAPIError as e:
                # A genuine fault (not the ordinary timeout, which now comes
                # back as a structured success=False body).
                wait_error = e.api_message
        finally:
            if not already_set:
                try:
                    self.bridge.delete_breakpoint(target_hex)
                except Exception as e:
                    logger.warning(
                        f"Could not remove temporary breakpoint at 0x{target_hex}: {e}"
                    )

        location = self.bridge.get_current_location()
        # A timeout now arrives as a structured success=False body rather than
        # an exception; treat either as "did not pause in time".
        timed_out = wait_error is not None or not wait_result.get("success", False)
        result: dict[str, Any] = {
            "target": target_hex,
            "address": wait_result.get(
                "current_address", location.get("address", "unknown")
            ),
            "state": location.get("state", "unknown"),
            "elapsed_ms": wait_result.get("elapsed_ms", 0),
        }
        if timed_out:
            result["reached"] = False
            result["error"] = wait_error or wait_result.get(
                "error", "Timed out waiting for the debugger to pause"
            )
            result["state"] = wait_result.get("current_state", "running")
        else:
            result["reached"] = _same_address(
                wait_result.get("current_address", result["address"])
            )
        return result

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

        # Group by category based on architecture
        arch = self.bridge._detect_architecture()
        if arch == "x86":
            general = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
            extended = []
        else:
            general = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"]
            extended = [f"r{i}" for i in range(8, 16)]

        for reg in general:
            if reg in registers:
                lines.append(f"{reg.upper():4} = 0x{registers[reg]}")

        if extended:
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

            ip_reg = "eip" if self.bridge._detect_architecture() == "x86" else "rip"
            trace.append({
                "step": i,
                "address": state["address"],
                ip_reg: registers.get(ip_reg, "unknown")
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
