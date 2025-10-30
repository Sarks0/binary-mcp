"""
Base interface for dynamic analysis engines (debuggers).

All debuggers should implement this interface for consistency.
"""

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any


class DebuggerState(Enum):
    """Debugger execution state."""
    NOT_LOADED = "not_loaded"
    LOADED = "loaded"
    RUNNING = "running"
    PAUSED = "paused"
    TERMINATED = "terminated"


class Debugger(ABC):
    """Base class for debugger engines."""

    @abstractmethod
    def connect(self, timeout: int = 10) -> bool:
        """
        Connect to the debugger.

        Args:
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully

        Raises:
            ConnectionError: If connection fails
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Disconnect from the debugger."""
        pass

    @abstractmethod
    def load_binary(self, binary_path: Path, args: list[str] | None = None) -> bool:
        """
        Load a binary into the debugger.

        Args:
            binary_path: Path to the binary
            args: Optional command-line arguments

        Returns:
            True if loaded successfully
        """
        pass

    @abstractmethod
    def set_breakpoint(self, address: str) -> bool:
        """
        Set a breakpoint at an address.

        Args:
            address: Memory address (hex string, e.g., "0x401000")

        Returns:
            True if breakpoint set successfully
        """
        pass

    @abstractmethod
    def delete_breakpoint(self, address: str) -> bool:
        """
        Delete a breakpoint.

        Args:
            address: Memory address of breakpoint

        Returns:
            True if deleted successfully
        """
        pass

    @abstractmethod
    def run(self) -> DebuggerState:
        """
        Start or resume execution.

        Returns:
            New debugger state
        """
        pass

    @abstractmethod
    def pause(self) -> bool:
        """
        Pause execution.

        Returns:
            True if paused successfully
        """
        pass

    @abstractmethod
    def step_into(self) -> dict[str, Any]:
        """
        Single-step into the next instruction.

        Returns:
            Current execution state (registers, instruction, etc.)
        """
        pass

    @abstractmethod
    def step_over(self) -> dict[str, Any]:
        """
        Step over the next instruction.

        Returns:
            Current execution state
        """
        pass

    @abstractmethod
    def get_registers(self) -> dict[str, str]:
        """
        Get current register values.

        Returns:
            Dictionary mapping register names to hex values
        """
        pass

    @abstractmethod
    def read_memory(self, address: str, size: int) -> bytes:
        """
        Read memory from the debugged process.

        Args:
            address: Memory address (hex string)
            size: Number of bytes to read

        Returns:
            Raw bytes from memory
        """
        pass

    @abstractmethod
    def write_memory(self, address: str, data: bytes) -> bool:
        """
        Write memory to the debugged process.

        Args:
            address: Memory address (hex string)
            data: Bytes to write

        Returns:
            True if write successful
        """
        pass

    @abstractmethod
    def get_state(self) -> DebuggerState:
        """
        Get current debugger state.

        Returns:
            Current state
        """
        pass

    @abstractmethod
    def get_current_location(self) -> dict[str, Any]:
        """
        Get current execution location.

        Returns:
            Dictionary with address, instruction, module, etc.
        """
        pass
