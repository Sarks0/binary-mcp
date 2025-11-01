"""
x64dbg HTTP bridge client.

Communicates with the x64dbg native plugin via HTTP API.
"""

import logging
import tempfile
from pathlib import Path
from typing import Any

import requests

from ..base import Debugger, DebuggerState

logger = logging.getLogger(__name__)


class X64DbgBridge(Debugger):
    """Client for x64dbg MCP plugin HTTP API."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8765, timeout: int = 30):
        """
        Initialize x64dbg bridge.

        Args:
            host: HTTP API host (default: localhost)
            port: HTTP API port (default: 8765)
            timeout: Request timeout in seconds
        """
        self.base_url = f"http://{host}:{port}"
        self.timeout = timeout
        self.connected = False
        self._auth_token = None

        logger.info(f"Initialized x64dbg bridge: {self.base_url}")

    def _read_auth_token(self) -> str | None:
        """
        Read authentication token from file created by x64dbg plugin.

        Returns:
            Authentication token or None if not found

        Raises:
            RuntimeError: If token file cannot be read
        """
        # Token file is created by x64dbg plugin in %TEMP%
        temp_dir = tempfile.gettempdir()
        token_file = Path(temp_dir) / "x64dbg_mcp_token.txt"

        if not token_file.exists():
            raise RuntimeError(
                f"Authentication token file not found: {token_file}\n"
                "Ensure x64dbg plugin is loaded and running."
            )

        try:
            with open(token_file) as f:
                token = f.read().strip()

            if not token:
                raise RuntimeError("Authentication token file is empty")

            logger.debug(f"Read authentication token ({len(token)} chars)")
            return token

        except Exception as e:
            raise RuntimeError(f"Failed to read authentication token: {e}")

    def _request(self, endpoint: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Make HTTP request to plugin API.

        Args:
            endpoint: API endpoint path
            data: Optional JSON data for POST request

        Returns:
            JSON response as dictionary

        Raises:
            ConnectionError: If request fails
            RuntimeError: If API returns error or authentication fails
        """
        url = f"{self.base_url}{endpoint}"

        # Read authentication token if not already cached
        if self._auth_token is None:
            try:
                self._auth_token = self._read_auth_token()
            except RuntimeError as e:
                logger.error(f"Authentication failed: {e}")
                raise ConnectionError(
                    f"Cannot authenticate with x64dbg plugin: {e}\n"
                    "Make sure the x64dbg plugin is loaded and running."
                )

        # Prepare headers with authentication
        headers = {
            "Authorization": f"Bearer {self._auth_token}",
            "Content-Type": "application/json"
        }

        try:
            if data is None:
                response = requests.get(url, headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, json=data, headers=headers, timeout=self.timeout)

            response.raise_for_status()
            result = response.json()

            if not result.get("success", False):
                error = result.get("error", "Unknown error")
                raise RuntimeError(f"API error: {error}")

            return result

        except requests.RequestException as e:
            logger.error(f"HTTP request failed: {e}")

            # Check if it's an authentication error
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 401:
                raise ConnectionError(
                    "Authentication failed: Invalid or expired token.\n"
                    "Try restarting x64dbg to generate a new token."
                )

            raise ConnectionError(f"Failed to connect to x64dbg: {e}")

    def connect(self, timeout: int = 10) -> bool:
        """
        Connect to x64dbg plugin.

        Args:
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully

        Raises:
            ConnectionError: If connection fails
        """
        try:
            result = self._request("/api/status")
            self.connected = True
            logger.info(f"Connected to x64dbg - state: {result.get('state')}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            raise ConnectionError(f"Cannot connect to x64dbg plugin at {self.base_url}")

    def disconnect(self) -> None:
        """Disconnect from x64dbg plugin."""
        self.connected = False
        logger.info("Disconnected from x64dbg")

    def load_binary(self, binary_path: Path, args: list[str] | None = None) -> bool:
        """
        Load a binary into x64dbg.

        Note: Currently requires manual loading in x64dbg GUI.
        Future: Automate via plugin API.

        Args:
            binary_path: Path to the binary
            args: Optional command-line arguments

        Returns:
            True if loaded successfully
        """
        data = {
            "path": str(binary_path),
            "args": args or []
        }

        try:
            self._request("/api/load", data)
            logger.info(f"Loaded binary: {binary_path}")
            return True
        except RuntimeError:
            logger.warning("Binary loading not fully implemented in plugin")
            return False

    def set_breakpoint(self, address: str) -> bool:
        """
        Set a breakpoint at an address.

        Args:
            address: Memory address (hex string, e.g., "0x401000" or "401000")

        Returns:
            True if breakpoint set successfully
        """
        # Normalize address
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        self._request("/api/breakpoint/set", data)
        logger.info(f"Set breakpoint at {address}")
        return True

    def delete_breakpoint(self, address: str) -> bool:
        """
        Delete a breakpoint.

        Args:
            address: Memory address of breakpoint

        Returns:
            True if deleted successfully
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        self._request("/api/breakpoint/delete", data)
        logger.info(f"Deleted breakpoint at {address}")
        return True

    def list_breakpoints(self) -> list[dict[str, Any]]:
        """
        List all breakpoints.

        Returns:
            List of breakpoint dictionaries
        """
        result = self._request("/api/breakpoint/list")
        return result.get("breakpoints", [])

    def run(self) -> DebuggerState:
        """
        Start or resume execution.

        Returns:
            New debugger state
        """
        result = self._request("/api/run")
        state_str = result.get("state", "running")
        logger.info(f"Debugger running - state: {state_str}")
        return self._parse_state(state_str)

    def pause(self) -> bool:
        """
        Pause execution.

        Returns:
            True if paused successfully
        """
        self._request("/api/pause")
        logger.info("Debugger paused")
        return True

    def step_into(self) -> dict[str, Any]:
        """
        Single-step into the next instruction.

        Returns:
            Current execution state (registers, instruction, etc.)
        """
        result = self._request("/api/step_into")
        address = result.get("address", "unknown")
        logger.debug(f"Stepped into: {address}")

        return {
            "address": address,
            "state": "paused"
        }

    def step_over(self) -> dict[str, Any]:
        """
        Step over the next instruction.

        Returns:
            Current execution state
        """
        result = self._request("/api/step_over")
        address = result.get("address", "unknown")
        logger.debug(f"Stepped over: {address}")

        return {
            "address": address,
            "state": "paused"
        }

    def step_out(self) -> dict[str, Any]:
        """
        Step out of current function.

        Returns:
            Current execution state
        """
        result = self._request("/api/step_out")
        address = result.get("address", "unknown")
        logger.debug(f"Stepped out to: {address}")

        return {
            "address": address,
            "state": "paused"
        }

    def get_registers(self) -> dict[str, str]:
        """
        Get current register values.

        Returns:
            Dictionary mapping register names to hex values
        """
        result = self._request("/api/registers")

        # Extract register values (remove 'success' key)
        registers = {k: v for k, v in result.items() if k != "success"}

        logger.debug(f"Got {len(registers)} register values")
        return registers

    def get_stack(self, depth: int = 20) -> list[dict[str, str]]:
        """
        Get stack trace.

        Args:
            depth: Number of stack frames to retrieve

        Returns:
            List of stack frame dictionaries
        """
        data = {"depth": depth}
        result = self._request("/api/stack", data)
        return result.get("frames", [])

    def get_modules(self) -> list[dict[str, Any]]:
        """
        Get loaded modules.

        Returns:
            List of module dictionaries
        """
        result = self._request("/api/modules")
        return result.get("modules", [])

    def get_threads(self) -> list[dict[str, Any]]:
        """
        Get thread list.

        Returns:
            List of thread dictionaries
        """
        result = self._request("/api/threads")
        return result.get("threads", [])

    def read_memory(self, address: str, size: int) -> bytes:
        """
        Read memory from the debugged process.

        Args:
            address: Memory address (hex string)
            size: Number of bytes to read

        Returns:
            Raw bytes from memory
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "size": size
        }

        result = self._request("/api/memory/read", data)
        hex_data = result.get("data", "")

        # Convert hex string to bytes
        return bytes.fromhex(hex_data)

    def write_memory(self, address: str, data: bytes) -> bool:
        """
        Write memory to the debugged process.

        Args:
            address: Memory address (hex string)
            data: Bytes to write

        Returns:
            True if write successful
        """
        if address.startswith("0x"):
            address = address[2:]

        payload = {
            "address": address,
            "data": data.hex()
        }

        self._request("/api/memory/write", payload)
        logger.info(f"Wrote {len(data)} bytes to {address}")
        return True

    def disassemble(self, address: str, count: int = 10) -> list[dict[str, str]]:
        """
        Disassemble instructions at address.

        Args:
            address: Start address
            count: Number of instructions to disassemble

        Returns:
            List of instruction dictionaries
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "count": count
        }

        result = self._request("/api/disassemble", data)
        return result.get("instructions", [])

    def get_state(self) -> DebuggerState:
        """
        Get current debugger state.

        Returns:
            Current state
        """
        result = self._request("/api/status")
        state_str = result.get("state", "not_loaded")
        return self._parse_state(state_str)

    def get_current_location(self) -> dict[str, Any]:
        """
        Get current execution location.

        Returns:
            Dictionary with address, instruction, module, etc.
        """
        result = self._request("/api/status")

        return {
            "address": result.get("current_address", "unknown"),
            "binary_path": result.get("binary_path", ""),
            "state": result.get("state", "unknown")
        }

    def _parse_state(self, state_str: str) -> DebuggerState:
        """Convert string state to DebuggerState enum."""
        state_map = {
            "not_loaded": DebuggerState.NOT_LOADED,
            "loaded": DebuggerState.LOADED,
            "running": DebuggerState.RUNNING,
            "paused": DebuggerState.PAUSED,
            "terminated": DebuggerState.TERMINATED
        }
        return state_map.get(state_str, DebuggerState.NOT_LOADED)

    def is_connected(self) -> bool:
        """Check if connected to x64dbg."""
        try:
            self._request("/api/status")
            return True
        except Exception:
            return False

    def dump_memory(self, address: str, size: int, output_file: str) -> bool:
        """
        Dump memory region to file.

        Args:
            address: Start address (hex string)
            size: Number of bytes to dump
            output_file: Path to save dumped memory

        Returns:
            True if dump successful

        Note:
            Requires C++ plugin implementation of /api/memory/dump
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "size": size
        }

        result = self._request("/api/memory/dump", data)
        hex_data = result.get("data", "")

        # Convert hex string to bytes and write to file
        memory_bytes = bytes.fromhex(hex_data)
        with open(output_file, 'wb') as f:
            f.write(memory_bytes)

        logger.info(f"Dumped {len(memory_bytes)} bytes to {output_file}")
        return True

    def search_memory(self, pattern: str, memory_region: str = "all") -> list[dict[str, str]]:
        """
        Search memory for byte pattern.

        Args:
            pattern: Hex pattern to search for (e.g., "90 90 90" or "909090")
            memory_region: Region to search ("all", "executable", "writable")

        Returns:
            List of addresses where pattern was found

        Note:
            Requires C++ plugin implementation of /api/memory/search
        """
        # Normalize pattern
        hex_pattern = pattern.replace(" ", "").replace("0x", "")

        data = {
            "pattern": hex_pattern,
            "region": memory_region
        }

        result = self._request("/api/memory/search", data)
        matches = result.get("matches", [])

        logger.debug(f"Found {len(matches)} matches for pattern {pattern}")
        return matches

    def get_memory_map(self) -> list[dict[str, Any]]:
        """
        Get memory map showing all regions.

        Returns:
            List of memory region dictionaries with base, size, permissions

        Note:
            Requires C++ plugin implementation of /api/memory/map
        """
        result = self._request("/api/memory/map")
        regions = result.get("regions", [])

        logger.debug(f"Got {len(regions)} memory regions")
        return regions

    def get_memory_info(self, address: str) -> dict[str, Any]:
        """
        Get information about memory at address.

        Args:
            address: Memory address to query

        Returns:
            Dictionary with base, size, permissions, type

        Note:
            Requires C++ plugin implementation of /api/memory/info
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        result = self._request("/api/memory/info", data)

        return {
            "base": result.get("base", "unknown"),
            "size": result.get("size", 0),
            "permissions": result.get("permissions", "unknown"),
            "type": result.get("type", "unknown"),
            "module": result.get("module", "")
        }

    def get_instruction(self, address: str | None = None) -> dict[str, Any]:
        """
        Get current or specific instruction details.

        Args:
            address: Optional address (uses current RIP if None)

        Returns:
            Dictionary with address, bytes, mnemonic, operands, etc.

        Note:
            Requires C++ plugin implementation of /api/instruction
        """
        data = {}
        if address:
            if address.startswith("0x"):
                address = address[2:]
            data["address"] = address

        result = self._request("/api/instruction", data)

        return {
            "address": result.get("address", "unknown"),
            "bytes": result.get("bytes", ""),
            "mnemonic": result.get("mnemonic", ""),
            "operands": result.get("operands", ""),
            "size": result.get("size", 0),
            "type": result.get("type", "")  # "call", "jmp", "ret", etc.
        }

    def evaluate_expression(self, expression: str) -> dict[str, Any]:
        """
        Evaluate expression (e.g., "[rsp+8]", "kernel32.CreateFileA").

        Args:
            expression: Expression to evaluate

        Returns:
            Dictionary with value and type

        Note:
            Requires C++ plugin implementation of /api/evaluate
        """
        data = {"expression": expression}
        result = self._request("/api/evaluate", data)

        return {
            "value": result.get("value", "unknown"),
            "type": result.get("type", "unknown"),
            "valid": result.get("valid", False)
        }

    def set_comment(self, address: str, comment: str) -> bool:
        """
        Set comment at address.

        Args:
            address: Address for comment
            comment: Comment text

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/comment/set
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "comment": comment
        }

        self._request("/api/comment/set", data)
        logger.debug(f"Set comment at {address}: {comment}")
        return True

    def get_comment(self, address: str) -> str:
        """
        Get comment at address.

        Args:
            address: Address to query

        Returns:
            Comment text or empty string

        Note:
            Requires C++ plugin implementation of /api/comment/get
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        result = self._request("/api/comment/get", data)

        return result.get("comment", "")

    def get_module_imports(self, module_name: str) -> list[dict[str, str]]:
        """
        Get import table for module.

        Args:
            module_name: Module name (e.g., "malware.exe", "kernel32.dll")

        Returns:
            List of import entries with module, function, address

        Note:
            Requires C++ plugin implementation of /api/module/imports
        """
        data = {"module": module_name}
        result = self._request("/api/module/imports", data)

        imports = result.get("imports", [])
        logger.debug(f"Got {len(imports)} imports for {module_name}")
        return imports

    def get_module_exports(self, module_name: str) -> list[dict[str, str]]:
        """
        Get export table for module.

        Args:
            module_name: Module name

        Returns:
            List of export entries with name, address, ordinal

        Note:
            Requires C++ plugin implementation of /api/module/exports
        """
        data = {"module": module_name}
        result = self._request("/api/module/exports", data)

        exports = result.get("exports", [])
        logger.debug(f"Got {len(exports)} exports for {module_name}")
        return exports

    def set_hardware_breakpoint(self, address: str, hw_type: str = "execute", hw_size: int = 1) -> bool:
        """
        Set hardware breakpoint using debug registers.

        Args:
            address: Address for breakpoint
            hw_type: Type ("execute", "read", "write", "access")
            hw_size: Size in bytes (1, 2, 4, 8)

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/breakpoint/hardware
            Uses DR0-DR7 registers (max 4 hardware breakpoints)
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "type": hw_type,
            "size": hw_size
        }

        self._request("/api/breakpoint/hardware", data)
        logger.info(f"Set hardware breakpoint at {address} ({hw_type}, {hw_size} bytes)")
        return True
