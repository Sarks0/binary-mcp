"""
x64dbg HTTP bridge client.

Communicates with the x64dbg native plugin via HTTP API.
"""

import logging
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

import requests

from ..base import Debugger, DebuggerState
from .error_logger import ErrorContext, X64DbgErrorLogger

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
        self._error_logger = X64DbgErrorLogger()

        logger.info(f"Initialized x64dbg bridge: {self.base_url}")
        logger.info(f"Error logging enabled: {self._error_logger.error_dir}")

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
        Make HTTP request to plugin API with comprehensive error logging.

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
        start_time = time.time()
        operation = endpoint.split("/")[-1]  # Extract operation name from endpoint

        # Read authentication token if not already cached
        if self._auth_token is None:
            try:
                self._auth_token = self._read_auth_token()
            except RuntimeError as e:
                # Log authentication error
                context = ErrorContext(
                    operation="authentication",
                    additional={"endpoint": endpoint}
                )
                self._error_logger.log_error(
                    operation="authentication",
                    error=e,
                    context=context,
                    endpoint=endpoint,
                    traceback_str=traceback.format_exc()
                )

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
            # Make request
            if data is None:
                response = requests.get(url, headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, json=data, headers=headers, timeout=self.timeout)

            duration_ms = int((time.time() - start_time) * 1000)

            response.raise_for_status()
            result = response.json()

            # Check API-level error
            if not result.get("success", False):
                error_msg = result.get("error", "Unknown error")
                error = RuntimeError(f"API error: {error_msg}")

                # Build context from request data
                context = ErrorContext(
                    operation=operation,
                    address=data.get("address") if data else None,
                    register=data.get("register") if data else None,
                    module=data.get("module") if data else None,
                    request_data=data or {},
                    additional={"url": url}
                )

                # Log API error
                self._error_logger.log_error(
                    operation=operation,
                    error=error,
                    context=context,
                    http_status=response.status_code,
                    api_response=result,
                    endpoint=endpoint,
                    duration_ms=duration_ms,
                    traceback_str=traceback.format_exc()
                )

                raise error

            return result

        except requests.RequestException as e:
            duration_ms = int((time.time() - start_time) * 1000)

            # Extract HTTP status if available
            http_status = None
            api_response = None
            if hasattr(e, 'response') and e.response is not None:
                http_status = e.response.status_code
                try:
                    api_response = e.response.json()
                except Exception:
                    api_response = {"text": e.response.text[:500]}

            # Build context
            context = ErrorContext(
                operation=operation,
                address=data.get("address") if data else None,
                register=data.get("register") if data else None,
                module=data.get("module") if data else None,
                request_data=data or {},
                additional={
                    "url": url,
                    "timeout": self.timeout,
                    "base_url": self.base_url
                }
            )

            # Log HTTP error
            self._error_logger.log_error(
                operation=operation,
                error=e,
                context=context,
                http_status=http_status,
                api_response=api_response,
                endpoint=endpoint,
                duration_ms=duration_ms,
                traceback_str=traceback.format_exc()
            )

            logger.error(f"HTTP request failed: {e}")

            # Check if it's an authentication error
            if http_status == 401:
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

    def resolve_symbol(self, expression: str) -> dict[str, Any]:
        """
        Resolve a symbol or expression to an address.

        This provides detailed feedback when symbol resolution fails,
        explaining the reason (not debugging, not paused, symbol not found).

        Args:
            expression: Symbol or expression to resolve. Can be:
                - Module!function format: "kernel32!CreateFileW"
                - Simple function name: "CreateFileW" (may need module prefix)
                - Address expression: "rax+0x10"
                - Hex address: "0x401000"

        Returns:
            Dictionary with:
                - success: True if resolved
                - address: Resolved address (hex string)
                - expression: Original expression
                - module: Module containing the address (if applicable)
                - symbol: Symbol name at address (if applicable)
                - error: Error message (if resolution failed)

        Example:
            result = bridge.resolve_symbol("kernel32!CreateFileW")
            if result["success"]:
                print(f"CreateFileW is at 0x{result['address']}")
            else:
                print(f"Failed: {result.get('error')}")

        Note:
            Symbol resolution only works when:
            - A binary is loaded (debugging active)
            - Debugger is paused (not running)
            - Module containing symbol is loaded
        """
        data = {"expression": expression}
        result = self._request("/api/resolve", data)
        return result

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

    def set_register(self, register: str, value: str) -> bool:
        """
        Set register value.

        Args:
            register: Register name (e.g., "rax", "eip", "rsp")
            value: New value (hex string)

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/register/set
        """
        if value.startswith("0x"):
            value = value[2:]

        data = {
            "register": register.lower(),
            "value": value
        }

        self._request("/api/register/set", data)
        logger.info(f"Set {register} = 0x{value}")
        return True

    def skip_instruction(self, count: int = 1) -> bool:
        """
        Skip N instructions without executing them.

        Args:
            count: Number of instructions to skip

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/skip
            Advances RIP without executing instructions
        """
        data = {"count": count}
        self._request("/api/skip", data)
        logger.info(f"Skipped {count} instruction(s)")
        return True

    def run_until_return(self) -> dict[str, Any]:
        """
        Run until current function returns.

        Returns:
            Execution state after return

        Note:
            Requires C++ plugin implementation of /api/run_until_return
        """
        result = self._request("/api/run_until_return")

        return {
            "address": result.get("address", "unknown"),
            "state": result.get("state", "paused")
        }

    def set_memory_breakpoint(self, address: str, bp_type: str = "access", size: int = 1) -> bool:
        """
        Set memory breakpoint.

        Args:
            address: Address for breakpoint
            bp_type: Type ("access", "read", "write", "execute")
            size: Size in bytes

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/breakpoint/memory
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "type": bp_type,
            "size": size
        }

        self._request("/api/breakpoint/memory", data)
        logger.info(f"Set memory breakpoint at {address} ({bp_type}, {size} bytes)")
        return True

    def delete_memory_breakpoint(self, address: str) -> bool:
        """
        Delete memory breakpoint.

        Args:
            address: Address of breakpoint to delete

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/breakpoint/memory/delete
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        self._request("/api/breakpoint/memory/delete", data)
        logger.info(f"Deleted memory breakpoint at {address}")
        return True

    def hide_debugger_peb(self) -> bool:
        """
        Hide debugger presence in Process Environment Block.

        Bypasses IsDebuggerPresent and PEB checks.

        Returns:
            True if successful

        Note:
            Requires C++ plugin implementation of /api/hide_debugger
            Essential for anti-debug malware analysis
        """
        self._request("/api/hide_debugger")
        logger.info("Debugger hidden in PEB")
        return True

    # =========================================================================
    # Wait/Synchronization Functions
    # =========================================================================

    def wait_until_paused(self, timeout: int = 30000) -> dict[str, Any]:
        """
        Wait until the debugger is paused (e.g., breakpoint hit, exception).

        This is essential for automation - blocks until the debugger stops
        instead of requiring polling loops.

        Args:
            timeout: Maximum wait time in milliseconds (default: 30 seconds)

        Returns:
            Dictionary with:
                - success: True if paused, False if timeout
                - state: Current state ("paused" or other)
                - elapsed_ms: Time waited in milliseconds
                - current_address: Address where paused (if successful)
                - error: Error message (if timeout)

        Example:
            bridge.run()
            result = bridge.wait_until_paused(timeout=60000)
            if result["success"]:
                print(f"Stopped at {result['current_address']}")
            else:
                print(f"Timeout after {result['elapsed_ms']}ms")
        """
        data = {"timeout": timeout}
        result = self._request("/api/wait/paused", data)
        return result

    def wait_until_running(self, timeout: int = 10000) -> dict[str, Any]:
        """
        Wait until the debugger is running.

        Useful after calling run() to confirm execution has started.

        Args:
            timeout: Maximum wait time in milliseconds (default: 10 seconds)

        Returns:
            Dictionary with:
                - success: True if running, False if timeout
                - state: Current state ("running" or other)
                - elapsed_ms: Time waited in milliseconds
                - error: Error message (if timeout)
        """
        data = {"timeout": timeout}
        result = self._request("/api/wait/running", data)
        return result

    def wait_until_debugging(self, timeout: int = 30000) -> dict[str, Any]:
        """
        Wait until debugging has started (binary is loaded).

        Useful after calling load_binary() to confirm the binary is ready.

        Args:
            timeout: Maximum wait time in milliseconds (default: 30 seconds)

        Returns:
            Dictionary with:
                - success: True if debugging, False if timeout
                - state: Current state
                - elapsed_ms: Time waited in milliseconds
                - is_running: Whether the debugger is running
                - error: Error message (if timeout)
        """
        data = {"timeout": timeout}
        result = self._request("/api/wait/debugging", data)
        return result

    def run_and_wait(self, timeout: int = 30000) -> dict[str, Any]:
        """
        Start execution and wait until it pauses (breakpoint, exception, etc.).

        This is a convenience method combining run() and wait_until_paused().

        Args:
            timeout: Maximum wait time in milliseconds (default: 30 seconds)

        Returns:
            Dictionary with wait result (same as wait_until_paused)

        Example:
            bridge.set_breakpoint("0x401000")
            result = bridge.run_and_wait(timeout=60000)
            if result["success"]:
                regs = bridge.get_registers()
                print(f"Hit breakpoint, RAX={regs['rax']}")
        """
        self.run()
        return self.wait_until_paused(timeout=timeout)

    # =========================================================================
    # Event System
    # =========================================================================

    def get_events(self, max_events: int = 100, peek: bool = False) -> dict[str, Any]:
        """
        Get pending debug events from the event queue.

        The event system captures debug events as they occur:
        - Breakpoint hits
        - Exceptions
        - Process/thread creation/exit
        - Module load/unload
        - Debug strings
        - Step completion

        Args:
            max_events: Maximum number of events to return (default: 100)
            peek: If True, don't remove events from queue (default: False)

        Returns:
            Dictionary with:
                - events: List of event objects
                - queue_size: Remaining events in queue
                - next_event_id: Next event ID (for filtering)

        Event object structure:
            - id: Unique event ID
            - type: Event type string (breakpoint_hit, exception, etc.)
            - timestamp: Milliseconds since plugin start
            - address: Address (hex string, if applicable)
            - thread_id: Thread ID (if applicable)
            - module: Module name (if applicable)
            - details: Additional details string

        Example:
            events = bridge.get_events()
            for event in events["events"]:
                if event["type"] == "breakpoint_hit":
                    print(f"Breakpoint at {event['address']}")
        """
        data = {"max_events": max_events, "peek": 1 if peek else 0}
        return self._request("/api/events", data)

    def clear_events(self) -> dict[str, Any]:
        """
        Clear all pending events from the event queue.

        Returns:
            Confirmation message
        """
        return self._request("/api/events/clear")

    def get_event_status(self) -> dict[str, Any]:
        """
        Get event system status.

        Returns:
            Dictionary with:
                - enabled: Whether event collection is enabled
                - queue_size: Number of events in queue
                - next_event_id: Next event ID
        """
        return self._request("/api/events/status")

    def poll_for_event(
        self,
        event_types: list[str] | None = None,
        timeout: int = 30000,
        poll_interval: int = 100
    ) -> dict[str, Any] | None:
        """
        Poll for a specific event type.

        This is a convenience method that polls the event queue until
        a matching event is found or timeout is reached.

        Args:
            event_types: List of event types to wait for (e.g., ["breakpoint_hit", "exception"])
                        If None, returns first event of any type
            timeout: Maximum wait time in milliseconds (default: 30 seconds)
            poll_interval: How often to poll in milliseconds (default: 100ms)

        Returns:
            Matching event object, or None if timeout

        Example:
            bridge.run()
            event = bridge.poll_for_event(["breakpoint_hit"], timeout=60000)
            if event:
                print(f"Hit breakpoint at {event['address']}")
        """
        import time

        start_time = time.time()
        timeout_sec = timeout / 1000

        while True:
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed >= timeout_sec:
                return None

            # Get events (don't peek - we want to consume them)
            result = self.get_events(max_events=10)
            events = result.get("events", [])

            for event in events:
                event_type = event.get("type", "")
                if event_types is None or event_type in event_types:
                    return event

            # Sleep before next poll
            time.sleep(poll_interval / 1000)

    def run_until_event(
        self,
        event_types: list[str] | None = None,
        timeout: int = 30000
    ) -> dict[str, Any]:
        """
        Run and wait for a specific event type.

        Combines run() with poll_for_event() for convenience.

        Args:
            event_types: List of event types to wait for
                        Default: ["breakpoint_hit", "exception", "paused"]
            timeout: Maximum wait time in milliseconds

        Returns:
            Dictionary with:
                - success: True if event received
                - event: The event object (if success)
                - error: Error message (if timeout)

        Example:
            bridge.set_breakpoint("kernel32.CreateFileA")
            result = bridge.run_until_event(["breakpoint_hit"], timeout=60000)
            if result["success"]:
                print(f"Breakpoint hit at {result['event']['address']}")
        """
        if event_types is None:
            event_types = ["breakpoint_hit", "exception", "paused", "system_breakpoint"]

        # Clear existing events first
        self.clear_events()

        # Start execution
        self.run()

        # Poll for event
        event = self.poll_for_event(event_types, timeout)

        if event:
            return {
                "success": True,
                "event": event
            }
        else:
            return {
                "success": False,
                "error": f"Timeout waiting for events: {event_types}"
            }

    # =========================================================================
    # Memory Allocation Functions (Phase 3)
    # =========================================================================

    def virt_alloc(self, size: int = 4096, address: str | None = None) -> dict[str, Any]:
        """
        Allocate memory in the debugee's address space.

        Uses VirtualAllocEx to allocate memory with read/write permissions.

        Args:
            size: Number of bytes to allocate (default: 4096 = one page)
            address: Optional preferred address (hex string). If None, OS chooses.

        Returns:
            Dictionary with:
                - success: True if allocation succeeded
                - address: Allocated address (hex string)
                - size: Actual size allocated

        Example:
            result = bridge.virt_alloc(4096)
            if result["success"]:
                mem_addr = result["address"]
                bridge.write_memory(mem_addr, b"Hello World")
        """
        data = {"size": size}
        if address:
            if address.startswith("0x"):
                address = address[2:]
            data["address"] = address

        result = self._request("/api/memory/alloc", data)
        logger.info(f"Allocated {size} bytes at 0x{result.get('address', 'unknown')}")
        return result

    def virt_free(self, address: str) -> dict[str, Any]:
        """
        Free memory allocated in the debugee's address space.

        Args:
            address: Address of memory to free (hex string)

        Returns:
            Dictionary with success status and message

        Example:
            bridge.virt_free("0x12340000")
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        result = self._request("/api/memory/free", data)
        logger.info(f"Freed memory at 0x{address}")
        return result

    def virt_protect(self, address: str, protection: str, size: int = 4096) -> dict[str, Any]:
        """
        Change memory protection.

        Args:
            address: Address of memory region (hex string)
            protection: New protection string:
                - "rwx" or "RWX": Read/Write/Execute
                - "rx" or "RX": Read/Execute
                - "rw" or "RW": Read/Write
                - "r" or "R": Read only
                - "x" or "X": Execute only
                - "n" or "none": No access
            size: Size of region to change (default: 4096)

        Returns:
            Dictionary with:
                - success: True if protection changed
                - address: Address that was modified
                - protection: Windows protection constant value

        Example:
            # Make code region writable for patching
            bridge.virt_protect("0x401000", "rwx", 0x1000)
            bridge.write_memory("0x401000", b"\\x90\\x90")  # Write NOPs
            bridge.virt_protect("0x401000", "rx", 0x1000)   # Restore
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "protection": protection,
            "size": size
        }

        result = self._request("/api/memory/protect", data)
        logger.info(f"Changed protection at 0x{address} to {protection}")
        return result

    def memset(self, address: str, value: int, size: int) -> dict[str, Any]:
        """
        Fill memory with a byte value.

        Args:
            address: Start address (hex string)
            value: Byte value to fill (0-255)
            size: Number of bytes to fill

        Returns:
            Dictionary with success status

        Example:
            # Zero out a buffer
            bridge.memset("0x12340000", 0, 1024)

            # Fill with NOPs (0x90)
            bridge.memset("0x401000", 0x90, 10)
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "value": value & 0xFF,
            "size": size
        }

        result = self._request("/api/memory/set", data)
        logger.info(f"Filled {size} bytes at 0x{address} with 0x{value & 0xFF:02x}")
        return result

    def check_valid_read_ptr(self, address: str) -> bool:
        """
        Check if address is a valid readable memory address.

        Args:
            address: Address to check (hex string)

        Returns:
            True if address is readable, False otherwise

        Example:
            if bridge.check_valid_read_ptr("0x401000"):
                data = bridge.read_memory("0x401000", 16)
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        result = self._request("/api/memory/check", data)
        return result.get("valid", False)

    # =========================================================================
    # Enhanced Breakpoint Functions (Phase 3)
    # =========================================================================

    def toggle_breakpoint(self, address: str, enable: bool = True) -> dict[str, Any]:
        """
        Enable or disable a software breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Dictionary with address and enabled status

        Example:
            bridge.set_breakpoint("0x401000")
            bridge.toggle_breakpoint("0x401000", enable=False)  # Temporarily disable
            bridge.run()
            bridge.toggle_breakpoint("0x401000", enable=True)   # Re-enable
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "enable": 1 if enable else 0
        }

        result = self._request("/api/breakpoint/toggle", data)
        logger.info(f"Breakpoint at 0x{address} {'enabled' if enable else 'disabled'}")
        return result

    def delete_hardware_breakpoint(self, address: str) -> dict[str, Any]:
        """
        Delete a hardware breakpoint.

        Args:
            address: Breakpoint address (hex string)

        Returns:
            Dictionary with success status

        Example:
            bridge.set_hardware_breakpoint("0x401000", "execute")
            # ... later ...
            bridge.delete_hardware_breakpoint("0x401000")
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        result = self._request("/api/breakpoint/hardware/delete", data)
        logger.info(f"Deleted hardware breakpoint at 0x{address}")
        return result

    def toggle_hardware_breakpoint(self, address: str, enable: bool = True) -> dict[str, Any]:
        """
        Enable or disable a hardware breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Dictionary with address and enabled status

        Example:
            bridge.set_hardware_breakpoint("0x401000", "write", 4)
            bridge.toggle_hardware_breakpoint("0x401000", enable=False)
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "enable": 1 if enable else 0
        }

        result = self._request("/api/breakpoint/hardware/toggle", data)
        logger.info(f"Hardware breakpoint at 0x{address} {'enabled' if enable else 'disabled'}")
        return result

    def toggle_memory_breakpoint(self, address: str, enable: bool = True) -> dict[str, Any]:
        """
        Enable or disable a memory breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Dictionary with address and enabled status
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {
            "address": address,
            "enable": 1 if enable else 0
        }

        result = self._request("/api/breakpoint/memory/toggle", data)
        logger.info(f"Memory breakpoint at 0x{address} {'enabled' if enable else 'disabled'}")
        return result

    def list_all_breakpoints(self) -> dict[str, Any]:
        """
        List all breakpoints of all types (software, hardware, memory).

        Returns:
            Dictionary with:
                - breakpoints: Dictionary containing:
                    - software: List of software breakpoints
                    - hardware: List of hardware breakpoints
                    - memory: List of memory breakpoints

        Each breakpoint entry contains:
            - address: Breakpoint address (hex string)
            - enabled: Whether breakpoint is enabled
            - type: Breakpoint type (for hw/memory)
            - singleshoot: Whether it's a single-shot BP (software only)
            - size: Access size (hardware only)

        Example:
            bps = bridge.list_all_breakpoints()
            for bp in bps["breakpoints"]["software"]:
                print(f"SW BP at {bp['address']}, enabled={bp['enabled']}")
            for bp in bps["breakpoints"]["hardware"]:
                print(f"HW BP at {bp['address']}, type={bp['type']}")
        """
        result = self._request("/api/breakpoint/list/all")
        return result
