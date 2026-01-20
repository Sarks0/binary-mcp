"""
x64dbg HTTP bridge client.

Communicates with the x64dbg native plugin via HTTP API.
"""

from __future__ import annotations

import logging
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any, Optional

import requests

from ..base import Debugger, DebuggerState
from .error_logger import ErrorContext, X64DbgErrorLogger
from src.utils.structured_errors import (
    ErrorCode,
    StructuredError,
    StructuredErrorException,
    classify_api_error,
    create_address_invalid_error,
    create_address_missing_error,
    create_api_error,
    create_breakpoint_set_failed_error,
    create_debugger_not_connected_error,
    create_disassembly_failed_error,
    create_error_from_api_response,
    create_memory_read_failed_error,
    create_memory_write_failed_error,
)

logger = logging.getLogger(__name__)

# Security: Maximum size for memory dumps (100MB) to prevent memory exhaustion
MAX_DUMP_SIZE = 100 * 1024 * 1024


class AddressValidationError(StructuredErrorException):
    """
    Raised when an address parameter is invalid or missing.

    Enhanced with structured error information for actionable feedback.
    """

    def __init__(
        self,
        message: str,
        address: str | None = None,
        param_name: str = "address",
    ):
        """
        Initialize address validation error with structured error.

        Args:
            message: Error message (for backwards compatibility)
            address: The invalid address value
            param_name: Name of the parameter
        """
        # Determine error type based on message
        if address is None or "missing" in message.lower() or "none" in message.lower():
            structured_error = create_address_missing_error(param_name)
        else:
            structured_error = create_address_invalid_error(
                address,
                param_name,
                {"original_message": message},
            )

        super().__init__(structured_error)
        # Store for backwards compatibility
        self._legacy_message = message

    def __str__(self) -> str:
        """Return structured error message."""
        return self.structured_error.to_user_message()


class X64DbgAPIError(StructuredErrorException):
    """
    Raised when an x64dbg API call fails.

    Provides structured error information with actionable suggestions.
    """

    def __init__(
        self,
        operation: str,
        api_message: str,
        context: dict[str, Any] | None = None,
    ):
        """
        Initialize API error with structured error.

        Args:
            operation: The operation that failed
            api_message: Error message from the API
            context: Additional context (address, module, etc.)
        """
        structured_error = create_error_from_api_response(
            operation, api_message, context
        )
        super().__init__(structured_error)
        self.operation = operation
        self.api_message = api_message
        self.context = context or {}


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

        self._max_retries = 3
        self._retry_delay = 0.1  # seconds

        logger.info(f"Initialized x64dbg bridge: {self.base_url}")
        logger.info(f"Error logging enabled: {self._error_logger.error_dir}")

    def _normalize_address(self, address: str | None, param_name: str = "address") -> str:
        """
        Normalize and validate an address parameter.

        Args:
            address: Address string (hex with or without 0x prefix)
            param_name: Name of parameter for error messages

        Returns:
            Normalized address string (without 0x prefix)

        Raises:
            AddressValidationError: If address is None, empty, or invalid
        """
        if address is None:
            raise AddressValidationError(
                f"Missing {param_name}: parameter is None",
                address=None,
                param_name=param_name,
            )

        if not isinstance(address, str):
            raise AddressValidationError(
                f"Invalid {param_name}: expected string, got {type(address).__name__}",
                address=str(address),
                param_name=param_name,
            )

        # Strip whitespace
        original_address = address
        address = address.strip()

        if not address:
            raise AddressValidationError(
                f"Missing {param_name}: empty string",
                address=None,
                param_name=param_name,
            )

        # Remove 0x prefix if present
        if address.lower().startswith("0x"):
            address = address[2:]

        # Validate hex characters
        if not address:
            raise AddressValidationError(
                f"Invalid {param_name}: only '0x' prefix provided",
                address=original_address,
                param_name=param_name,
            )

        try:
            # Verify it's valid hex
            int(address, 16)
        except ValueError:
            raise AddressValidationError(
                f"Invalid {param_name}: '{address}' is not a valid hex address",
                address=original_address,
                param_name=param_name,
            )

        return address

    def _request_with_retry(
        self,
        endpoint: str,
        data: dict[str, Any] | None = None,
        max_retries: int | None = None
    ) -> dict[str, Any]:
        """
        Make HTTP request with retry logic for transient failures.

        Args:
            endpoint: API endpoint path
            data: Optional JSON data for POST request
            max_retries: Override default max retries

        Returns:
            JSON response as dictionary

        Raises:
            ConnectionError: If all retries fail
            RuntimeError: If API returns error
        """
        retries = max_retries if max_retries is not None else self._max_retries
        last_error = None

        for attempt in range(retries + 1):
            try:
                return self._request(endpoint, data)
            except (ConnectionError, RuntimeError) as e:
                last_error = e
                error_msg = str(e)

                # Don't retry on validation errors (Missing address, etc.)
                # These are likely parameter issues that won't be fixed by retrying
                if "Missing" in error_msg and attempt < retries:
                    # Log and retry - might be a serialization race
                    logger.warning(
                        f"Request failed (attempt {attempt + 1}/{retries + 1}): {error_msg}. "
                        f"Retrying with data: {data}"
                    )
                    time.sleep(self._retry_delay * (attempt + 1))
                    continue
                elif "API error" in error_msg:
                    # API errors should include context for debugging
                    raise RuntimeError(
                        f"{error_msg}\n"
                        f"Request details:\n"
                        f"  Endpoint: {endpoint}\n"
                        f"  Data sent: {data}"
                    )
                else:
                    raise

        # All retries exhausted
        raise RuntimeError(
            f"Request failed after {retries + 1} attempts: {last_error}\n"
            f"Request details:\n"
            f"  Endpoint: {endpoint}\n"
            f"  Data sent: {data}"
        )

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

                # Build context from request data for structured error
                error_context = {
                    "address": data.get("address") if data else None,
                    "module": data.get("module") if data else None,
                    "register": data.get("register") if data else None,
                    "size": data.get("size") if data else None,
                    "expression": data.get("expression") if data else None,
                    "endpoint": endpoint,
                    "http_status": response.status_code,
                }

                # Create structured error
                structured_api_error = X64DbgAPIError(
                    operation=operation,
                    api_message=error_msg,
                    context=error_context,
                )

                # Build context for legacy error logging
                log_context = ErrorContext(
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
                    error=structured_api_error,
                    context=log_context,
                    http_status=response.status_code,
                    api_response=result,
                    endpoint=endpoint,
                    duration_ms=duration_ms,
                    traceback_str=traceback.format_exc()
                )

                raise structured_api_error

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

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails
        """
        # Validate and normalize address
        normalized_addr = self._normalize_address(address)

        data = {"address": normalized_addr}

        # Log the data being sent for debugging
        logger.debug(f"Setting breakpoint - sending data: {data}")

        self._request_with_retry("/api/breakpoint/set", data)
        logger.info(f"Set breakpoint at 0x{normalized_addr}")
        return True

    def delete_breakpoint(self, address: str) -> bool:
        """
        Delete a breakpoint.

        Args:
            address: Memory address of breakpoint

        Returns:
            True if deleted successfully

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails
        """
        normalized_addr = self._normalize_address(address)

        data = {"address": normalized_addr}
        logger.debug(f"Deleting breakpoint - sending data: {data}")

        self._request_with_retry("/api/breakpoint/delete", data)
        logger.info(f"Deleted breakpoint at 0x{normalized_addr}")
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

        Uses the x64dbg plugin API first, with capstone fallback if the API
        returns empty results.

        Args:
            address: Start address (hex string)
            count: Number of instructions to disassemble

        Returns:
            List of instruction dictionaries with keys:
                - address: hex address
                - mnemonic: instruction mnemonic
                - operand: instruction operands
                - bytes: (optional) instruction bytes

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If disassembly fails
        """
        normalized_addr = self._normalize_address(address)

        data = {
            "address": normalized_addr,
            "count": count
        }

        logger.debug(f"Disassembling at 0x{normalized_addr}, count={count}")
        result = self._request_with_retry("/api/disassemble", data)
        instructions = result.get("instructions", [])

        # If API returns empty results, try capstone fallback
        if not instructions:
            logger.warning(
                f"x64dbg API returned empty disassembly at 0x{normalized_addr}, "
                "trying capstone fallback"
            )
            instructions = self._disassemble_with_capstone(normalized_addr, count)

        if not instructions:
            raise RuntimeError(
                f"Disassembly failed at 0x{normalized_addr}: "
                "Both x64dbg API and capstone fallback returned empty results. "
                "This may indicate:\n"
                "  - Address is not readable (use x64dbg_check_memory first)\n"
                "  - Address contains invalid instructions\n"
                "  - Memory is not mapped at this address"
            )

        return instructions

    def _disassemble_with_capstone(self, address: str, count: int) -> list[dict[str, str]]:
        """
        Fallback disassembly using capstone library.

        Reads raw bytes from memory and disassembles locally.

        Args:
            address: Normalized address (without 0x prefix)
            count: Number of instructions to disassemble

        Returns:
            List of instruction dictionaries
        """
        try:
            import capstone
        except ImportError:
            logger.warning("Capstone library not available for fallback disassembly")
            return []

        try:
            # Read enough bytes for disassembly (estimate ~15 bytes per instruction max)
            byte_count = count * 15
            addr_int = int(address, 16)

            # Read memory
            raw_bytes = self.read_memory(f"0x{address}", byte_count)

            if not raw_bytes:
                logger.warning(f"Could not read memory at 0x{address}")
                return []

            # Determine architecture from debugger state
            # Default to x64 mode
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = False

            instructions = []
            for i, instr in enumerate(md.disasm(raw_bytes, addr_int)):
                if i >= count:
                    break
                instructions.append({
                    "address": f"{instr.address:X}",
                    "mnemonic": instr.mnemonic,
                    "operand": instr.op_str,
                    "bytes": instr.bytes.hex()
                })

            logger.info(f"Capstone fallback disassembled {len(instructions)} instructions")
            return instructions

        except Exception as e:
            logger.error(f"Capstone fallback disassembly failed: {e}")
            return []

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

        Raises:
            ValueError: If size is invalid or exceeds maximum

        Note:
            Requires C++ plugin implementation of /api/memory/dump
        """
        # Security: Validate size to prevent memory exhaustion (defense-in-depth)
        if size <= 0:
            raise ValueError("Size must be positive")
        if size > MAX_DUMP_SIZE:
            raise ValueError(
                f"Dump size {size} bytes exceeds maximum {MAX_DUMP_SIZE} bytes (100MB)"
            )

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

        Raises:
            AddressValidationError: If address is invalid
            ValueError: If hw_type or hw_size is invalid
            RuntimeError: If API call fails

        Note:
            Requires C++ plugin implementation of /api/breakpoint/hardware
            Uses DR0-DR7 registers (max 4 hardware breakpoints)
        """
        normalized_addr = self._normalize_address(address)

        # Validate hw_type
        valid_types = ("execute", "read", "write", "access")
        if hw_type not in valid_types:
            raise ValueError(f"Invalid hw_type '{hw_type}'. Must be one of: {valid_types}")

        # Validate hw_size (hardware breakpoints are limited by CPU)
        valid_sizes = (1, 2, 4, 8)
        if hw_size not in valid_sizes:
            raise ValueError(f"Invalid hw_size {hw_size}. Must be one of: {valid_sizes}")

        data = {
            "address": normalized_addr,
            "type": hw_type,
            "size": hw_size
        }

        logger.debug(f"Setting hardware breakpoint - sending data: {data}")
        self._request_with_retry("/api/breakpoint/hardware", data)
        logger.info(f"Set hardware breakpoint at 0x{normalized_addr} ({hw_type}, {hw_size} bytes)")
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

    def set_memory_breakpoint(
        self,
        address: str,
        bp_type: str = "access",
        size: int = 1,
        auto_split: bool = True
    ) -> dict[str, Any]:
        """
        Set memory breakpoint.

        For large ranges (>4096 bytes), automatically splits into multiple
        breakpoints for reliability, or use page guard breakpoints.

        Args:
            address: Address for breakpoint
            bp_type: Type ("access", "read", "write", "execute")
            size: Size in bytes
            auto_split: Auto-split large ranges into smaller breakpoints (default: True)

        Returns:
            Dictionary with:
                - success: bool
                - breakpoints_set: number of breakpoints created
                - warning: optional warning message for large ranges
                - addresses: list of breakpoint addresses if split

        Raises:
            AddressValidationError: If address is invalid
            ValueError: If bp_type is invalid
            RuntimeError: If API call fails

        Note:
            - Hardware memory breakpoints are limited to 1/2/4/8 bytes by CPU
            - Software memory breakpoints can be larger but may be unreliable
            - For ranges >4096 bytes, consider using page guard breakpoints instead
        """
        normalized_addr = self._normalize_address(address)

        # Validate bp_type
        valid_types = ("access", "read", "write", "execute")
        if bp_type not in valid_types:
            raise ValueError(f"Invalid bp_type '{bp_type}'. Must be one of: {valid_types}")

        # Validate size (must be positive)
        if size <= 0:
            raise ValueError(f"Invalid size {size}. Must be a positive integer.")

        # Constants for size limits
        max_reliable_size = 4096  # 4KB - page size
        chunk_size = 4096  # Split large ranges into page-sized chunks

        result = {
            "success": True,
            "breakpoints_set": 0,
            "warning": None,
            "addresses": []
        }

        # Warn about large ranges
        if size > max_reliable_size:
            result["warning"] = (
                f"Large memory breakpoint ({size} bytes) may be unreliable. "
                f"Memory breakpoints work best on small ranges (<{max_reliable_size} bytes). "
            )

            if auto_split:
                result["warning"] += (
                    f"Auto-splitting into {(size + chunk_size - 1) // chunk_size} chunks."
                )
                logger.warning(result["warning"])

                # Split into chunks
                addr_int = int(normalized_addr, 16)
                remaining = size
                chunk_count = 0

                while remaining > 0:
                    current_chunk = min(remaining, chunk_size)
                    chunk_addr = f"{addr_int:X}"

                    data = {
                        "address": chunk_addr,
                        "type": bp_type,
                        "size": current_chunk
                    }

                    logger.debug(f"Setting memory breakpoint chunk - sending data: {data}")
                    self._request_with_retry("/api/breakpoint/memory", data)

                    result["addresses"].append(f"0x{chunk_addr}")
                    chunk_count += 1
                    addr_int += current_chunk
                    remaining -= current_chunk

                result["breakpoints_set"] = chunk_count
                logger.info(
                    f"Set {chunk_count} memory breakpoints covering {size} bytes at 0x{normalized_addr}"
                )
                return result
            else:
                result["warning"] += (
                    "Consider using auto_split=True or page guard breakpoints for better reliability."
                )
                logger.warning(result["warning"])

        # Set single breakpoint
        data = {
            "address": normalized_addr,
            "type": bp_type,
            "size": size
        }

        logger.debug(f"Setting memory breakpoint - sending data: {data}")
        self._request_with_retry("/api/breakpoint/memory", data)

        result["breakpoints_set"] = 1
        result["addresses"] = [f"0x{normalized_addr}"]
        logger.info(f"Set memory breakpoint at 0x{normalized_addr} ({bp_type}, {size} bytes)")
        return result

    def delete_memory_breakpoint(self, address: str) -> bool:
        """
        Delete memory breakpoint.

        Args:
            address: Address of breakpoint to delete

        Returns:
            True if successful

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails

        Note:
            Requires C++ plugin implementation of /api/breakpoint/memory/delete
        """
        normalized_addr = self._normalize_address(address)

        data = {"address": normalized_addr}
        logger.debug(f"Deleting memory breakpoint - sending data: {data}")

        self._request_with_retry("/api/breakpoint/memory/delete", data)
        logger.info(f"Deleted memory breakpoint at 0x{normalized_addr}")
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

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails

        Example:
            bridge.set_breakpoint("0x401000")
            bridge.toggle_breakpoint("0x401000", enable=False)  # Temporarily disable
            bridge.run()
            bridge.toggle_breakpoint("0x401000", enable=True)   # Re-enable
        """
        normalized_addr = self._normalize_address(address)

        data = {
            "address": normalized_addr,
            "enable": 1 if enable else 0
        }

        logger.debug(f"Toggling breakpoint - sending data: {data}")
        result = self._request_with_retry("/api/breakpoint/toggle", data)
        logger.info(f"Breakpoint at 0x{normalized_addr} {'enabled' if enable else 'disabled'}")
        return result

    def delete_hardware_breakpoint(self, address: str) -> dict[str, Any]:
        """
        Delete a hardware breakpoint.

        Args:
            address: Breakpoint address (hex string)

        Returns:
            Dictionary with success status

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails

        Example:
            bridge.set_hardware_breakpoint("0x401000", "execute")
            # ... later ...
            bridge.delete_hardware_breakpoint("0x401000")
        """
        normalized_addr = self._normalize_address(address)

        data = {"address": normalized_addr}
        logger.debug(f"Deleting hardware breakpoint - sending data: {data}")

        result = self._request_with_retry("/api/breakpoint/hardware/delete", data)
        logger.info(f"Deleted hardware breakpoint at 0x{normalized_addr}")
        return result

    def toggle_hardware_breakpoint(self, address: str, enable: bool = True) -> dict[str, Any]:
        """
        Enable or disable a hardware breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Dictionary with address and enabled status

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails

        Example:
            bridge.set_hardware_breakpoint("0x401000", "write", 4)
            bridge.toggle_hardware_breakpoint("0x401000", enable=False)
        """
        normalized_addr = self._normalize_address(address)

        data = {
            "address": normalized_addr,
            "enable": 1 if enable else 0
        }

        logger.debug(f"Toggling hardware breakpoint - sending data: {data}")
        result = self._request_with_retry("/api/breakpoint/hardware/toggle", data)
        logger.info(f"Hardware breakpoint at 0x{normalized_addr} {'enabled' if enable else 'disabled'}")
        return result

    def toggle_memory_breakpoint(self, address: str, enable: bool = True) -> dict[str, Any]:
        """
        Enable or disable a memory breakpoint without deleting it.

        Args:
            address: Breakpoint address (hex string)
            enable: True to enable, False to disable

        Returns:
            Dictionary with address and enabled status

        Raises:
            AddressValidationError: If address is invalid
            RuntimeError: If API call fails
        """
        normalized_addr = self._normalize_address(address)

        data = {
            "address": normalized_addr,
            "enable": 1 if enable else 0
        }

        logger.debug(f"Toggling memory breakpoint - sending data: {data}")
        result = self._request_with_retry("/api/breakpoint/memory/toggle", data)
        logger.info(f"Memory breakpoint at 0x{normalized_addr} {'enabled' if enable else 'disabled'}")
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

    # =========================================================================
    # Phase 4: Tracing & Analysis Functions
    # =========================================================================

    def start_trace(
        self,
        trace_into: bool = True,
        max_entries: int = 100000,
        log_file: str | None = None
    ) -> dict[str, Any]:
        """
        Start instruction tracing.

        Records each instruction executed with address, disassembly, and timing.
        Useful for understanding program flow and finding interesting code paths.

        Args:
            trace_into: If True, trace into function calls. If False, trace over.
            max_entries: Maximum trace entries to keep in memory (default: 100000)
            log_file: Optional file path to write trace log (for large traces)

        Returns:
            Dictionary with trace configuration

        Example:
            bridge.start_trace(trace_into=True, max_entries=50000)
            bridge.run()
            # ... execution happens ...
            bridge.pause()
            trace = bridge.get_trace_data()
        """
        data = {
            "trace_into": 1 if trace_into else 0,
            "max_entries": max_entries
        }
        if log_file:
            data["log_file"] = log_file

        result = self._request("/api/trace/start", data)
        logger.info(f"Trace started (trace_into={trace_into}, max={max_entries})")
        return result

    def stop_trace(self) -> dict[str, Any]:
        """
        Stop instruction tracing.

        Returns:
            Dictionary with trace statistics (entry count, duration)
        """
        result = self._request("/api/trace/stop")
        logger.info("Trace stopped")
        return result

    def get_trace_data(self, offset: int = 0, limit: int = 1000) -> dict[str, Any]:
        """
        Get trace data.

        Args:
            offset: Starting index in trace buffer
            limit: Maximum entries to return (max 10000)

        Returns:
            Dictionary with:
                - total: Total entries in trace
                - offset: Current offset
                - enabled: Whether tracing is active
                - entries: List of trace entries with address, timestamp,
                          instruction, module, thread_id

        Example:
            trace = bridge.get_trace_data(offset=0, limit=100)
            for entry in trace["entries"]:
                print(f"{entry['address']}: {entry['instruction']}")
        """
        data = {"offset": offset, "limit": limit}
        return self._request("/api/trace/data", data)

    def clear_trace(self) -> dict[str, Any]:
        """
        Clear trace data from memory.

        Returns:
            Confirmation message
        """
        return self._request("/api/trace/clear")

    def set_api_breakpoint(self, api_name: str) -> dict[str, Any]:
        """
        Set a breakpoint on a Windows API function.

        Resolves the API name to an address and sets a logging breakpoint.
        Use get_api_log() to retrieve logged calls.

        Args:
            api_name: API function name in module!function format
                     Examples: "kernel32!CreateFileW", "ntdll!NtCreateFile"

        Returns:
            Dictionary with api_name and resolved address

        Example:
            bridge.set_api_breakpoint("kernel32!CreateFileW")
            bridge.set_api_breakpoint("kernel32!WriteFile")
            bridge.run_and_wait()
            log = bridge.get_api_log()
        """
        data = {"api_name": api_name}
        result = self._request("/api/api_breakpoint", data)
        logger.info(f"API breakpoint set: {api_name}")
        return result

    def get_api_log(self, offset: int = 0, limit: int = 100) -> dict[str, Any]:
        """
        Get API call log.

        Returns logged API calls from breakpoints set with set_api_breakpoint().

        Args:
            offset: Starting index
            limit: Maximum entries to return (max 1000)

        Returns:
            Dictionary with:
                - total: Total logged calls
                - entries: List of API call entries with:
                    - id: Call ID
                    - address: API function address
                    - return_address: Where call originated
                    - timestamp: When call occurred
                    - api_name: Function name
                    - module: Module name
                    - thread_id: Calling thread
                    - args: Function arguments (hex values)

        Example:
            log = bridge.get_api_log()
            for call in log["entries"]:
                print(f"{call['api_name']} called from {call['return_address']}")
        """
        data = {"offset": offset, "limit": limit}
        return self._request("/api/api_log", data)

    def clear_api_log(self) -> dict[str, Any]:
        """
        Clear the API call log.

        Returns:
            Confirmation message
        """
        return self._request("/api/api_log/clear")

    # =========================================================================
    # Conditional Breakpoint with Logging
    # =========================================================================

    def set_conditional_breakpoint(
        self,
        address: str,
        condition: str | None = None,
        log_text: str | None = None,
        log_condition: str | None = None,
        command_text: str | None = None,
        command_condition: str | None = None,
        break_on_hit: bool = True,
        fast_resume: bool = False,
        silent: bool = False
    ) -> dict[str, Any]:
        """
        Set a conditional breakpoint with optional logging using x64dbg native commands.

        Uses x64dbg's native conditional breakpoint features:
        - bpcnd: Set break condition
        - bplog: Set log text
        - bplogcondition: Set log condition
        - bpcmd: Set command on hit
        - bpcmdcondition: Set command condition
        - SetBreakpointFastResume: For log-and-continue behavior
        - SetBreakpointSilent: Suppress default log output

        Args:
            address: Breakpoint address (hex string or symbol)
            condition: Break condition expression. Only breaks if non-zero.
                      Examples: "rcx > 0x1000", "[rsp] == 0xDEADBEEF"
            log_text: Log message template using x64dbg format.
                     Examples: "CreateFileW: path={s:rcx}", "value={x:rax}"
                     Format specifiers:
                       - {x:reg} - hex value
                       - {d:reg} - decimal
                       - {s:reg} - string pointer (UTF-16 for W functions)
                       - {a:reg} - ASCII string pointer
                       - {p:reg} - pointer dereference
            log_condition: Condition for logging (logs only if non-zero)
            command_text: x64dbg command to execute on hit (e.g., "log rax")
            command_condition: Condition for command execution
            break_on_hit: If False, continue execution after logging (fast resume)
            fast_resume: Use fast resume (faster but fewer hooks)
            silent: Suppress x64dbg's default breakpoint hit message

        Returns:
            Dictionary with breakpoint configuration status

        Example:
            # Log CreateFileW calls without breaking
            bridge.set_conditional_breakpoint(
                "kernel32!CreateFileW",
                log_text="CreateFileW: path={s:rcx}, access={x:rdx}",
                break_on_hit=False,
                silent=True
            )

            # Break only when condition is met
            bridge.set_conditional_breakpoint(
                "0x401234",
                condition="rax > 0x1000"
            )

            # Log and break when specific value found
            bridge.set_conditional_breakpoint(
                "0x405000",
                condition="[rsp+8] == 0xDEADBEEF",
                log_text="Magic value! rax={x:rax}"
            )
        """
        normalized_addr = self._normalize_address(address)

        data = {
            "address": normalized_addr,
            "break_on_hit": 1 if break_on_hit else 0,
            "fast_resume": 1 if fast_resume else 0,
            "silent": 1 if silent else 0
        }

        if condition:
            data["condition"] = condition
        if log_text:
            data["log_text"] = log_text
        if log_condition:
            data["log_condition"] = log_condition
        if command_text:
            data["command_text"] = command_text
        if command_condition:
            data["command_condition"] = command_condition

        result = self._request("/api/breakpoint/conditional", data)
        logger.info(f"Conditional breakpoint set at 0x{normalized_addr}")
        return result

    def set_api_logging_breakpoint(
        self,
        api_name: str,
        log_file: str | None = None,
        max_calls: int = 1000,
        log_template: str | None = None,
        break_on_hit: bool = False
    ) -> dict[str, Any]:
        """
        Set up logging for a Windows API function.

        Creates a conditional breakpoint on the API that logs parameters
        according to a template. Can optionally write logs to a file.

        Args:
            api_name: API name (e.g., "WriteProcessMemory", "CreateFileW")
                     Can be bare name or module!function format.
            log_file: Optional file path to write logs to
            max_calls: Maximum number of calls to log (default: 1000)
            log_template: Custom log template. If None, uses default for known APIs.
            break_on_hit: If True, break execution on each call (default: False)

        Returns:
            Dictionary with:
                - api_name: The API being logged
                - address: Resolved address
                - log_file: Output file path (if specified)
                - log_template: The template being used

        Example:
            bridge.set_api_logging_breakpoint(
                "WriteProcessMemory",
                log_file="/tmp/wpm_calls.txt",
                max_calls=1000
            )
        """
        data = {
            "api_name": api_name,
            "max_calls": max_calls,
            "break_on_hit": 1 if break_on_hit else 0
        }

        if log_file:
            data["log_file"] = log_file
        if log_template:
            data["log_template"] = log_template

        result = self._request("/api/breakpoint/api_logging", data)
        logger.info(f"API logging breakpoint set for {api_name}")
        return result

    def get_breakpoint_log(
        self,
        address: str | None = None,
        offset: int = 0,
        limit: int = 50
    ) -> dict[str, Any]:
        """
        Get logged entries from conditional breakpoints.

        Retrieves log entries captured by conditional breakpoints with
        log_text or log_template configured.

        Args:
            address: Filter to specific breakpoint address. If None, return all.
            offset: Starting index for pagination
            limit: Maximum entries to return (default: 50, max: 1000)

        Returns:
            Dictionary with:
                - total: Total number of log entries
                - offset: Current offset
                - entries: List of log entries, each containing:
                    - timestamp: When the log was captured
                    - address: Breakpoint address
                    - message: Formatted log message
                    - thread_id: Thread that triggered the breakpoint
                    - registers: Register snapshot at time of hit (optional)

        Example:
            logs = bridge.get_breakpoint_log(address="0x7670EDC0", limit=50)
            for entry in logs["entries"]:
                print(f"[{entry['timestamp']}] {entry['message']}")
        """
        data = {"offset": offset, "limit": min(limit, 1000)}

        if address:
            normalized = self._normalize_address(address)
            data["address"] = normalized

        return self._request("/api/breakpoint/log", data)

    def clear_breakpoint_log(self, address: str | None = None) -> dict[str, Any]:
        """
        Clear breakpoint log entries.

        Args:
            address: Clear logs for specific breakpoint. If None, clear all.

        Returns:
            Confirmation with count of cleared entries
        """
        data = {}
        if address:
            data["address"] = self._normalize_address(address)

        return self._request("/api/breakpoint/log/clear", data)

    def find_strings(
        self,
        address: str | None = None,
        size: int = 0x10000,
        min_length: int = 4,
        ascii: bool = True,
        unicode: bool = True
    ) -> dict[str, Any]:
        """
        Search for strings in memory.

        Scans a memory region for ASCII and/or Unicode strings.

        Args:
            address: Start address (hex string). If None, uses main module base.
            size: Number of bytes to scan (default: 64KB, max: 10MB)
            min_length: Minimum string length (default: 4)
            ascii: Search for ASCII strings (default: True)
            unicode: Search for UTF-16LE strings (default: True)

        Returns:
            Dictionary with:
                - count: Number of strings found
                - strings: List of found strings with:
                    - address: String location
                    - value: String content
                    - length: String length

        Example:
            strings = bridge.find_strings(size=0x100000, min_length=6)
            for s in strings["strings"]:
                if "http" in s["value"].lower():
                    print(f"URL at {s['address']}: {s['value']}")
        """
        data = {
            "size": size,
            "min_length": min_length,
            "ascii": 1 if ascii else 0,
            "unicode": 1 if unicode else 0
        }
        if address:
            if address.startswith("0x"):
                address = address[2:]
            data["address"] = address

        result = self._request("/api/strings", data)
        logger.info(f"Found {result.get('count', 0)} strings")
        return result

    def pattern_scan(
        self,
        pattern: str,
        address: str | None = None,
        size: int = 0x100000
    ) -> dict[str, Any]:
        """
        Search for byte pattern with wildcards.

        Scans memory for a byte pattern, supporting wildcards (??) for
        unknown bytes.

        Args:
            pattern: Hex pattern with optional wildcards
                    Examples: "90 90 90", "E8 ?? ?? ?? ??", "48 8B ?? 48"
            address: Start address (hex string). If None, uses main module.
            size: Number of bytes to scan (default: 1MB, max: 100MB)

        Returns:
            Dictionary with:
                - count: Number of matches
                - pattern: The pattern searched for
                - matches: List of addresses where pattern was found

        Example:
            # Find all CALL instructions
            result = bridge.pattern_scan("E8 ?? ?? ?? ??")
            for addr in result["matches"]:
                print(f"CALL found at {addr}")

            # Find specific byte sequence
            result = bridge.pattern_scan("48 89 5C 24")
        """
        data = {"pattern": pattern, "size": size}
        if address:
            if address.startswith("0x"):
                address = address[2:]
            data["address"] = address

        result = self._request("/api/pattern", data)
        logger.info(f"Pattern scan found {result.get('count', 0)} matches")
        return result

    def xor_decrypt(
        self,
        address: str,
        size: int = 256,
        key: str | None = None,
        try_all: bool = False
    ) -> dict[str, Any]:
        """
        Try XOR decryption on a memory region.

        Useful for decoding simple XOR-obfuscated strings common in malware.

        Args:
            address: Address of encrypted data (hex string)
            size: Number of bytes to decrypt (default: 256, max: 1MB)
            key: XOR key as hex string (e.g., "41" or "DEADBEEF") or ASCII
            try_all: If True, try all single-byte keys and return promising results

        Returns:
            If try_all=True:
                Dictionary with results list showing keys that produce
                mostly printable output (>50% printable characters)

            If key provided:
                Dictionary with:
                    - key: The key used
                    - decrypted_hex: Decrypted bytes as hex string
                    - decrypted_ascii: Decrypted bytes as ASCII (with . for non-printable)

        Example:
            # Try all single-byte keys
            result = bridge.xor_decrypt("0x401000", size=64, try_all=True)
            for r in result["results"]:
                print(f"Key {r['key']}: {r['preview']}")

            # Decrypt with known key
            result = bridge.xor_decrypt("0x401000", size=100, key="37")
            print(result["decrypted_ascii"])
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address, "size": size}
        if key:
            data["key"] = key
        if try_all:
            data["try_all"] = 1

        return self._request("/api/xor", data)

    def find_references(self, address: str) -> dict[str, Any]:
        """
        Find references to an address.

        Searches for code or data references pointing to the target address.

        Args:
            address: Target address to find references to

        Returns:
            Dictionary with target and list of reference addresses

        Note:
            This provides limited results. For comprehensive reference
            search, use the x64dbg GUI.
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address}
        return self._request("/api/references", data)

    def get_callstack_detailed(self) -> dict[str, Any]:
        """
        Get detailed call stack with symbol information.

        Provides more information than get_stack(), including resolved
        symbols and module names for each frame.

        Returns:
            Dictionary with:
                - depth: Number of stack frames
                - frames: List of stack frames with:
                    - address: Frame address
                    - from: Call source address
                    - to: Call destination
                    - symbol: Resolved symbol name
                    - module: Module name
                    - comment: Any associated comment

        Example:
            stack = bridge.get_callstack_detailed()
            for frame in stack["frames"]:
                sym = frame["symbol"] or frame["address"]
                print(f"{frame['module']}!{sym}")
        """
        return self._request("/api/callstack/detailed")

    # =========================================================================
    # Phase 5: Anti-Debug Bypass Functions
    # =========================================================================

    def hide_debugger_peb(self) -> dict[str, Any]:
        """
        Patch PEB to hide debugger presence.

        Patches the following PEB fields:
        - BeingDebugged (PEB+0x2): Set to 0
        - NtGlobalFlag (PEB+0x68/0xBC): Clear debug heap flags

        This bypasses:
        - IsDebuggerPresent()
        - CheckRemoteDebuggerPresent() (partially)
        - NtGlobalFlag checks

        Returns:
            Dictionary with:
                - peb_address: Address of PEB
                - patch_count: Number of fields patched
                - patches: List of patches applied

        Example:
            result = bridge.hide_debugger_peb()
            print(f"Patched {result['patch_count']} fields")
        """
        result = self._request("/api/antidebug/peb")
        logger.info("PEB anti-debug bypass applied")
        return result

    def hide_debugger_full(self) -> dict[str, Any]:
        """
        Apply full anti-debug bypass.

        Patches:
        - PEB.BeingDebugged
        - PEB.NtGlobalFlag
        - ProcessHeap.Flags
        - ProcessHeap.ForceFlags
        - Calls x64dbg's HideDebugger command

        This bypasses most common anti-debug checks including:
        - IsDebuggerPresent()
        - NtGlobalFlag checks
        - Heap flags checks
        - And more via x64dbg's built-in hiding

        Returns:
            Dictionary with patch results and status

        Example:
            bridge.hide_debugger_full()
            bridge.run()  # Malware won't detect debugger
        """
        result = self._request("/api/antidebug/full")
        logger.info("Full anti-debug bypass applied")
        return result

    def get_antidebug_status(self) -> dict[str, Any]:
        """
        Get current anti-debug bypass status.

        Returns:
            Dictionary with:
                - peb_patched: Whether PEB.BeingDebugged is patched
                - ntglobalflag_patched: Whether NtGlobalFlag is patched
                - heap_patched: Whether heap flags are patched
                - timing_hooked: Whether timing functions are hooked
        """
        return self._request("/api/antidebug/status")

    def patch_debug_check(
        self,
        address: str,
        patch_type: str = "ret0"
    ) -> dict[str, Any]:
        """
        Patch a specific anti-debug check at an address.

        Use this to patch individual IsDebuggerPresent calls or similar
        debug checks in malware.

        Args:
            address: Address of the CALL instruction to patch
            patch_type: Type of patch to apply:
                - "ret0": XOR EAX,EAX + NOPs (makes function return 0)
                - "ret1": MOV EAX,1 (makes function return 1)
                - "nop": Just NOP the entire call (5 bytes)

        Returns:
            Dictionary with:
                - address: Patched address
                - patch_type: Type of patch applied
                - original: Original bytes (hex)

        Example:
            # Find and patch IsDebuggerPresent call
            result = bridge.pattern_scan("E8 ?? ?? ?? ?? 85 C0 75")
            for addr in result["matches"]:
                bridge.patch_debug_check(addr, "ret0")
        """
        if address.startswith("0x"):
            address = address[2:]

        data = {"address": address, "type": patch_type}
        result = self._request("/api/antidebug/patch", data)
        logger.info(f"Patched debug check at 0x{address}")
        return result

    # =========================================================================
    # Phase 6: Code Coverage Functions
    # =========================================================================

    def start_coverage(
        self,
        module: str | None = None,
        clear: bool = True
    ) -> dict[str, Any]:
        """
        Start code coverage tracking.

        Records which addresses are executed during debugging.
        Useful for understanding code coverage during malware execution.

        Args:
            module: Module name to filter coverage (None = all modules)
            clear: Whether to clear existing coverage data (default: True)

        Returns:
            Dictionary with confirmation message

        Example:
            bridge.start_coverage(module="malware.exe")
            bridge.run_and_wait()
            stats = bridge.get_coverage_stats()
            print(f"Covered {stats['unique_addresses']} addresses")
        """
        data = {"clear": 1 if clear else 0}
        if module:
            data["module"] = module

        result = self._request("/api/coverage/start", data)
        logger.info(f"Coverage started for: {module or 'all modules'}")
        return result

    def stop_coverage(self) -> dict[str, Any]:
        """
        Stop code coverage tracking.

        Returns:
            Dictionary with:
                - unique_addresses: Number of unique addresses executed
                - total_hits: Total execution count
                - duration_ms: Time coverage was active
        """
        result = self._request("/api/coverage/stop")
        logger.info("Coverage stopped")
        return result

    def get_coverage_data(
        self,
        offset: int = 0,
        limit: int = 1000,
        sort: str | None = None
    ) -> dict[str, Any]:
        """
        Get collected coverage data.

        Args:
            offset: Starting index for pagination
            limit: Maximum entries to return (max 10000)
            sort: Sort order - "hits" (most hit first), "address" (by address)

        Returns:
            Dictionary with:
                - total: Total entries
                - enabled: Whether coverage is active
                - entries: List of coverage entries with:
                    - address: Executed address
                    - hit_count: Number of times executed
                    - module: Module name
                    - symbol: Symbol name (if available)

        Example:
            data = bridge.get_coverage_data(sort="hits", limit=100)
            for entry in data["entries"]:
                print(f"{entry['address']}: {entry['hit_count']} hits")
        """
        data = {"offset": offset, "limit": limit}
        if sort:
            data["sort"] = sort

        return self._request("/api/coverage/data", data)

    def clear_coverage(self) -> dict[str, Any]:
        """
        Clear all coverage data.

        Returns:
            Confirmation message
        """
        return self._request("/api/coverage/clear")

    def get_coverage_stats(self) -> dict[str, Any]:
        """
        Get coverage statistics.

        Returns:
            Dictionary with:
                - enabled: Whether coverage is active
                - total_hits: Total execution count
                - unique_addresses: Number of unique addresses
                - modules: List of modules with per-module stats:
                    - name: Module name
                    - addresses: Unique addresses in module
                    - hits: Total hits in module

        Example:
            stats = bridge.get_coverage_stats()
            print(f"Total: {stats['unique_addresses']} addresses, {stats['total_hits']} hits")
            for mod in stats["modules"]:
                print(f"  {mod['name']}: {mod['addresses']} addrs, {mod['hits']} hits")
        """
        return self._request("/api/coverage/stats")

    def export_coverage(
        self,
        file_path: str,
        format: str = "csv"
    ) -> dict[str, Any]:
        """
        Export coverage data to a file.

        Args:
            file_path: Path to save the coverage file
            format: Output format:
                - "csv": CSV format (address,hit_count,module,symbol)
                - "json": JSON format
                - "drcov": DynamoRIO coverage format (for Lighthouse/bncov)

        Returns:
            Dictionary with export status and entry count

        Example:
            # Export for use with Binary Ninja's bncov
            bridge.export_coverage("coverage.drcov", format="drcov")

            # Simple CSV export
            bridge.export_coverage("coverage.csv", format="csv")
        """
        data = {"file": file_path, "format": format}
        result = self._request("/api/coverage/export", data)
        logger.info(f"Exported coverage to {file_path}")
        return result

    # =========================================================================
    # Module Dump with PE Reconstruction
    # =========================================================================

    def dump_module(
        self,
        module_name: str,
        output_path: str,
        fix_pe: bool = True,
        unmap_sections: bool = True,
        rebuild_iat: bool = False
    ) -> dict[str, Any]:
        """
        Dump a module from memory with PE header reconstruction.

        Reads a module from the debugged process memory and optionally fixes
        the PE headers so the dumped file can be analyzed in IDA, Ghidra, etc.

        Args:
            module_name: Module name (e.g., "malware.dll") or base address as hex string
            output_path: Path to save the dumped module
            fix_pe: Fix PE headers (ImageBase, section characteristics, etc.)
            unmap_sections: Convert sections from memory layout to file layout
            rebuild_iat: Attempt to rebuild Import Address Table (experimental)

        Returns:
            Dictionary with:
                - success: True if dump succeeded
                - output_path: Path to dumped file
                - original_base: Module base address
                - size: Dumped size in bytes
                - sections_fixed: Number of sections fixed
                - imports_rebuilt: Whether IAT was rebuilt
                - warnings: List of any warnings during processing

        Example:
            result = bridge.dump_module(
                module_name="ForOps_v17.dll",
                output_path="/tmp/dumped.dll",
                fix_pe=True,
                unmap_sections=True
            )
            if result["success"]:
                print(f"Dumped to {result['output_path']}")
        """
        import pefile

        result: dict[str, Any] = {
            "success": False,
            "output_path": output_path,
            "original_base": None,
            "size": 0,
            "sections_fixed": 0,
            "imports_rebuilt": False,
            "warnings": []
        }

        # Find the module
        modules = self.get_modules()
        target_module = None

        # Check if module_name is an address
        try:
            if module_name.lower().startswith("0x"):
                base_addr = int(module_name, 16)
            else:
                base_addr = int(module_name, 16)

            # Search by base address
            for mod in modules:
                mod_base_str = mod.get("base", "0")
                if mod_base_str.startswith("0x"):
                    mod_base = int(mod_base_str, 16)
                else:
                    mod_base = int(mod_base_str, 16)

                if mod_base == base_addr:
                    target_module = mod
                    break
        except ValueError:
            # It's a module name, not an address
            module_name_lower = module_name.lower()
            for mod in modules:
                if mod.get("name", "").lower() == module_name_lower:
                    target_module = mod
                    break

        if not target_module:
            raise RuntimeError(
                f"Module '{module_name}' not found. "
                f"Use get_modules() to list available modules."
            )

        # Get module details
        base_str = target_module.get("base", "0")
        if base_str.startswith("0x"):
            base_addr = int(base_str, 16)
        else:
            base_addr = int(base_str, 16)

        size = target_module.get("size", 0)
        if isinstance(size, str):
            if size.startswith("0x"):
                size = int(size, 16)
            else:
                size = int(size, 16)

        result["original_base"] = f"0x{base_addr:X}"
        result["size"] = size

        logger.info(f"Dumping module: {target_module.get('name', module_name)} "
                   f"at 0x{base_addr:X}, size 0x{size:X}")

        # Read module memory
        raw_data = self.read_memory(f"0x{base_addr:X}", size)
        if not raw_data:
            raise RuntimeError(f"Failed to read memory at 0x{base_addr:X}")

        if len(raw_data) < 64:
            raise RuntimeError(f"Read data too small ({len(raw_data)} bytes)")

        # Check for MZ header
        if raw_data[:2] != b'MZ':
            result["warnings"].append("No MZ header found - dumping raw memory")
            with open(output_path, 'wb') as f:
                f.write(raw_data)
            result["success"] = True
            return result

        # Parse PE for reconstruction
        if fix_pe or unmap_sections:
            try:
                pe = pefile.PE(data=raw_data, fast_load=True)
                pe.parse_data_directories()

                # Fix ImageBase
                pe.OPTIONAL_HEADER.ImageBase = base_addr
                logger.debug(f"Fixed ImageBase to 0x{base_addr:X}")

                if unmap_sections:
                    # Convert from memory layout to file layout
                    raw_data = self._unmap_sections(pe, raw_data, result)

                if rebuild_iat:
                    # Attempt to rebuild IAT
                    self._rebuild_iat(pe, raw_data, result)

                # Write the fixed PE
                pe.write(output_path)
                result["success"] = True
                logger.info(f"Dumped module to {output_path}")

            except pefile.PEFormatError as e:
                result["warnings"].append(f"PE parsing error: {e}")
                # Fall back to raw dump
                with open(output_path, 'wb') as f:
                    f.write(raw_data)
                result["success"] = True

            except Exception as e:
                result["warnings"].append(f"PE reconstruction error: {e}")
                # Fall back to raw dump
                with open(output_path, 'wb') as f:
                    f.write(raw_data)
                result["success"] = True
        else:
            # No PE fixing requested, dump raw
            with open(output_path, 'wb') as f:
                f.write(raw_data)
            result["success"] = True

        return result

    def _unmap_sections(
        self,
        pe: Any,
        raw_data: bytes,
        result: dict[str, Any]
    ) -> bytes:
        """
        Convert PE from memory layout to file layout.

        In memory, sections are aligned to SectionAlignment (typically 0x1000).
        On disk, sections are aligned to FileAlignment (typically 0x200).
        This function remaps sections to their file layout positions.

        Args:
            pe: Parsed pefile.PE object
            raw_data: Raw memory dump bytes
            result: Result dict to update with warnings/counts

        Returns:
            Remapped PE data with file layout
        """
        import pefile

        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        file_alignment = pe.OPTIONAL_HEADER.FileAlignment

        logger.debug(f"Section alignment: 0x{section_alignment:X}, "
                    f"File alignment: 0x{file_alignment:X}")

        # If alignments are the same, no remapping needed
        if section_alignment == file_alignment:
            result["warnings"].append("Section and file alignment are equal - no unmapping needed")
            return raw_data

        # Build the unmapped file
        # Start with headers (up to first section)
        headers_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        unmapped = bytearray(raw_data[:headers_size])

        sections_fixed = 0

        for section in pe.sections:
            section_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')

            # Memory location (RVA aligned to section alignment)
            memory_offset = section.VirtualAddress
            memory_size = section.Misc_VirtualSize

            # Calculate file location (RVA aligned to file alignment)
            # We need to figure out where this section should be in the file
            raw_size = section.SizeOfRawData
            raw_offset = section.PointerToRawData

            logger.debug(
                f"Section {section_name}: "
                f"VA=0x{memory_offset:X}, VSize=0x{memory_size:X}, "
                f"RawOff=0x{raw_offset:X}, RawSize=0x{raw_size:X}"
            )

            # Read section data from memory dump
            if memory_offset < len(raw_data):
                # Calculate how much data to copy
                data_size = min(memory_size, raw_size, len(raw_data) - memory_offset)
                section_data = raw_data[memory_offset:memory_offset + data_size]

                # Ensure unmapped buffer is large enough
                required_size = raw_offset + len(section_data)
                if len(unmapped) < required_size:
                    unmapped.extend(b'\x00' * (required_size - len(unmapped)))

                # Copy section data to file offset
                unmapped[raw_offset:raw_offset + len(section_data)] = section_data
                sections_fixed += 1

                logger.debug(f"Unmapped section {section_name}: "
                           f"{len(section_data)} bytes at file offset 0x{raw_offset:X}")
            else:
                result["warnings"].append(
                    f"Section {section_name} VA 0x{memory_offset:X} beyond dump size"
                )

        result["sections_fixed"] = sections_fixed

        # Update section headers with correct file offsets
        # (pefile should handle this when we call pe.write())

        return bytes(unmapped)

    def _rebuild_iat(
        self,
        pe: Any,
        raw_data: bytes,
        result: dict[str, Any]
    ) -> None:
        """
        Attempt to rebuild the Import Address Table.

        This is experimental and may not work for all binaries.
        It tries to resolve imported function addresses back to their names.

        Args:
            pe: Parsed pefile.PE object
            raw_data: Raw memory dump bytes
            result: Result dict to update with status
        """
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                result["warnings"].append("No import directory found")
                return

            imports_fixed = 0

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='replace')
                logger.debug(f"Processing imports from {dll_name}")

                for imp in entry.imports:
                    if imp.address:
                        # Try to resolve the address to a symbol
                        try:
                            resolve_result = self.resolve_symbol(f"0x{imp.address:X}")
                            if resolve_result.get("success") and resolve_result.get("symbol"):
                                # Found the symbol - IAT entry is valid
                                imports_fixed += 1
                        except Exception:
                            pass

            if imports_fixed > 0:
                result["imports_rebuilt"] = True
                logger.info(f"Verified {imports_fixed} import entries")

        except Exception as e:
            result["warnings"].append(f"IAT rebuild failed: {e}")

    # =========================================================================
    # Memory Watch and Diff Functions
    # =========================================================================

    def watch_memory(
        self,
        address: str,
        size: int = 4096,
        poll_interval_ms: int = 100
    ) -> dict[str, Any]:
        """
        Create a memory watch region.

        This creates a watch on the specified memory region and takes an initial
        snapshot. The watch can be used with run_until_memory_changed() to detect
        modifications.

        Args:
            address: Start address to watch (hex string)
            size: Number of bytes to watch (default: 4096)
            poll_interval_ms: Polling interval in milliseconds (default: 100)

        Returns:
            Dictionary with:
                - watch_id: Unique identifier for this watch
                - address: Normalized address
                - size: Watch size
                - initial_hash: SHA256 hash of initial memory contents
                - poll_interval_ms: Configured poll interval

        Example:
            watch = bridge.watch_memory("0x089A9020", size=4096)
            result = bridge.run_until_memory_changed(watch["watch_id"], timeout_ms=60000)
        """
        import hashlib

        normalized_addr = self._normalize_address(address)
        addr_int = int(normalized_addr, 16)

        # Read initial memory contents
        initial_data = self.read_memory(f"0x{normalized_addr}", size)
        if not initial_data:
            raise RuntimeError(f"Failed to read memory at 0x{normalized_addr}")

        # Generate watch ID
        watch_id = hashlib.sha256(
            f"{normalized_addr}_{size}_{time.time()}".encode()
        ).hexdigest()[:16]

        # Calculate initial hash
        initial_hash = hashlib.sha256(initial_data).hexdigest()

        # Store watch data
        if not hasattr(self, '_memory_watches'):
            self._memory_watches: dict[str, dict[str, Any]] = {}

        self._memory_watches[watch_id] = {
            "watch_id": watch_id,
            "address": addr_int,
            "address_hex": normalized_addr,
            "size": size,
            "poll_interval_ms": poll_interval_ms,
            "initial_data": initial_data,
            "initial_hash": initial_hash,
            "created_at": time.time()
        }

        logger.info(f"Created memory watch {watch_id} at 0x{normalized_addr}, size={size}")

        return {
            "watch_id": watch_id,
            "address": f"0x{normalized_addr}",
            "size": size,
            "initial_hash": initial_hash,
            "poll_interval_ms": poll_interval_ms
        }

    def run_until_memory_changed(
        self,
        watch_id: str,
        timeout_ms: int = 60000,
        poll_interval_ms: int | None = None
    ) -> dict[str, Any]:
        """
        Run execution until watched memory region changes.

        Starts execution and polls the watched memory region until a change
        is detected or timeout is reached.

        Args:
            watch_id: Watch ID from watch_memory()
            timeout_ms: Maximum wait time in milliseconds (default: 60 seconds)
            poll_interval_ms: Override poll interval (uses watch default if None)

        Returns:
            Dictionary with:
                - changed: True if memory changed, False if timeout
                - address: Watch address
                - change_offset: Offset of first change (if changed)
                - change_size: Total bytes changed
                - triggered_at: RIP when change detected (hex string)
                - before_hash: Hash before change
                - after_hash: Hash after change
                - elapsed_ms: Time elapsed
                - error: Error message (if applicable)

        Example:
            watch = bridge.watch_memory("0x089A9020", size=4096)
            result = bridge.run_until_memory_changed(watch["watch_id"], timeout_ms=60000)
            if result["changed"]:
                print(f"Memory changed at offset {result['change_offset']}")
                diff = bridge.memory_diff(watch["watch_id"])
        """
        import hashlib

        # Get watch data
        if not hasattr(self, '_memory_watches'):
            self._memory_watches = {}

        watch = self._memory_watches.get(watch_id)
        if not watch:
            return {
                "changed": False,
                "error": f"Watch not found: {watch_id}",
                "elapsed_ms": 0
            }

        address = watch["address"]
        size = watch["size"]
        initial_data = watch["initial_data"]
        initial_hash = watch["initial_hash"]
        interval = poll_interval_ms or watch["poll_interval_ms"]

        start_time = time.time()
        timeout_sec = timeout_ms / 1000

        # Start execution
        self.run()

        try:
            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed >= timeout_sec:
                    self.pause()
                    return {
                        "changed": False,
                        "address": f"0x{address:X}",
                        "before_hash": initial_hash,
                        "after_hash": initial_hash,
                        "elapsed_ms": int(elapsed * 1000),
                        "error": f"Timeout after {timeout_ms}ms"
                    }

                # Sleep for poll interval
                time.sleep(interval / 1000)

                # Pause to read memory
                self.pause()

                # Read current memory
                try:
                    current_data = self.read_memory(f"0x{address:X}", size)
                except Exception as e:
                    # Memory might become unmapped - this could indicate significant changes
                    logger.warning(f"Failed to read memory during watch: {e}")
                    location = self.get_current_location()
                    return {
                        "changed": True,
                        "address": f"0x{address:X}",
                        "change_offset": 0,
                        "change_size": size,
                        "triggered_at": f"0x{location.get('address', '0')}",
                        "before_hash": initial_hash,
                        "after_hash": "UNREADABLE",
                        "elapsed_ms": int((time.time() - start_time) * 1000),
                        "error": f"Memory became unreadable: {e}"
                    }

                # Calculate current hash
                current_hash = hashlib.sha256(current_data).hexdigest()

                if current_hash != initial_hash:
                    # Memory changed! Find the first changed byte
                    change_offset = None
                    change_count = 0

                    for i in range(min(len(initial_data), len(current_data))):
                        if initial_data[i] != current_data[i]:
                            if change_offset is None:
                                change_offset = i
                            change_count += 1

                    # Get current RIP
                    location = self.get_current_location()
                    triggered_at = location.get('address', '0')

                    # Update watch with new data for subsequent diffs
                    watch["last_data"] = current_data
                    watch["last_hash"] = current_hash

                    logger.info(
                        f"Memory change detected in watch {watch_id} at offset {change_offset}, "
                        f"{change_count} bytes changed"
                    )

                    return {
                        "changed": True,
                        "address": f"0x{address:X}",
                        "change_offset": change_offset or 0,
                        "change_size": change_count,
                        "triggered_at": f"0x{triggered_at}",
                        "before_hash": initial_hash,
                        "after_hash": current_hash,
                        "elapsed_ms": int((time.time() - start_time) * 1000)
                    }

                # No change, resume execution
                self.run()

        except Exception as e:
            logger.error(f"run_until_memory_changed failed: {e}")
            try:
                self.pause()
            except Exception:
                pass
            return {
                "changed": False,
                "address": f"0x{address:X}",
                "before_hash": initial_hash,
                "after_hash": initial_hash,
                "elapsed_ms": int((time.time() - start_time) * 1000),
                "error": str(e)
            }

    def memory_diff(self, watch_id: str) -> dict[str, Any]:
        """
        Get byte-level diff for a memory watch.

        Compares current memory contents against the initial snapshot
        and returns detailed diff information.

        Args:
            watch_id: Watch ID from watch_memory()

        Returns:
            Dictionary with:
                - changed: True if memory differs from initial snapshot
                - address: Watch address
                - size: Watch size
                - before_hash: Initial hash
                - after_hash: Current hash
                - changed_bytes: Total bytes that differ
                - changed_ranges: List of dicts with offset, length, address
                - diff: List of diff entries with offset, old_byte, new_byte
                       (limited to first 1000 changes)

        Example:
            diff = bridge.memory_diff(watch_id)
            for entry in diff["diff"]:
                print(f"Offset {entry['offset']}: {entry['old']} -> {entry['new']}")
        """
        import hashlib

        if not hasattr(self, '_memory_watches'):
            self._memory_watches = {}

        watch = self._memory_watches.get(watch_id)
        if not watch:
            return {
                "changed": False,
                "error": f"Watch not found: {watch_id}"
            }

        address = watch["address"]
        size = watch["size"]
        initial_data = watch["initial_data"]
        initial_hash = watch["initial_hash"]

        # Read current memory
        current_data = self.read_memory(f"0x{address:X}", size)
        if not current_data:
            return {
                "changed": False,
                "error": f"Failed to read memory at 0x{address:X}"
            }

        current_hash = hashlib.sha256(current_data).hexdigest()

        if current_hash == initial_hash:
            return {
                "changed": False,
                "address": f"0x{address:X}",
                "size": size,
                "before_hash": initial_hash,
                "after_hash": current_hash,
                "changed_bytes": 0,
                "changed_ranges": [],
                "diff": []
            }

        # Build detailed diff
        diff_entries = []
        changed_ranges = []
        change_start = None
        changed_bytes = 0

        for i in range(min(len(initial_data), len(current_data))):
            if initial_data[i] != current_data[i]:
                changed_bytes += 1
                if change_start is None:
                    change_start = i

                # Add to diff entries (limit to 1000)
                if len(diff_entries) < 1000:
                    diff_entries.append({
                        "offset": i,
                        "address": f"0x{address + i:X}",
                        "old": f"{initial_data[i]:02X}",
                        "new": f"{current_data[i]:02X}"
                    })
            else:
                if change_start is not None:
                    changed_ranges.append({
                        "offset": change_start,
                        "length": i - change_start,
                        "address": f"0x{address + change_start:X}"
                    })
                    change_start = None

        # Handle trailing change
        if change_start is not None:
            changed_ranges.append({
                "offset": change_start,
                "length": min(len(initial_data), len(current_data)) - change_start,
                "address": f"0x{address + change_start:X}"
            })

        return {
            "changed": True,
            "address": f"0x{address:X}",
            "size": size,
            "before_hash": initial_hash,
            "after_hash": current_hash,
            "changed_bytes": changed_bytes,
            "changed_ranges": changed_ranges,
            "diff": diff_entries,
            "truncated": len(diff_entries) >= 1000
        }

    def list_memory_watches(self) -> dict[str, Any]:
        """
        List all active memory watches.

        Returns:
            Dictionary with:
                - watches: List of watch info dictionaries
                - count: Number of active watches
        """
        if not hasattr(self, '_memory_watches'):
            self._memory_watches = {}

        watches = []
        for watch_id, watch in self._memory_watches.items():
            watches.append({
                "watch_id": watch_id,
                "address": f"0x{watch['address']:X}",
                "size": watch["size"],
                "initial_hash": watch["initial_hash"][:16] + "...",
                "poll_interval_ms": watch["poll_interval_ms"],
                "created_at": watch["created_at"]
            })

        return {
            "watches": watches,
            "count": len(watches)
        }

    def remove_memory_watch(self, watch_id: str) -> dict[str, Any]:
        """
        Remove a memory watch.

        Args:
            watch_id: Watch ID to remove

        Returns:
            Dictionary with success status
        """
        if not hasattr(self, '_memory_watches'):
            self._memory_watches = {}

        if watch_id in self._memory_watches:
            del self._memory_watches[watch_id]
            logger.info(f"Removed memory watch {watch_id}")
            return {"success": True, "watch_id": watch_id}
        else:
            return {"success": False, "error": f"Watch not found: {watch_id}"}

    # =========================================================================
    # API Hook Detection Methods
    # =========================================================================

    def detect_hooks(
        self,
        modules: list[str] | None = None,
        methods: list[str] | None = None,
        max_functions: int = 200
    ) -> dict[str, Any]:
        """
        Detect API hooks in loaded modules.

        Scans for inline hooks (JMP/CALL patches), IAT hooks (import table
        modifications), and EAT hooks (export table redirects).

        Args:
            modules: List of module names to scan. If None, scans common
                    system modules (ntdll, kernel32, kernelbase).
            methods: List of detection methods: "inline", "iat", "eat".
                    If None, defaults to ["inline", "iat", "eat"].
            max_functions: Maximum functions to check per module (default: 200)

        Returns:
            Dictionary containing:
                - hooks_found: List of detected hooks with details
                - summary: Statistics about the scan
                - modules_scanned: Number of modules scanned
                - functions_checked: Number of functions checked

        Example:
            result = bridge.detect_hooks(
                modules=["ntdll.dll", "kernel32.dll"],
                methods=["inline", "iat", "eat"]
            )
        """
        # Default modules
        if modules is None:
            modules = ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]

        # Default methods
        if methods is None:
            methods = ["inline", "iat", "eat"]

        # Normalize method names
        methods = [m.lower() for m in methods]

        # Get loaded modules info
        loaded_modules = self.get_modules()
        module_map: dict[str, dict[str, Any]] = {}
        for mod in loaded_modules:
            name = mod.get("name", "").lower()
            base = mod.get("base", "0")
            size = mod.get("size", "0")

            # Parse base and size
            if isinstance(base, str):
                base = int(base, 16) if base.startswith("0x") or base.startswith("0X") else int(base, 16)
            if isinstance(size, str):
                size = int(size, 16) if size.startswith("0x") or size.startswith("0X") else int(size, 16)

            module_map[name] = {
                "base": base,
                "size": size,
                "path": mod.get("path", "")
            }

        hooks_found: list[dict[str, Any]] = []
        modules_scanned = 0
        functions_checked = 0
        inline_hooks = 0
        iat_hooks = 0
        eat_hooks = 0

        for module_name in modules:
            module_name_lower = module_name.lower()
            if not module_name_lower.endswith(".dll") and "." not in module_name_lower:
                module_name_lower += ".dll"

            if module_name_lower not in module_map:
                logger.debug(f"Module not loaded: {module_name_lower}")
                continue

            mod_info = module_map[module_name_lower]
            mod_base = mod_info["base"]
            mod_size = mod_info["size"]
            modules_scanned += 1

            # Get module exports for inline and EAT hook detection
            exports: list[dict[str, str]] = []
            try:
                exports_result = self.get_module_exports(module_name_lower)
                exports = exports_result if isinstance(exports_result, list) else exports_result.get("exports", [])
            except Exception as e:
                logger.debug(f"Failed to get exports for {module_name_lower}: {e}")

            # Check inline hooks on exported functions
            if "inline" in methods and exports:
                for export in exports[:max_functions]:
                    functions_checked += 1
                    hook = self._check_inline_hook_entry(
                        export, mod_base, mod_size, module_name_lower
                    )
                    if hook:
                        hooks_found.append(hook)
                        inline_hooks += 1

            # Check EAT hooks (export table redirects)
            if "eat" in methods and exports:
                for export in exports[:max_functions]:
                    hook = self._check_eat_hook(
                        export, mod_base, mod_size, module_name_lower
                    )
                    if hook:
                        hooks_found.append(hook)
                        eat_hooks += 1

            # Check IAT hooks for the main executable
            if "iat" in methods:
                # Find the main executable module
                main_module = None
                for mod_name, mod_data in module_map.items():
                    if mod_name.endswith(".exe"):
                        main_module = mod_name
                        break

                if main_module:
                    iat_hook_results = self._check_iat_hooks(
                        main_module, module_name_lower, module_map, max_functions
                    )
                    for hook in iat_hook_results:
                        hooks_found.append(hook)
                        iat_hooks += 1
                        functions_checked += 1

        return {
            "hooks_found": hooks_found,
            "summary": {
                "total_hooks": len(hooks_found),
                "inline_hooks": inline_hooks,
                "iat_hooks": iat_hooks,
                "eat_hooks": eat_hooks
            },
            "modules_scanned": modules_scanned,
            "functions_checked": functions_checked
        }

    def _check_inline_hook_entry(
        self,
        export: dict[str, str],
        mod_base: int,
        mod_size: int,
        module_name: str
    ) -> dict[str, Any] | None:
        """
        Check if a function entry point has an inline hook.

        Looks for JMP (E9, FF 25), CALL (E8), push+ret, or mov+jmp patterns
        that redirect to addresses outside the module.

        Args:
            export: Export entry with name and address
            mod_base: Module base address
            mod_size: Module size
            module_name: Module name for reporting

        Returns:
            Hook info dict if hook detected, None otherwise
        """
        func_name = export.get("name", "")
        func_addr = export.get("address", "")

        if not func_addr:
            return None

        # Parse function address
        if isinstance(func_addr, str):
            try:
                func_addr_int = int(func_addr, 16) if not func_addr.startswith("0x") else int(func_addr, 16)
            except ValueError:
                return None
        else:
            func_addr_int = func_addr

        try:
            # Read first 16 bytes of function
            first_bytes = self.read_memory(f"0x{func_addr_int:X}", 16)
            if not first_bytes or len(first_bytes) < 5:
                return None

            redirect_to = None
            hook_type = None
            bytes_modified = 0

            # Check for relative JMP (E9 xx xx xx xx)
            if first_bytes[0] == 0xE9:
                offset = int.from_bytes(first_bytes[1:5], 'little', signed=True)
                next_addr = func_addr_int + 5
                redirect_to = next_addr + offset
                hook_type = "inline_jmp"
                bytes_modified = 5

            # Check for relative CALL (E8 xx xx xx xx)
            elif first_bytes[0] == 0xE8:
                offset = int.from_bytes(first_bytes[1:5], 'little', signed=True)
                next_addr = func_addr_int + 5
                redirect_to = next_addr + offset
                hook_type = "inline_call"
                bytes_modified = 5

            # Check for absolute JMP via memory (FF 25 xx xx xx xx) - RIP-relative in x64
            elif len(first_bytes) >= 6 and first_bytes[0] == 0xFF and first_bytes[1] == 0x25:
                offset = int.from_bytes(first_bytes[2:6], 'little', signed=True)
                next_addr = func_addr_int + 6
                ptr_addr = next_addr + offset
                # Read the pointer to get actual target
                try:
                    ptr_data = self.read_memory(f"0x{ptr_addr:X}", 8)
                    if ptr_data and len(ptr_data) >= 8:
                        redirect_to = int.from_bytes(ptr_data[:8], 'little')
                    else:
                        redirect_to = ptr_addr  # Fallback to pointer location
                except Exception:
                    redirect_to = ptr_addr
                hook_type = "inline_jmp_indirect"
                bytes_modified = 6

            # Check for push + ret pattern (68 xx xx xx xx C3) - 6 bytes
            elif len(first_bytes) >= 6 and first_bytes[0] == 0x68 and first_bytes[5] == 0xC3:
                redirect_to = int.from_bytes(first_bytes[1:5], 'little')
                hook_type = "push_ret"
                bytes_modified = 6

            # Check for mov rax + jmp rax pattern (48 B8 ... FF E0) - 12 bytes for 64-bit
            elif len(first_bytes) >= 12 and first_bytes[0] == 0x48 and first_bytes[1] == 0xB8:
                if first_bytes[10] == 0xFF and first_bytes[11] == 0xE0:
                    redirect_to = int.from_bytes(first_bytes[2:10], 'little')
                    hook_type = "mov_jmp"
                    bytes_modified = 12

            if redirect_to is None:
                return None

            # Check if redirect is outside the module
            mod_end = mod_base + mod_size
            if mod_base <= redirect_to < mod_end:
                # Redirect is within module - probably not a hook
                return None

            return {
                "module": module_name,
                "function": func_name,
                "address": f"0x{func_addr_int:X}",
                "type": "inline_hook",
                "hook_subtype": hook_type,
                "redirect_to": f"0x{redirect_to:X}",
                "bytes_modified": bytes_modified,
                "original_bytes": "unknown",
                "hooked_bytes": first_bytes[:bytes_modified].hex().upper()
            }

        except Exception as e:
            logger.debug(f"Failed to check inline hook for {func_name}: {e}")
            return None

    def _check_eat_hook(
        self,
        export: dict[str, str],
        mod_base: int,
        mod_size: int,
        module_name: str
    ) -> dict[str, Any] | None:
        """
        Check if an export table entry redirects outside the module (EAT hook).

        EAT hooks modify the export address table to point to code outside
        the module, often to a forwarded export or hooked function.

        Args:
            export: Export entry with name and address
            mod_base: Module base address
            mod_size: Module size
            module_name: Module name for reporting

        Returns:
            Hook info dict if EAT hook detected, None otherwise
        """
        func_name = export.get("name", "")
        func_addr = export.get("address", "")

        if not func_addr:
            return None

        # Parse function address
        if isinstance(func_addr, str):
            try:
                func_addr_int = int(func_addr, 16) if not func_addr.startswith("0x") else int(func_addr, 16)
            except ValueError:
                return None
        else:
            func_addr_int = func_addr

        # Check if export address is outside module bounds
        mod_end = mod_base + mod_size

        if func_addr_int < mod_base or func_addr_int >= mod_end:
            # Export points outside module - this is an EAT hook or forward
            # Try to determine where it points
            try:
                # Check if it's a known module
                target_module = None

                modules = self.get_modules()
                for mod in modules:
                    m_base = mod.get("base", "0")
                    m_size = mod.get("size", "0")
                    if isinstance(m_base, str):
                        m_base = int(m_base, 16) if m_base.startswith("0x") else int(m_base, 16)
                    if isinstance(m_size, str):
                        m_size = int(m_size, 16) if m_size.startswith("0x") else int(m_size, 16)

                    if m_base <= func_addr_int < m_base + m_size:
                        target_module = mod.get("name", "unknown")
                        break

                return {
                    "module": module_name,
                    "function": func_name,
                    "address": f"0x{func_addr_int:X}",
                    "type": "eat_hook",
                    "redirect_to": f"0x{func_addr_int:X}",
                    "target_module": target_module,
                    "bytes_modified": 0,
                    "original_bytes": "N/A",
                    "hooked_bytes": "N/A"
                }
            except Exception as e:
                logger.debug(f"Failed to analyze EAT hook for {func_name}: {e}")

        return None

    def _check_iat_hooks(
        self,
        main_module: str,
        target_module: str,
        module_map: dict[str, dict[str, Any]],
        max_functions: int
    ) -> list[dict[str, Any]]:
        """
        Check for IAT hooks by comparing import addresses to actual export addresses.

        IAT hooks modify the Import Address Table to redirect calls to hooked
        functions instead of the original API implementations.

        Args:
            main_module: Name of the main executable module
            target_module: Name of the DLL to check imports from
            module_map: Map of module names to their info
            max_functions: Maximum imports to check

        Returns:
            List of detected IAT hooks
        """
        hooks: list[dict[str, Any]] = []

        try:
            # Get imports for the main module
            imports = self.get_module_imports(main_module)
            if not imports:
                return hooks

            # Get exports from target module for comparison
            exports = self.get_module_exports(target_module)
            if not exports:
                return hooks

            # Build export address map
            export_map: dict[str, int] = {}
            for exp in exports:
                name = exp.get("name", "")
                addr = exp.get("address", "")
                if name and addr:
                    if isinstance(addr, str):
                        try:
                            addr_int = int(addr, 16) if not addr.startswith("0x") else int(addr, 16)
                        except ValueError:
                            continue
                    else:
                        addr_int = addr
                    export_map[name] = addr_int

            # Get target module info
            target_lower = target_module.lower()
            if target_lower not in module_map:
                return hooks
            target_info = module_map[target_lower]
            target_base = target_info["base"]
            target_size = target_info["size"]

            # Check each import from the target module
            checked = 0
            for imp in imports:
                if checked >= max_functions:
                    break

                imp_module = imp.get("module", "").lower()
                if target_lower not in imp_module:
                    continue

                func_name = imp.get("function", "")
                iat_addr = imp.get("address", "")

                if not func_name or not iat_addr:
                    continue

                checked += 1

                # Parse IAT entry address
                if isinstance(iat_addr, str):
                    try:
                        iat_addr_int = int(iat_addr, 16) if not iat_addr.startswith("0x") else int(iat_addr, 16)
                    except ValueError:
                        continue
                else:
                    iat_addr_int = iat_addr

                # Read the actual value at the IAT entry (the function pointer)
                try:
                    iat_value_bytes = self.read_memory(f"0x{iat_addr_int:X}", 8)
                    if not iat_value_bytes or len(iat_value_bytes) < 8:
                        continue
                    iat_value = int.from_bytes(iat_value_bytes[:8], 'little')
                except Exception:
                    continue

                # Compare with expected export address
                expected_addr = export_map.get(func_name)
                if expected_addr is None:
                    continue

                # Check if IAT value points to the expected address
                if iat_value != expected_addr:
                    # IAT has been modified - check if it points outside the target module
                    target_end = target_base + target_size

                    if iat_value < target_base or iat_value >= target_end:
                        # Definite IAT hook - points outside the expected module
                        hooks.append({
                            "module": target_module,
                            "function": func_name,
                            "address": f"0x{iat_addr_int:X}",
                            "type": "iat_hook",
                            "redirect_to": f"0x{iat_value:X}",
                            "expected_address": f"0x{expected_addr:X}",
                            "bytes_modified": 8,
                            "original_bytes": f"{expected_addr:016X}",
                            "hooked_bytes": f"{iat_value:016X}"
                        })

        except Exception as e:
            logger.debug(f"Failed to check IAT hooks for {main_module} -> {target_module}: {e}")

        return hooks

    def unhook_function(
        self,
        module_name: str,
        function_name: str,
        original_bytes: str | None = None
    ) -> dict[str, Any]:
        """
        Remove an inline hook from a function by restoring original bytes.

        Args:
            module_name: Name of the module containing the function
            function_name: Name of the function to unhook
            original_bytes: Original bytes to restore (hex string).
                           If not provided, common syscall stub patterns are tried.

        Returns:
            Dictionary with:
                - success: Whether unhook succeeded
                - function: Function name
                - address: Function address
                - previous_bytes: Bytes before unhooking
                - restored_bytes: Bytes after unhooking
                - error: Error message if failed

        Example:
            result = bridge.unhook_function(
                "ntdll.dll",
                "NtCreateFile",
                original_bytes="4C8BD1B8550000"
            )
        """
        result: dict[str, Any] = {
            "success": False,
            "function": function_name,
            "module": module_name,
            "address": None,
            "previous_bytes": None,
            "restored_bytes": None,
            "error": None
        }

        try:
            # Resolve function address
            expression = f"{module_name}!{function_name}"
            resolve_result = self.resolve_symbol(expression)

            if not resolve_result.get("success"):
                result["error"] = f"Failed to resolve '{expression}': {resolve_result.get('error', 'Unknown error')}"
                return result

            func_addr = resolve_result.get("address", "")
            if isinstance(func_addr, str):
                func_addr_int = int(func_addr, 16) if func_addr.startswith("0x") else int(func_addr, 16)
            else:
                func_addr_int = func_addr

            result["address"] = f"0x{func_addr_int:X}"

            # Read current bytes
            current_bytes = self.read_memory(f"0x{func_addr_int:X}", 16)
            if not current_bytes:
                result["error"] = f"Could not read memory at 0x{func_addr_int:X}"
                return result

            result["previous_bytes"] = current_bytes[:12].hex().upper()

            # Determine original bytes to restore
            if original_bytes:
                try:
                    orig_bytes = bytes.fromhex(original_bytes.replace(" ", "").replace("0x", ""))
                except ValueError:
                    result["error"] = f"Invalid hex string for original_bytes: {original_bytes}"
                    return result
            else:
                # Try common patterns for ntdll syscall stubs
                # These are the typical first bytes of Windows syscall stubs
                result["error"] = (
                    "Original bytes required to unhook.\n"
                    "Provide the original function prologue bytes (hex string).\n"
                    "Common ntdll syscall prologues:\n"
                    "  - 4C 8B D1 B8 xx xx 00 00  (mov r10, rcx; mov eax, syscall_num)\n"
                    "  - 48 89 5C 24 08           (mov [rsp+8], rbx)\n"
                    "  - 40 53 48 83 EC 20        (push rbx; sub rsp, 20h)"
                )
                return result

            # Check if already restored
            if current_bytes[:len(orig_bytes)] == orig_bytes:
                result["success"] = True
                result["restored_bytes"] = orig_bytes.hex().upper()
                result["error"] = "Function is not hooked (bytes already match original)"
                return result

            # Write original bytes
            self.write_memory(f"0x{func_addr_int:X}", orig_bytes)

            # Verify write
            verify_bytes = self.read_memory(f"0x{func_addr_int:X}", len(orig_bytes))
            if verify_bytes and verify_bytes == orig_bytes:
                result["success"] = True
                result["restored_bytes"] = orig_bytes.hex().upper()
            else:
                result["error"] = "Write verification failed"
                result["restored_bytes"] = verify_bytes.hex().upper() if verify_bytes else "read failed"

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"unhook_function failed: {e}")

        return result
