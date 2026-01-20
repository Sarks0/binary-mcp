"""
Structured error messages with actionable suggestions.

Provides rich error information for MCP tool consumers including:
- Error codes for programmatic handling
- Human-readable messages
- Actionable suggestions for resolution
- Debug information for troubleshooting
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ErrorCode(str, Enum):
    """
    Standard error codes for binary-mcp operations.

    Naming convention: CATEGORY_SPECIFIC_ERROR
    """

    # Address/Memory errors
    ADDRESS_INVALID = "ADDRESS_INVALID"
    ADDRESS_NOT_EXECUTABLE = "ADDRESS_NOT_EXECUTABLE"
    ADDRESS_NOT_READABLE = "ADDRESS_NOT_READABLE"
    ADDRESS_NOT_WRITABLE = "ADDRESS_NOT_WRITABLE"
    ADDRESS_MISSING = "ADDRESS_MISSING"
    MEMORY_READ_FAILED = "MEMORY_READ_FAILED"
    MEMORY_WRITE_FAILED = "MEMORY_WRITE_FAILED"
    MEMORY_ALLOC_FAILED = "MEMORY_ALLOC_FAILED"

    # Breakpoint errors
    BREAKPOINT_SET_FAILED = "BREAKPOINT_SET_FAILED"
    BREAKPOINT_DELETE_FAILED = "BREAKPOINT_DELETE_FAILED"
    BREAKPOINT_NOT_FOUND = "BREAKPOINT_NOT_FOUND"
    BREAKPOINT_LIMIT_REACHED = "BREAKPOINT_LIMIT_REACHED"

    # Module/Symbol errors
    MODULE_NOT_FOUND = "MODULE_NOT_FOUND"
    MODULE_NOT_LOADED = "MODULE_NOT_LOADED"
    SYMBOL_NOT_FOUND = "SYMBOL_NOT_FOUND"
    SYMBOL_RESOLVE_FAILED = "SYMBOL_RESOLVE_FAILED"

    # Debugger state errors
    DEBUGGER_NOT_CONNECTED = "DEBUGGER_NOT_CONNECTED"
    DEBUGGER_NOT_PAUSED = "DEBUGGER_NOT_PAUSED"
    DEBUGGER_NOT_RUNNING = "DEBUGGER_NOT_RUNNING"
    DEBUGGER_NO_BINARY = "DEBUGGER_NO_BINARY"
    DEBUGGER_TIMEOUT = "DEBUGGER_TIMEOUT"

    # Disassembly errors
    DISASSEMBLY_FAILED = "DISASSEMBLY_FAILED"
    INVALID_INSTRUCTION = "INVALID_INSTRUCTION"

    # Parameter errors
    PARAMETER_INVALID = "PARAMETER_INVALID"
    PARAMETER_MISSING = "PARAMETER_MISSING"
    PARAMETER_OUT_OF_RANGE = "PARAMETER_OUT_OF_RANGE"

    # Connection errors
    CONNECTION_FAILED = "CONNECTION_FAILED"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"

    # API errors
    API_ERROR = "API_ERROR"
    API_NOT_IMPLEMENTED = "API_NOT_IMPLEMENTED"

    # General errors
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
    OPERATION_FAILED = "OPERATION_FAILED"


@dataclass
class StructuredError:
    """
    Rich error information with actionable suggestions.

    Attributes:
        error: Error code for programmatic handling
        message: Human-readable error description
        reason: Explanation of why the error occurred
        suggestions: List of actionable steps to resolve the error
        debug_info: Additional debugging information
    """

    error: ErrorCode
    message: str
    reason: str | None = None
    suggestions: list[str] = field(default_factory=list)
    debug_info: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "error": self.error.value,
            "message": self.message,
            "reason": self.reason,
            "suggestions": self.suggestions,
            "debug_info": self.debug_info,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_user_message(self) -> str:
        """
        Format error for human-readable display.

        Returns:
            Multi-line string suitable for display to users
        """
        lines = [
            f"Error [{self.error.value}]: {self.message}",
        ]

        if self.reason:
            lines.append(f"Reason: {self.reason}")

        if self.suggestions:
            lines.append("\nSuggested actions:")
            for i, suggestion in enumerate(self.suggestions, 1):
                lines.append(f"  {i}. {suggestion}")

        if self.debug_info:
            lines.append("\nDebug information:")
            for key, value in self.debug_info.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)

    def __str__(self) -> str:
        """Return user-friendly message."""
        return self.to_user_message()


class StructuredBaseError(Exception):
    """
    Exception that wraps a StructuredError.

    Allows raising structured errors as exceptions while maintaining
    all error information.
    """

    def __init__(self, structured_error: StructuredError):
        self.structured_error = structured_error
        super().__init__(structured_error.to_user_message())

    def to_dict(self) -> dict[str, Any]:
        """Get the underlying structured error as a dictionary."""
        return self.structured_error.to_dict()

    def to_json(self, indent: int = 2) -> str:
        """Get the underlying structured error as JSON."""
        return self.structured_error.to_json(indent)


# =============================================================================
# Suggestion Mappings - Predefined suggestions for common error scenarios
# =============================================================================

BREAKPOINT_SUGGESTIONS = {
    "address_invalid": [
        "Verify the address is a valid hexadecimal value (e.g., '0x401000' or '401000')",
        "Use x64dbg_get_modules() to find valid module base addresses",
        "Use x64dbg_resolve_symbol() to convert function names to addresses",
    ],
    "address_not_executable": [
        "Verify the module containing this address is loaded with x64dbg_get_modules()",
        "Check address permissions with x64dbg_get_memory_info(address)",
        "Ensure the address is in a code section, not data",
    ],
    "set_failed": [
        "Ensure the debugger is connected and a binary is loaded",
        "Check if the address is valid and executable",
        "Try using x64dbg_resolve_symbol() if using a symbol name",
        "Check if maximum breakpoints have been reached (4 for hardware BPs)",
    ],
    "hw_limit": [
        "Hardware breakpoints are limited to 4 (DR0-DR3)",
        "Delete an existing hardware breakpoint first with x64dbg_delete_hardware_breakpoint()",
        "Consider using a software breakpoint instead for less critical locations",
    ],
}

MEMORY_SUGGESTIONS = {
    "read_failed": [
        "Verify the address is valid with x64dbg_check_memory(address)",
        "Check memory permissions with x64dbg_get_memory_info(address)",
        "Ensure the memory region is committed and not just reserved",
        "The process may have unmapped this memory region",
    ],
    "write_failed": [
        "Check if the memory has write permissions with x64dbg_get_memory_info(address)",
        "Use x64dbg_virt_protect() to add write permissions temporarily",
        "Code sections are typically read-only; patch with care",
    ],
    "alloc_failed": [
        "The requested memory size may be too large",
        "The specified address may conflict with existing allocations",
        "Try allocating without specifying an address to let the OS choose",
    ],
}

DEBUGGER_STATE_SUGGESTIONS = {
    "not_connected": [
        "Ensure x64dbg is running with the MCP plugin loaded",
        "Check that the plugin HTTP server is running on the expected port",
        "Verify the authentication token file exists in %TEMP%",
        "Restart x64dbg and reload the plugin",
    ],
    "not_paused": [
        "Use x64dbg_pause() to pause execution first",
        "Wait for the current operation to complete",
        "Set a breakpoint and run to it to pause at a specific location",
    ],
    "no_binary": [
        "Load a binary in x64dbg first (File -> Open)",
        "Use x64dbg_get_status() to check the current state",
        "Ensure the binary finished loading before sending commands",
    ],
    "timeout": [
        "The operation took too long; consider increasing the timeout",
        "Check if x64dbg is responding (try x64dbg_get_status())",
        "The debugged process may be hung or in an infinite loop",
    ],
}

SYMBOL_SUGGESTIONS = {
    "not_found": [
        "Verify the module is loaded with x64dbg_get_modules()",
        "Use module!function format (e.g., 'kernel32!CreateFileW')",
        "Check if symbols are loaded for the module",
        "The function name may be case-sensitive",
    ],
    "resolve_failed": [
        "Ensure debugging is active (binary is loaded)",
        "Make sure the debugger is paused, not running",
        "Try using the full module!function format",
        "The symbol may not exist or module not yet loaded",
    ],
}

DISASSEMBLY_SUGGESTIONS = {
    "failed": [
        "Check if the address is readable with x64dbg_check_memory(address)",
        "Verify the address contains valid code, not data",
        "The memory at this address may not be mapped",
        "Try reading a smaller number of instructions",
    ],
    "invalid_instruction": [
        "The bytes at this address may not be valid x86/x64 instructions",
        "You may be disassembling data or the middle of an instruction",
        "Check the function prologue to find the correct start address",
    ],
}


# =============================================================================
# Error Factory Functions
# =============================================================================


def create_address_invalid_error(
    address: str | None,
    param_name: str = "address",
    additional_info: dict[str, Any] | None = None,
) -> StructuredError:
    """Create error for invalid address parameter."""
    debug_info = {
        "parameter_name": param_name,
        "provided_value": address,
        "expected_format": "hexadecimal string (e.g., '0x401000' or '401000')",
    }
    if additional_info:
        debug_info.update(additional_info)

    return StructuredError(
        error=ErrorCode.ADDRESS_INVALID,
        message=f"Invalid {param_name}: '{address}'",
        reason="The address is not a valid hexadecimal value",
        suggestions=BREAKPOINT_SUGGESTIONS["address_invalid"],
        debug_info=debug_info,
    )


def create_address_missing_error(param_name: str = "address") -> StructuredError:
    """Create error for missing address parameter."""
    return StructuredError(
        error=ErrorCode.ADDRESS_MISSING,
        message=f"Missing required parameter: {param_name}",
        reason=f"The {param_name} parameter was not provided or is empty",
        suggestions=[
            f"Provide a valid hexadecimal address for '{param_name}'",
            "Format: '0x401000' or '401000'",
            "Use x64dbg_get_modules() to find module base addresses",
        ],
        debug_info={"parameter_name": param_name, "provided_value": None},
    )


def create_breakpoint_set_failed_error(
    address: str,
    api_error: str | None = None,
    address_valid: bool | None = None,
    module: str | None = None,
) -> StructuredError:
    """Create error for failed breakpoint set operation."""
    reason = "Failed to set breakpoint at the specified address"
    if api_error:
        reason = api_error

    debug_info = {
        "requested_address": address,
    }
    if address_valid is not None:
        debug_info["address_valid"] = address_valid
    if module is not None:
        debug_info["module"] = module

    suggestions = BREAKPOINT_SUGGESTIONS["set_failed"].copy()
    if "not executable" in (api_error or "").lower():
        suggestions = BREAKPOINT_SUGGESTIONS["address_not_executable"] + suggestions

    return StructuredError(
        error=ErrorCode.BREAKPOINT_SET_FAILED,
        message=f"Failed to set breakpoint at {address}",
        reason=reason,
        suggestions=suggestions,
        debug_info=debug_info,
    )


def create_breakpoint_hw_limit_error(address: str) -> StructuredError:
    """Create error for hardware breakpoint limit reached."""
    return StructuredError(
        error=ErrorCode.BREAKPOINT_LIMIT_REACHED,
        message=f"Cannot set hardware breakpoint at {address}",
        reason="Maximum number of hardware breakpoints (4) has been reached",
        suggestions=BREAKPOINT_SUGGESTIONS["hw_limit"],
        debug_info={
            "requested_address": address,
            "max_hardware_breakpoints": 4,
            "breakpoint_type": "hardware",
        },
    )


def create_memory_read_failed_error(
    address: str,
    size: int,
    api_error: str | None = None,
) -> StructuredError:
    """Create error for failed memory read operation."""
    return StructuredError(
        error=ErrorCode.MEMORY_READ_FAILED,
        message=f"Failed to read {size} bytes from {address}",
        reason=api_error or "Memory read operation failed",
        suggestions=MEMORY_SUGGESTIONS["read_failed"],
        debug_info={
            "address": address,
            "requested_size": size,
        },
    )


def create_memory_write_failed_error(
    address: str,
    size: int,
    api_error: str | None = None,
) -> StructuredError:
    """Create error for failed memory write operation."""
    return StructuredError(
        error=ErrorCode.MEMORY_WRITE_FAILED,
        message=f"Failed to write {size} bytes to {address}",
        reason=api_error or "Memory write operation failed",
        suggestions=MEMORY_SUGGESTIONS["write_failed"],
        debug_info={
            "address": address,
            "size": size,
        },
    )


def create_debugger_not_connected_error(
    host: str = "127.0.0.1",
    port: int = 8765,
    connection_error: str | None = None,
) -> StructuredError:
    """Create error for debugger connection failure."""
    return StructuredError(
        error=ErrorCode.DEBUGGER_NOT_CONNECTED,
        message="Cannot connect to x64dbg debugger",
        reason=connection_error or "Connection to x64dbg plugin failed",
        suggestions=DEBUGGER_STATE_SUGGESTIONS["not_connected"],
        debug_info={
            "host": host,
            "port": port,
            "url": f"http://{host}:{port}",
        },
    )


def create_debugger_not_paused_error(
    current_state: str | None = None,
    operation: str | None = None,
) -> StructuredError:
    """Create error for operations requiring paused state."""
    message = "Debugger must be paused for this operation"
    if operation:
        message = f"Operation '{operation}' requires debugger to be paused"

    return StructuredError(
        error=ErrorCode.DEBUGGER_NOT_PAUSED,
        message=message,
        reason=f"Current debugger state: {current_state or 'unknown'}",
        suggestions=DEBUGGER_STATE_SUGGESTIONS["not_paused"],
        debug_info={
            "current_state": current_state,
            "required_state": "paused",
            "operation": operation,
        },
    )


def create_debugger_no_binary_error(operation: str | None = None) -> StructuredError:
    """Create error for operations requiring a loaded binary."""
    message = "No binary is loaded in the debugger"
    if operation:
        message = f"Operation '{operation}' requires a binary to be loaded"

    return StructuredError(
        error=ErrorCode.DEBUGGER_NO_BINARY,
        message=message,
        reason="No debugging session is active",
        suggestions=DEBUGGER_STATE_SUGGESTIONS["no_binary"],
        debug_info={"operation": operation},
    )


def create_symbol_not_found_error(
    symbol: str,
    module: str | None = None,
) -> StructuredError:
    """Create error for symbol resolution failure."""
    message = f"Symbol not found: '{symbol}'"
    if module:
        message = f"Symbol '{symbol}' not found in module '{module}'"

    return StructuredError(
        error=ErrorCode.SYMBOL_NOT_FOUND,
        message=message,
        reason="The symbol could not be resolved to an address",
        suggestions=SYMBOL_SUGGESTIONS["not_found"],
        debug_info={
            "symbol": symbol,
            "module": module,
        },
    )


def create_symbol_resolve_failed_error(
    expression: str,
    api_error: str | None = None,
) -> StructuredError:
    """Create error for expression/symbol resolution failure."""
    return StructuredError(
        error=ErrorCode.SYMBOL_RESOLVE_FAILED,
        message=f"Failed to resolve: '{expression}'",
        reason=api_error or "Symbol resolution failed",
        suggestions=SYMBOL_SUGGESTIONS["resolve_failed"],
        debug_info={"expression": expression},
    )


def create_disassembly_failed_error(
    address: str,
    count: int,
    api_error: str | None = None,
) -> StructuredError:
    """Create error for disassembly failure."""
    return StructuredError(
        error=ErrorCode.DISASSEMBLY_FAILED,
        message=f"Disassembly failed at {address}",
        reason=api_error or "Could not disassemble instructions at the specified address",
        suggestions=DISASSEMBLY_SUGGESTIONS["failed"],
        debug_info={
            "address": address,
            "requested_count": count,
        },
    )


def create_module_not_loaded_error(
    module_name: str,
    available_modules: list[str] | None = None,
) -> StructuredError:
    """Create error for module not loaded."""
    suggestions = [
        f"Check if '{module_name}' is loaded with x64dbg_get_modules()",
        "The module may load later during execution",
        "Set a breakpoint on module load events to catch when it loads",
        "Verify the module name spelling (case may matter)",
    ]

    debug_info: dict[str, Any] = {"requested_module": module_name}
    if available_modules:
        debug_info["loaded_modules"] = available_modules[:10]  # Limit to 10

    return StructuredError(
        error=ErrorCode.MODULE_NOT_LOADED,
        message=f"Module not loaded: '{module_name}'",
        reason="The specified module is not currently loaded in the process",
        suggestions=suggestions,
        debug_info=debug_info,
    )


def create_timeout_error(
    operation: str,
    timeout_ms: int,
    partial_result: Any | None = None,
) -> StructuredError:
    """Create error for operation timeout."""
    return StructuredError(
        error=ErrorCode.DEBUGGER_TIMEOUT,
        message=f"Operation '{operation}' timed out after {timeout_ms}ms",
        reason="The operation did not complete within the specified time limit",
        suggestions=DEBUGGER_STATE_SUGGESTIONS["timeout"],
        debug_info={
            "operation": operation,
            "timeout_ms": timeout_ms,
            "partial_result": partial_result,
        },
    )


def create_api_error(
    operation: str,
    api_message: str,
    endpoint: str | None = None,
    http_status: int | None = None,
) -> StructuredError:
    """Create error for generic API failure."""
    suggestions = [
        "Check x64dbg is running and responsive",
        "Verify the plugin is loaded correctly",
        "Try the operation again - it may be a transient failure",
    ]

    # Add operation-specific suggestions based on the operation name
    if "breakpoint" in operation.lower():
        suggestions.extend(BREAKPOINT_SUGGESTIONS.get("set_failed", [])[:2])
    elif "memory" in operation.lower():
        suggestions.extend(MEMORY_SUGGESTIONS.get("read_failed", [])[:2])
    elif "disassemble" in operation.lower():
        suggestions.extend(DISASSEMBLY_SUGGESTIONS.get("failed", [])[:2])

    debug_info: dict[str, Any] = {
        "operation": operation,
        "api_message": api_message,
    }
    if endpoint:
        debug_info["endpoint"] = endpoint
    if http_status:
        debug_info["http_status"] = http_status

    return StructuredError(
        error=ErrorCode.API_ERROR,
        message=f"API error during '{operation}'",
        reason=api_message,
        suggestions=suggestions,
        debug_info=debug_info,
    )


def create_parameter_error(
    param_name: str,
    provided_value: Any,
    expected: str,
    valid_values: list[Any] | None = None,
) -> StructuredError:
    """Create error for invalid parameter value."""
    suggestions = [
        f"Provide a valid value for '{param_name}'",
        f"Expected: {expected}",
    ]
    if valid_values:
        suggestions.append(f"Valid options: {', '.join(str(v) for v in valid_values)}")

    return StructuredError(
        error=ErrorCode.PARAMETER_INVALID,
        message=f"Invalid value for parameter '{param_name}'",
        reason=f"Got '{provided_value}', expected {expected}",
        suggestions=suggestions,
        debug_info={
            "parameter": param_name,
            "provided": provided_value,
            "expected": expected,
            "valid_values": valid_values,
        },
    )


# =============================================================================
# Error Classification Helpers
# =============================================================================


def classify_api_error(api_message: str, operation: str = "") -> ErrorCode:
    """
    Classify an API error message into an appropriate ErrorCode.

    Args:
        api_message: The error message from the API
        operation: The operation that was being performed

    Returns:
        The most appropriate ErrorCode for this error
    """
    msg_lower = api_message.lower()

    # Address-related errors
    if "address" in msg_lower:
        if "invalid" in msg_lower or "not valid" in msg_lower:
            return ErrorCode.ADDRESS_INVALID
        if "missing" in msg_lower or "null" in msg_lower or "none" in msg_lower:
            return ErrorCode.ADDRESS_MISSING
        if "not executable" in msg_lower:
            return ErrorCode.ADDRESS_NOT_EXECUTABLE
        if "not readable" in msg_lower or "cannot read" in msg_lower:
            return ErrorCode.ADDRESS_NOT_READABLE
        if "not writable" in msg_lower or "cannot write" in msg_lower:
            return ErrorCode.ADDRESS_NOT_WRITABLE

    # Breakpoint errors
    if "breakpoint" in msg_lower:
        if "limit" in msg_lower or "maximum" in msg_lower or "dr" in msg_lower:
            return ErrorCode.BREAKPOINT_LIMIT_REACHED
        if "not found" in msg_lower or "does not exist" in msg_lower:
            return ErrorCode.BREAKPOINT_NOT_FOUND
        if "delete" in operation.lower():
            return ErrorCode.BREAKPOINT_DELETE_FAILED
        return ErrorCode.BREAKPOINT_SET_FAILED

    # Memory errors
    if "memory" in msg_lower:
        if "read" in msg_lower or "cannot read" in msg_lower:
            return ErrorCode.MEMORY_READ_FAILED
        if "write" in msg_lower or "cannot write" in msg_lower:
            return ErrorCode.MEMORY_WRITE_FAILED
        if "alloc" in msg_lower:
            return ErrorCode.MEMORY_ALLOC_FAILED

    # Module/Symbol errors
    if "module" in msg_lower:
        if "not found" in msg_lower or "not loaded" in msg_lower:
            return ErrorCode.MODULE_NOT_LOADED
    if "symbol" in msg_lower or "resolve" in msg_lower:
        if "not found" in msg_lower:
            return ErrorCode.SYMBOL_NOT_FOUND
        return ErrorCode.SYMBOL_RESOLVE_FAILED

    # Debugger state errors
    if "not debugging" in msg_lower or "no debug" in msg_lower:
        return ErrorCode.DEBUGGER_NO_BINARY
    if "not paused" in msg_lower or "running" in msg_lower:
        return ErrorCode.DEBUGGER_NOT_PAUSED
    if "timeout" in msg_lower:
        return ErrorCode.DEBUGGER_TIMEOUT
    if "connect" in msg_lower or "connection" in msg_lower:
        return ErrorCode.CONNECTION_FAILED
    if "auth" in msg_lower or "token" in msg_lower:
        return ErrorCode.AUTHENTICATION_FAILED

    # Disassembly errors
    if "disassembl" in msg_lower:
        return ErrorCode.DISASSEMBLY_FAILED

    # Parameter errors
    if "parameter" in msg_lower or "argument" in msg_lower:
        if "missing" in msg_lower:
            return ErrorCode.PARAMETER_MISSING
        if "invalid" in msg_lower or "out of range" in msg_lower:
            return ErrorCode.PARAMETER_INVALID

    return ErrorCode.API_ERROR


def create_error_from_api_response(
    operation: str,
    api_message: str,
    context: dict[str, Any] | None = None,
) -> StructuredError:
    """
    Create a StructuredError from an API error response.

    Automatically classifies the error and adds appropriate suggestions.

    Args:
        operation: The operation that failed
        api_message: The error message from the API
        context: Additional context (address, module, etc.)

    Returns:
        A StructuredError with appropriate classification and suggestions
    """
    context = context or {}
    error_code = classify_api_error(api_message, operation)

    # Route to specific error creators based on classification
    if error_code == ErrorCode.ADDRESS_INVALID:
        return create_address_invalid_error(
            context.get("address"),
            additional_info=context,
        )
    elif error_code == ErrorCode.ADDRESS_MISSING:
        return create_address_missing_error(context.get("param_name", "address"))
    elif error_code == ErrorCode.BREAKPOINT_SET_FAILED:
        return create_breakpoint_set_failed_error(
            context.get("address", "unknown"),
            api_error=api_message,
            module=context.get("module"),
        )
    elif error_code == ErrorCode.BREAKPOINT_LIMIT_REACHED:
        return create_breakpoint_hw_limit_error(context.get("address", "unknown"))
    elif error_code == ErrorCode.MEMORY_READ_FAILED:
        return create_memory_read_failed_error(
            context.get("address", "unknown"),
            context.get("size", 0),
            api_error=api_message,
        )
    elif error_code == ErrorCode.MEMORY_WRITE_FAILED:
        return create_memory_write_failed_error(
            context.get("address", "unknown"),
            context.get("size", 0),
            api_error=api_message,
        )
    elif error_code == ErrorCode.SYMBOL_NOT_FOUND:
        return create_symbol_not_found_error(
            context.get("symbol", context.get("expression", "unknown")),
            context.get("module"),
        )
    elif error_code == ErrorCode.SYMBOL_RESOLVE_FAILED:
        return create_symbol_resolve_failed_error(
            context.get("expression", "unknown"),
            api_error=api_message,
        )
    elif error_code == ErrorCode.DISASSEMBLY_FAILED:
        return create_disassembly_failed_error(
            context.get("address", "unknown"),
            context.get("count", 10),
            api_error=api_message,
        )
    elif error_code == ErrorCode.DEBUGGER_NO_BINARY:
        return create_debugger_no_binary_error(operation)
    elif error_code == ErrorCode.DEBUGGER_NOT_PAUSED:
        return create_debugger_not_paused_error(
            context.get("state"),
            operation,
        )
    elif error_code == ErrorCode.MODULE_NOT_LOADED:
        return create_module_not_loaded_error(
            context.get("module", "unknown"),
        )
    else:
        # Generic API error
        return create_api_error(
            operation,
            api_message,
            context.get("endpoint"),
            context.get("http_status"),
        )
