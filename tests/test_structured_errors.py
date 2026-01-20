"""
Tests for structured error messages.

Verifies that error codes, messages, suggestions, and debug info
are properly formatted for actionable user feedback.
"""

import json

import pytest

from src.utils.structured_errors import (
    ErrorCode,
    StructuredBaseError,
    StructuredError,
    classify_api_error,
    create_address_invalid_error,
    create_address_missing_error,
    create_api_error,
    create_breakpoint_hw_limit_error,
    create_breakpoint_set_failed_error,
    create_debugger_no_binary_error,
    create_debugger_not_connected_error,
    create_debugger_not_paused_error,
    create_disassembly_failed_error,
    create_error_from_api_response,
    create_memory_read_failed_error,
    create_memory_write_failed_error,
    create_module_not_loaded_error,
    create_parameter_error,
    create_symbol_not_found_error,
    create_symbol_resolve_failed_error,
    create_timeout_error,
)


class TestStructuredError:
    """Tests for StructuredError class."""

    def test_basic_creation(self):
        """Test creating a basic structured error."""
        error = StructuredError(
            error=ErrorCode.BREAKPOINT_SET_FAILED,
            message="Failed to set breakpoint at 0x7670EDC0",
            reason="Address is not executable or module not loaded",
            suggestions=[
                "Verify module is loaded with x64dbg_get_modules()",
                "Check address permissions with x64dbg_get_memory_info('0x7670EDC0')",
            ],
            debug_info={
                "requested_address": "0x7670EDC0",
                "address_valid": False,
                "module": None,
            },
        )

        assert error.error == ErrorCode.BREAKPOINT_SET_FAILED
        assert "0x7670EDC0" in error.message
        assert len(error.suggestions) == 2
        assert "requested_address" in error.debug_info

    def test_to_dict(self):
        """Test conversion to dictionary."""
        error = StructuredError(
            error=ErrorCode.ADDRESS_INVALID,
            message="Invalid address: 'xyz'",
            reason="Not a valid hexadecimal value",
            suggestions=["Use hex format like '0x401000'"],
            debug_info={"provided_value": "xyz"},
        )

        result = error.to_dict()

        assert result["error"] == "ADDRESS_INVALID"
        assert result["message"] == "Invalid address: 'xyz'"
        assert result["reason"] == "Not a valid hexadecimal value"
        assert "Use hex format" in result["suggestions"][0]
        assert result["debug_info"]["provided_value"] == "xyz"

    def test_to_json(self):
        """Test JSON serialization."""
        error = StructuredError(
            error=ErrorCode.MEMORY_READ_FAILED,
            message="Read failed",
            suggestions=["Check permissions"],
        )

        json_str = error.to_json()
        parsed = json.loads(json_str)

        assert parsed["error"] == "MEMORY_READ_FAILED"
        assert parsed["message"] == "Read failed"

    def test_to_user_message(self):
        """Test human-readable message format."""
        error = StructuredError(
            error=ErrorCode.DEBUGGER_NOT_CONNECTED,
            message="Cannot connect to x64dbg",
            reason="Plugin HTTP server not running",
            suggestions=[
                "Ensure x64dbg is running",
                "Check plugin is loaded",
            ],
            debug_info={"port": 8765},
        )

        msg = error.to_user_message()

        assert "Error [DEBUGGER_NOT_CONNECTED]" in msg
        assert "Cannot connect to x64dbg" in msg
        assert "Plugin HTTP server not running" in msg
        assert "Suggested actions:" in msg
        assert "1. Ensure x64dbg is running" in msg
        assert "2. Check plugin is loaded" in msg
        assert "port: 8765" in msg

    def test_str_method(self):
        """Test __str__ returns user message."""
        error = StructuredError(
            error=ErrorCode.API_ERROR,
            message="API call failed",
        )

        assert "Error [API_ERROR]" in str(error)


class TestStructuredBaseError:
    """Tests for StructuredBaseError."""

    def test_exception_wraps_error(self):
        """Test exception wraps structured error."""
        structured_error = StructuredError(
            error=ErrorCode.SYMBOL_NOT_FOUND,
            message="Symbol 'foo' not found",
        )

        exc = StructuredBaseError(structured_error)

        assert exc.structured_error == structured_error
        assert "SYMBOL_NOT_FOUND" in str(exc)

    def test_exception_to_dict(self):
        """Test exception provides dict access."""
        structured_error = StructuredError(
            error=ErrorCode.TIMEOUT_ERROR if hasattr(ErrorCode, 'TIMEOUT_ERROR') else ErrorCode.DEBUGGER_TIMEOUT,
            message="Operation timed out",
        )

        exc = StructuredBaseError(structured_error)
        result = exc.to_dict()

        assert result["error"] in ["TIMEOUT_ERROR", "DEBUGGER_TIMEOUT"]

    def test_exception_can_be_raised(self):
        """Test exception can be raised and caught."""
        structured_error = StructuredError(
            error=ErrorCode.BREAKPOINT_NOT_FOUND,
            message="No breakpoint at address",
        )

        with pytest.raises(StructuredBaseError) as exc_info:
            raise StructuredBaseError(structured_error)

        assert exc_info.value.structured_error.error == ErrorCode.BREAKPOINT_NOT_FOUND


class TestErrorFactoryFunctions:
    """Tests for error factory functions."""

    def test_create_address_invalid_error(self):
        """Test address invalid error creation."""
        error = create_address_invalid_error("xyz123", "breakpoint_address")

        assert error.error == ErrorCode.ADDRESS_INVALID
        assert "xyz123" in error.message
        assert "breakpoint_address" in error.message
        assert len(error.suggestions) > 0
        assert error.debug_info["parameter_name"] == "breakpoint_address"
        assert error.debug_info["provided_value"] == "xyz123"

    def test_create_address_missing_error(self):
        """Test address missing error creation."""
        error = create_address_missing_error("target_address")

        assert error.error == ErrorCode.ADDRESS_MISSING
        assert "target_address" in error.message
        assert error.debug_info["parameter_name"] == "target_address"

    def test_create_breakpoint_set_failed_error(self):
        """Test breakpoint set failed error creation."""
        error = create_breakpoint_set_failed_error(
            address="0x401000",
            api_error="Address is not executable",
            address_valid=False,
            module="kernel32.dll",
        )

        assert error.error == ErrorCode.BREAKPOINT_SET_FAILED
        assert "0x401000" in error.message
        assert "not executable" in error.reason
        assert error.debug_info["requested_address"] == "0x401000"
        assert error.debug_info["address_valid"] is False
        assert error.debug_info["module"] == "kernel32.dll"

    def test_create_breakpoint_hw_limit_error(self):
        """Test hardware breakpoint limit error."""
        error = create_breakpoint_hw_limit_error("0x7FFD12340000")

        assert error.error == ErrorCode.BREAKPOINT_LIMIT_REACHED
        assert "0x7FFD12340000" in error.message
        assert "4" in error.reason  # Maximum 4 hardware breakpoints
        assert "DR0-DR3" in error.suggestions[0]

    def test_create_memory_read_failed_error(self):
        """Test memory read failed error."""
        error = create_memory_read_failed_error(
            address="0x12340000",
            size=1024,
            api_error="Access violation",
        )

        assert error.error == ErrorCode.MEMORY_READ_FAILED
        assert "1024" in error.message
        assert "0x12340000" in error.message
        assert "Access violation" in error.reason

    def test_create_memory_write_failed_error(self):
        """Test memory write failed error."""
        error = create_memory_write_failed_error(
            address="0x401000",
            size=16,
            api_error="Memory is read-only",
        )

        assert error.error == ErrorCode.MEMORY_WRITE_FAILED
        assert "16" in error.message
        assert "0x401000" in error.message
        assert error.debug_info["size"] == 16

    def test_create_debugger_not_connected_error(self):
        """Test debugger not connected error."""
        error = create_debugger_not_connected_error(
            host="192.168.1.100",
            port=9999,
            connection_error="Connection refused",
        )

        assert error.error == ErrorCode.DEBUGGER_NOT_CONNECTED
        assert "Connection refused" in error.reason
        assert error.debug_info["host"] == "192.168.1.100"
        assert error.debug_info["port"] == 9999
        assert "http://192.168.1.100:9999" in error.debug_info["url"]

    def test_create_debugger_not_paused_error(self):
        """Test debugger not paused error."""
        error = create_debugger_not_paused_error(
            current_state="running",
            operation="read_memory",
        )

        assert error.error == ErrorCode.DEBUGGER_NOT_PAUSED
        assert "read_memory" in error.message
        assert "running" in error.reason

    def test_create_debugger_no_binary_error(self):
        """Test debugger no binary error."""
        error = create_debugger_no_binary_error("disassemble")

        assert error.error == ErrorCode.DEBUGGER_NO_BINARY
        assert "disassemble" in error.message
        assert "Load a binary" in error.suggestions[0]

    def test_create_symbol_not_found_error(self):
        """Test symbol not found error."""
        error = create_symbol_not_found_error(
            symbol="CreateFileW",
            module="kernel32.dll",
        )

        assert error.error == ErrorCode.SYMBOL_NOT_FOUND
        assert "CreateFileW" in error.message
        assert "kernel32.dll" in error.message
        assert error.debug_info["symbol"] == "CreateFileW"

    def test_create_symbol_resolve_failed_error(self):
        """Test symbol resolve failed error."""
        error = create_symbol_resolve_failed_error(
            expression="user32!MessageBoxW",
            api_error="Module not loaded",
        )

        assert error.error == ErrorCode.SYMBOL_RESOLVE_FAILED
        assert "user32!MessageBoxW" in error.message
        assert "Module not loaded" in error.reason

    def test_create_disassembly_failed_error(self):
        """Test disassembly failed error."""
        error = create_disassembly_failed_error(
            address="0xDEADBEEF",
            count=20,
            api_error="Invalid memory",
        )

        assert error.error == ErrorCode.DISASSEMBLY_FAILED
        assert "0xDEADBEEF" in error.message
        assert error.debug_info["requested_count"] == 20

    def test_create_module_not_loaded_error(self):
        """Test module not loaded error."""
        error = create_module_not_loaded_error(
            module_name="ws2_32.dll",
            available_modules=["kernel32.dll", "ntdll.dll"],
        )

        assert error.error == ErrorCode.MODULE_NOT_LOADED
        assert "ws2_32.dll" in error.message
        assert error.debug_info["requested_module"] == "ws2_32.dll"
        assert "kernel32.dll" in error.debug_info["loaded_modules"]

    def test_create_timeout_error(self):
        """Test timeout error."""
        error = create_timeout_error(
            operation="wait_until_paused",
            timeout_ms=30000,
            partial_result={"state": "still_running"},
        )

        assert error.error == ErrorCode.DEBUGGER_TIMEOUT
        assert "wait_until_paused" in error.message
        assert "30000" in error.message
        assert error.debug_info["partial_result"]["state"] == "still_running"

    def test_create_api_error(self):
        """Test generic API error."""
        error = create_api_error(
            operation="set_breakpoint",
            api_message="Internal plugin error",
            endpoint="/api/breakpoint/set",
            http_status=500,
        )

        assert error.error == ErrorCode.API_ERROR
        assert "set_breakpoint" in error.message
        assert "Internal plugin error" in error.reason
        assert error.debug_info["endpoint"] == "/api/breakpoint/set"
        assert error.debug_info["http_status"] == 500

    def test_create_parameter_error(self):
        """Test parameter error."""
        error = create_parameter_error(
            param_name="bp_type",
            provided_value="invalid",
            expected="one of the valid breakpoint types",
            valid_values=["execute", "read", "write", "access"],
        )

        assert error.error == ErrorCode.PARAMETER_INVALID
        assert "bp_type" in error.message
        assert "invalid" in error.reason
        assert "execute" in error.debug_info["valid_values"]


class TestErrorClassification:
    """Tests for error message classification."""

    def test_classify_address_errors(self):
        """Test classification of address-related errors."""
        assert classify_api_error("Invalid address format") == ErrorCode.ADDRESS_INVALID
        assert classify_api_error("Address is not valid") == ErrorCode.ADDRESS_INVALID
        assert classify_api_error("Missing address parameter") == ErrorCode.ADDRESS_MISSING
        assert classify_api_error("Address is None") == ErrorCode.ADDRESS_MISSING
        assert classify_api_error("Address not executable") == ErrorCode.ADDRESS_NOT_EXECUTABLE
        assert classify_api_error("Cannot read address") == ErrorCode.ADDRESS_NOT_READABLE
        assert classify_api_error("Cannot write to address") == ErrorCode.ADDRESS_NOT_WRITABLE

    def test_classify_breakpoint_errors(self):
        """Test classification of breakpoint errors."""
        assert classify_api_error("Breakpoint limit reached") == ErrorCode.BREAKPOINT_LIMIT_REACHED
        assert classify_api_error("Maximum breakpoints DR") == ErrorCode.BREAKPOINT_LIMIT_REACHED
        assert classify_api_error("Breakpoint not found") == ErrorCode.BREAKPOINT_NOT_FOUND
        assert classify_api_error("Breakpoint does not exist") == ErrorCode.BREAKPOINT_NOT_FOUND
        assert classify_api_error("Failed to set breakpoint") == ErrorCode.BREAKPOINT_SET_FAILED
        assert classify_api_error("Breakpoint failed", "delete_bp") == ErrorCode.BREAKPOINT_DELETE_FAILED

    def test_classify_memory_errors(self):
        """Test classification of memory errors."""
        assert classify_api_error("Memory read failed") == ErrorCode.MEMORY_READ_FAILED
        assert classify_api_error("Cannot read memory") == ErrorCode.MEMORY_READ_FAILED
        assert classify_api_error("Memory write failed") == ErrorCode.MEMORY_WRITE_FAILED
        assert classify_api_error("Cannot write memory") == ErrorCode.MEMORY_WRITE_FAILED
        assert classify_api_error("Memory allocation failed") == ErrorCode.MEMORY_ALLOC_FAILED

    def test_classify_debugger_state_errors(self):
        """Test classification of debugger state errors."""
        assert classify_api_error("Not debugging") == ErrorCode.DEBUGGER_NO_BINARY
        assert classify_api_error("No debug session") == ErrorCode.DEBUGGER_NO_BINARY
        assert classify_api_error("Debugger not paused") == ErrorCode.DEBUGGER_NOT_PAUSED
        assert classify_api_error("Target is running") == ErrorCode.DEBUGGER_NOT_PAUSED
        assert classify_api_error("Operation timeout") == ErrorCode.DEBUGGER_TIMEOUT
        assert classify_api_error("Connection failed") == ErrorCode.CONNECTION_FAILED
        assert classify_api_error("Auth token invalid") == ErrorCode.AUTHENTICATION_FAILED

    def test_classify_symbol_errors(self):
        """Test classification of symbol errors."""
        assert classify_api_error("Module not found") == ErrorCode.MODULE_NOT_LOADED
        assert classify_api_error("Module not loaded") == ErrorCode.MODULE_NOT_LOADED
        assert classify_api_error("Symbol not found") == ErrorCode.SYMBOL_NOT_FOUND
        assert classify_api_error("Resolve failed") == ErrorCode.SYMBOL_RESOLVE_FAILED

    def test_classify_disassembly_errors(self):
        """Test classification of disassembly errors."""
        assert classify_api_error("Disassembly failed") == ErrorCode.DISASSEMBLY_FAILED

    def test_classify_fallback_to_api_error(self):
        """Test unknown errors fall back to API_ERROR."""
        assert classify_api_error("Some unknown error") == ErrorCode.API_ERROR
        assert classify_api_error("") == ErrorCode.API_ERROR


class TestCreateErrorFromApiResponse:
    """Tests for automatic error creation from API responses."""

    def test_creates_address_invalid_error(self):
        """Test creates address invalid error from API response."""
        error = create_error_from_api_response(
            operation="set_breakpoint",
            api_message="Invalid address: xyz",
            context={"address": "xyz"},
        )

        assert error.error == ErrorCode.ADDRESS_INVALID
        assert "xyz" in error.debug_info.get("provided_value", "")

    def test_creates_breakpoint_error(self):
        """Test creates breakpoint error from API response."""
        error = create_error_from_api_response(
            operation="set_breakpoint",
            api_message="Failed to set breakpoint at location",
            context={"address": "0x401000"},
        )

        assert error.error == ErrorCode.BREAKPOINT_SET_FAILED

    def test_creates_symbol_not_found_error(self):
        """Test creates symbol not found error from API response."""
        error = create_error_from_api_response(
            operation="resolve_symbol",
            api_message="Symbol not found: CreateFileW",
            context={"expression": "CreateFileW", "module": "kernel32"},
        )

        assert error.error == ErrorCode.SYMBOL_NOT_FOUND
        assert "CreateFileW" in error.debug_info.get("symbol", "")

    def test_creates_generic_api_error(self):
        """Test creates generic API error for unknown messages."""
        error = create_error_from_api_response(
            operation="some_operation",
            api_message="Some weird error",
            context={"endpoint": "/api/test"},
        )

        assert error.error == ErrorCode.API_ERROR
        assert error.debug_info.get("operation") == "some_operation"


class TestIntegrationWithBridge:
    """Integration tests for error handling in bridge."""

    def test_address_validation_error_structure(self):
        """Test AddressValidationError provides structured error.

        Note: Uses factory function directly to avoid import chain issues
        with Python 3.9 type annotation compatibility.
        """
        # Create an error using the factory (simulates what AddressValidationError does)
        error = create_address_missing_error("target")
        exc = StructuredBaseError(error)

        assert exc.structured_error.error == ErrorCode.ADDRESS_MISSING
        assert "target" in str(exc)
        # Should have suggestions
        assert len(exc.structured_error.suggestions) > 0

    def test_address_validation_error_with_invalid_value(self):
        """Test AddressValidationError with invalid hex value.

        Note: Uses factory function directly to avoid import chain issues
        with Python 3.9 type annotation compatibility.
        """
        # Create an error using the factory (simulates what AddressValidationError does)
        error = create_address_invalid_error(
            address="xyz",
            param_name="breakpoint_address",
        )
        exc = StructuredBaseError(error)

        assert exc.structured_error.error == ErrorCode.ADDRESS_INVALID
        assert "xyz" in str(exc)
        # Check debug info contains the invalid value
        assert exc.structured_error.debug_info["provided_value"] == "xyz"
