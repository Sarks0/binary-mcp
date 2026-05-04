"""Security utilities for input validation and sanitization."""

import logging
import re
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base exception for security-related errors."""
    pass


class PathTraversalError(SecurityError):
    """Raised when path traversal attempt is detected."""
    pass


class FileSizeError(SecurityError):
    """Raised when file size exceeds limits."""
    pass


def sanitize_binary_path(
    binary_path: str,
    allowed_dirs: list[Path] | None = None,
    max_size_bytes: int = 500 * 1024 * 1024  # 500MB default
) -> Path:
    """
    Sanitize and validate binary path to prevent path traversal.

    Args:
        binary_path: User-supplied path to binary file
        allowed_dirs: List of allowed base directories (None = allow any)
        max_size_bytes: Maximum allowed file size in bytes

    Returns:
        Validated absolute path

    Raises:
        PathTraversalError: If path is invalid or outside allowed directories
        FileSizeError: If file exceeds size limit
        FileNotFoundError: If file does not exist
        ValueError: If path validation fails
    """
    # Check for symlinks BEFORE resolving (prevent TOCTOU race)
    raw_path = Path(binary_path)

    if raw_path.is_symlink() and allowed_dirs:
        try:
            real_target = raw_path.resolve()
            is_symlink_allowed = False
            for allowed_dir in allowed_dirs:
                resolved_allowed = allowed_dir.resolve()
                if real_target.is_relative_to(resolved_allowed):
                    is_symlink_allowed = True
                    break
            if not is_symlink_allowed:
                raise PathTraversalError(
                    f"Symlink target outside allowed directories: {binary_path}"
                )
        except (OSError, RuntimeError) as e:
            raise PathTraversalError(f"Invalid symlink: {e}")

    # Convert to Path object and resolve to absolute path
    try:
        path = raw_path.resolve()
    except (OSError, RuntimeError) as e:
        raise PathTraversalError(f"Invalid path: {e}")

    # Check if path exists
    if not path.exists():
        raise FileNotFoundError(f"File does not exist: {binary_path}")

    # Must be a file, not directory
    if not path.is_file():
        raise ValueError(f"Path is not a file: {binary_path}")

    # Check if path is within allowed directories
    if allowed_dirs:
        is_allowed = False
        for allowed_dir in allowed_dirs:
            try:
                resolved_allowed = allowed_dir.resolve()
                if path.is_relative_to(resolved_allowed):
                    is_allowed = True
                    break
            except (OSError, RuntimeError, ValueError):
                continue

        if not is_allowed:
            raise PathTraversalError(
                f"Access denied: Path outside allowed directories: {binary_path}"
            )

    # Check file size to prevent DoS
    try:
        file_size = path.stat().st_size
        if file_size > max_size_bytes:
            raise FileSizeError(
                f"File too large: {file_size} bytes (max: {max_size_bytes})"
            )
    except OSError as e:
        raise ValueError(f"Cannot get file size: {e}")

    return path


def validate_hex_address(address: str) -> str:
    """
    Validate hexadecimal memory address.

    Args:
        address: Hexadecimal address string (with or without 0x prefix)

    Returns:
        Validated address string without 0x prefix

    Raises:
        ValueError: If address is invalid
    """
    # Remove 0x prefix if present
    addr = address.lower().replace('0x', '').strip()

    # Must be valid hexadecimal
    if not re.match(r'^[0-9a-f]+$', addr):
        raise ValueError(f"Invalid hexadecimal address: {address}")

    # Length check (16 characters max for 64-bit)
    if len(addr) > 16:
        raise ValueError(
            f"Address too long for 64-bit architecture: {address}"
        )

    # Must not be empty
    if len(addr) == 0:
        raise ValueError("Address cannot be empty")

    return addr


def validate_numeric_range(
    value: int,
    min_val: int,
    max_val: int,
    param_name: str = "value"
) -> int:
    """
    Validate numeric value is within acceptable range.

    Args:
        value: Value to validate
        min_val: Minimum allowed value (inclusive)
        max_val: Maximum allowed value (inclusive)
        param_name: Parameter name for error messages

    Returns:
        Validated value

    Raises:
        TypeError: If value is not an integer
        ValueError: If value is outside range
    """
    if not isinstance(value, int):
        raise TypeError(f"{param_name} must be an integer, got {type(value).__name__}")

    if value < min_val or value > max_val:
        raise ValueError(
            f"{param_name} must be between {min_val} and {max_val}, got {value}"
        )

    return value


def sanitize_output_path(output_path: Path, allowed_dir: Path) -> Path:
    """
    Sanitize output path to prevent directory traversal.

    Args:
        output_path: Requested output path
        allowed_dir: Base directory for outputs

    Returns:
        Validated path within allowed directory

    Raises:
        PathTraversalError: If path is outside allowed directory
        ValueError: If path is invalid
    """
    # Resolve to absolute paths
    try:
        abs_path = output_path.resolve()
        abs_allowed = allowed_dir.resolve()
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Invalid path: {e}")

    # Check if path is within allowed directory
    try:
        if not abs_path.is_relative_to(abs_allowed):
            raise PathTraversalError(
                f"Output path must be within {abs_allowed}"
            )
    except ValueError:
        raise PathTraversalError(
            f"Output path must be within {abs_allowed}"
        )

    # Ensure parent directory exists
    if not abs_path.parent.exists():
        raise ValueError(f"Parent directory does not exist: {abs_path.parent}")

    # Check for symlinks in path components
    for parent in abs_path.parents:
        if parent == abs_allowed:
            break
        if parent.is_symlink():
            raise PathTraversalError(
                "Symlinks not allowed in output path"
            )

    return abs_path


def safe_regex_compile(pattern: str, max_length: int = 100, timeout_ms: int = 1000):
    """
    Safely compile regex pattern with complexity limits.

    Args:
        pattern: Regex pattern to compile
        max_length: Maximum pattern length
        timeout_ms: Timeout for regex operations (informational, used by callers)

    Returns:
        Compiled regex pattern

    Raises:
        ValueError: If pattern is too complex or dangerous
    """
    import re as _re

    # Validate pattern length
    if len(pattern) > max_length:
        raise ValueError(f"Regex pattern too long (max {max_length} characters)")

    # Structural ReDoS detection: check for nested quantifiers
    # This catches patterns like (.+)+, ([a-z]+)+, (a|a)+, (\\w+\\s?)*, etc.
    nested_quantifier_re = _re.compile(
        r'(?:'
        r'\([^)]*[+*][^)]*\)[+*?]'   # Group with quantifier followed by quantifier
        r'|'
        r'\([^)]*\)\{[0-9,]+\}'       # Group followed by {n,m} quantifier
        r'|'
        r'[+*]\)+[+*]'                # Quantifier, close group(s), quantifier
        r')'
    )
    if nested_quantifier_re.search(pattern):
        raise ValueError(
            "Potentially dangerous regex: nested quantifiers detected (ReDoS risk)"
        )

    # Check for excessive alternation within groups (e.g., (a|a|a|a|a|...))
    excessive_alternation_re = _re.compile(r'\([^)]*(?:\|[^)]*){10,}\)')
    if excessive_alternation_re.search(pattern):
        raise ValueError(
            "Potentially dangerous regex: excessive alternation detected (ReDoS risk)"
        )

    # Check for excessive group nesting depth
    depth = 0
    max_depth = 0
    for char in pattern:
        if char == '(':
            depth += 1
            max_depth = max(max_depth, depth)
        elif char == ')':
            depth -= 1
    if max_depth > 5:
        raise ValueError(
            f"Regex nesting too deep ({max_depth} levels, max 5)"
        )

    try:
        return _re.compile(pattern, _re.IGNORECASE)
    except _re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")


def validate_state_id(state_id: str) -> str:
    """
    Validate a debug state ID to prevent path traversal.

    State IDs are generated as hex SHA256 prefixes and must match
    that format strictly.

    Args:
        state_id: State identifier string

    Returns:
        Validated state ID

    Raises:
        ValueError: If state_id format is invalid
    """
    if not state_id or not isinstance(state_id, str):
        raise ValueError("State ID cannot be empty")
    state_id = state_id.strip()
    if not re.match(r'^[a-f0-9]{1,64}$', state_id):
        raise ValueError(
            "Invalid state ID format: must be 1-64 hex characters"
        )
    return state_id


def validate_parameter_pattern(value: str, param_name: str, pattern: str = r'^[a-zA-Z0-9:_.\-]+$', max_length: int = 200) -> str:
    """
    Validate a string parameter against an allowed pattern.

    Args:
        value: Parameter value to validate
        param_name: Parameter name for error messages
        pattern: Regex pattern for allowed characters
        max_length: Maximum allowed length

    Returns:
        Validated parameter string

    Raises:
        ValueError: If parameter is invalid
    """
    if not value or not isinstance(value, str):
        raise ValueError(f"{param_name} cannot be empty")
    value = value.strip()
    if len(value) > max_length:
        raise ValueError(f"{param_name} too long (max {max_length} characters)")
    if not re.match(pattern, value):
        raise ValueError(
            f"Invalid {param_name}: contains disallowed characters"
        )
    return value


def get_allowed_dirs() -> list[Path] | None:
    """
    Get allowed directories from configuration.

    Reads BINARY_MCP_ALLOWED_DIRS environment variable (colon-separated paths).
    Returns None if not configured (allows any directory).

    Returns:
        List of allowed directory Paths, or None if unrestricted
    """
    import os
    dirs_config = os.environ.get("BINARY_MCP_ALLOWED_DIRS", "").strip()
    if not dirs_config:
        return None
    return [Path(d.strip()) for d in dirs_config.split(":") if d.strip()]


class UserFacingError(Exception):
    """
    Exception with separate user-facing and internal error messages.

    Prevents information disclosure by showing safe messages to users
    while logging detailed internal errors.
    """

    def __init__(self, user_message: str, internal_details: str = None):
        """
        Initialize user-facing error.

        Args:
            user_message: Safe message shown to user
            internal_details: Detailed error info logged internally
        """
        super().__init__(user_message)
        self.user_message = user_message
        self.internal_details = internal_details
        self.error_id = str(uuid.uuid4())[:8]

        # Log internal details with error ID for tracking
        if internal_details:
            logger.error(f"Error {self.error_id}: {internal_details}")

    def __str__(self):
        return f"{self.user_message}\nReference ID: {self.error_id}"


def safe_error_message(
    user_message: str,
    internal_details: Exception = None,
    error_id: str = None
) -> str:
    """
    Create a safe error message for users without exposing internals.

    Args:
        user_message: User-friendly error description
        internal_details: Exception or details to log internally
        error_id: Optional error ID (generated if not provided)

    Returns:
        Safe error message with reference ID
    """
    if error_id is None:
        error_id = str(uuid.uuid4())[:8]

    # Log internal details
    if internal_details:
        logger.error(f"Error {error_id}: {internal_details}", exc_info=True)

    # If the exception carries a curated diagnostic (e.g. GhidraAnalysisError
    # with extracted stderr context), surface it. The diagnostic is already
    # filtered to actionable lines from a trusted subprocess -- it tells the
    # user *why* the call failed (poisoned OSGi cache, JDK mismatch, OOM,
    # missing file, ...) rather than hiding behind a reference ID.
    diagnostic = getattr(internal_details, "diagnostic", None) if internal_details else None
    if diagnostic:
        return (
            f"Error: {user_message}\n"
            f"Reference ID: {error_id}\n\n"
            f"Diagnostic:\n{diagnostic}"
        )

    return f"Error: {user_message}\nReference ID: {error_id}\nPlease contact support with this reference ID."
