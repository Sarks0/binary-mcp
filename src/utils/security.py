"""Security utilities for input validation and sanitization."""

import re
from pathlib import Path
from typing import List, Optional


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
    allowed_dirs: Optional[List[Path]] = None,
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
    # Convert to Path object and resolve to absolute path
    try:
        path = Path(binary_path).resolve()
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

    # Check for symlinks pointing outside allowed directories
    if path.is_symlink() and allowed_dirs:
        try:
            real_path = path.readlink().resolve()
            is_symlink_allowed = False

            for allowed_dir in allowed_dirs:
                resolved_allowed = allowed_dir.resolve()
                if real_path.is_relative_to(resolved_allowed):
                    is_symlink_allowed = True
                    break

            if not is_symlink_allowed:
                raise PathTraversalError(
                    f"Symlink target outside allowed directories: {binary_path}"
                )
        except (OSError, RuntimeError) as e:
            raise PathTraversalError(f"Invalid symlink: {e}")

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


def safe_regex_compile(pattern: str, max_length: int = 100):
    """
    Safely compile regex pattern with complexity limits.

    Args:
        pattern: Regex pattern to compile
        max_length: Maximum pattern length

    Returns:
        Compiled regex pattern

    Raises:
        ValueError: If pattern is too complex or dangerous
    """
    import re

    # Validate pattern length
    if len(pattern) > max_length:
        raise ValueError(f"Regex pattern too long (max {max_length} characters)")

    # Check for potentially dangerous constructs that can cause ReDoS
    dangerous_patterns = [
        r'(.+)+',     # Nested quantifiers
        r'(.*)*',     # Nested quantifiers
        r'(.+)*',     # Nested quantifiers
        r'(.*)+',     # Nested quantifiers
        r'(.*)(.*)' , # Multiple greedy quantifiers
    ]

    for danger in dangerous_patterns:
        if danger in pattern:
            raise ValueError(
                f"Potentially dangerous regex pattern detected: {danger}"
            )

    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"Invalid regex pattern: {e}")
