"""
X64DbgErrorLogger - Error logging and tracking for x64dbg operations.

Thin subclass of BaseErrorLogger tailored for x64dbg's HTTP + Plugin architecture.
"""

from src.engines.dynamic.base_error_logger import (
    BaseErrorLogger,
    ErrorContext,
    ErrorRecord,
)

__all__ = ["ErrorContext", "ErrorRecord", "X64DbgErrorLogger"]


class X64DbgErrorLogger(BaseErrorLogger):
    """
    Error logger for x64dbg operations.

    Stores errors in `~/.ghidra_mcp_cache/x64dbg_errors/` with:
    - Individual JSON files per error
    - Manifest file for quick browsing
    - Statistics for error analysis
    - Automatic cleanup of old errors
    """

    _error_dir_name = "x64dbg_errors"
    _error_id_prefix = "x64_"
    _export_log_header = "X64DBG ERROR LOG"
