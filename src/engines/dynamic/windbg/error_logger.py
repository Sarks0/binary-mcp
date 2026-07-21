"""
WinDbgErrorLogger - Error logging and tracking for WinDbg operations.

Thin subclass of BaseErrorLogger tailored for WinDbg's DbgEng/Pybag architecture.
"""

from src.engines.dynamic.base_error_logger import (
    BaseErrorLogger,
    ErrorContext,
    ErrorRecord,
)

__all__ = ["ErrorContext", "ErrorRecord", "WinDbgErrorLogger"]


class WinDbgErrorLogger(BaseErrorLogger):
    """
    Error logger for WinDbg operations.

    Stores errors in `~/.ghidra_mcp_cache/windbg_errors/` with:
    - Individual JSON files per error
    - Manifest file for quick browsing
    - Statistics for error analysis
    - Automatic cleanup of old errors
    """

    _error_dir_name = "windbg_errors"
    _error_id_prefix = "windbg_"
    _export_log_header = "WINDBG ERROR LOG"
