"""
WinDbg kernel debugging integration.

Provides kernel-mode dynamic analysis capabilities through WinDbg via the Pybag library.

Components:
- kernel_types.py: Data classes for kernel objects (drivers, devices, IRPs, etc.)
- output_parser.py: Parser for WinDbg text command output
- error_logger.py: Error logging and persistence
- bridge.py: WinDbg bridge implementing the Debugger ABC

Architecture:
    MCP Server (Python) <--Pybag--> DbgEng COM API <---> WinDbg/KD
"""

from src.engines.dynamic.windbg.error_logger import (
    ErrorContext,
    ErrorRecord,
    WinDbgErrorLogger,
)
from src.engines.dynamic.windbg.kernel_types import (
    IRP,
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
    WinDbgMode,
)

__all__ = [
    "CrashAnalysis",
    "DeviceObject",
    "DriverObject",
    "ErrorContext",
    "ErrorRecord",
    "IOCTLCode",
    "IRP",
    "PoolAllocation",
    "WinDbgErrorLogger",
    "WinDbgMode",
]
