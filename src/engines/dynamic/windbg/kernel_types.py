"""
Kernel object data classes for WinDbg integration.

Typed representations of Windows kernel structures used in driver analysis,
IOCTL decoding, pool allocation tracking, crash dump analysis, and IRP inspection.
"""

from dataclasses import dataclass, field
from enum import Enum


class WinDbgMode(Enum):
    """WinDbg operating mode."""

    USER_MODE = "user_mode"
    KERNEL_MODE = "kernel_mode"
    DUMP_ANALYSIS = "dump_analysis"


@dataclass
class DriverObject:
    """Windows DRIVER_OBJECT kernel structure."""

    name: str
    address: str
    device_objects: list[str] = field(default_factory=list)
    dispatch_table: dict[str, str] = field(default_factory=dict)
    driver_start: str | None = None
    driver_size: int | None = None
    driver_extension: str | None = None


@dataclass
class DeviceObject:
    """Windows DEVICE_OBJECT kernel structure."""

    address: str
    driver_object: str
    device_type: int
    device_name: str | None = None
    attached_to: str | None = None
    flags: int = 0


@dataclass
class IOCTLCode:
    """Decoded Windows I/O Control Code (IOCTL).

    IOCTL bit layout (32-bit):
        [31:16] DeviceType  [15:14] Access  [13:2] Function  [1:0] Method
    """

    raw_code: int
    device_type: int
    function_code: int
    method: int
    access: int
    risk_level: str = "unknown"

    @staticmethod
    def decode(raw_code: int) -> "IOCTLCode":
        """Decompose a raw 32-bit IOCTL code into its bit-field components.

        Args:
            raw_code: Raw 32-bit IOCTL control code.

        Returns:
            IOCTLCode with all fields populated including risk assessment.
        """
        device_type = (raw_code >> 16) & 0xFFFF
        access = (raw_code >> 14) & 0x3
        function_code = (raw_code >> 2) & 0xFFF
        method = raw_code & 0x3

        # METHOD_NEITHER (3) allows raw user-mode pointers into kernel,
        # METHOD_IN_DIRECT/METHOD_OUT_DIRECT (1,2) use MDLs but still need review.
        risk_level = _assess_ioctl_risk(method, function_code)

        return IOCTLCode(
            raw_code=raw_code,
            device_type=device_type,
            function_code=function_code,
            method=method,
            access=access,
            risk_level=risk_level,
        )


@dataclass
class PoolAllocation:
    """Windows kernel pool allocation record."""

    address: str
    tag: str
    size: int
    pool_type: str
    owning_component: str | None = None


@dataclass
class CrashAnalysis:
    """Windows BSOD / bugcheck crash analysis result."""

    bugcheck_code: int
    bugcheck_name: str
    arguments: list[str] = field(default_factory=list)
    faulting_module: str | None = None
    faulting_address: str | None = None
    stack_trace: list[str] = field(default_factory=list)
    probable_cause: str | None = None


@dataclass
class IRP:
    """Windows I/O Request Packet."""

    address: str
    major_function: str
    minor_function: str | None = None
    io_stack_locations: list[dict[str, str]] = field(default_factory=list)
    thread: str | None = None
    status: str | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Transfer method constants from the Windows DDK
_METHOD_BUFFERED = 0
_METHOD_IN_DIRECT = 1
_METHOD_OUT_DIRECT = 2
_METHOD_NEITHER = 3

# Custom function codes >= 0x800 are vendor-defined and may lack hardening
_CUSTOM_FUNCTION_THRESHOLD = 0x800


def _assess_ioctl_risk(method: int, function_code: int) -> str:
    """Return a risk-level string for an IOCTL based on its transfer method.

    Args:
        method: Transfer method (0-3).
        function_code: 12-bit function code from the IOCTL.

    Returns:
        One of "high", "medium", or "low".
    """
    if method == _METHOD_NEITHER:
        return "high"
    if method in (_METHOD_IN_DIRECT, _METHOD_OUT_DIRECT):
        return "medium" if function_code >= _CUSTOM_FUNCTION_THRESHOLD else "low"
    # METHOD_BUFFERED with a custom function code still warrants attention
    if function_code >= _CUSTOM_FUNCTION_THRESHOLD:
        return "medium"
    return "low"
