"""
High-level WinDbg command wrappers for MCP tools.

Provides convenient kernel debugging workflows built on top of WinDbgBridge.
"""

import logging
from pathlib import Path
from typing import Any

from .bridge import WinDbgBridge

logger = logging.getLogger(__name__)

# IRP major function names for the standard 28-slot dispatch table
_IRP_MAJOR_FUNCTIONS = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
]


class WinDbgCommands:
    """High-level command interface for WinDbg kernel debugging."""

    def __init__(self, bridge: WinDbgBridge | None = None):
        """Initialize commands interface.

        Args:
            bridge: WinDbgBridge instance (creates new if None).
        """
        self.bridge = bridge or WinDbgBridge()

    def ensure_connected(self) -> None:
        """Ensure the bridge has an active debug session."""
        if self.bridge.get_state().value == "not_loaded":
            self.bridge.connect()

    def get_status_summary(self) -> str:
        """Return a formatted summary of the current debug session.

        Returns:
            Human-readable status string.
        """
        state = self.bridge.get_state()
        mode = self.bridge._mode

        lines = [
            f"State: {state.value}",
            f"Mode: {mode.value}",
        ]
        if self.bridge._is_local_kernel:
            if getattr(self.bridge, "_local_kernel_limited", False):
                lines.append("Connection: local kernel (limited - bcdedit not enabled)")
                lines.append(
                    "Warning: Data access limited. For full access run "
                    "'bcdedit -debug on', reboot, and run as Administrator."
                )
            else:
                lines.append("Connection: local kernel (inspection mode)")
                lines.append(
                    "Note: Memory, registers, modules, and symbols are available. "
                    "Execution control (breakpoints, stepping) requires a remote KDNET connection."
                )
        if self.bridge._binary_path:
            lines.append(f"Target: {self.bridge._binary_path}")

        try:
            loc = self.bridge.get_current_location()
            lines.append(f"Address: 0x{loc.get('address', '?')}")
            if loc.get("instruction"):
                lines.append(f"Instruction: {loc['instruction']}")
        except Exception:
            pass

        return "\n".join(lines)

    def dump_registers(self) -> str:
        """Return a formatted register dump.

        Returns:
            Formatted register string.
        """
        self.ensure_connected()
        registers = self.bridge.get_registers()

        lines = ["Registers:", "-" * 40]
        general = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip"]
        extended = [f"r{i}" for i in range(8, 16)]

        for reg in general:
            if reg in registers:
                lines.append(f"{reg.upper():4} = 0x{registers[reg]}")
        lines.append("")
        for reg in extended:
            if reg in registers:
                lines.append(f"{reg.upper():4} = 0x{registers[reg]}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Driver analysis workflows
    # ------------------------------------------------------------------

    def analyze_driver(self, driver_name: str) -> dict[str, Any]:
        """Full driver analysis: driver object, dispatch table, devices, IOCTLs.

        Args:
            driver_name: Driver name (e.g. '\\Driver\\ACPI' or just 'ACPI').

        Returns:
            Dictionary with driver_object, devices, dispatch_table, and ioctl_info.
        """
        self.ensure_connected()
        driver = self.bridge.get_driver_object(driver_name)

        # Fetch each device object
        devices = []
        for dev_addr in driver.device_objects:
            try:
                dev = self.bridge.get_device_object(dev_addr)
                devices.append({
                    "address": dev.address,
                    "device_type": dev.device_type,
                    "device_name": dev.device_name,
                    "flags": dev.flags,
                    "attached_to": dev.attached_to,
                })
            except Exception as exc:
                logger.warning("Failed to read device %s: %s", dev_addr, exc)

        # Annotate dispatch table with handler categories
        dispatch = {}
        for irp_name, handler_addr in driver.dispatch_table.items():
            dispatch[irp_name] = {
                "address": handler_addr,
                "is_device_control": irp_name == "IRP_MJ_DEVICE_CONTROL",
            }

        return {
            "driver_name": driver.name,
            "driver_address": driver.address,
            "driver_start": driver.driver_start,
            "driver_size": driver.driver_size,
            "device_count": len(devices),
            "devices": devices,
            "dispatch_table": dispatch,
            "dispatch_handler_count": len(dispatch),
        }

    def find_ioctl_handlers(self, driver_name: str) -> list[dict[str, Any]]:
        """Find and annotate all IOCTL dispatch routines for a driver.

        Args:
            driver_name: Driver name.

        Returns:
            List of dicts describing each IOCTL-related dispatch handler.
        """
        self.ensure_connected()
        driver = self.bridge.get_driver_object(driver_name)

        handlers: list[dict[str, Any]] = []
        ioctl_related = {
            "IRP_MJ_DEVICE_CONTROL",
            "IRP_MJ_INTERNAL_DEVICE_CONTROL",
            "IRP_MJ_FILE_SYSTEM_CONTROL",
        }

        for irp_name, addr in driver.dispatch_table.items():
            if irp_name in ioctl_related:
                handlers.append({
                    "irp_function": irp_name,
                    "handler_address": addr,
                    "driver": driver.name,
                })

        return handlers

    def get_driver_vulnerability_surface(
        self, driver_name: str
    ) -> dict[str, Any]:
        """Automated attack surface analysis for a kernel driver.

        Checks IOCTL handlers, METHOD_NEITHER risk, accessible device objects,
        and pool usage patterns.

        Args:
            driver_name: Driver name.

        Returns:
            Dictionary with vulnerability surface assessment.
        """
        self.ensure_connected()
        analysis = self.analyze_driver(driver_name)

        # Classify dispatch handlers
        handlers = analysis["dispatch_table"]
        ioctl_handler = handlers.get("IRP_MJ_DEVICE_CONTROL")

        # Detect missing dispatch routines (common sign of pass-through)
        covered = set(handlers.keys())
        uncovered = [fn for fn in _IRP_MAJOR_FUNCTIONS if fn not in covered]

        # Check if the driver device is accessible from user mode
        accessible_devices = []
        for dev in analysis["devices"]:
            if dev.get("device_name"):
                accessible_devices.append(dev["device_name"])

        findings: list[str] = []
        risk = "low"

        if ioctl_handler:
            findings.append(
                f"IRP_MJ_DEVICE_CONTROL handler at {ioctl_handler['address']}"
            )
            risk = "medium"

        if accessible_devices:
            findings.append(
                f"User-accessible device objects: {', '.join(accessible_devices)}"
            )
            risk = "medium"

        if len(uncovered) > 20:
            findings.append(
                f"{len(uncovered)} of 28 IRP handlers not implemented "
                "(likely pass-through to default)"
            )

        return {
            "driver_name": analysis["driver_name"],
            "overall_risk": risk,
            "ioctl_handler": ioctl_handler,
            "accessible_devices": accessible_devices,
            "uncovered_irp_functions": uncovered,
            "findings": findings,
            "device_count": analysis["device_count"],
            "dispatch_handler_count": analysis["dispatch_handler_count"],
        }

    # ------------------------------------------------------------------
    # Crash dump workflows
    # ------------------------------------------------------------------

    def analyze_crash_dump(self, dump_path: str) -> dict[str, Any]:
        """Full crash dump analysis with recommendations.

        Args:
            dump_path: Path to the .dmp file.

        Returns:
            Dictionary with bugcheck info, stack, faulting module, and
            recommendations.
        """
        path = Path(dump_path)
        self.bridge.open_dump(path)

        crash = self.bridge.analyze_crash()

        recommendations: list[str] = []
        if crash.faulting_module:
            recommendations.append(
                f"Investigate module '{crash.faulting_module}' "
                f"for the root cause"
            )
        if crash.bugcheck_code == 0x50:
            recommendations.append(
                "PAGE_FAULT_IN_NONPAGED_AREA: Check for invalid "
                "pointer dereference or use-after-free"
            )
        elif crash.bugcheck_code == 0xD1:
            recommendations.append(
                "DRIVER_IRQL_NOT_LESS_OR_EQUAL: Driver accessing "
                "paged memory at elevated IRQL"
            )
        elif crash.bugcheck_code == 0x7E:
            recommendations.append(
                "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: Unhandled "
                "exception in a system thread"
            )

        return {
            "dump_path": str(path),
            "bugcheck_code": f"0x{crash.bugcheck_code:X}",
            "bugcheck_name": crash.bugcheck_name,
            "arguments": crash.arguments,
            "faulting_module": crash.faulting_module,
            "faulting_address": crash.faulting_address,
            "stack_trace": crash.stack_trace,
            "probable_cause": crash.probable_cause,
            "recommendations": recommendations,
        }

    # ------------------------------------------------------------------
    # Cross-reference helpers
    # ------------------------------------------------------------------

    def compare_dispatch_tables(
        self, driver1: str, driver2: str
    ) -> dict[str, Any]:
        """Compare dispatch tables of two drivers to detect hooks.

        Useful for identifying rootkit-style dispatch table modifications by
        comparing a suspect driver against a known-good baseline.

        Args:
            driver1: First driver name (baseline).
            driver2: Second driver name (suspect).

        Returns:
            Dictionary with matched, added, removed, and changed entries.
        """
        self.ensure_connected()
        drv1 = self.bridge.get_driver_object(driver1)
        drv2 = self.bridge.get_driver_object(driver2)

        table1 = drv1.dispatch_table
        table2 = drv2.dispatch_table

        all_keys = set(table1) | set(table2)
        matched: list[str] = []
        changed: list[dict[str, str]] = []
        only_in_first: list[str] = []
        only_in_second: list[str] = []

        for key in sorted(all_keys):
            in1 = key in table1
            in2 = key in table2
            if in1 and in2:
                if table1[key] == table2[key]:
                    matched.append(key)
                else:
                    changed.append({
                        "irp_function": key,
                        "driver1_address": table1[key],
                        "driver2_address": table2[key],
                    })
            elif in1:
                only_in_first.append(key)
            else:
                only_in_second.append(key)

        return {
            "driver1": drv1.name,
            "driver2": drv2.name,
            "matched_count": len(matched),
            "changed": changed,
            "only_in_driver1": only_in_first,
            "only_in_driver2": only_in_second,
            "potential_hooks": len(changed),
        }
