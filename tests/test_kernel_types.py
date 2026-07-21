"""
Tests for WinDbg kernel type data classes.

Verifies IOCTL decoding, risk classification, and dataclass construction.
"""


from src.engines.dynamic.windbg.kernel_types import (
    IRP,
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
    WinDbgMode,
)


class TestWinDbgMode:
    """Tests for WinDbgMode enum."""

    def test_user_mode(self):
        assert WinDbgMode.USER_MODE.value == "user_mode"

    def test_kernel_mode(self):
        assert WinDbgMode.KERNEL_MODE.value == "kernel_mode"

    def test_dump_analysis(self):
        assert WinDbgMode.DUMP_ANALYSIS.value == "dump_analysis"


class TestIOCTLCodeDecode:
    """Tests for IOCTLCode.decode() bit-field decomposition."""

    def test_file_device_unknown_method_neither(self):
        """FILE_DEVICE_UNKNOWN (0x22), METHOD_NEITHER (3), func 0x803."""
        code = IOCTLCode.decode(0x0022200F)
        assert code.device_type == 0x22
        assert code.method == 3
        assert code.function_code == 0x803
        assert code.access == 0
        assert code.raw_code == 0x0022200F

    def test_method_buffered_standard_func(self):
        """METHOD_BUFFERED (0) with standard function code = low risk."""
        code = IOCTLCode.decode(0x00220004)
        assert code.method == 0
        assert code.function_code == 1
        assert code.risk_level == "low"

    def test_method_buffered_custom_func(self):
        """METHOD_BUFFERED (0) with custom function (>= 0x800) = medium risk."""
        code = IOCTLCode.decode(0x00222000)
        assert code.method == 0
        assert code.function_code == 0x800
        assert code.risk_level == "medium"

    def test_method_neither_high_risk(self):
        """METHOD_NEITHER (3) always yields high risk."""
        code = IOCTLCode.decode(0x00220003)
        assert code.method == 3
        assert code.risk_level == "high"

    def test_method_in_direct_standard(self):
        """METHOD_IN_DIRECT (1) with standard function = low risk."""
        code = IOCTLCode.decode(0x00220005)
        assert code.method == 1
        assert code.risk_level == "low"

    def test_method_in_direct_custom_func(self):
        """METHOD_IN_DIRECT (1) with custom function = medium risk."""
        code = IOCTLCode.decode(0x00222001)
        assert code.method == 1
        assert code.function_code == 0x800
        assert code.risk_level == "medium"

    def test_method_out_direct_custom_func(self):
        """METHOD_OUT_DIRECT (2) with custom function = medium risk."""
        code = IOCTLCode.decode(0x00222002)
        assert code.method == 2
        assert code.risk_level == "medium"

    def test_zero_ioctl(self):
        """Zero IOCTL should decode cleanly."""
        code = IOCTLCode.decode(0x00000000)
        assert code.device_type == 0
        assert code.function_code == 0
        assert code.method == 0
        assert code.access == 0
        assert code.risk_level == "low"

    def test_max_ioctl(self):
        """Maximum 32-bit IOCTL should decode all fields."""
        code = IOCTLCode.decode(0xFFFFFFFF)
        assert code.device_type == 0xFFFF
        assert code.access == 3
        assert code.function_code == 0xFFF
        assert code.method == 3
        assert code.risk_level == "high"

    def test_access_field_extraction(self):
        """Verify access bits [15:14] are extracted correctly."""
        # FILE_READ_ACCESS (1) in bits 14-15 => 0x4000
        code = IOCTLCode.decode(0x00224000)
        assert code.access == 1

        # FILE_WRITE_ACCESS (2) => 0x8000
        code = IOCTLCode.decode(0x00228000)
        assert code.access == 2

        # READ|WRITE (3) => 0xC000
        code = IOCTLCode.decode(0x0022C000)
        assert code.access == 3

    def test_roundtrip(self):
        """Reconstructed raw code should match original."""
        original = 0x0022E00B
        code = IOCTLCode.decode(original)
        reconstructed = (
            (code.device_type << 16)
            | (code.access << 14)
            | (code.function_code << 2)
            | code.method
        )
        assert reconstructed == original


class TestDriverObject:
    """Tests for DriverObject dataclass."""

    def test_required_fields(self):
        driver = DriverObject(name="\\Driver\\Test", address="fffff800")
        assert driver.name == "\\Driver\\Test"
        assert driver.address == "fffff800"

    def test_default_fields(self):
        driver = DriverObject(name="test", address="0")
        assert driver.device_objects == []
        assert driver.dispatch_table == {}
        assert driver.driver_start is None
        assert driver.driver_size is None
        assert driver.driver_extension is None

    def test_full_construction(self):
        driver = DriverObject(
            name="\\Driver\\ACPI",
            address="fffff80012340000",
            device_objects=["fffff80012350000", "fffff80012360000"],
            dispatch_table={"IRP_MJ_CREATE": "fffff80012370000"},
            driver_start="fffff80012340000",
            driver_size=0x10000,
            driver_extension="fffff80012380000",
        )
        assert len(driver.device_objects) == 2
        assert driver.driver_size == 0x10000


class TestDeviceObject:
    """Tests for DeviceObject dataclass."""

    def test_required_fields(self):
        dev = DeviceObject(address="fffff800", driver_object="\\Driver\\Test", device_type=0x22)
        assert dev.device_type == 0x22

    def test_defaults(self):
        dev = DeviceObject(address="0", driver_object="x", device_type=0)
        assert dev.device_name is None
        assert dev.attached_to is None
        assert dev.flags == 0


class TestPoolAllocation:
    """Tests for PoolAllocation dataclass."""

    def test_construction(self):
        pool = PoolAllocation(
            address="fffff800", tag="Ntfs", size=256, pool_type="NonPaged"
        )
        assert pool.tag == "Ntfs"
        assert pool.size == 256
        assert pool.owning_component is None


class TestCrashAnalysis:
    """Tests for CrashAnalysis dataclass."""

    def test_minimal(self):
        crash = CrashAnalysis(bugcheck_code=0x50, bugcheck_name="PAGE_FAULT")
        assert crash.bugcheck_code == 0x50
        assert crash.arguments == []
        assert crash.stack_trace == []
        assert crash.probable_cause is None

    def test_full(self):
        crash = CrashAnalysis(
            bugcheck_code=0xD1,
            bugcheck_name="DRIVER_IRQL",
            arguments=["arg1", "arg2", "arg3", "arg4"],
            faulting_module="TestDriver.sys",
            faulting_address="fffff80012340000",
            stack_trace=["frame0", "frame1"],
            probable_cause="TestDriver",
        )
        assert len(crash.arguments) == 4
        assert len(crash.stack_trace) == 2


class TestIRP:
    """Tests for IRP dataclass."""

    def test_minimal(self):
        irp = IRP(address="fffff800", major_function="IRP_MJ_CREATE")
        assert irp.minor_function is None
        assert irp.io_stack_locations == []
        assert irp.thread is None
        assert irp.status is None

    def test_full(self):
        irp = IRP(
            address="fffff800",
            major_function="IRP_MJ_DEVICE_CONTROL",
            minor_function="0",
            io_stack_locations=[{"DeviceObject": "fffff801"}],
            thread="fffff802",
            status="STATUS_SUCCESS",
        )
        assert len(irp.io_stack_locations) == 1
