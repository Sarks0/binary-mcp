"""
Tests for WinDbg output parser.

Uses hardcoded WinDbg command output as fixtures; no WinDbg installation required.
"""


from src.engines.dynamic.windbg.kernel_types import (
    CrashAnalysis,
    DeviceObject,
    DriverObject,
    IOCTLCode,
    PoolAllocation,
)
from src.engines.dynamic.windbg.output_parser import WinDbgOutputParser

# ---------------------------------------------------------------------------
# Fixtures: representative WinDbg text output
# ---------------------------------------------------------------------------

REGISTER_OUTPUT = (
    "rax=0000000000000001 rbx=00007ff6a1b20000 rcx=0000000000000000\n"
    "rdx=0000000000000001 rsi=0000000000000000 rdi=00007ff6a1b20000\n"
    "rip=fffff80012340000 rsp=fffff80012350000 rbp=fffff80012360000\n"
    "efl=00000246"
)

MODULE_OUTPUT = (
    "fffff800`12340000 fffff800`12350000   nt         (pdb symbols)\n"
    "00007ff6`a1b20000 00007ff6`a1b40000   notepad    (deferred)\n"
    "fffff800`22340000 fffff800`22350000   TestDriver (no symbols)\n"
)

STACK_OUTPUT = (
    "# Child-SP          RetAddr           Call Site\n"
    "00 fffff800`1234abcd fffff800`5678efab nt!KeBugCheckEx+0x0\n"
    "01 fffff800`1234abd0 fffff800`5678efcd TestDriver!DispatchDeviceControl+0x42\n"
    "02 fffff800`1234abe0 fffff800`5678efef nt!IofCallDriver+0x55\n"
)

DISASSEMBLY_OUTPUT = (
    "nt!KeBugCheckEx:\n"
    "fffff800`12340000 4883ec28        sub     rsp,28h\n"
    "fffff800`12340004 488bc1          mov     rax,rcx\n"
    "fffff800`12340007 8bd1            mov     edx,ecx\n"
)

MEMORY_DUMP_OUTPUT = (
    "fffff800`12340000  48 83 ec 28 48 8b c1 48-8b d1 e8 00 00 00 00 c3  H...(H..H......\n"
    "fffff800`12340010  90 90 90 90 cc cc cc cc-cc cc cc cc cc cc cc cc  ................\n"
)

DRIVER_OBJECT_OUTPUT = (
    "Driver object (fffff800`12340000) is for:\n"
    " \\Driver\\TestDriver\n"
    "Driver Extension List: (id, addr)\n"
    "(fffff800`12350000, fffff800`12360000)\n"
    "Device Object list:\n"
    "fffff800`12370000\n"
    "fffff800`12370100\n"
    "\n"
    "Dispatch routines:\n"
    "[00] IRP_MJ_CREATE                  fffff800`12380000  TestDriver!CreateDispatch\n"
    "[02] IRP_MJ_CLOSE                   fffff800`12380100  TestDriver!CloseDispatch\n"
    "[0e] IRP_MJ_DEVICE_CONTROL          fffff800`12380200  TestDriver!DeviceControl\n"
)

DEVICE_OBJECT_OUTPUT = (
    "Device object (fffff800`12370000) is for:\n"
    " TestDevice \\Driver\\TestDriver\n"
    "Device Type: 00000022\n"
    "Flags: 00000040\n"
    "AttachedTo (Lower) fffff800`12380000\n"
)

POOL_OUTPUT = (
    "Pool page fffff800`12340000 region is Nonpaged pool\n"
    " fffff800`12340000 size:  100 previous size:    0  (Allocated)  Ntfs\n"
    "     Pooltag Ntfs : NTFS general allocation, Binary : ntfs.sys\n"
)

IOCTL_DECODE_OUTPUT = (
    "Device Type    : 0x0022 (FILE_DEVICE_UNKNOWN)\n"
    "Method         : 0x3 (METHOD_NEITHER)\n"
    "Access         : FILE_ANY_ACCESS\n"
    "Function       : 0x803\n"
)

ANALYZE_OUTPUT = (
    "BugCheck 50 {fffff80012340000, 0000000000000000, fffff80012350000, 0000000000000002}\n"
    "\n"
    "PAGE_FAULT_IN_NONPAGED_AREA (50)\n"
    "MODULE_NAME: TestDriver\n"
    "IMAGE_NAME: TestDriver.sys\n"
    "BUGCHECK_STR: AV_TestDriver!bad_func\n"
    "FAULTING_IP:\n"
    "TestDriver!bad_func+10\n"
    "fffff800`12360000 mov rax, [rcx]\n"
    "\n"
    "STACK_TEXT:\n"
    "fffff800`12340000 fffff800`12350000 : nt!KeBugCheckEx\n"
    "fffff800`12340010 fffff800`12350010 : TestDriver!bad_func+0x10\n"
    "\n"
    "FOLLOWUP_NAME: MachineOwner\n"
    "FAILURE_BUCKET_ID: AV_TestDriver!bad_func\n"
)

PROCESS_OUTPUT = (
    "PROCESS fffff800`12340000\n"
    "    SessionId: 0  Cid: 0004    Peb: 00000000  ParentCid: 0000\n"
    "    DirBase: 001aa000  ObjectTable: ffff9c0123450000  HandleCount: 1234\n"
    "    Image: System\n"
    "\n"
    "PROCESS fffff800`12350000\n"
    "    SessionId: 1  Cid: 01a8    Peb: 7ffd0000  ParentCid: 0004\n"
    "    Image: smss.exe\n"
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestParseRegisters:
    def test_basic(self):
        regs = WinDbgOutputParser.parse_registers(REGISTER_OUTPUT)
        assert regs["rax"] == "0000000000000001"
        assert regs["rip"] == "fffff80012340000"
        assert regs["efl"] == "00000246"

    def test_count(self):
        regs = WinDbgOutputParser.parse_registers(REGISTER_OUTPUT)
        assert len(regs) == 10

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_registers("") == {}

    def test_single_register(self):
        regs = WinDbgOutputParser.parse_registers("rip=deadbeef")
        assert regs == {"rip": "deadbeef"}


class TestParseModules:
    def test_basic(self):
        mods = WinDbgOutputParser.parse_modules(MODULE_OUTPUT)
        assert len(mods) == 3
        assert mods[0]["name"] == "nt"
        assert mods[0]["symbol_status"] == "pdb symbols"

    def test_backtick_removal(self):
        mods = WinDbgOutputParser.parse_modules(MODULE_OUTPUT)
        assert "`" not in mods[0]["start"]

    def test_deferred_symbols(self):
        mods = WinDbgOutputParser.parse_modules(MODULE_OUTPUT)
        assert mods[1]["symbol_status"] == "deferred"

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_modules("") == []


class TestParseStack:
    def test_basic(self):
        frames = WinDbgOutputParser.parse_stack(STACK_OUTPUT)
        assert len(frames) == 3

    def test_frame_fields(self):
        frames = WinDbgOutputParser.parse_stack(STACK_OUTPUT)
        assert frames[0]["frame"] == "00"
        assert frames[0]["call_site"] == "nt!KeBugCheckEx+0x0"

    def test_header_skipped(self):
        frames = WinDbgOutputParser.parse_stack(STACK_OUTPUT)
        for f in frames:
            assert "Child-SP" not in f.get("call_site", "")

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_stack("") == []


class TestParseDisassembly:
    def test_basic(self):
        instrs = WinDbgOutputParser.parse_disassembly(DISASSEMBLY_OUTPUT)
        assert len(instrs) == 3

    def test_instruction_content(self):
        instrs = WinDbgOutputParser.parse_disassembly(DISASSEMBLY_OUTPUT)
        assert instrs[0]["instruction"] == "sub     rsp,28h"
        assert instrs[0]["bytes"] == "4883ec28"

    def test_function_label_skipped(self):
        instrs = WinDbgOutputParser.parse_disassembly(DISASSEMBLY_OUTPUT)
        for instr in instrs:
            assert "KeBugCheckEx:" not in instr.get("instruction", "")

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_disassembly("") == []


class TestParseMemoryDump:
    def test_basic(self):
        raw = WinDbgOutputParser.parse_memory_dump(MEMORY_DUMP_OUTPUT)
        assert len(raw) == 32

    def test_first_bytes(self):
        raw = WinDbgOutputParser.parse_memory_dump(MEMORY_DUMP_OUTPUT)
        assert raw[0] == 0x48
        assert raw[3] == 0x28

    def test_second_line(self):
        raw = WinDbgOutputParser.parse_memory_dump(MEMORY_DUMP_OUTPUT)
        assert raw[16] == 0x90
        assert raw[20] == 0xCC

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_memory_dump("") == b""


class TestParseDriverObject:
    def test_name(self):
        driver = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert "TestDriver" in driver.name

    def test_address(self):
        driver = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert driver.address == "fffff80012340000"

    def test_device_objects(self):
        driver = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert len(driver.device_objects) == 2
        assert "fffff80012370000" in driver.device_objects

    def test_dispatch_table(self):
        driver = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert "IRP_MJ_CREATE" in driver.dispatch_table
        assert "IRP_MJ_CLOSE" in driver.dispatch_table
        assert "IRP_MJ_DEVICE_CONTROL" in driver.dispatch_table

    def test_hex_dispatch_index(self):
        """Dispatch indices like [0e] (hex) should be parsed correctly."""
        driver = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert "IRP_MJ_DEVICE_CONTROL" in driver.dispatch_table

    def test_return_type(self):
        result = WinDbgOutputParser.parse_driver_object(DRIVER_OBJECT_OUTPUT)
        assert isinstance(result, DriverObject)


class TestParseDeviceObject:
    def test_basic(self):
        dev = WinDbgOutputParser.parse_device_object(DEVICE_OBJECT_OUTPUT)
        assert dev.device_type == 0x22
        assert dev.flags == 0x40

    def test_device_name(self):
        dev = WinDbgOutputParser.parse_device_object(DEVICE_OBJECT_OUTPUT)
        assert dev.device_name == "TestDevice"

    def test_attached_to(self):
        dev = WinDbgOutputParser.parse_device_object(DEVICE_OBJECT_OUTPUT)
        assert dev.attached_to == "fffff80012380000"

    def test_return_type(self):
        result = WinDbgOutputParser.parse_device_object(DEVICE_OBJECT_OUTPUT)
        assert isinstance(result, DeviceObject)


class TestParsePoolInfo:
    def test_basic(self):
        pool = WinDbgOutputParser.parse_pool_info(POOL_OUTPUT)
        assert pool.pool_type == "NonPaged"
        assert pool.size == 0x100

    def test_tag(self):
        pool = WinDbgOutputParser.parse_pool_info(POOL_OUTPUT)
        assert pool.tag == "Ntfs"

    def test_owning_component(self):
        pool = WinDbgOutputParser.parse_pool_info(POOL_OUTPUT)
        assert pool.owning_component == "ntfs.sys"

    def test_paged_pool(self):
        paged_output = POOL_OUTPUT.replace("Nonpaged", "Paged")
        pool = WinDbgOutputParser.parse_pool_info(paged_output)
        assert pool.pool_type == "Paged"

    def test_return_type(self):
        result = WinDbgOutputParser.parse_pool_info(POOL_OUTPUT)
        assert isinstance(result, PoolAllocation)


class TestParseIOCTLDecode:
    def test_structured_output(self):
        ioctl = WinDbgOutputParser.parse_ioctl_decode(IOCTL_DECODE_OUTPUT)
        assert ioctl.device_type == 0x22
        assert ioctl.method == 3
        assert ioctl.function_code == 0x803
        assert ioctl.risk_level == "high"

    def test_raw_hex_fallback(self):
        ioctl = WinDbgOutputParser.parse_ioctl_decode("IOCTL: 0x0022200F")
        assert ioctl.device_type == 0x22
        assert ioctl.method == 3

    def test_empty_fallback(self):
        ioctl = WinDbgOutputParser.parse_ioctl_decode("no ioctl here")
        assert ioctl.raw_code == 0
        assert ioctl.risk_level == "unknown"

    def test_return_type(self):
        result = WinDbgOutputParser.parse_ioctl_decode(IOCTL_DECODE_OUTPUT)
        assert isinstance(result, IOCTLCode)


class TestParseAnalyze:
    def test_bugcheck_code(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert crash.bugcheck_code == 0x50

    def test_bugcheck_name(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert "TestDriver" in crash.bugcheck_name

    def test_faulting_module(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert crash.faulting_module == "TestDriver"

    def test_arguments(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert len(crash.arguments) == 4
        assert crash.arguments[0] == "fffff80012340000"

    def test_stack_trace(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert len(crash.stack_trace) >= 2

    def test_probable_cause(self):
        crash = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert crash.probable_cause == "MachineOwner"

    def test_return_type(self):
        result = WinDbgOutputParser.parse_analyze(ANALYZE_OUTPUT)
        assert isinstance(result, CrashAnalysis)


class TestParseProcesses:
    def test_basic(self):
        procs = WinDbgOutputParser.parse_processes(PROCESS_OUTPUT)
        assert len(procs) == 2

    def test_system_process(self):
        procs = WinDbgOutputParser.parse_processes(PROCESS_OUTPUT)
        assert procs[0]["image"] == "System"
        assert procs[0]["pid"] == "0004"

    def test_second_process(self):
        procs = WinDbgOutputParser.parse_processes(PROCESS_OUTPUT)
        assert procs[1]["image"] == "smss.exe"
        assert procs[1]["ppid"] == "0004"

    def test_empty_input(self):
        assert WinDbgOutputParser.parse_processes("") == []
