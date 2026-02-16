"""
Tests for WinDbg bridge.

Mocks Pybag and subprocess so tests run on any platform (macOS/Linux/Windows).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.engines.dynamic.base import DebuggerState
from src.engines.dynamic.windbg.bridge import (
    WinDbgBridge,
    WinDbgBridgeError,
)
from src.engines.dynamic.windbg.kernel_types import WinDbgMode


class TestPlatformGuard:
    """Non-Windows platforms should get a clear error."""

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Darwin")
    def test_connect_fails_on_macos(self, mock_sys):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.connect()
        assert "platform" in exc_info.value.operation

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Linux")
    def test_connect_fails_on_linux(self, mock_sys):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError):
            bridge.connect()


class TestAutoDetectPath:
    """Test CDB and KD path auto-detection."""

    @patch("pathlib.Path.is_file", return_value=False)
    def test_no_cdb_found(self, mock_is_file):
        result = WinDbgBridge._find_cdb()
        assert result is None

    @patch("pathlib.Path.is_file", return_value=True)
    def test_cdb_found(self, mock_is_file):
        result = WinDbgBridge._find_cdb()
        assert result is not None
        assert "cdb.exe" in str(result)

    @patch("pathlib.Path.is_file", return_value=False)
    @patch("shutil.which", return_value=None)
    def test_no_kd_found(self, mock_which, mock_is_file):
        result = WinDbgBridge._find_kd()
        assert result is None

    @patch("pathlib.Path.is_file", return_value=True)
    def test_kd_found(self, mock_is_file):
        result = WinDbgBridge._find_kd()
        assert result is not None
        assert "kd.exe" in str(result)


class TestBridgeInitialization:
    def test_initial_state(self):
        bridge = WinDbgBridge()
        assert bridge.get_state() == DebuggerState.NOT_LOADED
        assert bridge._mode == WinDbgMode.USER_MODE
        assert bridge._cdb_proc is None
        assert bridge._breakpoints == {}

    def test_disconnect_safe_when_not_connected(self):
        bridge = WinDbgBridge()
        bridge.disconnect()
        assert bridge.get_state() == DebuggerState.NOT_LOADED

    def test_decode_ioctl_without_connection(self):
        """IOCTL decoding is pure Python and needs no connection."""
        bridge = WinDbgBridge()
        ioctl = bridge.decode_ioctl(0x0022200F)
        assert ioctl.device_type == 0x22
        assert ioctl.risk_level == "high"


class TestConnectWithMockedPybag:
    """Test connect() and kernel connect methods with mocked Pybag."""

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    def test_connect_success(self, mock_sys):
        bridge = WinDbgBridge()
        result = bridge.connect()
        assert result is True
        assert bridge.get_state() == DebuggerState.LOADED

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", False)
    def test_connect_no_pybag(self, mock_sys):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.connect()
        assert "pybag" in exc_info.value.operation.lower() or "Pybag" in exc_info.value.message

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    @patch("src.engines.dynamic.windbg.bridge.pybag")
    def test_connect_kernel_net(self, mock_pybag, mock_sys):
        mock_kd = MagicMock()
        mock_pybag.KernelDbg.return_value = mock_kd

        bridge = WinDbgBridge()
        result = bridge.connect_kernel_net(port=50000, key="1.2.3.4")
        assert result is True
        assert bridge._mode == WinDbgMode.KERNEL_MODE
        assert bridge.get_state() == DebuggerState.PAUSED
        mock_kd.attach.assert_called_once_with("net:port=50000,key=1.2.3.4")

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    @patch("src.engines.dynamic.windbg.bridge.pybag")
    def test_connect_kernel_local(self, mock_pybag, mock_sys):
        mock_kd = MagicMock()
        # Validation: module_list returns data so validation passes
        mock_params = MagicMock()
        mock_params.Base = 0xFFFFF80000000000
        mock_params.Size = 0x10000
        mock_kd.module_list.return_value = [(("nt",), mock_params)]
        mock_pybag.KernelDbg.return_value = mock_kd

        bridge = WinDbgBridge()
        result = bridge.connect_kernel_local()
        assert result is True
        assert bridge._mode == WinDbgMode.KERNEL_MODE
        assert bridge._is_local_kernel is True
        mock_kd.attach.assert_called_once_with("local")

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    @patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
    @patch("src.engines.dynamic.windbg.bridge.pybag")
    def test_connect_kernel_local_not_enabled(self, mock_pybag, mock_sys):
        """connect_kernel_local() raises when kernel debugging is not enabled."""
        mock_kd = MagicMock()
        # Validation: module_list empty AND get_pc fails → not enabled
        mock_kd.module_list.return_value = []
        mock_kd.reg.get_pc.side_effect = RuntimeError("no session")
        mock_pybag.KernelDbg.return_value = mock_kd

        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.connect_kernel_local()
        assert "bcdedit" in exc_info.value.message.lower()
        assert bridge._dbg is None  # Cleaned up


class TestABCMethodsWithMockedPybag:
    """Test all 13 Debugger ABC methods with mocked Pybag."""

    @pytest.fixture()
    def bridge(self):
        """Create a bridge with a mocked Pybag debugger attached."""
        b = WinDbgBridge()
        b._dbg = MagicMock()
        b._state = DebuggerState.PAUSED
        return b

    def test_load_binary(self):
        with (
            patch(
                "src.engines.dynamic.windbg.bridge.platform.system",
                return_value="Windows",
            ),
            patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True),
            patch("src.engines.dynamic.windbg.bridge.pybag") as mock_pybag,
        ):
            mock_dbg = MagicMock()
            mock_pybag.UserDbg.return_value = mock_dbg

            bridge = WinDbgBridge()
            result = bridge.load_binary(Path("C:\\test.exe"), args=["-v"])
            assert result is True
            assert bridge.get_state() == DebuggerState.PAUSED
            mock_dbg.create.assert_called_once()

    def test_set_breakpoint(self, bridge):
        result = bridge.set_breakpoint("0x401000")
        assert result is True
        bridge._dbg.bp.assert_called_once()
        assert "0x401000" in bridge._breakpoints

    def test_set_breakpoint_captures_bp_id(self, bridge):
        """bp() return value is used as the breakpoint ID."""
        bridge._dbg.bp.return_value = 42
        bridge.set_breakpoint("0x401000")
        assert bridge._breakpoints["0x401000"] == 42

    def test_set_breakpoint_fallback_counter(self, bridge):
        """When bp() returns None, use an auto-incrementing counter."""
        bridge._dbg.bp.return_value = None
        bridge.set_breakpoint("0x401000")
        assert bridge._breakpoints["0x401000"] == 0
        bridge.set_breakpoint("0x402000")
        assert bridge._breakpoints["0x402000"] == 1

    def test_delete_breakpoint(self, bridge):
        # Set first so we have a tracked BP ID
        bridge._dbg.bp.return_value = 7
        bridge.set_breakpoint("0x401000")
        assert bridge._breakpoints["0x401000"] == 7

        result = bridge.delete_breakpoint("0x401000")
        assert result is True
        bridge._dbg.bc.assert_called_once_with(7)
        assert "0x401000" not in bridge._breakpoints

    def test_delete_breakpoint_fallback(self, bridge):
        """Delete a BP that wasn't tracked — falls back to command."""
        result = bridge.delete_breakpoint("0x401000")
        assert result is True
        bridge._dbg.cmd.assert_called_once_with("bc 0x401000")

    def test_run(self, bridge):
        state = bridge.run()
        assert state == DebuggerState.RUNNING
        bridge._dbg.go.assert_called_once()

    def test_run_blocked_in_dump_mode(self, bridge):
        bridge._mode = WinDbgMode.DUMP_ANALYSIS
        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.run()
        assert "dump analysis" in exc_info.value.message.lower()

    def test_run_blocked_in_local_kernel(self, bridge):
        bridge._is_local_kernel = True
        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.run()
        assert "local kernel" in exc_info.value.message.lower()

    def test_pause(self, bridge):
        result = bridge.pause()
        assert result is True
        bridge._dbg._control.SetInterrupt.assert_called_once_with(0)

    def test_step_into(self, bridge):
        bridge._dbg.reg.rip = 0x401000
        bridge._dbg.cmd.return_value = (
            "fffff80012340000 4883ec28  sub rsp,28h"
        )
        result = bridge.step_into()
        assert "address" in result
        bridge._dbg.stepi.assert_called_once()

    def test_step_over(self, bridge):
        bridge._dbg.reg.rip = 0x401000
        bridge._dbg.cmd.return_value = ""
        result = bridge.step_over()
        assert "address" in result
        bridge._dbg.stepo.assert_called_once()

    def test_step_into_blocked_in_dump(self, bridge):
        bridge._mode = WinDbgMode.DUMP_ANALYSIS
        with pytest.raises(WinDbgBridgeError):
            bridge.step_into()

    def test_get_registers(self, bridge):
        bridge._dbg.reg.register_dict.return_value = {"rax": 1, "rbx": 255}
        regs = bridge.get_registers()
        assert regs["rax"] == "1"
        assert regs["rbx"] == "ff"

    def test_get_registers_fallback(self, bridge):
        """Fall back to parsing 'r' command when register_dict() fails."""
        bridge._dbg.reg.register_dict.side_effect = RuntimeError("no access")
        bridge._dbg.cmd.return_value = "rax=0000000000000001 rbx=00000000000000ff"
        regs = bridge.get_registers()
        # Parser should extract at least rax
        assert "rax" in regs

    def test_read_memory(self, bridge):
        bridge._dbg.read.return_value = b"\x90\x90"
        data = bridge.read_memory("0x401000", 2)
        assert data == b"\x90\x90"

    def test_write_memory(self, bridge):
        result = bridge.write_memory("0x401000", b"\xcc")
        assert result is True
        bridge._dbg.write.assert_called_once()

    def test_write_memory_blocked_in_dump(self, bridge):
        bridge._mode = WinDbgMode.DUMP_ANALYSIS
        with pytest.raises(WinDbgBridgeError):
            bridge.write_memory("0x401000", b"\xcc")

    def test_write_memory_blocked_in_local_kernel(self, bridge):
        bridge._is_local_kernel = True
        with pytest.raises(WinDbgBridgeError):
            bridge.write_memory("0x401000", b"\xcc")

    def test_get_state(self, bridge):
        assert bridge.get_state() == DebuggerState.PAUSED

    def test_get_current_location(self, bridge):
        bridge._dbg.reg.rip = 0xDEADBEEF
        bridge._dbg.cmd.return_value = ""
        loc = bridge.get_current_location()
        assert loc["address"] == "deadbeef"

    def test_get_current_location_fallback(self, bridge):
        """Fall back to reg.get_pc() when reg.rip fails."""
        type(bridge._dbg.reg).rip = property(
            lambda self: (_ for _ in ()).throw(AttributeError("no rip"))
        )
        bridge._dbg.reg.get_pc.return_value = 0xCAFEBABE
        loc = bridge.get_current_location()
        assert loc["address"] == "cafebabe"


class TestExtensionCommands:
    """Test execute_extension() with mocked subprocess."""

    def test_execute_command_via_pybag(self):
        bridge = WinDbgBridge()
        bridge._dbg = MagicMock()
        bridge._dbg.cmd.return_value = "test output"
        bridge._state = DebuggerState.PAUSED

        result = bridge.execute_command("lm")
        assert result == "test output"

    @patch("src.engines.dynamic.windbg.bridge.subprocess.run")
    def test_execute_extension_via_cdb(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="extension output", stderr="", returncode=0
        )

        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")
        bridge._binary_path = Path("C:\\dump.dmp")
        bridge._mode = WinDbgMode.DUMP_ANALYSIS

        result = bridge.execute_extension("!analyze -v")
        assert "extension output" in result
        mock_run.assert_called_once()

    @patch("src.engines.dynamic.windbg.bridge.subprocess.run")
    def test_execute_extension_local_kernel_uses_kd(self, mock_run):
        """Local kernel CDB fallback should prefer kd.exe."""
        mock_run.return_value = MagicMock(
            stdout="kernel output", stderr="", returncode=0
        )

        bridge = WinDbgBridge()
        bridge._kd_path = Path("C:\\kd.exe")
        bridge._cdb_path = Path("C:\\cdb.exe")
        bridge._mode = WinDbgMode.KERNEL_MODE
        bridge._is_local_kernel = True

        result = bridge.execute_extension("lm")
        assert "kernel output" in result
        # Should use kd.exe, not cdb.exe
        call_args = mock_run.call_args[0][0]
        assert "kd.exe" in call_args[0]
        assert "-kl" in call_args

    def test_execute_extension_no_cdb(self):
        bridge = WinDbgBridge()
        bridge._cdb_path = None
        with pytest.raises(Exception):
            bridge.execute_extension("!analyze -v")

    def test_local_kernel_without_kd_raises(self):
        """Local kernel mode without kd.exe should raise, not fall back to CDB."""
        bridge = WinDbgBridge()
        bridge._kd_path = None
        bridge._cdb_path = Path("C:\\cdb.exe")
        bridge._mode = WinDbgMode.KERNEL_MODE
        bridge._is_local_kernel = True

        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge._execute_cdb_command("lm")
        assert "kd.exe is required" in exc_info.value.message
        assert "CDB does not support" in exc_info.value.message

    @patch("src.engines.dynamic.windbg.bridge.subprocess.run")
    def test_execute_cdb_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="cdb", timeout=30)

        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")

        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.execute_extension("!analyze -v")
        assert "timed out" in exc_info.value.message.lower()

    @patch("src.engines.dynamic.windbg.bridge.subprocess.run")
    def test_execute_cdb_detects_kernel_not_enabled(self, mock_run):
        """CDB output containing 'does not support local kernel debugging' raises."""
        mock_run.return_value = MagicMock(
            stdout=(
                "Microsoft (R) Windows Debugger\n"
                "The system does not support local kernel debugging.\n"
                "Debuggee initialization failed, HRESULT 0x80004001\n"
            ),
            stderr="",
            returncode=1,
        )
        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")

        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.execute_extension("lm")
        assert "bcdedit" in exc_info.value.message.lower()


class TestCDBBannerFilter:
    """Test CDB/KD output banner filtering."""

    def test_filters_microsoft_banner(self):
        output = (
            "Microsoft (R) Windows Debugger Version 10.0.26100.2454 AMD64\n"
            "Copyright (c) Microsoft Corporation. All rights reserved.\n"
            "\n"
            "Loading Dump File [C:\\dump.dmp]\n"
            "Windows 10 Version 19041 MP (4 procs) Free x64\n"
            "\n"
            "Actual command output here\n"
            "More output\n"
            "quit:\n"
        )
        result = WinDbgBridge._filter_cdb_banner(output)
        assert "Microsoft" not in result
        assert "Copyright" not in result
        assert "Loading Dump" not in result
        assert "Actual command output here" in result
        assert "More output" in result
        assert "quit:" not in result

    def test_filters_extensions_gallery_noise(self):
        """Modern WinDbg emits Extensions Gallery setup before the banner."""
        output = (
            "************* Preparing the environment for Debugger Extensions Gallery "
            "repositories **************\n"
            "   ExtensionRepository : Implicit\n"
            "   UseExperimentalFeatureForNugetShare : true\n"
            "   AllowNugetExeUpdate : true\n"
            "   NonInteractiveNuget : true\n"
            "   AllowParallelInitializationOfLocalRepositories : true\n"
            "\n"
            "   EnableRedirectToV8JsProvider : false\n"
            "\n"
            "   -- Configuring repositories\n"
            "      ----> Repository : LocalInstalled, Enabled: true\n"
            "      ----> Repository : UserExtensions, Enabled: true\n"
            "\n"
            ">>>>>>>>>>>>> Preparing the environment completed, duration 0.000 seconds\n"
            "\n"
            "************* Waiting for Debugger Extensions Gallery to Initialize **************\n"
            "\n"
            ">>>>>>>>>>>>> Waiting completed, duration 0.015 seconds\n"
            "   ----> Repository : UserExtensions, Enabled: true, Packages count: 0\n"
            "   ----> Repository : LocalInstalled, Enabled: true, Packages count: 29\n"
            "\n"
            "Microsoft (R) Windows Debugger Version 10.0.26100.4188 AMD64\n"
            "Copyright (c) Microsoft Corporation. All rights reserved.\n"
            "\n"
            "start             end                 module name\n"
            "fffff800`12340000 fffff800`12350000   nt\n"
            "quit:\n"
        )
        result = WinDbgBridge._filter_cdb_banner(output)
        assert "Extensions Gallery" not in result
        assert "ExtensionRepository" not in result
        assert "Repository" not in result
        assert "Microsoft" not in result
        assert "module name" in result
        assert "nt" in result

    def test_empty_output(self):
        assert WinDbgBridge._filter_cdb_banner("") == ""

    def test_no_banner(self):
        output = "Module list:\nnt    fffff800`12340000\n"
        result = WinDbgBridge._filter_cdb_banner(output)
        assert "Module list:" in result
        assert "nt" in result


class TestCDBErrorDetection:
    """Test _check_cdb_error() error pattern matching."""

    def test_detects_kernel_not_enabled(self):
        output = (
            "The system does not support local kernel debugging.\n"
            "Debuggee initialization failed, HRESULT 0x80004001\n"
        )
        msg = WinDbgBridge._check_cdb_error(output)
        assert msg is not None
        assert "bcdedit" in msg.lower()

    def test_detects_admin_required(self):
        output = "Local kernel debugging requires Administrative privileges.\n"
        msg = WinDbgBridge._check_cdb_error(output)
        assert msg is not None
        assert "Administrator" in msg

    def test_no_error_returns_none(self):
        output = "start  end  module name\nnt  fffff800`12340000\n"
        assert WinDbgBridge._check_cdb_error(output) is None


class TestKernelSpecificMethods:
    """Test kernel-specific methods with mocked bridge."""

    @pytest.fixture()
    def bridge(self):
        b = WinDbgBridge()
        b._dbg = MagicMock()
        b._state = DebuggerState.PAUSED
        return b

    def test_get_driver_object(self, bridge):
        bridge._dbg.cmd.return_value = (
            "Driver object (fffff800`12340000) is for:\n"
            " \\Driver\\Test\n"
            "Device Object list:\n"
            "\n"
            "Dispatch routines:\n"
            "[00] IRP_MJ_CREATE fffff800`12380000 Test!Create\n"
        )
        driver = bridge.get_driver_object("\\Driver\\Test")
        assert "Test" in driver.name

    def test_get_driver_object_not_found(self, bridge):
        bridge._dbg.cmd.return_value = "Could not find \\Driver\\Nonexistent"
        with pytest.raises(Exception):
            bridge.get_driver_object("\\Driver\\Nonexistent")

    def test_get_loaded_drivers(self, bridge):
        # Mock module_list() for native pybag path
        mock_params = MagicMock()
        mock_params.Base = 0xFFFFF80012340000
        mock_params.Size = 0x10000
        bridge._dbg.module_list.return_value = [
            (("nt",), mock_params),
        ]
        mods = bridge.get_loaded_drivers()
        assert len(mods) == 1
        assert mods[0]["name"] == "nt"
        assert mods[0]["start"] == "fffff80012340000"
        assert mods[0]["end"] == "fffff80012350000"

    def test_get_loaded_drivers_empty_fallback(self, bridge):
        """Empty module_list() falls through to lm command."""
        bridge._dbg.module_list.return_value = []
        bridge._dbg.cmd.return_value = ""
        mods = bridge.get_loaded_drivers()
        assert mods == []

    def test_get_processes(self, bridge):
        bridge._dbg.cmd.return_value = (
            "PROCESS fffff800`12340000\n"
            "    SessionId: 0  Cid: 0004    Peb: 00000000  ParentCid: 0000\n"
            "    Image: System\n"
        )
        procs = bridge.get_processes()
        assert len(procs) == 1
        assert procs[0]["image"] == "System"

    def test_analyze_crash(self, bridge):
        bridge._dbg.cmd.return_value = (
            "BugCheck 50 {0, 0, 0, 0}\n"
            "BUGCHECK_STR: PAGE_FAULT\n"
            "MODULE_NAME: test\n"
        )
        crash = bridge.analyze_crash()
        assert crash.bugcheck_code == 0x50


class TestDumpAnalysis:
    """Test dump file opening and mode guards."""

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    def test_open_dump_cdb_only(self, mock_sys):
        """open_dump() uses CDB subprocess — pybag OpenDumpFile is E_NOTIMPL."""
        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")

        result = bridge.open_dump(Path("C:\\dump.dmp"))
        assert result is True
        assert bridge._mode == WinDbgMode.DUMP_ANALYSIS
        assert bridge._state == DebuggerState.PAUSED
        assert bridge._binary_path == Path("C:\\dump.dmp")

    @patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
    def test_open_dump_requires_cdb(self, mock_sys):
        """open_dump() raises if CDB is not found."""
        bridge = WinDbgBridge()
        bridge._cdb_path = None

        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.open_dump(Path("C:\\dump.dmp"))
        assert "CDB.exe is required" in exc_info.value.message


class TestDisconnect:
    """Test disconnect cleanup."""

    def test_disconnect_cleans_pybag(self):
        bridge = WinDbgBridge()
        mock_dbg = MagicMock()
        bridge._dbg = mock_dbg
        bridge._state = DebuggerState.PAUSED

        bridge.disconnect()
        mock_dbg.detach.assert_called_once()
        assert bridge._dbg is None
        assert bridge.get_state() == DebuggerState.NOT_LOADED

    def test_disconnect_kills_cdb_subprocess(self):
        bridge = WinDbgBridge()
        mock_proc = MagicMock()
        bridge._cdb_proc = mock_proc

        bridge.disconnect()
        mock_proc.terminate.assert_called_once()
        assert bridge._cdb_proc is None

    def test_disconnect_handles_detach_error(self):
        bridge = WinDbgBridge()
        mock_dbg = MagicMock()
        mock_dbg.detach.side_effect = RuntimeError("already detached")
        bridge._dbg = mock_dbg

        bridge.disconnect()  # Should not raise
        assert bridge._dbg is None

    def test_disconnect_resets_local_kernel_flag(self):
        bridge = WinDbgBridge()
        bridge._is_local_kernel = True
        bridge._mode = WinDbgMode.KERNEL_MODE
        bridge.disconnect()
        assert bridge._is_local_kernel is False
        assert bridge._mode == WinDbgMode.USER_MODE
