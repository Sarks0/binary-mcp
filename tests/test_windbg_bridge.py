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
    """Test CDB path auto-detection."""

    @patch("pathlib.Path.is_file", return_value=False)
    def test_no_cdb_found(self, mock_is_file):
        result = WinDbgBridge._find_cdb()
        assert result is None

    @patch("pathlib.Path.is_file", return_value=True)
    def test_cdb_found(self, mock_is_file):
        result = WinDbgBridge._find_cdb()
        assert result is not None
        assert "cdb.exe" in str(result)


class TestBridgeInitialization:
    def test_initial_state(self):
        bridge = WinDbgBridge()
        assert bridge.get_state() == DebuggerState.NOT_LOADED
        assert bridge._mode == WinDbgMode.USER_MODE

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
        mock_pybag.KernelDbg.return_value = mock_kd

        bridge = WinDbgBridge()
        result = bridge.connect_kernel_local()
        assert result is True
        assert bridge._mode == WinDbgMode.KERNEL_MODE
        mock_kd.attach.assert_called_once_with("local")


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

    def test_delete_breakpoint(self, bridge):
        result = bridge.delete_breakpoint("0x401000")
        assert result is True
        bridge._dbg.bc.assert_called_once()

    def test_run(self, bridge):
        state = bridge.run()
        assert state == DebuggerState.RUNNING
        bridge._dbg.go.assert_called_once()

    def test_pause(self, bridge):
        result = bridge.pause()
        assert result is True
        bridge._dbg.break_in.assert_called_once()

    def test_step_into(self, bridge):
        bridge._dbg.reg.rip = 0x401000
        bridge._dbg.exec_command.return_value = (
            "fffff80012340000 4883ec28  sub rsp,28h"
        )
        result = bridge.step_into()
        assert "address" in result
        bridge._dbg.step_into.assert_called_once()

    def test_step_over(self, bridge):
        bridge._dbg.reg.rip = 0x401000
        bridge._dbg.exec_command.return_value = ""
        result = bridge.step_over()
        assert "address" in result
        bridge._dbg.step_over.assert_called_once()

    def test_get_registers(self, bridge):
        bridge._dbg.regs = {"rax": 1, "rbx": 255}
        regs = bridge.get_registers()
        assert regs["rax"] == "1"
        assert regs["rbx"] == "ff"

    def test_read_memory(self, bridge):
        bridge._dbg.read.return_value = b"\x90\x90"
        data = bridge.read_memory("0x401000", 2)
        assert data == b"\x90\x90"

    def test_write_memory(self, bridge):
        result = bridge.write_memory("0x401000", b"\xcc")
        assert result is True
        bridge._dbg.write.assert_called_once()

    def test_get_state(self, bridge):
        assert bridge.get_state() == DebuggerState.PAUSED

    def test_get_current_location(self, bridge):
        bridge._dbg.reg.rip = 0xDEADBEEF
        bridge._dbg.exec_command.return_value = ""
        loc = bridge.get_current_location()
        assert loc["address"] == "deadbeef"


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
        mock_run.return_value = MagicMock(stdout="extension output", returncode=0)

        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")
        bridge._binary_path = Path("C:\\dump.dmp")

        result = bridge.execute_extension("!analyze -v")
        assert result == "extension output"
        mock_run.assert_called_once()

    def test_execute_extension_no_cdb(self):
        bridge = WinDbgBridge()
        bridge._cdb_path = None
        with pytest.raises(Exception):
            bridge.execute_extension("!analyze -v")

    @patch("src.engines.dynamic.windbg.bridge.subprocess.run")
    def test_execute_cdb_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="cdb", timeout=30)

        bridge = WinDbgBridge()
        bridge._cdb_path = Path("C:\\cdb.exe")

        with pytest.raises(WinDbgBridgeError) as exc_info:
            bridge.execute_extension("!analyze -v")
        assert "timed out" in exc_info.value.message.lower()


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
