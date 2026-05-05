"""Tests for KDSERIAL / Hyper-V pipe / IPv6 KDNET transports."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())

from src.engines.dynamic.base import DebuggerState  # noqa: E402
from src.engines.dynamic.windbg.bridge import (  # noqa: E402
    WinDbgBridge,
    WinDbgBridgeError,
)


def _broken_bridge_factory(mock_pybag):
    """Mocked KernelDbg whose wait() flips the SessionTracker to BROKEN."""
    mock_kd = MagicMock()
    mock_pybag.KernelDbg.return_value = mock_kd

    bridge = WinDbgBridge()

    def _wait(_ms):
        bridge._session.record_break(thread_id=0xABCD)

    mock_kd.wait.side_effect = _wait
    return bridge, mock_kd


@patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
@patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
@patch("src.engines.dynamic.windbg.bridge.pybag")
class TestKdnetIpv6:
    def test_default_v4_no_suffix(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        result = bridge.connect_kernel_net(port=50000, key="1.2.3.4")
        assert result["status"] == "connected_broken"
        mock_kd.attach.assert_called_once_with("net:port=50000,key=1.2.3.4")

    def test_v6_appends_ipversion(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        bridge.connect_kernel_net(port=50000, key="1.2.3.4", ipversion=6)
        mock_kd.attach.assert_called_once_with(
            "net:port=50000,key=1.2.3.4,ipversion=6"
        )

    def test_invalid_ipversion_rejected(self, mock_pybag, _system):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError, match="invalid ipversion"):
            bridge.connect_kernel_net(port=50000, key="1.2.3.4", ipversion=5)


@patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
@patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
@patch("src.engines.dynamic.windbg.bridge.pybag")
class TestKdSerial:
    def test_default_form(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        result = bridge.connect_kernel_serial(port="COM1")
        assert result["status"] == "connected_broken"
        assert result["port"] == "COM1"
        assert result["baud"] == 115200
        mock_kd.attach.assert_called_once_with(
            "com:port=COM1,baud=115200,reconnect"
        )

    def test_pipe_flag_inserts_pipe(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        bridge.connect_kernel_serial(
            port=r"\\.\pipe\com_1", baud=921600, pipe=True, reconnect=False
        )
        mock_kd.attach.assert_called_once_with(
            r"com:port=\\.\pipe\com_1,baud=921600,pipe"
        )

    def test_rejects_empty_port(self, mock_pybag, _system):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError, match="port is required"):
            bridge.connect_kernel_serial(port="")

    def test_rejects_bad_baud(self, mock_pybag, _system):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError, match="invalid baud"):
            bridge.connect_kernel_serial(port="COM1", baud=0)

    def test_paused_state_after_break(self, mock_pybag, _system):
        bridge, _ = _broken_bridge_factory(mock_pybag)
        bridge.connect_kernel_serial(port="COM1")
        assert bridge.get_state() == DebuggerState.PAUSED


@patch("src.engines.dynamic.windbg.bridge.platform.system", return_value="Windows")
@patch("src.engines.dynamic.windbg.bridge.PYBAG_AVAILABLE", True)
@patch("src.engines.dynamic.windbg.bridge.pybag")
class TestKdPipe:
    def test_default_form(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        result = bridge.connect_kernel_pipe(pipe_name=r"\\.\pipe\com_1")
        assert result["status"] == "connected_broken"
        assert result["pipe_name"] == r"\\.\pipe\com_1"
        mock_kd.attach.assert_called_once_with(
            r"com:pipe,port=\\.\pipe\com_1,reconnect"
        )

    def test_no_reconnect(self, mock_pybag, _system):
        bridge, mock_kd = _broken_bridge_factory(mock_pybag)
        bridge.connect_kernel_pipe(pipe_name="com_1", reconnect=False)
        mock_kd.attach.assert_called_once_with("com:pipe,port=com_1")

    def test_rejects_empty_pipe(self, mock_pybag, _system):
        bridge = WinDbgBridge()
        with pytest.raises(WinDbgBridgeError, match="pipe_name is required"):
            bridge.connect_kernel_pipe(pipe_name="")
