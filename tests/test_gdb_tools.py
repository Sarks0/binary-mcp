"""
Tests for the GDB Linux debugging MCP tool layer.

The engine has its own suites (test_gdb_mi_parser, test_gdb_mi_session,
test_gdb_allowlist, test_gdb_bridge). What is asserted here is only what the
tool layer itself owns and the engine cannot: the platform gate, path
confinement before the file is touched, hex-argument validation, error
hygiene, and the F-7 envelope on every return rendered from the debugged
process.

The bridge is a hand-written stand-in rather than a MagicMock, because a mock
answers every attribute and would let a tool call a method the real bridge does
not have -- which is exactly the bug this layer can introduce.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import src.tools.gdb_tools as gdb_tools
from src.engines.dynamic.base import DebuggerState
from src.engines.dynamic.gdb.bridge import GdbBridgeError
from src.engines.dynamic.gdb.mi_session import MISessionError
from src.utils.formatters import UNTRUSTED_END_MARKER, UNTRUSTED_OPEN_SENTINEL


def _real_fastmcp():
    """Get the genuine FastMCP class past other modules' import-time stubs.

    Same problem and same remedy as tests/test_x64dbg_tool_groups.py: several
    suites install MagicMock stubs for fastmcp/mcp and never restore them, so a
    plain import here can yield a mock whose get_tools() is not awaitable.
    """
    stubbed = {
        name: module for name, module in sys.modules.items()
        if isinstance(module, MagicMock)
        and (name == "fastmcp" or name.startswith("fastmcp.")
             or name == "mcp" or name.startswith("mcp."))
    }
    if not stubbed:
        return importlib.import_module("fastmcp").FastMCP

    for name in stubbed:
        del sys.modules[name]
    try:
        return importlib.import_module("fastmcp").FastMCP
    finally:
        sys.modules.update(stubbed)


class FakeBridge:
    """A GdbBridge stand-in that records calls and returns scripted values."""

    def __init__(self, **overrides):
        self.calls: list[tuple] = []
        self._overrides = overrides
        self.state = overrides.get("state", DebuggerState.PAUSED)
        self.connected = overrides.get("connected", True)

    def _answer(self, name, default):
        value = self._overrides.get(name, default)
        if isinstance(value, Exception):
            raise value
        return value

    def is_connected(self):
        return self.connected

    def connect(self, timeout: int = 10):
        self.calls.append(("connect",))
        return self._answer("connect", True)

    def disconnect(self):
        self.calls.append(("disconnect",))
        return self._answer("disconnect", None)

    def load_binary(self, binary_path, args=None):
        self.calls.append(("load_binary", str(binary_path), args))
        return self._answer("load_binary", True)

    def attach(self, pid):
        self.calls.append(("attach", pid))
        return self._answer("attach", True)

    def detach(self):
        self.calls.append(("detach",))
        return self._answer("detach", True)

    def run(self, stop_at="entry"):
        self.calls.append(("run", stop_at))
        return self._answer("run", DebuggerState.PAUSED)

    def pause(self):
        self.calls.append(("pause",))
        return self._answer("pause", True)

    def get_state(self):
        return self._answer("get_state", self.state)

    def get_current_location(self):
        return self._answer("get_current_location", {
            "state": "paused", "address": "0x401136", "function": "main",
            "file": "mal.c", "line": "12", "stop_reason": "breakpoint-hit",
            "instruction": "mov rax, rdi",
        })

    def step_into(self):
        self.calls.append(("step_into",))
        return self._answer("step_into", self.get_current_location())

    def step_over(self):
        self.calls.append(("step_over",))
        return self._answer("step_over", self.get_current_location())

    def step_out(self):
        self.calls.append(("step_out",))
        return self._answer("step_out", self.get_current_location())

    def set_breakpoint(self, address):
        self.calls.append(("set_breakpoint", address))
        return self._answer("set_breakpoint", True)

    def delete_breakpoint(self, address):
        self.calls.append(("delete_breakpoint", address))
        return self._answer("delete_breakpoint", True)

    def list_breakpoints(self):
        return self._answer("list_breakpoints", [
            {"number": "1", "type": "breakpoint", "enabled": "y",
             "addr": "0x401136", "func": "main", "file": "mal.c",
             "line": "12", "times": "3"},
        ])

    def get_registers(self):
        return self._answer("get_registers", {"rax": "0x0", "rip": "0x401136"})

    def read_memory(self, address, size):
        return self._answer("read_memory", bytes(range(32)))

    def write_memory(self, address, data):
        self.calls.append(("write_memory", address, data))
        return self._answer("write_memory", True)

    def disassemble(self, address, count=10):
        return self._answer("disassemble", [
            {"address": "0x401136", "func-name": "main", "offset": "0",
             "inst": "mov rax, rdi"},
        ])

    def get_modules(self):
        return self._answer("get_modules", [
            {"from": "0x7f0000", "to": "0x7f1000",
             "target-name": "/lib/libc.so.6", "symbols-loaded": "1"},
        ])

    def resolve_static_address(self, static_address):
        return self._answer("resolve_static_address", "0x555555555136")

    def execute_console(self, command):
        self.calls.append(("execute_console", command))
        return self._answer("execute_console", "#0  main () at mal.c:12\n")


@pytest.fixture(scope="module")
def tools():
    """Register the GDB tools once and return them by name."""
    app = _real_fastmcp()("test")
    gdb_tools.register_gdb_tools(app)
    return asyncio.run(app.get_tools())


@pytest.fixture
def on_linux(monkeypatch):
    monkeypatch.setattr(gdb_tools.platform, "system", lambda: "Linux")


@pytest.fixture
def bridge(monkeypatch, on_linux):
    """Install a FakeBridge as the module singleton."""
    fake = FakeBridge()
    monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
    return fake


def _call(tools, name, **kwargs):
    return tools[name].fn(**kwargs)


def _fenced(text: str) -> bool:
    return UNTRUSTED_OPEN_SENTINEL in text and UNTRUSTED_END_MARKER in text


class TestRegistration:
    def test_registers_the_whole_surface(self, tools):
        assert len(tools) == 21

    def test_every_tool_is_gdb_prefixed(self, tools):
        """The catalog classifies this engine by prefix, so a stray name would
        register as uncategorized."""
        assert all(name.startswith("gdb_") for name in tools)

    def test_every_tool_has_a_docstring(self, tools):
        for name, tool in tools.items():
            assert tool.description, name


class TestPlatformGate:
    """Registration is unconditional; refusal happens per call."""

    @pytest.mark.parametrize("system", ["Windows", "Darwin", "FreeBSD"])
    def test_every_tool_refuses_off_linux(self, tools, monkeypatch, system):
        monkeypatch.setattr(gdb_tools.platform, "system", lambda: system)
        # Arguments that satisfy each signature; the gate must fire before any
        # of them is looked at.
        args = {
            "gdb_load_binary": {"binary_path": "/samples/mal.elf"},
            "gdb_attach": {"pid": 1234},
            "gdb_set_breakpoint": {"address": "0x401136"},
            "gdb_delete_breakpoint": {"address": "0x401136"},
            "gdb_read_memory": {"address": "0x401136"},
            "gdb_write_memory": {"address": "0x401136", "data": "90"},
            "gdb_disassemble": {"address": "0x401136"},
            "gdb_resolve_static_address": {"static_address": "0x1136"},
            "gdb_execute_console": {"command": "backtrace"},
        }
        for name in tools:
            result = _call(tools, name, **args.get(name, {}))
            assert result == gdb_tools._PLATFORM_MSG, name

    def test_the_platform_message_names_the_alternatives(self):
        """A refusal that does not say where to go next costs the model a turn."""
        assert "x64dbg" in gdb_tools._PLATFORM_MSG
        assert "WinDbg" in gdb_tools._PLATFORM_MSG

    def test_macos_is_refused_with_its_reason(self, tools, monkeypatch):
        """macOS is out of scope deliberately, not by oversight."""
        monkeypatch.setattr(gdb_tools.platform, "system", lambda: "Darwin")
        assert "macOS" in _call(tools, "gdb_status")

    def test_the_gate_fires_before_the_bridge_is_built(self, tools, monkeypatch):
        """Off Linux, no tool may construct a session -- that would resolve a
        GDB executable and start a subprocess on a platform we refuse."""
        monkeypatch.setattr(gdb_tools.platform, "system", lambda: "Windows")
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", None)

        def explode():
            raise AssertionError("the platform gate let a bridge be built")

        monkeypatch.setattr(gdb_tools, "get_gdb_bridge", explode)
        assert _call(tools, "gdb_run") == gdb_tools._PLATFORM_MSG


class TestStatus:
    def test_reports_no_session_without_building_one(self, tools, monkeypatch, on_linux):
        """gdb_status is the discovery call, so it must answer on a host with
        no GDB installed rather than raising from the getter."""
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", None)

        def explode():
            raise AssertionError("gdb_status built a bridge")

        monkeypatch.setattr(gdb_tools, "get_gdb_bridge", explode)
        result = _call(tools, "gdb_status")
        assert "No GDB session" in result
        assert "gdb_load_binary" in result

    def test_reports_the_location_when_stopped(self, tools, bridge):
        result = _call(tools, "gdb_status")
        assert "breakpoint-hit" in result
        assert "0x401136" in result

    def test_reports_a_bare_state_when_not_running(self, tools, monkeypatch, on_linux):
        monkeypatch.setattr(
            gdb_tools, "_gdb_bridge", FakeBridge(state=DebuggerState.LOADED)
        )
        assert _call(tools, "gdb_status") == "State: loaded"


class TestLoadBinaryConfinement:
    def test_confines_the_path_before_touching_gdb(
        self, tools, monkeypatch, on_linux, tmp_path
    ):
        """The engine's link-base read opens the file, so a confinement check
        after the fact would already have followed a traversal."""
        fake = FakeBridge()
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)

        def deny(path, *a, **kw):
            raise gdb_tools.PathTraversalError("Access denied")

        monkeypatch.setattr(gdb_tools, "sanitize_binary_path", deny)
        result = _call(tools, "gdb_load_binary", binary_path="/etc/shadow")
        assert fake.calls == [], "GDB was told about a path that was refused"
        assert "/etc/shadow" not in result

    def test_a_confined_path_reaches_the_bridge(
        self, tools, monkeypatch, on_linux, tmp_path
    ):
        sample = tmp_path / "mal.elf"
        sample.write_bytes(b"\x7fELF")
        fake = FakeBridge()
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        monkeypatch.setattr(gdb_tools, "sanitize_binary_path", lambda p, *a, **k: sample)

        result = _call(
            tools, "gdb_load_binary", binary_path=str(sample), args=["--verbose"]
        )
        assert ("load_binary", str(sample), ["--verbose"]) in fake.calls
        assert "mal.elf" in result

    def test_reports_only_the_basename(self, tools, monkeypatch, on_linux, tmp_path):
        """Audit F-10: a path the server resolved must not be echoed."""
        sample = tmp_path / "nested" / "deep" / "mal.elf"
        sample.parent.mkdir(parents=True)
        sample.write_bytes(b"\x7fELF")
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", FakeBridge())
        monkeypatch.setattr(gdb_tools, "sanitize_binary_path", lambda p, *a, **k: sample)

        result = _call(tools, "gdb_load_binary", binary_path=str(sample))
        assert "mal.elf" in result
        assert str(sample.parent) not in result

    def test_connects_first_when_no_session_is_up(
        self, tools, monkeypatch, on_linux, tmp_path
    ):
        sample = tmp_path / "mal.elf"
        sample.write_bytes(b"\x7fELF")
        fake = FakeBridge(connected=False)
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        monkeypatch.setattr(gdb_tools, "sanitize_binary_path", lambda p, *a, **k: sample)

        _call(tools, "gdb_load_binary", binary_path=str(sample))
        assert fake.calls[0] == ("connect",)

    def test_loading_does_not_run_the_sample(
        self, tools, monkeypatch, on_linux, tmp_path
    ):
        """The documented claim: only gdb_run executes anything."""
        sample = tmp_path / "mal.elf"
        sample.write_bytes(b"\x7fELF")
        fake = FakeBridge()
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        monkeypatch.setattr(gdb_tools, "sanitize_binary_path", lambda p, *a, **k: sample)

        _call(tools, "gdb_load_binary", binary_path=str(sample))
        assert not any(call[0] == "run" for call in fake.calls)


class TestExecutionControl:
    def test_run_defaults_to_stopping_at_the_entry_point(self, tools, bridge):
        _call(tools, "gdb_run")
        assert ("run", "entry") in bridge.calls

    def test_run_passes_the_requested_stop_point(self, tools, bridge):
        _call(tools, "gdb_run", stop_at="main")
        assert ("run", "main") in bridge.calls

    def test_run_free_says_the_target_is_unsupervised(
        self, tools, monkeypatch, on_linux
    ):
        fake = FakeBridge(run=DebuggerState.RUNNING)
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_run", stop_at="none")
        assert "unsupervised" in result
        assert "gdb_pause" in result

    def test_an_invalid_stop_point_is_reported_not_silently_defaulted(
        self, tools, monkeypatch, on_linux
    ):
        fake = FakeBridge(run=GdbBridgeError("stop_at must be 'entry'"))
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_run", stop_at="whenever")
        assert "Reference ID" in result or "stop_at" in result

    def test_continue_refuses_when_the_target_is_not_stopped(
        self, tools, monkeypatch, on_linux
    ):
        fake = FakeBridge(state=DebuggerState.RUNNING)
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_continue")
        assert "not stopped" in result
        assert not any(call[0] == "run" for call in fake.calls)

    def test_continue_resumes_a_stopped_target(self, tools, bridge):
        _call(tools, "gdb_continue")
        assert ("run", "entry") in bridge.calls

    @pytest.mark.parametrize(
        "tool,method",
        [("gdb_step_into", "step_into"), ("gdb_step_over", "step_over"),
         ("gdb_step_out", "step_out"), ("gdb_pause", "pause")],
    )
    def test_execution_tools_reach_their_method(self, tools, bridge, tool, method):
        _call(tools, tool)
        assert any(call[0] == method for call in bridge.calls)


class TestBreakpoints:
    def test_set_passes_the_address_through(self, tools, bridge):
        result = _call(tools, "gdb_set_breakpoint", address="0x401136")
        assert ("set_breakpoint", "0x401136") in bridge.calls
        assert "0x401136" in result

    def test_delete_passes_the_address_through(self, tools, bridge):
        _call(tools, "gdb_delete_breakpoint", address="0x401136")
        assert ("delete_breakpoint", "0x401136") in bridge.calls

    def test_an_unknown_address_reports_why(self, tools, monkeypatch, on_linux):
        fake = FakeBridge(
            delete_breakpoint=GdbBridgeError("no breakpoint was set at that address")
        )
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_delete_breakpoint", address="0xdeadbeef")
        assert "Reference ID" in result or "no breakpoint" in result

    def test_an_empty_list_is_said_plainly(self, tools, monkeypatch, on_linux):
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", FakeBridge(list_breakpoints=[]))
        assert _call(tools, "gdb_list_breakpoints") == "No breakpoints set."

    def test_the_listing_fences_its_symbol_text(self, tools, bridge):
        """func/file come from the binary's own symbols."""
        result = _call(tools, "gdb_list_breakpoints")
        assert _fenced(result)
        assert "1 breakpoint(s)" in result.split(UNTRUSTED_OPEN_SENTINEL)[0]


class TestWriteMemoryValidation:
    """The tool owns hex parsing, so these cases never reach the engine."""

    def test_accepts_plain_hex(self, tools, bridge):
        _call(tools, "gdb_write_memory", address="0x401136", data="9090c3")
        assert ("write_memory", "0x401136", b"\x90\x90\xc3") in bridge.calls

    def test_accepts_whitespace_and_an_0x_prefix(self, tools, bridge):
        _call(tools, "gdb_write_memory", address="0x401136", data="0x90 90 c3")
        assert ("write_memory", "0x401136", b"\x90\x90\xc3") in bridge.calls

    def test_rejects_an_odd_digit_count(self, tools, bridge):
        result = _call(tools, "gdb_write_memory", address="0x401136", data="909")
        assert "even number" in result
        assert bridge.calls == []

    def test_rejects_non_hex(self, tools, bridge):
        result = _call(tools, "gdb_write_memory", address="0x401136", data="zz")
        assert "not valid hex" in result
        assert bridge.calls == []

    def test_rejects_empty_data(self, tools, bridge):
        result = _call(tools, "gdb_write_memory", address="0x401136", data="   ")
        assert "No bytes" in result
        assert bridge.calls == []

    def test_caps_the_write_size(self, tools, bridge):
        oversized = "90" * (gdb_tools._MAX_WRITE_BYTES + 1)
        result = _call(tools, "gdb_write_memory", address="0x401136", data=oversized)
        assert "limit" in result
        assert bridge.calls == []

    def test_a_write_at_the_cap_is_allowed(self, tools, bridge):
        at_cap = "90" * gdb_tools._MAX_WRITE_BYTES
        _call(tools, "gdb_write_memory", address="0x401136", data=at_cap)
        assert any(call[0] == "write_memory" for call in bridge.calls)


class TestUntrustedEnvelope:
    """F-7: everything rendered from the debugged process is fenced."""

    @pytest.mark.parametrize(
        "tool,kwargs",
        [
            ("gdb_read_memory", {"address": "0x401136"}),
            ("gdb_disassemble", {"address": "0x401136"}),
            ("gdb_get_registers", {}),
            ("gdb_get_modules", {}),
            ("gdb_list_breakpoints", {}),
            ("gdb_execute_console", {"command": "backtrace"}),
            ("gdb_status", {}),
        ],
    )
    def test_sample_derived_output_is_fenced(self, tools, bridge, tool, kwargs):
        assert _fenced(_call(tools, tool, **kwargs)), tool

    def test_the_hexdump_ascii_column_is_inside_the_envelope(self, tools, bridge):
        """The ASCII column is the most direct sample-authored channel here."""
        result = _call(tools, "gdb_read_memory", address="0x401136")
        body = result.split(UNTRUSTED_OPEN_SENTINEL)[1]
        assert "00 01 02" in body

    def test_the_header_stays_outside_the_envelope(self, tools, bridge):
        """Server-authored text outside, sample text inside: the contrast is
        what makes the boundary informative."""
        result = _call(tools, "gdb_read_memory", address="0x401136")
        assert result.split(UNTRUSTED_OPEN_SENTINEL)[0].startswith("Memory at")

    def test_rebasing_is_not_fenced(self, tools, bridge):
        """It returns this server's own arithmetic over two integers and
        carries no text from the target, so an envelope would be noise."""
        result = _call(tools, "gdb_resolve_static_address", static_address="0x1136")
        assert not _fenced(result)
        assert "0x555555555136" in result

    def test_empty_console_output_is_not_wrapped(self, tools, monkeypatch, on_linux):
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", FakeBridge(execute_console="  "))
        result = _call(tools, "gdb_execute_console", command="backtrace")
        assert result == "Command produced no output."


class TestErrorHygiene:
    """Audit F-10: GdbBridgeError routinely carries GDB's own diagnostic text,
    which quotes the sample path and the server's working directory."""

    def test_a_bridge_error_does_not_leak_its_detail(
        self, tools, monkeypatch, on_linux
    ):
        leak = "/home/analyst/secret-samples/mal.elf: No such file"
        monkeypatch.setattr(
            gdb_tools, "_gdb_bridge", FakeBridge(read_memory=GdbBridgeError(leak))
        )
        result = _call(tools, "gdb_read_memory", address="0x401136")
        assert "secret-samples" not in result
        assert "Reference ID" in result

    def test_a_missing_gdb_is_reported_not_raised(
        self, tools, monkeypatch, on_linux
    ):
        """find_gdb() runs inside MISession.__init__, so 'gdb is not
        installed' surfaces from the getter rather than from a command."""
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", None)

        def no_gdb():
            raise MISessionError("GDB was not found")

        monkeypatch.setattr(gdb_tools, "get_gdb_bridge", no_gdb)
        result = _call(tools, "gdb_get_registers")
        assert isinstance(result, str)
        assert "Reference ID" in result

    @pytest.mark.parametrize(
        "tool,kwargs",
        [
            ("gdb_run", {}),
            ("gdb_continue", {}),
            ("gdb_pause", {}),
            ("gdb_step_into", {}),
            ("gdb_step_over", {}),
            ("gdb_step_out", {}),
            ("gdb_set_breakpoint", {"address": "0x401136"}),
            ("gdb_delete_breakpoint", {"address": "0x401136"}),
            ("gdb_list_breakpoints", {}),
            ("gdb_get_registers", {}),
            ("gdb_read_memory", {"address": "0x401136"}),
            ("gdb_disassemble", {"address": "0x401136"}),
            ("gdb_get_modules", {}),
            ("gdb_resolve_static_address", {"static_address": "0x1136"}),
            ("gdb_execute_console", {"command": "backtrace"}),
            ("gdb_attach", {"pid": 1}),
            ("gdb_detach", {}),
            ("gdb_status", {}),
        ],
    )
    def test_no_tool_raises_an_engine_error_at_the_client(
        self, tools, monkeypatch, on_linux, tool, kwargs
    ):
        """A raised exception crosses the MCP boundary as a protocol error with
        the raw text attached, which is both a leak and unusable to the model."""
        method = {
            "gdb_run": "run", "gdb_continue": "run", "gdb_pause": "pause",
            "gdb_step_into": "step_into", "gdb_step_over": "step_over",
            "gdb_step_out": "step_out", "gdb_set_breakpoint": "set_breakpoint",
            "gdb_delete_breakpoint": "delete_breakpoint",
            "gdb_list_breakpoints": "list_breakpoints",
            "gdb_get_registers": "get_registers",
            "gdb_read_memory": "read_memory", "gdb_disassemble": "disassemble",
            "gdb_get_modules": "get_modules",
            "gdb_resolve_static_address": "resolve_static_address",
            "gdb_execute_console": "execute_console", "gdb_attach": "attach",
            "gdb_detach": "detach", "gdb_status": "get_current_location",
        }[tool]
        fake = FakeBridge(**{method: GdbBridgeError("boom"), "get_state": None})
        fake._overrides["get_state"] = DebuggerState.PAUSED
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, tool, **kwargs)
        assert isinstance(result, str), tool


class TestConsoleAllowlist:
    def test_a_refused_command_never_reaches_gdb(self, tools, monkeypatch, on_linux):
        """The engine validates before sending; the tool must surface that
        rather than retrying or rewording."""
        fake = FakeBridge(
            execute_console=GdbBridgeError("console command refused: shell escape")
        )
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_execute_console", command="shell id")
        assert isinstance(result, str)
        assert "Reference ID" in result or "refused" in result

    def test_the_docstring_names_the_shell_escapes_it_blocks(self, tools):
        """A model reading only the docstring must learn why print and x are
        absent, or it will keep trying them."""
        description = tools["gdb_execute_console"].description
        assert "$_shell" in description
        assert "allowlist" in description

    def test_the_docstring_enumerates_what_is_permitted(self, tools):
        from src.engines.dynamic.gdb.allowlist import allowed_commands

        description = tools["gdb_execute_console"].description
        for command in allowed_commands():
            assert command in description, command


class TestSessionLifecycle:
    def test_disconnect_drops_the_singleton(self, tools, monkeypatch, on_linux):
        fake = FakeBridge()
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        _call(tools, "gdb_disconnect")
        assert gdb_tools._gdb_bridge is None
        assert ("disconnect",) in fake.calls

    def test_reset_survives_a_gdb_that_will_not_stop(self, monkeypatch):
        """The point of the reset is that the next getter builds a fresh
        bridge; a GDB that cannot be stopped must not make that impossible."""
        fake = FakeBridge(disconnect=GdbBridgeError("the subprocess is wedged"))
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        gdb_tools.reset_gdb_bridge()
        assert gdb_tools._gdb_bridge is None

    def test_attach_reports_where_the_process_stopped(self, tools, bridge):
        result = _call(tools, "gdb_attach", pid=4321)
        assert ("attach", 4321) in bridge.calls
        assert "0x401136" in result

    def test_a_yama_refusal_explains_itself(self, tools, monkeypatch, on_linux):
        """GDB's own error for a blocked attach does not mention ptrace_scope,
        which is why the engine checks it first."""
        fake = FakeBridge(attach=GdbBridgeError("Yama ptrace_scope is 1"))
        monkeypatch.setattr(gdb_tools, "_gdb_bridge", fake)
        result = _call(tools, "gdb_attach", pid=4321)
        assert isinstance(result, str)

    def test_detach_leaves_the_process_running(self, tools, bridge):
        result = _call(tools, "gdb_detach")
        assert ("detach",) in bridge.calls
        assert "continues running" in result


class TestSessionLogging:
    def test_calls_are_logged_as_dynamic_analysis(self, monkeypatch):
        """The manager's fallback infers the type from an x64dbg_ prefix and
        would file every GDB call as static, so the type is passed explicitly."""
        recorded = {}

        class Manager:
            active_session_id = "s1"

            def log_tool_call(self, **kwargs):
                recorded.update(kwargs)

        app = _real_fastmcp()("test-logging")
        gdb_tools.register_gdb_tools(app, Manager())
        try:
            registered = asyncio.run(app.get_tools())
            monkeypatch.setattr(gdb_tools.platform, "system", lambda: "Linux")
            monkeypatch.setattr(gdb_tools, "_gdb_bridge", FakeBridge())
            registered["gdb_get_registers"].fn()
        finally:
            gdb_tools._session_manager = None

        assert recorded["tool_name"] == "gdb_get_registers"
        assert recorded["analysis_type"] is gdb_tools.AnalysisType.DYNAMIC


class TestSourceDiscipline:
    SOURCE = Path("src/tools/gdb_tools.py").read_text(encoding="utf-8")

    def test_every_handler_returns_through_a_sanctioned_helper(self):
        """The complement of the repo-wide F-10 guard.

        test_error_hygiene forbids leaking an exception's text; this requires
        the positive form, that each handler routes through safe_tool_error or
        safe_path_error. A handler returning a hand-written string passes the
        prohibition while still losing the reference ID that makes a failure
        diagnosable from the server log.

        Asserted over the AST rather than the text, because the module
        docstring quotes the forbidden f-string pattern in order to explain
        it -- a substring scan flags its own documentation.
        """
        tree = ast.parse(self.SOURCE, filename="src/tools/gdb_tools.py")
        sanctioned = {"safe_tool_error", "safe_path_error"}
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            called = {
                sub.func.id
                for sub in ast.walk(node)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
            }
            logged = any(
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in ("warning", "error", "exception")
                for sub in ast.walk(node)
            )
            # A handler that validates the CALLER's own argument needs
            # neither: gdb_write_memory catching ValueError from
            # bytes.fromhex() returns a fixed instruction, and there is no
            # server-side detail to log or reference. Allowed only while every
            # return in it is a plain literal, so nothing can be interpolated.
            literal_only = all(
                isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str)
                for sub in ast.walk(node)
                if isinstance(sub, ast.Return) and sub.value is not None
            )
            if not (called & sanctioned) and not logged and not literal_only:
                offenders.append(node.lineno)

        assert not offenders, (
            "except handler(s) at line(s) "
            + ", ".join(str(n) for n in offenders)
            + " neither return through safe_tool_error/safe_path_error nor log"
        )

    def test_no_divider_comments(self):
        """Repo style: heading comments, no rules under them."""
        for line in self.SOURCE.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                content = stripped.lstrip("#").strip()
                assert not (content and set(content) <= set("-=*_~")), line
