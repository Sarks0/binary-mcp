"""Tests for the GDB debugger bridge.

Split in two. The offline tests drive the bridge against a scripted fake
session, so they run on every CI platform and can reproduce situations a real
GDB will not perform on demand, including a GDB that reports success for a
deletion it did not carry out. The live tests need a real gdb on Linux.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from src.engines.dynamic.base import DebuggerState
from src.engines.dynamic.gdb.bridge import (
    MAX_READ_BYTES,
    GdbBridge,
    GdbBridgeError,
    _normalise_address,
)
from src.engines.dynamic.gdb.mi_parser import MIRecord, RecordKind
from src.engines.dynamic.gdb.mi_session import MIResponse

GDB = shutil.which("gdb")
CC = shutil.which("gcc") or shutil.which("cc")

_SOURCE = """
#include <stdio.h>
int target(int x){ return x * 3; }
int main(int argc, char **argv){ printf("%d\\n", target(argc)); return 0; }
"""


def response(results=None, klass="done", console=""):
    record = MIRecord(
        kind=RecordKind.RESULT, raw="", klass=klass, results=results or {}
    )
    return MIResponse(record=record, console=[console] if console else [])


class FakeSession:
    """A scripted MISession stand-in.

    ``replies`` maps an MI command prefix to a response or a callable. The
    recorded ``sent`` list is what lets a test assert that an operation was
    verified rather than assumed.
    """

    def __init__(self, replies=None, alive=True):
        self.replies = replies or {}
        self.sent: list[str] = []
        self._alive = alive
        self.stopped_record = None
        self.stop_calls = 0

    @property
    def is_alive(self):
        return self._alive

    def start(self):
        self._alive = True

    def stop(self):
        self._alive = False

    def send(self, command, timeout=None):
        self.sent.append(command)
        for prefix, reply in self.replies.items():
            if command.startswith(prefix):
                return reply(command) if callable(reply) else reply
        return response()

    def drain_events(self):
        return []

    def wait_for_stop(self, timeout=None):
        self.stop_calls += 1
        return self.stopped_record


@pytest.fixture
def bridge():
    return GdbBridge(session=FakeSession())


class TestAddressNormalisation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("0x401136", "401136"),
            ("0X401136", "401136"),
            ("401136", "401136"),
            ("*0x401136", "401136"),
            ("0x00401136", "401136"),
            ("0x0", "0"),
            ("  0x401136  ", "401136"),
        ],
    )
    def test_equivalent_spellings_collapse(self, raw, expected):
        """The breakpoint map is keyed on this, so spellings must agree."""
        assert _normalise_address(raw) == expected


class TestAddressValidation:
    @pytest.mark.parametrize(
        "bad",
        ["main", "$pc", "0x401136; shell id", "$_shell(1)", "", "0xZZZ", "-1"],
    )
    def test_non_hex_addresses_are_refused(self, bridge, bad):
        """An address reaches MI inside a command string, so it is bounded."""
        with pytest.raises(GdbBridgeError, match="hexadecimal"):
            bridge.set_breakpoint(bad)

    def test_read_memory_rejects_non_positive_size(self, bridge):
        with pytest.raises(GdbBridgeError, match="positive"):
            bridge.read_memory("0x1000", 0)

    def test_read_memory_rejects_an_oversized_request(self, bridge):
        with pytest.raises(GdbBridgeError, match="read limit"):
            bridge.read_memory("0x1000", MAX_READ_BYTES + 1)


class TestBreakpointNumberMap:
    """The address-to-number map, which is what makes deletion possible."""

    def test_set_records_the_number_gdb_assigned(self):
        session = FakeSession(
            {"-break-insert": response({"bkpt": {"number": "7", "addr": "0x401136"}})}
        )
        bridge = GdbBridge(session=session)
        assert bridge.set_breakpoint("0x401136")
        assert bridge.breakpoints == {"401136": "7"}

    def test_set_fails_loudly_when_gdb_reports_no_number(self):
        """Without a number the breakpoint could never be deleted."""
        session = FakeSession({"-break-insert": response({"bkpt": {"addr": "0x1"}})})
        bridge = GdbBridge(session=session)
        with pytest.raises(GdbBridgeError, match="no number"):
            bridge.set_breakpoint("0x401136")

    def test_delete_uses_the_number_not_the_address(self):
        """MI deletes by number; -break-delete *0xADDR deletes nothing."""
        session = FakeSession(
            {
                "-break-insert": response({"bkpt": {"number": "3"}}),
                "-break-list": response(
                    {"BreakpointTable": {"nr_rows": "0", "body": []}}
                ),
            }
        )
        bridge = GdbBridge(session=session)
        bridge.set_breakpoint("0x401136")
        assert bridge.delete_breakpoint("0x401136")

        deletes = [c for c in session.sent if c.startswith("-break-delete")]
        assert deletes == ["-break-delete 3"]
        assert "*" not in deletes[0], "deleted by address, which is a silent no-op"
        assert bridge.breakpoints == {}

    def test_delete_of_an_unknown_address_is_refused(self, bridge):
        with pytest.raises(GdbBridgeError, match="no breakpoint was set"):
            bridge.delete_breakpoint("0x401136")

    def test_delete_catches_a_gdb_that_reports_success_but_does_nothing(self):
        """The §2.8 guard: ^done means accepted, not performed.

        This is the situation a real GDB will not produce on request, which is
        the reason for the fake: -break-delete answers ^done while -break-list
        still shows the breakpoint. Without the readback the bridge would
        report success and leave the target armed.
        """
        session = FakeSession(
            {
                "-break-insert": response({"bkpt": {"number": "5"}}),
                "-break-delete": response(),
                "-break-list": response(
                    {
                        "BreakpointTable": {
                            "nr_rows": "1",
                            "body": [{"bkpt": {"number": "5"}}],
                        }
                    }
                ),
            }
        )
        bridge = GdbBridge(session=session)
        bridge.set_breakpoint("0x401136")

        with pytest.raises(GdbBridgeError, match="still present"):
            bridge.delete_breakpoint("0x401136")
        assert bridge.breakpoints == {"401136": "5"}, "map must not drop a live entry"


class TestWriteMemoryReadback:
    def test_write_is_confirmed_by_reading_it_back(self):
        session = FakeSession(
            {
                "-data-write-memory-bytes": response(),
                "-data-read-memory-bytes": response(
                    {"memory": [{"contents": "deadbeef"}]}
                ),
            }
        )
        assert GdbBridge(session=session).write_memory("0x1000", bytes.fromhex("deadbeef"))

    def test_write_that_did_not_take_effect_is_an_error(self):
        session = FakeSession(
            {
                "-data-write-memory-bytes": response(),
                "-data-read-memory-bytes": response(
                    {"memory": [{"contents": "00000000"}]}
                ),
            }
        )
        with pytest.raises(GdbBridgeError, match="read back differ"):
            GdbBridge(session=session).write_memory("0x1000", bytes.fromhex("deadbeef"))

    def test_empty_write_is_refused(self, bridge):
        with pytest.raises(GdbBridgeError, match="no bytes"):
            bridge.write_memory("0x1000", b"")


class TestRegisterNameMapping:
    def test_numbers_are_mapped_through_the_cached_name_list(self):
        session = FakeSession(
            {
                "-data-list-register-names": response(
                    {"register-names": ["rax", "rbx", "rcx"]}
                ),
                "-data-list-register-values": response(
                    {
                        "register-values": [
                            {"number": "0", "value": "0x1"},
                            {"number": "2", "value": "0x3"},
                        ]
                    }
                ),
            }
        )
        bridge = GdbBridge(session=session)
        assert bridge.get_registers() == {"rax": "0x1", "rcx": "0x3"}

    def test_names_are_fetched_once_per_session(self):
        session = FakeSession(
            {
                "-data-list-register-names": response({"register-names": ["rax"]}),
                "-data-list-register-values": response(
                    {"register-values": [{"number": "0", "value": "0x1"}]}
                ),
            }
        )
        bridge = GdbBridge(session=session)
        bridge.get_registers()
        bridge.get_registers()
        assert session.sent.count("-data-list-register-names") == 1


class TestConsoleGating:
    def test_allowlisted_command_is_sent(self):
        session = FakeSession(
            {"-interpreter-exec console": response(console="mappings\n")}
        )
        bridge = GdbBridge(session=session)
        assert bridge.execute_console("info proc mappings") == "mappings\n"

    @pytest.mark.parametrize(
        "payload",
        ["shell id", "python print(1)", 'print $_shell("id")', "pipe show version | id"],
    )
    def test_escapes_are_refused_before_being_sent(self, payload):
        session = FakeSession()
        bridge = GdbBridge(session=session)
        with pytest.raises(GdbBridgeError, match="refused"):
            bridge.execute_console(payload)
        assert session.sent == [], "a refused command must never reach GDB"


class TestLoadDoesNotRun:
    def test_load_binary_sends_no_execution_command(self, tmp_path):
        """The target is a sample; loading it must not detonate it."""
        binary = tmp_path / "sample.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)

        session = FakeSession()
        bridge = GdbBridge(session=session)
        bridge.load_binary(binary)

        assert not any(c.startswith("-exec-run") for c in session.sent)
        assert not any(c.startswith("-exec-continue") for c in session.sent)
        assert bridge.get_state() is DebuggerState.LOADED

    def test_arguments_are_quoted(self, tmp_path):
        binary = tmp_path / "sample.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        session = FakeSession()
        GdbBridge(session=session).load_binary(binary, ["--in", "/tmp/a b/c"])
        args = [c for c in session.sent if c.startswith("-exec-arguments")]
        assert args == ['-exec-arguments "--in" "/tmp/a b/c"']

    def test_run_rejects_an_unknown_stop_point(self, bridge):
        with pytest.raises(GdbBridgeError, match="stop_at"):
            bridge.run(stop_at="whenever")


class TestRebasing:
    def test_requires_a_loaded_binary(self, bridge):
        with pytest.raises(GdbBridgeError, match="no binary is loaded"):
            bridge.resolve_static_address("0x1149")

    def test_requires_a_started_target(self, tmp_path, monkeypatch):
        """A PIE has no load base until it is mapped, so this must not guess."""
        binary = tmp_path / "sample.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        bridge = GdbBridge(session=FakeSession())
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge._read_elf_link_base", lambda _p: 0
        )
        bridge.load_binary(binary)
        with pytest.raises(GdbBridgeError, match="load base is not known"):
            bridge.resolve_static_address("0x1149")

    def test_arithmetic_for_a_pie_target(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        bridge = GdbBridge(session=FakeSession())
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge._read_elf_link_base", lambda _p: 0
        )
        bridge.load_binary(binary)
        bridge._state = DebuggerState.PAUSED
        bridge._load_base = 0x555555554000
        assert bridge.resolve_static_address("0x1149") == "0x555555555149"

    def test_arithmetic_is_the_identity_for_a_non_pie_target(self, tmp_path, monkeypatch):
        binary = tmp_path / "sample.elf"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 64)
        bridge = GdbBridge(session=FakeSession())
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge._read_elf_link_base", lambda _p: 0x400000
        )
        bridge.load_binary(binary)
        bridge._state = DebuggerState.PAUSED
        bridge._load_base = 0x400000
        assert bridge.resolve_static_address("0x401136") == "0x401136"


class TestPlatformScope:
    def test_connect_refuses_off_linux_and_names_the_alternative(self, monkeypatch):
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge.platform.system", lambda: "Windows"
        )
        bridge = GdbBridge(session=FakeSession())
        with pytest.raises(GdbBridgeError, match="x64dbg"):
            bridge.connect()


class TestAttachPreflight:
    def test_yama_scope_blocks_attach_with_an_actionable_message(self, monkeypatch):
        """GDB's own error does not mention ptrace_scope, so this one does."""
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge._ptrace_scope", lambda: 1
        )
        bridge = GdbBridge(session=FakeSession())
        with pytest.raises(GdbBridgeError, match="ptrace_scope"):
            bridge.attach(4242)

    def test_attach_proceeds_when_yama_is_absent(self, monkeypatch):
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.bridge._ptrace_scope", lambda: None
        )
        session = FakeSession()
        assert GdbBridge(session=session).attach(4242)
        assert "-target-attach 4242" in session.sent

    def test_non_positive_pid_is_refused(self, bridge):
        with pytest.raises(GdbBridgeError, match="pid must be positive"):
            bridge.attach(0)


class TestErrorHygiene:
    def test_failures_do_not_echo_the_sample_path(self, tmp_path):
        """A refusal message reaches the model; a host path must not."""
        secret = tmp_path / "secret-sample.elf"
        secret.write_bytes(b"\x7fELF" + b"\x00" * 64)
        session = FakeSession(
            {"-file-exec-and-symbols": response({"msg": "No such file"}, klass="error")}
        )
        bridge = GdbBridge(session=session)
        with pytest.raises(GdbBridgeError) as excinfo:
            bridge.load_binary(secret)
        assert "secret-sample.elf" not in str(excinfo.value)


live = pytest.mark.skipif(GDB is None, reason="gdb not installed")
linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="the GDB engine is Linux-scoped"
)


@pytest.fixture(scope="module")
def pie_binary(tmp_path_factory):
    if CC is None:
        pytest.skip("no compiler available")
    import subprocess

    tmp = tmp_path_factory.mktemp("gdb_bridge")
    src = tmp / "t.c"
    src.write_text(_SOURCE)
    out = tmp / "t_pie"
    proc = subprocess.run(
        [CC, "-O0", "-g", "-o", str(out), str(src)], capture_output=True, text=True
    )
    if proc.returncode != 0:
        pytest.skip(f"compiler failed: {proc.stderr.strip()[:200]}")
    return out


@live
@linux_only
class TestLiveBridge:
    @pytest.fixture
    def connected(self, pie_binary):
        bridge = GdbBridge(timeout=25)
        bridge.connect()
        bridge.load_binary(pie_binary)
        yield bridge
        bridge.disconnect()

    def test_loading_does_not_start_the_target(self, connected):
        assert connected.get_state() is DebuggerState.LOADED

    def test_run_to_entry_then_breakpoint_on_a_rebased_address(self, connected):
        assert connected.run(stop_at="entry") is DebuggerState.PAUSED

        runtime = connected.resolve_static_address("0x1149")
        assert int(runtime, 16) > 0x1149, "a PIE address must relocate upward"

        assert connected.set_breakpoint(runtime)
        assert connected.breakpoints

        connected.run()
        location = connected.get_current_location()
        assert location.get("stop_reason") == "breakpoint-hit"
        assert location.get("function") == "target"

    def test_registers_are_named_not_numbered(self, connected):
        connected.run(stop_at="entry")
        registers = connected.get_registers()
        assert "rip" in registers and "rsp" in registers
        assert registers["rip"].startswith("0x")

    def test_memory_round_trip_at_the_stack_pointer(self, connected):
        connected.run(stop_at="entry")
        address = connected.get_registers()["rsp"]
        original = connected.read_memory(address, 8)
        assert len(original) == 8

        connected.write_memory(address, b"\xde\xad\xbe\xef" + original[4:])
        assert connected.read_memory(address, 4) == b"\xde\xad\xbe\xef"
        connected.write_memory(address, original)
        assert connected.read_memory(address, 8) == original

    def test_breakpoint_deletion_actually_deletes(self, connected):
        connected.run(stop_at="entry")
        runtime = connected.resolve_static_address("0x1149")
        connected.set_breakpoint(runtime)
        assert len(connected.list_breakpoints()) >= 1

        assert connected.delete_breakpoint(runtime)
        assert connected.breakpoints == {}
        assert connected.list_breakpoints() == []

    def test_stepping_advances_the_program_counter(self, connected):
        connected.run(stop_at="entry")
        before = int(connected.get_registers()["rip"], 16)
        connected.step_into()
        after = int(connected.get_registers()["rip"], 16)
        assert after != before

    def test_console_is_gated_against_a_real_gdb(self, connected):
        connected.run(stop_at="entry")
        assert "Mapped address spaces" in connected.execute_console("info proc mappings")
        with pytest.raises(GdbBridgeError, match="refused"):
            connected.execute_console("shell touch /tmp/should_not_exist_gdb_bridge")
        assert not Path("/tmp/should_not_exist_gdb_bridge").exists()
