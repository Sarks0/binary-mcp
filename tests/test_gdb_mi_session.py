"""Tests for the GDB/MI session transport.

Split in two. The routing, correlation and validation tests drive the session
object directly without spawning anything, so they run on every CI platform.
The live tests need a real ``gdb`` and skip without one; they pin the
behaviours that motivated the design -- hardening that actually applies, and a
command reply that arrives before the stop event it triggered.
"""

from __future__ import annotations

import queue
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from src.engines.dynamic.gdb.mi_parser import MIRecord, RecordKind
from src.engines.dynamic.gdb.mi_session import (
    MIResponse,
    MISession,
    MISessionClosedError,
    MISessionError,
    MITimeoutError,
    _setting_holds,
    find_gdb,
)

GDB = shutil.which("gdb")
CC = shutil.which("gcc") or shutil.which("cc")

_SOURCE = """
#include <stdio.h>
int target(int x){ return x * 3; }
int main(int argc, char **argv){ printf("%d\\n", target(argc)); return 0; }
"""

_SPINNER = "int main(void){ volatile long i = 0; while (1) { i++; } }\n"


@pytest.fixture
def offline_session():
    """A session object that never spawns GDB.

    ``find_gdb`` returns an explicit path unchanged, so this constructs
    cleanly on a machine with no debugger at all.
    """
    return MISession(gdb_path="/nonexistent/gdb", timeout=1)


class TestFindGdb:
    def test_explicit_path_wins(self):
        assert find_gdb("/opt/custom/gdb") == "/opt/custom/gdb"

    def test_falls_back_to_config(self, monkeypatch):
        monkeypatch.setenv("GDB_PATH", "/opt/from/config/gdb")
        assert find_gdb() == "/opt/from/config/gdb"

    def test_reports_absence_without_leaking_host_layout(self, monkeypatch):
        monkeypatch.delenv("GDB_PATH", raising=False)
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.mi_session.get_config", lambda *a, **k: None
        )
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.mi_session.shutil.which", lambda _: None
        )
        with pytest.raises(MISessionError) as excinfo:
            find_gdb()
        message = str(excinfo.value)
        assert "GDB_PATH" in message
        assert str(Path.home()) not in message


class TestCommandValidation:
    def test_rejects_empty_command(self, offline_session):
        with pytest.raises(MISessionError):
            offline_session.send("")

    def test_rejects_padded_command(self, offline_session):
        with pytest.raises(MISessionError):
            offline_session.send("  -break-list  ")

    def test_rejects_caller_supplied_token(self, offline_session):
        """Tokens are this module's to assign; a caller one breaks correlation."""
        with pytest.raises(MISessionError):
            offline_session.send("42-break-list")

    def test_send_on_a_dead_session_raises_closed(self, offline_session):
        with pytest.raises(MISessionClosedError):
            offline_session.send("-break-list")


class TestRouting:
    """The reader thread's classification, exercised without a process."""

    def test_async_records_go_to_the_event_queue(self, offline_session):
        offline_session._route('*stopped,reason="breakpoint-hit",thread-id="1"')
        offline_session._route('=library-loaded,id="/lib/libc.so.6"')
        events = offline_session.drain_events()
        assert [e.klass for e in events] == ["stopped", "library-loaded"]
        assert offline_session.drain_events() == []

    def test_async_record_never_satisfies_a_pending_command(self, offline_session):
        reply: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[1] = reply
        offline_session._route('*stopped,reason="breakpoint-hit"')
        assert reply.empty(), "an exec record was delivered as a command reply"

    def test_result_is_delivered_to_the_matching_token(self, offline_session):
        first: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        second: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[7] = first
        offline_session._pending[8] = second

        offline_session._route('8^done,value="second"')
        assert first.empty()
        assert second.get_nowait().results["value"] == "second"

    def test_untokened_result_attributes_to_a_lone_waiter(self, offline_session):
        reply: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[3] = reply
        offline_session._route("^done")
        assert reply.get_nowait().klass == "done"

    def test_untokened_result_is_dropped_when_ambiguous(self, offline_session):
        first: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        second: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[1] = first
        offline_session._pending[2] = second
        offline_session._route("^done")
        assert first.empty() and second.empty()

    def test_stream_records_are_collected_only_while_in_flight(self, offline_session):
        offline_session._route(r'~"ignored, nothing in flight\n"')
        assert offline_session._inflight_console == []

        offline_session._collecting = True
        offline_session._route(r'~"Breakpoint 1, target (x=1)\n"')
        offline_session._route(r'&"warning: no source\n"')
        assert offline_session._inflight_console == ["Breakpoint 1, target (x=1)\n"]
        assert offline_session._inflight_log == ["warning: no source\n"]

    def test_unparseable_line_does_not_kill_the_reader(self, offline_session):
        """A malformed record must not strand every waiting command."""
        offline_session._route('^done,bkpt={number="1"')
        offline_session._route('*stopped,reason="exited-normally"')
        assert [e.klass for e in offline_session.drain_events()] == ["stopped"]

    def test_inferior_output_is_ignored_not_misrouted(self, offline_session):
        reply: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[1] = reply
        offline_session._route("uid=0(root) gid=0(root)")
        assert reply.empty()
        assert offline_session.drain_events() == []


class TestTeardown:
    def test_fail_pending_unblocks_waiters_with_an_error(self, offline_session):
        reply: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
        offline_session._pending[1] = reply
        offline_session._fail_pending()
        record = reply.get_nowait()
        assert record.is_error
        assert offline_session._pending == {}

    def test_stop_without_start_is_a_noop(self, offline_session):
        offline_session.stop()
        assert not offline_session.is_alive

    def test_wait_for_stop_returns_none_when_not_running(self, offline_session):
        assert offline_session.wait_for_stop(timeout=0.2) is None


class TestTimeout:
    def test_timeout_names_the_operation_but_not_its_arguments(self, monkeypatch):
        """A command can carry a sample path; the error must not repeat it."""
        session = MISession(gdb_path="/nonexistent/gdb", timeout=0.2)
        monkeypatch.setattr(type(session), "is_alive", property(lambda _: True))
        monkeypatch.setattr(session, "_write", lambda _line: None)

        with pytest.raises(MITimeoutError) as excinfo:
            session.send("-file-exec-and-symbols /srv/samples/secret-malware.elf")
        message = str(excinfo.value)
        assert "-file-exec-and-symbols" in message
        assert "secret-malware.elf" not in message


class TestSettingVerification:
    """_setting_holds: what counts as a setting having taken effect."""

    @staticmethod
    def _response(results, error=False):
        record = MIRecord(
            kind=RecordKind.RESULT,
            raw="",
            klass="error" if error else "done",
            results=results,
        )
        return MIResponse(record=record)

    def test_scalar_setting(self):
        assert _setting_holds(self._response({"value": "off"}), "off")
        assert not _setting_holds(self._response({"value": "on"}), "off")

    def test_error_reply_never_counts_as_applied(self):
        assert not _setting_holds(self._response({}, error=True), "off")

    def test_prefix_setting_requires_every_toggle(self):
        holds = self._response(
            {"showlist": {"option": [
                {"name": "gdb-scripts", "value": "off"},
                {"name": "local-gdbinit", "value": "off"},
            ]}}
        )
        assert _setting_holds(holds, "off")

        partial = self._response(
            {"showlist": {"option": [
                {"name": "gdb-scripts", "value": "off"},
                {"name": "local-gdbinit", "value": "on"},
            ]}}
        )
        assert not _setting_holds(partial, "off")

    def test_path_sub_options_are_not_toggles(self):
        """`set auto-load off` leaves safe-path and scripts-directory as paths.

        Verified on GNU gdb 15.1. Demanding "off" from them would fail a
        session that is correctly hardened.
        """
        response = self._response(
            {"showlist": {"option": [
                {"name": "gdb-scripts", "value": "off"},
                {"name": "libthread-db", "value": "off"},
                {"name": "local-gdbinit", "value": "off"},
                {"name": "python-scripts", "value": "off"},
                {"name": "safe-path", "value": "$debugdir:$datadir/auto-load"},
                {"name": "scripts-directory", "value": "$debugdir:$datadir/auto-load"},
            ]}}
        )
        assert _setting_holds(response, "off")


class TestHardeningPolicy:
    """start() decides what an absent setting means, per platform."""

    @staticmethod
    def _session_with_missing_setting(monkeypatch, platform):
        session = MISession(gdb_path="/nonexistent/gdb", timeout=1)
        monkeypatch.setattr(
            "src.engines.dynamic.gdb.mi_session.sys.platform", platform
        )
        monkeypatch.setattr(session, "stop", lambda: None)

        def fake_send(command, timeout=None):
            error = command == "-gdb-show startup-with-shell"
            record = MIRecord(
                kind=RecordKind.RESULT,
                raw="",
                klass="error" if error else "done",
                results={"msg": "Undefined show command."} if error
                else {"value": "off"},
            )
            return MIResponse(record=record)

        monkeypatch.setattr(session, "send", fake_send)
        return session

    def test_absent_posix_setting_is_tolerated_off_linux(self, monkeypatch):
        """Windows GDB has no startup-with-shell; the risk is absent too."""
        session = self._session_with_missing_setting(monkeypatch, "win32")
        from src.engines.dynamic.gdb.mi_session import _HARDENING

        setting = next(h for h in _HARDENING if h.name == "startup-with-shell")
        session._apply_hardening(setting)
        assert session.hardening_report["startup-with-shell"] == "absent"

    def test_absent_posix_setting_is_fatal_on_linux(self, monkeypatch):
        """On Linux the shell-launch path is real, so absence fails closed."""
        session = self._session_with_missing_setting(monkeypatch, "linux")
        from src.engines.dynamic.gdb.mi_session import _HARDENING

        setting = next(h for h in _HARDENING if h.name == "startup-with-shell")
        with pytest.raises(MISessionError, match="startup-with-shell"):
            session._apply_hardening(setting)


live = pytest.mark.skipif(GDB is None, reason="gdb not installed")


@pytest.fixture(scope="module")
def compiled_targets():
    if CC is None:
        pytest.skip("no compiler available")
    tmp = Path(tempfile.mkdtemp(prefix="gdb_mi_session_"))
    built = {}
    for name, source, flags in (
        ("t_pie", _SOURCE, ["-O0", "-g"]),
        ("spin", _SPINNER, ["-O0"]),
    ):
        src = tmp / f"{name}.c"
        src.write_text(source)
        out = tmp / name
        proc = subprocess.run(
            [CC, *flags, "-o", str(out), str(src)], capture_output=True, text=True
        )
        if proc.returncode != 0:
            pytest.skip(f"compiler failed: {proc.stderr.strip()[:200]}")
        built[name] = out
    return built


@pytest.fixture
def session():
    s = MISession(timeout=20)
    s.start()
    yield s
    s.stop()


@live
class TestLiveSession:
    def test_start_applies_the_portable_hardening_settings(self, session):
        for setting, expected in (("confirm", "off"), ("mi-async", "on")):
            response = session.send(f"-gdb-show {setting}")
            assert response.results.get("value") == expected, setting

    @pytest.mark.skipif(sys.platform != "linux", reason="POSIX-only setting")
    def test_startup_with_shell_is_off_on_linux(self, session):
        """The setting that stops the inferior being launched via /bin/sh.

        Windows GDB has no such command -- it creates the process directly --
        so this is asserted only where the shell-launch path exists.
        """
        assert session.send("-gdb-show startup-with-shell").results["value"] == "off"
        assert session.hardening_report["startup-with-shell"] == "applied"

    def test_hardening_report_covers_every_setting(self, session):
        report = session.hardening_report
        assert set(report) == {
            "confirm",
            "startup-with-shell",
            "auto-load",
            "mi-async",
        }
        assert all(state in ("applied", "absent") for state in report.values())
        # Only the POSIX-only one may be absent, and only off Linux.
        for name, state in report.items():
            if state == "absent":
                assert name == "startup-with-shell" and sys.platform != "linux"

    @pytest.mark.skipif(sys.platform != "linux", reason="Unix-only auto-load prefix")
    def test_auto_load_is_off_which_nx_alone_does_not_achieve(self, session):
        """--nx skips named init files; the cwd .gdbinit needs auto-load off.

        Verified on GNU gdb 15.1: a --nx session still reports local-gdbinit
        ON, so a sample shipping a .gdbinit beside itself would run code in
        the debugger. This pins the setting that closes it.
        """
        response = session.send('-interpreter-exec console "show auto-load local-gdbinit"')
        assert "is off" in response.console_text

    def test_every_reply_matches_its_own_token(self, session):
        for expected in range(1, 16):
            response = session.send(f"-data-evaluate-expression {expected}+0")
            assert response.record.token is not None
            assert response.results["value"] == str(expected)

    def test_error_reply_is_returned_not_raised(self, session):
        response = session.send("-break-insert no_such_symbol_xyz")
        assert response.is_error
        assert response.error_message

    def test_run_to_breakpoint_and_wait_for_stop(self, session, compiled_targets):
        session.send(f"-file-exec-and-symbols {compiled_targets['t_pie']}")
        inserted = session.send("-break-insert target")
        assert not inserted.is_error

        session.send("-exec-run")
        stop = session.wait_for_stop(timeout=20)
        assert stop is not None, "no *stopped record arrived"
        assert stop.results.get("reason") == "breakpoint-hit"

    def test_interrupt_reply_precedes_the_stop_record(self, session, compiled_targets):
        """The ordering the whole transport exists for.

        -exec-interrupt answers ^done while the inferior is still running; the
        *stopped record follows. A request/response transport would read the
        wrong record or block.
        """
        session.send(f"-file-exec-and-symbols {compiled_targets['spin']}")
        session.send("-exec-run")
        time.sleep(0.5)

        response = session.send("-exec-interrupt")
        assert not response.is_error
        assert not any(
            e.kind is RecordKind.EXEC and e.klass == "stopped"
            for e in response.events
        ), "the stop was consumed as the command reply"

        stop = session.wait_for_stop(timeout=20)
        assert stop is not None
        assert stop.results.get("reason") == "signal-received"

    def test_stop_terminates_the_process(self, compiled_targets):
        s = MISession(timeout=20)
        s.start()
        assert s.is_alive
        s.stop()
        assert not s.is_alive
        with pytest.raises(MISessionClosedError):
            s.send("-break-list")

    def test_context_manager_cleans_up(self):
        with MISession(timeout=20) as s:
            assert s.is_alive
            assert not s.send("-break-list").is_error
        assert not s.is_alive
