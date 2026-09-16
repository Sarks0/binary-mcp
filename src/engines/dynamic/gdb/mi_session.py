"""
Transport for a GDB/MI subprocess: spawn, correlate, and hand back records.

This is the layer between :mod:`mi_parser` (text -> records) and the bridge
(records -> debugger semantics). It owns exactly one ``gdb --interpreter=mi2``
process and answers one question reliably: *which output belongs to the
command I just sent?*

Three properties of MI force the shape of this module.

**Replies and stop events are not ordered.** With ``mi-async on`` -- which this
session enables, because ``-exec-interrupt`` does not work without it --
GDB answers ``-exec-interrupt`` with ``^done`` immediately and emits the
``*stopped`` record later, once the inferior actually halts. Anything modelled
as request/response therefore reads the wrong record, or blocks forever. Async
records go to a separate queue (:meth:`drain_events`, :meth:`wait_for_stop`)
and never satisfy a command's reply.

**Output must be pumped, not polled.** ``select`` reports the pipe idle while
Python's buffered reader still holds complete unread lines, so a poll loop
silently misses records that have already arrived. A reader thread is the fix,
and it is also what lets a stop event be noticed while no command is in
flight.

**Commands need tokens.** Every command goes out as ``<token><command>`` and
GDB echoes the token on the matching ``^result`` record, so a reply is matched
by identity rather than by arrival order.

Security posture, which is why :meth:`start` refuses to continue if any of it
fails to apply (all verified against GNU gdb 15.1):

- ``--nx`` skips the init files GDB would otherwise read at startup
  (``~/.gdbinit`` and the system one).
- ``set auto-load off`` is what closes the sample-directory vector, and
  ``--nx`` alone does **not**: verified on GNU gdb 15.1, a ``--nx`` session
  still reports *"Auto-loading of .gdbinit script from current directory is
  on"*. A sample shipping a ``.gdbinit`` next to itself would execute code in
  the debugger the moment the working directory is its own. Turning the whole
  ``auto-load`` prefix off also disables per-objfile Python scripts and
  ``libthread_db`` loading, all confirmed off afterwards.
- ``set startup-with-shell off`` -- this defaults to **on**, meaning the
  inferior is launched through ``/bin/sh -c`` and its argv is shell-expanded.
- ``set confirm off`` -- a console command that stops to ask "(y or n)" would
  otherwise block a read until its deadline.

This module deliberately exposes no way to run a console command. MI's
``-interpreter-exec console`` reaches ``shell`` and ``python``, both verified
to execute as the server user, so console access belongs behind the
command allowlist at the layer above, not in the transport.

One inherited caution from the parser: a ``^done`` means GDB *accepted* the
command, not that the operation happened. ``-break-delete *0xADDR`` answers
``^done`` and leaves the breakpoint armed. Callers that change debuggee state
must read it back.
"""

from __future__ import annotations

import logging
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from src.engines.dynamic.gdb.mi_parser import (
    MIParseError,
    MIRecord,
    RecordKind,
    parse_line,
)
from src.utils.config import get_config, get_config_int

logger = logging.getLogger(__name__)

@dataclass(frozen=True)
class _Hardening:
    """One setting start() must establish before the session is usable.

    ``linux_only`` marks a setting that does not exist on every GDB build.
    ``startup-with-shell`` is the case in point: it is a POSIX notion, and
    Windows GDB has no such command because it creates the inferior directly
    rather than through a shell. Its absence there means the risk is absent,
    not that hardening failed -- but on Linux an absent setting is treated as
    fatal, because that is where the shell-launch path is real.
    """

    name: str
    value: str
    purpose: str
    linux_only: bool = False


# Applied in order by start(). Every one is a plain MI command -- no console
# escape is needed to harden the session, which is what keeps this module free
# of an execution surface.
_HARDENING: tuple[_Hardening, ...] = (
    _Hardening("confirm", "off", "suppress interactive confirmation prompts"),
    _Hardening(
        "startup-with-shell",
        "off",
        "launch the inferior without a shell",
        linux_only=True,
    ),
    _Hardening(
        "auto-load",
        "off",
        "refuse auto-loaded scripts from the sample directory",
    ),
    _Hardening("mi-async", "on", "allow -exec-interrupt while the inferior runs"),
)

# Kept for diagnostics only; bounded so a chatty GDB cannot grow it without end.
_STDERR_LINES = 200

DEFAULT_TIMEOUT = 30
_EXIT_GRACE_SECONDS = 5.0


def _setting_holds(response: MIResponse, expected: str) -> bool:
    """True if a -gdb-show reply reports *expected*.

    Scalar settings answer ``value="off"``. Prefix settings such as
    ``auto-load`` answer a ``showlist`` of sub-options instead, and only the
    boolean ones are toggles: verified on GNU gdb 15.1, ``set auto-load off``
    leaves ``gdb-scripts``, ``libthread-db``, ``local-gdbinit`` and
    ``python-scripts`` all ``off`` while ``safe-path`` and
    ``scripts-directory`` keep their directory lists, because those two are
    paths rather than switches. Every boolean must match; the paths are not
    part of the question.
    """
    if response.is_error:
        return False
    value = response.results.get("value")
    if isinstance(value, str):
        return value == expected
    showlist = response.results.get("showlist")
    if isinstance(showlist, dict):
        options = showlist.get("option")
        entries = options if isinstance(options, list) else [options]
        toggles = [
            entry["value"]
            for entry in entries
            if isinstance(entry, dict) and entry.get("value") in ("on", "off")
        ]
        return bool(toggles) and all(v == expected for v in toggles)
    return False


class MISessionError(Exception):
    """A GDB/MI transport failure.

    Module-private by design: every raise site in this file uses a sentence
    written in this repository, so the message can be shown verbatim without
    leaking host layout. Where a failing command is named, only its MI
    operation is included -- never its arguments, which may carry a sample's
    path.
    """


class MITimeoutError(MISessionError):
    """GDB did not answer within the deadline."""


class MISessionClosedError(MISessionError):
    """The GDB process exited, or the session was stopped."""


@dataclass
class MIResponse:
    """Everything one command produced.

    Attributes:
        record: The ``^result`` record that closed the command.
        console: Console stream text emitted while the command was in flight.
        log: Debugger log stream text, mostly warnings.
        events: Async records observed while waiting. They are *also* queued
            for :meth:`drain_events`, so a caller that ignores this field does
            not lose them.
    """

    record: MIRecord
    console: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)
    events: list[MIRecord] = field(default_factory=list)

    @property
    def is_error(self) -> bool:
        return self.record.is_error

    @property
    def error_message(self) -> str | None:
        return self.record.error_message

    @property
    def results(self) -> dict:
        return self.record.results

    @property
    def console_text(self) -> str:
        return "".join(self.console)


def find_gdb(explicit: str | None = None) -> str:
    """Resolve the GDB executable.

    Order: the argument, then ``GDB_PATH`` (env or .env), then ``gdb`` on PATH.

    Raises:
        MISessionError: No GDB could be found.
    """
    for candidate in (explicit, get_config("GDB_PATH")):
        if candidate:
            resolved = shutil.which(candidate) or candidate
            return resolved
    found = shutil.which("gdb")
    if not found:
        raise MISessionError(
            "GDB was not found. Install it (apt install gdb) or set GDB_PATH "
            "to the executable."
        )
    return found


class MISession:
    """A live ``gdb --interpreter=mi2`` process with token-correlated commands.

    Not a debugger: it moves records, and knows nothing about breakpoints or
    memory. :class:`~src.engines.dynamic.gdb.bridge.GdbBridge` builds that on
    top.

    Thread-safety: :meth:`send` serialises callers on an internal lock, so one
    command is in flight at a time. The reader thread never blocks on a caller.
    """

    def __init__(
        self,
        gdb_path: str | None = None,
        timeout: int | None = None,
        extra_args: list[str] | None = None,
    ):
        self.gdb_path = find_gdb(gdb_path)
        if timeout is not None:
            self.timeout = timeout
        else:
            self.timeout = get_config_int("GDB_TIMEOUT", DEFAULT_TIMEOUT)
        self._extra_args = list(extra_args or [])

        self._proc: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None

        self._send_lock = threading.Lock()
        self._token = 0

        # token -> queue carrying that command's single ^result record.
        self._pending: dict[int, queue.Queue[MIRecord]] = {}
        self._pending_lock = threading.Lock()

        # Stream records and async records seen while a command is in flight.
        # Guarded by _send_lock: only the in-flight sender reads them.
        self._inflight_console: list[str] = []
        self._inflight_log: list[str] = []
        self._inflight_events: list[MIRecord] = []
        self._collecting = False

        self._events: queue.Queue[MIRecord] = queue.Queue()
        self._stderr: deque[str] = deque(maxlen=_STDERR_LINES)

        self._hardening_report: dict[str, str] = {}
        self._closed = threading.Event()
        self._exit_status: int | None = None

    # -- lifecycle

    @property
    def is_alive(self) -> bool:
        """True while the GDB process is running and the session is usable."""
        return (
            self._proc is not None
            and self._proc.poll() is None
            and not self._closed.is_set()
        )

    def start(self) -> None:
        """Spawn GDB and apply the hardening settings.

        Raises:
            MISessionError: GDB could not be spawned, did not reach its first
                prompt, or rejected a hardening setting. Rejection is fatal on
                purpose: a session that failed to turn off ``startup-with-shell``
                would launch samples through a shell.
        """
        if self.is_alive:
            return

        argv = [self.gdb_path, "--interpreter=mi2", "--nx", "-q", *self._extra_args]
        logger.info("Starting GDB/MI session: %s", self.gdb_path)
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - fixed argv, never a shell
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            logger.debug("GDB spawn failed", exc_info=exc)
            raise MISessionError(
                "Could not start GDB. Check that GDB_PATH points at an "
                "executable debugger."
            ) from exc

        self._closed.clear()
        self._reader = threading.Thread(
            target=self._pump_stdout, name="gdb-mi-reader", daemon=True
        )
        self._reader.start()
        self._stderr_reader = threading.Thread(
            target=self._pump_stderr, name="gdb-mi-stderr", daemon=True
        )
        self._stderr_reader.start()

        self._hardening_report = {}
        for setting in _HARDENING:
            self._apply_hardening(setting)

    def _apply_hardening(self, setting: _Hardening) -> None:
        """Establish one setting, or fail the session trying.

        Existence is probed with ``-gdb-show`` rather than inferred from a
        failed ``-gdb-set``: verified on GNU gdb 15.1, setting an unknown name
        does not report it as unknown. ``set`` doubles as ``set var``, so GDB
        parses the name as an expression and answers with the thoroughly
        misleading *"No symbol table is loaded."* ``show`` answers
        *"Undefined show command"*, which is unambiguous.

        The value is then read back. This module tells its callers that a
        ``^done`` means accepted rather than performed; hardening is
        state-changing, so it holds itself to the same rule.
        """
        probe = self.send(f"-gdb-show {setting.name}")
        if probe.is_error:
            if not setting.linux_only or sys.platform == "linux":
                self.stop()
                raise MISessionError(
                    f"This GDB has no '{setting.name}' setting, which is "
                    f"required to {setting.purpose}. Refusing to continue "
                    "with an unhardened debugger."
                )
            logger.info(
                "GDB has no '%s' setting on this platform; the risk it guards "
                "against does not apply here",
                setting.name,
            )
            self._hardening_report[setting.name] = "absent"
            return

        applied = self.send(f"-gdb-set {setting.name} {setting.value}")
        if applied.is_error:
            self.stop()
            raise MISessionError(
                f"GDB rejected a required security setting ({setting.purpose}); "
                f"could not set '{setting.name}'. Refusing to continue with an "
                "unhardened debugger."
            )

        verify = self.send(f"-gdb-show {setting.name}")
        if not _setting_holds(verify, setting.value):
            self.stop()
            raise MISessionError(
                f"GDB accepted '{setting.name}' but it did not take effect "
                f"({setting.purpose}). Refusing to continue with an unhardened "
                "debugger."
            )
        self._hardening_report[setting.name] = "applied"

    @property
    def hardening_report(self) -> dict[str, str]:
        """What start() established: setting name -> "applied" or "absent"."""
        return dict(self._hardening_report)

    def stop(self) -> None:
        """Shut the session down, killing GDB if it will not exit."""
        proc, self._proc = self._proc, None
        self._closed.set()
        if proc is None:
            return

        try:
            if proc.poll() is None and proc.stdin is not None:
                try:
                    proc.stdin.write("-gdb-exit\n")
                    proc.stdin.flush()
                except (OSError, ValueError):
                    pass
            try:
                proc.wait(timeout=_EXIT_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                logger.warning("GDB did not exit on -gdb-exit; killing it")
                proc.kill()
                proc.wait(timeout=_EXIT_GRACE_SECONDS)
        except Exception as exc:  # pragma: no cover - best-effort teardown
            logger.debug("Error while stopping GDB", exc_info=exc)
        finally:
            self._exit_status = proc.returncode
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:  # pragma: no cover
                        pass
            self._fail_pending()

    def __enter__(self) -> MISession:
        self.start()
        return self

    def __exit__(self, *_exc_info) -> None:
        self.stop()

    # -- commands

    def send(self, command: str, timeout: float | None = None) -> MIResponse:
        """Send one MI command and wait for the ``^result`` record that closes it.

        Async records that arrive while waiting do not satisfy the command;
        they are queued for :meth:`drain_events` and also returned on
        :attr:`MIResponse.events`.

        Args:
            command: An MI command, e.g. ``-break-insert main``. Must not
                already carry a token; this method assigns one.
            timeout: Seconds to wait, defaulting to the session timeout.

        Returns:
            The command's response. A ``^error`` reply is returned, not raised
            -- GDB refusing a command is an answer, and callers routinely need
            its message.

        Raises:
            MISessionClosedError: GDB is not running, or exited while waiting.
            MITimeoutError: No reply arrived before the deadline.
        """
        if not command or command.strip() != command:
            raise MISessionError("MI command must be non-empty and unpadded.")
        if command[0].isdigit():
            raise MISessionError("MI command must not carry its own token.")

        deadline_seconds = self.timeout if timeout is None else timeout

        with self._send_lock:
            if not self.is_alive:
                raise MISessionClosedError("The GDB session is not running.")

            self._token += 1
            token = self._token
            reply: queue.Queue[MIRecord] = queue.Queue(maxsize=1)
            with self._pending_lock:
                self._pending[token] = reply

            self._inflight_console = []
            self._inflight_log = []
            self._inflight_events = []
            self._collecting = True
            try:
                self._write(f"{token}{command}")
                record = self._await_reply(reply, deadline_seconds, command)
                return MIResponse(
                    record=record,
                    console=list(self._inflight_console),
                    log=list(self._inflight_log),
                    events=list(self._inflight_events),
                )
            finally:
                self._collecting = False
                with self._pending_lock:
                    self._pending.pop(token, None)

    def _await_reply(
        self, reply: queue.Queue[MIRecord], deadline_seconds: float, command: str
    ) -> MIRecord:
        deadline = time.monotonic() + deadline_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                return reply.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if self._closed.is_set() or (
                    self._proc is not None and self._proc.poll() is not None
                ):
                    raise MISessionClosedError(
                        "GDB exited before answering."
                    ) from None
        # Name the operation but not its arguments: a command can carry a
        # sample path, and this message reaches the model.
        operation = command.split(" ", 1)[0]
        raise MITimeoutError(
            f"GDB did not answer {operation} within {deadline_seconds:g}s."
        )

    def _write(self, line: str) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise MISessionClosedError("The GDB session is not running.")
        try:
            proc.stdin.write(line + "\n")
            proc.stdin.flush()
        except (OSError, ValueError) as exc:
            raise MISessionClosedError("GDB closed its input stream.") from exc

    # -- events

    def drain_events(self) -> list[MIRecord]:
        """Return every async record queued since the last drain."""
        drained: list[MIRecord] = []
        while True:
            try:
                drained.append(self._events.get_nowait())
            except queue.Empty:
                return drained

    def wait_for_stop(self, timeout: float | None = None) -> MIRecord | None:
        """Block until the inferior halts or exits.

        This is the counterpart to the async-ordering problem in the module
        docstring: ``-exec-run`` and ``-exec-interrupt`` both return long
        before the inferior settles, so the stop has to be waited for by
        content rather than assumed from the reply.

        Returns:
            The ``*stopped`` (or ``*exited``) record, or ``None`` on timeout.
        """
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                record = self._events.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if not self.is_alive:
                    return None
                continue
            if record.kind is RecordKind.EXEC and record.klass in ("stopped", "exited"):
                return record

    @property
    def stderr_tail(self) -> list[str]:
        """Recent GDB stderr lines, for diagnostics. Never shown to the model."""
        return list(self._stderr)

    # -- reader threads

    def _pump_stdout(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            return
        try:
            for line in proc.stdout:
                self._route(line.rstrip("\n"))
        except (OSError, ValueError) as exc:  # pragma: no cover - pipe torn down
            logger.debug("GDB stdout reader ended", exc_info=exc)
        finally:
            self._closed.set()
            self._fail_pending()

    def _pump_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            for line in proc.stderr:
                self._stderr.append(line.rstrip("\n"))
        except (OSError, ValueError):  # pragma: no cover - pipe torn down
            pass

    def _route(self, line: str) -> None:
        """Classify one line and deliver it to whoever is waiting for it."""
        try:
            record = parse_line(line)
        except MIParseError as exc:
            # A malformed structured record is a parser gap or a truncated
            # read. Log it and keep the session alive rather than killing the
            # reader thread, which would strand every waiting command.
            logger.warning("Unparseable GDB/MI line; ignoring it: %s", exc)
            return

        if record.kind is RecordKind.RESULT:
            self._deliver_result(record)
            return

        if record.is_async:
            self._events.put(record)
            if self._collecting:
                self._inflight_events.append(record)
            return

        if record.kind is RecordKind.CONSOLE and self._collecting:
            self._inflight_console.append(record.text or "")
        elif record.kind is RecordKind.LOG and self._collecting:
            self._inflight_log.append(record.text or "")

    def _deliver_result(self, record: MIRecord) -> None:
        with self._pending_lock:
            waiter = self._pending.get(record.token) if record.token else None
            if waiter is None and len(self._pending) == 1:
                # GDB omits the token on replies to commands it originated
                # itself. With exactly one command in flight the attribution is
                # unambiguous; with none, the record is dropped.
                waiter = next(iter(self._pending.values()))
        if waiter is None:
            logger.debug("Dropping unattributable result record: %s", record.klass)
            return
        try:
            waiter.put_nowait(record)
        except queue.Full:  # pragma: no cover - one reply per token
            logger.debug("Duplicate result for token %s", record.token)

    def _fail_pending(self) -> None:
        """Unblock every waiting command once GDB is gone."""
        with self._pending_lock:
            waiters = list(self._pending.values())
            self._pending.clear()
        for waiter in waiters:
            try:
                waiter.put_nowait(
                    MIRecord(kind=RecordKind.RESULT, raw="", klass="error",
                             results={"msg": "GDB exited."})
                )
            except queue.Full:  # pragma: no cover
                pass
