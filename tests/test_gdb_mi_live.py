"""Live GDB/MI integration tests.

These need a real ``gdb`` on PATH and are skipped otherwise, so CI (which has
no debugger installed) stays green while a developer VM with GDB gets real
coverage. Run them on any machine with GDB:

    uv run pytest tests/test_gdb_mi_live.py -v

For a readable environment report to paste into an issue, run the file
directly instead:

    uv run python tests/test_gdb_mi_live.py

Two jobs. First, drive a real MI session and prove the parser handles every
line it produces -- the check most likely to catch a grammar gap that
hand-written fixtures miss. Second, re-verify the behavioural findings from
the issue #7 review, each of which shaped the engine design. Those were
established against GNU gdb 15.1; several are documented as version- or
distro-dependent, so a failure here is not necessarily a bug in this repo --
it may mean the plan needs a version caveat. Each assertion says so.
"""

from __future__ import annotations

import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from src.engines.dynamic.gdb.mi_parser import (
    MIParseError,
    RecordKind,
    parse_line,
)

GDB = shutil.which("gdb")
CC = shutil.which("gcc") or shutil.which("cc")

pytestmark = pytest.mark.skipif(GDB is None, reason="gdb not installed")

# A target with a named function, a syscall, and a fork, so one binary covers
# breakpoints, syscall catching and fork-follow.
_SOURCE = """
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
int target(int x){ return x * 3; }
int child_work(void){ return 7; }
int main(int argc, char **argv){
    int fd = open("/etc/passwd", O_RDONLY);
    char buf[64];
    if (fd >= 0) { read(fd, buf, sizeof buf); close(fd); }
    pid_t p = fork();
    if (p == 0) { return child_work(); }
    wait(NULL);
    printf("%d\\n", target(argc));
    return 0;
}
"""


class MISession:
    """Minimal MI driver: send a command, collect the records it produces.

    Output is pumped by a background reader thread into a queue rather than
    polled with ``select``. That is not incidental: ``select`` reports the
    pipe idle while Python's buffered reader still holds unread lines, so a
    poll loop silently misses records that have already arrived. The real
    bridge needs a reader thread for the same reason, plus the one in
    Verdict 02 of the issue #7 review -- replies and async stop records are
    not ordered with respect to each other.

    This is a test harness, not that bridge: no token correlation, no
    cancellation. Every wait is deadline-bounded so a wedged GDB fails the
    test instead of hanging the suite.
    """

    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
        self.proc = subprocess.Popen(
            [GDB, "--interpreter=mi2", "-nx", "-q"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.all_lines: list[str] = []
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._reader = threading.Thread(target=self._pump, daemon=True)
        self._reader.start()
        self._collect(settle=0.4)

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self._queue.put(line.rstrip("\n"))
        self._queue.put(None)

    def _next(self, wait: float) -> str | None:
        try:
            return self._queue.get(timeout=wait)
        except queue.Empty:
            return None

    def _collect(self, settle: float) -> list:
        """Read records until the stream goes quiet for *settle* seconds."""
        deadline = time.time() + self.timeout
        records = []
        while time.time() < deadline:
            line = self._next(settle)
            if line is None:
                break
            self.all_lines.append(line)
            records.append(parse_line(line))
        return records

    def send(self, command: str, settle: float = 0.4) -> list:
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        return self._collect(settle=settle)

    def wait_for_stop(self, timeout: float = 20.0) -> list:
        """Read until the inferior halts or exits, or the deadline passes.

        A settle window alone is not enough: with an async-capable GDB the
        reply to ``-exec-run`` returns long before the inferior actually
        halts, so the stop has to be waited for by content, not by time.
        """
        deadline = time.time() + timeout
        records: list = []
        while time.time() < deadline:
            line = self._next(0.3)
            if line is None:
                continue
            self.all_lines.append(line)
            record = parse_line(line)
            records.append(record)
            if record.kind is RecordKind.EXEC and record.klass in ("stopped", "exited"):
                return records
        return records

    def close(self) -> None:
        try:
            self.proc.stdin.write("-gdb-exit\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def results(records: list, klass: str | None = None) -> list:
        return [r for r in records if r.kind is RecordKind.RESULT
                and (klass is None or r.klass == klass)]

    @staticmethod
    def console_text(records: list) -> str:
        return "".join(r.text or "" for r in records if r.kind is RecordKind.CONSOLE)

    @staticmethod
    def stopped(records: list):
        for r in records:
            if r.kind is RecordKind.EXEC and r.klass == "stopped":
                return r
        return None


@pytest.fixture(scope="module")
def target_binary() -> Path:
    """A PIE ELF with symbols, or a system binary if no compiler is present."""
    if CC is None:
        for candidate in ("/bin/ls", "/usr/bin/ls", "/bin/true"):
            if Path(candidate).exists():
                return Path(candidate)
        pytest.skip("no compiler and no system binary to debug")

    tmp = Path(tempfile.mkdtemp(prefix="gdb_mi_live_"))
    src, out = tmp / "t.c", tmp / "t_pie"
    src.write_text(_SOURCE)
    proc = subprocess.run(
        [CC, "-O0", "-g", "-o", str(out), str(src)],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        pytest.skip(f"compiler failed: {proc.stderr.strip()[:200]}")
    return out


@pytest.fixture
def session():
    s = MISession()
    yield s
    s.close()


def _has_symbols(binary: Path) -> bool:
    return CC is not None and binary.name == "t_pie"


# --- 1. Parser conformance against live output -----------------------------


def test_parser_handles_every_line_of_a_live_session(session, target_binary):
    """The headline check: no line GDB emits may defeat the parser.

    parse_line raises MIParseError on a malformed structured record, and
    MISession parses every line as it is read, so a grammar gap fails here.
    """
    commands = [
        "-gdb-set mi-async on",
        "-gdb-set confirm off",
        "-gdb-set startup-with-shell off",
        f"-file-exec-and-symbols {target_binary}",
        "-break-list",
        "-data-list-register-names",
        "-list-thread-groups",
        "-file-list-exec-source-files",
        "-gdb-version",
        "-exec-run --start",
        "-data-list-register-values x",
        "-stack-info-frame",
        "-stack-list-frames",
        "-data-disassemble -s $pc -e $pc+32 -- 0",
        "-data-disassemble -s $pc -e $pc+32 -- 3",
        "-data-read-memory-bytes $pc 16",
        '-data-evaluate-expression "$pc"',
        "-thread-info",
        '-interpreter-exec console "info proc mappings"',
        "-exec-step-instruction",
        "-exec-continue",
    ]
    for cmd in commands:
        session.send(cmd)

    assert len(session.all_lines) > 20, "session produced implausibly little output"

    # Nothing structured should have been misfiled as RAW. Inferior stdout is
    # legitimately RAW, so only flag lines starting with an MI sigil.
    misfiled = [
        ln for ln in session.all_lines
        if ln[:1] in "^*+=~@&" and parse_line(ln).kind is RecordKind.RAW
    ]
    assert not misfiled, f"MI lines fell through to RAW: {misfiled[:5]}"


def test_every_captured_line_reparses_identically(session, target_binary):
    """Re-parsing the captured transcript must not raise."""
    session.send(f"-file-exec-and-symbols {target_binary}")
    session.send("-break-list")
    session.send("-gdb-version")
    for line in session.all_lines:
        try:
            parse_line(line)
        except MIParseError as exc:  # pragma: no cover - failure path
            pytest.fail(f"parser rejected live GDB output:\n  {line!r}\n  {exc}")


# --- 2. Findings from the issue #7 review ----------------------------------


def test_break_delete_by_address_is_a_silent_no_op(session, target_binary):
    """Review finding 2.8 -- the ABC deletes by address, MI deletes by number.

    If this fails, GDB has started honouring an address argument and the
    bridge's address->number map may be unnecessary on this version.
    """
    session.send(f"-file-exec-and-symbols {target_binary}")
    inserted = session.send("-break-insert main")
    done = MISession.results(inserted, "done")
    if not done or "bkpt" not in done[0].results:
        pytest.skip("could not set a breakpoint on main (stripped binary?)")
    addr = done[0].results["bkpt"]["addr"]
    number = done[0].results["bkpt"]["number"]

    deleted = session.send(f"-break-delete *{addr}")
    assert MISession.results(deleted, "done"), "delete-by-address did not answer ^done"

    listed = session.send("-break-list")
    table = MISession.results(listed, "done")[0].results["BreakpointTable"]
    assert table["nr_rows"] != "0", (
        "delete-by-address actually deleted the breakpoint on this GDB. "
        "Review finding 2.8 does not hold here -- the plan needs a version note."
    )

    session.send(f"-break-delete {number}")
    listed = session.send("-break-list")
    table = MISession.results(listed, "done")[0].results["BreakpointTable"]
    assert table["nr_rows"] == "0", "delete-by-number failed to remove the breakpoint"


def test_exec_run_without_breakpoints_runs_to_completion(session, target_binary):
    """Review finding 2.7 -- the issue's load_binary mapping detonates the sample."""
    session.send("-gdb-set confirm off")
    session.send("-gdb-set startup-with-shell off")
    session.send(f"-file-exec-and-symbols {target_binary}")
    session.send("-exec-run", settle=1.2)

    after = session.send("-data-list-register-values x 0")
    errors = [r for r in MISession.results(after) if r.is_error]
    assert errors, (
        "expected the process to have exited, leaving no registers to read. "
        "If this passes, -exec-run behaves differently on this GDB."
    )
    assert "no registers" in (errors[0].error_message or "").lower()


def test_exec_run_start_stops_before_user_code(session, target_binary):
    """Review finding 2.7's fix -- --start installs a temporary breakpoint."""
    if not _has_symbols(target_binary):
        pytest.skip("needs a binary with symbols")
    session.send("-gdb-set confirm off")
    session.send("-gdb-set startup-with-shell off")
    session.send(f"-file-exec-and-symbols {target_binary}")
    records = session.send("-exec-run --start", settle=0.3)
    records += session.wait_for_stop()

    stop = MISession.stopped(records)
    assert stop is not None, "-exec-run --start did not stop the inferior"
    after = session.send("-data-list-register-values x 0")
    assert not [r for r in MISession.results(after) if r.is_error], (
        "process should still be alive and stopped after --start"
    )


def test_startup_with_shell_defaults_on(session):
    """Security finding S3 -- target argv is shell-expanded unless turned off."""
    records = session.send('-interpreter-exec console "show startup-with-shell"')
    text = MISession.console_text(records).lower()
    assert "on" in text, (
        f"expected startup-with-shell on by default, got: {text.strip()!r}. "
        "If it is off here, S3 does not apply to this build."
    )


def test_follow_fork_defaults_to_parent(session):
    """Review finding 2.9 -- the child of a fork runs untraced by default."""
    fork_mode = MISession.console_text(
        session.send('-interpreter-exec console "show follow-fork-mode"')
    ).lower()
    detach = MISession.console_text(
        session.send('-interpreter-exec console "show detach-on-fork"')
    ).lower()
    assert "parent" in fork_mode, f"unexpected follow-fork-mode: {fork_mode.strip()!r}"
    assert "on" in detach, f"unexpected detach-on-fork: {detach.strip()!r}"


def test_console_shell_escape_is_reachable(session):
    """Security finding S1 -- justifies the allowlist.

    Runs a harmless `echo`. If this is blocked on your build (a hardened or
    sandboxed GDB), S1's severity is lower there -- worth knowing either way.
    """
    records = session.send('-interpreter-exec console "shell echo MI_SHELL_REACHABLE"')
    combined = MISession.console_text(records) + "\n".join(session.all_lines[-12:])
    assert "MI_SHELL_REACHABLE" in combined, (
        "the shell escape did not execute on this build -- S1 may not apply here"
    )


def test_pie_breakpoint_address_changes_after_run(session, target_binary):
    """Review finding 2.3 -- static addresses do not survive PIE relocation."""
    if not _has_symbols(target_binary):
        pytest.skip("needs a binary with symbols")
    session.send("-gdb-set confirm off")
    session.send("-gdb-set startup-with-shell off")
    session.send(f"-file-exec-and-symbols {target_binary}")

    inserted = session.send("-break-insert target")
    before = MISession.results(inserted, "done")[0].results["bkpt"]["addr"]

    session.send("-exec-run", settle=0.3)
    session.wait_for_stop()
    listed = session.send("-break-list")
    table = MISession.results(listed, "done")[0].results["BreakpointTable"]
    body = table.get("body") or []
    if not body:
        pytest.skip("breakpoint table empty after run")
    after = body[0]["bkpt"]["addr"]

    if int(before, 16) == int(after, 16):
        pytest.skip("binary is not PIE on this toolchain; nothing to relocate")
    assert int(after, 16) > int(before, 16), (
        f"expected relocation, got {before} -> {after}"
    )


# --- Standalone environment report -----------------------------------------


def _report() -> int:
    """Print a paste-able summary of this machine's GDB behaviour."""
    if GDB is None:
        print("gdb not found on PATH")
        return 1

    version = subprocess.run([GDB, "--version"], capture_output=True, text=True)
    print("=" * 68)
    print("GDB/MI environment report")
    print("=" * 68)
    print(f"gdb      : {GDB}")
    print(f"version  : {version.stdout.splitlines()[0] if version.stdout else '?'}")
    print(f"compiler : {CC or 'none (tests will fall back to a system binary)'}")
    ptrace = Path("/proc/sys/kernel/yama/ptrace_scope")
    print(f"ptrace_scope: {ptrace.read_text().strip() if ptrace.exists() else 'no Yama LSM'}")
    print()

    s = MISession()
    try:
        probes = {
            "startup-with-shell": "show startup-with-shell",
            "auto-load safe-path": "show auto-load safe-path",
            "follow-fork-mode": "show follow-fork-mode",
            "detach-on-fork": "show detach-on-fork",
            "disable-randomization": "show disable-randomization",
            "mi-async": "show mi-async",
        }
        for label, cmd in probes.items():
            text = MISession.console_text(s.send(f'-interpreter-exec console "{cmd}"'))
            print(f"  {label:22}: {text.strip() or '(no output)'}")

        print()
        parsed = sum(1 for ln in s.all_lines if ln.strip())
        print(f"  lines parsed without error: {parsed}")
    finally:
        s.close()

    print()
    print("Run the full suite with:  uv run pytest tests/test_gdb_mi_live.py -v")
    return 0


if __name__ == "__main__":
    sys.exit(_report())
