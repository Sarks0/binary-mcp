"""
GDB implementation of the :class:`Debugger` interface for Linux ELF targets.

Sits on :class:`~src.engines.dynamic.gdb.mi_session.MISession`, which moves
records, and turns them into debugger semantics: breakpoints, memory,
registers, stepping and state. Everything here goes out as structured MI. The
one console command it issues, ``info proc mappings``, is on the allowlist and
is checked against it rather than trusted.

Three behaviours measured on GNU gdb 15.1 shape this class, each of which a
naive binding gets wrong.

**MI deletes breakpoints by number, not address.** ``-break-delete *0xADDR``
answers ``^done`` and leaves the breakpoint armed. The ABC deletes by address,
so this class keeps an address-to-number map, deletes by number, and reads
``-break-list`` back to confirm. More generally: a ``^done`` means GDB accepted
the command, not that the operation happened, so every state change here is
verified rather than assumed.

**Loading a binary must not run it.** The target is a malware sample. Loading
sets the file and arguments and nothing else; starting execution is
:meth:`run`, which stops at the entry point by default and only runs free when
asked. ``-exec-run`` with no breakpoints runs the sample to completion, and the
next call then fails with "No registers."

**PIE addresses need rebasing, and that is the common case.** A stripped,
statically linked ELF cannot take a symbolic breakpoint at all, so every
breakpoint comes from a Ghidra address and has to be relocated. The formula is
``runtime = static - link_base + load_base``, verified against both an ET_DYN
and an ET_EXEC target: for PIE, link_base is 0 and load_base comes from the
runtime mapping; for ET_EXEC the two are equal and the arithmetic is the
identity. link_base is read from the ELF with pyelftools, which is already a
dependency, and load_base from the process mappings.

Scope is Linux x86-64, stated rather than implied. :meth:`connect` refuses
elsewhere and names the engine to use instead, because the register model and
the ``/proc`` lookups here are POSIX. The session layer underneath is
platform-neutral on purpose and is exercised on Windows CI against a second
GDB build.
"""

from __future__ import annotations

import logging
import platform
import re
from pathlib import Path
from typing import Any

from src.engines.dynamic.base import Debugger, DebuggerState
from src.engines.dynamic.gdb.allowlist import validate_console_command
from src.engines.dynamic.gdb.mi_parser import MIRecord, RecordKind
from src.engines.dynamic.gdb.mi_session import (
    MISession,
    MISessionError,
    quote_mi_argument,
)

logger = logging.getLogger(__name__)

MAX_READ_BYTES = 16 * 1024 * 1024

_HEX_ADDRESS = re.compile(r"^(0[xX])?[0-9a-fA-F]{1,16}$")

_PTRACE_SCOPE = Path("/proc/sys/kernel/yama/ptrace_scope")


class GdbBridgeError(Exception):
    """A GDB debugging operation failed.

    Module-private so a verbatim passthrough is safe by construction: every
    raise site uses a sentence written in this repository and names only MI
    operations or caller-supplied numbers, never a host path.
    """


def _normalise_address(address: str) -> str:
    """Canonical form for the breakpoint map: lowercase hex, no 0x, no zeros."""
    text = address.strip().lower().removeprefix("*").removeprefix("0x")
    return text.lstrip("0") or "0"


def _require_hex_address(address: str) -> int:
    """Parse a hex address, refusing anything that is not one.

    Addresses reach MI inside a command string, so a non-hex value is refused
    here rather than passed through and interpreted as an expression.
    """
    text = address.strip()
    if not _HEX_ADDRESS.match(text):
        raise GdbBridgeError(
            f"address must be hexadecimal, got {text!r}. Use a form like "
            "0x401136."
        )
    return int(text, 16)


class GdbBridge(Debugger):
    """Drive a Linux GDB session through the common debugger interface."""

    def __init__(self, session: MISession | None = None, timeout: int | None = None):
        self._session = session or MISession(timeout=timeout)
        self._state = DebuggerState.NOT_LOADED
        self._binary_path: Path | None = None
        self._breakpoints: dict[str, str] = {}
        self._register_names: list[str] | None = None
        self._link_base: int | None = None
        self._load_base: int | None = None
        self._last_stop: MIRecord | None = None

    @property
    def session(self) -> MISession:
        return self._session

    @property
    def breakpoints(self) -> dict[str, str]:
        """Address to GDB breakpoint number, for the addresses set here."""
        return dict(self._breakpoints)

    def _command(self, command: str, timeout: float | None = None) -> Any:
        response = self._session.send(command, timeout=timeout)
        self._absorb_events(response.events)
        return response

    def _require(self, command: str, what: str, timeout: float | None = None) -> Any:
        """Send a command and raise if GDB refused it."""
        response = self._command(command, timeout=timeout)
        if response.is_error:
            raise GdbBridgeError(f"{what} failed: {response.error_message}")
        return response

    def _absorb_events(self, events: list[MIRecord]) -> None:
        for record in events:
            if record.kind is not RecordKind.EXEC:
                continue
            if record.klass == "running":
                self._state = DebuggerState.RUNNING
            elif record.klass == "stopped":
                self._state = DebuggerState.PAUSED
                self._last_stop = record
            elif record.klass == "exited":
                self._state = DebuggerState.TERMINATED

    def _drain(self) -> None:
        self._absorb_events(self._session.drain_events())

    def connect(self, timeout: int = 10) -> bool:
        """Start GDB and apply its hardening.

        Raises:
            GdbBridgeError: Not running on Linux, or GDB could not be started
                or hardened.
        """
        if platform.system() != "Linux":
            raise GdbBridgeError(
                "The GDB engine supports Linux only. On Windows use the "
                "x64dbg engine for user-mode debugging, or WinDbg for kernel "
                f"debugging. Current platform: {platform.system()}"
            )
        try:
            self._session.start()
        except MISessionError as exc:
            raise GdbBridgeError(f"could not start GDB: {exc}") from exc
        self._state = DebuggerState.NOT_LOADED
        return True

    def disconnect(self) -> None:
        self._session.stop()
        self._state = DebuggerState.NOT_LOADED
        self._breakpoints.clear()
        self._register_names = None
        self._link_base = None
        self._load_base = None
        self._last_stop = None

    def is_connected(self) -> bool:
        return self._session.is_alive

    def load_binary(self, binary_path: Path, args: list[str] | None = None) -> bool:
        """Load a binary and its arguments without starting it.

        Loading is deliberately inert. ``-exec-run`` with no breakpoints runs
        the sample to completion, so starting execution is :meth:`run`, which
        stops at the entry point unless told otherwise.
        """
        path = Path(binary_path)
        self._require(
            f"-file-exec-and-symbols {quote_mi_argument(str(path))}",
            "loading the binary",
        )
        if args:
            quoted = " ".join(quote_mi_argument(a) for a in args)
            self._require(f"-exec-arguments {quoted}", "setting target arguments")

        self._binary_path = path
        self._link_base = _read_elf_link_base(path)
        self._load_base = None
        self._state = DebuggerState.LOADED
        return True

    def run(self, stop_at: str = "entry") -> DebuggerState:
        """Start the target.

        Args:
            stop_at: ``"entry"`` stops before any user code (console
                ``starti``), ``"main"`` stops at main (``-exec-run --start``),
                and ``"none"`` lets the sample run free. ``"none"`` is the only
                value that leaves a malware sample unsupervised.

        Returns:
            The state after the target settles.
        """
        if stop_at not in ("entry", "main", "none"):
            raise GdbBridgeError(
                f"stop_at must be 'entry', 'main' or 'none', got {stop_at!r}"
            )

        if self._state is DebuggerState.PAUSED:
            self._require("-exec-continue", "resuming the target")
        elif stop_at == "entry":
            self._require('-interpreter-exec console "starti"', "starting the target")
        elif stop_at == "main":
            self._require("-exec-run --start", "starting the target")
        else:
            self._require("-exec-run", "starting the target")

        if stop_at == "none":
            self._state = DebuggerState.RUNNING
            return self._state

        self.wait_for_stop()
        return self._state

    def wait_for_stop(self, timeout: float | None = None) -> MIRecord | None:
        """Wait for the target to halt, then update state.

        A reply to ``-exec-run`` or ``-exec-interrupt`` arrives before the
        inferior settles, so the stop has to be waited for by content.
        """
        record = self._session.wait_for_stop(timeout=timeout)
        if record is not None:
            self._absorb_events([record])
        return record

    def pause(self) -> bool:
        """Interrupt a running target."""
        self._require("-exec-interrupt", "interrupting the target")
        return self.wait_for_stop() is not None

    def set_breakpoint(self, address: str) -> bool:
        """Set a breakpoint at a runtime address, recording its GDB number.

        The number is what makes deletion possible at all, since MI cannot
        delete by address.
        """
        value = _require_hex_address(address)
        response = self._require(
            f"-break-insert *0x{value:x}", "setting the breakpoint"
        )
        bkpt = response.results.get("bkpt")
        if not isinstance(bkpt, dict) or "number" not in bkpt:
            raise GdbBridgeError(
                "GDB accepted the breakpoint but reported no number, so it "
                "could not be recorded for later deletion"
            )
        self._breakpoints[_normalise_address(address)] = bkpt["number"]
        return True

    def delete_breakpoint(self, address: str) -> bool:
        """Delete a breakpoint by address, via the number GDB gave it.

        ``-break-delete *0xADDR`` answers ``^done`` and deletes nothing, so
        the number is looked up and the result read back.
        """
        key = _normalise_address(address)
        number = self._breakpoints.get(key)
        if number is None:
            raise GdbBridgeError(
                "no breakpoint was set at that address by this session, so "
                "there is no GDB breakpoint number to delete"
            )

        self._require(f"-break-delete {number}", "deleting the breakpoint")
        if number in self._list_breakpoint_numbers():
            raise GdbBridgeError(
                f"GDB accepted the deletion of breakpoint {number} but it is "
                "still present"
            )
        del self._breakpoints[key]
        return True

    def list_breakpoints(self) -> list[dict[str, Any]]:
        """Every breakpoint GDB currently holds."""
        response = self._require("-break-list", "listing breakpoints")
        table = response.results.get("BreakpointTable")
        if not isinstance(table, dict):
            return []
        body = table.get("body") or []
        rows = body if isinstance(body, list) else [body]
        found = []
        for row in rows:
            if isinstance(row, dict):
                bkpt = row.get("bkpt")
                if isinstance(bkpt, dict):
                    found.append(bkpt)
        return found

    def _list_breakpoint_numbers(self) -> set[str]:
        return {b["number"] for b in self.list_breakpoints() if "number" in b}

    def step_into(self) -> dict[str, Any]:
        self._require("-exec-step-instruction", "stepping into")
        self.wait_for_stop()
        return self.get_current_location()

    def step_over(self) -> dict[str, Any]:
        self._require("-exec-next-instruction", "stepping over")
        self.wait_for_stop()
        return self.get_current_location()

    def step_out(self) -> dict[str, Any]:
        self._require("-exec-finish", "stepping out")
        self.wait_for_stop()
        return self.get_current_location()

    def get_registers(self) -> dict[str, str]:
        """Current registers as name to hex value.

        MI answers ``-data-list-register-values`` with register *numbers*, so
        the names are fetched once and cached for the session.
        """
        if self._register_names is None:
            response = self._require(
                "-data-list-register-names", "reading register names"
            )
            names = response.results.get("register-names") or []
            self._register_names = [n for n in names if isinstance(n, str)]

        response = self._require(
            "-data-list-register-values x", "reading register values"
        )
        values = response.results.get("register-values") or []
        registers: dict[str, str] = {}
        for entry in values:
            if not isinstance(entry, dict):
                continue
            try:
                index = int(entry.get("number", ""))
            except ValueError:
                continue
            if 0 <= index < len(self._register_names):
                name = self._register_names[index]
                if name:
                    registers[name] = entry.get("value", "")
        return registers

    def read_memory(self, address: str, size: int) -> bytes:
        """Read *size* bytes from the target."""
        value = _require_hex_address(address)
        if size <= 0:
            raise GdbBridgeError(f"size must be positive, got {size}")
        if size > MAX_READ_BYTES:
            raise GdbBridgeError(
                f"size {size} exceeds the {MAX_READ_BYTES} byte read limit"
            )

        response = self._require(
            f"-data-read-memory-bytes 0x{value:x} {size}", "reading memory"
        )
        blocks = response.results.get("memory") or []
        chunks = [
            bytes.fromhex(b["contents"])
            for b in blocks
            if isinstance(b, dict) and isinstance(b.get("contents"), str)
        ]
        if not chunks:
            raise GdbBridgeError("GDB returned no memory for that address")
        return b"".join(chunks)

    def write_memory(self, address: str, data: bytes) -> bool:
        """Write *data* to the target, then read it back to confirm."""
        value = _require_hex_address(address)
        if not data:
            raise GdbBridgeError("no bytes to write")

        self._require(
            f"-data-write-memory-bytes 0x{value:x} {data.hex()}", "writing memory"
        )
        if self.read_memory(f"0x{value:x}", len(data)) != data:
            raise GdbBridgeError(
                "GDB accepted the write but the bytes read back differ, so "
                "the write did not take effect"
            )
        return True

    def get_state(self) -> DebuggerState:
        """Current state, after absorbing any events that arrived unasked."""
        if not self._session.is_alive:
            return DebuggerState.TERMINATED
        self._drain()
        return self._state

    def get_current_location(self) -> dict[str, Any]:
        """Where the target is stopped, with the next instruction."""
        frame_response = self._command("-stack-info-frame")
        frame = frame_response.results.get("frame")
        location: dict[str, Any] = {"state": self.get_state().value}
        if isinstance(frame, dict):
            location.update(
                address=frame.get("addr"),
                function=frame.get("func"),
                file=frame.get("file"),
                line=frame.get("line"),
            )
        if self._last_stop is not None:
            location["stop_reason"] = self._last_stop.results.get("reason")

        disassembly = self._command("-data-disassemble -s $pc -e $pc+16 -- 0")
        if not disassembly.is_error:
            instructions = disassembly.results.get("asm_insns") or []
            if instructions and isinstance(instructions[0], dict):
                location["instruction"] = instructions[0].get("inst")
        return location

    def disassemble(self, address: str, count: int = 10) -> list[dict[str, str]]:
        """Disassemble *count* instructions from *address*."""
        value = _require_hex_address(address)
        if count <= 0:
            raise GdbBridgeError(f"count must be positive, got {count}")
        end = value + count * 16
        response = self._require(
            f"-data-disassemble -s 0x{value:x} -e 0x{end:x} -- 0",
            "disassembling",
        )
        rows = response.results.get("asm_insns") or []
        return [r for r in rows if isinstance(r, dict)][:count]

    def attach(self, pid: int) -> bool:
        """Attach to a running process.

        Checks Yama first: ``ptrace_scope`` of 1 or more blocks attaching to a
        process that is not a descendant, and the resulting GDB error does not
        say so.
        """
        if pid <= 0:
            raise GdbBridgeError(f"pid must be positive, got {pid}")

        scope = _ptrace_scope()
        if scope is not None and scope >= 1:
            raise GdbBridgeError(
                f"the kernel's Yama ptrace_scope is {scope}, which blocks "
                "attaching to a process that is not a child of the debugger. "
                "Run the server with CAP_SYS_PTRACE, or set "
                "/proc/sys/kernel/yama/ptrace_scope to 0 on an isolated "
                "analysis machine."
            )

        self._require(f"-target-attach {pid}", "attaching to the process")
        self._state = DebuggerState.PAUSED
        return True

    def detach(self) -> bool:
        self._require("-target-detach", "detaching from the process")
        self._state = DebuggerState.NOT_LOADED
        return True

    def get_modules(self) -> list[dict[str, Any]]:
        """Loaded objects with their runtime ranges."""
        response = self._require("-file-list-shared-libraries", "listing modules")
        libraries = response.results.get("shared-libraries") or []
        return [lib for lib in libraries if isinstance(lib, dict)]

    def resolve_static_address(self, static_address: str) -> str:
        """Map a link-time address from static analysis to its runtime address.

        ``runtime = static - link_base + load_base``. For a non-PIE ET_EXEC
        the two bases are equal and this is the identity; for PIE the load
        base is read from the running process.

        Raises:
            GdbBridgeError: No binary is loaded, or the load base is not yet
                knowable because the target has not started.
        """
        value = _require_hex_address(static_address)
        if self._binary_path is None or self._link_base is None:
            raise GdbBridgeError(
                "no binary is loaded, so there is no link base to rebase from"
            )

        load_base = self._resolve_load_base()
        if load_base is None:
            raise GdbBridgeError(
                "the target's load base is not known yet. Start the target "
                "before rebasing a static address, because a PIE binary has "
                "no load base until it is mapped."
            )
        return f"0x{value - self._link_base + load_base:x}"

    def _resolve_load_base(self) -> int | None:
        if self._load_base is not None:
            return self._load_base
        if self._binary_path is None:
            return None
        if self._state not in (DebuggerState.PAUSED, DebuggerState.RUNNING):
            return None

        mappings = self.execute_console("info proc mappings")
        target = str(self._binary_path)
        lowest: int | None = None
        for line in mappings.splitlines():
            fields = line.split()
            if len(fields) >= 6 and fields[-1] == target:
                try:
                    start = int(fields[0], 16)
                except ValueError:
                    continue
                lowest = start if lowest is None else min(lowest, start)
        self._load_base = lowest
        return lowest

    def execute_console(self, command: str) -> str:
        """Run an allowlisted console command and return its console output.

        The console reaches ``shell`` and ``python``, so the command is
        validated before it is sent rather than after. The validator is an
        allowlist: anything it does not recognise is refused.
        """
        allowed, reason = validate_console_command(command)
        if not allowed:
            raise GdbBridgeError(f"console command refused: {reason}")

        response = self._command(
            f'-interpreter-exec console {quote_mi_argument(command)}'
        )
        if response.is_error:
            raise GdbBridgeError(
                f"console command failed: {response.error_message}"
            )
        return response.console_text


def _ptrace_scope() -> int | None:
    """Yama's ptrace_scope, or None where the LSM is absent."""
    try:
        return int(_PTRACE_SCOPE.read_text().strip())
    except (OSError, ValueError):
        return None


def _read_elf_link_base(path: Path) -> int | None:
    """Lowest PT_LOAD virtual address, which is the ELF's link base.

    Returns None when the file cannot be read as an ELF, so a caller that
    never rebases is not blocked by it.
    """
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as handle:
            elf = ELFFile(handle)
            loads = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
            if not loads:
                return None
            return min(int(s["p_vaddr"]) for s in loads)
    except Exception as exc:
        logger.debug("Could not read an ELF link base", exc_info=exc)
        return None


__all__ = ["GdbBridge", "GdbBridgeError", "MAX_READ_BYTES"]
