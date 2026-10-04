"""Tests for the GDB console-command allowlist.

The rejection corpus is not imagined. Every payload in ``PROVEN_ESCAPES`` was
executed against GNU gdb 15.1 while this module was written, and the live test
at the bottom re-proves it on demand: it runs each payload through a real GDB
and asserts a marker file appears, then asserts the allowlist refuses the same
string. A rejection test alone would pass just as happily against a payload
that never worked.
"""

from __future__ import annotations

import os
import shutil
import sys
import time

import pytest

from src.engines.dynamic.gdb.allowlist import (
    MAX_COMMAND_LENGTH,
    allowed_commands,
    allowed_info_subcommands,
    validate_console_command,
)

GDB = shutil.which("gdb")

# Payloads confirmed to execute on gdb 15.1. {marker} is substituted with a
# path the test then checks for. Each entry is (label, payload template).
PROVEN_ESCAPES = [
    ("shell", "shell touch {marker}"),
    ("bang alias for shell", "!touch {marker}"),
    ("python one-liner", "python open('{marker}','w')"),
    ("$_shell inside print", 'print $_shell("touch {marker}")'),
    ("$_shell inside x", 'x/1x $_shell("touch {marker}")'),
    ("pipe into a shell command", "pipe show version | touch {marker}"),
]


class TestProvenEscapesAreRejected:
    @pytest.mark.parametrize(
        "payload",
        [template.format(marker="/tmp/marker") for _, template in PROVEN_ESCAPES],
    )
    def test_each_proven_escape_is_refused(self, payload):
        ok, reason = validate_console_command(payload)
        assert not ok, f"allowlist admitted a payload proven to execute: {payload!r}"
        assert reason


class TestScriptingAndCarriers:
    """Commands whose arguments are themselves commands, or that defer them."""

    @pytest.mark.parametrize(
        "payload",
        [
            "eval \"print %d\", 1+1",
            "with confirm off -- shell id",
            "thread apply all shell id",
            "frame apply all shell id",
            "taas shell id",
            "faas shell id",
            "define pwn",
            "document pwn",
            "alias pwn = shell",
            "commands 1",
            "source /tmp/script.gdb",
            "guile (system \"id\")",
            "gu (system \"id\")",
            "pi __import__('os').system('id')",
            "py 1",
            "compile code system(\"id\");",
            "compile file /tmp/x.c",
            "make",
            "edit",
        ],
    )
    def test_carrier_and_scripting_commands_are_refused(self, payload):
        ok, _ = validate_console_command(payload)
        assert not ok, f"carrier command admitted: {payload!r}"


class TestHostFilesystemAndHardening:
    @pytest.mark.parametrize(
        "payload",
        [
            "dump binary memory /tmp/out 0 100",
            "append binary memory /tmp/out 0 100",
            "restore /tmp/in binary 0",
            "set logging file /tmp/out",
            "set logging enabled on",
            # Undoing the session layer's own hardening.
            "set startup-with-shell on",
            "set auto-load on",
            "set confirm on",
            "add-auto-load-safe-path /",
            # Process and target control belongs to the structured tools.
            "attach 1",
            "detach",
            "kill",
            "run",
            "start",
            "target remote :1234",
            # Changing execution.
            "jump *0x400000",
            "return",
            "call system(\"id\")",
        ],
    )
    def test_refused(self, payload):
        ok, _ = validate_console_command(payload)
        assert not ok, f"admitted: {payload!r}"


class TestExpressionCommandsAreNotAdmitted:
    """print/x/output evaluate expressions, which is where $_shell lives."""

    @pytest.mark.parametrize(
        "payload",
        ["print 1+1", "p 1", "output 1", "printf \"%d\", 1", "x/4x 0x400000",
         "ptype int", "echo hi"],
    )
    def test_refused(self, payload):
        ok, _ = validate_console_command(payload)
        assert not ok, f"expression command admitted: {payload!r}"


class TestAbbreviationsAreRefused:
    """GDB resolves unique prefixes; the allowlist matches exact names only.

    "she" reaches shell, so accepting abbreviations would mean enumerating
    every prefix of every dangerous command. Refusing them costs a little
    convenience and closes the class.
    """

    @pytest.mark.parametrize("payload", ["she id", "sh id", "pyt 1", "i proc", "inf proc"])
    def test_refused(self, payload):
        ok, _ = validate_console_command(payload)
        assert not ok, f"abbreviation admitted: {payload!r}"


class TestForbiddenCharacters:
    @pytest.mark.parametrize(
        "payload",
        [
            "info proc | touch /tmp/x",
            "info proc ; shell id",
            "info proc > /tmp/x",
            "info proc < /tmp/x",
            "info proc `id`",
            "info proc $(id)",
            "info proc & ",
            "info proc\nshell id",
            "info proc\rshell id",
            "info proc\x00shell id",
        ],
    )
    def test_refused(self, payload):
        ok, reason = validate_console_command(payload)
        assert not ok, f"admitted: {payload!r}"
        assert reason


class TestConvenienceFunctionShape:
    """Matching the shape, not the name, so a future $_... is refused too."""

    @pytest.mark.parametrize(
        "payload",
        [
            'show $_shell("id")',
            'show $_anything_new("id")',
            "show $_ (x)",
            "backtrace $_shell(1)",
        ],
    )
    def test_refused(self, payload):
        ok, reason = validate_console_command(payload)
        assert not ok
        assert reason


class TestAllowedCommands:
    @pytest.mark.parametrize(
        "payload",
        [
            "info proc",
            "info proc mappings",
            "info sharedlibrary",
            "info threads",
            "info breakpoints",
            "info functions",
            "info registers",
            "info auto-load",
            "show confirm",
            "show startup-with-shell",
            "show auto-load local-gdbinit",
            "backtrace",
            "backtrace 10",
            "backtrace full",
            "bt",
            "where",
            "frame",
            "frame 2",
            "thread 1",
            "list",
            "list 10",
            "list 10,20",
            "version",
        ],
    )
    def test_accepted(self, payload):
        ok, reason = validate_console_command(payload)
        assert ok, f"rejected a safe command {payload!r}: {reason}"


class TestArgumentForms:
    def test_unknown_info_subcommand_is_refused(self):
        ok, reason = validate_console_command("info symbol 0x400000")
        assert not ok
        assert "allowlist" in reason

    def test_bare_info_is_refused_with_guidance(self):
        ok, reason = validate_console_command("info")
        assert not ok
        assert "proc" in reason

    def test_info_regexp_argument_is_refused(self):
        """info functions takes a regexp; attacker-influenced regexps stay out."""
        ok, _ = validate_console_command("info functions ^(a+)+$")
        assert not ok

    def test_frame_rejects_an_expression_selector(self):
        ok, _ = validate_console_command("frame address $sp")
        assert not ok

    def test_backtrace_rejects_a_non_count_argument(self):
        ok, _ = validate_console_command("backtrace -full-of-nonsense")
        assert not ok

    def test_empty_and_whitespace(self):
        for payload in ("", "   ", "\t"):
            ok, reason = validate_console_command(payload)
            assert not ok
            assert reason == "empty command"

    def test_overlong_command(self):
        ok, reason = validate_console_command("info proc " + "a" * MAX_COMMAND_LENGTH)
        assert not ok
        assert "too long" in reason


class TestIntrospection:
    def test_allowed_sets_are_exposed_and_immutable(self):
        assert isinstance(allowed_commands(), frozenset)
        assert "backtrace" in allowed_commands()
        assert "shell" not in allowed_commands()
        assert "print" not in allowed_commands()
        assert "proc" in allowed_info_subcommands()
        assert "symbol" not in allowed_info_subcommands()

    def test_no_allowed_command_evaluates_an_expression(self):
        """A guard against someone adding print/call/x later."""
        expression_commands = {
            "print", "p", "output", "printf", "echo", "x", "call", "set",
            "ptype", "whatis", "eval", "pipe", "with", "shell", "python",
        }
        assert not (allowed_commands() & expression_commands)


@pytest.mark.skipif(GDB is None, reason="gdb not installed")
@pytest.mark.skipif(sys.platform != "linux", reason="POSIX shell payloads")
class TestEscapesReallyExecute:
    """Prove the rejection corpus is real rather than theoretical.

    For each payload: run it through a real GDB and assert the marker file
    appears, then assert the allowlist refuses the same string. If GDB is ever
    hardened upstream so a payload stops working, this fails loudly and the
    corpus gets revisited -- which is the point.
    """

    @pytest.mark.parametrize("label,template", PROVEN_ESCAPES, ids=[p[0] for p in PROVEN_ESCAPES])
    def test_payload_executes_and_is_refused(self, label, template, tmp_path):
        from src.engines.dynamic.gdb.mi_session import MISession

        marker = tmp_path / "executed"
        payload = template.format(marker=marker)

        session = MISession(timeout=20)
        session.start()
        try:
            escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
            session.send(f'-interpreter-exec console "{escaped}"')
            for _ in range(20):
                if marker.exists():
                    break
                time.sleep(0.1)
        finally:
            session.stop()

        assert marker.exists(), (
            f"payload {label!r} did not execute on this GDB; the corpus entry "
            "may be stale and should be re-checked rather than trusted"
        )
        os.remove(marker)

        ok, reason = validate_console_command(payload)
        assert not ok, f"allowlist admits {label!r}, which just executed"
        assert reason
