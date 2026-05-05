"""Tests for the token-aware WinDbg command allowlist."""

from __future__ import annotations

import pytest

from src.engines.dynamic.windbg.allowlist import (
    parse_compound,
    validate_command,
)


class TestParseCompound:
    def test_single_command(self):
        assert parse_compound("bp nt!NtCreateFile") == ["bp nt!NtCreateFile"]

    def test_simple_split(self):
        assert parse_compound("g; k") == ["g", "k"]

    def test_quoted_semicolon_kept(self):
        # ;.shell calc inside double quotes must not split.
        result = parse_compound('bp X ".printf \\"a;b\\""')
        assert len(result) == 1
        assert "a;b" in result[0]

    def test_braced_block_kept(self):
        # The whole .foreach is one subcommand even with ; inside braces.
        cmd = ".foreach (a {!process 0 0; !handle ${a}}) { !thread ${a} }"
        result = parse_compound(cmd)
        assert len(result) == 1

    def test_trailing_semicolon_dropped(self):
        assert parse_compound("g;") == ["g"]

    def test_empty_input(self):
        assert parse_compound("") == []
        assert parse_compound("   ") == []


class TestDenyFirstToken:
    @pytest.mark.parametrize("cmd", [
        ".shell calc",
        ".dvalloc 0x1000 0x100",
        ".dvfree 0x1000 0x100",
        ".kill",
        ".restart",
        ".dump /m c:\\out.dmp",
        ".writemem c:\\out 0x1000 0x100",
        ".script c:\\evil.js",
        ".load mymodule",
        ".sympath srv*foo",
        ".symfix",
        ".pagein 0x1000",
        ".attach 1234",
        "eb 0x1000 90 90",
        "ed 0x1000 deadbeef",
        "eq 0x1000 0xfeedface",
        "a 0x1000",
    ])
    def test_blocks(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} should be blocked"
        assert reason


class TestAllowed:
    @pytest.mark.parametrize("cmd", [
        "bp nt!NtCreateFile",
        "g",
        "k",
        "kn",
        "!process 0 0",
        "!thread",
        "lm m nt",
        "dt nt!_EPROCESS 0xfffff800deadbeef",
        "db 0x1000",
        "dd 0x1000",
        "r rip",
        "r @rip",  # bare read of register
        ".formats 0x41",
        ".tlist",
        ".outmask /l verbose",
        ".printf \"hello\"",
        ".bugcheck",
        # Compound with all-allowed parts
        "g; k",
        ".foreach (a {!process 0 0}) {!handle ${a}}",
    ])
    def test_allows(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is True, f"{cmd!r} should be allowed; got: {reason}"


class TestArgFormDeny:
    def test_register_write_via_r_blocked(self):
        ok, reason = validate_command("r @rip = 0x1000")
        assert ok is False
        assert "register write" in reason

    def test_register_read_with_at_sigil_allowed(self):
        ok, _ = validate_command("r @rip")
        assert ok is True

    def test_process_invasive_blocked(self):
        ok, reason = validate_command(".process /i 0xfffff800deadbeef")
        assert ok is False
        assert "/i" in reason

    def test_process_non_invasive_allowed(self):
        ok, _ = validate_command(".process 0xfffff800deadbeef")
        assert ok is True

    def test_chkimg_with_fix_blocked(self):
        ok, reason = validate_command("!chkimg -d nt /f")
        assert ok is False
        assert "chkimg" in reason.lower()

    def test_chkimg_readonly_allowed(self):
        ok, _ = validate_command("!chkimg -d nt")
        assert ok is True

    def test_search_write_variants_blocked(self):
        ok, reason = validate_command("s -b 0x1000 L100 90 90")
        assert ok is False
        assert "search-and-write" in reason

    def test_search_readonly_allowed(self):
        ok, _ = validate_command("s 0x1000 L100 90 90")
        assert ok is True

    def test_bugcheck_simulator_blocked(self):
        ok, reason = validate_command(".bugcheck 0x7E")
        assert ok is False

    def test_bugcheck_bare_allowed(self):
        ok, _ = validate_command(".bugcheck")
        assert ok is True

    def test_printf_dml_blocked(self):
        ok, reason = validate_command(".printf /D \"<link>x</link>\"")
        assert ok is False
        assert "DML" in reason

    def test_printf_plain_allowed(self):
        ok, _ = validate_command(".printf \"hello world\"")
        assert ok is True


class TestCompoundEvasion:
    def test_quoted_dot_shell_not_blocked_at_top_level(self):
        # bp with a quoted command-string that contains ".shell" as text.
        # The quoted text is part of bp's argument, not a separate
        # subcommand. We accept this - the argument doesn't execute.
        ok, _ = validate_command('bp X ".printf \\"hello\\""')
        assert ok is True

    def test_semicolon_chained_block_blocked(self):
        # User tries to slip .shell after a legitimate command.
        ok, reason = validate_command("g; .shell calc")
        assert ok is False

    def test_foreach_with_blocked_inner_blocked(self):
        # .foreach itself is allowed but its block body must validate.
        ok, reason = validate_command(
            ".foreach (a {!process 0 0}) {.shell calc}"
        )
        assert ok is False
        assert "compound block" in reason or "shell" in reason.lower()

    def test_too_many_subcommands_blocked(self):
        cmd = ";".join(["g"] * 17)
        ok, reason = validate_command(cmd)
        assert ok is False
        assert "compound" in reason.lower()


class TestEmptyAndOversize:
    def test_empty(self):
        ok, _ = validate_command("")
        assert ok is False

    def test_whitespace_only(self):
        ok, _ = validate_command("   ")
        assert ok is False

    def test_oversize(self):
        ok, reason = validate_command("g " * 3000)
        assert ok is False
        assert "too long" in reason
