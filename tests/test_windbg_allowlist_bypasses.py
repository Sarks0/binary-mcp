"""
Regression tests for the WinDbg allowlist bypasses (audit H1, H2, H3).

The token-aware validator split subcommands only on ``;`` and blocked a set of
dangerous first tokens. Three separator/expansion holes let a denied command
reach cdb anyway:

  H1 newline injection   -- ``k\\n.shell calc`` was validated as just ``k``,
     because WinDbg treats a raw newline as a command separator but
     parse_compound did not.
  H2 script-file include -- ``$<C:\\evil.wds`` (and $><, $$<, $$><, $$>a<) runs
     an arbitrary debugger command file from disk; none were denied.
  H3 alias definition    -- ``aS x .shell`` / ``aS x eb`` defines an alias that
     WinDbg expands before command-name resolution, smuggling a denied
     primitive past the first-token check.
"""

from __future__ import annotations

import pytest

from src.engines.dynamic.windbg.allowlist import parse_compound, validate_command

# -- H1: a newline is a subcommand separator, validated like ';' --


class TestNewlineInjection:
    @pytest.mark.parametrize("sep", ["\n", "\r", "\r\n"])
    @pytest.mark.parametrize("payload", [
        "k{sep}.shell calc",       # denied first token after the newline
        "r @rip{sep}eb 1000 90",   # denied write-primitive after the newline
        "g{sep}.dvalloc 0x1000",   # RWX alloc after the newline
    ])
    def test_denied_command_after_newline_is_caught(self, sep, payload):
        ok, reason = validate_command(payload.format(sep=sep))
        assert ok is False, f"{payload!r} with {sep!r} slipped through"
        assert reason

    def test_parse_compound_splits_on_newline(self):
        assert parse_compound("k\n.shell calc") == ["k", ".shell calc"]

    def test_crlf_between_two_reads_does_not_create_empty_subcommand(self):
        # \r\n must not yield an empty middle subcommand that gets rejected.
        ok, reason = validate_command("k\r\nlm")
        assert ok is True, reason

    def test_multiline_all_read_still_allowed(self):
        ok, reason = validate_command("k\nr @rip\nlm m nt")
        assert ok is True, reason


# -- H2: script-file include operators are denied --


class TestScriptFileInclude:
    @pytest.mark.parametrize("op", ["$<", "$><", "$$<", "$$><", "$$>a<"])
    def test_script_include_denied(self, op):
        ok, reason = validate_command(f"{op}C:\\evil.wds")
        assert ok is False, f"{op!r} include should be denied"
        assert reason

    def test_script_include_denied_after_newline(self):
        ok, _ = validate_command("k\n$$>a<C:\\evil.wds")
        assert ok is False

    def test_legit_pseudo_register_still_allowed(self):
        # $ is also used for pseudo-registers/aliases; those must NOT be denied.
        ok, reason = validate_command("dd @$teb")
        assert ok is True, reason


# -- H3: alias-definition family is denied --


class TestAliasDefinition:
    @pytest.mark.parametrize("cmd", [
        "aS x .shell",
        "as x .shell",
        "aS x eb",
        "aS /x foo bar",
        "ad x",
        "ad *",
        ".cmdtree C:\\evil.txt",
    ])
    def test_alias_family_denied(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} should be denied"
        assert reason

    def test_alias_definition_denied_after_newline(self):
        ok, _ = validate_command("g\naS x .shell")
        assert ok is False
