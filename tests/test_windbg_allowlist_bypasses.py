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

A later audit round found two more, both verified by execution:

  F-1 quoted subcommand  -- ``j`` (Execute If-Else) and ``z`` (Execute While)
     delimit their subcommands with SINGLE QUOTES, and parse_compound treats
     ``'`` as a protected region. Everything inside ``j 1 '...'`` was
     therefore never validated: ``j 1 '$$><c:\\tmp\\evil.txt'`` ran an
     arbitrary debugger command file (-> ``.shell`` -> RCE on the analyst
     host), ``j 1 'eb <kaddr> 90'`` wrote kernel memory, ``j 1 '.dvalloc'``
     allocated RWX in the target and ``j 1 'a 401000'`` assembled shellcode.
  F-2 missing writes     -- ``f`` (Fill), ``m`` (Move), ``ef`` (enter float)
     and bare ``e`` are memory-write primitives that were absent from the
     deny set and passed both gates directly, no ``j`` wrapper needed.
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


# -- F-1: single-quoted subcommand bodies are validated --

# The four payloads from the audit, each verified to have reached the debugger
# before the fix. Kept verbatim so the regression is unambiguous.
_J_PAYLOADS = [
    "j 1 '$$><c:\\tmp\\evil.txt'",   # arbitrary command file -> .shell -> RCE
    "j 1 'eb ffff800000000000 90'",  # kernel memory write
    "j 1 '.dvalloc 1000'",           # RWX allocation in the target
    "j 1 'a 401000'",                # assemble shellcode into the target
]


class TestQuotedSubcommandBody:
    @pytest.mark.parametrize("cmd", _J_PAYLOADS)
    def test_j_payloads_denied(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} slipped through"
        assert reason

    @pytest.mark.parametrize("cmd", [
        c.replace("j 1 ", "z ", 1) for c in _J_PAYLOADS
    ])
    def test_z_payloads_denied(self, cmd):
        # 'z' (Execute While) has the same single-quoted body syntax.
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} slipped through"
        assert reason

    @pytest.mark.parametrize("cmd", ["j 1 '.shell calc'", "z '.shell calc'"])
    def test_driver_command_denied_by_name(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False
        assert "denied" in reason

    def test_quoted_body_denied_even_when_driver_token_is_unrecognised(self):
        # The fix must not depend on naming the outer command: 'j(1)' does not
        # match a 'j' deny token (the expression is glued to the command name).
        # Under the allowlist that variation is exactly what fails closed --
        # an unrecognised command name is refused before its body matters.
        ok, reason = validate_command("j(1) '.shell calc'")
        assert ok is False
        assert "allowlist" in reason

    def test_quoted_body_reason_is_prefixed(self):
        ok, reason = validate_command("bp X '.dvalloc 1000'")
        assert ok is False
        assert reason.startswith("in quoted subcommand: ")

    @pytest.mark.parametrize("cmd", [
        "bp X 'foo ; .shell calc",     # single quote never closes
        'bp X ".shell calc',           # double quote never closes
        "lm 'foo ; .shell calc",       # ... behind a NON-carrier, so nothing
        'lm "foo ; .shell calc',       #     would have recursed into the tail
    ])
    def test_unterminated_quoted_region_fails_closed(self, cmd):
        # parse_compound stops splitting on ';' once a quote opens, so each of
        # these is a single subcommand behind a harmless first token. The
        # validator refuses structurally malformed input rather than guessing
        # where cdb would resume splitting.
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} slipped through"
        assert "unterminated" in reason

    def test_unterminated_block_fails_closed(self):
        # Same hole with a brace: the block never closes, so the block
        # extractor never sees the payload and the splitter never separates it.
        ok, reason = validate_command(
            ".foreach (a {!process 0 0}) {!handle ${a} ; .shell calc"
        )
        assert ok is False
        assert "unterminated" in reason

    def test_quoted_body_inside_foreach_block_denied(self):
        ok, reason = validate_command(
            ".foreach (a {!process 0 0}) {j 1 '.shell calc'}"
        )
        assert ok is False
        assert reason

    def test_apostrophe_inside_double_quotes_is_literal_text(self):
        # A double-quoted string is argument text, not a subcommand body; an
        # apostrophe in it must not open a phantom quoted region.
        ok, reason = validate_command(".printf \"it's fine\"")
        assert ok is True, reason

    def test_conditional_breakpoint_command_string_still_allowed(self):
        # Exactly what windbg_set_conditional_breakpoint builds.
        ok, reason = validate_command(
            'bp 0x1000 ".if (rcx==0x100) {} .else {gc}"'
        )
        assert ok is True, reason


# -- F-1: recursion is depth-capped, not stack-bounded --


class TestRecursionDepth:
    def test_deeply_nested_block_rejected_not_crashed(self):
        # ~1500 levels of nesting inside the 4096-char limit. Without a depth
        # cap this recursed once per level and raised RecursionError out of
        # the validator instead of returning a verdict. Under the allowlist
        # the bare '{{{...' token is refused before any recursion happens;
        # either way the requirement is a verdict, not an exception.
        cmd = "{" * 1500 + ".shell calc" + "}" * 1500
        ok, reason = validate_command(cmd)
        assert ok is False
        assert reason

    def test_depth_cap_fires_on_a_legitimate_carrier_chain(self):
        # Nesting through an ALLOWED carrier is the case that actually
        # recurses, so this is where the cap has to hold.
        payload = "!process 0 0"
        for _ in range(40):
            payload = ".if (1) {" + payload + "}"
        ok, reason = validate_command(payload)
        assert ok is False
        assert "too deep" in reason

    def test_deeply_nested_quoted_command_rejected_not_crashed(self):
        payload = ".shell calc"
        for _ in range(300):
            payload = "{'" + payload + "'}"
        ok, reason = validate_command(payload)
        assert ok is False
        assert reason

    def test_normal_nesting_still_under_the_cap(self):
        # Two levels of legitimate nesting must keep working.
        ok, reason = validate_command(
            ".foreach (a {!process 0 0}) {.foreach (b {!handle ${a}}) {!thread ${b}}}"
        )
        assert ok is True, reason


# -- F-2: the rest of the memory-write family --


class TestMemoryWriteFamily:
    @pytest.mark.parametrize("cmd", [
        "f 1000 L100 90",              # Fill Memory
        "f ffff800000000000 L20 cc",   # Fill kernel range
        "m 1000 1100 2000",            # Move Memory
        "ef 1000 1.5",                 # Enter 4-byte float
        "e 1000 90",                   # bare Enter Values (last-used type)
        "E 1000 90",                   # first token is lowercased
        "eD 1000 1.5",                 # folds onto the already-denied 'ed'
    ])
    def test_write_primitive_denied(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} should be denied"
        assert reason

    @pytest.mark.parametrize("cmd", [
        "g\nf 1000 L100 90",
        "k; m 1000 1100 2000",
        "j 1 'f 1000 L100 90'",
    ])
    def test_write_primitive_denied_when_nested(self, cmd):
        ok, reason = validate_command(cmd)
        assert ok is False, f"{cmd!r} should be denied"
        assert reason

    @pytest.mark.parametrize("cmd", [
        "db 0x1000",
        "dd 0x1000",
        "dt nt!_EPROCESS",
        "!process 0 0",
        "u nt!KeBugCheckEx L10",
        "x nt!Ps*",
        "lm m nt",
    ])
    def test_read_commands_unaffected(self, cmd):
        # The new single-letter deny tokens must not shadow read commands.
        ok, reason = validate_command(cmd)
        assert ok is True, f"{cmd!r} should still be allowed; got: {reason}"


# -- The include operators are refused by the one authoritative gate --


class TestScriptIncludeRefusedByTheAuthoritativeGate:
    """The tool-layer substring scan is gone; the allowlist must stand alone.

    ``_BLOCKED_COMMANDS`` used to be scanned by ``windbg_execute_command`` as a
    second gate. It is no longer consulted by any code path (a denylist in
    front of an allowlist can only add false refusals), so the include
    operators have to be refused by the validator itself -- in every position a
    compound command can put them.
    """

    @pytest.mark.parametrize("op", ["$<", "$><", "$$<", "$$><", "$$>a<"])
    @pytest.mark.parametrize("template", [
        "{op}c:\\evil.wds",
        "k; {op}c:\\evil.wds",
        "k\n{op}c:\\evil.wds",
        "bp X \"{op}c:\\evil.wds\"",
        ".foreach (a {{!process 0 0}}) {{{op}c:\\evil.wds}}",
    ])
    def test_include_operator_refused_in_every_position(self, op, template):
        ok, reason = validate_command(template.format(op=op))
        assert ok is False, f"{template.format(op=op)!r} slipped through"
        assert reason
