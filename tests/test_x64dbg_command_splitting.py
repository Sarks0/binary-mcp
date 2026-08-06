"""
Regression tests for x64dbg ';' command splitting (audit findings F-9 / F-16).

THE BUG
-------
All three gates between ``x64dbg_execute_command`` and x64dbg's ``DbgCmdExec``
validated the FIRST TOKEN of the WHOLE string. x64dbg does not dispatch the
whole string: ``cmdsplit`` (x64dbg/x64dbg, src/dbg/command.cpp:207-253) chops it
on ';' and ``cmddirectexec`` then trims and dispatches EACH segment on its own.

So a string beginning with an allowlisted command carried arbitrary extra
commands past every gate::

    'init C:/evil.exe'                -> refused (allowlist)
    'InitDebug C:/evil.exe'           -> refused (allowlist catches the alias)
    'scriptcmd init C:/evil.exe'      -> refused (allowlist)
    'log x;init C:/evil.exe'          -> REACHED DbgCmdExec, LAUNCHING THE SAMPLE
    'log x;scriptcmd init C:/evil.exe'-> REACHED DbgCmdExec
    'log x;alloc 1000;memcpy 1000,2000,10;threadcreate 1000'
                                      -> REACHED DbgCmdExec (shellcode chain)

A static-analysis server that can be talked into executing the sample is the
cardinal-rule violation, so these tests are about the payloads above never
reaching a bridge call again -- at the TOOL layer and at the BRIDGE layer
independently, because either one alone is a single point of failure.

DESIGN DECISION: ';' INSIDE QUOTES
----------------------------------
x64dbg's cmdsplit IS quote-aware -- verified against the upstream source, which
runs a '"' / '\\' state machine and only splits on a ';' seen outside quotes.
``log "hello;world"`` is therefore genuinely ONE command to x64dbg, and
rejecting it would be a false positive. We mirror that state machine character
for character and let quoted ';' through as literal text.

The one place we deliberately diverge is an UNTERMINATED quote (or a dangling
trailing escape). x64dbg would treat the remainder as quoted, and so does our
mirror -- it is not a bypass today -- but that is precisely the input where two
independent parsers are most likely to drift apart across versions, and drift
here is measured in "the sample got launched". Malformed input is refused.
"""

from __future__ import annotations

import ast
import contextlib
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.engines.dynamic.x64dbg.bridge import (
    X64DbgBridge,
    split_x64dbg_command,
    x64dbg_command_name,
    x64dbg_command_segments,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DYNAMIC_TOOLS = REPO_ROOT / "src" / "tools" / "dynamic_tools.py"
PLUGIN_CPP = REPO_ROOT / "src" / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"


# The exact strings the audit executed against the real gate logic. Every one of
# them must now be refused, at both layers.
SPLIT_PAYLOADS = [
    "log x;init C:/evil.exe",
    "log x;scriptcmd init C:/evil.exe",
    "log x;alloc 1000;memcpy 1000,2000,10;threadcreate 1000",
]

# Single-command payloads that the first remediation pass already refused. They
# are re-asserted here so a change to the splitter cannot quietly un-refuse them.
DIRECT_PAYLOADS = [
    "init C:/evil.exe",
    "InitDebug C:/evil.exe",
    "scriptcmd init C:/evil.exe",
]

# Documented, supported usage -- the fix must not cost us these.
LEGITIMATE_COMMANDS = [
    "dis.prev(rip, 5)",
    "findall 0 E8",
    "findall 0, E8",
    'log "hello"',
    "cfanalyze",
    "eval 1+1",
    "bplist",
]


@pytest.fixture
def bridge() -> X64DbgBridge:
    """A bridge instance. The constructor performs no I/O, so this is offline-safe."""
    return X64DbgBridge()


class ToolHarness:
    """The registered tool plus the mock bridge standing in for x64dbg."""

    def __init__(self, tool, mock_bridge):
        self.tool = tool
        self.bridge = mock_bridge

    def __call__(self, command):
        return self.tool(command)

    @property
    def reached_x64dbg(self) -> bool:
        """
        Whether the string made it to ``bridge.execute_command``.

        This is the property the tests actually care about: a gate that refuses
        only after dispatching is not a gate. Note that the tool wraps its body
        in ``except Exception``, so "returned an error string" alone would not
        distinguish a refusal from a swallowed failure downstream.
        """
        return self.bridge.execute_command.called


@pytest.fixture
def execute_command_tool(monkeypatch):
    """The registered ``x64dbg_execute_command`` callable, wired to a mock bridge."""
    mod = pytest.importorskip(
        "src.tools.dynamic_tools", reason="dynamic_tools requires FastMCP"
    )

    captured: dict = {}

    def _decorator(*_a, **_kw):
        def _wrap(f):
            captured[f.__name__] = f
            return f

        return _wrap

    app = MagicMock()
    app.tool = MagicMock(side_effect=_decorator)
    monkeypatch.setattr(mod, "_session_manager", None, raising=False)
    mod.register_dynamic_tools(app, None)

    mock_bridge = MagicMock()
    mock_bridge.execute_command.return_value = {"success": True, "message": "ok"}
    monkeypatch.setattr(mod, "get_x64dbg_bridge", lambda: mock_bridge)
    return ToolHarness(captured["x64dbg_execute_command"], mock_bridge)


# ---------------------------------------------------------------------------
# The splitter mirrors x64dbg's cmdsplit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("log x", ["log x"]),
        ("log x;init C:/evil.exe", ["log x", "init C:/evil.exe"]),
        (
            "log x;alloc 1000;memcpy 1000,2000,10;threadcreate 1000",
            ["log x", "alloc 1000", "memcpy 1000,2000,10", "threadcreate 1000"],
        ),
        # Empty segments are dropped and survivors trimmed, exactly as
        # cmddirectexec does before dispatching.
        ("log x ;  ; init evil", ["log x", "init evil"]),
        (";;;log x", ["log x"]),
        ("log x;", ["log x"]),
        # Quote-aware: a ';' inside quotes is literal, so this is ONE command.
        ('log "hello;world"', ['log "hello;world"']),
        # ...and the quote closes, so a ';' after it splits again.
        ('log "a;b";init evil', ['log "a;b"', "init evil"]),
        # An escaped quote does not open a quoted region.
        (r'log \";init evil', [r'log \"', "init evil"]),
    ],
)
def test_split_matches_x64dbg_cmdsplit(command, expected):
    """
    F-16: the splitter has to agree with x64dbg's, not approximate it.

    A segment we fail to produce is a segment nobody validates, so each case
    here is taken from the semantics of cmdsplit's state machine.
    """
    assert split_x64dbg_command(command) == expected


def test_command_name_extraction():
    """The token tested against the allowlists is the command name, not the blob."""
    assert x64dbg_command_name("dis.prev(rip, 5)") == "dis.prev"
    assert x64dbg_command_name("init,C:/evil.exe") == "init"
    assert x64dbg_command_name("  InitDebug C:/evil.exe  ") == "initdebug"
    assert x64dbg_command_name("log\tx") == "log"


# ---------------------------------------------------------------------------
# Structural rejections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["", "   ", "\t", " \t ", None])
def test_empty_input_raises_value_error_not_index_error(command):
    """
    F-12 must survive the rewrite: empty input is a ValueError, never IndexError.

    Callers treat ValueError as "rejected input"; an IndexError escapes as an
    opaque internal error and reads to a caller like a server bug rather than a
    refusal.
    """
    with pytest.raises(ValueError) as exc_info:
        x64dbg_command_segments(command)

    assert not isinstance(exc_info.value, IndexError)
    assert "empty" in str(exc_info.value).lower()


@pytest.mark.parametrize("command", ["", "   ", "\t", " \t "])
def test_bridge_validate_command_still_rejects_empty(bridge, command):
    with pytest.raises(ValueError) as exc_info:
        bridge._validate_command(command)

    assert not isinstance(exc_info.value, IndexError)
    assert "empty" in str(exc_info.value).lower()


@pytest.mark.parametrize("command", ["", "   ", "\t"])
def test_tool_rejects_empty(execute_command_tool, command):
    assert "empty" in execute_command_tool(command).lower()
    assert not execute_command_tool.reached_x64dbg


@pytest.mark.parametrize(
    "command",
    [
        "$log x",
        "  $log x",
        "$ log x",
        # '$' after a split: refused per-segment as well, so the rule does not
        # depend on where in the string the caller put it.
        "log x;$log y",
    ],
)
def test_dollar_prefix_is_refused(bridge, execute_command_tool, command):
    """
    F-16: cmdsplit runs stringformatinline over a '$'-prefixed command BEFORE
    splitting (command.cpp:211-218), so the text that gets split on ';' is the
    EXPANSION, not the text we validated. An expansion that yields a ';' would
    smuggle in a command no gate ever saw. The expansion depends on live
    debuggee state and cannot be evaluated here, so the prefix is refused.
    """
    with pytest.raises(ValueError, match=r"\$"):
        x64dbg_command_segments(command)

    with pytest.raises(ValueError):
        bridge._validate_command(command)

    assert execute_command_tool(command).startswith("Error:")
    assert not execute_command_tool.reached_x64dbg


@pytest.mark.parametrize(
    "command",
    [
        "log x\ninit C:/evil.exe",
        "log x\rinit C:/evil.exe",
        "log x\r\ninit C:/evil.exe",
    ],
)
def test_embedded_line_breaks_are_refused(bridge, execute_command_tool, command):
    """x64dbg's script/log-redirection surface is line-oriented; CR/LF is a second command."""
    with pytest.raises(ValueError, match="line break"):
        x64dbg_command_segments(command)

    with pytest.raises(ValueError):
        bridge._validate_command(command)

    assert execute_command_tool(command).startswith("Error:")
    assert not execute_command_tool.reached_x64dbg


def test_nul_byte_is_refused(bridge, execute_command_tool):
    """
    A NUL truncates at the C boundary: what we validate past it is not what
    x64dbg sees, and vice versa. Refuse rather than reason about it.
    """
    command = "log x\x00;init C:/evil.exe"

    with pytest.raises(ValueError, match="NUL"):
        x64dbg_command_segments(command)

    with pytest.raises(ValueError):
        bridge._validate_command(command)

    assert execute_command_tool(command).startswith("Error:")
    assert not execute_command_tool.reached_x64dbg


def test_unterminated_quote_is_refused(bridge, execute_command_tool):
    """See the module docstring: the one deliberate divergence from cmdsplit."""
    command = 'log "hello'

    with pytest.raises(ValueError, match="unterminated quote"):
        x64dbg_command_segments(command)

    with pytest.raises(ValueError):
        bridge._validate_command(command)

    assert execute_command_tool(command).startswith("Error:")
    assert not execute_command_tool.reached_x64dbg


# ---------------------------------------------------------------------------
# The verified payloads -- tool layer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", SPLIT_PAYLOADS + DIRECT_PAYLOADS)
def test_tool_layer_refuses_payload(execute_command_tool, command):
    """
    F-9/F-16 at the tool layer.

    ``reached_x64dbg`` is the load-bearing assertion: the string must be refused
    before ``bridge.execute_command`` is ever called, because by the time
    x64dbg has the string it has already run the earlier segments.
    """
    result = execute_command_tool(command)
    assert result.startswith("Error:"), result
    assert "not in the allowed command list" in result
    assert not execute_command_tool.reached_x64dbg


def test_tool_layer_names_the_offending_segment(execute_command_tool):
    """The refusal must name the segment that failed, not the harmless first one."""
    result = execute_command_tool("log x;init C:/evil.exe")
    assert "'init'" in result
    assert "'log'" not in result


# ---------------------------------------------------------------------------
# The verified payloads -- bridge layer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", SPLIT_PAYLOADS + DIRECT_PAYLOADS)
def test_bridge_layer_refuses_payload(bridge, command):
    """F-9/F-16 at the bridge layer, which must stand on its own."""
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(command)


@pytest.mark.parametrize("command", SPLIT_PAYLOADS + DIRECT_PAYLOADS)
def test_execute_command_refuses_payload_before_any_request(bridge, command):
    """No HTTP round trip may happen for a refused string."""

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("_request_with_retry called for a refused command")

    bridge._request_with_retry = explode  # type: ignore[method-assign]

    with pytest.raises(ValueError):
        bridge.execute_command(command)


@pytest.mark.parametrize(
    "dangerous",
    [
        # scriptcmd/scriptexec reach cmddirectexec -- the full dispatcher.
        "scriptcmd", "scriptexec", "dllscript",
        # Shellcode staging inside the debuggee.
        "alloc", "memcpy", "fill", "memset", "copystr", "strcpy", "asm",
        "setpagerights", "threadcreate", "threadnew",
        # Arbitrary writes on the analyst's host / privilege escalation.
        "minidump", "savelog", "logsave", "redirectlog", "logredirect",
        "restartadmin", "runas", "adminrestart",
        # Stores a command x64dbg later runs through cmddirectexec.
        "setbreakpointcommand", "bpcommand",
        "addfavouritetool", "addfavouritecommand",
        "loadplugin",
    ],
)
def test_newly_identified_dangerous_commands_are_refused(bridge, dangerous):
    """
    F-16: these were reachable because nobody had enumerated them.

    Named explicitly so the fix cannot be reduced to "the allowlist happens to
    exclude them today".
    """
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(f"{dangerous} 1000")

    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(f"log x;{dangerous} 1000")


# ---------------------------------------------------------------------------
# No collateral damage: legitimate commands still work
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", LEGITIMATE_COMMANDS)
def test_legitimate_commands_pass_bridge_layer(bridge, command):
    bridge._validate_command(command)  # must not raise


@pytest.mark.parametrize("command", LEGITIMATE_COMMANDS)
def test_legitimate_commands_pass_tool_layer(execute_command_tool, command):
    """The documented examples must still reach the bridge unchanged."""
    result = execute_command_tool(command)

    assert execute_command_tool.reached_x64dbg, result
    execute_command_tool.bridge.execute_command.assert_called_once_with(command.strip())
    assert result.startswith("Command executed:")


def test_semicolon_inside_quotes_is_not_a_false_rejection(bridge):
    """
    x64dbg's cmdsplit is quote-aware, so this really is ONE ``log`` command.

    Documented decision (see the module docstring): we mirror that behaviour
    rather than rejecting every ';', because rejecting it would be a false
    positive against real x64dbg semantics. The safety of doing so rests on our
    splitter matching cmdsplit's state machine, which
    test_split_matches_x64dbg_cmdsplit pins down.
    """
    assert split_x64dbg_command('log "hello;world"') == ['log "hello;world"']
    bridge._validate_command('log "hello;world"')  # must not raise


def test_quoted_semicolon_does_not_smuggle_a_command(bridge):
    """
    The flip side: once the quote CLOSES, a later ';' splits again.

    'log "a;b";init evil' is two commands to x64dbg and must be refused.
    """
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command('log "a;b";init evil')


def test_multi_segment_legitimate_command_is_allowed(bridge):
    """Chaining permitted analysis commands stays permitted -- the gate is per segment."""
    bridge._validate_command("cfanalyze;analxrefs;bplist")


# ---------------------------------------------------------------------------
# List hygiene: the pruned denylist entries, and allowlist relationships
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dead", ["savefile", "quit", "exit", "exec", "execute"])
def test_dead_denylist_entries_are_gone_but_still_refused(bridge, dead):
    """
    F-16: these five matched NO command registered by x64dbg's
    registercommands() and were removed from ``_BLOCKED_COMMANDS``.

    They blocked nothing while making the denylist look more thorough than it
    was -- which is the illusion that let alias-reachable commands through in
    the first place. Removing them must not make them executable: the allowlist
    refuses everything it does not recognise, which is exactly why the allowlist
    and not the denylist is the control.
    """
    assert dead not in X64DbgBridge._BLOCKED_COMMANDS
    assert dead not in X64DbgBridge._ALLOWED_COMMANDS

    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(f"{dead} some-argument")


def test_bridge_allowlist_matches_the_plugin_allowlist():
    """
    The bridge must not send anything the plugin will refuse, and vice versa.

    Kept identical on purpose (unlike the denylist, which is deliberately a
    different control): drift in either direction is a bug, so it is asserted
    rather than left to review.
    """
    source = PLUGIN_CPP.read_text(encoding="utf-8", errors="replace")
    start = source.index("static const char* ALLOWED_COMMANDS[] = {")
    end = source.index("nullptr", start)
    body = re.sub(r"//[^\n]*", "", source[start:end])
    plugin = {m.lower() for m in re.findall(r'"([^"]+)"', body)}

    assert set(X64DbgBridge._ALLOWED_COMMANDS) == plugin


def test_tool_allowlist_is_subset_of_bridge_allowlist():
    """Anything the tool admits, the bridge must also admit, or the tool is broken."""
    tree = ast.parse(DYNAMIC_TOOLS.read_text(encoding="utf-8"), filename=str(DYNAMIC_TOOLS))
    tool: set[str] | None = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == "allowed_command_prefixes"
            for t in node.targets
        ):
            continue
        value = node.value
        assert isinstance(value, ast.Call) and value.args
        tool = {
            elt.value
            for elt in ast.walk(value.args[0])
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
        }
        break

    assert tool, "allowed_command_prefixes not found in dynamic_tools.py"
    assert tool <= set(X64DbgBridge._ALLOWED_COMMANDS)


@pytest.mark.parametrize("universal_bypass", ["scriptcmd", "scriptexec"])
def test_script_dispatchers_are_on_neither_allowlist(universal_bypass):
    """
    ``scriptcmd`` routes through ScriptCmdExecAwait -> cmddirectexec, i.e.
    x64dbg's FULL command dispatcher. One entry would make every other entry on
    either allowlist decorative, because "scriptcmd init C:/evil.exe" would then
    be a legal command. Pinned so a future editor cannot add it quietly.
    """
    source = DYNAMIC_TOOLS.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(DYNAMIC_TOOLS))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "allowed_command_prefixes"
            for t in node.targets
        ):
            names = {
                elt.value
                for elt in ast.walk(node.value)
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
            assert universal_bypass not in names

    assert universal_bypass not in X64DbgBridge._ALLOWED_COMMANDS
    assert universal_bypass in X64DbgBridge._BLOCKED_COMMANDS


def test_allowlist_exclusion_comment_warns_about_scriptcmd():
    """
    The reason ``scriptcmd`` must never be added has to live next to the list.

    Allowlist semantics already exclude it, so nothing fails today -- which is
    exactly why the warning is needed: the next editor adding "just one more
    command" gets no feedback from the type system.
    """
    source = DYNAMIC_TOOLS.read_text(encoding="utf-8").lower()
    start = source.index("never add, in particular")
    end = source.index("allowed_command_prefixes = frozenset", start)
    warning = source[start:end]

    assert "scriptcmd" in warning
    assert "scriptexec" in warning
    assert "cmddirectexec" in warning


class TestCommandEndpointChokepoint:
    """Every POST to /api/command is validated, not just execute_command().

    F-9/F-16 fixed execute_command, but 38 other bridge methods build a command
    string and POST it directly, never touching that gate. Validation now
    happens in _request, so a new method cannot reintroduce the hole by
    forgetting to call the validator -- which is how those 38 came to exist.
    """

    def _bridge(self):
        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge()
        bridge._auth_token = "test-token"
        return bridge

    def _fake_post(self, sent):
        def post(url, json=None, headers=None, timeout=None):
            sent.append(json.get("command") if json else None)

            class Response:
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"success": True, "data": {}}

            return Response()

        return post

    @pytest.mark.parametrize(
        "call",
        [
            lambda b: b.add_watch("x;init C:/evil.exe"),
            lambda b: b.set_watch_expression(1, "x;init C:/evil.exe"),
            lambda b: b.set_watch_name(1, "n;init C:/evil.exe"),
            lambda b: b.set_dll_breakpoint("d;init C:/evil.exe"),
            lambda b: b.add_struct("S;init C:/evil.exe"),
            lambda b: b.set_variable("v", "1;init C:/evil.exe"),
        ],
    )
    def test_chained_payload_never_leaves_the_bridge(self, call):
        sent: list = []
        bridge = self._bridge()
        with patch("requests.post", self._fake_post(sent)), patch(
            "requests.get", self._fake_post(sent)
        ):
            with pytest.raises(ValueError):
                call(bridge)
        assert sent == [], f"payload reached the plugin: {sent!r}"

    @pytest.mark.parametrize(
        "call",
        [
            lambda b: b.add_watch("eax"),
            lambda b: b.delete_watch(1),
            lambda b: b.set_watchdog(1, "changed"),
            lambda b: b.set_dll_breakpoint("kernel32.dll"),
            lambda b: b.analyze_control_flow(),
            lambda b: b.add_struct("MyStruct"),
            lambda b: b.undo_instruction(),
        ],
    )
    def test_legitimate_internal_commands_still_dispatch(self, call):
        """The chokepoint must not break the dedicated tools -- an over-tight
        gate here is just as much a defect as a missing one."""
        sent: list = []
        bridge = self._bridge()
        with patch("requests.post", self._fake_post(sent)), patch(
            "requests.get", self._fake_post(sent)
        ):
            call(bridge)
        assert len(sent) == 1, f"expected one dispatched command, got {sent!r}"


class TestSetRegisterValue:
    """HandleSetRegister snprintf's the VALUE into 'mov reg, value' and hands
    that to DbgCmdExec, which splits on ';'. Stripping '0x' was the only
    processing it got."""

    def _bridge(self):
        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge()
        bridge._auth_token = "test-token"
        return bridge

    @pytest.mark.parametrize(
        "value",
        ["0;init C:/evil.exe", "$(calc)", "1 2", "deadbeefdeadbeef0", "", "0xZZ", "-1"],
    )
    def test_non_hex_values_are_refused(self, value):
        with pytest.raises(ValueError, match="Invalid register value"):
            self._bridge().set_register("rax", value)

    @pytest.mark.parametrize("value", ["0x401000", "401000", "0", "deadbeefdeadbeef"])
    def test_hex_values_are_accepted(self, value):
        sent: list = []

        def post(url, json=None, headers=None, timeout=None):
            sent.append(json)

            class Response:
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"success": True, "data": {}}

            return Response()

        with patch("requests.post", post), patch("requests.get", post):
            self._bridge().set_register("rax", value)
        assert len(sent) == 1


class TestParseTypesSemicolonLimitation:
    """Pre-existing, surfaced not introduced: x64dbg splits every command on
    ';' before ParseTypes runs, so C source was always arriving truncated."""

    def test_semicolon_definition_gets_an_accurate_message(self):
        from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

        bridge = X64DbgBridge()
        bridge._auth_token = "test-token"
        with pytest.raises(ValueError) as excinfo:
            bridge.parse_types("struct A{int x;};")
        message = str(excinfo.value)
        assert "load_types" in message, message
        assert "splits every command" in message, message


class TestStartTraceReportsResolvedLogPath:
    """x64dbg_start_trace must report where the log ACTUALLY landed.

    The plugin confines trace logs to its own output directory (F-27) and
    returns the resolved absolute path. The tool echoed the REQUESTED name
    instead, so an analyst who passed "trace.csv" was told "Log file:
    trace.csv" while the file was written under the plugin output root -- the
    same "cannot find what was just written" failure this codebase has hit
    repeatedly, reported rather than enforced.
    """

    @contextlib.contextmanager
    def _tool(self, start_trace_result):
        from unittest.mock import MagicMock

        import src.tools.dynamic_tools as dynamic_tools

        bridge = MagicMock()
        bridge.start_trace.return_value = start_trace_result
        captured = {}

        class App:
            def tool(self, *a, **k):
                def deco(fn):
                    captured[fn.__name__] = fn
                    return fn

                return deco

        with patch.object(dynamic_tools, "get_x64dbg_bridge", lambda: bridge):
            dynamic_tools.register_dynamic_tools(App(), MagicMock())
            yield captured["x64dbg_start_trace"]

    def test_resolved_path_is_reported(self):
        resolved = r"C:\Users\a\AppData\Local\Temp\obsidian_x64dbg\output\trace.csv"
        with self._tool({"log_file": resolved}) as tool:
            out = tool(log_file="trace.csv")
        assert resolved in out, out

    def test_resolved_path_read_from_nested_data(self):
        resolved = r"C:\out\trace.csv"
        with self._tool({"data": {"log_file": resolved}}) as tool:
            out = tool(log_file="trace.csv")
        assert resolved in out, out

    def test_falls_back_to_requested_name_when_plugin_is_silent(self):
        """An older plugin build returns no log_file; do not print nothing."""
        with self._tool({}) as tool:
            out = tool(log_file="trace.csv")
        assert "trace.csv" in out, out

    def test_no_log_file_means_no_log_line(self):
        with self._tool({}) as tool:
            out = tool()
        assert "Log file" not in out, out
