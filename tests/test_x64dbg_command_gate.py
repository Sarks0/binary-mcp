"""
Regression tests for the x64dbg EXECUTE_COMMAND security gate.

Covers audit findings:

* **F-4** -- the Python blocklist and the C++ "server-side safety net" were
  byte-identical lists using identical matching, i.e. one control described as
  two. The plugin gate is now an allowlist and is the authoritative decision
  point; Python is only a fast-fail early reject.
* **F-9** -- exact-first-token matching against an alias-rich command language.
  x64dbg registers several spellings per command handler, so a denylist that
  names one spelling of ``init`` (the command that STARTS a process) leaves
  ``x64dbg_execute_command`` one alias away from being an arbitrary-process-
  launch primitive. Fixed by inverting the plugin gate to fail closed.
* **F-12** -- ``_validate_command`` raised ``IndexError`` on an empty or
  whitespace-only command instead of a clean validation error.
* **F-15** -- the auth token file was created with default (nullptr) security
  attributes rather than an explicit user-only DACL.

The C++ cannot be compiled here (no MSVC, no x64dbg SDK), so the plugin-side
tests parse ``plugin.cpp`` as text. They exist so the allowlist inversion
cannot be silently reverted to a denylist without a test failing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.engines.dynamic.x64dbg.bridge import X64DbgBridge

REPO_ROOT = Path(__file__).resolve().parents[1]
PLUGIN_CPP = REPO_ROOT / "src" / "engines" / "dynamic" / "x64dbg" / "plugin" / "plugin.cpp"


@pytest.fixture
def bridge() -> X64DbgBridge:
    """A bridge instance. The constructor performs no I/O, so this is offline-safe."""
    return X64DbgBridge()


# ---------------------------------------------------------------------------
# F-12: empty / whitespace-only commands
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", ["", "   ", "\t", "\n", " \t\r\n "])
def test_empty_command_raises_value_error_not_index_error(bridge, command):
    """
    F-12: ``command.strip().split()[0]`` raised IndexError on empty input.

    Callers treat ValueError as "rejected input" and let IndexError escape as an
    opaque internal error, so the type of the exception is the point of the test.
    """
    with pytest.raises(ValueError) as exc_info:
        bridge._validate_command(command)

    assert not isinstance(exc_info.value, IndexError)
    assert "empty" in str(exc_info.value).lower()


def test_none_command_raises_value_error(bridge):
    """A None slipping through an untyped caller must not raise AttributeError."""
    with pytest.raises(ValueError):
        bridge._validate_command(None)  # type: ignore[arg-type]


def test_execute_command_rejects_empty_before_any_request(bridge):
    """The empty-command rejection must happen before the HTTP round trip."""

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("_request_with_retry called for an empty command")

    bridge._request_with_retry = explode  # type: ignore[method-assign]

    with pytest.raises(ValueError):
        bridge.execute_command("   ")


# ---------------------------------------------------------------------------
# Python fast-fail denylist still rejects the dangerous originals
# ---------------------------------------------------------------------------


ORIGINAL_BLOCKED = [
    "scriptdll", "scriptload", "scriptrun",
    "loadlib", "freelib",
    "savedata", "savefile",
    "quit", "stop", "exit",
    "detach", "attach", "init",
    "exec", "execute",
    "createthread",
    "tracesetcommand", "tracesetlog", "tracesetlogfile",
]


@pytest.mark.parametrize("name", ORIGINAL_BLOCKED)
def test_originally_blocked_commands_remain_blocked(bridge, name):
    """Inverting the plugin gate must not have loosened the Python early reject."""
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(f"{name} some-argument")


@pytest.mark.parametrize(
    "command",
    [
        'init "C:\\evil.exe"',
        'INIT "C:\\evil.exe"',
        'Init "C:\\evil.exe"',
        # x64dbg accepts ',' as an argument separator, so the command name can
        # butt straight up against the first argument with no space.
        'init,"C:\\evil.exe"',
        "init(1)",
    ],
)
def test_init_is_blocked_in_every_spelling_python_layer_reaches(bridge, command):
    """
    F-9: ``init`` is the command that starts a debuggee (the plugin builds
    ``init "<path>"`` in HandleLoadBinary). Every form the Python tokenizer can
    normalise must be rejected here; the forms it cannot are caught by the
    plugin allowlist, which fails closed.
    """
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(command)


@pytest.mark.parametrize(
    "alias",
    ["initdbg", "initdebug", "attachdebugger", "detachdebugger", "plugload", "scylla"],
)
def test_dangerous_aliases_are_denied_by_python_layer(bridge, alias):
    """
    F-9 / F-4: the two layers must not be the same list. Python now names alias
    spellings the plugin does not need to enumerate (the plugin rejects unknown
    tokens by default), which is what makes it a genuinely different control.
    """
    with pytest.raises(ValueError, match="blocked by security policy"):
        bridge._validate_command(f"{alias} whatever")


@pytest.mark.parametrize(
    "command",
    [
        "dis.prev(rip, 5)",
        "findall 0, E8",
        'log "hello"',
        "cfanalyze",
        "rtu",
        "AddWatch rax",
        "varlist",
        "bplist",
        "refstr",
        "eval 1+1",
    ],
)
def test_normal_analysis_commands_pass_python_layer(bridge, command):
    """Ordinary read-only analysis and navigation commands must still go through."""
    bridge._validate_command(command)  # must not raise


def test_python_layer_is_a_denylist_not_a_copy_of_the_plugin_allowlist():
    """
    F-4: the fix is only real if the two layers are structurally different.
    Python denies by name; the plugin allows by name.
    """
    blocked = X64DbgBridge._BLOCKED_COMMANDS
    allowed = _parse_plugin_allowlist()

    assert isinstance(blocked, frozenset)
    # A denylist and an allowlist over the same command language must not
    # overlap: anything Python denies must not be plugin-executable.
    assert blocked.isdisjoint(allowed), (
        f"commands both denied by Python and allowed by the plugin: "
        f"{sorted(blocked & allowed)}"
    )
    # And they must not have become the same list again.
    assert blocked != allowed


# ---------------------------------------------------------------------------
# Plugin-side (C++) structural tests -- the allowlist inversion must stick
# ---------------------------------------------------------------------------


def _plugin_source() -> str:
    assert PLUGIN_CPP.is_file(), f"missing plugin source: {PLUGIN_CPP}"
    return PLUGIN_CPP.read_text(encoding="utf-8", errors="replace")


def _parse_plugin_allowlist() -> set[str]:
    """Extract the string entries of the ALLOWED_COMMANDS table from plugin.cpp."""
    source = _plugin_source()
    start = source.index("static const char* ALLOWED_COMMANDS[] = {")
    end = source.index("nullptr", start)
    body = source[start:end]
    # Drop // comments so commented-out examples cannot be mistaken for entries.
    body = re.sub(r"//[^\n]*", "", body)
    return {m.lower() for m in re.findall(r'"([^"]+)"', body)}


def test_plugin_allowlist_table_exists():
    """The allowlist table must be present and non-trivial."""
    allowed = _parse_plugin_allowlist()
    assert len(allowed) > 20, f"allowlist looks truncated: {sorted(allowed)}"


def test_legacy_plugin_blocklist_symbols_are_gone():
    """
    F-4 regression guard: reintroducing the denylist would restore the
    duplicated-control problem, so the old symbols must not come back.
    """
    source = _plugin_source()
    for symbol in ("BLOCKED_COMMAND_PREFIXES[]", "bool IsCommandBlocked"):
        assert symbol not in source, f"legacy denylist symbol reintroduced: {symbol}"

    # The old comment claimed a duplicated list was a safety net (F-4).
    assert "this is a safety net in case it is bypassed" not in source


def _command_gate() -> str:
    """Body of ``IsCommandAllowed`` -- the ';'-splitting outer gate (F-16)."""
    source = _plugin_source()
    gate = source[source.index("static bool IsCommandAllowed(const std::string& command)"):]
    return gate[: gate.index("\n// Handler: EXECUTE_COMMAND")]


def _segment_gate() -> str:
    """Body of ``IsCommandSegmentAllowed`` -- the per-segment matcher (F-16)."""
    source = _plugin_source()
    start = source.index("static bool IsCommandSegmentAllowed(const std::string& segment)")
    # Up to and including the function's closing brace.
    end = source.index("\n}\n", start) + len("\n}")
    return source[start:end]


def test_plugin_gate_is_wired_up_and_fails_closed():
    """HandleExecuteCommand must consult the allowlist and refuse by default."""
    source = _plugin_source()

    assert "static bool IsCommandAllowed(const std::string& command)" in source
    assert "if (!IsCommandAllowed(command))" in source

    # A refused command returns a JSON error rather than crashing the plugin.
    handler = source[source.index("if (!IsCommandAllowed(command))"):]
    handler = handler[: handler.index("LogInfo(\"Executing command")]
    assert "BuildJsonResponse(false" in handler

    # Both halves of the gate must end in a rejection: unknown tokens,
    # including unknown aliases, are refused rather than admitted.
    assert _command_gate().rstrip().endswith("return false;\n}")

    segment_gate = _segment_gate()
    assert segment_gate.rstrip().endswith("return false;\n}")
    assert "if (firstWord.empty()) {" in segment_gate  # empty token is not a free pass


@pytest.mark.parametrize(
    "dangerous",
    [
        # Process control / code loading -- the F-9 cardinal-rule cases.
        "init", "initdbg", "initdebug", "attach", "detach",
        "loadlib", "freelib", "scriptdll", "scriptload", "scriptrun",
        "createthread", "exec", "execute",
        "plugload", "pluginload",
        # Session control and arbitrary file writes.
        "quit", "stop", "exit", "savedata", "savefile",
        # Trace CONFIGURATION takes commands and file paths as arguments, so
        # allowing it would re-open the hole the allowlist closes.
        "tracesetcommand", "tracesetlog", "tracesetlogfile",
    ],
)
def test_plugin_allowlist_excludes_dangerous_commands(dangerous):
    assert dangerous not in _parse_plugin_allowlist()


@pytest.mark.parametrize(
    "required",
    [
        # x64dbg_execute_command's own docstring examples.
        "dis.prev", "findall", "log",
        # Commands the bridge builds and sends on /api/command. If one of these
        # is dropped from the allowlist the corresponding tool breaks at
        # runtime, which no unit test would otherwise catch.
        "rtu", "instrundo", "disasm", "dump", "sdump", "graph",
        "cfanalyze", "analxrefs", "analrecur", "analadv", "exhandlers", "exinfo",
        "findasm", "findguid", "modcallfind", "reffindrange", "refstr",
        "addwatch", "delwatch", "setwatchdog", "setwatchexpression", "setwatchname",
        "bpdll", "bcdll", "bpedll", "bpddll",
        "addstruct", "addunion", "addmember", "addtype",
        "visittype", "sizeoftype", "removetype",
        "enumtypes", "cleartypes", "loadtypes", "parsetypes",
        "var", "vardel", "varlist",
        "enableprivilege", "disableprivilege",
        "ticnd", "tocnd", "tibt", "tobt",
    ],
)
def test_plugin_allowlist_covers_commands_the_project_issues(required):
    assert required in _parse_plugin_allowlist()


def test_plugin_gate_rejects_embedded_line_breaks():
    """
    x64dbg's script engine is line-oriented and the gate does not split on
    CR/LF, so a command carrying a newline could otherwise smuggle a second
    (unchecked) command past a first token that looks harmless.
    """
    gate = _command_gate()
    assert "'\\n'" in gate and "'\\r'" in gate


def test_plugin_documents_which_layer_is_authoritative():
    """F-4: the layering must be described honestly in the source."""
    source = _plugin_source()
    header = source[source.index("// EXECUTE_COMMAND gate"): source.index("static const char* ALLOWED_COMMANDS")]
    lowered = header.lower()
    assert "authoritative" in lowered
    assert "fail" in lowered and "closed" in lowered


# ---------------------------------------------------------------------------
# F-15: auth token file ACL
# ---------------------------------------------------------------------------


def test_token_file_uses_explicit_user_only_dacl():
    """F-15: the token file must be created with a restricted DACL, not nullptr."""
    source = _plugin_source()

    assert "BuildCurrentUserOnlySecurity" in source
    assert "#include <sddl.h>" in source, "SDDL helpers used without the header"
    assert "ConvertStringSecurityDescriptorToSecurityDescriptorA" in source
    # D:P => protected DACL (no inherited ACEs), FA => FILE_ALL_ACCESS.
    assert '"D:P(A;;FA;;;"' in source

    # The old call site passed nullptr security attributes with this comment.
    assert "nullptr,       // Default security - same user, same access" not in source
    assert "haveSecurity ? &sa : nullptr" in source

    # A security descriptor only applies when the file is created, so a stale
    # file must be removed first or it keeps its old ACL through CREATE_ALWAYS.
    assert "DeleteFileA(tokenPath)" in source


def test_token_file_security_descriptor_is_freed():
    """The descriptor from ConvertStringSecurityDescriptor... must be LocalFree'd."""
    source = _plugin_source()
    setup = source[source.index("void pluginSetup()"):]
    setup = setup[: setup.index("// Create shutdown event")]
    assert "LocalFree(sd)" in setup


# ---------------------------------------------------------------------------
# Second remediation pass -- F-16 / F-17 / F-19 / F-20 / F-27 and the
# lower-priority memory-safety defects found in the same audit.
#
# Same caveat as above: none of this C++ can be compiled here (no MSVC, no
# x64dbg SDK), so these are structural assertions over the source text. They
# are deliberately anchored on the *shape* of each control -- the API that
# enforces it, the branch that rejects -- rather than on formatting, so they
# survive reflowing but fail if the control itself is removed.
# ---------------------------------------------------------------------------


MAIN_CPP = REPO_ROOT / "src" / "engines" / "dynamic" / "x64dbg" / "server" / "main.cpp"
EVENT_SYSTEM_CPP = (
    REPO_ROOT / "src" / "engines" / "dynamic" / "x64dbg" / "plugin" / "event_system.cpp"
)


def _main_source() -> str:
    assert MAIN_CPP.is_file(), f"missing server source: {MAIN_CPP}"
    return MAIN_CPP.read_text(encoding="utf-8", errors="replace")


def _event_system_source() -> str:
    assert EVENT_SYSTEM_CPP.is_file(), f"missing source: {EVENT_SYSTEM_CPP}"
    return EVENT_SYSTEM_CPP.read_text(encoding="utf-8", errors="replace")


def _function_body(source: str, signature: str, *, until: str) -> str:
    """Text from ``signature`` up to the next occurrence of ``until``."""
    start = source.index(signature)
    return source[start : source.index(until, start + len(signature))]


def _strip_comments(source: str) -> str:
    """
    Drop // and /* */ comments.

    The house style is long explanatory comments that QUOTE the defective code
    they replaced, so a naive "this string must not appear" assertion would be
    tripped by the very comment documenting the fix. Strip comments first so
    those assertions look at code only.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"//[^\n]*", "", source)


# --- F-16: the allowlist applies to every ';'-separated segment -------------


def test_command_gate_splits_on_semicolons():
    """
    F-16: DbgCmdExec treats ';' as a command separator, so ``bplist; init "x"``
    used to pass the gate on ``bplist`` and then run ``init``. The gate must
    now split and check each segment.
    """
    gate = _strip_comments(_command_gate())

    assert "command.find(';', start)" in gate, (
        "the gate no longer splits on the ';' command separator"
    )
    assert "IsCommandSegmentAllowed(segment)" in gate, (
        "the gate no longer applies the allowlist per segment"
    )
    # Any segment that fails is a rejection of the whole command list.
    assert re.search(
        r"if\s*\(\s*!IsCommandSegmentAllowed\(segment\)\s*\)\s*\{\s*return false;", gate
    )


def test_command_gate_does_not_match_the_whole_string_itself():
    """
    The outer gate must delegate every allowlist decision to the per-segment
    matcher. If it consults ALLOWED_COMMANDS directly again, someone has
    reintroduced whole-string matching alongside the split.
    """
    assert "ALLOWED_COMMANDS[" not in _strip_comments(_command_gate())


def test_segment_gate_rejects_empty_segments_and_leading_dollar():
    """
    F-16: an empty segment (``allowed;;other``, a trailing ';') must fail
    closed rather than be skipped, and a leading '$' -- which makes x64dbg
    parse the line as an expression rather than a registered command -- must be
    refused explicitly.
    """
    segment_gate = _strip_comments(_segment_gate())

    assert re.search(
        r"if\s*\(\s*begin\s*>=\s*segment\.size\(\)\s*\)\s*\{\s*return false;", segment_gate
    )
    assert re.search(
        r"if\s*\(\s*segment\[begin\]\s*==\s*'\$'\s*\)\s*\{\s*return false;", segment_gate
    )


# --- F-17: named pipe authentication and DACL ------------------------------


def _create_named_pipe_call() -> str:
    """The CreateNamedPipeA argument list, comments removed."""
    return _strip_comments(
        _function_body(_plugin_source(), "CreateNamedPipeA(", until=");")
    )


def test_pipe_rejects_remote_clients():
    """F-17: named pipes are reachable over SMB unless this flag is set."""
    assert "PIPE_REJECT_REMOTE_CLIENTS" in _create_named_pipe_call()


def test_pipe_is_created_with_explicit_security_attributes():
    """F-17: the pipe must not be created with nullptr SECURITY_ATTRIBUTES."""
    source = _strip_comments(_plugin_source())

    assert "BuildCurrentUserOnlySecurity(pipeSa, pipeSd)" in source

    # The security-attributes argument is the last one, and it must be the
    # conditional -- not the bare nullptr the old call passed.
    create = _create_named_pipe_call()
    last_argument = create.rstrip().rstrip(")").rsplit(",", 1)[-1].strip()
    assert last_argument == "havePipeSecurity ? &pipeSa : nullptr", (
        f"CreateNamedPipeA security attributes are {last_argument!r}"
    )


def test_pipe_peer_is_authenticated_before_any_request_is_dispatched():
    """
    F-17: the bearer token is only checked in obsidian_server.exe, so the pipe
    itself must verify that its peer IS that server process. Any other local
    process -- including the sample being debugged, which runs as the same user
    -- could otherwise drive WRITE_MEMORY / EXECUTE_COMMAND / LOAD_BINARY.
    """
    source = _plugin_source()

    assert "GetNamedPipeClientProcessId" in source
    assert "static bool IsPipeClientAuthorised(HANDLE pipe)" in source

    # The check runs before the handler switch, not after it.
    check_pos = source.index("if (!IsPipeClientAuthorised(g_pipeServer))")
    dispatch_pos = source.index("switch (requestType)")
    assert check_pos < dispatch_pos

    # A rejected peer is disconnected rather than served.
    rejection = source[check_pos : source.index("// Handle requests from HTTP server", check_pos)]
    assert "DisconnectNamedPipe" in rejection


def test_pipe_peer_check_fails_closed_when_no_server_was_spawned():
    """A zero recorded PID must reject, not wave everything through."""
    source = _plugin_source()
    checker = _function_body(
        source, "static bool IsPipeClientAuthorised(HANDLE pipe)", until="\n// Named Pipe server thread"
    )
    assert re.search(r"if\s*\(\s*expectedPid\s*==\s*0\s*\)\s*\{[^}]*return false;", checker, re.S)
    assert re.search(r"clientPid\s*!=\s*expectedPid", checker)


def test_spawned_server_pid_is_recorded_and_cleared():
    """
    The PID the peer check compares against must be recorded on spawn, and
    cleared whenever the process handle that pins it against reuse is closed.
    """
    source = _plugin_source()
    assert "g_serverProcessId.store(pi.dwProcessId)" in source
    assert source.count("g_serverProcessId.store(0)") >= 2


# --- F-19: pre-auth request bounds in the HTTP server ----------------------


def test_content_length_is_capped():
    """F-19: Content-Length was atoi'd with no upper bound."""
    source = _main_source()

    assert "MAX_CONTENT_LENGTH" in source
    assert "Protocol::MAX_MESSAGE_SIZE" in source
    assert re.search(
        r"MAX_CONTENT_LENGTH\s*=\s*Protocol::MAX_MESSAGE_SIZE", source
    ), "the body cap is no longer tied to the pipe's message ceiling"
    assert "MAX_HEADER_SIZE" in source
    assert "REQUEST_DEADLINE_MS" in source


def test_content_length_uses_strtoll_not_atoi():
    """atoi cannot report failure or overflow; strtoll can."""
    code = _strip_comments(_main_source())
    assert "strtoll(" in code
    assert "atoi(request.c_str()" not in code
    # errno/ERANGE handling is what makes strtoll's overflow report usable.
    assert "ERANGE" in code


def test_body_read_loop_uses_unsigned_comparisons():
    """
    F-19: ``(int)bodyReceived < contentLength`` truncated to a NEGATIVE value
    past 2 GiB, so the loop could never terminate on length.
    """
    code = _strip_comments(_main_source())
    assert "(int)bodyReceived" not in code
    assert "bodyReceived" not in code, (
        "the signed body counter is gone; reintroducing it reintroduces the bug"
    )
    assert "request.size() - bodyStart < contentLength" in code


def test_oversized_or_slow_requests_are_rejected_before_the_handler():
    """A bounds violation must answer with a status code and close, not parse."""
    source = _main_source()
    assert '413, "Payload Too Large"' in source
    assert '408, "Request Timeout"' in source
    assert '431, "Request Header Fields Too Large"' in source

    # The reject path must not fall through into HandleHTTPRequest.
    assert re.search(
        r"if\s*\(!earlyReject\.empty\(\)\)\s*\{[^}]*SendAll\(", source, re.S
    )


def test_response_send_is_looped():
    """A short send() used to truncate large responses and hang the client."""
    code = _strip_comments(_main_source())
    assert "static bool SendAll(SOCKET sock, const char* data, size_t length)" in code
    assert "SendAll(clientSocket, response.c_str(), response.size())" in code
    # The unlooped call is gone.
    assert "send(clientSocket, response.c_str()" not in code
    # SendAll must actually loop rather than wrap a single send().
    body = _function_body(code, "static bool SendAll(", until="\n}\n")
    assert re.search(r"while\s*\(\s*sent\s*<\s*length\s*\)", body)
    assert "sent += (size_t)written;" in body


# --- F-20: abortable waits and a safe unload -------------------------------


@pytest.mark.parametrize(
    "handler",
    ["HandleWaitPaused", "HandleWaitRunning", "HandleWaitDebugging"],
)
def test_wait_handlers_are_abortable(handler):
    """
    F-20: these polled with a bare Sleep(50) for up to five minutes and could
    not be interrupted, so pluginStop returned while they were still running
    inside a DLL x64dbg was about to FreeLibrary.
    """
    source = _plugin_source()
    body = _strip_comments(
        _function_body(source, f"std::string {handler}(const std::string& request)", until="\n}\n")
    )

    assert "AbortableSleep(" in body
    assert "Sleep(pollInterval)" not in body


def test_abortable_sleep_waits_on_the_shutdown_event():
    """The abort has to be event-driven; a shorter Sleep is not a fix."""
    source = _plugin_source()
    body = _strip_comments(
        _function_body(source, "static bool AbortableSleep(DWORD milliseconds)", until="\n}\n")
    )

    assert "WaitForSingleObject(shutdown, milliseconds)" in body
    assert "HANDLE shutdown = g_shutdownEvent;" in body
    # Only WAIT_TIMEOUT means "keep polling"; everything else stops.
    assert re.search(r"return\s+waitResult\s*==\s*WAIT_TIMEOUT", body)


def test_plugin_stop_waits_long_enough_and_pins_on_timeout():
    """
    F-20: pluginStop waited 1000 ms and then returned regardless, which is the
    unload. It must now wait meaningfully longer and, on a genuine timeout,
    prevent the unload instead of proceeding into it.
    """
    source = _plugin_source()

    match = re.search(r"PIPE_THREAD_SHUTDOWN_TIMEOUT_MS\s*=\s*(\d+)", source)
    assert match, "the pipe-thread shutdown timeout is no longer a named constant"
    assert int(match.group(1)) >= 5000

    stop = _strip_comments(
        _function_body(source, "void pluginStop()", until="// Delete authentication token file")
    )
    assert "WaitForSingleObject(g_pipeThread, PIPE_THREAD_SHUTDOWN_TIMEOUT_MS)" in stop
    assert "GET_MODULE_HANDLE_EX_FLAG_PIN" in stop
    # The timeout branch must not fall through into the resource teardown.
    pin_pos = stop.index("GET_MODULE_HANDLE_EX_FLAG_PIN")
    close_pos = stop.index("CloseHandle(g_pipeThread)")
    assert "return;" in stop[pin_pos:close_pos]


def test_plugin_stop_does_not_close_the_pipe_handle():
    """
    The owning thread is the sole closer; pluginStop may only cancel I/O.
    Closing from here raced the thread's own close (double free) and could hand
    the thread a recycled handle value.
    """
    source = _plugin_source()
    stop = _function_body(source, "void pluginStop()", until="// Delete authentication token file")

    assert "CloseHandle(g_pipeServer)" not in _strip_comments(stop)
    assert "CancelIoEx(g_pipeServer" in stop
    assert "EnterCriticalSection(&g_pipeHandleLock)" in stop


def test_g_running_is_atomic():
    """A plain bool shared across threads lets the compiler hoist the load."""
    code = _strip_comments(_plugin_source())
    assert "std::atomic<bool> g_running" in code
    assert "static bool g_running" not in code
    assert "#include <atomic>" in code


# --- F-27: confined output paths -------------------------------------------


def _confinement_helper() -> str:
    source = _plugin_source()
    return _function_body(
        source,
        "static bool ResolveConfinedOutputPath(",
        until="// Extensions each writer may produce",
    )


def test_output_paths_are_canonicalised_and_confined():
    """
    F-27: both writers took an attacker-supplied path straight to fopen. The
    control is prefix-matching AFTER canonicalisation -- that is what makes
    '..', 8.3 short names, device names and trailing dots all fail together.
    """
    helper = _strip_comments(_confinement_helper())

    assert "GetFullPathNameA" in helper
    assert re.search(r'component\s*==\s*"\.\."', helper), (
        "parent-directory components are no longer rejected"
    )
    assert "_strnicmp" in helper, "the base-prefix check must be case-insensitive on Windows"
    assert "HasAllowedExtension(canonical, allowedExtensions)" in helper

    # UNC / absolute forms are refused outright.
    assert re.search(r"rel\[0\]\s*==\s*'\\\\'", helper)
    assert "c == ':'" in helper  # drive letters and NTFS alternate data streams


def test_export_coverage_confines_its_file_argument():
    source = _plugin_source()
    body = _function_body(
        source,
        "std::string HandleExportCoverage(const std::string& request)",
        until="// EVENT HANDLERS",
    )
    assert "ResolveConfinedOutputPath(filePath, COVERAGE_OUTPUT_EXTENSIONS" in body
    assert "fopen(filePath.c_str()" not in body
    assert "fopen(resolvedPath.c_str()" in body


def test_start_trace_confines_its_log_file_argument():
    source = _plugin_source()
    body = _function_body(
        source,
        "std::string HandleStartTrace(const std::string& request)",
        until="// Handler: STOP_TRACE",
    )
    assert "ResolveConfinedOutputPath(logFile, TRACE_LOG_EXTENSIONS" in body
    assert "fopen(logFile.c_str()" not in body
    assert "fopen(resolvedLogPath.c_str()" in body


def test_start_trace_closes_a_live_log_handle_before_replacing_it():
    """Re-arming a trace used to overwrite a live FILE* without fclose."""
    source = _plugin_source()
    body = _function_body(
        source,
        "std::string HandleStartTrace(const std::string& request)",
        until="// Handler: STOP_TRACE",
    )
    close_pos = body.index("fclose(g_traceState.logFileHandle)")
    open_pos = body.index("g_traceState.logFileHandle = fopen(")
    assert close_pos < open_pos


@pytest.mark.parametrize(
    "extension_table",
    ["COVERAGE_OUTPUT_EXTENSIONS", "TRACE_LOG_EXTENSIONS"],
)
def test_output_extension_whitelists_exclude_executables(extension_table):
    source = _plugin_source()
    start = source.index(f"{extension_table}[] = {{")
    body = source[start : source.index("};", start)]
    extensions = {m.lower() for m in re.findall(r'"([^"]+)"', body)}

    assert extensions, f"{extension_table} is empty"
    for dangerous in (".exe", ".dll", ".cmd", ".bat", ".ps1", ".scr", ".com", ".vbs"):
        assert dangerous not in extensions


# --- lower-priority defects from the same audit ----------------------------


def test_extract_int_field_honours_the_default_on_parse_failure():
    """A discarded sscanf result silently yielded 0 instead of defaultValue."""
    source = _plugin_source()
    body = _strip_comments(_function_body(source, "int ExtractIntField(", until="\n}\n"))

    assert re.search(r"if\s*\(\s*sscanf\(.*\)\s*!=\s*1\s*\)", body), (
        "sscanf's result is discarded again"
    )
    assert "return defaultValue;" in body


def test_negative_offsets_are_clamped():
    """
    The three paginated handlers (trace data, API log, coverage data) feed
    ``offset`` into ``for (size_t i = offset; ...)``, where a negative value
    becomes SIZE_MAX. Today the loop condition catches that; the clamp is what
    stops it being correct only by accident.
    """
    code = _strip_comments(_plugin_source())
    assert code.count("if (offset < 0) offset = 0;") >= 3


def test_generate_secure_token_honours_its_length_parameter():
    """The terminator used to be written at a fixed index 64 regardless."""
    source = _plugin_source()
    body = _strip_comments(
        _function_body(source, "static bool GenerateSecureToken(", until="\n}\n")
    )

    assert "outToken[64]" not in body
    assert "tokenLength - 1" not in body
    assert re.search(r"tokenLength\s*<\s*requiredLength", body)


@pytest.mark.parametrize(
    "source_getter, escaper",
    [
        (_plugin_source, "std::string JsonEscape(const std::string& str)"),
        (_event_system_source, "static std::string JsonEscapeEvent(const std::string& str)"),
    ],
)
def test_json_escapers_escape_non_ascii(source_getter, escaper):
    """
    Bytes >= 0x80 passed through raw produce invalid UTF-8, which breaks
    response.json() on the Python side -- and those bytes come from the sample
    (module paths, symbols, OutputDebugString).
    """
    body = _strip_comments(_function_body(source_getter(), escaper, until="\n}\n"))
    assert re.search(r"uc\s*<\s*0x20\s*\|\|\s*uc\s*>=\s*0x7F", body), (
        "the escaper no longer covers the 0x7F..0xFF range"
    )


def test_load_binary_rejects_command_metacharacters():
    """
    path / arguments / working_directory are concatenated into a quoted x64dbg
    command string that has no escape syntax, so a quote closes the argument
    and ';' starts a new command.
    """
    source = _plugin_source()
    assert "static bool ContainsCommandMetacharacters(const std::string& value)" in source

    checker = _strip_comments(
        _function_body(
            source,
            "static bool ContainsCommandMetacharacters(const std::string& value)",
            until="\n}\n",
        )
    )
    for metacharacter in ("'\"'", "','", "';'"):
        assert f"c == {metacharacter}" in checker

    body = _strip_comments(
        _function_body(
            source, "std::string HandleLoadBinary(const std::string& request)", until="\n}\n"
        )
    )
    for field in ("path", "args", "workingDir"):
        assert f"ContainsCommandMetacharacters({field})" in body
    # The rejection happens before the command string is built.
    assert body.index("ContainsCommandMetacharacters(path)") < body.index('"init \\""')


def test_oversized_pipe_message_does_not_drop_the_connection():
    """
    One oversized frame used to `break` the pipe loop; the HTTP server treats a
    lost pipe as fatal, so the bridge stayed dead until x64dbg was restarted.
    """
    source = _plugin_source()
    start = source.index("if (requestLength > Protocol::MAX_MESSAGE_SIZE) {")
    body = _strip_comments(source[start : source.index("// Read request data", start)])

    assert "ERROR_MORE_DATA" in body, "the oversized message is no longer drained"
    assert "continue;" in body
    assert "Request exceeds the maximum message size" in body


def test_pipe_connect_event_is_checked():
    """
    A NULL hEvent makes WaitForMultipleObjects return WAIT_FAILED, which the
    old else-branch misread as "shutdown requested".
    """
    source = _plugin_source()
    start = source.index("overlapped.hEvent = CreateEventA(")
    body = source[start : source.index("BOOL connected = ConnectNamedPipe", start)]
    assert "if (!overlapped.hEvent) {" in body

    # WAIT_FAILED must be distinguished from the shutdown case.
    wait = source[source.index("HANDLE waitHandles[2]"):]
    wait = wait[: wait.index("} else if (!connected")]
    assert "WAIT_OBJECT_0 + 1" in wait


def test_module_name_is_json_escaped_in_import_and_export_handlers():
    """Every other field in the file is escaped; these two were missed."""
    source = _plugin_source()
    for handler, terminator in (
        ("std::string HandleGetModuleImports(const std::string& request)", "\n}\n"),
        ("std::string HandleGetModuleExports(const std::string& request)", "\n}\n"),
    ):
        body = _function_body(source, handler, until=terminator)
        assert 'JsonEscape(moduleName)' in body
        assert '<< moduleName <<' not in body


def test_state_reset_methods_are_actually_called():
    """Dead cleanup code reads as teardown that happens. Wire it up or drop it."""
    source = _plugin_source()
    stop = _function_body(source, "void pluginStop()", until="// Delete authentication token file")

    for state in ("g_traceState", "g_apiLogState", "g_coverageState", "g_antiDebugState"):
        assert f"{state}.Reset()" in stop
