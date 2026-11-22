"""
Regression tests for the Obsidian plugin / obsidian_server security review.

Each finding is pinned two ways where possible:

* EXECUTABLE: the shipped C++ is extracted verbatim (or #included, for the
  Windows-free listener policy), compiled with -Werror and run. This follows
  tests/test_cpp_request_parsing.py: the code under test is the code that
  ships, not a transcription that can drift.
* SOURCE GUARDS: for Windows-only fixes that cannot run here (Schannel flags,
  socket options, pipe flags, integrity labels), a cheap check that the fix is
  still present and the vulnerable form has not come back.

Finding IDs refer to the review: H1 token exposure across integrity levels,
M1 command injection past the EXECUTE_COMMAND allowlist, M2 oversized-response
pipe desync, M3 proxy token leak (tested in test_remote_bridge.py), M4
SO_REUSEADDR, M5 network retrieval during client-certificate checks, M6
single-threaded DoS, L1 pipe squatting, L2/L3 token handling, L4 output-file
TOCTOU, L5 export escaping, L6 request parsing, L7 pipe edge cases, L8 server
shutdown, L9 strict hex, L10 server token validation, I1 Origin, I2 TLS
protocol, I3 build hardening, I4 request logging.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
_X64DBG = _REPO / "src" / "engines" / "dynamic" / "x64dbg"
_PLUGIN_CPP = _X64DBG / "plugin" / "plugin.cpp"
_MAIN_CPP = _X64DBG / "server" / "main.cpp"
_TLS_H = _X64DBG / "server" / "schannel_tls.h"
_ACTIVITY_H = _X64DBG / "server" / "activity_log.h"
_POLICY_H = _X64DBG / "server" / "listener_policy.h"
_CMAKE = _X64DBG / "plugin" / "CMakeLists.txt"

_COMPILER = shutil.which("g++") or shutil.which("clang++")
requires_cxx = pytest.mark.skipif(_COMPILER is None, reason="no C++ compiler available")


def _extract_function(source: str, signature: str) -> str:
    """One top-level function, verbatim: signature to the first column-0 brace."""
    start = source.index(signature)
    end = source.index("\n}\n", start) + len("\n}\n")
    return source[start:end]


def _extract_json_parser(source: str) -> str:
    """The strict request parser, from its banner to the end of ExtractStringField."""
    start = source.index("// STRICT REQUEST PARSING (review finding L6)")
    tail = source.index("std::string ExtractStringField(", start)
    end = source.index("\n}\n", tail) + len("\n}\n")
    return source[start:end]


def _code_lines(source: str) -> list[str]:
    return [line for line in source.splitlines() if not line.strip().startswith("//")]


def _compile_and_run(tmp_path: Path, name: str, program: str, include: Path | None = None) -> str:
    cpp = tmp_path / f"{name}.cpp"
    cpp.write_text(program, encoding="utf-8")
    binary = tmp_path / name
    args = [_COMPILER, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-O1"]
    if include is not None:
        args += ["-I", str(include)]
    built = subprocess.run(args + [str(cpp), "-o", str(binary)], capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    ran = subprocess.run([str(binary)], capture_output=True, text=True)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    return ran.stdout


_PRELUDE = r"""
#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <map>
#include <string>
#include <vector>
static int failures = 0;
#define CHECK(cond, label) do { if (!(cond)) { printf("FAIL %s\n", label); failures++; } } while (0)
"""


# L6: strict request parsing in the plugin


_JSON_CASES = r"""
int main() {
    std::string e;
    CHECK(ValidateRequestJson("{\"type\":1}", e), "simple object");
    CHECK(ValidateRequestJson(" { } ", e), "empty object with whitespace");
    CHECK(!ValidateRequestJson("{\"type\":1,\"type\":16}", e), "duplicate key refused");
    CHECK(e.find("duplicate") != std::string::npos, "duplicate named in error");
    CHECK(!ValidateRequestJson("{\"type\":1} trailing", e), "trailing data refused");
    CHECK(!ValidateRequestJson("[1,2]", e), "array refused");
    CHECK(!ValidateRequestJson("{\"type\":1,", e), "truncated refused");
    CHECK(!ValidateRequestJson("{\"a\":\"x\ny\"}", e), "raw control char refused");
    CHECK(!ValidateRequestJson("{\"a\":\"\\q\"}", e), "unknown escape refused");
    CHECK(!ValidateRequestJson("{\"a\":01}", e), "leading zero refused");
    CHECK(!ValidateRequestJson("{\"a\":\"\\udc00\"}", e), "lone low surrogate refused");
    std::string deep = "{\"a\":";
    for (int i = 0; i < 40; i++) deep += "[";
    for (int i = 0; i < 40; i++) deep += "]";
    deep += "}";
    CHECK(!ValidateRequestJson(deep, e), "excess nesting refused");

    CHECK(ExtractStringField("{\"a\":\"\\u0041\\u00e9\"}", "a") == "A\xc3\xa9", "unicode decoded");
    CHECK(ExtractStringField("{\"a\":\"\\ud83d\\ude00\"}", "a") == "\xf0\x9f\x98\x80", "surrogate pair");
    CHECK(ExtractStringField("{\"a\":\"x\\\\y\\\"z\"}", "a") == "x\\y\"z", "escapes decoded");

    // Field confusion the substring search allowed: a nested key, and the key
    // text inside another string value, must not be what a handler reads.
    CHECK(ExtractStringField("{\"opts\":{\"address\":\"evil\"},\"address\":\"good\"}", "address") == "good",
          "nested key ignored");
    CHECK(ExtractStringField("{\"note\":\"\\\"address\\\":\\\"evil\\\"\",\"address\":\"good\"}", "address") == "good",
          "key text inside a string ignored");
    CHECK(ExtractStringField("{\"opts\":{\"address\":\"evil\"}}", "address", "dflt") == "dflt",
          "only nested -> default");

    CHECK(ExtractStringField("{\"a\":123}", "a") == "123", "number as string");
    CHECK(ExtractStringField("{\"a\":null}", "a", "d") == "d", "null -> default");
    CHECK(ExtractIntField("{\"a\":-5}", "a", 7) == -5, "negative int");
    CHECK(ExtractIntField("{\"a\":true}", "a", 7) == 1, "true -> 1");
    CHECK(ExtractIntField("{\"a\":false}", "a", 7) == 0, "false -> 0");
    CHECK(ExtractIntField("{\"a\":99999999999}", "a", 7) == 7, "overflow -> default");
    CHECK(ExtractIntField("{\"a\":1.5}", "a", 7) == 7, "fraction -> default");
    CHECK(ExtractIntField("{\"a\":\"5\"}", "a", 7) == 7, "string -> default");
    CHECK(ExtractIntField("{\"type\":1,\"type\":16}", "type", -1) == -1, "malformed -> default");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_plugin_request_parser_is_strict(tmp_path):
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    program = _PRELUDE + "\n" + _extract_json_parser(source) + _JSON_CASES
    _compile_and_run(tmp_path, "json_parser", program)


# L6 end to end: obsidian_server builds the pipe request, the plugin parses it


_SPLICE_CASES = r"""
static std::string Req(const std::string& headers, const std::string& body) {
    return "POST /api/register/set HTTP/1.1\r\n" + headers + "\r\n\r\n" + body;
}
int main() {
    std::string out, e;
    // Bytes beyond Content-Length are not part of the body.
    CHECK(ExtractDeclaredBody(Req("Content-Length: 2", "{}GARBAGE")) == "{}", "body bounded");
    CHECK(ExtractDeclaredBody(Req("Host: x", "{\"a\":1}")).empty(), "no Content-Length -> no body");

    CHECK(BuildPluginRequest(6, "", out) && out == "{\"type\":6}", "empty body");
    CHECK(BuildPluginRequest(6, " { } ", out) && out == "{\"type\":6}", "empty object");
    CHECK(BuildPluginRequest(6, "{\"register\":\"rax\"}", out) &&
          out == "{\"type\":6,\"register\":\"rax\"}", "spliced");
    CHECK(ValidateRequestJson(out, e), "spliced request parses");
    CHECK(!BuildPluginRequest(6, "junk{\"a\":1}", out), "leading junk refused");
    CHECK(!BuildPluginRequest(6, "[1]", out), "non-object refused");

    // A body carrying its own "type" can no longer override the endpoint's:
    // the plugin refuses the duplicate outright.
    CHECK(BuildPluginRequest(6, "{\"type\":16,\"command\":\"x\"}", out), "type-bearing body builds");
    CHECK(!ValidateRequestJson(out, e), "duplicate type refused by plugin");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_server_body_splice_and_plugin_parse_agree(tmp_path):
    main_src = _MAIN_CPP.read_text(encoding="utf-8")
    plugin_src = _PLUGIN_CPP.read_text(encoding="utf-8")
    program = "\n".join(
        [
            _PRELUDE,
            "void Log(const char*, ...) {}",
            _extract_function(main_src, "static bool AsciiEqualsIgnoreCase"),
            _extract_function(main_src, "static bool FindHeaderValue"),
            _extract_function(main_src, "static std::string ExtractDeclaredBody("),
            _extract_function(main_src, "static bool BuildPluginRequest("),
            _extract_json_parser(plugin_src),
            _SPLICE_CASES,
        ]
    )
    _compile_and_run(tmp_path, "splice", program)


# M1 / L9: command strings built by handlers


_COMMAND_CASES = r"""
int main() {
    // Register values: hex literal only.
    CHECK(IsRegisterValueLiteral("401000"), "hex");
    CHECK(IsRegisterValueLiteral("0x401000"), "0x hex");
    CHECK(IsRegisterValueLiteral("deadbeefdeadbeef"), "16 digits");
    CHECK(!IsRegisterValueLiteral("deadbeefdeadbeef0"), "17 digits");
    CHECK(!IsRegisterValueLiteral(""), "empty");
    CHECK(!IsRegisterValueLiteral("0x"), "prefix only");
    CHECK(!IsRegisterValueLiteral("1;2"), "separator");
    CHECK(!IsRegisterValueLiteral("1 2"), "space");
    CHECK(!IsRegisterValueLiteral("-1"), "sign");

    // bpx symbols: symbol characters only.
    CHECK(IsBreakpointSymbol("kernel32!CreateFileW"), "module!symbol");
    CHECK(IsBreakpointSymbol("kernel32.CreateFileW"), "module.symbol");
    CHECK(IsBreakpointSymbol("?Func@Class@@QAEXXZ"), "mangled");
    CHECK(!IsBreakpointSymbol("a;b"), "separator");
    CHECK(!IsBreakpointSymbol("a b"), "space");
    CHECK(!IsBreakpointSymbol("a\"b"), "quote");
    CHECK(!IsBreakpointSymbol("a,b"), "comma");
    CHECK(!IsBreakpointSymbol(std::string(256, 'a')), "too long");

    // The choke point refuses separators and controls in ANY handler-built
    // command, and passes ordinary ones through unchanged.
    CHECK(InternalCmdExec("bp 401000"), "plain command passes");
    CHECK(executed.size() == 1 && executed[0] == "bp 401000", "plain command executed");
    CHECK(!InternalCmdExec("mov rax, 1;bp 2"), "separator refused");
    CHECK(!InternalCmdExec("bp 1\nbp 2"), "newline refused");
    CHECK(!InternalCmdExec("bp 1\rbp 2"), "carriage return refused");
    CHECK(InternalCmdExec("init \"C:\\a b\\x.exe\""), "quoted argument passes");
    CHECK(executed.size() == 2, "nothing refused was executed");

    // Strict hex digits for WRITE_MEMORY.
    CHECK(HexDigitValue('0') == 0 && HexDigitValue('f') == 15 && HexDigitValue('F') == 15, "hex digits");
    CHECK(HexDigitValue('g') == -1 && HexDigitValue('-') == -1 && HexDigitValue(' ') == -1, "non-hex");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_handler_command_validation(tmp_path):
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    program = "\n".join(
        [
            _PRELUDE,
            "static std::vector<std::string> executed;",
            "static bool DbgCmdExec(const char* c) { executed.push_back(c); return true; }",
            "static void LogError(const char*, ...) {}",
            _extract_function(source, "static bool InternalCmdExec("),
            _extract_function(source, "static bool IsRegisterValueLiteral("),
            _extract_function(source, "static bool IsBreakpointSymbol("),
            _extract_function(source, "static int HexDigitValue("),
            _COMMAND_CASES,
        ]
    )
    _compile_and_run(tmp_path, "commands", program)


def test_only_the_gated_handler_calls_dbgcmdexec_directly():
    """M1: every handler-built command goes through InternalCmdExec.

    The two direct calls left are the choke point itself and EXECUTE_COMMAND,
    which sits behind the IsCommandAllowed allowlist.
    """
    direct = [
        line.strip()
        for line in _code_lines(_PLUGIN_CPP.read_text(encoding="utf-8"))
        if re.search(r"\bDbgCmdExec\(", line)
    ]
    assert sorted(direct) == sorted(
        ["return DbgCmdExec(cmd);", "if (DbgCmdExec(command.c_str())) {"]
    ), direct


def test_set_register_and_bpx_are_validated_in_cpp():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    set_register = _extract_function(source, "std::string HandleSetRegister(")
    assert "IsRegisterValueLiteral(valueStr)" in set_register
    assert "valueStr.length() > 32" not in set_register
    set_bp = _extract_function(source, "std::string HandleSetBreakpoint(")
    assert set_bp.index("IsBreakpointSymbol(normalizedAddr)") < set_bp.index('"bpx %s"')


def test_write_memory_hex_is_strict():
    handler = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "std::string HandleWriteMemory("
    )
    assert "sscanf" not in "\n".join(_code_lines(handler))
    assert "% 2 != 0" in handler


# M2 / L7: pipe framing


def test_plugin_caps_every_response_at_the_pipe_limit():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    writer = _extract_function(source, "static bool WritePipeResponse(")
    assert "Protocol::MAX_MESSAGE_SIZE" in writer
    thread = source[source.index("static DWORD WINAPI PipeServerThread") :]
    thread = thread[: thread.index("\n}\n")]
    # Every response leaves through the capped writer; no raw WriteFile.
    assert "WriteFile(" not in thread
    assert thread.count("WritePipeResponse(") >= 3


def test_empty_frame_gets_a_reply():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    block = source[source.index("if (requestLength == 0) {") :]
    block = block[: block.index("continue;")]
    assert "WritePipeResponse(" in block


def test_read_memory_reply_fits_one_frame():
    handler = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "std::string HandleReadMemory("
    )
    assert "(Protocol::MAX_MESSAGE_SIZE - 4096) / 2" in handler


def test_server_reads_exactly_and_resets_on_framing_errors():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    client = source[source.index("class PipeClient {") : source.index("// Global pipe client")]
    assert "ReadExact(" in client and "WriteExact(" in client
    # Every failure after a byte has been written resets the connection
    # instead of leaving unread bytes to be taken as the next length.
    assert client.count("ResetAfterFramingFailure();") >= 3
    assert "WaitForSingleObject(overlapped.hEvent, timeoutMs)" in client


def test_pattern_scan_is_bounded():
    handler = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "std::string HandlePatternScan("
    )
    assert "16 * 1024 * 1024" in handler
    assert "MAX_PATTERN_BYTES = 256" in handler
    assert "budgetEnd" in handler
    assert "if (!DbgMemRead(startAddr, buffer.data(), size))" in handler


# L1: pipe identity


def test_pipe_is_per_session_first_instance_and_never_recreated():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    assert "FILE_FLAG_FIRST_PIPE_INSTANCE" in source
    assert 'g_pipeName = std::string(Protocol::PIPE_NAME) + "_" + suffix;' in source
    thread = source[source.index("static DWORD WINAPI PipeServerThread") :]
    thread = thread[: thread.index("\n}\n")]
    reject = thread[thread.index("if (!IsPipeClientAuthorised(g_pipeServer)) {") :]
    reject = reject[: reject.index("continue;")]
    assert "ClosePipeServerHandle" not in reject, "rejecting a peer must not free the name"


def test_server_authenticates_the_pipe_server():
    client = _MAIN_CPP.read_text(encoding="utf-8")
    assert "GetNamedPipeServerProcessId" in client
    assert "SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION" in client


# H1 / L2 / L3: the bearer token


def test_token_file_and_pipe_carry_a_no_read_up_label():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    # The definition, not the forward declaration above PipeServerThread.
    helper = _extract_function(
        source,
        "static bool BuildCurrentUserOnlySecurity(SECURITY_ATTRIBUTES& sa, "
        "PSECURITY_DESCRIPTOR& outSd) {",
    )
    assert "S:(ML;;NRNWNX;;;" in helper


def test_token_never_enters_x64dbgs_own_environment():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    assert not [
        line
        for line in _code_lines(source)
        if 'SetEnvironmentVariableA("OBSIDIAN_AUTH_TOKEN"' in line
    ]
    assert "BuildServerEnvironment(token)" in source


def test_token_file_written_after_spawn_and_only_for_generated_tokens():
    setup = _extract_function(_PLUGIN_CPP.read_text(encoding="utf-8"), "void pluginSetup() {")
    assert setup.index("SpawnHTTPServer(token)") < setup.index("WriteTokenFile(token)")
    assert "if (pinned.empty()) {\n        WriteTokenFile(token);" in setup


def test_load_binary_is_opt_in():
    handler = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "std::string HandleLoadBinary("
    )
    assert handler.index("g_allowLoadBinary") < handler.index('init \\"')


def test_server_validates_its_token():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    accept = _extract_function(source, "static bool AcceptToken(")
    assert "Listener::IsPinnedToken" in accept


# M4 / M5 / I2: socket and TLS


def test_listener_uses_exclusive_address():
    code = "\n".join(_code_lines(_MAIN_CPP.read_text(encoding="utf-8")))
    assert "SO_EXCLUSIVEADDRUSE" in code
    assert "SO_REUSEADDR" not in code


def test_client_certificate_check_makes_no_network_requests():
    source = _TLS_H.read_text(encoding="utf-8")
    for flag in (
        "CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL",
        "CERT_CHAIN_DISABLE_AIA",
        "CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE",
    ):
        assert flag in source
    assert "clientCert->hCertStore" in source
    assert "&chainParameters, 0, nullptr, &chain" not in source


def test_negotiated_protocol_is_checked():
    assert "SECPKG_ATTR_CONNECTION_INFO" in _TLS_H.read_text(encoding="utf-8")


# L4 / L5 / L8 / I3 / I4


def test_plugin_never_opens_output_files_by_name_with_fopen():
    code = "\n".join(_code_lines(_PLUGIN_CPP.read_text(encoding="utf-8")))
    assert "fopen(" not in code
    opener = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "static FILE* OpenConfinedOutputFile("
    )
    for needle in (
        "GetFinalPathNameByHandleA",
        "nNumberOfLinks != 1",
        "FILE_ATTRIBUTE_REPARSE_POINT",
        "FILE_FLAG_OPEN_REPARSE_POINT",
    ):
        assert needle in opener or needle in _PLUGIN_CPP.read_text(encoding="utf-8")


def test_coverage_export_escapes_debuggee_strings():
    handler = _extract_function(
        _PLUGIN_CPP.read_text(encoding="utf-8"), "std::string HandleExportCoverage("
    )
    assert "JsonEscape(entry.module)" in handler and "JsonEscape(entry.symbol)" in handler
    assert "CsvField(entry.module)" in handler and "CsvField(entry.symbol)" in handler


_CSV_CASES = r"""
int main() {
    CHECK(CsvField("kernel32.dll") == "\"kernel32.dll\"", "plain");
    CHECK(CsvField("a\"b") == "\"a\"\"b\"", "quote doubled");
    CHECK(CsvField("a,b\nc") == "\"a,b c\"", "comma kept inside quotes, newline flattened");
    CHECK(CsvField("=cmd") == "\"'=cmd\"", "formula neutralised");
    CHECK(CsvField("@x") == "\"'@x\"", "at-sign neutralised");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_csv_field_escaping(tmp_path):
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    program = _PRELUDE + _extract_function(source, "static std::string CsvField(") + _CSV_CASES
    _compile_and_run(tmp_path, "csv", program)


def test_server_shutdown_does_not_rely_on_ctrl_c():
    code = "\n".join(_code_lines(_PLUGIN_CPP.read_text(encoding="utf-8")))
    assert "GenerateConsoleCtrlEvent" not in code
    assert "TerminateProcess(g_serverProcess, 0);" in code


def test_build_enables_cfg_and_cet():
    cmake = _CMAKE.read_text(encoding="utf-8")
    assert "/guard:cf" in cmake
    assert "/CETCOMPAT" in cmake


def test_request_bodies_are_not_logged():
    source = _PLUGIN_CPP.read_text(encoding="utf-8")
    assert 'LogInfo("Received request: %s"' not in source


# Logging: pre-auth noise cannot crowd out the record


def test_preauth_events_are_low_priority():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    for event in (
        "auth.failed",
        "host.rejected",
        "origin.rejected",
        "client.rejected",
        "tls.handshake_failed",
        "header.duplicated",
        "request.received",
    ):
        assert re.search(rf'Event\("{re.escape(event)}",\s*ActivityLog::LOW_PRIORITY\)', source), (
            event
        )


def test_text_log_is_capped_and_neutralises_control_characters():
    log_fn = _extract_function(
        _MAIN_CPP.read_text(encoding="utf-8"), "void Log(const char* format, ...) {"
    )
    assert "MAX_TEXT_LOG_BYTES" in log_fn
    assert "c < 0x20" in log_fn


_LOG_DRIVER = r"""
#include "activity_log.h"
int main() {
    ActivityLog::Init("./", "t", 8765, "http://127.0.0.1:8765 tls=OFF loopback");
    const std::string pad(4000, 'x');
    for (int i = 0; i < 3500; i++) {
        ActivityLog::Event("auth.failed", ActivityLog::LOW_PRIORITY).Str("pad", pad);
    }
    ActivityLog::Event("pipe.roundtrip").Num("id", 42);
    ActivityLog::Shutdown(true, "done");
    return 0;
}
"""


@requires_cxx
def test_low_priority_flood_leaves_room_for_real_events(tmp_path):
    """~14 MB of pre-auth noise must not stop a later normal event being logged."""
    test_log = __import__("tests.test_server_activity_log", fromlist=["WINDOWS_H"])
    win = tmp_path / "win"
    win.mkdir()
    (win / "Windows.h").write_text(test_log.WINDOWS_H, encoding="utf-8")
    (tmp_path / "activity_log.h").write_text(
        _ACTIVITY_H.read_text(encoding="utf-8"), encoding="utf-8"
    )
    cpp = tmp_path / "flood.cpp"
    cpp.write_text(_LOG_DRIVER, encoding="utf-8")
    binary = tmp_path / "flood"
    built = subprocess.run(
        [
            _COMPILER,
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(win),
            "-I",
            str(tmp_path),
            str(cpp),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr
    assert subprocess.run([str(binary)], cwd=tmp_path).returncode == 0
    produced = [p for p in tmp_path.rglob("*") if p.name.endswith(".jsonl")]
    text = produced[0].read_text(encoding="utf-8")
    assert '"ev":"pipe.roundtrip"' in text
    stop = [line for line in text.splitlines() if '"ev":"server.stop"' in line][0]
    assert '"suppressed_low_priority":' in stop
    assert int(re.search(r'"suppressed_low_priority":(\d+)', stop).group(1)) > 0


# I1 / L1 / M6: listener policy additions (header is Windows-free; #included)


_POLICY_CASES = r"""
#include "listener_policy.h"
#include <cstdio>
static int failures = 0;
#define CHECK(cond, label) do { if (!(cond)) { printf("FAIL %s\n", label); failures++; } } while (0)
int main() {
    Listener::Options o;  // loopback 127.0.0.1:8765, plaintext
    CHECK(Listener::OriginAllowed(o, "http://127.0.0.1:8765"), "own origin");
    CHECK(Listener::OriginAllowed(o, "http://localhost:8765"), "localhost spelling");
    CHECK(!Listener::OriginAllowed(o, "http://localhost:3000"), "other localhost port");
    CHECK(!Listener::OriginAllowed(o, "http://localhost"), "default port 80 differs");
    CHECK(!Listener::OriginAllowed(o, "https://127.0.0.1:8765"), "wrong scheme");
    CHECK(!Listener::OriginAllowed(o, "null"), "null origin");
    CHECK(!Listener::OriginAllowed(o, "http://evil.test:8765"), "other host");
    CHECK(!Listener::OriginAllowed(o, "http://127.0.0.1:8765/x"), "path in origin");
    CHECK(!Listener::OriginAllowed(o, "http://user@127.0.0.1:8765"), "userinfo");
    CHECK(!Listener::OriginAllowed(o, "http://127.0.0.1:87650"), "port overflow digits");

    Listener::Options t;
    const char* args[] = {"s", "--bind", "192.168.1.50", "--tls-cert-thumbprint",
                          "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"};
    std::string err;
    CHECK(Listener::ParseOptions(5, args, t, err), "tls options parse");
    CHECK(Listener::OriginAllowed(t, "https://192.168.1.50:8765"), "tls own origin");
    CHECK(!Listener::OriginAllowed(t, "http://192.168.1.50:8765"), "tls wrong scheme");

    CHECK(Listener::IsValidPipeName("\\\\.\\pipe\\x64dbg_mcp_0123abcd"), "valid pipe");
    CHECK(!Listener::IsValidPipeName("\\\\.\\pipe\\x64dbg_mcp"), "bare legacy name not accepted via flag");
    CHECK(!Listener::IsValidPipeName("\\\\server\\pipe\\x64dbg_mcp_00"), "remote pipe refused");
    CHECK(!Listener::IsValidPipeName("\\\\.\\pipe\\x64dbg_mcp_00G"), "non-hex");
    CHECK(!Listener::IsValidPipeName("\\\\.\\pipe\\x64dbg_mcp_00\\..\\x"), "traversal");

    Listener::Options p;
    const char* pipeArgs[] = {"s", "--pipe", "\\\\.\\pipe\\x64dbg_mcp_00ff", "--plugin-pid", "4242"};
    CHECK(Listener::ParseOptions(5, pipeArgs, p, err), "pipe options parse");
    CHECK(p.pipeName == "\\\\.\\pipe\\x64dbg_mcp_00ff" && p.pluginPid == 4242, "pipe options stored");
    const char* badPid[] = {"s", "--plugin-pid", "0"};
    CHECK(!Listener::ParseOptions(3, badPid, p, err), "zero pid refused");
    const char* badPipe[] = {"s", "--pipe", "\\\\.\\pipe\\other"};
    CHECK(!Listener::ParseOptions(3, badPipe, p, err), "foreign pipe refused");

    Listener::PeerThrottle throttle;
    const uint32_t remote = 0xC0A80132u;  // 192.168.1.50
    unsigned long long now = 1000;
    for (unsigned i = 0; i + 1 < Listener::PeerThrottle::MAX_FAILURES; i++) {
        throttle.RecordFailure(remote, now);
    }
    CHECK(throttle.Allowed(remote, now), "below threshold still allowed");
    throttle.RecordFailure(remote, now);
    CHECK(!throttle.Allowed(remote, now), "blocked at threshold");
    CHECK(throttle.Allowed(remote, now + Listener::PeerThrottle::BLOCK_MS + 1), "block expires");
    for (unsigned i = 0; i < 50; i++) throttle.RecordFailure(0x7F000001u, now);
    CHECK(throttle.Allowed(0x7F000001u, now), "loopback never throttled");
    for (uint32_t a = 0; a < 1000; a++) throttle.RecordFailure(0x0A000000u + a, now);
    CHECK(throttle.Allowed(0x0A0000FFu, now), "table stays bounded");
    printf("failures=%d\n", failures);
    return failures != 0;
}
"""


@requires_cxx
def test_listener_policy_additions(tmp_path):
    _compile_and_run(tmp_path, "policy", _POLICY_CASES, include=_POLICY_H.parent)


def test_server_uses_exact_origin_matching():
    source = _MAIN_CPP.read_text(encoding="utf-8")
    assert "Listener::OriginAllowed(g_listener, originHeader)" in source
