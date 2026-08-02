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


def test_plugin_gate_is_wired_up_and_fails_closed():
    """HandleExecuteCommand must consult the allowlist and refuse by default."""
    source = _plugin_source()

    assert "static bool IsCommandAllowed(const std::string& command)" in source
    assert "if (!IsCommandAllowed(command))" in source

    # A refused command returns a JSON error rather than crashing the plugin.
    handler = source[source.index("if (!IsCommandAllowed(command))"):]
    handler = handler[: handler.index("LogInfo(\"Executing command")]
    assert "BuildJsonResponse(false" in handler

    # The matcher's final statement must be a rejection: unknown tokens,
    # including unknown aliases, are refused rather than admitted.
    gate = source[
        source.index("static bool IsCommandAllowed(const std::string& command)"):
    ]
    gate = gate[: gate.index("\n// Handler: EXECUTE_COMMAND")]
    assert gate.rstrip().endswith("return false;\n}")
    assert "if (firstWord.empty()) {" in gate  # empty token is not a free pass


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
    Only the first token is matched, so a command carrying a newline could
    otherwise smuggle a second (unchecked) command to x64dbg's line-oriented
    script engine.
    """
    source = _plugin_source()
    gate = source[source.index("static bool IsCommandAllowed(const std::string& command)"):]
    gate = gate[: gate.index("\n// Handler: EXECUTE_COMMAND")]
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
