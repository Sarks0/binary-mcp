"""
Regression tests for audit finding F-10: raw exception text reaching the model.

Roughly 190 tool handlers under ``src/tools/`` used to end in
``return f"Error: {e}"``. Whatever the debugger, an external tool, or the
filesystem put in the exception string went into the model's context and from
there into generated reports -- absolute host paths, the operator's username
(every output directory is rooted at ``Path.home()``), CDB stdout, Pybag
internals.

These tests pin both halves of the fix:

* unexpected failures are reduced to a safe message plus a reference ID, and
* deliberate validation messages stay verbatim, because a model that cannot
  read "must be a valid C identifier" cannot repair its own call.

``LEAK_MARKER`` below stands in for the host secrets: a real ``Path.home()``
string and a traceback fragment. If either shows up in a tool's return value,
the tool is leaking.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.tools.error_hygiene import curated_structured_text, safe_tool_error
from src.utils.structured_errors import (
    ErrorCode,
    StructuredBaseError,
    StructuredError,
)

HOME = str(Path.home())
TRACEBACK_MARKER = 'File "/usr/lib/python3/site-packages/pybag/dbgeng.py", line 42'
LEAK_MARKER = f"{HOME}/samples/secret.dmp"


def assert_no_host_leak(text: str) -> None:
    """Fail if a tool's model-facing string carries host or traceback detail."""
    assert HOME not in text, f"leaked Path.home() in: {text!r}"
    assert "Traceback (most recent call last)" not in text
    assert TRACEBACK_MARKER not in text
    assert "site-packages" not in text


def assert_has_reference_id(text: str) -> None:
    """The safe path always hands back a correlation ID for the server log."""
    assert re.search(r"Reference ID: [0-9a-f]{8}", text), text


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------


class TestSafeToolError:
    def test_generic_exception_is_reduced_to_reference_id(self):
        err = OSError(f"cannot open {LEAK_MARKER}: permission denied")
        out = safe_tool_error("windbg_open_dump", err)

        assert_no_host_leak(out)
        assert_has_reference_id(out)
        assert "windbg_open_dump" in out

    def test_operation_name_is_optional(self):
        out = safe_tool_error("", RuntimeError(LEAK_MARKER))
        assert_no_host_leak(out)
        assert_has_reference_id(out)

    def test_ghidra_diagnostic_passthrough_is_preserved(self):
        """
        security.safe_error_message deliberately surfaces a curated
        ``.diagnostic`` (security.py:720-731). Routing tool errors through
        safe_tool_error must not swallow it -- that diagnostic is how a user
        learns their JDK is mismatched or the OSGi cache is poisoned.
        """
        from src.engines.static.ghidra.runner import GhidraAnalysisError

        err = GhidraAnalysisError(
            "headless analysis failed",
            diagnostic="UnsupportedClassVersionError: Ghidra requires JDK 21",
        )
        out = safe_tool_error("analyze_binary", err)

        assert "UnsupportedClassVersionError" in out
        assert "JDK 21" in out
        assert_has_reference_id(out)

    def test_structured_error_keeps_curated_fields(self):
        structured = StructuredError(
            error=ErrorCode.DEBUGGER_NOT_CONNECTED,
            message="Cannot connect to x64dbg debugger",
            reason="Connection refused on 127.0.0.1:8765",
            suggestions=["Start x64dbg", "Load the MCP plugin"],
            debug_info={"plugin_log": LEAK_MARKER},
        )
        out = safe_tool_error("x64dbg_status", StructuredBaseError(structured))

        # Curated half survives: the model can act on it.
        assert "DEBUGGER_NOT_CONNECTED" in out
        assert "Cannot connect to x64dbg debugger" in out
        assert "Connection refused" in out
        assert "Load the MCP plugin" in out
        # debug_info does not.
        assert_no_host_leak(out)
        assert "plugin_log" not in out
        assert_has_reference_id(out)


class TestCuratedStructuredText:
    def test_debug_info_block_is_dropped(self):
        """
        ``StructuredError.to_user_message`` appends a "Debug information"
        block. That block is where WinDbgBridgeError parks raw CDB stdout,
        so the tool layer renders everything except it.
        """
        structured = StructuredError(
            error=ErrorCode.WINDBG_COMMAND_FAILED,
            message="WinDbg command failed: 'lm'",
            reason="Command produced an error or unexpected output",
            suggestions=["Check the target is broken in"],
            debug_info={"command": "lm", "output": f"symbol path srv*{HOME}*..."},
        )
        text = curated_structured_text(StructuredBaseError(structured))

        assert "Debug information" not in text
        assert_no_host_leak(text)
        assert "WinDbg command failed: 'lm'" in text
        assert "Check the target is broken in" in text

    def test_optional_fields_are_omitted_cleanly(self):
        structured = StructuredError(
            error=ErrorCode.OPERATION_FAILED,
            message="Operation failed",
        )
        text = curated_structured_text(StructuredBaseError(structured))
        assert text == "Error [OPERATION_FAILED]: Operation failed"


# ---------------------------------------------------------------------------
# Tool-level: a representative sample of registered tools
# ---------------------------------------------------------------------------


def _capture_tools(register, *args, **kwargs) -> dict:
    """Run a ``register_*_tools`` function against a fake app, keep the tools."""
    captured: dict = {}

    def _decorator(*_a, **_kw):
        def _wrap(f):
            captured[f.__name__] = f
            return f

        return _wrap

    app = MagicMock()
    app.tool = MagicMock(side_effect=_decorator)
    register(app, *args, **kwargs)
    return captured


@pytest.fixture
def dynamic_tools(monkeypatch):
    """Register the x64dbg tools with the module session manager left unset."""
    mod = pytest.importorskip(
        "src.tools.dynamic_tools", reason="dynamic_tools requires FastMCP"
    )
    monkeypatch.setattr(mod, "_session_manager", None, raising=False)
    tools = _capture_tools(mod.register_dynamic_tools, None)
    monkeypatch.setattr(mod, "_session_manager", None, raising=False)
    return mod, tools


@pytest.fixture
def windbg_tools(monkeypatch):
    """Register the WinDbg tools and pretend we are on Windows."""
    mod = pytest.importorskip(
        "src.tools.windbg_tools", reason="windbg_tools requires FastMCP"
    )
    monkeypatch.setattr(mod, "_is_windows", lambda: True)
    monkeypatch.setattr(mod, "_session_manager", None, raising=False)
    tools = _capture_tools(mod.register_windbg_tools, None)
    monkeypatch.setattr(mod, "_session_manager", None, raising=False)
    return mod, tools


class TestDynamicToolsDoNotLeak:
    @pytest.mark.parametrize(
        "tool_name",
        [
            "x64dbg_status",
            "x64dbg_detach",
            "x64dbg_run",
            "x64dbg_pause",
            "x64dbg_get_registers",
            "x64dbg_get_modules",
        ],
    )
    def test_bridge_failure_is_not_echoed(self, dynamic_tools, monkeypatch, tool_name):
        mod, tools = dynamic_tools
        boom = OSError(f"x64dbg plugin died while writing {LEAK_MARKER}")

        def _raise(*_a, **_kw):
            raise boom

        monkeypatch.setattr(mod, "get_x64dbg_bridge", _raise)
        monkeypatch.setattr(mod, "get_x64dbg_commands", _raise)

        out = tools[tool_name]()

        assert_no_host_leak(out)
        assert_has_reference_id(out)

    def test_connect_keeps_its_actionable_hint(self, dynamic_tools, monkeypatch):
        """
        The port/plugin hint is the useful half of the old message; only the
        socket exception behind it was dropped.
        """
        mod, tools = dynamic_tools

        class _Bridge:
            def __init__(self, *_a, **_kw):
                pass

            def connect(self):
                raise ConnectionRefusedError(f"no listener; tried {LEAK_MARKER}")

        monkeypatch.setattr(mod, "X64DbgBridge", _Bridge)

        out = tools["x64dbg_connect"](port=9999)

        assert_no_host_leak(out)
        assert_has_reference_id(out)
        assert "9999" in out
        assert "MCP plugin" in out

    def test_format_log_template_failure_is_generic(self, dynamic_tools):
        """
        The ``<format error>`` marker is embedded verbatim in breakpoint log
        output, which is exactly the text that ends up in reports.
        """
        mod, _ = dynamic_tools

        class _Bridge:
            def get_registers(self):
                raise RuntimeError(f"register read failed: {LEAK_MARKER}")

        out = mod._format_log_template(_Bridge(), "{rax}")
        assert out == "<format error>"

    def test_validation_message_stays_informative(self, dynamic_tools, monkeypatch):
        """
        A ValueError raised by this project's own validator must survive
        intact -- hiding "must be a valid C identifier" behind a reference ID
        would leave the model with no way to fix its call.
        """
        mod, tools = dynamic_tools

        class _Bridge:
            def set_variable(self, name, value):
                raise ValueError(
                    f"Invalid variable name '{name}': must start with "
                    "letter/underscore and contain only alphanumeric "
                    "characters and underscores"
                )

        monkeypatch.setattr(mod, "get_x64dbg_bridge", lambda: _Bridge())

        out = tools["x64dbg_set_variable"]("bad name", "1")

        assert "must start with letter/underscore" in out
        assert "Reference ID" not in out


class TestWinDbgToolsDoNotLeak:
    @pytest.mark.parametrize(
        "tool_name",
        ["windbg_status", "windbg_run", "windbg_pause", "windbg_get_modules"],
    )
    def test_bridge_error_debug_info_is_not_echoed(
        self, windbg_tools, monkeypatch, tool_name
    ):
        """
        ``WinDbgBridgeError`` stores raw CDB stdout under
        ``debug_info["output"]``, and CDB echoes the symbol path
        (``srv*C:\\Users\\<user>\\symbols*...``) on almost every failure.
        """
        mod, tools = windbg_tools
        from src.engines.dynamic.windbg.bridge import WinDbgBridgeError

        err = WinDbgBridgeError(
            "lm",
            f"Symbol search path is: srv*{HOME}/symbols*https://msdl\n"
            f"{TRACEBACK_MARKER}",
        )

        def _raise(*_a, **_kw):
            raise err

        monkeypatch.setattr(mod, "get_windbg_bridge", _raise)
        monkeypatch.setattr(mod, "get_windbg_commands", _raise)

        out = tools[tool_name]()

        assert_no_host_leak(out)
        assert_has_reference_id(out)
        # The curated half still reaches the model.
        assert "WINDBG_COMMAND_FAILED" in out

    def test_open_dump_failure_is_not_echoed(self, windbg_tools, monkeypatch):
        mod, tools = windbg_tools
        from src.engines.dynamic.windbg.bridge import WinDbgBridgeError

        def _raise(*_a, **_kw):
            raise WinDbgBridgeError("open_dump", f"cannot map {LEAK_MARKER}")

        monkeypatch.setattr(mod, "get_windbg_bridge", _raise)

        out = tools["windbg_open_dump"](f"{HOME}/samples/secret.dmp")
        assert_no_host_leak(out)
        assert_has_reference_id(out)

    def test_disconnect_failure_is_not_echoed(self, windbg_tools, monkeypatch):
        mod, tools = windbg_tools

        def _raise(*_a, **_kw):
            raise RuntimeError(f"COM release failed in {TRACEBACK_MARKER}")

        monkeypatch.setattr(mod, "get_windbg_bridge", _raise)

        out = tools["windbg_disconnect"]()
        assert_no_host_leak(out)
        assert_has_reference_id(out)

    def test_parameter_validation_stays_informative(self, windbg_tools):
        """Range checks the model needs in order to retry are untouched."""
        _, tools = windbg_tools

        out = tools["windbg_connect_kernel"](
            key="1a2b3c.4d5e6f.7890ab.cdef01", ipversion=9
        )
        assert "ipversion must be 4 or 6" in out
        assert "Reference ID" not in out

    def test_address_validator_stays_informative(self, windbg_tools):
        mod, _ = windbg_tools
        out = mod._validate_address("rax; .shell calc")
        assert "Invalid address format" in out
        assert "nt!NtCreateFile" in out


class TestOtherToolModulesDoNotLeak:
    def test_fid_match_unexpected_failure(self, monkeypatch):
        mod = pytest.importorskip("src.tools.fid_tools")

        cache = MagicMock()
        cache.get_cached.side_effect = OSError(f"cache unreadable: {LEAK_MARKER}")
        tools = _capture_tools(
            mod.register_fid_tools, MagicMock(), cache, MagicMock()
        )

        import src.utils.security as security

        monkeypatch.setattr(
            security,
            "sanitize_binary_path",
            lambda p, **kw: Path(p),
        )
        monkeypatch.setattr(mod, "sanitize_binary_path", lambda p, **kw: Path(p))

        out = tools["fid_match"]("/samples/a.bin")
        assert_no_host_leak(out)
        assert_has_reference_id(out)


# ---------------------------------------------------------------------------
# Source-level guard against reintroduction
# ---------------------------------------------------------------------------

_TOOLS_DIR = Path(__file__).resolve().parent.parent / "src" / "tools"

# src/server.py is NOT under src/tools/, and every F-10 guard globbed only that
# directory -- so the single largest tool surface in the repo (41 MCP tools) was
# scanned by none of them. It carried 55 handlers echoing caught exceptions,
# including one this branch itself added that returned the Path.home()-derived
# extraction root. Scanning it here is what stops that recurring.
_SERVER_PY = Path(__file__).resolve().parent.parent / "src" / "server.py"


def _guarded_sources() -> list[Path]:
    """Every file the F-10 guards must inspect: src/tools/*.py plus server.py."""
    return sorted(_TOOLS_DIR.glob("*.py")) + [_SERVER_PY]

# Exception types whose messages are raised by this project's own validators.
# Those are deliberately echoed verbatim (see the F-10 comments in the tool
# modules); anything broader has to go through safe_error_message /
# safe_tool_error instead.
_VALIDATION_ONLY_HANDLERS = {"ValueError"}


def _raw_error_returns(path: Path) -> list[tuple[int, str]]:
    """Find ``return f"Error: {e}"`` sites and the except clause governing them."""
    lines = path.read_text(encoding="utf-8").splitlines()
    found = []
    for index, line in enumerate(lines):
        if line.strip() != 'return f"Error: {e}"':
            continue
        clause = None
        for back in range(index - 1, -1, -1):
            match = re.match(r"except\s+(.*?)\s+as\s+e\s*:", lines[back].strip())
            if match:
                clause = match.group(1)
                break
        found.append((index + 1, clause or "<none>"))
    return found


def test_no_catch_all_handler_echoes_raw_exception_text():
    """
    Audit F-10 guard. A ``return f"Error: {e}"`` under ``except Exception``
    (or under any non-validation exception type) is the exact pattern the
    finding was about: it puts external-tool and filesystem text, including
    ``Path.home()``, into model context. New tools must use
    ``safe_error_message`` / ``safe_tool_error`` instead.
    """
    offenders = []
    for path in _guarded_sources():
        for line_no, clause in _raw_error_returns(path):
            if clause not in _VALIDATION_ONLY_HANDLERS:
                offenders.append(f"{path.name}:{line_no} (except {clause})")

    assert not offenders, (
        "raw exception text returned to the model (audit F-10):\n  "
        + "\n  ".join(offenders)
    )


# ---------------------------------------------------------------------------
# AST guard: ANY returned f-string that interpolates a caught exception
# ---------------------------------------------------------------------------
#
# The line-matching guard above only ever recognised ONE spelling -- the exact
# source line ``return f"Error: {e}"``. An adversarial review of the first
# remediation pass found that every leak it was supposed to catch was written
# in some other spelling and sailed straight through it:
#
#     return f"Invalid binary path: {e}"          # review_tools x5, fid_tools
#     return f"Error: Invalid output path - {e}"  # dynamic_tools
#     return f"File not found: {e}"               # vt_tools
#
# All of those interpolate a caught exception whose message is built from a
# resolved absolute path -- the quarantine allow-list, the dump directory, the
# sanitized sample path -- i.e. exactly the ``Path.home()`` disclosure F-10 is
# about. A guard that a one-word rename defeats is not a guard, so the check
# below is structural: parse the module, find every ``except ... as <name>``,
# and flag any ``return`` inside it whose f-string interpolates <name>.
#
# The old line-based test is deliberately KEPT rather than replaced. It pins
# the single most common spelling with a very precise message, and the two
# tests failing together on a regression is cheap.

_AST_ALLOWED_HANDLERS = {
    # This project's own validators. "Invalid hash length: 33", "address must
    # be hex", enum/range errors: the model needs these to repair its own
    # call, and they quote the model's own arguments, not the host.
    "ValueError",
    "TypeError",
    # UserFacingError exists precisely to make a verbatim passthrough safe by
    # construction (src/utils/security.py). Its __str__ is
    # ``user_message + "Reference ID: ..."`` -- user_message is written in this
    # repo, and the untrusted half (internal_details) is LOGGED in __init__ and
    # never rendered. Echoing one is the sanctioned pattern, not a leak.
    "UserFacingError",
    # Dedicated, module-private exception types introduced precisely so that
    # a verbatim passthrough is bounded by construction rather than by
    # inspection. Both are raised ONLY with sentences written in this repo:
    #   * CfgBuildError  (src/tools/control_flow_tools.py) -- "Unsupported
    #     architecture for disassembly...", "...has no basic blocks in the
    #     cached analysis", "Ghidra did not produce output."
    #   * VirusTotalError (src/tools/vt_tools.py) -- "Hash not found in
    #     VirusTotal database", "rate limit exceeded", the HTTP status line.
    # Neither can carry a filesystem path, because neither is ever raised
    # with one. Widening this set requires the same audit.
    "CfgBuildError",
    "VirusTotalError",
    # Third-party, reviewed: pefile raises PEFormatError with a fixed set of
    # structural descriptions ("DOS Header magic not found.", "Invalid NT
    # Headers signature.") and never interpolates the file path -- pefile is
    # handed a file object / bytes by the time these fire. The text is the
    # only thing that tells a user their "PE" is actually a script or a
    # truncated download, so it is worth keeping.
    "pefile.PEFormatError",
}


def _handler_clause_names(handler: ast.ExceptHandler) -> list[str]:
    """Names of the exception types a handler catches, as written in source."""
    if handler.type is None:
        return ["<bare except>"]
    if isinstance(handler.type, ast.Tuple):
        return [ast.unparse(element) for element in handler.type.elts]
    return [ast.unparse(handler.type)]


def _interpolated_names(node: ast.AST) -> set[str]:
    """Every bare name interpolated by an f-string anywhere under ``node``."""
    names: set[str] = set()
    # Walk EVERY name in the returned expression, not just the ones inside
    # f-string placeholders.
    #
    # The original guard inspected only ast.FormattedValue, so it caught
    # `return f"Error: {e}"` and nothing else. An adversarial review pointed
    # out that `str(e)`, `"{}".format(e)`, `"x: " % e`, `"x: " + str(e)`,
    # `return e` and `e.args[0]` all leak exactly the same host detail and all
    # sailed past it -- a guard that reports coverage it does not have.
    #
    # Subtrees that are calls to an audited safe helper are pruned rather than
    # walked: passing the exception to safe_tool_error / safe_error_message /
    # safe_path_error / curated_structured_text IS the sanctioned fix, so
    # seeing `e` in there is correct, not a leak.
    for inner in _walk_pruning_safe_helpers(node):
        if isinstance(inner, ast.Name):
            names.add(inner.id)
    return names


#: Helpers that log the detail internally and return a safe string. Handing a
#: caught exception to one of these is the fix, not the defect.
_SAFE_ERROR_HELPERS = frozenset(
    {
        "safe_tool_error",
        "safe_error_message",
        "safe_path_error",
        "curated_structured_text",
        "format_error_response",
    }
)


def _walk_pruning_safe_helpers(node: ast.AST):
    """Yield every node under ``node``, skipping audited safe-helper calls."""
    if isinstance(node, ast.Call):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in _SAFE_ERROR_HELPERS:
            return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from _walk_pruning_safe_helpers(child)


def _exception_echoing_returns(path: Path) -> list[tuple[int, str, str]]:
    """
    Find ``return f"...{e}..."`` statements governed by ``except ... as e``.

    Returns ``(line_number, clause_text, source_text)`` for each offender,
    skipping handlers whose caught types are all on the allow-list.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    offenders: list[tuple[int, str, str]] = []

    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or handler.name is None:
            continue

        clauses = _handler_clause_names(handler)
        if set(clauses) <= _AST_ALLOWED_HANDLERS:
            continue

        # ast.walk descends into nested handlers too. That is intentional: a
        # `return f"...{e}..."` inside an inner try still leaks the OUTER
        # exception if it names it, and the inner handler is visited on its
        # own turn for its own binding.
        for node in ast.walk(handler):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            if handler.name in _interpolated_names(node.value):
                offenders.append(
                    (node.lineno, ", ".join(clauses), ast.unparse(node)[:120])
                )

    return offenders


def test_no_returned_fstring_interpolates_a_caught_exception():
    """
    Audit F-10 guard, structural form.

    Any exception a tool handler catches may carry host detail -- an absolute
    path under ``Path.home()``, the operator's username, CDB stdout, Pybag COM
    internals -- and interpolating it into the returned string puts that
    detail in the model's context and then in generated reports. Route it
    through ``safe_error_message`` / ``safe_tool_error`` / ``safe_path_error``,
    which log the detail against a reference ID, or narrow the handler to one
    of the audited types in ``_AST_ALLOWED_HANDLERS``.
    """
    offenders = []
    for path in _guarded_sources():
        for line_no, clause, source in _exception_echoing_returns(path):
            offenders.append(f"{path.name}:{line_no} (except {clause}) -> {source}")

    assert not offenders, (
        "returned f-string interpolates a caught exception (audit F-10):\n  "
        + "\n  ".join(offenders)
    )


def test_ast_guard_actually_catches_the_spellings_the_line_guard_missed():
    """
    Meta-test: prove the new guard would have failed the FIRST pass.

    Without this, a future refactor could quietly reduce the AST check to the
    same literal match as the old one and nothing would notice. Each snippet
    below is a real leak that shipped in pass one and that
    ``_raw_error_returns`` scores as clean.
    """
    leaks = [
        # review_tools.py / fid_tools.py, pass one.
        'def f():\n'
        '    try:\n'
        '        pass\n'
        '    except (PathTraversalError, FileSizeError) as e:\n'
        '        return f"Invalid binary path: {e}"\n',
        # dynamic_tools.py, pass one.
        'def f():\n'
        '    try:\n'
        '        pass\n'
        '    except PathTraversalError as e:\n'
        '        return f"Error: Invalid output path - {e}"\n',
        # vt_tools.py, pass one.
        'def f():\n'
        '    try:\n'
        '        pass\n'
        '    except FileNotFoundError as e:\n'
        '        return f"File not found: {e}"\n',
        # Interpolation nested in an expression rather than bare.
        'def f():\n'
        '    try:\n'
        '        pass\n'
        '    except OSError as e:\n'
        '        return f"failed: {str(e).strip()}"\n',
    ]

    for source in leaks:
        tree = ast.parse(source)
        handler = next(
            node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
        )
        assert set(_handler_clause_names(handler)) - _AST_ALLOWED_HANDLERS, source
        returns = [
            node
            for node in ast.walk(handler)
            if isinstance(node, ast.Return)
            and node.value is not None
            and handler.name in _interpolated_names(node.value)
        ]
        assert returns, f"AST guard missed a known pass-one leak:\n{source}"

    # ... and the allow-listed shape stays clean, so the guard is not simply
    # flagging everything.
    tree = ast.parse(
        'def f():\n'
        '    try:\n'
        '        pass\n'
        '    except ValueError as e:\n'
        '        return f"Invalid limit: {e}"\n'
    )
    handler = next(
        node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
    )
    assert set(_handler_clause_names(handler)) <= _AST_ALLOWED_HANDLERS


class TestPeToolsStructuredErrorsAreCurated:
    """pe_tools must not hand StructuredError.debug_info to the model.

    The three pe_tools handlers returned ``to_user_message()``, which appends
    a "Debug information" block verbatim. The producers put host state in it:
    carving._validate_output_dir puts the resolved output_dir and the entire
    BINARY_MCP_ALLOWED_DIRS list there, authenticode puts the resolved sample
    path. All of that carries the operator's username into model context and
    from there into any report built on the transcript.
    """

    def _confined_error(self, tmp_path, monkeypatch):
        from pathlib import Path

        from src.utils.carving import _validate_output_dir
        from src.utils.structured_errors import StructuredBaseError

        quarantine = tmp_path / "quarantine-token"
        quarantine.mkdir()
        monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(quarantine))
        try:
            _validate_output_dir(Path("/etc/pwned"))
        except StructuredBaseError as exc:
            return exc, str(quarantine)
        raise AssertionError("expected _validate_output_dir to refuse /etc/pwned")

    def test_curated_text_omits_debug_info(self, tmp_path, monkeypatch):
        from src.tools.error_hygiene import curated_structured_text

        exc, quarantine = self._confined_error(tmp_path, monkeypatch)
        out = curated_structured_text(exc)

        assert quarantine not in out, out
        assert "/etc/pwned" not in out, out
        assert "Debug information" not in out, out

    def test_curated_text_stays_actionable(self, tmp_path, monkeypatch):
        """Suppressing the leak must not reduce the message to a bare code --
        the model still needs to know how to correct its own call."""
        from src.tools.error_hygiene import curated_structured_text

        exc, _ = self._confined_error(tmp_path, monkeypatch)
        out = curated_structured_text(exc)

        assert "Invalid output_dir" in out
        assert "BINARY_MCP_ALLOWED_DIRS" in out
        assert "Suggested actions" in out

    def test_pe_tools_no_longer_calls_to_user_message(self):
        """Pin the fix so the leak cannot be reintroduced by a later edit.

        AST-based rather than a substring scan: the explanatory comments above
        each fixed site legitimately name ``to_user_message()``, and a textual
        check flags those. Matching on actual call nodes is what the assertion
        is really about.
        """
        import ast
        import pathlib

        tree = ast.parse(
            pathlib.Path("src/tools/pe_tools.py").read_text(encoding="utf-8")
        )
        offenders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "to_user_message"
        ]
        assert not offenders, (
            f"pe_tools calls to_user_message() at lines {offenders}; it appends "
            "the leaky debug_info block. Use curated_structured_text instead"
        )


# ---------------------------------------------------------------------------
# Self-test: the widened guard must actually catch the non-f-string spellings
# ---------------------------------------------------------------------------

_LEAKY_SPELLINGS = {
    "f-string": 'return f"Error: {e}"',
    "str() call": "return str(e)",
    "repr() call": "return repr(e)",
    "format()": 'return "Error: {}".format(e)',
    "percent": 'return "Error: %s" % e',
    "concatenation": 'return "Error: " + str(e)',
    "bare name": "return e",
    "attribute": "return e.args[0]",
    "join": 'return "".join(["Error: ", str(e)])',
    "nested in fstring call": 'return f"Error: {str(e)}"',
}

_SAFE_SPELLINGS = {
    "safe_tool_error": 'return safe_tool_error("op", e)',
    "safe_error_message": 'return safe_error_message("op", e)',
    "safe_path_error": 'return safe_path_error("op", e)',
    "curated_structured_text": "return curated_structured_text(e)",
    "prefixed safe call": 'return "note\\n" + safe_tool_error("op", e)',
    "unrelated name": 'return f"Error: {other}"',
}


def _guard_flags(body: str, tmp_path) -> bool:
    """Run the real guard over a synthetic handler and report whether it fired."""
    source = "def f():\n    try:\n        pass\n    except Exception as e:\n        " + body + "\n"
    path = tmp_path / "synthetic_tool.py"
    path.write_text(source, encoding="utf-8")
    return bool(_exception_echoing_returns(path))


@pytest.mark.parametrize("label,body", sorted(_LEAKY_SPELLINGS.items()))
def test_widened_guard_catches_every_leaky_spelling(label, body, tmp_path):
    """
    The guard inspected only ``ast.FormattedValue``, so it caught the f-string
    and nothing else -- ``str(e)``, ``.format(e)``, ``%``, concatenation, a
    bare ``return e`` and ``e.args[0]`` all leak identical host detail and all
    passed. A guard reporting coverage it does not have is worse than none.
    """
    assert _guard_flags(body, tmp_path), f"{label} not flagged: {body}"


@pytest.mark.parametrize("label,body", sorted(_SAFE_SPELLINGS.items()))
def test_widened_guard_does_not_flag_the_sanctioned_fix(label, body, tmp_path):
    """Handing the exception to an audited helper IS the fix; flagging it would
    make the guard unusable and push people to suppress it."""
    assert not _guard_flags(body, tmp_path), f"{label} wrongly flagged: {body}"


# ---------------------------------------------------------------------------
# AST guard: exception text forwarded through StructuredError.reason
# ---------------------------------------------------------------------------
#
# Both guards above glob src/tools/ ONLY, and both key on RETURNED strings. The
# src/utils/ producers that raise StructuredBaseError from a path failure are
# outside that scope on both counts, and they leaked the same host detail
# through a different door:
#
#     except (PathTraversalError, FileSizeError, ...) as e:
#         raise StructuredBaseError(StructuredError(..., reason=str(e), ...))
#
# curated_structured_text drops debug_info but deliberately KEEPS reason, so the
# confinement denial -- which interpolates the quarantine directory list and
# Path.home() -- reached the model verbatim from carving.carve,
# similarity_hashes.compute and authenticode.inspect. That is the same finding
# the tool handlers were fixed for, re-entering through the structured path.
#
# The fix is security.safe_path_reason(); this guard keeps it that way.

_SRC_DIR = Path(__file__).resolve().parent.parent / "src"


# Helpers that exist precisely to render a caught exception safely. Passing the
# exception to one of these IS the fix, so the guard must not flag it -- the
# same reasoning as _SAFE_SPELLINGS for the returned-string guard.
_SANCTIONED_REASON_HELPERS = {"safe_path_reason", "path_error_guidance"}

# Exception types whose message describes the FILE FORMAT or this project's own
# internal state, never the host's directory layout: pefile's "DOS Header magic
# not found", a KeyError on a digest algorithm. The model needs those to tell a
# malformed sample from a bad path, and they carry nothing to disclose. A
# handler that catches only these may echo the exception.
_NON_DISCLOSING_HANDLERS = {"PEFormatError", "ValueError", "KeyError"}


def _handler_types(handler: ast.ExceptHandler) -> set[str]:
    """Bare type names caught by an except clause (``pefile.PEFormatError`` -> ...)."""
    if handler.type is None:
        return {"BaseException"}
    nodes = (
        handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
    )
    names: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Name):
            names.add(node.id)
        else:  # pragma: no cover - defensive
            names.add(ast.unparse(node))
    return names


def _reason_kwargs_echoing_exception(path: Path) -> list[tuple[int, str]]:
    """Find ``reason=`` keyword arguments that interpolate a caught exception."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:  # pragma: no cover - not expected in-repo
        return []

    offenders: list[tuple[int, str]] = []
    for handler in ast.walk(tree):
        if not isinstance(handler, ast.ExceptHandler) or not handler.name:
            continue
        if _handler_types(handler) <= _NON_DISCLOSING_HANDLERS:
            continue
        for node in ast.walk(handler):
            if not isinstance(node, ast.keyword) or node.arg != "reason":
                continue
            names = {
                child.id
                for child in ast.walk(node.value)
                if isinstance(child, ast.Name)
            }
            if handler.name not in names:
                continue
            if (
                isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in _SANCTIONED_REASON_HELPERS
            ):
                continue
            offenders.append((node.value.lineno, ast.unparse(node.value)))
    return offenders


def test_structured_error_reason_never_echoes_a_caught_exception():
    """
    ``StructuredError.reason`` is forwarded to the model verbatim by
    ``curated_structured_text``, so it must never carry exception text. Put the
    original in ``debug_info`` (dropped by that renderer, kept by the log) and
    use ``security.safe_path_reason`` for the model-facing half.
    """
    offenders = [
        f"{path.relative_to(_SRC_DIR.parent)}:{line_no}  reason={expr}"
        for path in sorted(_SRC_DIR.rglob("*.py"))
        for line_no, expr in _reason_kwargs_echoing_exception(path)
    ]

    assert not offenders, (
        "caught-exception text forwarded through StructuredError.reason; it "
        "reaches the model via curated_structured_text (audit F-10):\n  "
        + "\n  ".join(offenders)
    )


_LEAKY_REASONS = {
    "str": "        raise E(S(reason=str(e), debug_info={}))",
    "fstring": '        raise E(S(reason=f"could not resolve: {e}"))',
    "concat": '        raise E(S(reason="failed: " + str(e)))',
    "bare": "        raise E(S(reason=e.args[0]))",
}

_SAFE_REASONS = {
    "sanctioned helper": "        raise E(S(reason=safe_path_reason(e)))",
    "literal": '        raise E(S(reason="the path is outside the allow-list"))',
    "detail in debug_info": (
        '        raise E(S(reason="generic", debug_info={"detail": str(e)}))'
    ),
}


def _reason_guard_flags(body: str, tmp_path: Path, clause: str = "OSError") -> bool:
    source = f"try:\n    pass\nexcept {clause} as e:\n{body}\n"
    path = tmp_path / "sample_reason.py"
    path.write_text(source, encoding="utf-8")
    return bool(_reason_kwargs_echoing_exception(path))


@pytest.mark.parametrize("label,body", sorted(_LEAKY_REASONS.items()))
def test_reason_guard_catches_leaky_spellings(label, body, tmp_path):
    """A guard that passes because it recognises nothing is worse than none."""
    assert _reason_guard_flags(body, tmp_path), f"{label} not flagged: {body}"


@pytest.mark.parametrize("label,body", sorted(_SAFE_REASONS.items()))
def test_reason_guard_allows_the_sanctioned_fix(label, body, tmp_path):
    assert not _reason_guard_flags(body, tmp_path), f"{label} wrongly flagged: {body}"


@pytest.mark.parametrize("clause", ["pefile.PEFormatError", "ValueError", "KeyError"])
def test_reason_guard_allows_format_only_handlers(clause, tmp_path):
    """PE-parser and internal-state messages name no host path -- and the model
    needs them to tell a malformed sample from a bad path."""
    assert not _reason_guard_flags("        raise E(S(reason=str(e)))", tmp_path, clause)
