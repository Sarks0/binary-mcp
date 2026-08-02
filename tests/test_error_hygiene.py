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
    for path in sorted(_TOOLS_DIR.glob("*.py")):
        for line_no, clause in _raw_error_returns(path):
            if clause not in _VALIDATION_ONLY_HANDLERS:
                offenders.append(f"{path.name}:{line_no} (except {clause})")

    assert not offenders, (
        "raw exception text returned to the model (audit F-10):\n  "
        + "\n  ".join(offenders)
    )
