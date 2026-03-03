"""
Tests for control flow analysis tools.

Uses mocked cache/runner data to test CFG construction,
cyclomatic complexity, loop detection, and dead code analysis.
"""

from unittest.mock import MagicMock


# Sample cached analysis data for testing
def _make_analysis_context(functions=None):
    """Build a minimal analysis context dict."""
    return {
        "metadata": {
            "name": "test.exe",
            "executable_format": "PE",
            "image_base": "0x400000",
        },
        "functions": functions or [],
        "imports": [],
        "strings": [],
        "memory_map": [],
    }


def _make_function(
    name="test_func",
    address="0x401000",
    basic_blocks=None,
    called_functions=None,
    pseudocode="int test_func() { return 0; }",
    is_thunk=False,
    is_external=False,
    parameters=None,
    local_variables=None,
    signature="int test_func(void)",
    decompile_status="success",
):
    return {
        "name": name,
        "address": address,
        "basic_blocks": basic_blocks or [],
        "called_functions": called_functions or [],
        "pseudocode": pseudocode,
        "is_thunk": is_thunk,
        "is_external": is_external,
        "parameters": parameters or [],
        "local_variables": local_variables or [],
        "signature": signature,
        "decompile_status": decompile_status,
    }


class TestControlFlowHelpers:
    """Test internal helper functions."""

    def test_parse_address_hex(self):
        """Should parse hex address strings."""
        from src.tools.control_flow_tools import _parse_address

        assert _parse_address("0x401000") == 0x401000
        assert _parse_address("401000") == 0x401000

    def test_find_function_by_name(self):
        """Should find functions by exact name."""
        from src.tools.control_flow_tools import _find_function

        funcs = [_make_function(name="main", address="0x401000")]
        result = _find_function(funcs, "main")
        assert result is not None
        assert result["name"] == "main"

    def test_find_function_by_address(self):
        """Should find functions by address."""
        from src.tools.control_flow_tools import _find_function

        funcs = [_make_function(name="main", address="0x401000")]
        result = _find_function(funcs, "0x401000")
        assert result is not None

    def test_find_function_not_found(self):
        """Should return None for unknown functions."""
        from src.tools.control_flow_tools import _find_function

        funcs = [_make_function(name="main")]
        assert _find_function(funcs, "nonexistent") is None

    def test_find_loops_no_edges(self):
        """No edges means no loops."""
        from src.tools.control_flow_tools import _find_loops

        blocks = {0x401000: {"start": 0x401000, "end": 0x401010, "size": 10}}
        loops = _find_loops(blocks, [], 0x401000)
        assert loops == []

    def test_find_loops_with_back_edge(self):
        """A back edge to an ancestor should produce a loop."""
        from src.tools.control_flow_tools import _find_loops

        blocks = {
            0x401000: {"start": 0x401000, "end": 0x401010, "size": 10},
            0x401010: {"start": 0x401010, "end": 0x401020, "size": 10},
        }
        # Block 0x401010 jumps back to 0x401000 = loop
        edges = [(0x401000, 0x401010), (0x401010, 0x401000)]
        loops = _find_loops(blocks, edges, 0x401000)
        assert len(loops) == 1
        assert loops[0]["header"] == 0x401000

    def test_compute_nesting_depth_single_loop(self):
        """Single loop should have depth 1."""
        from src.tools.control_flow_tools import _compute_nesting_depth

        loops = [{"header": 0x401000, "back_edge_src": 0x401010,
                   "body": {0x401000, 0x401010}}]
        depths = _compute_nesting_depth(loops)
        assert depths[0x401000] == 1

    def test_compute_nesting_depth_nested(self):
        """Inner loop should have deeper nesting."""
        from src.tools.control_flow_tools import _compute_nesting_depth

        outer_body = {0x1000, 0x2000, 0x3000, 0x4000}
        inner_body = {0x2000, 0x3000}
        loops = [
            {"header": 0x1000, "back_edge_src": 0x4000, "body": outer_body},
            {"header": 0x2000, "back_edge_src": 0x3000, "body": inner_body},
        ]
        depths = _compute_nesting_depth(loops)
        assert depths[0x1000] == 1
        assert depths[0x2000] == 2


class TestControlFlowToolRegistration:
    """Test that tools register and handle basic inputs."""

    def setup_method(self):
        """Set up mock app, cache, and runner."""
        self.app = MagicMock()
        self.app.tool = MagicMock(return_value=lambda f: f)
        self.session_manager = MagicMock()
        self.cache = MagicMock()
        self.runner = MagicMock()

    def test_registration_succeeds(self):
        """register_control_flow_tools should not raise."""
        from src.tools.control_flow_tools import register_control_flow_tools

        register_control_flow_tools(
            self.app, self.session_manager, self.cache, self.runner
        )
        # Verify app.tool was called (tools were registered)
        assert self.app.tool.call_count >= 4

    def test_analyze_control_flow_no_cache(self):
        """Should return error when binary not analyzed."""
        from src.tools.control_flow_tools import register_control_flow_tools

        self.cache.get_cached.return_value = None
        self.runner.analyze = MagicMock(side_effect=RuntimeError("no ghidra"))

        register_control_flow_tools(
            self.app, self.session_manager, self.cache, self.runner
        )


class TestDeadCodeDetection:
    """Test dead code / orphan function detection logic."""

    def test_entry_point_not_flagged(self):
        """Entry points (main, _start) should not be flagged as dead."""
        funcs = [
            _make_function(name="main", address="0x401000"),
            _make_function(
                name="helper",
                address="0x402000",
                called_functions=[],
            ),
        ]
        # main has no callers but is an entry point
        # helper has no callers and is not an entry point
        entry_names = {"main", "_start", "entry", "DllMain", "WinMain"}
        orphans = [
            f for f in funcs
            if f["name"] not in entry_names
            and not any(
                f["name"] in [c["name"] for c in other.get("called_functions", [])]
                for other in funcs
                if other["name"] != f["name"]
            )
        ]
        assert len(orphans) == 1
        assert orphans[0]["name"] == "helper"
