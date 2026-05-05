"""Tests for the VR-workflow enhancements.

Covers:
- _extract_iocs_shallow: cache-free IOC extraction for VR triage
- scan_pseudocode: explicit error on shallow/structural cache
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())


def test_extract_iocs_shallow_finds_url_and_path(tmp_path):
    """Shallow extractor pulls IOCs from raw bytes without a Ghidra cache."""
    from src.tools.malware_tools import _extract_iocs_shallow

    binary = tmp_path / "fake.bin"
    payload = (
        b"\x00" * 16
        + b"https://evil.example.com/payload.exe\x00"
        + b"C:\\Windows\\System32\\malware.dll\x00"
        + b"\x90" * 32
    )
    binary.write_bytes(payload)

    out = _extract_iocs_shallow(str(binary))
    assert "SHALLOW" in out
    assert "evil.example.com" in out
    assert "Total IOCs" in out


def test_extract_iocs_shallow_handles_empty(tmp_path):
    """Empty / IOC-free file returns the no-IOCs message without crashing."""
    from src.tools.malware_tools import _extract_iocs_shallow

    binary = tmp_path / "empty.bin"
    binary.write_bytes(b"\x00" * 1024)

    out = _extract_iocs_shallow(str(binary))
    assert "No IOCs extracted" in out or "Total IOCs: 0" in out


def test_scan_pseudocode_rejects_shallow_cache():
    """scan_pseudocode must surface a clear error on a depth='shallow' cache."""
    from src.tools.review_tools import register_review_tools

    fake_app = MagicMock()
    fake_session_manager = MagicMock()
    fake_runner = MagicMock()
    fake_cache = MagicMock()

    captured: dict[str, object] = {}

    def fake_tool(*_args, **_kwargs):
        def decorator(fn):
            if fn.__name__ == "scan_pseudocode":
                captured["scan_pseudocode"] = fn
            return fn
        return decorator

    fake_app.tool = fake_tool

    # _load_context returns (context, _) with a shallow-tagged metadata.
    import src.tools.review_tools as rt
    rt._load_context = lambda _bp, _c, _r: (
        {"metadata": {"analysis_depth": "shallow"}, "functions": []},
        None,
    )

    register_review_tools(fake_app, fake_session_manager, fake_cache, fake_runner)
    fn = captured["scan_pseudocode"]
    out = fn("/tmp/whatever.bin")
    assert "shallow" in out.lower()
    assert "force_reanalyze" in out
    assert "search_strings" in out
