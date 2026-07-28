"""
Tests for path-confinement hardening (audit item 2: H8, H9, M13, P4).

Before this change, ``sanitize_binary_path`` only enforced directory
confinement when the *caller* passed ``allowed_dirs``. Almost every tool
entry point called it bare, so an operator who set ``BINARY_MCP_ALLOWED_DIRS``
still got arbitrary-file reads handed to Ghidra/ILSpy (H9), and an unset
config silently meant "allow any" with no signal (M13). The validator now
resolves the configured allow-list itself and can fail closed, so confinement
is applied uniformly without touching ~30 call sites.

``read_full`` also read whole files into memory unbounded (H8); it now rejects
oversized files.
"""

import pytest

from src.utils.binary_reader import BinaryReader
from src.utils.security import PathTraversalError, sanitize_binary_path

# -- H9 / P4: confinement is applied even when the caller omits allowed_dirs --


def test_confinement_applied_when_caller_omits_allowed_dirs(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    inside_file = allowed / "sample.bin"
    inside_file.write_bytes(b"MZ\x00\x00")
    outside_file = outside / "secret.bin"
    outside_file.write_bytes(b"MZ\x00\x00")

    monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(allowed))
    monkeypatch.delenv("BINARY_MCP_REQUIRE_CONFINEMENT", raising=False)

    # Caller passes NO allowed_dirs -- confinement must still apply.
    assert sanitize_binary_path(str(inside_file)) == inside_file.resolve()
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside_file))


def test_explicit_allowed_dirs_still_enforced(tmp_path, monkeypatch):
    """Control: an explicitly-passed allow-list keeps working unchanged."""
    monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside_file = tmp_path / "b.bin"
    outside_file.write_bytes(b"MZ\x00\x00")
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(outside_file), allowed_dirs=[allowed])


# -- M13: unconfigured behaviour (default-open with a signal, or fail closed) --


def test_unconfigured_allows_by_default(tmp_path, monkeypatch):
    """Back-compat: with nothing configured, analysis still works."""
    monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
    monkeypatch.delenv("BINARY_MCP_REQUIRE_CONFINEMENT", raising=False)
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    assert sanitize_binary_path(str(f)) == f.resolve()


def test_require_confinement_fails_closed_when_unconfigured(tmp_path, monkeypatch):
    """Operators can demand a hard boundary: unset allow-list -> refuse."""
    monkeypatch.delenv("BINARY_MCP_ALLOWED_DIRS", raising=False)
    monkeypatch.setenv("BINARY_MCP_REQUIRE_CONFINEMENT", "1")
    f = tmp_path / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    with pytest.raises(PathTraversalError):
        sanitize_binary_path(str(f))


def test_require_confinement_allows_inside_configured_dir(tmp_path, monkeypatch):
    """Fail-closed mode still permits files inside the configured allow-list."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    f = allowed / "a.bin"
    f.write_bytes(b"MZ\x00\x00")
    monkeypatch.setenv("BINARY_MCP_ALLOWED_DIRS", str(allowed))
    monkeypatch.setenv("BINARY_MCP_REQUIRE_CONFINEMENT", "1")
    assert sanitize_binary_path(str(f)) == f.resolve()


# -- H8: read_full must not slurp an unbounded file into memory --


def test_read_full_accepts_within_cap(tmp_path):
    f = tmp_path / "small.bin"
    f.write_bytes(b"\x00" * 1024)
    with BinaryReader(str(f)) as reader:
        assert reader.read_full(max_bytes=8192) == b"\x00" * 1024


def test_read_full_rejects_oversized(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"\x00" * 4096)
    with BinaryReader(str(f)) as reader:
        with pytest.raises(ValueError, match="too large"):
            reader.read_full(max_bytes=1024)
