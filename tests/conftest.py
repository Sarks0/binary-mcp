"""Suite-wide test isolation."""

import pytest


@pytest.fixture(autouse=True)
def _no_symbol_server_by_default(monkeypatch):
    """Never let an analysis under test reach the real symbol server.

    First imports try an automatic PDB fetch (BINARY_MCP_AUTO_PDB). Tests that
    exercise that path patch the fetch or set the policy themselves.
    """
    monkeypatch.setenv("BINARY_MCP_AUTO_PDB", "never")
