"""Suite-wide test isolation."""

import pytest

# Variables that now change what the code under test connects to, or refuses to
# connect to. Before the endpoint policy existed, X64DbgBridge() ignored the
# environment entirely; it now resolves it, so a developer with X64DBG_HOST set
# in their shell would see the x64dbg suites fail for a reason that has nothing
# to do with their change. Cleared for every test; the tests that exercise the
# policy set what they need themselves.
_REMOTE_ENV_VARS = (
    "X64DBG_HOST",
    "X64DBG_PORT",
    "X64DBG_TIMEOUT",
    "X64DBG_TLS_CA",
    "X64DBG_TLS_CLIENT_CERT",
    "X64DBG_TLS_CLIENT_KEY",
    "OBSIDIAN_AUTH_TOKEN",
    "BINARY_MCP_TRANSPORT",
    "BINARY_MCP_HTTP_HOST",
    "BINARY_MCP_HTTP_PORT",
    "BINARY_MCP_HTTP_PATH",
    "BINARY_MCP_HTTP_TOKEN",
    "BINARY_MCP_HTTP_ALLOWED_HOSTS",
    "BINARY_MCP_REMOTE_ALLOW",
    "BINARY_MCP_REMOTE_TLS_CERT",
    "BINARY_MCP_REMOTE_TLS_KEY",
    "BINARY_MCP_REMOTE_TLS_CA",
    "BINARY_MCP_REMOTE_CLIENT_ALLOWLIST",
)


@pytest.fixture(autouse=True)
def _no_symbol_server_by_default(monkeypatch):
    """Never let an analysis under test reach the real symbol server.

    First imports try an automatic PDB fetch (BINARY_MCP_AUTO_PDB). Tests that
    exercise that path patch the fetch or set the policy themselves.
    """
    monkeypatch.setenv("BINARY_MCP_AUTO_PDB", "never")


@pytest.fixture(autouse=True)
def _no_ambient_remote_config(monkeypatch):
    """Resolve endpoints from the test's own environment, never the developer's."""
    for name in _REMOTE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
