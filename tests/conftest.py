"""Suite-wide test isolation."""

import pytest

import src.utils.config as config_module

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
    # Both of these became live reads in this branch.
    "BINARY_MCP_SESSION_DIR",
    "BINARY_MCP_LOG_LEVEL",
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
    """Resolve endpoints from the test's own environment, never the developer's.

    Clearing os.environ is not enough on its own, which is what this fixture
    used to do. The code under test resolves through ``get_config``, which
    falls back to a ``.env`` found by searching up from src/utils and in the
    working directory -- so deleting X64DBG_HOST from the environment just made
    get_config fall through to that file. A developer with
    ``X64DBG_HOST=192.168.1.50`` in a .env still saw every x64dbg suite fail
    inside the X64DbgBridge constructor: precisely the failure this fixture
    claims to prevent.

    Marking the cache loaded and empty removes the file as an input entirely.
    A test that wants a value sets it in the environment, where get_config
    looks first.
    """
    for name in _REMOTE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config_module, "_config_cache", {})
    monkeypatch.setattr(config_module, "_env_loaded", True)
