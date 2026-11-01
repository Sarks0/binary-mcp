"""Suite-wide test isolation."""

import pytest

import src.utils.config as config_module
from src.integrations import base as integration_base

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

# Everything the threat-intel providers resolve at call time. get_config reads
# os.environ BEFORE the .env cache (src/utils/config.py:211), so clearing the
# cache -- which _no_ambient_remote_config already does -- does not reach a
# developer who has exported these or whose shell or IDE loads .env into the
# environment. On such a machine the credentials were visible to every test.
#
# Two things went wrong because of that, and both are worth naming:
#
#   * the "missing key" tests passed only on a machine with no key. They stub
#     the module-level _get_api_key hook, which only the *_check_api tools
#     consult; mb_lookup and the vt_* lookups resolve through
#     IntegrationClient.require_key(). With a real key present the stub did
#     nothing, the tools performed a LIVE LOOKUP WITH THE REAL KEY, and the
#     assertion failed for a reason that had nothing to do with the code.
#   * MB_ALLOW_DOWNLOAD=1 in the environment would flip the download gate that
#     several tests assert is closed.
#
# A test that wants one of these sets it itself, where get_config looks first.
_PROVIDER_ENV_VARS = (
    "VT_API_KEY",
    "VT_API_TIMEOUT",
    "ABUSECH_API_KEY",
    "ABUSECH_API_TIMEOUT",
    "MB_API_KEY",
    "MB_API_TIMEOUT",
    "MB_ALLOW_DOWNLOAD",
    "MB_MAX_DOWNLOAD_MB",
    "ATTACK_DOMAIN",
    "ATTACK_DATA_DIR",
    "ATTACK_OFFLINE",
    "ATTACK_MAX_BUNDLE_MB",
    "ATTACK_TIMEOUT",
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


@pytest.fixture(autouse=True)
def _no_provider_credentials(monkeypatch):
    """Never let a developer's own API keys reach a test.

    See _PROVIDER_ENV_VARS for what went wrong without this and why clearing
    the .env cache was not enough.
    """
    for name in _PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_provider_network(monkeypatch):
    """Make an un-stubbed provider request a loud test failure, not a request.

    Clearing the credentials above stops a test spending real quota, but it
    only removes the motive. This removes the means, and it is the half that
    keeps working when someone adds a provider or a test that resolves its key
    some other way: there is no path from this suite to a third-party API that
    does not go through this one function.

    It is deliberately an AssertionError rather than a connection error. A
    test that reaches the network has a bug in the test, and the handlers under
    test catch OSError and render it as a tidy "Reference ID" string -- which
    is exactly how this went unnoticed. AssertionError is not caught by any of
    them, so the failure names itself.

    Every test that needs a reply overrides this, which is what
    tests.integration_stubs.capture_requests and raise_http already do.
    """
    def refuse(request, timeout=None):
        raise AssertionError(
            "a test reached the network through the shared provider transport: "
            f"{getattr(request, 'full_url', request)}. Stub it with "
            "tests.integration_stubs.capture_requests or raise_http."
        )

    monkeypatch.setattr(integration_base, "urlopen", refuse)
