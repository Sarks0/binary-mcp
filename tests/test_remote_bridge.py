"""Tests for the x64dbg endpoint policy and its wiring into X64DbgBridge.

The counterpart to tests/test_remote_policy.py, which covers the listener. Same
emphasis on refusals: a non-loopback endpoint without the opt-in, without a CA,
or without a token is a connection that must not be attempted, and a policy
that allowed any of the three would pass a happy-path test just as well.

Two things beyond the policy are pinned here because they are the parts that
were wrong before and would be silently wrong again:

  * ``verify`` and ``cert`` actually reach ``requests``. A policy that resolves
    a CA and then does not pass it is a policy that verifies nothing.
  * the local token file is not consulted for a remote endpoint. It reads
    *this* machine's %TEMP%, so for a remote endpoint it answers a question
    nobody asked and reports "ensure the plugin is loaded" for a plugin that is.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import src.utils.config as config_module
from src.engines.dynamic.x64dbg.bridge import X64DbgBridge
from src.utils.remote import (
    DEFAULT_X64DBG_PORT,
    ENV_OBSIDIAN_TOKEN,
    ENV_REMOTE_ALLOW,
    ENV_X64DBG_CLIENT_CERT,
    ENV_X64DBG_CLIENT_KEY,
    ENV_X64DBG_HOST,
    ENV_X64DBG_PORT,
    ENV_X64DBG_TLS_CA,
    DebuggerEndpoint,
    DebuggerEndpointError,
    RemoteConfigError,
    TransportConfigError,
    resolve_debugger_endpoint,
)


@pytest.fixture(autouse=True)
def _no_dotenv(monkeypatch):
    """Resolve from the test's own environment and nothing else.

    The autouse fixture in conftest.py already clears these from os.environ;
    this additionally stops ``get_config`` falling back to a developer's .env.
    """
    monkeypatch.setattr(config_module, "_config_cache", {})
    monkeypatch.setattr(config_module, "_env_loaded", True)


@pytest.fixture
def ca_file(tmp_path):
    """A readable file standing in for the CA that signs the plugin's certificate.

    The policy checks the path resolves to a readable file, not that it parses
    as PEM -- OpenSSL owns that, and a fake keeps these tests free of key
    generation.
    """
    ca = tmp_path / "debugger-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    return ca


@pytest.fixture
def client_pair(tmp_path):
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    return cert, key


def _remote(monkeypatch, ca_file, **overrides):
    """Configure a valid remote endpoint, then apply ``overrides``."""
    env = {
        ENV_X64DBG_HOST: "192.168.1.50",
        ENV_REMOTE_ALLOW: "1",
        ENV_X64DBG_TLS_CA: str(ca_file),
        ENV_OBSIDIAN_TOKEN: "b" * 64,
    }
    env.update(overrides)
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


# Loopback: the default, and the tunnel case


class TestLoopbackEndpoint:
    def test_defaults(self):
        endpoint = resolve_debugger_endpoint()
        assert endpoint.host == "127.0.0.1"
        assert endpoint.port == DEFAULT_X64DBG_PORT
        assert endpoint.base_url == "http://127.0.0.1:8765"
        assert endpoint.is_loopback

    def test_needs_no_opt_in_no_ca_and_no_token(self):
        """The tunnel case must stay frictionless: it is the recommended setup."""
        endpoint = resolve_debugger_endpoint()
        assert endpoint.tls_enabled is False
        assert endpoint.requests_kwargs() == {}
        assert endpoint.token_must_come_from_env is False

    def test_env_host_and_port_are_honoured(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_HOST, "localhost")
        monkeypatch.setenv(ENV_X64DBG_PORT, "9001")
        endpoint = resolve_debugger_endpoint()
        assert endpoint.base_url == "http://localhost:9001"

    def test_explicit_arguments_beat_the_environment(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_HOST, "localhost")
        monkeypatch.setenv(ENV_X64DBG_PORT, "9001")
        endpoint = resolve_debugger_endpoint(host="127.0.0.1", port=8765)
        assert endpoint.base_url == "http://127.0.0.1:8765"

    def test_whole_loopback_range_counts(self):
        assert resolve_debugger_endpoint(host="127.0.0.2").is_loopback

    def test_ipv6_loopback_gets_bracketed(self):
        """``f"http://{host}:{port}"`` with ``::1`` produced http://::1:8765.

        The bridge accepted ``::1`` as a loopback spelling and then built a URL
        that is not a URL, so that combination never worked.
        """
        assert resolve_debugger_endpoint(host="::1").base_url == "http://[::1]:8765"

    def test_blank_host_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_HOST, "   ")
        assert resolve_debugger_endpoint().host == "127.0.0.1"

    def test_loopback_may_still_use_tls(self, ca_file, monkeypatch):
        """A local TLS terminator is a legitimate endpoint, not a misconfiguration."""
        monkeypatch.setenv(ENV_X64DBG_TLS_CA, str(ca_file))
        endpoint = resolve_debugger_endpoint()
        assert endpoint.base_url == "https://127.0.0.1:8765"
        assert endpoint.requests_kwargs() == {"verify": str(ca_file.resolve())}


class TestPortParsing:
    @pytest.mark.parametrize("value", ["not-a-port", "80.5"])
    def test_unparseable(self, monkeypatch, value):
        monkeypatch.setenv(ENV_X64DBG_PORT, value)
        with pytest.raises(DebuggerEndpointError, match="not an integer"):
            resolve_debugger_endpoint()

    @pytest.mark.parametrize("value", ["0", "65536", "-1"])
    def test_out_of_range(self, monkeypatch, value):
        monkeypatch.setenv(ENV_X64DBG_PORT, value)
        with pytest.raises(DebuggerEndpointError, match="outside 1-65535"):
            resolve_debugger_endpoint()

    def test_empty_falls_back_to_the_default(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_PORT, "")
        assert resolve_debugger_endpoint().port == DEFAULT_X64DBG_PORT


class TestWildcardIsNotADestination:
    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "*"])
    def test_refused(self, host):
        with pytest.raises(DebuggerEndpointError, match="not a destination"):
            resolve_debugger_endpoint(host=host)

    @pytest.mark.parametrize("host", ["0.0.0.0", "::"])
    def test_refused_even_with_the_opt_in(self, monkeypatch, ca_file, host):
        _remote(monkeypatch, ca_file, **{ENV_X64DBG_HOST: host})
        with pytest.raises(DebuggerEndpointError, match="not a destination"):
            resolve_debugger_endpoint()


# The refusals that matter


class TestNonLoopbackRequiresAllThree:
    def test_refused_without_the_opt_in(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_REMOTE_ALLOW: None})
        with pytest.raises(DebuggerEndpointError, match=ENV_REMOTE_ALLOW):
            resolve_debugger_endpoint()

    def test_opt_in_must_be_truthy(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_REMOTE_ALLOW: "0"})
        with pytest.raises(DebuggerEndpointError, match=ENV_REMOTE_ALLOW):
            resolve_debugger_endpoint()

    def test_the_refusal_points_at_the_tunnel(self, monkeypatch, ca_file):
        """The simpler answer has to be in the message, or nobody finds it."""
        _remote(monkeypatch, ca_file, **{ENV_REMOTE_ALLOW: None})
        with pytest.raises(DebuggerEndpointError, match="tunnel"):
            resolve_debugger_endpoint()

    def test_refused_without_a_ca(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_X64DBG_TLS_CA: None})
        with pytest.raises(DebuggerEndpointError, match=ENV_X64DBG_TLS_CA):
            resolve_debugger_endpoint()

    def test_the_ca_refusal_says_where_the_far_end_gets_tls(self, monkeypatch, ca_file):
        """The message has to name the other half of the setup.

        It used to say obsidian_server.exe could not serve TLS and something
        else had to terminate it. The same branch gave the listener Schannel,
        so that sent operators off to install stunnel for no reason.
        """
        _remote(monkeypatch, ca_file, **{ENV_X64DBG_TLS_CA: None})
        with pytest.raises(DebuggerEndpointError) as exc:
            resolve_debugger_endpoint()
        message = str(exc.value)
        assert "tls_cert_thumbprint" in message, (
            "the refusal does not say how to give the far end a certificate"
        )
        assert "does not serve TLS" not in message

    def test_refused_without_a_token(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_OBSIDIAN_TOKEN: None})
        with pytest.raises(DebuggerEndpointError, match=ENV_OBSIDIAN_TOKEN):
            resolve_debugger_endpoint()

    def test_blank_token_is_not_a_token(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_OBSIDIAN_TOKEN: "   "})
        with pytest.raises(DebuggerEndpointError, match=ENV_OBSIDIAN_TOKEN):
            resolve_debugger_endpoint()

    def test_accepted_with_all_three(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file)
        endpoint = resolve_debugger_endpoint()
        assert endpoint.base_url == "https://192.168.1.50:8765"
        assert endpoint.is_loopback is False
        assert endpoint.tls_enabled
        assert endpoint.token_must_come_from_env is True

    def test_plaintext_remote_is_not_reachable_by_any_configuration(
        self, monkeypatch, ca_file
    ):
        """There is no combination that yields http:// to a non-loopback host."""
        _remote(monkeypatch, ca_file, **{ENV_X64DBG_TLS_CA: None})
        with pytest.raises(DebuggerEndpointError):
            resolve_debugger_endpoint()
        _remote(monkeypatch, ca_file)
        assert resolve_debugger_endpoint().scheme == "https"


class TestClientCertificate:
    def test_cert_without_key(self, monkeypatch, ca_file, client_pair):
        cert, _ = client_pair
        monkeypatch.setenv(ENV_X64DBG_TLS_CA, str(ca_file))
        monkeypatch.setenv(ENV_X64DBG_CLIENT_CERT, str(cert))
        with pytest.raises(DebuggerEndpointError, match=ENV_X64DBG_CLIENT_KEY):
            resolve_debugger_endpoint()

    def test_key_without_cert(self, monkeypatch, ca_file, client_pair):
        _, key = client_pair
        monkeypatch.setenv(ENV_X64DBG_TLS_CA, str(ca_file))
        monkeypatch.setenv(ENV_X64DBG_CLIENT_KEY, str(key))
        with pytest.raises(DebuggerEndpointError, match=ENV_X64DBG_CLIENT_CERT):
            resolve_debugger_endpoint()

    def test_cert_without_a_ca_is_refused(self, monkeypatch, client_pair):
        """Presenting a client certificate over plaintext HTTP is not a thing."""
        cert, key = client_pair
        monkeypatch.setenv(ENV_X64DBG_CLIENT_CERT, str(cert))
        monkeypatch.setenv(ENV_X64DBG_CLIENT_KEY, str(key))
        with pytest.raises(DebuggerEndpointError, match="plaintext"):
            resolve_debugger_endpoint()

    def test_mutual_tls_reaches_requests(self, monkeypatch, ca_file, client_pair):
        cert, key = client_pair
        _remote(monkeypatch, ca_file, **{
            ENV_X64DBG_CLIENT_CERT: str(cert),
            ENV_X64DBG_CLIENT_KEY: str(key),
        })
        endpoint = resolve_debugger_endpoint()
        assert endpoint.mutual_tls
        assert endpoint.requests_kwargs() == {
            "verify": str(ca_file.resolve()),
            "cert": (str(cert.resolve()), str(key.resolve())),
        }

    def test_missing_ca_file_is_caught_at_resolution(self, monkeypatch, tmp_path):
        monkeypatch.setenv(ENV_X64DBG_TLS_CA, str(tmp_path / "absent.pem"))
        with pytest.raises(DebuggerEndpointError, match="does not point at a file"):
            resolve_debugger_endpoint()


class TestEndpointInvariants:
    """The dataclass holds its own shape, whoever builds it."""

    def test_client_cert_without_key(self, tmp_path):
        with pytest.raises(DebuggerEndpointError, match="both client_cert and client_key"):
            DebuggerEndpoint(tls_ca=tmp_path / "ca.pem", client_cert=tmp_path / "c.pem")

    def test_client_cert_without_ca(self, tmp_path):
        with pytest.raises(DebuggerEndpointError, match="no tls_ca"):
            DebuggerEndpoint(
                client_cert=tmp_path / "c.pem", client_key=tmp_path / "k.pem"
            )

    def test_bare_endpoint_is_fine(self):
        assert DebuggerEndpoint().base_url == "http://127.0.0.1:8765"


class TestDescribe:
    def test_names_tls_off(self):
        assert "tls=OFF" in resolve_debugger_endpoint().describe()

    def test_names_remote(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file)
        described = resolve_debugger_endpoint().describe()
        assert "REMOTE" in described
        assert "tls=server" in described

    def test_never_prints_the_token(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file, **{ENV_OBSIDIAN_TOKEN: "s3cret-token-value"})
        assert "s3cret" not in resolve_debugger_endpoint().describe()


class TestExceptionHierarchy:
    """One base, so a caller may handle either direction without naming both."""

    def test_both_are_remote_config_errors(self):
        assert issubclass(DebuggerEndpointError, RemoteConfigError)
        assert issubclass(TransportConfigError, RemoteConfigError)

    def test_they_are_distinguishable(self):
        assert not issubclass(DebuggerEndpointError, TransportConfigError)
        assert not issubclass(TransportConfigError, DebuggerEndpointError)


# The bridge


class TestBridgeUsesThePolicy:
    def test_default_construction_is_unchanged(self):
        bridge = X64DbgBridge()
        assert bridge.base_url == "http://127.0.0.1:8765"
        assert bridge._request_kwargs == {}

    def test_host_argument_is_no_longer_inert(self, monkeypatch, ca_file):
        """x64dbg_connect has always plumbed a host here; it could not be used.

        The old constructor compared it against three loopback spellings and
        raised on anything else, so the argument existed and was unusable.
        """
        _remote(monkeypatch, ca_file, **{ENV_X64DBG_HOST: None})
        bridge = X64DbgBridge(host="192.168.1.50")
        assert bridge.base_url == "https://192.168.1.50:8765"

    def test_remote_host_without_the_opt_in_is_refused(self):
        with pytest.raises(DebuggerEndpointError, match=ENV_REMOTE_ALLOW):
            X64DbgBridge(host="192.168.1.50")

    def test_configured_endpoint_is_used_when_nothing_is_passed(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_HOST, "localhost")
        monkeypatch.setenv(ENV_X64DBG_PORT, "9999")
        assert X64DbgBridge().base_url == "http://localhost:9999"

    def test_tls_material_is_resolved_once_onto_the_bridge(
        self, monkeypatch, ca_file, client_pair
    ):
        cert, key = client_pair
        _remote(monkeypatch, ca_file, **{
            ENV_X64DBG_CLIENT_CERT: str(cert),
            ENV_X64DBG_CLIENT_KEY: str(key),
        })
        bridge = X64DbgBridge()
        assert bridge._request_kwargs == {
            "verify": str(ca_file.resolve()),
            "cert": (str(cert.resolve()), str(key.resolve())),
        }


class TestBridgePassesTlsToRequests:
    """A resolved CA that never reaches requests verifies nothing."""

    def _response(self):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"success": True}
        response.raise_for_status.return_value = None
        return response

    def test_verify_and_cert_reach_post(self, monkeypatch, ca_file, client_pair):
        cert, key = client_pair
        _remote(monkeypatch, ca_file, **{
            ENV_X64DBG_CLIENT_CERT: str(cert),
            ENV_X64DBG_CLIENT_KEY: str(key),
        })
        bridge = X64DbgBridge()
        with patch("requests.post", return_value=self._response()) as post:
            bridge._request("/api/status", {"a": 1})
        kwargs = post.call_args.kwargs
        assert kwargs["verify"] == str(ca_file.resolve())
        assert kwargs["cert"] == (str(cert.resolve()), str(key.resolve()))

    def test_verify_reaches_get(self, monkeypatch, ca_file):
        _remote(monkeypatch, ca_file)
        bridge = X64DbgBridge()
        with patch("requests.get", return_value=self._response()) as get:
            bridge._request("/api/status")
        assert get.call_args.kwargs["verify"] == str(ca_file.resolve())

    def test_loopback_call_is_byte_for_byte_what_it_was(self):
        """No verify, no cert: the common path must not change shape."""
        bridge = X64DbgBridge()
        bridge._auth_token = "token"
        with patch("requests.get", return_value=self._response()) as get:
            bridge._request("/api/status")
        kwargs = get.call_args.kwargs
        assert "verify" not in kwargs
        assert "cert" not in kwargs
        assert set(kwargs) == {"headers", "timeout"}


class TestTokenSourcing:
    def test_env_token_is_used(self, monkeypatch):
        monkeypatch.setenv(ENV_OBSIDIAN_TOKEN, "env-token")
        assert X64DbgBridge()._read_auth_token() == "env-token"

    def test_remote_endpoint_never_reads_the_local_token_file(
        self, monkeypatch, ca_file, tmp_path
    ):
        """The file is on the debugger host, so this machine's copy is not it.

        Writing a decoy here is the point: if the fallback ran, the bridge
        would authenticate with the wrong token and the failure would surface
        as a 401 from the plugin rather than as the missing variable.
        """
        _remote(monkeypatch, ca_file)
        bridge = X64DbgBridge()
        monkeypatch.delenv(ENV_OBSIDIAN_TOKEN, raising=False)

        decoy = tmp_path / "x64dbg_mcp_token.txt"
        decoy.write_text("local-host-token")
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        with pytest.raises(RuntimeError) as exc:
            bridge._read_auth_token()
        assert ENV_OBSIDIAN_TOKEN in str(exc.value)
        assert "local-host-token" not in str(exc.value)

    def test_the_remote_error_does_not_blame_the_plugin(
        self, monkeypatch, ca_file
    ):
        """"Ensure the plugin is loaded" sends the operator to the wrong host."""
        _remote(monkeypatch, ca_file)
        bridge = X64DbgBridge()
        monkeypatch.delenv(ENV_OBSIDIAN_TOKEN, raising=False)
        with pytest.raises(RuntimeError) as exc:
            bridge._read_auth_token()
        assert "Ensure x64dbg plugin is loaded" not in str(exc.value)

    def test_loopback_endpoint_still_falls_back_to_the_file(self, monkeypatch, tmp_path):
        token_file = tmp_path / "x64dbg_mcp_token.txt"
        token_file.write_text("file-token\n")
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        assert X64DbgBridge()._read_auth_token() == "file-token"

    def test_loopback_endpoint_reports_a_missing_file_as_before(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))
        with pytest.raises(RuntimeError, match="Authentication token file not found"):
            X64DbgBridge()._read_auth_token()


class TestBlankAndZeroArguments:
    """A blank host is unset; a zero port is wrong. They must not share a path."""

    def test_blank_host_argument_still_reads_the_environment(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_HOST, "localhost")
        assert resolve_debugger_endpoint(host="").host == "localhost"

    def test_blank_host_falls_back_to_the_default_when_unset(self):
        assert resolve_debugger_endpoint(host="   ").host == "127.0.0.1"

    def test_zero_port_is_refused_not_defaulted(self):
        """0 is falsy, so a truthiness check here would silently serve 8765."""
        with pytest.raises(DebuggerEndpointError, match="outside 1-65535"):
            resolve_debugger_endpoint(port=0)

    def test_explicit_port_beats_the_environment(self, monkeypatch):
        monkeypatch.setenv(ENV_X64DBG_PORT, "9001")
        assert resolve_debugger_endpoint(port=8765).port == 8765


class TestTokenShapeIsValidated:
    """A token that cannot be compared, or safely placed in a header, is refused.

    Checked at configuration time rather than per request: a non-ASCII token
    made `hmac.compare_digest` raise on *every* request including the correct
    one, and a token containing CR or LF is a header-injection primitive where
    the bridge builds "Bearer " + token into an outbound header.
    """

    @pytest.mark.parametrize(
        "token",
        # No NUL case: an environment variable cannot hold one, so os.environ
        # refuses it before this policy is reached.
        ["tok en", "tok\nen", "tok\ren", "tok\ten", "tøken", "tok;en", "tok\"en"],
    )
    def test_refused(self, monkeypatch, ca_file, token):
        _remote(monkeypatch, ca_file, **{ENV_OBSIDIAN_TOKEN: token})
        with pytest.raises(DebuggerEndpointError, match="bearer token may not hold"):
            resolve_debugger_endpoint()

    @pytest.mark.parametrize("token", ["b" * 64, "a-b_c.d~e+f/g=", "A1"])
    def test_accepted(self, monkeypatch, ca_file, token):
        _remote(monkeypatch, ca_file, **{ENV_OBSIDIAN_TOKEN: token})
        assert resolve_debugger_endpoint().token_must_come_from_env is True
