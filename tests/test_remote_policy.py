"""Tests for the MCP transport policy and the HTTP gate.

Two things are pinned here.

The policy (:func:`resolve_transport_config`) is tested for what it *refuses*,
because every refusal is a listener that does not come up wrong: a wildcard
bind, a LAN bind without the opt-in, a LAN bind without TLS, a LAN bind with a
token that would change on restart. A test that only checked the happy path
would pass just as well against a policy that permitted all four.

The gate (:class:`RemoteAccessGate`) is plain ASGI, so it is exercised by
calling it with scope dicts rather than through a server. That is deliberate:
``src/server.py`` cannot be imported without a Ghidra installation, so a test
that needed the real app could not run in CI.
"""

from __future__ import annotations

import ipaddress
import ssl

import pytest

import src.utils.config as config_module
import src.utils.remote as remote_module
from src.utils.remote import (
    DEFAULT_HTTP_PATH,
    DEFAULT_HTTP_PORT,
    ENV_CLIENT_ALLOWLIST,
    ENV_HTTP_ALLOWED_HOSTS,
    ENV_HTTP_HOST,
    ENV_HTTP_PATH,
    ENV_HTTP_PORT,
    ENV_HTTP_TOKEN,
    ENV_REMOTE_ALLOW,
    ENV_TLS_CA,
    ENV_TLS_CERT,
    ENV_TLS_KEY,
    ENV_TRANSPORT,
    RemoteAccessGate,
    TransportConfig,
    TransportConfigError,
    is_loopback_host,
    is_wildcard_host,
    resolve_transport_config,
    strip_host_port,
    strip_origin,
)

ALL_ENV = (
    ENV_TRANSPORT,
    ENV_HTTP_HOST,
    ENV_HTTP_PORT,
    ENV_HTTP_PATH,
    ENV_HTTP_TOKEN,
    ENV_HTTP_ALLOWED_HOSTS,
    ENV_REMOTE_ALLOW,
    ENV_TLS_CERT,
    ENV_TLS_KEY,
    ENV_TLS_CA,
    ENV_CLIENT_ALLOWLIST,
)


@pytest.fixture(autouse=True)
def _clean_transport_env(monkeypatch):
    """Resolve from the test's own environment and nothing else.

    ``get_config`` falls back to a cached ``.env`` file, so a developer's local
    .env could otherwise decide the outcome of these tests. Marking the cache
    loaded and empty removes that input entirely.
    """
    for name in ALL_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(config_module, "_config_cache", {})
    monkeypatch.setattr(config_module, "_env_loaded", True)


@pytest.fixture
def tls_pair(tmp_path):
    """Two readable files standing in for a certificate and key.

    The policy checks that the paths resolve to readable files, not that they
    parse as PEM -- uvicorn and OpenSSL own that, and a fake pair keeps these
    tests free of key generation.
    """
    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\n")
    key.write_text("-----BEGIN PRIVATE KEY-----\n")
    return cert, key


def _remote(monkeypatch, tls_pair, **overrides):
    """Configure a valid non-loopback listener, then apply ``overrides``."""
    cert, key = tls_pair
    env = {
        ENV_TRANSPORT: "http",
        ENV_HTTP_HOST: "192.168.1.50",
        ENV_REMOTE_ALLOW: "1",
        ENV_TLS_CERT: str(cert),
        ENV_TLS_KEY: str(key),
        ENV_HTTP_TOKEN: "a" * 64,
    }
    env.update(overrides)
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


# ---------------------------------------------------------------------------
# Host classification
# ---------------------------------------------------------------------------


class TestHostClassification:
    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "localhost", "LOCALHOST", "::1", "[::1]", "127.0.0.2", " 127.0.0.1 "],
    )
    def test_loopback_spellings(self, host):
        assert is_loopback_host(host)

    @pytest.mark.parametrize("host", ["192.168.1.50", "0.0.0.0", "example.test", "10.0.0.1"])
    def test_non_loopback(self, host):
        assert not is_loopback_host(host)

    def test_whole_loopback_range_counts(self):
        """127.0.0.2 is loopback. An equality check against 127.0.0.1 would miss it."""
        assert is_loopback_host("127.0.0.2")
        assert is_loopback_host("127.255.255.254")

    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "[::]", "*", "", "   "])
    def test_wildcard_spellings(self, host):
        assert is_wildcard_host(host)

    @pytest.mark.parametrize("host", ["127.0.0.1", "192.168.1.50", "localhost"])
    def test_not_wildcard(self, host):
        assert not is_wildcard_host(host)


class TestHeaderHostParsing:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("127.0.0.1:8770", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.1"),
            ("[::1]:8770", "::1"),
            ("[::1]", "::1"),
            ("Example.Test:8770", "example.test"),
            ("example.test", "example.test"),
        ],
    )
    def test_strip_host_port(self, value, expected):
        assert strip_host_port(value) == expected

    def test_bare_ipv6_is_not_split_on_its_own_colons(self):
        """Splitting '::1' on ':' would leave an empty host and refuse a valid request."""
        assert strip_host_port("::1") == "::1"
        assert strip_host_port("fe80::1") == "fe80::1"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("https://example.test:8770", "example.test"),
            ("http://127.0.0.1:8770", "127.0.0.1"),
            ("https://[::1]:8770", "::1"),
            ("null", "null"),
        ],
    )
    def test_strip_origin(self, value, expected):
        assert strip_origin(value) == expected


# ---------------------------------------------------------------------------
# Policy: stdio
# ---------------------------------------------------------------------------


class TestStdioDefault:
    def test_nothing_configured_is_stdio(self):
        config = resolve_transport_config()
        assert config.transport == "stdio"
        assert not config.is_http

    @pytest.mark.parametrize("value", ["stdio", "STDIO", " stdio ", ""])
    def test_explicit_stdio(self, monkeypatch, value):
        monkeypatch.setenv(ENV_TRANSPORT, value)
        assert resolve_transport_config().transport == "stdio"

    def test_stdio_carries_no_token(self, monkeypatch):
        """A transport with no listener must not mint a credential."""
        monkeypatch.setenv(ENV_TRANSPORT, "stdio")
        config = resolve_transport_config()
        assert config.token == ""
        assert config.token_was_generated is False

    def test_stdio_ignores_a_listener_misconfiguration(self, monkeypatch):
        """A stale HTTP setting must not stop a stdio server starting."""
        monkeypatch.setenv(ENV_TRANSPORT, "stdio")
        monkeypatch.setenv(ENV_HTTP_HOST, "0.0.0.0")
        monkeypatch.setenv(ENV_HTTP_PORT, "not-a-port")
        assert resolve_transport_config().transport == "stdio"

    def test_unknown_transport_is_refused(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "sse")
        with pytest.raises(TransportConfigError, match="not a transport"):
            resolve_transport_config()


# ---------------------------------------------------------------------------
# Policy: loopback HTTP
# ---------------------------------------------------------------------------


class TestLoopbackHttp:
    def test_defaults(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        config = resolve_transport_config()
        assert config.is_http
        assert config.host == "127.0.0.1"
        assert config.port == DEFAULT_HTTP_PORT
        assert config.path == DEFAULT_HTTP_PATH
        assert config.is_loopback

    def test_streamable_http_is_accepted_as_http(self, monkeypatch):
        """The MCP spec's name for the transport must not be a refusal."""
        monkeypatch.setenv(ENV_TRANSPORT, "streamable-http")
        assert resolve_transport_config().transport == "http"

    def test_token_is_generated_when_unset(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        config = resolve_transport_config()
        assert config.token_was_generated is True
        assert len(config.token) == 64
        int(config.token, 16)  # hex

    def test_generated_tokens_differ_between_starts(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        assert resolve_transport_config().token != resolve_transport_config().token

    def test_configured_token_is_kept(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_TOKEN, "configured-token")
        config = resolve_transport_config()
        assert config.token == "configured-token"
        assert config.token_was_generated is False

    def test_loopback_needs_no_opt_in_and_no_tls(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        config = resolve_transport_config()
        assert config.tls_enabled is False
        assert config.uvicorn_config() == {}

    def test_loopback_accepts_every_loopback_host_header(self, monkeypatch):
        """A client may dial localhost, 127.0.0.1 or ::1 and reach the same listener."""
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        allowed = resolve_transport_config().allowed_hosts
        assert {"localhost", "127.0.0.1", "::1"} <= allowed

    def test_extra_allowed_hosts_are_added(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_ALLOWED_HOSTS, "analyst.lan, Box.Local ,")
        allowed = resolve_transport_config().allowed_hosts
        assert "analyst.lan" in allowed
        assert "box.local" in allowed


class TestPortAndPath:
    @pytest.mark.parametrize("value", ["not-a-port", "80.5", ""])
    def test_unparseable_port(self, monkeypatch, value):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_PORT, value)
        if value == "":
            # Empty falls back to the default rather than failing.
            assert resolve_transport_config().port == DEFAULT_HTTP_PORT
        else:
            with pytest.raises(TransportConfigError, match="not an integer"):
                resolve_transport_config()

    @pytest.mark.parametrize("value", ["0", "65536", "-1"])
    def test_out_of_range_port(self, monkeypatch, value):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_PORT, value)
        with pytest.raises(TransportConfigError, match="outside 1-65535"):
            resolve_transport_config()

    def test_path_must_be_absolute(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_PATH, "mcp")
        with pytest.raises(TransportConfigError, match="must start with"):
            resolve_transport_config()


# ---------------------------------------------------------------------------
# Policy: the refusals that matter
# ---------------------------------------------------------------------------


class TestWildcardBindIsAlwaysRefused:
    @pytest.mark.parametrize("host", ["0.0.0.0", "::", "*"])
    def test_refused_without_opt_in(self, monkeypatch, host):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_HOST, host)
        with pytest.raises(TransportConfigError, match="binds every interface"):
            resolve_transport_config()

    @pytest.mark.parametrize("host", ["0.0.0.0", "::"])
    def test_refused_even_with_opt_in_and_tls(self, monkeypatch, tls_pair, host):
        """The opt-in says 'reachable from the LAN', not 'reachable from everywhere'.

        A wildcard bind is the one setting an operator can reach by typo and
        never notice, so it has no escape hatch.
        """
        _remote(monkeypatch, tls_pair, **{ENV_HTTP_HOST: host})
        with pytest.raises(TransportConfigError, match="binds every interface"):
            resolve_transport_config()


class TestNonLoopbackRequiresAllThree:
    def test_refused_without_the_opt_in(self, monkeypatch, tls_pair):
        _remote(monkeypatch, tls_pair, **{ENV_REMOTE_ALLOW: None})
        with pytest.raises(TransportConfigError, match=ENV_REMOTE_ALLOW):
            resolve_transport_config()

    def test_opt_in_must_be_truthy(self, monkeypatch, tls_pair):
        _remote(monkeypatch, tls_pair, **{ENV_REMOTE_ALLOW: "0"})
        with pytest.raises(TransportConfigError, match=ENV_REMOTE_ALLOW):
            resolve_transport_config()

    def test_refused_without_tls(self, monkeypatch, tls_pair):
        _remote(monkeypatch, tls_pair, **{ENV_TLS_CERT: None, ENV_TLS_KEY: None})
        with pytest.raises(TransportConfigError, match="TLS is required"):
            resolve_transport_config()

    def test_refused_without_an_explicit_token(self, monkeypatch, tls_pair):
        """A generated token would change on restart and break the far client."""
        _remote(monkeypatch, tls_pair, **{ENV_HTTP_TOKEN: None})
        with pytest.raises(TransportConfigError, match=ENV_HTTP_TOKEN):
            resolve_transport_config()

    def test_never_generates_a_token_for_a_remote_bind(self, monkeypatch, tls_pair):
        _remote(monkeypatch, tls_pair, **{ENV_HTTP_TOKEN: None})
        with pytest.raises(TransportConfigError):
            resolve_transport_config()

    def test_accepted_with_all_three(self, monkeypatch, tls_pair):
        _remote(monkeypatch, tls_pair)
        config = resolve_transport_config()
        assert config.host == "192.168.1.50"
        assert config.tls_enabled
        assert config.token_was_generated is False
        assert config.is_loopback is False

    def test_remote_host_header_set_excludes_loopback(self, monkeypatch, tls_pair):
        """A listener bound to the LAN address is not reached as 'localhost'."""
        _remote(monkeypatch, tls_pair)
        allowed = resolve_transport_config().allowed_hosts
        assert allowed == {"192.168.1.50"}


class TestTlsMaterial:
    def test_key_without_cert(self, monkeypatch, tls_pair):
        _, key = tls_pair
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_TLS_KEY, str(key))
        with pytest.raises(TransportConfigError, match=ENV_TLS_CERT):
            resolve_transport_config()

    def test_cert_without_key(self, monkeypatch, tls_pair):
        cert, _ = tls_pair
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_TLS_CERT, str(cert))
        with pytest.raises(TransportConfigError, match=ENV_TLS_KEY):
            resolve_transport_config()

    def test_ca_without_cert(self, monkeypatch, tls_pair):
        """A CA path with no TLS verifies nothing; say so rather than ignoring it."""
        cert, _ = tls_pair
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_TLS_CA, str(cert))
        with pytest.raises(TransportConfigError, match="no TLS to verify within"):
            resolve_transport_config()

    def test_missing_cert_file_is_caught_at_startup(self, monkeypatch, tmp_path):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_TLS_CERT, str(tmp_path / "absent.crt"))
        monkeypatch.setenv(ENV_TLS_KEY, str(tmp_path / "absent.key"))
        with pytest.raises(TransportConfigError, match="does not point at a file"):
            resolve_transport_config()

    def test_directory_is_not_a_cert(self, monkeypatch, tmp_path):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_TLS_CERT, str(tmp_path))
        monkeypatch.setenv(ENV_TLS_KEY, str(tmp_path))
        with pytest.raises(TransportConfigError, match="does not point at a file"):
            resolve_transport_config()


class TestUvicornConfig:
    def test_no_tls_passes_nothing(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        assert resolve_transport_config().uvicorn_config() == {}

    def test_server_tls(self, monkeypatch, tls_pair):
        cert, key = tls_pair
        _remote(monkeypatch, tls_pair)
        uvicorn = resolve_transport_config().uvicorn_config()
        assert uvicorn["ssl_certfile"] == str(cert.resolve())
        assert uvicorn["ssl_keyfile"] == str(key.resolve())
        assert "ssl_cert_reqs" not in uvicorn

    def test_ca_turns_on_mutual_tls(self, monkeypatch, tls_pair, tmp_path):
        """ssl_ca_certs alone only offers to check a client cert; CERT_REQUIRED demands one."""
        ca = tmp_path / "ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\n")
        _remote(monkeypatch, tls_pair, **{ENV_TLS_CA: str(ca)})
        config = resolve_transport_config()
        assert config.mutual_tls
        uvicorn = config.uvicorn_config()
        assert uvicorn["ssl_ca_certs"] == str(ca.resolve())
        assert uvicorn["ssl_cert_reqs"] == ssl.CERT_REQUIRED


class TestClientAllowlistParsing:
    def test_bare_address_becomes_a_single_host_network(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_CLIENT_ALLOWLIST, "10.0.0.7")
        networks = resolve_transport_config().client_allowlist
        assert ipaddress.ip_address("10.0.0.7") in networks[0]
        assert ipaddress.ip_address("10.0.0.8") not in networks[0]

    def test_cidr_and_whitespace(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_CLIENT_ALLOWLIST, " 10.0.0.0/24 , 192.168.1.5 ,")
        assert len(resolve_transport_config().client_allowlist) == 2

    def test_unparseable_entry_is_refused(self, monkeypatch):
        """Silently dropping a malformed entry would widen the allowlist."""
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_CLIENT_ALLOWLIST, "10.0.0.0/24, not-an-address")
        with pytest.raises(TransportConfigError, match="not an address or CIDR"):
            resolve_transport_config()


class TestDescribe:
    def test_names_tls_off(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        assert "tls=OFF" in resolve_transport_config().describe()

    def test_names_mutual_tls(self, monkeypatch, tls_pair, tmp_path):
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        _remote(monkeypatch, tls_pair, **{ENV_TLS_CA: str(ca)})
        assert "tls=mutual" in resolve_transport_config().describe()

    def test_never_prints_the_token(self, monkeypatch):
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_TOKEN, "s3cret-token-value")
        assert "s3cret-token-value" not in resolve_transport_config().describe()

    def test_stdio_says_no_listener(self):
        assert "no listener" in resolve_transport_config().describe()


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

TOKEN = "f" * 64


def _config(**overrides) -> TransportConfig:
    base = {
        "transport": "http",
        "host": "127.0.0.1",
        "port": DEFAULT_HTTP_PORT,
        "path": DEFAULT_HTTP_PATH,
        "token": TOKEN,
        "allowed_hosts": frozenset({"127.0.0.1", "localhost", "::1"}),
    }
    base.update(overrides)
    return TransportConfig(**base)


class _Recorder:
    """Collects ASGI messages and records whether the inner app was reached."""

    def __init__(self):
        self.messages: list[dict] = []
        self.inner_called = False

    async def send(self, message):
        self.messages.append(message)

    async def app(self, scope, receive, send):
        self.inner_called = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    async def receive(self):
        return {"type": "http.request", "body": b"", "more_body": False}

    @property
    def status(self) -> int | None:
        for message in self.messages:
            if message["type"] == "http.response.start":
                return message["status"]
        return None

    @property
    def body(self) -> bytes:
        return b"".join(
            m.get("body", b"") for m in self.messages if m["type"] == "http.response.body"
        )

    def header(self, name: bytes) -> bytes | None:
        for message in self.messages:
            if message["type"] == "http.response.start":
                for key, value in message["headers"]:
                    if key == name:
                        return value
        return None


def _scope(headers=None, client=("127.0.0.1", 50000), scope_type="http"):
    return {
        "type": scope_type,
        "method": "POST",
        "path": DEFAULT_HTTP_PATH,
        "headers": list(headers or []),
        "client": client,
    }


def _authed(extra=()):
    return [(b"host", b"127.0.0.1:8770"),
            (b"authorization", f"Bearer {TOKEN}".encode()),
            *extra]


async def _call(config, scope):
    recorder = _Recorder()
    gate = RemoteAccessGate(recorder.app, config=config)
    await gate(scope, recorder.receive, recorder.send)
    return recorder


class TestGateScopeTypes:
    async def test_lifespan_passes_through(self):
        """Gating lifespan would stop the app ever starting."""
        recorder = await _call(_config(), {"type": "lifespan"})
        assert recorder.inner_called

    async def test_websocket_is_closed(self):
        recorder = await _call(_config(), _scope(scope_type="websocket"))
        assert not recorder.inner_called
        assert recorder.messages == [{"type": "websocket.close", "code": 1008}]

    async def test_unknown_scope_is_dropped(self):
        recorder = await _call(_config(), {"type": "something-else"})
        assert not recorder.inner_called
        assert recorder.messages == []


class TestGateAuthentication:
    async def test_valid_token_reaches_the_app(self):
        recorder = await _call(_config(), _scope(_authed()))
        assert recorder.inner_called
        assert recorder.status == 200

    async def test_missing_authorization(self):
        recorder = await _call(_config(), _scope([(b"host", b"127.0.0.1")]))
        assert not recorder.inner_called
        assert recorder.status == 401
        assert recorder.header(b"www-authenticate") == b"Bearer"

    async def test_wrong_token(self):
        recorder = await _call(
            _config(), _scope([(b"host", b"127.0.0.1"), (b"authorization", b"Bearer " + b"a" * 64)])
        )
        assert not recorder.inner_called
        assert recorder.status == 401

    async def test_token_prefix_is_not_enough(self):
        """A truncated token must fail; compare_digest is not a prefix match."""
        recorder = await _call(
            _config(),
            _scope([(b"host", b"127.0.0.1"), (b"authorization", f"Bearer {TOKEN[:32]}".encode())]),
        )
        assert recorder.status == 401

    @pytest.mark.parametrize(
        "value",
        [b"", b"Bearer", b"Bearer ", b"Basic " + b"f" * 64, b"Token " + b"f" * 64, b"f" * 64],
    )
    async def test_malformed_authorization(self, value):
        recorder = await _call(
            _config(), _scope([(b"host", b"127.0.0.1"), (b"authorization", value)])
        )
        assert not recorder.inner_called
        assert recorder.status == 401

    async def test_scheme_is_case_insensitive(self):
        """RFC 9110 makes the scheme name case-insensitive; refusing 'bearer' is a false positive."""
        recorder = await _call(
            _config(),
            _scope([(b"host", b"127.0.0.1"), (b"authorization", f"bearer {TOKEN}".encode())]),
        )
        assert recorder.inner_called

    async def test_denial_body_does_not_echo_the_request(self):
        recorder = await _call(
            _config(),
            _scope([(b"host", b"127.0.0.1"), (b"authorization", b"Bearer guessed-token-value")]),
        )
        assert b"guessed-token-value" not in recorder.body
        assert TOKEN.encode() not in recorder.body


class TestGateHostAndOrigin:
    async def test_host_with_port_is_accepted(self):
        recorder = await _call(_config(), _scope(_authed()))
        assert recorder.inner_called

    async def test_bracketed_ipv6_host_is_accepted(self):
        recorder = await _call(
            _config(),
            _scope([(b"host", b"[::1]:8770"), (b"authorization", f"Bearer {TOKEN}".encode())]),
        )
        assert recorder.inner_called

    async def test_unknown_host_is_refused(self):
        """The DNS-rebinding control: a name that resolves here is not a licence to drive it."""
        recorder = await _call(
            _config(),
            _scope([(b"host", b"evil.test"), (b"authorization", f"Bearer {TOKEN}".encode())]),
        )
        assert not recorder.inner_called
        assert recorder.status == 400

    async def test_host_is_checked_before_the_token(self):
        """A rebinding attempt is refused without the token ever being compared."""
        recorder = await _call(_config(), _scope([(b"host", b"evil.test")]))
        assert recorder.status == 400

    async def test_absent_host_header_is_allowed(self):
        """HTTP/2 clients may send :authority instead; the token still gates the request."""
        recorder = await _call(
            _config(), _scope([(b"authorization", f"Bearer {TOKEN}".encode())])
        )
        assert recorder.inner_called

    async def test_matching_origin_is_allowed(self):
        recorder = await _call(
            _config(), _scope(_authed([(b"origin", b"http://127.0.0.1:8770")]))
        )
        assert recorder.inner_called

    async def test_foreign_origin_is_refused(self):
        recorder = await _call(
            _config(), _scope(_authed([(b"origin", b"https://evil.test")]))
        )
        assert not recorder.inner_called
        assert recorder.status == 400

    async def test_no_cors_headers_are_ever_added(self):
        """An Access-Control-Allow-Origin here would undo the Origin check."""
        recorder = await _call(_config(), _scope(_authed()))
        assert recorder.header(b"access-control-allow-origin") is None

    async def test_extra_allowed_host_is_honoured(self):
        config = _config(
            host="192.168.1.50", allowed_hosts=frozenset({"192.168.1.50", "analyst.lan"})
        )
        recorder = await _call(
            config,
            _scope([(b"host", b"analyst.lan:8770"), (b"authorization", f"Bearer {TOKEN}".encode())]),
        )
        assert recorder.inner_called


class TestGateClientAllowlist:
    def _config_with_allowlist(self, entries="10.0.0.0/24"):
        return _config(
            client_allowlist=tuple(
                ipaddress.ip_network(e.strip()) for e in entries.split(",")
            )
        )

    async def test_allowed_client_passes(self):
        recorder = await _call(
            self._config_with_allowlist(), _scope(_authed(), client=("10.0.0.7", 1234))
        )
        assert recorder.inner_called

    async def test_denied_client_is_refused(self):
        recorder = await _call(
            self._config_with_allowlist(), _scope(_authed(), client=("10.9.9.9", 1234))
        )
        assert not recorder.inner_called
        assert recorder.status == 403

    async def test_address_is_checked_before_the_token(self):
        """A client outside the allowlist never gets to present a credential."""
        recorder = await _call(
            self._config_with_allowlist(), _scope([], client=("10.9.9.9", 1234))
        )
        assert recorder.status == 403

    async def test_ipv4_mapped_client_matches_an_ipv4_entry(self):
        """A dual-stack socket reports an IPv4 peer as ::ffff:a.b.c.d."""
        recorder = await _call(
            self._config_with_allowlist(), _scope(_authed(), client=("::ffff:10.0.0.7", 1234))
        )
        assert recorder.inner_called

    async def test_missing_client_address_is_refused(self):
        """An allowlist that cannot be evaluated must not be treated as satisfied."""
        recorder = await _call(
            self._config_with_allowlist(), _scope(_authed(), client=None)
        )
        assert not recorder.inner_called
        assert recorder.status == 403

    async def test_unparseable_client_address_is_refused(self):
        recorder = await _call(
            self._config_with_allowlist(), _scope(_authed(), client=("not-an-ip", 1234))
        )
        assert recorder.status == 403

    async def test_no_allowlist_means_any_address_may_authenticate(self):
        recorder = await _call(_config(), _scope(_authed(), client=("10.9.9.9", 1234)))
        assert recorder.inner_called


class TestGateDuplicateHeaders:
    """A duplicate header the gate decides on is refused, not resolved.

    Picking the first value while something downstream picks the last is how a
    gate gets talked past. HTTP/1.1 permits one Host, so a second is malformed
    input rather than a case with a correct winner.
    """

    async def test_two_host_headers(self):
        recorder = await _call(
            _config(),
            _scope([
                (b"host", b"127.0.0.1"),
                (b"host", b"evil.test"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
            ]),
        )
        assert not recorder.inner_called
        assert recorder.status == 400

    async def test_two_host_headers_even_when_both_are_allowed(self):
        recorder = await _call(
            _config(),
            _scope([
                (b"host", b"127.0.0.1"),
                (b"host", b"localhost"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
            ]),
        )
        assert recorder.status == 400

    async def test_two_origin_headers(self):
        recorder = await _call(
            _config(),
            _scope(_authed([(b"origin", b"http://127.0.0.1:8770"),
                            (b"origin", b"https://evil.test")])),
        )
        assert not recorder.inner_called
        assert recorder.status == 400

    async def test_two_authorization_headers(self):
        """One good and one bad credential is not a request to pick the good one."""
        recorder = await _call(
            _config(),
            _scope([
                (b"host", b"127.0.0.1"),
                (b"authorization", f"Bearer {TOKEN}".encode()),
                (b"authorization", b"Bearer " + b"x" * 64),
            ]),
        )
        assert not recorder.inner_called
        assert recorder.status == 401


class TestTransportConfigInvariants:
    """The dataclass refuses a half-configured TLS pair whoever builds it.

    Without this, ``uvicorn_config()`` would hand uvicorn the string "None" as
    a key path and fail at the first handshake instead of at startup.
    """

    def test_cert_without_key_is_rejected(self, tmp_path):
        with pytest.raises(TransportConfigError, match="both tls_cert and tls_key"):
            TransportConfig(transport="http", tls_cert=tmp_path / "c.pem")

    def test_key_without_cert_is_rejected(self, tmp_path):
        with pytest.raises(TransportConfigError, match="both tls_cert and tls_key"):
            TransportConfig(transport="http", tls_key=tmp_path / "k.pem")

    def test_ca_without_cert_is_rejected(self, tmp_path):
        with pytest.raises(TransportConfigError, match="tls_ca but no tls_cert"):
            TransportConfig(transport="http", tls_ca=tmp_path / "ca.pem")

    def test_neither_is_fine(self):
        assert TransportConfig(transport="stdio").tls_enabled is False


class TestWhitespaceHostFallsBackToTheDefault:
    def test_blank_host_is_not_a_wildcard_bind(self, monkeypatch):
        """A variable set to whitespace means unset, not 'every interface'."""
        monkeypatch.setenv(ENV_TRANSPORT, "http")
        monkeypatch.setenv(ENV_HTTP_HOST, "   ")
        config = resolve_transport_config()
        assert config.host == "127.0.0.1"
        assert config.is_loopback


class TestCipherSuites:
    """The HTTP transport must not offer a suite without server authentication.

    uvicorn's default is ``ssl_ciphers="TLSv1"``, which expands to 39 suites
    including three with ``Au=None``: AECDH-AES256-SHA, AECDH-AES128-SHA and
    AECDH-NULL-SHA. Anonymous key exchange means the server sends no
    certificate, so there is nothing for a client to verify and an active
    attacker can interpose with no certificate of their own; the third also has
    ``Enc=None``, i.e. no confidentiality.

    Reaching them needs a client that offers them, which neither requests nor
    Node does -- so this was never exploitable against the shipped clients.

    These assert the PROPERTIES of the expanded list rather than the cipher
    string itself, because the properties are what matter and the string is
    only one way to get them. The expansion is done by OpenSSL on a bare
    context: no certificate is involved, so no fixture key material is needed
    and the test says nothing about uvicorn beyond that it passes the string
    through (verified separately, by hand, against a live listener).
    """

    def _suites(self, cipher_string=None):
        import ssl as ssl_module

        if cipher_string is None:
            cipher_string = remote_module.HTTP_CIPHERS
        context = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
        context.set_ciphers(cipher_string)
        return context.get_ciphers()

    def test_ciphers_are_set_explicitly(self, tls_pair):
        """Inheriting uvicorn's default is the bug; passing nothing is the bug."""
        cert, key = tls_pair
        config = TransportConfig(
            transport="http", host="192.168.1.50", token="t" * 64,
            tls_cert=cert, tls_key=key,
        ).uvicorn_config()
        assert config.get("ssl_ciphers") == remote_module.HTTP_CIPHERS, (
            "uvicorn_config does not set ssl_ciphers, so uvicorn's default "
            "'TLSv1' list applies and anonymous suites are offered"
        )

    def test_the_default_we_are_avoiding_really_is_unsafe(self):
        """Guard the premise: if uvicorn's default stops being dangerous, say so.

        Without this, the tests below could pass against a list that happens to
        be fine for an unrelated reason, and nobody would know the override had
        stopped earning its keep.
        """
        anonymous = [c["name"] for c in self._suites("TLSv1")
                     if c["auth"] == "auth-null"]
        assert anonymous, (
            "uvicorn's default cipher list no longer contains anonymous "
            "suites; re-evaluate whether HTTP_CIPHERS is still needed"
        )

    def test_no_anonymous_suites(self):
        anonymous = [c["name"] for c in self._suites() if c["auth"] == "auth-null"]
        assert not anonymous, f"suites with no server authentication: {anonymous}"

    def test_no_null_encryption(self):
        nulls = [c["name"] for c in self._suites() if "NULL" in c["name"].upper()]
        assert not nulls, f"suites with no confidentiality: {nulls}"

    def test_forward_secrecy_only(self):
        """A static-RSA suite means one stolen key decrypts every past session."""
        static = [c["name"] for c in self._suites()
                  if c["kea"] not in ("kx-ecdhe", "kx-any")]
        assert not static, f"suites without forward secrecy: {static}"

    def test_tls_12_floor_without_a_version_knob(self):
        """TLS 1.0/1.1 define no AEAD suites, so the cipher list is the floor.

        uvicorn exposes no minimum_version setting, so this is how the floor
        gets enforced rather than left to whatever the host's OpenSSL defaults
        to.
        """
        protocols = {c["protocol"] for c in self._suites()}
        assert protocols <= {"TLSv1.2", "TLSv1.3"}, f"pre-1.2 suites: {protocols}"

    def test_aead_only(self):
        cbc = [c["name"] for c in self._suites()
               if "CBC" in c["name"].upper() or c["name"].endswith("-SHA")]
        assert not cbc, f"CBC/SHA1 suites offered: {cbc}"

    def test_both_rsa_and_ecdsa_server_keys_work(self):
        """Narrowing the list must not lock out a certificate type."""
        auths = {c["auth"] for c in self._suites()}
        assert "auth-rsa" in auths and "auth-ecdsa" in auths, auths

    def test_a_ca_turns_on_client_verification(self, tls_pair):
        import ssl as ssl_module

        cert, key = tls_pair
        config = TransportConfig(
            transport="http", host="192.168.1.50", token="t" * 64,
            tls_cert=cert, tls_key=key, tls_ca=cert,
        ).uvicorn_config()
        assert config["ssl_cert_reqs"] == ssl_module.CERT_REQUIRED
        assert config["ssl_ca_certs"] == str(cert)

    def test_without_a_ca_no_client_cert_is_demanded(self, tls_pair):
        cert, key = tls_pair
        config = TransportConfig(
            transport="http", host="192.168.1.50", token="t" * 64,
            tls_cert=cert, tls_key=key,
        ).uvicorn_config()
        assert "ssl_cert_reqs" not in config
        assert "ssl_ca_certs" not in config
