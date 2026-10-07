"""Transport policy for this server's own MCP listener.

`stdio` is the default and the only transport that needs no policy: the client
spawns the server as a subprocess, the "connection" is a pair of pipes, and
nothing is reachable from the network. Setting ``BINARY_MCP_TRANSPORT=http``
turns that inside out -- the server becomes a listener a client connects to,
which is what lets the MCP client live on one host and this server (with
Ghidra, x64dbg and the sample) live on another.

Everything in this module exists because that listener is not an ordinary web
service. A client that reaches it can drive every tool in the roster: read and
write debuggee memory, set breakpoints, resume threads, decompile and dump. The
posture is therefore:

  * loopback by default, and a loopback bind needs no opt-in;
  * a non-loopback bind is refused unless the operator sets
    ``BINARY_MCP_REMOTE_ALLOW``, supplies a TLS certificate and key, and sets an
    explicit token -- all three, every time;
  * a wildcard bind (``0.0.0.0``, ``::``, ``*``) is refused outright, with or
    without the opt-in, because "expose this to every interface" must never be
    reachable by typo. An operator who wants LAN access names the interface.

Fail-closed is the whole design: every path that cannot prove the configuration
is safe raises :class:`TransportConfigError` and the server does not start.
A listener that comes up degraded is worse than one that refuses to come up,
because the operator finds out from the logs instead of from the refusal.

The gate itself (:class:`RemoteAccessGate`) is plain ASGI with no framework
import, so it can be tested by calling it with a scope dict -- which matters
here, because the module that wires it up (``src/server.py``) cannot be
imported without a Ghidra installation.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import secrets
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.utils.config import get_config, get_config_bool

logger = logging.getLogger(__name__)

# Environment variables that drive the transport. Named as constants so error
# messages, the policy below and CONFIG_KEYS cannot drift apart -- an operator
# who hits a refusal is told the exact variable to set.
ENV_TRANSPORT = "BINARY_MCP_TRANSPORT"
ENV_HTTP_HOST = "BINARY_MCP_HTTP_HOST"
ENV_HTTP_PORT = "BINARY_MCP_HTTP_PORT"
ENV_HTTP_PATH = "BINARY_MCP_HTTP_PATH"
ENV_HTTP_TOKEN = "BINARY_MCP_HTTP_TOKEN"
ENV_HTTP_ALLOWED_HOSTS = "BINARY_MCP_HTTP_ALLOWED_HOSTS"
ENV_REMOTE_ALLOW = "BINARY_MCP_REMOTE_ALLOW"
ENV_TLS_CERT = "BINARY_MCP_REMOTE_TLS_CERT"
ENV_TLS_KEY = "BINARY_MCP_REMOTE_TLS_KEY"
ENV_TLS_CA = "BINARY_MCP_REMOTE_TLS_CA"
ENV_CLIENT_ALLOWLIST = "BINARY_MCP_REMOTE_CLIENT_ALLOWLIST"

# The other direction: the x64dbg Obsidian plugin this server dials.
ENV_X64DBG_HOST = "X64DBG_HOST"
ENV_X64DBG_PORT = "X64DBG_PORT"
ENV_X64DBG_TLS_CA = "X64DBG_TLS_CA"
ENV_X64DBG_CLIENT_CERT = "X64DBG_TLS_CLIENT_CERT"
ENV_X64DBG_CLIENT_KEY = "X64DBG_TLS_CLIENT_KEY"
ENV_OBSIDIAN_TOKEN = "OBSIDIAN_AUTH_TOKEN"

STDIO = "stdio"
HTTP = "http"

DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8770
DEFAULT_HTTP_PATH = "/mcp"

# What obsidian_server.exe binds, and the only address it binds today.
DEFAULT_X64DBG_HOST = "127.0.0.1"
DEFAULT_X64DBG_PORT = 8765

# Token length in bytes before hex encoding. 32 bytes -> 64 hex characters,
# matching the token the x64dbg plugin generates, so the two look alike in logs.
TOKEN_BYTES = 32

# Host names that mean "this machine" but are not IP literals, so
# ipaddress.ip_address cannot classify them.
_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})

# What a loopback bind accepts in a Host header. A client may dial any of these
# and reach the same listener, so refusing the others would be a false positive.
_LOOPBACK_HOST_HEADERS = frozenset({"localhost", "127.0.0.1", "::1"})


class RemoteConfigError(Exception):
    """A remote endpoint or listener is configured unsafely. Fail closed."""


class TransportConfigError(RemoteConfigError):
    """This server's own listener is misconfigured; do not start."""


class DebuggerEndpointError(RemoteConfigError):
    """The x64dbg endpoint this server would dial is misconfigured; do not dial it."""


def _normalize_host(value: str) -> str:
    """Lowercase a host and strip IPv6 brackets, leaving the bare name or IP."""
    host = value.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def is_loopback_host(value: str) -> bool:
    """Report whether ``value`` names only this machine.

    Both spellings matter: ``localhost`` is not parseable as an address, and
    ``127.0.0.2`` is loopback without being ``127.0.0.1`` -- so the whole
    127.0.0.0/8 range and ``::1`` go through ``ip_address.is_loopback`` rather
    than an equality check against a hardcoded trio.
    """
    host = _normalize_host(value)
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_wildcard_host(value: str) -> bool:
    """Report whether ``value`` asks to bind every interface.

    ``0.0.0.0``, ``::``, ``*`` and the empty string all mean "everywhere" to
    one layer or another, and all of them are refused -- see the module
    docstring for why this is not negotiable with an opt-in.
    """
    host = _normalize_host(value)
    if host in ("", "*"):
        return True
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def strip_host_port(value: str) -> str:
    """Return the host part of a ``Host``-header value, without its port.

    ``Host`` arrives as ``127.0.0.1:8770``, ``[::1]:8770``, ``example:8770`` or
    bare. A bare IPv6 literal has several colons and no brackets, which is why
    the single-colon case is the only one split -- splitting ``::1`` on ':'
    would leave an empty host and reject a legitimate request.
    """
    host = value.strip().lower()
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            return host[1:end]
        return host.lstrip("[")
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def strip_origin(value: str) -> str:
    """Return the host of an ``Origin`` value (``https://host:port``)."""
    origin = value.strip().lower()
    if origin == "null":
        return "null"
    _, _, remainder = origin.rpartition("//")
    return strip_host_port(remainder or origin)


def _parse_networks(raw: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse a comma-separated allowlist of addresses and CIDRs.

    A bare address is accepted and becomes a single-host network, because
    "allow this one client" is the common case and making operators write
    ``/32`` invites the typo that locks them out.
    """
    networks = []
    for entry in raw.split(","):
        item = entry.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise TransportConfigError(
                f"{ENV_CLIENT_ALLOWLIST} entry {item!r} is not an address or CIDR: {exc}"
            ) from exc
    return tuple(networks)


def _require_readable(
    path_value: str,
    env_name: str,
    error: type[RemoteConfigError] = TransportConfigError,
) -> Path:
    """Resolve a configured file and refuse now if it cannot be read.

    Checked at configuration time rather than at the first TLS handshake:
    uvicorn's failure for a missing key is a traceback out of the event loop,
    long after the log has claimed the server started, and requests' failure
    for a missing CA bundle surfaces as an opaque SSLError on whatever tool
    call happened to be first.
    """
    path = Path(path_value).expanduser()
    if not path.is_file():
        raise error(f"{env_name} does not point at a file: {path}")
    try:
        with open(path, "rb"):
            pass
    except OSError as exc:
        raise error(f"{env_name} is not readable ({path}): {exc}") from exc
    return path.resolve()


def _bracket(host: str) -> str:
    """Wrap a bare IPv6 literal in brackets so it can go in a URL authority.

    ``f"http://{host}:{port}"`` with host ``::1`` produces ``http://::1:8765``,
    which is not a URL. The bridge built its base URL that way and accepted
    ``::1`` as a loopback spelling, so that combination has never worked.
    """
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


@dataclass(frozen=True)
class TransportConfig:
    """A validated transport configuration. Only produced by :func:`resolve_transport_config`."""

    transport: str
    host: str = DEFAULT_HTTP_HOST
    port: int = DEFAULT_HTTP_PORT
    path: str = DEFAULT_HTTP_PATH
    token: str = ""
    token_was_generated: bool = False
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_ca: Path | None = None
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    client_allowlist: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    def __post_init__(self) -> None:
        """Keep the TLS fields consistent regardless of how this was built.

        ``resolve_transport_config`` already refuses a half-configured pair,
        but it is not the only possible constructor, and the failure mode of an
        inconsistent one is quiet: ``uvicorn_config`` would hand uvicorn the
        string "None" as a key path, which fails at the first handshake rather
        than at startup.
        """
        if (self.tls_cert is None) != (self.tls_key is None):
            raise TransportConfigError(
                "TransportConfig needs both tls_cert and tls_key, or neither"
            )
        if self.tls_ca is not None and self.tls_cert is None:
            raise TransportConfigError("TransportConfig has tls_ca but no tls_cert")

    @property
    def is_http(self) -> bool:
        return self.transport == HTTP

    @property
    def tls_enabled(self) -> bool:
        return self.tls_cert is not None

    @property
    def mutual_tls(self) -> bool:
        return self.tls_ca is not None

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    @property
    def url(self) -> str:
        scheme = "https" if self.tls_enabled else "http"
        return f"{scheme}://{_bracket(self.host)}:{self.port}{self.path}"

    def uvicorn_config(self) -> dict[str, Any]:
        """Return the uvicorn keyword arguments that carry the TLS settings.

        FastMCP hands ``uvicorn_config`` straight to ``uvicorn.Config``, so
        this is where TLS actually gets turned on. ``ssl_ca_certs`` alone only
        offers to verify a client certificate; ``ssl_cert_reqs=CERT_REQUIRED``
        is what makes a client without one fail the handshake, which is the
        difference between mutual TLS and a decorative CA path.
        """
        config: dict[str, Any] = {}
        if self.tls_cert is not None:
            config["ssl_certfile"] = str(self.tls_cert)
            config["ssl_keyfile"] = str(self.tls_key)
            if self.tls_ca is not None:
                config["ssl_ca_certs"] = str(self.tls_ca)
                config["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        return config

    def describe(self) -> str:
        """One line for the startup log, naming every control that is NOT on.

        Phrased as what is missing because that is the question an operator
        asks later: a line that only lists what is enabled reads the same
        whether TLS is on or off.
        """
        if not self.is_http:
            return "transport=stdio (no listener)"
        parts = [f"transport=http bind={self.host}:{self.port}{self.path}"]
        parts.append("tls=mutual" if self.mutual_tls else ("tls=server" if self.tls_enabled else "tls=OFF"))
        parts.append(
            f"client-allowlist={len(self.client_allowlist)} entry(s)"
            if self.client_allowlist else "client-allowlist=OFF"
        )
        parts.append("token=generated-this-start" if self.token_was_generated else "token=configured")
        return " ".join(parts)


def resolve_transport_config() -> TransportConfig:
    """Resolve and validate the transport from the environment.

    Returns:
        A :class:`TransportConfig`. ``transport="stdio"`` carries no network
        settings and is the default when nothing is configured.

    Raises:
        TransportConfigError: If the configuration is unparseable, or asks for
            a listener the policy in the module docstring refuses.
    """
    raw = (get_config(ENV_TRANSPORT) or STDIO).strip().lower()
    if raw in ("", STDIO):
        return TransportConfig(transport=STDIO)
    # "streamable-http" is the MCP spec's name for what FastMCP calls "http";
    # accepting it avoids a refusal over vocabulary.
    if raw not in (HTTP, "streamable-http"):
        raise TransportConfigError(
            f"{ENV_TRANSPORT}={raw!r} is not a transport. Use 'stdio' (default) or 'http'."
        )

    host = (get_config(ENV_HTTP_HOST) or "").strip() or DEFAULT_HTTP_HOST
    if is_wildcard_host(host):
        raise TransportConfigError(
            f"{ENV_HTTP_HOST}={host!r} binds every interface, which is refused "
            f"even with {ENV_REMOTE_ALLOW} set. Name the interface address this "
            f"server should be reachable on (for example the host's LAN address), "
            f"or leave it unset for {DEFAULT_HTTP_HOST}."
        )

    port_raw = (get_config(ENV_HTTP_PORT) or str(DEFAULT_HTTP_PORT)).strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise TransportConfigError(f"{ENV_HTTP_PORT}={port_raw!r} is not an integer") from exc
    if not 1 <= port <= 65535:
        raise TransportConfigError(f"{ENV_HTTP_PORT}={port} is outside 1-65535")

    path = (get_config(ENV_HTTP_PATH) or DEFAULT_HTTP_PATH).strip()
    if not path.startswith("/"):
        raise TransportConfigError(f"{ENV_HTTP_PATH}={path!r} must start with '/'")

    # TLS. A key without a certificate is a misconfiguration worth naming
    # rather than silently serving plaintext on.
    cert_raw = (get_config(ENV_TLS_CERT) or "").strip()
    key_raw = (get_config(ENV_TLS_KEY) or "").strip()
    ca_raw = (get_config(ENV_TLS_CA) or "").strip()
    if key_raw and not cert_raw:
        raise TransportConfigError(f"{ENV_TLS_KEY} is set but {ENV_TLS_CERT} is not")
    if cert_raw and not key_raw:
        raise TransportConfigError(f"{ENV_TLS_CERT} is set but {ENV_TLS_KEY} is not")
    if ca_raw and not cert_raw:
        raise TransportConfigError(
            f"{ENV_TLS_CA} asks for client-certificate verification, but "
            f"{ENV_TLS_CERT}/{ENV_TLS_KEY} are unset so there is no TLS to verify within"
        )
    tls_cert = _require_readable(cert_raw, ENV_TLS_CERT) if cert_raw else None
    tls_key = _require_readable(key_raw, ENV_TLS_KEY) if key_raw else None
    tls_ca = _require_readable(ca_raw, ENV_TLS_CA) if ca_raw else None

    client_allowlist = _parse_networks(get_config(ENV_CLIENT_ALLOWLIST) or "")

    token = (get_config(ENV_HTTP_TOKEN) or "").strip()
    token_was_generated = False

    loopback = is_loopback_host(host)
    if not loopback:
        # The three remote requirements, each refused separately so the message
        # names the one thing still missing instead of a generic "misconfigured".
        if not get_config_bool(ENV_REMOTE_ALLOW):
            raise TransportConfigError(
                f"{ENV_HTTP_HOST}={host!r} is not a loopback address. Binding this "
                f"server where other hosts can reach it exposes every tool in the "
                f"roster -- including debuggee memory writes -- to anyone who "
                f"obtains the token. Set {ENV_REMOTE_ALLOW}=1 to say you intend "
                f"that, and see docs/remote-access.md."
            )
        if tls_cert is None:
            raise TransportConfigError(
                f"{ENV_HTTP_HOST}={host!r} is not loopback, so TLS is required: set "
                f"{ENV_TLS_CERT} and {ENV_TLS_KEY}. Without it the bearer token "
                f"crosses the network in cleartext and anyone who captures it owns "
                f"the debugger."
            )
        if not token:
            raise TransportConfigError(
                f"{ENV_HTTP_TOKEN} must be set explicitly for a non-loopback bind. "
                f"A generated token changes on every restart, which would silently "
                f"break the client's configuration on the other host."
            )
    elif not token:
        # Loopback with no token configured: mint one. Still required -- any
        # local process can reach a loopback listener, which is exactly why the
        # x64dbg plugin tokens its own loopback server too.
        token = secrets.token_hex(TOKEN_BYTES)
        token_was_generated = True

    allowed_hosts = {_normalize_host(host)}
    if loopback:
        allowed_hosts |= _LOOPBACK_HOST_HEADERS
    for extra in (get_config(ENV_HTTP_ALLOWED_HOSTS) or "").split(","):
        name = _normalize_host(extra)
        if name:
            allowed_hosts.add(name)

    return TransportConfig(
        transport=HTTP,
        host=host,
        port=port,
        path=path,
        token=token,
        token_was_generated=token_was_generated,
        tls_cert=tls_cert,
        tls_key=tls_key,
        tls_ca=tls_ca,
        allowed_hosts=frozenset(allowed_hosts),
        client_allowlist=client_allowlist,
    )


# ---------------------------------------------------------------------------
# The other direction: the x64dbg endpoint this server dials
# ---------------------------------------------------------------------------
#
# Same posture, mirrored. The listener above decides who may drive this server;
# this decides what this server may drive. The asymmetry worth naming is which
# certificate matters: the listener holds a server certificate and optionally
# verifies a CLIENT one; the bridge verifies the plugin's SERVER certificate
# against a CA and optionally presents a client one. They are different roles
# with different files, so ``BINARY_MCP_REMOTE_TLS_CA`` (client certs this
# server accepts) and ``X64DBG_TLS_CA`` (the CA that signs the plugin's
# certificate) are deliberately NOT the same variable. Reusing one would mean
# a CA trusted to issue client credentials silently became a CA trusted to
# impersonate the debugger.
#
# One thing this does not do is make the plugin reachable. obsidian_server.exe
# binds 127.0.0.1 and speaks plaintext HTTP (server/main.cpp -- INADDR_LOOPBACK,
# no TLS), so a non-loopback endpoint only exists if something on the debugger
# host terminates TLS and forwards to that loopback port. Phase 3 of
# docs/remote-access-plan.md replaces that with a native listener. Until then
# the supported paths are a tunnel (loopback, no opt-in needed) or a TLS
# terminator, and both land here.


@dataclass(frozen=True)
class DebuggerEndpoint:
    """A validated x64dbg endpoint. Only produced by :func:`resolve_debugger_endpoint`."""

    host: str = DEFAULT_X64DBG_HOST
    port: int = DEFAULT_X64DBG_PORT
    tls_ca: Path | None = None
    client_cert: Path | None = None
    client_key: Path | None = None

    def __post_init__(self) -> None:
        if (self.client_cert is None) != (self.client_key is None):
            raise DebuggerEndpointError(
                "DebuggerEndpoint needs both client_cert and client_key, or neither"
            )
        if self.client_cert is not None and self.tls_ca is None:
            raise DebuggerEndpointError(
                "DebuggerEndpoint has a client certificate but no tls_ca, so there "
                "is no TLS to present it over"
            )

    @property
    def is_loopback(self) -> bool:
        return is_loopback_host(self.host)

    @property
    def tls_enabled(self) -> bool:
        """True when a CA is configured, which is also what selects https.

        The CA doubles as the "TLS is on" switch rather than having a separate
        scheme variable, because https without a CA to verify against is the
        one combination there is never a reason to want: it would encrypt the
        token against a passive listener and hand it to any active one.
        """
        return self.tls_ca is not None

    @property
    def mutual_tls(self) -> bool:
        return self.client_cert is not None

    @property
    def scheme(self) -> str:
        return "https" if self.tls_enabled else "http"

    @property
    def base_url(self) -> str:
        return f"{self.scheme}://{_bracket(self.host)}:{self.port}"

    @property
    def token_must_come_from_env(self) -> bool:
        """True when the plugin's token file is on a machine this one cannot read.

        The plugin writes its token to ``%TEMP%\\x64dbg_mcp_token.txt`` on the
        host x64dbg runs on. For a remote endpoint that is not this host, so
        looking there produces "token file not found" for what is really "you
        did not provision a token" -- a message that sends the operator to
        check whether the plugin is loaded instead of to the one thing they
        have to do.
        """
        return not self.is_loopback

    def requests_kwargs(self) -> dict[str, Any]:
        """Return the ``requests`` keyword arguments carrying the TLS settings.

        Empty for a plaintext loopback endpoint, so the common case is byte for
        byte the call it was before. ``verify`` is a CA path rather than True:
        the plugin's certificate is one an analyst issued for a lab host, so the
        system trust store is the wrong thing to check it against.
        """
        kwargs: dict[str, Any] = {}
        if self.tls_ca is not None:
            kwargs["verify"] = str(self.tls_ca)
        if self.client_cert is not None and self.client_key is not None:
            kwargs["cert"] = (str(self.client_cert), str(self.client_key))
        return kwargs

    def describe(self) -> str:
        """One line for the log, naming what is NOT on rather than what is."""
        parts = [self.base_url]
        parts.append("tls=mutual" if self.mutual_tls else ("tls=server" if self.tls_enabled else "tls=OFF"))
        parts.append("loopback" if self.is_loopback else "REMOTE")
        return " ".join(parts)


def resolve_debugger_endpoint(
    host: str | None = None, port: int | None = None
) -> DebuggerEndpoint:
    """Resolve and validate the x64dbg endpoint.

    Args:
        host: Explicit host, overriding ``$X64DBG_HOST``. ``None`` resolves
            from the environment, then the loopback default.
        port: Explicit port, overriding ``$X64DBG_PORT``.

    Returns:
        A validated :class:`DebuggerEndpoint`.

    Raises:
        DebuggerEndpointError: If the endpoint is unparseable, or is a
            non-loopback host without the opt-in, a CA and a token.
    """
    # A blank host is treated as unset, same as None: "" is not a host, and a
    # caller that passes one should still get the configured endpoint rather
    # than silently bypassing it. The port cannot do the same, because 0 is
    # falsy AND an invalid port -- it has to reach the range check below.
    if not (host or "").strip():
        host = get_config(ENV_X64DBG_HOST) or ""
    resolved_host = _normalize_host(str(host)) or DEFAULT_X64DBG_HOST

    if is_wildcard_host(resolved_host):
        raise DebuggerEndpointError(
            f"{ENV_X64DBG_HOST}={resolved_host!r} is not a destination. "
            f"0.0.0.0 and :: mean 'every interface' to a listener and nothing at "
            f"all to a client -- name the debugger host's address, or leave it "
            f"unset for {DEFAULT_X64DBG_HOST}."
        )

    if port is None:
        port_raw = (get_config(ENV_X64DBG_PORT) or str(DEFAULT_X64DBG_PORT)).strip()
    else:
        port_raw = str(port)
    try:
        resolved_port = int(port_raw)
    except ValueError as exc:
        raise DebuggerEndpointError(
            f"{ENV_X64DBG_PORT}={port_raw!r} is not an integer"
        ) from exc
    if not 1 <= resolved_port <= 65535:
        raise DebuggerEndpointError(f"{ENV_X64DBG_PORT}={resolved_port} is outside 1-65535")

    ca_raw = (get_config(ENV_X64DBG_TLS_CA) or "").strip()
    cert_raw = (get_config(ENV_X64DBG_CLIENT_CERT) or "").strip()
    key_raw = (get_config(ENV_X64DBG_CLIENT_KEY) or "").strip()
    if cert_raw and not key_raw:
        raise DebuggerEndpointError(
            f"{ENV_X64DBG_CLIENT_CERT} is set but {ENV_X64DBG_CLIENT_KEY} is not"
        )
    if key_raw and not cert_raw:
        raise DebuggerEndpointError(
            f"{ENV_X64DBG_CLIENT_KEY} is set but {ENV_X64DBG_CLIENT_CERT} is not"
        )
    if cert_raw and not ca_raw:
        raise DebuggerEndpointError(
            f"{ENV_X64DBG_CLIENT_CERT} asks to present a client certificate, but "
            f"{ENV_X64DBG_TLS_CA} is unset so the connection would be plaintext "
            f"HTTP with nothing to present it over"
        )

    tls_ca = _require_readable(ca_raw, ENV_X64DBG_TLS_CA, DebuggerEndpointError) if ca_raw else None
    client_cert = (
        _require_readable(cert_raw, ENV_X64DBG_CLIENT_CERT, DebuggerEndpointError)
        if cert_raw else None
    )
    client_key = (
        _require_readable(key_raw, ENV_X64DBG_CLIENT_KEY, DebuggerEndpointError)
        if key_raw else None
    )

    if not is_loopback_host(resolved_host):
        # The three remote requirements, refused one at a time so the message
        # names the single thing still missing. Same shape as the listener's.
        if not get_config_bool(ENV_REMOTE_ALLOW):
            raise DebuggerEndpointError(
                f"{ENV_X64DBG_HOST}={resolved_host!r} is not a loopback address. "
                f"Driving a debugger across the network means this server's "
                f"bearer token, and every memory write it authorises, crosses it "
                f"too. Set {ENV_REMOTE_ALLOW}=1 to say you intend that, and see "
                f"docs/remote-access.md -- a tunnel to 127.0.0.1 needs no opt-in "
                f"and is the simpler answer."
            )
        if tls_ca is None:
            raise DebuggerEndpointError(
                f"{ENV_X64DBG_HOST}={resolved_host!r} is not loopback, so TLS is "
                f"required: set {ENV_X64DBG_TLS_CA} to the CA that signs the "
                f"debugger host's certificate. Without it the token crosses the "
                f"network in cleartext and anyone who captures it owns the "
                f"debugger. Note that obsidian_server.exe does not serve TLS "
                f"itself yet -- something on that host has to terminate it."
            )
        if not (get_config(ENV_OBSIDIAN_TOKEN) or "").strip():
            raise DebuggerEndpointError(
                f"{ENV_OBSIDIAN_TOKEN} must be set for a non-loopback endpoint. "
                f"The plugin writes its token to %TEMP% on the debugger host, "
                f"which is not this machine -- read it there and set it here."
            )

    return DebuggerEndpoint(
        host=resolved_host,
        port=resolved_port,
        tls_ca=tls_ca,
        client_cert=client_cert,
        client_key=client_key,
    )


Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]


# Returned by _header when a header the gate decides on appears more than once.
_DUPLICATE = object()


def _header(
    headers: Iterable[tuple[bytes, bytes]], name: bytes
) -> str | None | object:
    """Return the single value of header ``name``, ``None``, or ``_DUPLICATE``.

    ASGI guarantees lowercase header names, so no case folding is needed here
    -- unlike the C++ server, which parses raw HTTP and has to anchor the match
    itself (see FindHeaderValue in server/main.cpp).

    Duplicates are reported rather than resolved. A gate that takes the first
    ``Host`` while something downstream takes the last is a gate that can be
    talked past, and this project has already paid for one parser that
    disagreed with the thing it was guarding (see split_x64dbg_command in the
    x64dbg bridge). HTTP/1.1 permits exactly one Host, so a second is
    malformed input, not a case to pick a winner in.
    """
    found: str | None = None
    for key, value in headers:
        if key == name:
            if found is not None:
                return _DUPLICATE
            found = value.decode("latin-1")
    return found


class RemoteAccessGate:
    """ASGI gate in front of the MCP endpoint.

    Three checks, cheapest and least secret-dependent first, so a denial never
    depends on comparing a token the caller was never going to get right:

    1. **Client address** against ``BINARY_MCP_REMOTE_CLIENT_ALLOWLIST`` (403).
    2. **Host and Origin** against the configured bind name (400). This is the
       DNS-rebinding control: a browser on any host that can resolve a name to
       this address would otherwise be able to drive the server through a page
       the operator never visited, and the MCP endpoint is not CORS-protected.
    3. **Bearer token**, compared with ``hmac.compare_digest`` (401).

    The gate deliberately does not implement CORS. There is no browser client
    for this server, and an ``Access-Control-Allow-Origin`` here would undo
    check 2.

    ``lifespan`` passes straight through: gating it would stop the app starting.
    ``websocket`` is closed, because this app serves no websocket route and a
    scope that reaches here is either a probe or a misconfiguration.
    """

    def __init__(self, app: Any, *, config: TransportConfig) -> None:
        self._app = app
        self._config = config

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")

        if scope_type == "lifespan":
            await self._app(scope, receive, send)
            return

        if scope_type == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return

        if scope_type != "http":
            # An unknown scope type is not something to guess at.
            return

        denial = self._check(scope)
        if denial is not None:
            status, message, extra_headers = denial
            await self._deny(send, status, message, extra_headers)
            return

        await self._app(scope, receive, send)

    # -- checks ------------------------------------------------------------

    def _client_address(self, scope: dict[str, Any]) -> str | None:
        client = scope.get("client")
        if isinstance(client, (tuple, list)) and client:
            return str(client[0])
        return None

    def _check(
        self, scope: dict[str, Any]
    ) -> tuple[int, str, tuple[tuple[bytes, bytes], ...]] | None:
        """Return ``(status, message, headers)`` to refuse with, or None to allow."""
        config = self._config
        headers = scope.get("headers") or []
        peer = self._client_address(scope)

        if config.client_allowlist:
            # No peer address means no way to satisfy an allowlist that exists.
            # Refusing is the only answer that keeps the allowlist meaningful.
            if peer is None:
                logger.warning("Refused a request with no client address: allowlist is configured")
                return (403, "Client address not permitted", ())
            try:
                address = ipaddress.ip_address(peer)
            except ValueError:
                logger.warning("Refused client %r: address is unparseable", peer)
                return (403, "Client address not permitted", ())
            # An IPv4 client arriving over a dual-stack socket appears as
            # ::ffff:a.b.c.d, which matches no IPv4 network -- so compare the
            # mapped form too rather than refusing a client the operator
            # believes they allowed.
            candidates = [address]
            mapped = getattr(address, "ipv4_mapped", None)
            if mapped is not None:
                candidates.append(mapped)
            if not any(c in net for c in candidates for net in config.client_allowlist):
                logger.warning("Refused client %s: not in %s", peer, ENV_CLIENT_ALLOWLIST)
                return (403, "Client address not permitted", ())

        host_header = _header(headers, b"host")
        if host_header is _DUPLICATE:
            logger.warning("Refused request from %s: more than one Host header", peer)
            return (400, "Host not allowed", ())
        if host_header is not None:
            if strip_host_port(str(host_header)) not in config.allowed_hosts:
                logger.warning(
                    "Refused request for Host %r from %s: not in the allowed set. "
                    "Add the name clients dial to %s.",
                    host_header, peer, ENV_HTTP_ALLOWED_HOSTS,
                )
                return (400, "Host not allowed", ())

        origin_header = _header(headers, b"origin")
        if origin_header is _DUPLICATE:
            logger.warning("Refused request from %s: more than one Origin header", peer)
            return (400, "Origin not allowed", ())
        if origin_header is not None:
            if strip_origin(str(origin_header)) not in config.allowed_hosts:
                logger.warning(
                    "Refused request with Origin %r from %s (cross-origin requests "
                    "are not served)", origin_header, peer,
                )
                return (400, "Origin not allowed", ())

        authorization = _header(headers, b"authorization")
        if authorization is _DUPLICATE:
            logger.warning(
                "Refused request from %s: more than one Authorization header", peer
            )
            return (401, "Authentication required", ((b"www-authenticate", b"Bearer"),))
        if not authorization:
            logger.warning("Refused request from %s: no Authorization header", peer)
            return (401, "Authentication required", ((b"www-authenticate", b"Bearer"),))

        scheme, _, presented = str(authorization).partition(" ")
        if scheme.strip().lower() != "bearer" or not presented.strip():
            logger.warning("Refused request from %s: Authorization is not 'Bearer <token>'", peer)
            return (401, "Authentication required", ((b"www-authenticate", b"Bearer"),))

        if not hmac.compare_digest(presented.strip(), config.token):
            logger.warning("Refused request from %s: token mismatch", peer)
            return (401, "Authentication required", ((b"www-authenticate", b"Bearer"),))

        return None

    # -- response ----------------------------------------------------------

    async def _deny(
        self,
        send: Send,
        status: int,
        message: str,
        extra_headers: tuple[tuple[bytes, bytes], ...] = (),
    ) -> None:
        # The body says only what was refused. It never echoes the Host, the
        # Origin or the presented token: a denial is read by whoever sent it,
        # and reflecting their input back is how a refusal becomes an oracle.
        body = b'{"error":"%s"}' % message.encode("ascii", "replace")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                *extra_headers,
            ],
        })
        await send({"type": "http.response.body", "body": body})
