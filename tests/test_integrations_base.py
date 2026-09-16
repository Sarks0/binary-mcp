"""
Tests for the shared provider transport (src/integrations/).

This layer replaced two hand-rolled copies of the same HTTP plumbing, so the
tests here pin the behaviour BOTH copies were relied upon for -- a key read
from config, a clamped timeout, a bounded read, correct body encoding, and
errors mapped to sentences that carry no host detail. A regression here is a
regression in every provider at once, which is exactly why it is worth
asserting centrally rather than once per provider.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from src.integrations import (
    IntegrationClient,
    IntegrationError,
    ProviderConfig,
    normalise_hash,
)
from src.integrations import base as integration_base
from tests.integration_stubs import (
    FakeResponse,
    capture_requests,
    raise_http,
    shrink_response_cap,
)


def _config(**overrides) -> ProviderConfig:
    defaults = dict(
        name="TestProvider",
        base_url="https://api.example.test/v1/",
        auth_header="X-Test-Key",
        key_config_keys=("TEST_API_KEY",),
        timeout_config_key="TEST_API_TIMEOUT",
        key_hint="Get a key from https://example.test/keys",
    )
    defaults.update(overrides)
    return ProviderConfig(**defaults)


def _client(**overrides) -> IntegrationClient:
    return IntegrationClient(_config(**overrides), IntegrationError)


# ---------------------------------------------------------------------------
# Structural: no caller can put bytes into a request body
# ---------------------------------------------------------------------------


def test_every_request_body_is_encoded_from_a_mapping():
    """
    The transport half of "sample bytes have no path to the wire".

    Providers hand the client ``form=`` or ``json_body=`` MAPPINGS; the client
    encodes them. If a future edit ever lets a caller pass raw bytes straight
    through to ``Request(data=...)``, a file could reach the network, and the
    README's never-uploads claim would quietly become false. Assert the shape
    structurally rather than trusting review.
    """
    source = Path(integration_base.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    requests_built = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "Request"
    ]
    assert len(requests_built) == 1, "more than one place builds an HTTP request"

    data_args = [kw.value for kw in requests_built[0].keywords if kw.arg == "data"]
    assert len(data_args) == 1
    assert isinstance(data_args[0], ast.Name) and data_args[0].id == "body"

    # Every assignment to `body` is either None or an encoder over a mapping.
    assignments = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "body" for t in node.targets)
    ]
    assert assignments, "the body assignment disappeared; re-check this guard"
    for assignment in assignments:
        rendered = ast.unparse(assignment.value)
        assert (
            rendered == "None"
            or "urlencode(" in rendered
            or "json.dumps(" in rendered
        ), f"request body built by something other than an encoder: {rendered}"


def test_form_and_json_bodies_are_mutually_exclusive():
    with pytest.raises(ValueError, match="not both"):
        _client().request(form={"a": "1"}, json_body={"a": 1})


# ---------------------------------------------------------------------------
# Key handling
# ---------------------------------------------------------------------------


def test_missing_key_names_the_variable_and_where_to_get_one(monkeypatch):
    client = _client()
    monkeypatch.setattr(client, "api_key", lambda: None)
    with pytest.raises(ValueError) as excinfo:
        client.require_key()
    message = str(excinfo.value)
    assert "TEST_API_KEY" in message
    assert "https://example.test/keys" in message


def test_credential_noun_uses_the_providers_own_word(monkeypatch):
    """abuse.ch says "Auth-Key"; echoing "API key" back at that user is worse."""
    client = _client(credential_noun="Auth-Key")
    monkeypatch.setattr(client, "api_key", lambda: None)
    with pytest.raises(ValueError, match="Auth-Key not configured"):
        client.require_key()


def test_first_configured_key_wins(monkeypatch):
    """A provider may accept a new canonical name and an older alias."""
    client = _client(key_config_keys=("NEW_NAME", "OLD_NAME"))
    values = {"OLD_NAME": "from-old"}
    monkeypatch.setattr(
        "src.utils.config.get_config", lambda key, default=None: values.get(key, default)
    )
    assert client.api_key() == "from-old"

    values["NEW_NAME"] = "from-new"
    assert client.api_key() == "from-new"


@pytest.mark.parametrize(
    "key,expected",
    [("0123456789abcdefghij", "0123...ghij"), ("short", "***"), ("", None)],
)
def test_masked_key_never_shows_the_middle(monkeypatch, key, expected):
    client = _client()
    monkeypatch.setattr(client, "api_key", lambda: key or None)
    assert client.masked_key() == expected


def test_no_request_is_made_without_a_key(monkeypatch):
    client = _client()
    seen = capture_requests(monkeypatch, client, {})
    monkeypatch.setattr(client, "api_key", lambda: None)
    with pytest.raises(ValueError):
        client.request()
    assert seen == []


def test_the_key_travels_in_the_providers_header(monkeypatch):
    client = _client(auth_header="Auth-Key")
    seen = capture_requests(monkeypatch, client, {}, api_key="secret-value")
    client.request()
    assert seen[0].headers["Auth-key"] == "secret-value"


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "configured,expected",
    [(None, 30), (0, 5), (1, 5), (45, 45), (10_000, 300), ("nonsense", 30)],
)
def test_timeout_is_clamped(monkeypatch, configured, expected):
    """
    A misconfigured timeout must not hang a tool call or fail it instantly.

    `get_config_int` already falls back to the default for junk, so the string
    case lands on the default rather than the floor.
    """
    client = _client()
    values = {} if configured is None else {"TEST_API_TIMEOUT": str(configured)}
    monkeypatch.setattr(
        "src.utils.config.get_config", lambda key, default=None: values.get(key, default)
    )
    assert client.timeout() == expected


def test_the_clamped_timeout_is_what_reaches_the_socket(monkeypatch):
    client = _client()
    recorded = {}

    def fake_urlopen(request, timeout=None):
        recorded["timeout"] = timeout
        return FakeResponse(b"{}")

    monkeypatch.setattr(integration_base, "urlopen", fake_urlopen)
    monkeypatch.setattr(client, "api_key", lambda: "k")
    monkeypatch.setattr(client, "timeout", lambda: 17)
    client.request()
    assert recorded["timeout"] == 17


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


def test_query_parameters_are_encoded_not_concatenated(monkeypatch):
    client = _client()
    seen = capture_requests(monkeypatch, client, {})
    client.request("search", params={"query": "tag:x p:5+", "limit": 10})
    url = seen[0].full_url
    assert url.startswith("https://api.example.test/v1/search?")
    assert "tag%3Ax+p%3A5%2B" in url or "tag%3Ax%20p%3A5%2B" in url
    assert "limit=10" in url


def test_form_body_is_urlencoded_and_marked_as_such(monkeypatch):
    client = _client()
    seen = capture_requests(monkeypatch, client, {})
    client.request(form={"query": "get_info", "hash": "a" * 64})
    assert seen[0].data == b"query=get_info&hash=" + b"a" * 64
    assert seen[0].headers["Content-type"] == "application/x-www-form-urlencoded"
    assert seen[0].get_method() == "POST"


def test_json_body_is_serialised_and_marked_as_such(monkeypatch):
    """ThreatFox and YARAify want JSON where MalwareBazaar wants a form."""
    client = _client()
    seen = capture_requests(monkeypatch, client, {})
    client.request(json_body={"query": "search_ioc", "search_term": "evil.test"})
    assert json.loads(seen[0].data) == {"query": "search_ioc", "search_term": "evil.test"}
    assert seen[0].headers["Content-type"] == "application/json"
    assert seen[0].get_method() == "POST"


def test_a_body_free_request_stays_a_get(monkeypatch):
    client = _client()
    seen = capture_requests(monkeypatch, client, {})
    client.request("files/abc")
    assert seen[0].get_method() == "GET"
    assert seen[0].data is None


# ---------------------------------------------------------------------------
# Bounded reads
# ---------------------------------------------------------------------------


def test_oversize_response_is_refused(monkeypatch):
    client = _client()
    capture_requests(monkeypatch, client, {})
    shrink_response_cap(monkeypatch, client, 16)
    monkeypatch.setattr(
        integration_base, "urlopen", lambda r, timeout=None: FakeResponse(b"x" * 64)
    )
    with pytest.raises(IntegrationError, match="response cap"):
        client.request()


def test_a_response_at_the_cap_is_allowed(monkeypatch):
    """Off-by-one check: the cap is a ceiling, not an exclusive bound."""
    client = _client()
    payload = b'{"ok":1}'
    capture_requests(monkeypatch, client, {})
    shrink_response_cap(monkeypatch, client, len(payload))
    monkeypatch.setattr(
        integration_base, "urlopen", lambda r, timeout=None: FakeResponse(payload)
    )
    assert client.request().payload == {"ok": 1}


def test_per_call_cap_overrides_the_provider_default(monkeypatch):
    """A sample download has a different ceiling than a JSON reply."""
    client = _client()
    capture_requests(monkeypatch, client, {})
    monkeypatch.setattr(
        integration_base, "urlopen", lambda r, timeout=None: FakeResponse(b"x" * 64)
    )
    with pytest.raises(IntegrationError, match="response cap"):
        client.request(expect_json=False, max_bytes=8)


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def test_non_json_reply_to_a_json_request_is_an_error(monkeypatch):
    client = _client()
    capture_requests(monkeypatch, client, raw=b"<html>502</html>")
    with pytest.raises(IntegrationError, match="not JSON"):
        client.request()


def test_non_json_reply_is_fine_when_not_expected(monkeypatch):
    """A zip archive is the success case for a sample download."""
    client = _client()
    capture_requests(monkeypatch, client, raw=b"PK\x03\x04binary")
    response = client.request(expect_json=False)
    assert response.payload == {}
    assert response.raw == b"PK\x03\x04binary"


def test_a_json_array_decodes_to_an_empty_payload(monkeypatch):
    """The payload contract is a dict; a bare array is not one."""
    client = _client()
    capture_requests(monkeypatch, client, raw=b"[1, 2, 3]")
    assert client.request().payload == {}


# ---------------------------------------------------------------------------
# Error mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code,fragment",
    [
        (401, "rejected the API key"),
        (429, "rate limit"),
        (503, "temporarily unavailable"),
        (418, "API error: 418"),
    ],
)
def test_default_status_mapping(monkeypatch, code, fragment):
    client = _client()
    raise_http(monkeypatch, client, code)
    with pytest.raises(IntegrationError, match=fragment):
        client.request()


def test_network_failure_names_the_provider_not_the_stack(monkeypatch):
    client = _client()
    monkeypatch.setattr(client, "api_key", lambda: "k")

    def boom(request, timeout=None):
        raise URLError("connection refused")

    monkeypatch.setattr(integration_base, "urlopen", boom)
    with pytest.raises(IntegrationError) as excinfo:
        client.request()
    assert "TestProvider" in str(excinfo.value)


def test_a_subclass_can_override_one_status_and_inherit_the_rest(monkeypatch):
    """The pattern both providers use: special-case a few codes, defer the rest."""

    class Custom(IntegrationClient):
        def map_http_error(self, error):
            if error.code == 404:
                return IntegrationError("nothing of that name here")
            return super().map_http_error(error)

    client = Custom(_config(), IntegrationError)

    raise_http(monkeypatch, client, 404)
    with pytest.raises(IntegrationError, match="nothing of that name here"):
        client.request()

    raise_http(monkeypatch, client, 429)
    with pytest.raises(IntegrationError, match="rate limit"):
        client.request()


def test_reading_an_error_body_never_masks_the_failure(monkeypatch):
    """A body that explodes on read must not turn a 403 into a crash."""

    class Exploding:
        def read(self):
            raise OSError("no body for you")

        def close(self):
            return None

    client = _client()
    monkeypatch.setattr(client, "api_key", lambda: "k")

    def boom(request, timeout=None):
        raise HTTPError(request.full_url, 403, "Forbidden", {}, Exploding())

    monkeypatch.setattr(integration_base, "urlopen", boom)
    with pytest.raises(IntegrationError, match="API error: 403"):
        client.request()


# ---------------------------------------------------------------------------
# Shared hash validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["a" * 32, "B" * 40, "  " + "f" * 64 + " "])
def test_normalise_hash_accepts_the_three_digests(raw):
    assert normalise_hash(raw) == raw.strip().lower()


@pytest.mark.parametrize(
    "raw", ["", "a" * 31, "z" * 32, "a" * 30 + "/x", "../" * 10 + "aa", "a" * 96]
)
def test_normalise_hash_rejects_everything_else(raw):
    with pytest.raises(ValueError):
        normalise_hash(raw)


def test_sha3_384_is_opt_in():
    """YARAify accepts it; nothing else should start accepting it by accident."""
    assert normalise_hash("a" * 96, allow_sha3_384=True) == "a" * 96
    with pytest.raises(ValueError):
        normalise_hash("a" * 96)


def test_sha256_only_rejects_the_shorter_digests():
    assert normalise_hash("a" * 64, sha256_only=True) == "a" * 64
    for raw in ("a" * 32, "a" * 40, "a" * 96):
        with pytest.raises(ValueError, match="SHA256"):
            normalise_hash(raw, sha256_only=True)
