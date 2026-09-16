"""
Shared stubs for exercising src/integrations clients without a network.

Each provider's tests used to patch ``urlopen`` and the key lookup inside its
own tool module. Both now live in :mod:`src.integrations.base`, so the patch
target is shared -- and so is the temptation to re-invent a slightly different
fake response in each test file. One implementation here keeps the three
providers' tests asserting against the same transport behaviour.

Not named ``test_*``, so pytest does not collect it as a test module.
"""

from __future__ import annotations

import json
from dataclasses import replace
from urllib.error import HTTPError

from src.integrations import base as integration_base


class FakeResponse:
    """Enough of an HTTP response for IntegrationClient and HTTPError."""

    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self, amount: int | None = None) -> bytes:
        return self._payload if amount is None else self._payload[:amount]

    def close(self) -> None:
        # HTTPError wraps the fp it is handed in a tempfile closer, which calls
        # close() on garbage collection; without it pytest reports an
        # unraisable AttributeError from the finaliser.
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def capture_requests(
    monkeypatch,
    client,
    payload: dict | list | None = None,
    raw: bytes | None = None,
    api_key: str = "test-api-key",
) -> list:
    """
    Record every urllib Request ``client`` builds, answering each identically.

    Args:
        monkeypatch: pytest's monkeypatch fixture.
        client: The IntegrationClient under test; its key lookup is stubbed so
            no real configuration is consulted.
        payload: JSON body to answer with. Ignored when ``raw`` is given.
        raw: Exact bytes to answer with, for non-JSON replies.
        api_key: Value the stubbed key lookup returns.

    Returns:
        The list the requests are appended to, in call order.
    """
    seen: list = []
    body = raw if raw is not None else json.dumps(
        payload if payload is not None else {}
    ).encode()

    def fake_urlopen(request, timeout=None):
        seen.append(request)
        return FakeResponse(body)

    monkeypatch.setattr(integration_base, "urlopen", fake_urlopen)
    monkeypatch.setattr(client, "api_key", lambda: api_key)
    return seen


def raise_http(monkeypatch, client, code: int, payload: dict | None = None,
               api_key: str = "test-api-key") -> None:
    """Make every request through ``client`` fail with one HTTP status."""

    def fake_urlopen(request, timeout=None):
        raise HTTPError(
            request.full_url,
            int(code),
            "Status",
            {},
            None if payload is None else FakeResponse(json.dumps(payload).encode()),
        )

    monkeypatch.setattr(integration_base, "urlopen", fake_urlopen)
    monkeypatch.setattr(client, "api_key", lambda: api_key)


def shrink_response_cap(monkeypatch, client, max_response_bytes: int) -> None:
    """Lower a client's response ceiling; ProviderConfig is frozen."""
    monkeypatch.setattr(
        client, "config", replace(client.config, max_response_bytes=max_response_bytes)
    )
