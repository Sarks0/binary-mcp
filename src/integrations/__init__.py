"""
Shared plumbing for third-party threat-intelligence APIs.

Every provider this server talks to needs the same six things: a key read from
the environment or .env, a clamped socket timeout, a bounded read, a request
body in whatever encoding that provider happens to want, an HTTP error mapped
to a sentence safe to hand the model, and a JSON decode that fails loudly.
Before this package existed, ``vt_tools`` and ``mb_tools`` each carried their
own copy of all six -- about 150 duplicated lines -- and the copies had already
begun to drift (one capped the response, the other capped it differently; one
mapped 403, the other did not).

The point of factoring it out is not line count. It is that the next provider
costs a table and a renderer instead of another transport, and that a fix to
the shared behaviour -- a new status code, a tighter cap -- lands once.
"""

from src.integrations.base import (
    IntegrationClient,
    IntegrationError,
    IntegrationResponse,
    ProviderConfig,
)
from src.integrations.hashes import normalise_hash

__all__ = [
    "IntegrationClient",
    "IntegrationError",
    "IntegrationResponse",
    "ProviderConfig",
    "normalise_hash",
]
