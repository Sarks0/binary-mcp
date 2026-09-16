"""
One HTTP client for every third-party threat-intelligence provider.

What is genuinely shared, and therefore lives here:

* the API key, read from the environment or .env, with a curated
  "not configured" message naming the variable and where to get a key;
* a socket timeout, clamped so a misconfigured value cannot hang a tool call
  or make it fail instantly;
* a BOUNDED read -- an unbounded ``response.read()`` on a hostile or broken
  endpoint is an out-of-memory bug waiting for a bad day;
* request-body encoding, because the providers disagree: VirusTotal takes
  query-string GETs, MalwareBazaar and URLhaus want form-encoded POSTs, and
  ThreatFox and YARAify want JSON POSTs. Callers name what they are sending
  and never assemble a body themselves, which is what keeps a file object
  structurally unable to become one;
* HTTP and network failures mapped to a provider-authored sentence -- never
  a raw exception string, which can carry host detail (audit F-10);
* a JSON decode that says "that was not JSON" instead of raising
  ``JSONDecodeError`` out of a tool handler.

What is NOT shared, and stays with each provider: which status codes mean
what (``map_http_error``), how a provider signals failure inside a 200 (abuse.ch
uses ``query_status``, VirusTotal uses HTTP codes), and every line of
rendering. Subclass to override the first; do the rest in the tool module.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


class IntegrationError(RuntimeError):
    """
    A provider failure whose message this project wrote itself.

    Audit F-10: tool handlers return ``f"<Provider> error: {e}"`` verbatim for
    this type, which is right for the curated sentences raised here and in the
    provider modules, and wrong for anything else that happens to be a
    ``RuntimeError`` in the same try block -- urllib, json and the hashing
    helpers all live in there. Each provider subclasses this so the
    passthrough applies to exactly the strings we authored; everything else
    drops through to ``safe_error_message``.

    Every raise site in this module was audited for host detail: the messages
    below carry a status line, a provider-authored reason, or a byte count.
    ``URLError.reason`` for an https:// request is a socket or TLS error, not
    a filesystem path.
    """


@dataclass(frozen=True)
class ProviderConfig:
    """Everything that differs between providers except rendering."""

    #: Human-readable provider name, used in error sentences.
    name: str

    #: Base URL. A request path is appended to it verbatim, so it carries its
    #: own trailing slash when the provider posts to a directory-style root.
    base_url: str

    #: Header the key travels in: "x-apikey" (VirusTotal), "Auth-Key" (abuse.ch).
    #: Empty for a provider that needs no credential at all.
    auth_header: str

    #: Config keys tried in order; the first one set wins. A tuple rather than
    #: a string so a provider can accept a new canonical name while still
    #: honouring the one an operator already has in their .env.
    #:
    #: EMPTY means the provider needs no credential -- MITRE ATT&CK is served
    #: as static files from a public repository. A keyless provider still wants
    #: everything else this client does (clamped timeout, bounded read, mapped
    #: errors), so "no key" is a configuration, not a reason to hand-roll
    #: another transport.
    key_config_keys: tuple[str, ...]

    #: Config key holding a socket-timeout override.
    timeout_config_key: str

    #: What the provider calls the credential in its own documentation.
    #: abuse.ch says "Auth-Key" throughout; saying "API key" back at a user who
    #: just read their docs costs them a moment of doubt for no reason.
    credential_noun: str = "API key"

    #: Appended to the "key not configured" message -- where to get one.
    key_hint: str = ""

    default_timeout: int = 30
    min_timeout: int = 5
    max_timeout: int = 300

    #: Ceiling on a decoded response. Generous enough for the largest real
    #: reply, small enough that a runaway one is refused rather than buffered.
    max_response_bytes: int = 32 * 1024 * 1024

    user_agent: str = "binary-mcp"

    #: Extra request headers, if the provider needs any.
    extra_headers: dict = field(default_factory=dict)


@dataclass(frozen=True)
class IntegrationResponse:
    """A decoded reply plus the bytes it came from."""

    #: Parsed JSON object, or ``{}`` when the body was not a JSON object.
    #: For an endpoint whose success body is binary (a sample archive), an
    #: empty payload alongside non-empty ``raw`` is the success case.
    payload: dict

    raw: bytes


class IntegrationClient:
    """
    A configured HTTP client for one provider.

    Subclass and override :meth:`map_http_error` to turn that provider's
    status codes into sentences worth reading.
    """

    def __init__(self, config: ProviderConfig, error_cls: type[IntegrationError] = IntegrationError):
        self.config = config
        self.error_cls = error_cls

    # -- configuration ----------------------------------------------------

    def api_key(self) -> str | None:
        """First configured key among ``key_config_keys``, or None."""
        from src.utils.config import get_config

        for key in self.config.key_config_keys:
            value = get_config(key)
            if value:
                return value
        return None

    def require_key(self) -> str:
        """
        Return the key, or raise a ValueError that says how to set one.

        ValueError rather than IntegrationError on purpose: an unconfigured
        key is the caller's problem to fix, and the tool handlers render it as
        "Configuration error: ..." rather than as a provider failure.

        Returns "" for a keyless provider, which is not an error.
        """
        if not self.config.key_config_keys:
            return ""

        key = self.api_key()
        if key:
            return key

        primary = self.config.key_config_keys[0]
        message = (
            f"{self.config.name} {self.config.credential_noun} not configured. "
            f"Set the {primary} environment variable."
        )
        if self.config.key_hint:
            message = f"{message} {self.config.key_hint}"
        raise ValueError(message)

    def masked_key(self) -> str | None:
        """The configured key, safe to print. None when unset."""
        key = self.api_key()
        if not key:
            return None
        return key[:4] + "..." + key[-4:] if len(key) > 12 else "***"

    def timeout(self) -> int:
        """Configured socket timeout, clamped to the provider's range."""
        from src.utils.config import get_config_int

        configured = get_config_int(self.config.timeout_config_key, self.config.default_timeout)
        return max(self.config.min_timeout, min(configured, self.config.max_timeout))

    # -- requests ---------------------------------------------------------

    def build_url(self, path: str = "", params: dict | None = None) -> str:
        url = f"{self.config.base_url}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    def request(
        self,
        path: str = "",
        *,
        method: str = "GET",
        params: dict | None = None,
        form: dict | None = None,
        json_body: dict | None = None,
        expect_json: bool = True,
        max_bytes: int | None = None,
    ) -> IntegrationResponse:
        """
        Perform one request and return its decoded reply.

        Args:
            path: Appended to ``base_url``. Callers percent-encode any value
                they interpolate into it.
            method: Defaults to GET; a body implies POST unless overridden.
            params: Query-string parameters, encoded here so no caller has to
                remember to escape them.
            form: ``application/x-www-form-urlencoded`` body fields. Values are
                coerced to ``str`` and encoded here.
            json_body: ``application/json`` body.
            expect_json: ``False`` when a successful reply is binary; the
                returned payload is then ``{}`` and ``raw`` holds the bytes.
            max_bytes: Override the provider's response cap for this call --
                a sample download has a different ceiling than a JSON reply.

        Raises:
            ValueError: If the API key is not configured.
            IntegrationError subclass: On any transport or protocol failure.
        """
        if form is not None and json_body is not None:
            raise ValueError("pass either form or json_body, not both")

        api_key = self.require_key()

        headers = {
            "Accept": "application/json",
            "User-Agent": self.config.user_agent,
            **self.config.extra_headers,
        }
        if api_key and self.config.auth_header:
            headers[self.config.auth_header] = api_key

        body: bytes | None = None
        if form is not None:
            body = urlencode({k: str(v) for k, v in form.items()}).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            method = "POST"
        elif json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"

        request = Request(
            self.build_url(path, params), data=body, headers=headers, method=method
        )

        cap = max_bytes if max_bytes is not None else self.config.max_response_bytes

        try:
            # nosec B310 - base_url is a hardcoded https:// constant per provider
            with urlopen(request, timeout=self.timeout()) as response:
                raw = response.read(cap + 1)
        except HTTPError as e:
            raise self.map_http_error(e) from None
        except URLError as e:
            raise self.error_cls(
                f"Network error connecting to {self.config.name}: {e.reason}"
            ) from None

        if len(raw) > cap:
            raise self.error_cls(
                f"{self.config.name} response exceeded the "
                f"{cap // (1024 * 1024)}MB response cap"
            )

        return IntegrationResponse(payload=self._decode(raw, expect_json), raw=raw)

    def _decode(self, raw: bytes, expect_json: bool) -> dict:
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            if expect_json:
                raise self.error_cls(
                    f"{self.config.name} returned a response that was not JSON"
                ) from None
            return {}
        return parsed if isinstance(parsed, dict) else {}

    # -- error mapping ----------------------------------------------------

    def read_error_body(self, error: HTTPError) -> bytes:
        """
        Best-effort read of an error response body.

        Providers put their most useful diagnostics here -- which privilege is
        missing, which quota tripped -- and the status line does not say it.
        Never allowed to mask the original failure, hence the broad catch.
        """
        try:
            return error.read() or b""
        except Exception:  # nosec B110 - body is best-effort enrichment only
            return b""

    def map_http_error(self, error: HTTPError) -> Exception:
        """
        Turn an HTTP failure into a provider-authored sentence.

        The default covers what is common to every provider; override in a
        subclass for the codes that carry provider-specific meaning, and call
        ``super().map_http_error(error)`` for the rest.
        """
        name = self.config.name

        if error.code == 401:
            return self.error_cls(f"{name} rejected the API key")
        if error.code == 429:
            return self.error_cls(
                f"{name} rate limit exceeded. Wait and retry."
            )
        if error.code in (502, 503, 504):
            return self.error_cls(
                f"{name} is temporarily unavailable ({error.code})"
            )
        return self.error_cls(f"{name} API error: {error.code} {error.reason}")
