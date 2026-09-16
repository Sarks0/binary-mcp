"""
ThreatFox, URLhaus and YARAify (abuse.ch) -- IOC, distribution and rule pivots.

These three sit alongside ``mb_tools`` (MalwareBazaar) and share its Auth-Key:
abuse.ch issues ONE key per account that works across every platform it runs.
They are grouped in one module for that reason -- the credential, the
``query_status`` protocol and the failure vocabulary are common to all three,
while each has only a handful of endpoints.

What each one answers, in terms of artefacts this server already computes:

* **ThreatFox** -- an IOC to a malware family. Feed it the domains, URLs and
  IPs from ``extract_iocs_with_context`` and it names the family, the threat
  type and a confidence level.
* **URLhaus** -- a URL, domain or IP to its malware-distribution history, and
  crucially to the PAYLOAD HASHES served from it. That closes the loop back to
  MalwareBazaar: host -> payload hash -> sample.
* **YARAify** -- a hash to the public YARA rules that match it, and the reverse:
  a rule name, imphash, TLSH, telfhash, gimphash, icon dhash or ClamAV
  signature to the files that match. It is the natural counterpart to
  ``generate_yara_rule_from_session``: write a rule, then ask what else in the
  public corpus it would have caught.

API shapes (https://threatfox.abuse.ch/api/, https://urlhaus-api.abuse.ch/,
https://yaraify.abuse.ch/api/). They are deliberately NOT uniform, which is why
the transport lives in src/integrations rather than being hand-rolled per
service:

===========  =====================================  ============  ===========
Service      Base URL                               Body          Path
===========  =====================================  ============  ===========
ThreatFox    https://threatfox-api.abuse.ch/api/v1/ JSON          fixed
URLhaus      https://urlhaus-api.abuse.ch/v1/       form-encoded  per-endpoint
YARAify      https://yaraify-api.abuse.ch/api/v1/   JSON          fixed
===========  =====================================  ============  ===========

All three POST, all three take the ``Auth-Key`` header, and all three answer
with a ``query_status`` field where ``"ok"`` means ``data`` is populated.

Outbound-data posture: as with MalwareBazaar, these are POSTs because the API
requires POST, not because anything is being submitted. What goes in a body is
a hash, an IOC, a rule name or a malware family. There is no upload or submit
call in this module, and ``tests/test_abusech_tools.py`` pins that every
request body is a mapping of scalars.
"""

import logging
import re
from urllib.error import HTTPError

from src.integrations import IntegrationClient, IntegrationError, ProviderConfig
from src.integrations.hashes import normalise_hash
from src.tools.mb_tools import ABUSECH_API_KEY_ENV, MB_API_KEY_ENV
from src.utils.formatters import wrap_untrusted

logger = logging.getLogger(__name__)


class AbuseChError(IntegrationError):
    """
    A ThreatFox/URLhaus/YARAify failure whose message this module wrote.

    Same contract as ``VirusTotalError`` and ``MalwareBazaarError`` (audit
    F-10): the handlers pass these through verbatim because every raise site
    is a sentence written here, a status line, or a ``query_status`` token
    already constrained to ``[a-z0-9_]{1,64}``. None can carry a host path.
    """


THREATFOX_API_BASE = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_API_BASE = "https://urlhaus-api.abuse.ch/v1/"
YARAIFY_API_BASE = "https://yaraify-api.abuse.ch/api/v1/"

ABUSECH_TIMEOUT_ENV = "ABUSECH_API_TIMEOUT"

#: Ceiling on a JSON reply. A busy host on URLhaus, or a widely-matched YARA
#: rule, can return thousands of rows.
ABUSECH_MAX_JSON_BYTES = 64 * 1024 * 1024

#: Rows rendered per section before truncating.
_ROW_LIMIT = 15

_STATUS_TOKEN_RE = re.compile(r"\A[a-z0-9_]{1,64}\Z")


class _AbuseChClient(IntegrationClient):
    """abuse.ch reports most failures inside a 200, via ``query_status``."""

    def map_http_error(self, error: HTTPError) -> Exception:
        if error.code == 401:
            return AbuseChError(
                f"{self.config.name} rejected the Auth-Key. "
                f"Check {ABUSECH_API_KEY_ENV}."
            )
        if error.code == 429:
            return AbuseChError(
                f"{self.config.name} rate limit reached. The API is free under "
                "fair use; slow down and retry."
            )
        return super().map_http_error(error)


def _make_client(name: str, base_url: str) -> _AbuseChClient:
    return _AbuseChClient(
        ProviderConfig(
            name=name,
            base_url=base_url,
            auth_header="Auth-Key",
            credential_noun="Auth-Key",
            # Same key as MalwareBazaar: abuse.ch issues one per account.
            key_config_keys=(ABUSECH_API_KEY_ENV, MB_API_KEY_ENV),
            timeout_config_key=ABUSECH_TIMEOUT_ENV,
            key_hint="Get one free at https://auth.abuse.ch/.",
            max_response_bytes=ABUSECH_MAX_JSON_BYTES,
        ),
        AbuseChError,
    )


threatfox_client = _make_client("ThreatFox", THREATFOX_API_BASE)
urlhaus_client = _make_client("URLhaus", URLHAUS_API_BASE)
yaraify_client = _make_client("YARAify", YARAIFY_API_BASE)

#: ``query_status`` values worth an explanation. Anything absent is reported
#: with its raw token, so a status abuse.ch adds later is visible rather than
#: flattened into "no results".
_STATUS_MESSAGES: dict[str, str] = {
    "no_result": "No records matched.",
    "no_results": "No records matched.",
    "ok": "",
    "illegal_search_term": "The search term was rejected as malformed.",
    "illegal_hash": "The hash was rejected as malformed.",
    "illegal_url": "The URL was rejected as malformed.",
    "illegal_host": "The host was rejected as malformed.",
    "invalid_url": "The URL was rejected as malformed.",
    "invalid_host": "The host was rejected as malformed.",
    "invalid_md5": "That is not a valid MD5 hash.",
    "invalid_sha256": "That is not a valid SHA256 hash.",
    "no_selector": "The query needs a selector.",
    "unknown_query": "The query type was not recognised; the API may have changed.",
    "http_post_expected": (
        "The API expected a POST. This is a bug in binary-mcp, not in your input."
    ),
    "no_auth_key": (
        f"An abuse.ch Auth-Key is required. Set {ABUSECH_API_KEY_ENV} "
        "(free from https://auth.abuse.ch/)."
    ),
    "unknown_auth_key": (
        f"abuse.ch rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
    ),
    "invalid_auth_key": (
        f"abuse.ch rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
    ),
    "unauthorized": f"abuse.ch rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}.",
}


def _status(payload: dict) -> str:
    """The reply's ``query_status``, or "" if it is not a safe token."""
    status = str(payload.get("query_status", "")).strip().lower()
    return status if _STATUS_TOKEN_RE.match(status) else ""


def _status_message(service: str, status: str) -> str:
    """Explain a non-ok ``query_status``, echoing unknown tokens verbatim."""
    if status in _STATUS_MESSAGES and _STATUS_MESSAGES[status]:
        return f"{service}: {_STATUS_MESSAGES[status]}"
    if status:
        return f"{service} returned status: {status}"
    return f"{service} returned an unrecognised response."


def query(client: _AbuseChClient, path: str = "", *, json_body=None, form=None) -> dict:
    """
    Run one abuse.ch query and return its payload, or raise with a sentence.

    Raises:
        AbuseChError: When ``query_status`` is anything other than ``ok``.
    """
    payload = client.request(path, json_body=json_body, form=form).payload
    status = _status(payload)
    if status != "ok":
        raise AbuseChError(_status_message(client.config.name, status))
    return payload


def _rows(payload: dict) -> list[dict]:
    """The ``data`` rows of a reply, tolerating a single-object shape."""
    data = payload.get("data")
    if isinstance(data, dict):
        return [data]
    return [row for row in data if isinstance(row, dict)] if isinstance(data, list) else []


def _scalar(value) -> str:
    """Render one field value as a single line."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return " | ".join(f"{k}={v}" for k, v in sorted(value.items()))
    return str(value).replace("\r", " ").replace("\n", " ")


def _fields(entry: dict, spec: tuple[tuple[str, str], ...], indent: str = "   ") -> list[str]:
    """Render the named fields of one row, skipping the empty ones."""
    lines = []
    for field, label in spec:
        text = _scalar(entry.get(field))
        if text:
            lines.append(f"{indent}{label}: {text}")
    return lines


def _fence(body_lines: list[str], kind: str) -> str:
    """Wrap assembled rows in the F-7 envelope, or return "" when empty."""
    if not body_lines:
        return ""
    return wrap_untrusted("\n".join(body_lines).rstrip("\n"), kind=kind)


# ---------------------------------------------------------------------------
# What is attacker-controlled here
# ---------------------------------------------------------------------------
#
# Nearly everything. ThreatFox IOCs ARE attacker infrastructure, written by
# whoever registered it; URLhaus rows are live malware distribution URLs and
# the file names served from them; YARAify carries submitter file names and
# community rule names and descriptions. A URL is an especially effective
# injection carrier because it is expected to look like opaque text.
#
# abuse.ch-computed values -- hashes, sizes, dates, confidence levels, counts,
# the URL status flag -- stay outside the envelope where the shape of the
# output allows it. That contrast is what makes the boundary informative
# rather than decorative, and it is why urlhaus_lookup_payload leaves the
# payload hashes usable outside the fence while the distribution URLs go in.
#
# ThreatFox is the exception, deliberately. Its answer is a LIST of rows, and
# splitting each row across a fenced and an unfenced block would interleave
# two envelopes per record and be unreadable. So a whole row goes inside,
# computed fields included. Over-fencing costs some contrast; under-fencing
# would put attacker text outside the boundary, and only one of those two
# errors is unsafe. The names below say which half is which so a future reader
# can see the choice rather than infer a mistake.
_THREATFOX_COMPUTED = (
    ("threat_type", "Threat Type"),
    ("first_seen", "First Seen"),
    ("last_seen", "Last Seen"),
)
_THREATFOX_AUTHORED = (
    ("ioc", "IOC"),
    ("malware_printable", "Malware"),
    ("malware", "Malware (tag)"),
    ("malware_alias", "Aliases"),
    ("threat_type_desc", "Threat Description"),
    ("reporter", "Reporter"),
    ("reference", "Reference"),
    ("tags", "Tags"),
)

_URLHAUS_URL_TRUSTED = (
    ("id", "URLhaus ID"),
    ("url_status", "Status"),
    ("date_added", "Added"),
    ("threat", "Threat"),
    ("host", "Host"),
)
_URLHAUS_URL_UNTRUSTED = (
    ("url", "URL"),
    ("reporter", "Reporter"),
    ("tags", "Tags"),
    ("larted", "Abuse reported"),
)

_URLHAUS_PAYLOAD_TRUSTED = (
    ("sha256_hash", "SHA256"),
    ("md5_hash", "MD5"),
    ("file_size", "Size (bytes)"),
    ("file_type", "File Type"),
    ("firstseen", "First Seen"),
    ("signature", "Signature"),
)

_YARAIFY_TRUSTED = (
    ("sha256_hash", "SHA256"),
    ("md5_hash", "MD5"),
    ("sha1_hash", "SHA1"),
    ("file_size", "Size (bytes)"),
    ("file_type_mime", "MIME Type"),
    ("first_seen", "First Seen"),
    ("last_seen", "Last Seen"),
    ("imphash", "imphash"),
    ("tlsh", "TLSH"),
    ("telfhash", "telfhash"),
    ("gimphash", "gimphash"),
    ("dhash_icon", "Icon dhash"),
)

#: YARAify corpus pivots, as (tool argument, API query). Every one takes its
#: value in ``search_term``. Pinned as a table for the same reason as
#: MB_SEARCH_PIVOTS: one reviewable place to check against the abuse.ch docs.
YARAIFY_PIVOTS: tuple[tuple[str, str], ...] = (
    ("yara_rule", "get_yara"),
    ("imphash", "query_imphash"),
    ("tlsh", "query_tlsh"),
    ("telfhash", "query_telfhash"),
    ("gimphash", "query_gimphash"),
    ("dhash_icon", "query_dhash_icon"),
    ("clamav", "query_clamav"),
)


def register_abusech_tools(app, session_manager=None):
    """
    Register the ThreatFox, URLhaus and YARAify tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
    """
    from src.utils.security import safe_error_message

    @app.tool()
    def abusech_check_api() -> str:
        """
        Check the abuse.ch Auth-Key against ThreatFox, URLhaus and YARAify.

        One abuse.ch Auth-Key covers MalwareBazaar, ThreatFox, URLhaus and
        YARAify. Keys are free from https://auth.abuse.ch/ and are MANDATORY --
        abuse.ch removed anonymous access, so an unauthenticated client gets no
        data rather than an obvious error.

        Returns:
            Key status and one live probe per service.
        """
        try:
            output = ["ABUSE.CH API STATUS"]

            masked = threatfox_client.masked_key()
            if not masked:
                output.append("Auth-Key not configured")
                output.append("")
                output.append("1. Get a free key: https://auth.abuse.ch/")
                output.append("2. Add it to the .env file in the project root:")
                output.append(f"   {ABUSECH_API_KEY_ENV}=your_auth_key_here")
                output.append("")
                output.append(
                    "This one key also covers MalwareBazaar (mb_* tools)."
                )
                return "\n".join(output)

            output.append(f"Auth-Key configured: {masked}")
            output.append("")

            probes = (
                ("ThreatFox", threatfox_client, "",
                 {"json_body": {"query": "get_iocs", "days": 1}}),
                ("URLhaus", urlhaus_client, "host/",
                 {"form": {"host": "urlhaus.abuse.ch"}}),
                ("YARAify", yaraify_client, "",
                 {"json_body": {"query": "recent_yararules"}}),
            )
            for label, client, path, kwargs in probes:
                try:
                    payload = query(client, path, **kwargs)
                    output.append(f"{label}: reachable ({len(_rows(payload))} row(s))")
                except AbuseChError as e:
                    # A "no results" answer still proves the key was accepted.
                    output.append(f"{label}: {e}")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"abusech_check_api failed: {e}")
            return safe_error_message("Failed to check abuse.ch status", e)

    # -- ThreatFox --------------------------------------------------------

    @app.tool()
    def threatfox_lookup_ioc(ioc: str) -> str:
        """
        Identify an IOC on ThreatFox: which malware family does it belong to?

        Takes a domain, URL, IP:port, or hash and returns the malware family,
        threat type and confidence level ThreatFox has recorded for it. Pair it
        with extract_iocs_with_context to turn strings pulled out of a binary
        into named families.

        Args:
            ioc: The indicator to look up (domain, URL, ip:port, or hash)

        Returns:
            Matching ThreatFox records.

        Example:
            threatfox_lookup_ioc("evil-domain.test")
            threatfox_lookup_ioc("139.180.203.104:443")
        """
        try:
            ioc = (ioc or "").strip()
            if not ioc:
                return "Error: Provide an IOC to look up"

            payload = query(
                threatfox_client,
                json_body={"query": "search_ioc", "search_term": ioc},
            )
            return _render_threatfox(f"THREATFOX IOC LOOKUP\nIOC: {ioc}", payload)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"threatfox_lookup_ioc failed: {e}")
            return safe_error_message("Failed to look up IOC", e)

    @app.tool()
    def threatfox_lookup_hash(file_hash: str) -> str:
        """
        Find the ThreatFox IOCs associated with a malware sample hash.

        Args:
            file_hash: MD5, SHA1 or SHA256 of the sample

        Returns:
            IOCs ThreatFox links to that sample (C2 addresses, URLs, domains).

        Example:
            threatfox_lookup_hash("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d")
        """
        try:
            digest = normalise_hash(file_hash)
            payload = query(
                threatfox_client,
                json_body={"query": "search_hash", "hash": digest},
            )
            return _render_threatfox(
                f"THREATFOX HASH LOOKUP\nHash: {digest}", payload
            )

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"threatfox_lookup_hash failed: {e}")
            return safe_error_message("Failed to look up hash", e)

    @app.tool()
    def threatfox_by_malware(malware: str, limit: int = 25) -> str:
        """
        List the current IOCs ThreatFox holds for one malware family.

        Useful for building a blocklist or a hunting pivot for a family you
        have just identified statically.

        Args:
            malware: Family name as ThreatFox knows it, e.g. "Cobalt Strike",
                "AgentTesla", or a Malpedia-style id like "win.emotet"
            limit: Maximum IOCs to return (1-1000, default 25)

        Returns:
            IOCs for that family with types, confidence and first-seen dates.

        Example:
            threatfox_by_malware("Cobalt Strike", limit=50)
        """
        try:
            malware = (malware or "").strip()
            if not malware:
                return "Error: Provide a malware family name"
            try:
                limit = max(1, min(int(limit), 1000))
            except (TypeError, ValueError):
                return f"Error: limit must be an integer, got {limit!r}"

            payload = query(
                threatfox_client,
                json_body={"query": "malwareinfo", "malware": malware, "limit": limit},
            )
            return _render_threatfox(
                f"THREATFOX MALWARE FAMILY\nFamily: {malware}\nLimit: {limit}", payload
            )

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"threatfox_by_malware failed: {e}")
            return safe_error_message("Failed to query malware family", e)

    # -- URLhaus ----------------------------------------------------------

    @app.tool()
    def urlhaus_lookup_url(url: str) -> str:
        """
        Look up a URL on URLhaus: is it a known malware distribution point?

        Returns the URL's status, the threat it serves, and the hashes of the
        payloads observed at it -- which you can then fetch with mb_download or
        look up with vt_lookup.

        Args:
            url: The full URL to look up

        Returns:
            URLhaus record with payload hashes.

        Example:
            urlhaus_lookup_url("http://evil.test/payload.exe")
        """
        try:
            url = (url or "").strip()
            if not url:
                return "Error: Provide a URL to look up"

            payload = query(urlhaus_client, "url/", form={"url": url})
            rows = _rows(payload)
            entry = rows[0] if rows else payload

            output = ["URLHAUS URL LOOKUP"]
            output.extend(_fields(entry, _URLHAUS_URL_TRUSTED, indent="  "))

            body = _fields(entry, _URLHAUS_URL_UNTRUSTED, indent="  ")

            payloads = entry.get("payloads")
            if isinstance(payloads, list) and payloads:
                output.append("")
                output.append(f"Payloads observed ({len(payloads)}):")
                for item in payloads[:_ROW_LIMIT]:
                    if not isinstance(item, dict):
                        continue
                    output.extend(_fields(item, (
                        ("response_sha256", "SHA256"),
                        ("response_md5", "MD5"),
                        ("response_size", "Size (bytes)"),
                        ("file_type", "File Type"),
                        ("signature", "Signature"),
                    )))
                    name = _scalar(item.get("filename"))
                    if name:
                        body.append(f"  Served filename: {name}")
                    output.append("")
                if len(payloads) > _ROW_LIMIT:
                    output.append(f"  ... and {len(payloads) - _ROW_LIMIT} more")

            fenced = _fence(body, "URLhaus URL, reporter and served file names")
            if fenced:
                output.append("")
                output.append(fenced)

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"urlhaus_lookup_url failed: {e}")
            return safe_error_message("Failed to look up URL", e)

    @app.tool()
    def urlhaus_lookup_host(host: str) -> str:
        """
        Look up a domain or IP on URLhaus: what malware has it distributed?

        The natural next call after extract_iocs_with_context turns up a domain
        or IP in a sample.

        Args:
            host: Domain name or IP address

        Returns:
            The host's URLhaus reputation and the malware URLs seen on it.

        Example:
            urlhaus_lookup_host("evil.test")
            urlhaus_lookup_host("192.0.2.10")
        """
        try:
            host = (host or "").strip()
            if not host:
                return "Error: Provide a host to look up"

            payload = query(urlhaus_client, "host/", form={"host": host})

            output = ["URLHAUS HOST LOOKUP", f"Host: {host}"]
            output.extend(_fields(payload, (
                ("firstseen", "First Seen"),
                ("url_count", "Known malware URLs"),
                ("blacklists", "Blocklist status"),
            ), indent="  "))
            output.append("")

            urls = payload.get("urls")
            body: list[str] = []
            if isinstance(urls, list) and urls:
                output.append(f"Malware URLs ({len(urls)} known):")
                for item in urls[:_ROW_LIMIT]:
                    if not isinstance(item, dict):
                        continue
                    body.extend(_fields(item, _URLHAUS_URL_TRUSTED + _URLHAUS_URL_UNTRUSTED))
                    body.append("")
                if len(urls) > _ROW_LIMIT:
                    output.append(f"  (showing {_ROW_LIMIT})")

            fenced = _fence(body, "URLhaus malware distribution URLs")
            if fenced:
                output.append(fenced)
            elif not body:
                output.append("No malware URLs recorded for this host.")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"urlhaus_lookup_host failed: {e}")
            return safe_error_message("Failed to look up host", e)

    @app.tool()
    def urlhaus_lookup_payload(file_hash: str) -> str:
        """
        Look up a sample on URLhaus: where was it distributed from?

        The reverse of urlhaus_lookup_host -- given a hash you already have,
        find the URLs that served it.

        Args:
            file_hash: MD5 or SHA256 of the sample (URLhaus indexes both)

        Returns:
            The payload record and the URLs it was served from.

        Example:
            urlhaus_lookup_payload("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d")
        """
        try:
            digest = normalise_hash(file_hash)
            if len(digest) == 40:
                return (
                    "Error: URLhaus indexes payloads by MD5 or SHA256; "
                    "a SHA1 cannot be looked up."
                )
            field = "sha256_hash" if len(digest) == 64 else "md5_hash"

            payload = query(urlhaus_client, "payload/", form={field: digest})

            output = ["URLHAUS PAYLOAD LOOKUP", f"Hash: {digest}"]
            output.extend(_fields(payload, _URLHAUS_PAYLOAD_TRUSTED, indent="  "))

            virustotal = payload.get("virustotal")
            if isinstance(virustotal, dict):
                ratio = _scalar(virustotal.get("result"))
                if ratio:
                    output.append(f"  VirusTotal: {ratio}")

            urls = payload.get("urls")
            body: list[str] = []
            if isinstance(urls, list) and urls:
                output.append("")
                output.append(f"Distribution URLs ({len(urls)}):")
                for item in urls[:_ROW_LIMIT]:
                    if not isinstance(item, dict):
                        continue
                    body.extend(_fields(item, _URLHAUS_URL_TRUSTED + _URLHAUS_URL_UNTRUSTED))
                    body.append("")
                if len(urls) > _ROW_LIMIT:
                    output.append(f"  (showing {_ROW_LIMIT})")

            fenced = _fence(body, "URLhaus malware distribution URLs")
            if fenced:
                output.append(fenced)

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"urlhaus_lookup_payload failed: {e}")
            return safe_error_message("Failed to look up payload", e)

    # -- YARAify ----------------------------------------------------------

    @app.tool()
    def yaraify_lookup_hash(file_hash: str) -> str:
        """
        Ask YARAify which public YARA rules match a sample.

        Answers "has anyone already written detection for this?" without you
        uploading anything -- the lookup is by hash against files YARAify has
        already scanned.

        Args:
            file_hash: MD5, SHA1, SHA256 or SHA3-384 of the sample

        Returns:
            Matching YARA rules, ClamAV signatures and file metadata.

        Example:
            yaraify_lookup_hash("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d")
        """
        try:
            digest = normalise_hash(file_hash, allow_sha3_384=True)
            payload = query(
                yaraify_client,
                json_body={"query": "lookup_hash", "search_term": digest},
            )

            rows = _rows(payload)
            entry = rows[0] if rows else {}

            output = ["YARAIFY HASH LOOKUP", f"Hash: {digest}"]
            output.extend(_fields(entry, _YARAIFY_TRUSTED, indent="  "))

            body: list[str] = []
            name = _scalar(entry.get("file_name"))
            if name:
                body.append(f"  Submitted name: {name}")

            matches = entry.get("static_results")
            if isinstance(matches, list) and matches:
                output.append("")
                output.append(f"YARA rules matched ({len(matches)}):")
                for match in matches[:_ROW_LIMIT]:
                    if isinstance(match, dict):
                        body.extend(_fields(match, (
                            ("rule_name", "Rule"),
                            ("author", "Author"),
                            ("description", "Description"),
                            ("tlp", "TLP"),
                        )))
                        body.append("")
                    else:
                        body.append(f"   Rule: {_scalar(match)}")
                if len(matches) > _ROW_LIMIT:
                    output.append(f"  (showing {_ROW_LIMIT})")
            else:
                output.append("")
                output.append("No public YARA rules matched this sample.")

            clamav = entry.get("clamav_results")
            if isinstance(clamav, list) and clamav:
                body.append(f"   ClamAV: {_scalar(clamav[:10])}")

            fenced = _fence(body, "YARAify community rule names and submitted file names")
            if fenced:
                output.append("")
                output.append(fenced)

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"yaraify_lookup_hash failed: {e}")
            return safe_error_message("Failed to look up hash", e)

    @app.tool()
    def yaraify_search(
        yara_rule: str = "",
        imphash: str = "",
        tlsh: str = "",
        telfhash: str = "",
        gimphash: str = "",
        dhash_icon: str = "",
        clamav: str = "",
    ) -> str:
        """
        Find files in the YARAify corpus by rule name or structural hash.

        Exactly ONE pivot per call -- YARAify has a separate query per selector.

        This is the counterpart to this server's own YARA generation and
        similarity hashing: take the imphash or TLSH from compute_similarity_hashes,
        or the name of a rule generate_yara_rule_from_session produced, and ask
        what else in the public corpus it matches.

        Args:
            yara_rule: Name of a YARA rule, e.g. "MALWARE_Win_Neshta"
            imphash: PE import hash
            tlsh: TLSH fuzzy hash
            telfhash: telfhash (ELF import hash)
            gimphash: gimphash (Go binary import hash)
            dhash_icon: Perceptual hash of the embedded icon
            clamav: ClamAV signature name

        Returns:
            Matching files with hashes and metadata.

        Example:
            yaraify_search(yara_rule="MALWARE_Win_Neshta")
            yaraify_search(imphash="f34d5f2d4577ed6d9ceec516c1f5a744")
        """
        try:
            values = {
                "yara_rule": yara_rule,
                "imphash": imphash,
                "tlsh": tlsh,
                "telfhash": telfhash,
                "gimphash": gimphash,
                "dhash_icon": dhash_icon,
                "clamav": clamav,
            }
            supplied = {
                argument: values[argument].strip()
                for argument, _query in YARAIFY_PIVOTS
                if values.get(argument) and values[argument].strip()
            }

            if not supplied:
                names = ", ".join(argument for argument, _q in YARAIFY_PIVOTS)
                return f"Error: Provide exactly one search pivot. One of: {names}"
            if len(supplied) > 1:
                return (
                    "YARAify accepts one pivot per query; got "
                    f"{', '.join(sorted(supplied))}. Call yaraify_search once per pivot."
                )

            argument, value = next(iter(supplied.items()))
            api_query = next(q for a, q in YARAIFY_PIVOTS if a == argument)

            payload = query(
                yaraify_client,
                json_body={"query": api_query, "search_term": value},
            )
            rows = _rows(payload)

            output = ["YARAIFY SEARCH", f"Pivot: {argument}", ""]
            if not rows:
                output.append("No matching files.")
                return "\n".join(output)

            output.append(f"Found {len(rows)} file(s):")
            output.append("")

            body: list[str] = []
            for index, entry in enumerate(rows[:_ROW_LIMIT], 1):
                name = _scalar(entry.get("file_name")) or "Unknown"
                body.append(f"{index}. {name}")
                body.extend(_fields(entry, _YARAIFY_TRUSTED))
                body.append("")

            fenced = _fence(body, "YARAify search results (submitter-supplied file names)")
            if fenced:
                output.append(fenced)
            if len(rows) > _ROW_LIMIT:
                output.append("")
                output.append(f"(showing {_ROW_LIMIT} of {len(rows)})")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except AbuseChError as e:
            return f"abuse.ch error: {e}"
        except Exception as e:
            logger.error(f"yaraify_search failed: {e}")
            return safe_error_message("Failed to search YARAify", e)

    logger.info("Registered 9 abuse.ch tools (ThreatFox, URLhaus, YARAify)")


def _render_threatfox(header: str, payload: dict) -> str:
    """Render ThreatFox rows, fencing the attacker-authored half."""
    rows = _rows(payload)
    output = [header, ""]

    if not rows:
        output.append("No ThreatFox records matched.")
        return "\n".join(output)

    output.append(f"Found {len(rows)} record(s):")
    output.append("")

    body: list[str] = []
    for index, entry in enumerate(rows[:_ROW_LIMIT], 1):
        # Lead each row with what ThreatFox computed -- the id, the kind of
        # indicator and the confidence -- so the row is identifiable at a
        # glance, then the attacker-authored content it is about.
        ioc_type = _scalar(entry.get("ioc_type")) or "ioc"
        record_id = _scalar(entry.get("id"))
        confidence = _scalar(entry.get("confidence_level"))
        marker = ", ".join(
            part for part in (
                f"ThreatFox ID {record_id}" if record_id else "",
                f"confidence {confidence}" if confidence else "",
            ) if part
        )
        body.append(f"{index}. {ioc_type}" + (f" ({marker})" if marker else ""))
        body.extend(_fields(entry, _THREATFOX_AUTHORED))
        body.extend(_fields(entry, _THREATFOX_COMPUTED))
        body.append("")

    fenced = _fence(body, "ThreatFox IOCs (attacker infrastructure and community labels)")
    if fenced:
        output.append(fenced)
    if len(rows) > _ROW_LIMIT:
        output.append("")
        output.append(f"(showing {_ROW_LIMIT} of {len(rows)})")

    return "\n".join(output)
