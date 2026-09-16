"""
MalwareBazaar (abuse.ch) integration for collecting and hunting malware samples.

MalwareBazaar is the sample-acquisition half of what VirusTotal does not give
you on a free key: it serves the actual bytes, and it lets you pivot on the
hashes a reverse-engineering session already produces -- imphash, TLSH,
telfhash, gimphash, icon dhash, ClamAV signature, YARA rule name.

Tools:
- ``mb_check_api``  -- is the Auth-Key configured and accepted
- ``mb_lookup``     -- metadata for one hash (``query=get_info``)
- ``mb_search``     -- corpus pivot by tag/signature/file type/imphash/...
- ``mb_recent``     -- the newest uploads (``query=get_recent``)
- ``mb_download``   -- fetch the sample itself (``query=get_file``), opt-in

API shape (https://bazaar.abuse.ch/api/):
- Base URL ``https://mb-api.abuse.ch/api/v1/``
- EVERY query is an ``application/x-www-form-urlencoded`` POST with a ``query``
  field naming the operation.
- Every query needs an ``Auth-Key`` header. abuse.ch made this mandatory for
  the whole API -- an unauthenticated request no longer works at all, which is
  the single most common reason an older MalwareBazaar client suddenly stops
  returning data. Keys are free from https://auth.abuse.ch/.
- JSON replies carry ``query_status``; ``"ok"`` means ``data`` is populated.
- ``get_file`` is the exception: on success the body is a **zip archive**, not
  JSON, and the archive is encrypted with the password ``infected``.

Outbound-data posture. Unlike the VirusTotal module, these calls are POSTs --
that is the API's design, not a submission path. What goes in the body is a
hash, a tag, or a rule name, and nothing else: there is no ``add_file``/upload
call here, and ``mb_lookup(file_path=...)`` hashes the file locally and sends
only the digest. ``tests/test_mb_tools.py`` pins that the request body is built
exclusively from scalar form fields, so no sample bytes can reach the wire.

Downloading. ``mb_download`` writes malware to disk, which nothing else in this
server does. It is therefore off unless the operator sets
``MB_ALLOW_DOWNLOAD=1``, it writes only inside ``~/.binary_mcp_output/malwarebazaar``,
and it leaves the archive **encrypted** -- the tool never extracts it, so
nothing on the host ever holds a runnable copy that this server put there.
"""

import hashlib
import json
import logging
import re
from pathlib import Path
from urllib.error import HTTPError

from src.integrations import IntegrationClient, IntegrationError, ProviderConfig
from src.integrations.hashes import normalise_hash as _normalise_hash
from src.tools.error_hygiene import safe_path_error
from src.utils.formatters import wrap_untrusted

logger = logging.getLogger(__name__)


class MalwareBazaarError(IntegrationError):
    """
    A MalwareBazaar failure whose message this module wrote itself.

    Same contract as :class:`src.tools.vt_tools.VirusTotalError` (audit F-10):
    the handlers pass these through verbatim because this module authored the
    sentence, while every other exception goes to ``safe_error_message``.
    """


MB_API_BASE = "https://mb-api.abuse.ch/api/v1/"
MB_API_KEY_ENV = "MB_API_KEY"
MB_TIMEOUT_ENV = "MB_API_TIMEOUT"
MB_ALLOW_DOWNLOAD_ENV = "MB_ALLOW_DOWNLOAD"
MB_MAX_DOWNLOAD_MB_ENV = "MB_MAX_DOWNLOAD_MB"

MB_DEFAULT_TIMEOUT = 30

#: Where ``mb_download`` is allowed to write. Same root as the memory dumps in
#: dynamic_tools (``~/.binary_mcp_output``), which is already unioned into the
#: path allow-list by ``security.server_artifact_dirs()`` -- so a downloaded
#: archive is reachable by the rest of the server without widening anything.
MB_DOWNLOAD_DIR = Path.home() / ".binary_mcp_output" / "malwarebazaar"

#: abuse.ch ships every sample inside a zip encrypted with this password, so
#: that a download cannot be executed by accident and so that AV on the
#: analyst's own machine does not eat it in transit.
MB_ZIP_PASSWORD = "infected"  # nosec B105 - documented public constant, not a credential

#: Ceiling on a JSON reply. get_recent(selector="100") is the largest.
MB_MAX_JSON_BYTES = 64 * 1024 * 1024

MB_DEFAULT_MAX_DOWNLOAD_MB = 128

_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

#: ``query_status`` is an API-authored enum, but it still arrives over the
#: network, so it is only ever echoed after passing this.
_STATUS_TOKEN_RE = re.compile(r"\A[a-z0-9_]{1,64}\Z")

#: The corpus pivots ``mb_search`` exposes, as (tool argument, API query,
#: API field). Kept as one table because these three names differ per pivot in
#: ways that are easy to get subtly wrong -- ``get_siginfo`` takes
#: ``signature`` while ``get_imphash`` takes ``imphash`` -- and a table makes
#: the whole mapping reviewable against the abuse.ch docs in one glance.
MB_SEARCH_PIVOTS: tuple[tuple[str, str, str], ...] = (
    ("tag", "get_taginfo", "tag"),
    ("signature", "get_siginfo", "signature"),
    ("file_type", "get_file_type", "file_type"),
    ("clamav", "get_clamavinfo", "clamav"),
    ("imphash", "get_imphash", "imphash"),
    ("tlsh", "get_tlsh", "tlsh"),
    ("telfhash", "get_telfhash", "telfhash"),
    ("gimphash", "get_gimphash", "gimphash"),
    ("dhash_icon", "get_dhash_icon", "dhash_icon"),
    ("yara_rule", "get_yarainfo", "yara_rule"),
)

MB_SEARCH_MAX_LIMIT = 1000

#: ``query_status`` values worth an explanation rather than an echo. Anything
#: not listed is reported with its raw token so a new status is visible rather
#: than swallowed.
_STATUS_MESSAGES: dict[str, str] = {
    "no_results": "No samples matched.",
    "hash_not_found": "Hash not found in MalwareBazaar.",
    "file_not_found": "MalwareBazaar has no downloadable file for that SHA256.",
    "tag_not_found": "No samples carry that tag.",
    "signature_not_found": "No samples carry that malware family signature.",
    "illegal_hash": "MalwareBazaar rejected the hash format.",
    "illegal_sha256_hash": "MalwareBazaar requires a full SHA256 for this query.",
    "illegal_tag": "MalwareBazaar rejected the tag.",
    "illegal_signature": "MalwareBazaar rejected the signature.",
    "illegal_yara_rule": "MalwareBazaar rejected the YARA rule name.",
    "illegal_imphash": "MalwareBazaar rejected the imphash.",
    "illegal_limit": "MalwareBazaar rejected the limit value.",
    "limit_exceeded": f"Limit is capped at {MB_SEARCH_MAX_LIMIT}.",
    "no_selector_provided": "MalwareBazaar needs a selector for this query.",
    "unknown_query": (
        "MalwareBazaar does not recognise that query; the API may have changed."
    ),
    "http_post_expected": (
        "MalwareBazaar expected a POST. This is a bug in binary-mcp, not in your input."
    ),
    "no_auth_key": (
        f"MalwareBazaar requires an Auth-Key. Set {MB_API_KEY_ENV} "
        "(free from https://auth.abuse.ch/)."
    ),
    "unknown_auth_key": (
        f"MalwareBazaar rejected the Auth-Key. Check {MB_API_KEY_ENV}."
    ),
    "invalid_auth_key": (
        f"MalwareBazaar rejected the Auth-Key. Check {MB_API_KEY_ENV}."
    ),
    "unauthorized": (
        f"MalwareBazaar rejected the Auth-Key. Check {MB_API_KEY_ENV}."
    ),
}


class _MalwareBazaarClient(IntegrationClient):
    """abuse.ch's status codes; most failures arrive inside a 200 instead."""

    def map_http_error(self, error: HTTPError) -> Exception:
        if error.code == 401:
            return MalwareBazaarError(
                f"MalwareBazaar rejected the Auth-Key. Check {MB_API_KEY_ENV}."
            )
        if error.code == 429:
            return MalwareBazaarError(
                "MalwareBazaar rate limit reached. The API is free under fair "
                "use; slow down and retry."
            )
        return super().map_http_error(error)


_client = _MalwareBazaarClient(
    ProviderConfig(
        name="MalwareBazaar",
        base_url=MB_API_BASE,
        auth_header="Auth-Key",
        credential_noun="Auth-Key",
        key_config_keys=(MB_API_KEY_ENV,),
        timeout_config_key=MB_TIMEOUT_ENV,
        key_hint="Get one free at https://auth.abuse.ch/.",
        default_timeout=MB_DEFAULT_TIMEOUT,
        max_response_bytes=MB_MAX_JSON_BYTES,
    ),
    MalwareBazaarError,
)


def _get_api_key() -> str | None:
    return _client.api_key()


def _download_allowed() -> bool:
    from src.utils.config import get_config_bool
    return get_config_bool(MB_ALLOW_DOWNLOAD_ENV, False)


def _max_download_bytes() -> int:
    from src.utils.config import get_config_int
    megabytes = get_config_int(MB_MAX_DOWNLOAD_MB_ENV, MB_DEFAULT_MAX_DOWNLOAD_MB)
    return max(1, min(megabytes, 2048)) * 1024 * 1024


def normalise_hash(file_hash: str, sha256_only: bool = False) -> str:
    """
    Validate a hash before it becomes a request field.

    Thin wrapper over the shared validator so this module's public surface is
    unchanged; see :func:`src.integrations.hashes.normalise_hash`.
    """
    return _normalise_hash(file_hash, sha256_only=sha256_only)


def _request(fields: dict[str, str | int], expect_json: bool = True) -> tuple[dict, bytes]:
    """
    POST one form-encoded query to MalwareBazaar.

    Args:
        fields: Form fields. Every value is coerced to ``str`` and urlencoded
            by the shared client; callers never build the body themselves,
            which is what keeps file content structurally unable to reach it.
        expect_json: ``False`` for ``get_file``, whose success body is a zip.

    Returns:
        ``(parsed_json, raw_body)``. ``parsed_json`` is ``{}`` when the body
        was not JSON, which for ``get_file`` is the success case.

    Raises:
        ValueError: If the Auth-Key is not configured.
        MalwareBazaarError: On a transport or protocol failure.
    """
    response = _client.request(
        form=fields,
        expect_json=expect_json,
        max_bytes=None if expect_json else _max_download_bytes(),
    )
    return response.payload, response.raw


def _status(payload: dict) -> str:
    """Return the reply's ``query_status``, or "" if it is not a safe token."""
    status = str(payload.get("query_status", "")).strip().lower()
    return status if _STATUS_TOKEN_RE.match(status) else ""


def _status_message(status: str) -> str:
    """Explain a non-ok ``query_status``, echoing unknown tokens verbatim."""
    if status in _STATUS_MESSAGES:
        return _STATUS_MESSAGES[status]
    if status:
        return f"MalwareBazaar returned status: {status}"
    return "MalwareBazaar returned an unrecognised response."


def query(fields: dict[str, str | int]) -> list[dict]:
    """
    Run one JSON MalwareBazaar query and return its ``data`` rows.

    Raises:
        MalwareBazaarError: With a curated sentence when ``query_status`` is
            anything other than ``ok``.
    """
    payload, _ = _request(fields)
    status = _status(payload)
    if status != "ok":
        raise MalwareBazaarError(_status_message(status))

    data = payload.get("data")
    if isinstance(data, dict):        # get_info returns a one-element list, but
        return [data]                 # be tolerant if that ever changes
    return data if isinstance(data, list) else []


def download_sample(sha256: str) -> bytes:
    """
    Fetch one sample as the password-protected zip abuse.ch serves.

    Returns the archive bytes untouched: this function never extracts, and no
    caller in this module does either.
    """
    sha256 = normalise_hash(sha256, sha256_only=True)
    payload, raw = _request({"query": "get_file", "sha256_hash": sha256}, expect_json=False)

    # A JSON body here means the request failed; a zip body means it worked.
    if payload:
        raise MalwareBazaarError(_status_message(_status(payload)))

    if not raw.startswith(b"PK"):
        raise MalwareBazaarError(
            "MalwareBazaar returned something that is not a zip archive"
        )
    return raw


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
#
# Which fields are attacker-controlled is the whole question for F-7 fencing.
#
#   Submitter/sample-authored: file_name (whatever the uploader called it),
#   tags, comments, and the `signature` family label (community-assigned).
#   Also the YARA rule names and vendor-intel blurbs, which are third-party
#   text relayed verbatim.
#
#   abuse.ch/tool-computed: hashes, file_size, first_seen/last_seen,
#   file_type_mime, imphash/tlsh/ssdeep, the download counters.
#
# Only the first group goes inside the envelope. Keeping the second group
# outside is what makes the boundary informative rather than decorative.
_UNTRUSTED_FIELDS: tuple[tuple[str, str], ...] = (
    ("file_name", "File Name"),
    ("signature", "Signature"),
    ("reporter", "Reporter"),
    ("delivery_method", "Delivery Method"),
)

_TRUSTED_FIELDS: tuple[tuple[str, str], ...] = (
    ("sha256_hash", "SHA256"),
    ("sha1_hash", "SHA1"),
    ("md5_hash", "MD5"),
    ("file_size", "Size (bytes)"),
    ("file_type", "File Type"),
    ("file_type_mime", "MIME Type"),
    ("first_seen", "First Seen"),
    ("last_seen", "Last Seen"),
    ("imphash", "imphash"),
    ("tlsh", "TLSH"),
    ("telfhash", "telfhash"),
    ("gimphash", "gimphash"),
    ("ssdeep", "ssdeep"),
    ("dhash_icon", "Icon dhash"),
)


def _scalar(value) -> str:
    """Render one MalwareBazaar field value as a single line."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value).replace("\r", " ").replace("\n", " ")


def _trusted_lines(entry: dict) -> list[str]:
    lines = []
    for field, label in _TRUSTED_FIELDS:
        text = _scalar(entry.get(field))
        if text:
            lines.append(f"  {label}: {text}")
    return lines


def _untrusted_lines(entry: dict) -> list[str]:
    """Submitter-authored fields, for the caller to fence."""
    lines = []
    for field, label in _UNTRUSTED_FIELDS:
        text = _scalar(entry.get(field))
        if text:
            lines.append(f"  {label}: {text}")

    tags = entry.get("tags")
    if tags:
        lines.append(f"  Tags: {_scalar(tags)}")

    yara_rules = entry.get("yara_rules")
    if isinstance(yara_rules, list) and yara_rules:
        names = [str(r.get("rule_name", r)) if isinstance(r, dict) else str(r)
                 for r in yara_rules[:10]]
        lines.append(f"  YARA Rules: {', '.join(names)}")

    return lines


def _row(entry: dict, index: int | None = None) -> list[str]:
    """One search-result row: submitter-authored text only (caller fences it)."""
    name = _scalar(entry.get("file_name")) or "Unknown"
    prefix = f"{index}. " if index is not None else ""
    lines = [f"{prefix}{name}"]
    for field, label in (("sha256_hash", "SHA256"), ("file_type", "Type"),
                         ("signature", "Signature"), ("first_seen", "First Seen")):
        text = _scalar(entry.get(field))
        if text:
            lines.append(f"   {label}: {text}")
    tags = entry.get("tags")
    if tags:
        lines.append(f"   Tags: {_scalar(tags)}")
    return lines


def register_mb_tools(app, session_manager=None):
    """
    Register MalwareBazaar tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
        sanitize_output_path,
    )

    @app.tool()
    def mb_check_api() -> str:
        """
        Check that the MalwareBazaar Auth-Key is configured and accepted.

        abuse.ch requires an Auth-Key on every MalwareBazaar API call. Keys are
        free from https://auth.abuse.ch/. An unauthenticated client gets no
        data at all, so run this first if lookups return nothing.

        Returns:
            Key status and the result of one cheap live query.
        """
        try:
            output = ["MALWAREBAZAAR API STATUS"]

            api_key = _get_api_key()
            if not api_key:
                output.append("Auth-Key not configured")
                output.append("")
                output.append("1. Get a free key: https://auth.abuse.ch/")
                output.append("2. Add it to the .env file in the project root:")
                output.append(f"   {MB_API_KEY_ENV}=your_auth_key_here")
                output.append(f"   (or export {MB_API_KEY_ENV}=... in the environment)")
                return "\n".join(output)

            masked = api_key[:4] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            output.append(f"Auth-Key configured: {masked}")

            try:
                rows = query({"query": "get_taginfo", "tag": "exe", "limit": 1})
                output.append("API connection successful")
                output.append(f"Test query (tag:exe, limit 1) returned {len(rows)} sample(s)")
            except MalwareBazaarError as e:
                # "no results" still proves the key was accepted.
                output.append(f"API test returned: {e}")

            output.append("")
            if _download_allowed():
                output.append(f"Sample download: ENABLED ({MB_ALLOW_DOWNLOAD_ENV} is set)")
                output.append(f"  Download directory: {MB_DOWNLOAD_DIR}")
                output.append(
                    f"  Max archive size: {_max_download_bytes() // (1024 * 1024)}MB "
                    f"({MB_MAX_DOWNLOAD_MB_ENV})"
                )
            else:
                output.append(
                    f"Sample download: DISABLED (set {MB_ALLOW_DOWNLOAD_ENV}=1 to enable)"
                )

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except MalwareBazaarError as e:
            return f"MalwareBazaar error: {e}"
        except Exception as e:
            logger.error(f"mb_check_api failed: {e}")
            return safe_error_message("Failed to check MalwareBazaar status", e)

    @app.tool()
    def mb_lookup(file_hash: str = "", file_path: str = "") -> str:
        """
        Look up a sample on MalwareBazaar by hash or local file.

        Returns the family signature, tags, file type, the fuzzy/structural
        hashes you can pivot on (imphash, TLSH, ssdeep, icon dhash) and the
        YARA rules that matched.

        Nothing is uploaded: with file_path the file is hashed locally and only
        the SHA256 is sent.

        Args:
            file_hash: MD5, SHA1 or SHA256 to look up
            file_path: Path to a local file (hashed automatically)

        Returns:
            Sample metadata, or a note that the hash is unknown.

        Example:
            mb_lookup(file_hash="094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d")
            mb_lookup(file_path="suspicious.exe")
        """
        try:
            if not file_hash and not file_path:
                return "Error: Provide either file_hash or file_path"

            output = ["MALWAREBAZAAR LOOKUP"]

            if file_path:
                safe_path = sanitize_binary_path(file_path)
                output.append(f"File: {safe_path}")
                digest = hashlib.sha256()
                with open(safe_path, "rb") as handle:
                    while chunk := handle.read(8192):
                        digest.update(chunk)
                file_hash = digest.hexdigest()
                output.append(f"SHA256: {file_hash}")
            else:
                file_hash = normalise_hash(file_hash)
                output.append(f"Hash: {file_hash}")

            output.append("")

            rows = query({"query": "get_info", "hash": file_hash})
            if not rows:
                output.append("Hash not found in MalwareBazaar.")
                return "\n".join(output)

            entry = rows[0]
            output.append("Sample Information:")
            output.extend(_trusted_lines(entry))

            intel = entry.get("intelligence")
            if isinstance(intel, dict):
                downloads = _scalar(intel.get("downloads"))
                uploads = _scalar(intel.get("uploads"))
                if downloads or uploads:
                    output.append(
                        f"  MalwareBazaar activity: {downloads or '0'} downloads, "
                        f"{uploads or '0'} uploads"
                    )

            # F-7: the uploader chooses the file name, the tags, the family
            # label and the free-text comments. A sample can therefore be named
            # something that reads like an instruction to the model, which is
            # exactly the channel the envelope exists to mark.
            submitter_text = _untrusted_lines(entry)
            if submitter_text:
                output.append("")
                output.append(
                    wrap_untrusted(
                        "\n".join(submitter_text),
                        kind="MalwareBazaar submitter-supplied names, tags and labels",
                    )
                )

            output.append("")
            # The SHA256 comes back over the network, so validate it before it
            # is printed OUTSIDE the envelope as part of a URL. Everything
            # unvalidated goes inside the fence; a link the reader is invited
            # to click has to be a link this module can vouch for.
            reported_sha256 = str(entry.get("sha256_hash", "")).strip().lower()
            if _SHA256_RE.match(reported_sha256):
                output.append(f"Web: https://bazaar.abuse.ch/sample/{reported_sha256}/")
            if not _download_allowed():
                output.append(
                    f"To fetch the sample itself, set {MB_ALLOW_DOWNLOAD_ENV}=1 "
                    "and call mb_download."
                )

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("mb_lookup", e)
        except ValueError as e:
            return f"Configuration error: {e}"
        except MalwareBazaarError as e:
            return f"MalwareBazaar error: {e}"
        except FileNotFoundError as e:
            # The path here is the SANITIZED absolute one, so its message quotes
            # a resolved host path (audit F-10). Category survives, path does not.
            return safe_path_error("mb_lookup", e, "file path")
        except Exception as e:
            logger.error(f"mb_lookup failed: {e}")
            return safe_error_message("Failed to look up sample", e)

    @app.tool()
    def mb_search(
        tag: str = "",
        signature: str = "",
        file_type: str = "",
        clamav: str = "",
        imphash: str = "",
        tlsh: str = "",
        telfhash: str = "",
        gimphash: str = "",
        dhash_icon: str = "",
        yara_rule: str = "",
        limit: int = 20,
    ) -> str:
        """
        Find samples on MalwareBazaar by one corpus pivot.

        Exactly ONE pivot may be given per call -- MalwareBazaar has a separate
        query per selector, so combining them is not a thing the API can do.

        The structural pivots are the ones worth reaching for after a static
        analysis pass: imphash and gimphash cluster by import table, TLSH and
        ssdeep by byte similarity, dhash_icon by embedded icon, yara_rule by a
        rule that already fired.

        Args:
            tag: Community tag, e.g. "AgentTesla", "exe", "RAT"
            signature: Malware family label, e.g. "Emotet"
            file_type: File extension as MalwareBazaar records it, e.g. "dll"
            clamav: ClamAV signature name
            imphash: PE import hash (32 hex chars)
            tlsh: TLSH fuzzy hash
            telfhash: telfhash (ELF import hash)
            gimphash: gimphash (Go binary import hash)
            dhash_icon: Perceptual hash of the embedded icon
            yara_rule: Name of a YARA rule that matched
            limit: Maximum samples to return (1-1000, default 20)

        Returns:
            Matching samples with hashes, family labels and tags.

        Example:
            mb_search(tag="AgentTesla", limit=10)
            mb_search(imphash="f34d5f2d4577ed6d9ceec516c1f5a744")
            mb_search(signature="Emotet", limit=50)
        """
        try:
            # Bind the arguments to the pivot table by name once, here, rather
            # than reading them back out of locals(): the table is the single
            # place the (argument, query, field) triple is written down, and a
            # pivot added to it without a matching parameter should fail
            # loudly at registration rather than silently never match.
            values = {
                "tag": tag,
                "signature": signature,
                "file_type": file_type,
                "clamav": clamav,
                "imphash": imphash,
                "tlsh": tlsh,
                "telfhash": telfhash,
                "gimphash": gimphash,
                "dhash_icon": dhash_icon,
                "yara_rule": yara_rule,
            }
            supplied = {
                argument: values[argument].strip()
                for argument, _query, _field in MB_SEARCH_PIVOTS
                if values.get(argument) and values[argument].strip()
            }

            if not supplied:
                names = ", ".join(argument for argument, _q, _f in MB_SEARCH_PIVOTS)
                return f"Error: Provide exactly one search pivot. One of: {names}"
            if len(supplied) > 1:
                return (
                    "Error: MalwareBazaar accepts one pivot per query; "
                    f"got {', '.join(sorted(supplied))}. Call mb_search once per pivot."
                )

            argument, value = next(iter(supplied.items()))
            api_query, api_field = next(
                (q, f) for a, q, f in MB_SEARCH_PIVOTS if a == argument
            )

            try:
                limit = int(limit)
            except (TypeError, ValueError):
                return f"Error: limit must be an integer, got {limit!r}"
            limit = max(1, min(limit, MB_SEARCH_MAX_LIMIT))

            output = [
                "MALWAREBAZAAR SEARCH",
                f"Pivot: {argument}",
                f"Limit: {limit}",
                "",
            ]

            rows = query({"query": api_query, api_field: value, "limit": limit})
            if not rows:
                output.append("No results found.")
                return "\n".join(output)

            output.append(f"Found {len(rows)} sample(s):")
            output.append("")

            # F-7: every row leads with a submitter-chosen file name and carries
            # community tags and a family label -- free text from the corpus.
            body: list[str] = []
            for index, entry in enumerate(rows, 1):
                body.extend(_row(entry, index))
                body.append("")

            output.append(
                wrap_untrusted(
                    "\n".join(body).rstrip("\n"),
                    kind="MalwareBazaar search results (submitter-supplied names and tags)",
                )
            )

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except MalwareBazaarError as e:
            return f"MalwareBazaar error: {e}"
        except Exception as e:
            logger.error(f"mb_search failed: {e}")
            return safe_error_message("Failed to search MalwareBazaar", e)

    @app.tool()
    def mb_recent(selector: str = "time") -> str:
        """
        List the most recent MalwareBazaar uploads.

        Args:
            selector: "time" for everything uploaded in the last hour, or
                "100" for the newest 100 samples.

        Returns:
            Recent samples with hashes, family labels and tags.

        Example:
            mb_recent()
            mb_recent(selector="100")
        """
        try:
            selector = (selector or "time").strip().lower()
            if selector not in ("time", "100"):
                return 'Error: selector must be "time" (last hour) or "100" (newest 100)'

            output = [
                "MALWAREBAZAAR RECENT UPLOADS",
                f"Selector: {selector}"
                + (" (last 60 minutes)" if selector == "time" else " (newest 100)"),
                "",
            ]

            rows = query({"query": "get_recent", "selector": selector})
            if not rows:
                output.append("No recent samples returned.")
                return "\n".join(output)

            output.append(f"Found {len(rows)} sample(s):")
            output.append("")

            body: list[str] = []
            for index, entry in enumerate(rows, 1):
                body.extend(_row(entry, index))
                body.append("")

            output.append(
                wrap_untrusted(
                    "\n".join(body).rstrip("\n"),
                    kind="MalwareBazaar recent uploads (submitter-supplied names and tags)",
                )
            )

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except MalwareBazaarError as e:
            return f"MalwareBazaar error: {e}"
        except Exception as e:
            logger.error(f"mb_recent failed: {e}")
            return safe_error_message("Failed to list recent samples", e)

    @app.tool()
    def mb_download(sha256: str, output_name: str = "") -> str:
        """
        Download a malware sample from MalwareBazaar as an encrypted zip.

        DISABLED BY DEFAULT. The operator must set MB_ALLOW_DOWNLOAD=1 in the
        server environment; without it this tool refuses and explains how to
        enable it. This is the only tool in this server that writes malware to
        disk.

        What lands on disk is abuse.ch's password-protected zip, saved under
        ~/.binary_mcp_output/malwarebazaar/ and NEVER extracted by this tool.
        The archive password is "infected". Extract it yourself, in an isolated
        analysis VM, when you actually intend to run or open the sample.

        Args:
            sha256: Full SHA256 of the sample (MalwareBazaar requires SHA256)
            output_name: Optional file name for the archive, relative to the
                download directory. Defaults to "<sha256>.zip".

        Returns:
            The path written, the archive size, and the extraction password.

        Example:
            mb_download("094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d")
        """
        try:
            if not _download_allowed():
                return (
                    "Sample download is disabled.\n"
                    f"Set {MB_ALLOW_DOWNLOAD_ENV}=1 in the server environment (or .env) "
                    "to enable mb_download.\n"
                    "It is off by default because it is the only tool here that writes "
                    "malware to disk; the archive stays encrypted, but it is still a "
                    "live sample on your filesystem."
                )

            digest = normalise_hash(sha256, sha256_only=True)
            name = (output_name or f"{digest}.zip").strip()
            if not name.lower().endswith(".zip"):
                name = f"{name}.zip"

            MB_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
            destination = sanitize_output_path(Path(name), MB_DOWNLOAD_DIR)

            archive = download_sample(digest)
            destination.write_bytes(archive)

            return "\n".join([
                "MALWAREBAZAAR DOWNLOAD",
                f"SHA256: {digest}",
                f"Saved: {destination}",
                f"Size: {len(archive)} bytes (zip archive, not extracted)",
                f'Password: "{MB_ZIP_PASSWORD}"',
                "",
                "The archive is left encrypted on purpose. Extract it only inside an "
                "isolated analysis VM -- extracting it here puts a live sample on this "
                "host, where your own AV will likely quarantine it.",
            ])

        except PathTraversalError as e:
            return safe_error_message("mb_download", e)
        except ValueError as e:
            return f"Configuration error: {e}"
        except MalwareBazaarError as e:
            return f"MalwareBazaar error: {e}"
        except OSError as e:
            # The message quotes the resolved download path, rooted at
            # Path.home() -- same F-10 reasoning as everywhere else.
            return safe_path_error("mb_download", e, "download directory")
        except Exception as e:
            logger.error(f"mb_download failed: {e}")
            return safe_error_message("Failed to download sample", e)

    logger.info("Registered 5 MalwareBazaar tools")
