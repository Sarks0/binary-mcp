"""
VirusTotal integration tools for binary analysis.

Provides tools for:
- Hash/file lookup on VirusTotal (``GET /api/v3/files/{id}``)
- Detection summary and per-engine AV results
- Sandbox behaviour summary (``GET /api/v3/files/{id}/behaviour_summary``)
- Intelligence corpus search (``GET /api/v3/intelligence/search``, premium only)
- API key / quota status (``GET /api/v3/users/{id}/overall_quotas``)

The module docstring previously advertised "Related samples search". No such
tool exists -- VT exposes related samples through the ``/files/{id}/similar_files``
and ``/files/{id}/{relationship}`` endpoints, and none of them are called from
here. The claim is removed rather than left standing: a docstring is the only
description of this module a reader (or a model) gets, and an unimplemented
bullet in it is indistinguishable from a real capability.

Every call is a GET. There is no submission, upload, or comment path, which is
what backs the README's "samples are never uploaded anywhere" claim --
``tests/test_docs_accuracy.py::test_no_vt_caller_uses_post`` fails if that
stops being true.

Requires the VT_API_KEY environment variable (or a .env entry).
"""

import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from src.tools.error_hygiene import safe_path_error
from src.utils.formatters import wrap_untrusted

logger = logging.getLogger(__name__)


class VirusTotalError(RuntimeError):
    """
    A VirusTotal API failure whose message this module wrote itself.

    Audit F-10: the vt_* handlers return ``f"VirusTotal error: {e}"``
    verbatim, which is right for the curated sentences raised below ("Hash not
    found in VirusTotal database", "rate limit exceeded", the HTTP status
    line) and wrong for anything else that happens to be a ``RuntimeError``
    inside the same try block -- urllib, json and the hashing helpers all live
    in there. Raising and catching a dedicated subclass makes the passthrough
    apply to exactly the strings this module authored; everything else drops
    through to ``safe_error_message``.
    """


# VirusTotal API configuration
VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY_ENV = "VT_API_KEY"
VT_TIMEOUT_ENV = "VT_API_TIMEOUT"

#: Default socket timeout for a VT call, overridable with ``VT_API_TIMEOUT``.
VT_DEFAULT_TIMEOUT = 30

#: Ceiling on a decoded VT JSON response. A ``/files/{id}`` report with every
#: engine result and a long ``names`` list is tens of KB; anything in the tens
#: of MB is either an API change or a hostile response, and reading it
#: unbounded into memory is the failure mode worth refusing outright.
VT_MAX_RESPONSE_BYTES = 32 * 1024 * 1024

#: VT accepts an MD5, SHA-1 or SHA-256 as a file object's ``id``.
#:
#: The length check this replaces (``len(h) not in (32, 40, 64)``) let any
#: 32/40/64-character string through and then interpolated it straight into
#: the request path. ``"a" * 30 + "/x?"`` is 33 characters, so it failed --
#: but ``"..%2f" * n``-style values, or anything containing ``/``, ``?`` or
#: ``#`` at one of the three accepted lengths, reached the URL builder and
#: could address a different endpoint (or append query parameters) on VT's
#: API. The host is hardcoded so this is not SSRF, but "this argument is a
#: hash" is a claim the code should actually enforce, not merely measure.
_HASH_RE = re.compile(r"\A(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\Z")

#: Maximum ``limit`` VT accepts on an Intelligence search page.
VT_SEARCH_MAX_LIMIT = 300

#: Per-section cap when rendering a behaviour report.
_BEHAVIOUR_SECTION_LIMIT = 10

#: Per-engine detections shown by ``vt_lookup``.
_DETECTIONS_SHOWN = 15


def _get_api_key() -> str | None:
    """Get VirusTotal API key from .env file or environment."""
    from src.utils.config import get_config
    return get_config(VT_API_KEY_ENV)


def _get_timeout() -> int:
    """Socket timeout for VT calls, clamped to a sane range."""
    from src.utils.config import get_config_int
    timeout = get_config_int(VT_TIMEOUT_ENV, VT_DEFAULT_TIMEOUT)
    return max(5, min(timeout, 300))


def normalise_hash(file_hash: str) -> str:
    """
    Lower-case, strip and validate a file hash used as a VT object id.

    Args:
        file_hash: MD5, SHA-1 or SHA-256, in any case, optionally padded.

    Returns:
        The canonical lower-case hash.

    Raises:
        ValueError: If the value is not a hex MD5/SHA-1/SHA-256. The message
            is a validation message the model needs in order to correct its
            own call, so it is deliberately specific (audit F-10 keeps this
            class of message; it quotes no host state).
    """
    candidate = (file_hash or "").strip().lower()
    if not _HASH_RE.match(candidate):
        raise ValueError(
            f"Invalid hash: {len(candidate)} characters. Expected a hex "
            "MD5 (32), SHA1 (40) or SHA256 (64) with no other characters."
        )
    return candidate


def _vt_error_detail(body: bytes) -> str:
    """
    Pull VT's own error sentence out of an error response body.

    VT answers a failed call with ``{"error": {"code": "...", "message":
    "..."}}``. That message says *which* privilege is missing or *which*
    quota tripped, which is exactly the thing "VirusTotal API error: 403
    Forbidden" does not say. It is VirusTotal-authored text about the
    caller's own key -- not sample-derived content -- so it is safe to
    surface, but it is still network input, so it is length-capped and
    stripped of line breaks before it lands in a message.
    """
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
        message = payload.get("error", {}).get("message")
        code = payload.get("error", {}).get("code")
    except (ValueError, AttributeError):
        return ""

    parts = [str(p) for p in (code, message) if p]
    if not parts:
        return ""
    detail = ": ".join(parts).replace("\r", " ").replace("\n", " ").strip()
    return detail[:300]


def _vt_request(
    endpoint: str,
    method: str = "GET",
    data: bytes | None = None,
    params: dict | None = None,
) -> dict:
    """
    Make a request to VirusTotal API.

    Args:
        endpoint: API endpoint path, already URL-safe (e.g. "/files/{id}")
        method: HTTP method
        data: Request body for POST
        params: Query-string parameters; encoded here rather than by the
            caller so no caller has to remember to escape them.

    Returns:
        JSON response as dict

    Raises:
        ValueError: If API key not configured
        VirusTotalError: If the API request fails
    """
    api_key = _get_api_key()
    if not api_key:
        raise ValueError(
            f"VirusTotal API key not configured. "
            f"Set {VT_API_KEY_ENV} environment variable."
        )

    url = f"{VT_API_BASE}{endpoint}"
    if params:
        url = f"{url}?{urlencode(params)}"

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": "binary-mcp",
    }

    if data:
        headers["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=headers, method=method)

    try:
        with urlopen(req, timeout=_get_timeout()) as response:  # nosec B310 - VT API URL is hardcoded
            body = response.read(VT_MAX_RESPONSE_BYTES + 1)
        if len(body) > VT_MAX_RESPONSE_BYTES:
            raise VirusTotalError(
                "VirusTotal response exceeded the "
                f"{VT_MAX_RESPONSE_BYTES // (1024 * 1024)}MB response cap"
            )
        return json.loads(body.decode("utf-8"))
    except HTTPError as e:
        # Read the body once: VT's own error sentence is more useful than the
        # status line, and on 4xx it is the only thing that distinguishes
        # "wrong key" from "key without this privilege".
        try:
            detail = _vt_error_detail(e.read())
        except Exception:  # nosec B110 - detail is best-effort enrichment
            detail = ""
        suffix = f" ({detail})" if detail else ""

        if e.code == 404:
            raise VirusTotalError("Hash not found in VirusTotal database")
        elif e.code == 400:
            raise VirusTotalError(f"VirusTotal rejected the request{suffix}")
        elif e.code == 401:
            raise VirusTotalError(f"Invalid VirusTotal API key{suffix}")
        elif e.code == 403:
            raise VirusTotalError(
                "VirusTotal denied this request: the API key lacks the "
                f"privilege it needs{suffix}"
            )
        elif e.code == 429:
            raise VirusTotalError(
                "VirusTotal API rate limit exceeded. The public API allows "
                "4 requests/minute and 500/day; wait and retry"
                f"{suffix}"
            )
        elif e.code in (503, 504):
            raise VirusTotalError(
                f"VirusTotal is temporarily unavailable ({e.code}){suffix}"
            )
        else:
            raise VirusTotalError(f"VirusTotal API error: {e.code} {e.reason}{suffix}")
    except URLError as e:
        raise VirusTotalError(f"Network error connecting to VirusTotal: {e.reason}")
    except json.JSONDecodeError:
        raise VirusTotalError("VirusTotal returned a response that was not JSON")


def calculate_file_hashes(file_path: str) -> dict:
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path: Path to file

    Returns:
        Dict with md5, sha1, sha256 keys
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5 = hashlib.md5()  # nosec B324 - MD5 used for identification, not security
    sha1 = hashlib.sha1()  # nosec B324 - SHA1 used for identification, not security
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def lookup_hash(file_hash: str) -> dict:
    """
    Look up a hash on VirusTotal.

    Args:
        file_hash: MD5, SHA1, or SHA256 hash

    Returns:
        VirusTotal analysis results
    """
    file_hash = normalise_hash(file_hash)
    response = _vt_request(f"/files/{quote(file_hash, safe='')}")
    return response.get("data", {})


def get_behavior_report(file_hash: str) -> dict:
    """
    Get behavior analysis report from VirusTotal sandbox.

    Calls ``/files/{id}/behaviour_summary``, which merges the reports of every
    sandbox VT ran the sample through into one object.

    Args:
        file_hash: MD5, SHA1 or SHA256 hash of the file

    Returns:
        Behavior analysis results
    """
    file_hash = normalise_hash(file_hash)
    response = _vt_request(f"/files/{quote(file_hash, safe='')}/behaviour_summary")
    return response.get("data", {})


def search_files(query: str, limit: int = 10, cursor: str = "") -> tuple[list[dict], str]:
    """
    Search VirusTotal for files matching query.

    ``/intelligence/search`` is a VT Enterprise ("premium") endpoint: a public
    API key gets 403 here, which ``_vt_request`` now reports as a missing
    privilege rather than a bare status line.

    Args:
        query: VT search query (e.g., "type:peexe" or "tag:ransomware")
        limit: Maximum results to return (VT caps a page at 300)
        cursor: Continuation cursor from a previous page, if any

    Returns:
        ``(results, next_cursor)`` -- next_cursor is "" on the last page.
    """
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        raise ValueError(f"limit must be an integer, got {limit!r}")
    limit = max(1, min(limit, VT_SEARCH_MAX_LIMIT))

    params: dict[str, str | int] = {"query": query, "limit": limit}
    if cursor:
        params["cursor"] = cursor

    response = _vt_request("/intelligence/search", params=params)
    next_cursor = response.get("meta", {}).get("cursor", "") or ""
    return response.get("data", []), next_cursor


def _utc_iso(timestamp) -> str | None:
    """
    Render a VT epoch timestamp as an explicit UTC ISO-8601 string.

    Every date VT returns (``first_submission_date``, ``last_analysis_date``,
    ...) is seconds since the Unix epoch, i.e. UTC. The previous code passed
    them to ``datetime.fromtimestamp()`` with no tzinfo, which reinterprets
    them in the SERVER's local zone and prints no offset -- so the same report
    read "2024-01-01T09:00:00" in London and "2024-01-01T01:00:00" in
    California, with nothing in the output to say which. For a first-seen date
    used to reason about a campaign timeline, that is a silently wrong answer,
    and the kind that only shows up when two analysts compare notes.
    """
    if timestamp is None:
        return None
    try:
        return datetime.fromtimestamp(int(timestamp), tz=UTC).isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        return None


def format_detection_summary(vt_data: dict) -> dict:
    """
    Format VirusTotal data into a readable summary.

    ``detection_ratio`` follows VirusTotal's own convention -- *malicious over
    the engines that returned a verdict*. The previous implementation reported
    ``(malicious + suspicious) / sum(stats.values())``, which differs from the
    number on the VT web page in both directions at once: the numerator folded
    in "suspicious" hits, and the denominator counted ``type-unsupported`` and
    ``failure`` engines that never examined the file. On a sample where 8 of
    70 engines do not handle the file type, that turned VT's "45/62" into
    "47/70". ``flagged`` keeps the malicious+suspicious count available for
    callers that want it, under a name that says what it is.

    Args:
        vt_data: Raw VirusTotal API response data

    Returns:
        Formatted summary dict
    """
    attributes = vt_data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    results = attributes.get("last_analysis_results", {})

    def _stat(name: str) -> int:
        try:
            return int(stats.get(name, 0) or 0)
        except (TypeError, ValueError):
            return 0

    malicious = _stat("malicious")
    suspicious = _stat("suspicious")

    total_engines = 0
    for value in stats.values():
        try:
            total_engines += int(value or 0)
        except (TypeError, ValueError):
            continue

    # Engines that never produced a verdict are not part of the denominator VT
    # displays: "type-unsupported" means the engine does not handle this file
    # type at all, and "failure" means it errored out.
    scanned_engines = total_engines - _stat("type-unsupported") - _stat("failure")
    scanned_engines = max(scanned_engines, 0)

    # Get top detections
    detections = []
    for engine, result in results.items():
        if isinstance(result, dict) and result.get("category") in ("malicious", "suspicious"):
            detections.append({
                "engine": engine,
                "result": result.get("result") or "Unknown",
                "category": result.get("category"),
            })

    # Sort by engine name for consistency
    detections.sort(key=lambda x: x["engine"])

    names = attributes.get("names") or []

    return {
        "detection_ratio": f"{malicious}/{scanned_engines}",
        "malicious": malicious,
        "suspicious": suspicious,
        "flagged": malicious + suspicious,
        "undetected": _stat("undetected"),
        "harmless": _stat("harmless"),
        "scanned_engines": scanned_engines,
        "total_engines": total_engines,
        "sha256": attributes.get("sha256"),
        "sha1": attributes.get("sha1"),
        "md5": attributes.get("md5"),
        "file_type": attributes.get("type_description"),
        "file_size": attributes.get("size"),
        "reputation": attributes.get("reputation"),
        "first_seen": _utc_iso(attributes.get("first_submission_date")),
        "last_seen": _utc_iso(attributes.get("last_submission_date")),
        "last_analysis": _utc_iso(attributes.get("last_analysis_date")),
        "tags": attributes.get("tags") or [],
        "names": list(names)[:5],  # First 5 names
        "detections": detections[:20],  # Top 20 detections
    }


# ---------------------------------------------------------------------------
# Behaviour report rendering
# ---------------------------------------------------------------------------
#
# Only a minority of behaviour_summary fields are plain lists of strings. The
# previous renderer assumed they all were, and printed the rest through
# f-string interpolation -- so ``registry_keys_set``, whose entries are
# ``{"key": ..., "value": ...}`` objects, came out as
#
#     - {'key': 'HKLM\\...\\Run', 'value': 'C:\\Users\\...\\x.exe'}
#
# a Python dict repr in a malware report. ``files_dropped``, ``files_copied``
# and ``ip_traffic`` have the same shape and were rendered the same way; only
# ``dns_lookups`` and ``http_conversations`` had the isinstance() check.
#
# Each entry below is (field, heading, preferred keys). The keys are tried in
# order against a dict entry and the ones present are joined, so a shape change
# on VT's side degrades to "show me what is there" rather than a dict repr.
_BEHAVIOUR_SECTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("processes_created", "Processes Created", ()),
    ("processes_injected", "Processes Injected", ()),
    ("processes_terminated", "Processes Terminated", ()),
    ("command_executions", "Commands Executed", ()),
    ("modules_loaded", "Modules Loaded", ()),
    ("files_written", "Files Written", ()),
    ("files_dropped", "Files Dropped", ("path", "sha256")),
    ("files_copied", "Files Copied", ("source", "destination")),
    ("files_deleted", "Files Deleted", ()),
    ("registry_keys_set", "Registry Keys Set", ("key", "value")),
    ("registry_keys_deleted", "Registry Keys Deleted", ()),
    ("mutexes_created", "Mutexes Created", ()),
    ("services_created", "Services Created", ()),
    ("services_started", "Services Started", ()),
    ("dns_lookups", "DNS Lookups", ("hostname", "resolved_ips")),
    ("http_conversations", "HTTP Conversations", ("request_method", "url")),
    ("ip_traffic", "IP Traffic", ("destination_ip", "destination_port",
                                  "transport_layer_protocol")),
)

#: Longest single rendered observation. Command lines in particular are
#: unbounded free text chosen by the sample.
_OBSERVATION_MAX_CHARS = 300


def render_observation(entry, preferred_keys: tuple[str, ...] = ()) -> str:
    """
    Render one sandbox observation as a single readable line.

    Args:
        entry: A string, or a dict from a behaviour_summary list field.
        preferred_keys: Dict keys to show, in order, when present.

    Returns:
        A one-line string, truncated with a marker that says so. The previous
        renderer appended "..." unconditionally (``f"  - {c[:100]}..."``), so
        a 12-character command line was reported as truncated when it was not.
    """
    if isinstance(entry, dict):
        parts = []
        for key in preferred_keys:
            value = entry.get(key)
            if value in (None, "", [], {}):
                continue
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(v) for v in value)
            parts.append(str(value))
        # Nothing recognised: show the whole object as JSON rather than as a
        # Python repr, so at least it is parseable by whoever reads it.
        text = " | ".join(parts) if parts else json.dumps(entry, sort_keys=True, default=str)
    else:
        text = str(entry)

    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > _OBSERVATION_MAX_CHARS:
        text = text[:_OBSERVATION_MAX_CHARS] + f" [truncated, {len(text)} chars]"
    return text


def _behaviour_activity_lines(behavior: dict) -> list[str]:
    """Build the sample-authored portion of a behaviour report."""
    activity: list[str] = []

    for field, heading, preferred_keys in _BEHAVIOUR_SECTIONS:
        entries = behavior.get(field) or []
        if not isinstance(entries, list) or not entries:
            continue

        activity.append(f"{heading} ({len(entries)}):")
        for entry in entries[:_BEHAVIOUR_SECTION_LIMIT]:
            activity.append(f"  - {render_observation(entry, preferred_keys)}")
        if len(entries) > _BEHAVIOUR_SECTION_LIMIT:
            activity.append(f"  ... and {len(entries) - _BEHAVIOUR_SECTION_LIMIT} more")
        activity.append("")

    return activity


def register_vt_tools(app, session_manager=None):
    """
    Register VirusTotal tools with the MCP app.

    Args:
        app: FastMCP application instance
        session_manager: Optional session manager for logging
    """
    from src.utils.security import (
        FileSizeError,
        PathTraversalError,
        safe_error_message,
        sanitize_binary_path,
    )

    @app.tool()
    def vt_lookup(
        file_hash: str = "",
        file_path: str = "",
    ) -> str:
        """
        Look up a file on VirusTotal by hash or path.

        Queries VirusTotal for detection results, file metadata, and tags.
        Requires VT_API_KEY environment variable.

        Nothing is uploaded: with file_path the file is hashed locally and only
        the hash is sent. Sending a hash still tells VirusTotal you hold the
        sample.

        The detection ratio is malicious engines over engines that returned a
        verdict, matching the number shown on the VirusTotal web page. Engines
        that do not support the file type, or that failed, are excluded from
        the denominator.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash to look up
            file_path: Path to file (will calculate hash automatically)

        Returns:
            Detection summary with AV results

        Example:
            vt_lookup(file_hash="44d88612fea8a8f36de82e1278abb02f")
            vt_lookup(file_path="suspicious.exe")
        """
        try:
            if not file_hash and not file_path:
                return "Error: Provide either file_hash or file_path"

            output = []
            output.append("VIRUSTOTAL LOOKUP")

            # Get VT data
            if file_path:
                file_path = sanitize_binary_path(file_path)
                output.append(f"File: {file_path}")

                # Calculate hashes
                hashes = calculate_file_hashes(file_path)
                output.append(f"MD5:    {hashes['md5']}")
                output.append(f"SHA1:   {hashes['sha1']}")
                output.append(f"SHA256: {hashes['sha256']}")
                output.append("")

                vt_data = lookup_hash(hashes["sha256"])
            else:
                output.append(f"Hash: {file_hash}")
                output.append("")
                vt_data = lookup_hash(file_hash)

            # Format results
            summary = format_detection_summary(vt_data)

            # Detection summary
            if summary["malicious"] > 0:
                output.append(f"MALICIOUS: {summary['detection_ratio']} engines detected this file")
            elif summary["suspicious"] > 0:
                output.append(
                    f"SUSPICIOUS: {summary['suspicious']}/{summary['scanned_engines']} "
                    "engines flagged this file"
                )
            else:
                output.append(f"CLEAN: {summary['detection_ratio']} - No detections")

            if summary["suspicious"] and summary["malicious"]:
                output.append(
                    f"  (plus {summary['suspicious']} suspicious; "
                    f"{summary['flagged']}/{summary['scanned_engines']} flagged in total)"
                )
            if summary["total_engines"] != summary["scanned_engines"]:
                skipped = summary["total_engines"] - summary["scanned_engines"]
                output.append(
                    f"  ({skipped} engines did not return a verdict: unsupported file "
                    "type or scan failure)"
                )

            output.append("")
            output.append("File Information:")
            output.append(f"  Type: {summary['file_type'] or 'Unknown'}")
            output.append(f"  Size: {summary['file_size'] or 'Unknown'} bytes")

            if summary["first_seen"]:
                output.append(f"  First Seen: {summary['first_seen']}")
            if summary["last_seen"]:
                output.append(f"  Last Seen: {summary['last_seen']}")
            if summary["last_analysis"]:
                output.append(f"  Last Analysed: {summary['last_analysis']}")

            # F-7: `tags` and `names` are free-form strings chosen by whoever
            # uploaded or tagged the sample -- i.e. attacker-controlled text
            # arriving over the network, not VirusTotal's own verdict. A
            # submitter can name a file anything, so these two lines are fenced
            # as one block while the detection ratio, file type and hashes
            # around them stay outside as trusted server/VT-computed values.
            attacker_named: list[str] = []
            if summary["tags"]:
                attacker_named.append(f"  Tags: {', '.join(str(t) for t in summary['tags'][:10])}")
            if summary["names"]:
                attacker_named.append(
                    f"  Known Names: {', '.join(str(n) for n in summary['names'])}"
                )
            if attacker_named:
                output.append(
                    wrap_untrusted(
                        "\n".join(attacker_named),
                        kind="VirusTotal submitter-supplied names and tags",
                    )
                )

            # Show detections
            if summary["detections"]:
                output.append("")
                output.append(f"Detections ({len(summary['detections'])} shown):")
                for det in summary["detections"][:_DETECTIONS_SHOWN]:
                    output.append(f"  - {det['engine']}: {det['result']}")
                if len(summary["detections"]) > _DETECTIONS_SHOWN:
                    extra = len(summary["detections"]) - _DETECTIONS_SHOWN
                    output.append(f"  ... and {extra} more")

            # Hashes for reference
            output.append("")
            output.append("Hashes:")
            output.append(f"  MD5:    {summary['md5']}")
            output.append(f"  SHA1:   {summary['sha1']}")
            output.append(f"  SHA256: {summary['sha256']}")

            return "\n".join(output)

        except (PathTraversalError, FileSizeError) as e:
            return safe_error_message("vt_lookup", e)
        except ValueError as e:
            return f"Configuration error: {e}"
        except VirusTotalError as e:
            # Audit F-10: curated, host-free text raised by this module.
            return f"VirusTotal error: {e}"
        except FileNotFoundError as e:
            # Audit F-10: calculate_file_hashes is handed the SANITIZED absolute
            # path, so its "File not found: <path>" message quotes a resolved
            # host path -- under the default quarantine policy, one rooted at
            # Path.home(). The category survives; the path does not.
            return safe_path_error("vt_lookup", e, "file path")
        except Exception as e:
            logger.error(f"vt_lookup failed: {e}")
            return safe_error_message("Failed to look up file", e)

    @app.tool()
    def vt_behavior(file_hash: str) -> str:
        """
        Get VirusTotal sandbox behavior report for a file.

        Shows process activity, file operations, network connections,
        and registry changes observed during sandbox execution, merged across
        every sandbox VirusTotal ran the sample through
        (GET /files/{id}/behaviour_summary).

        Args:
            file_hash: MD5, SHA1 or SHA256 hash of the file

        Returns:
            Behavior analysis summary

        Example:
            vt_behavior("a1b2c3d4e5f6...")
        """
        try:
            output = []
            output.append("VIRUSTOTAL BEHAVIOR REPORT")
            output.append(f"Hash: {file_hash}")
            output.append("")

            behavior = get_behavior_report(file_hash)

            if not behavior:
                output.append("No behavior data available for this file.")
                output.append("The file may not have been executed in a sandbox.")
                return "\n".join(output)

            # F-7: everything a sandbox observed is a string the SAMPLE chose --
            # process command lines, dropped file names, C2 URLs, mutex names,
            # registry paths. A command line is an especially attractive
            # injection carrier because it is long, free-form and expected to
            # look like text. Collect the observed-activity sections into one
            # block, fence it once, and leave the report header and the sandbox
            # verdicts (which the sandbox vendor authors, not the sample)
            # outside the envelope.
            activity = _behaviour_activity_lines(behavior)

            if activity:
                output.append(
                    wrap_untrusted(
                        "\n".join(activity).rstrip("\n"),
                        kind="sandbox-observed activity of the sample",
                    )
                )
                output.append("")

            # Vendor-authored conclusions: the sandbox's verdict strings, the
            # MITRE technique IDs it mapped, and the names of the behaviour
            # rules that fired. These are written by the sandbox vendor rather
            # than chosen by the sample, so they stay outside the envelope.
            verdicts = behavior.get("verdicts") or []
            if verdicts:
                output.append("Sandbox Verdicts:")
                for v in verdicts:
                    output.append(f"  - {render_observation(v, ('verdict', 'category'))}")

            techniques = behavior.get("mitre_attack_techniques") or []
            if techniques:
                output.append("")
                output.append(f"MITRE ATT&CK Techniques ({len(techniques)}):")
                for technique in techniques[:_BEHAVIOUR_SECTION_LIMIT]:
                    output.append(
                        f"  - {render_observation(technique, ('id', 'signature_description'))}"
                    )
                if len(techniques) > _BEHAVIOUR_SECTION_LIMIT:
                    extra = len(techniques) - _BEHAVIOUR_SECTION_LIMIT
                    output.append(f"  ... and {extra} more")

            # The observed-activity sections are assembled in `activity`
            # rather than appended to `output` one line at a time, so the old
            # "len(output) == 4" heuristic for an empty report no longer
            # matches. Check the collected data directly instead.
            if not activity and not verdicts and not techniques:
                output.append("No significant behavior recorded.")

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except VirusTotalError as e:
            # Audit F-10: curated, host-free text raised by this module.
            return f"VirusTotal error: {e}"
        except Exception as e:
            logger.error(f"vt_behavior failed: {e}")
            return safe_error_message("Failed to get behavior report", e)

    @app.tool()
    def vt_search(query: str, limit: int = 10, cursor: str = "") -> str:
        """
        Search VirusTotal for files matching a query.

        Uses VirusTotal Intelligence search syntax (GET /intelligence/search).
        This endpoint is VT Enterprise only: a free/public API key is rejected
        with a privilege error, not an empty result set.

        Args:
            query: Search query (e.g., "tag:ransomware", "type:peexe")
            limit: Maximum results per page (1-300, default: 10)
            cursor: Continuation cursor printed by a previous call, to page on

        Returns:
            List of matching files with detection info

        Example:
            vt_search("tag:ransomware")
            vt_search("type:peexe p:5+")
            vt_search("tag:ransomware", limit=50)
        """
        try:
            output = []
            output.append("VIRUSTOTAL SEARCH")
            output.append(f"Query: {query}")
            output.append(f"Limit: {limit}")
            output.append("")

            results, next_cursor = search_files(query, limit, cursor)

            if not results:
                output.append("No results found.")
                return "\n".join(output)

            output.append(f"Found {len(results)} results:")
            output.append("")

            # F-7: each result row leads with a submitter-chosen file name and
            # ends with community tags -- both attacker-controlled free text
            # (an uploader can name a sample anything, including a fake tool
            # transcript). Fence the result list once; the query echo, the
            # result count and this tool's own banner stay outside.
            rows: list[str] = []
            for i, item in enumerate(results, 1):
                attrs = item.get("attributes", {})
                summary = format_detection_summary(item)

                names = attrs.get("names") or []
                name = str(names[0]) if names else "Unknown"

                rows.append(f"{i}. {name}")
                rows.append(f"   SHA256: {attrs.get('sha256', 'Unknown')}")
                rows.append(f"   Type: {attrs.get('type_description', 'Unknown')}")
                rows.append(f"   Detection: {summary['detection_ratio']}")
                if summary["first_seen"]:
                    rows.append(f"   First Seen: {summary['first_seen']}")

                tags = attrs.get("tags") or []
                if tags:
                    rows.append(f"   Tags: {', '.join(str(t) for t in tags[:5])}")

                rows.append("")

            output.append(
                wrap_untrusted(
                    "\n".join(rows).rstrip("\n"),
                    kind="VirusTotal search results (submitter-supplied names and tags)",
                )
            )
            output.append("")

            if next_cursor:
                output.append("More results are available. To fetch the next page:")
                output.append(f'  vt_search(query={query!r}, limit={limit}, cursor="{next_cursor}")')

            return "\n".join(output)

        except ValueError as e:
            return f"Configuration error: {e}"
        except VirusTotalError as e:
            # Audit F-10: curated, host-free text raised by this module.
            return f"VirusTotal error: {e}"
        except Exception as e:
            logger.error(f"vt_search failed: {e}")
            return safe_error_message("Failed to search VirusTotal", e)

    @app.tool()
    def vt_check_api() -> str:
        """
        Check if VirusTotal API is configured and working.

        Verifies the API key is set, can connect to VirusTotal, and reports the
        key's remaining request quota (GET /users/{id}/overall_quotas, which
        does not itself consume quota).

        Returns:
            API status and quota information
        """
        try:
            output = []
            output.append("VIRUSTOTAL API STATUS")

            api_key = _get_api_key()
            if not api_key:
                output.append("API key not configured")
                output.append("")
                output.append("Configure your API key using one of these methods:")
                output.append("")
                output.append("1. Create a .env file in the project root:")
                output.append(f"   {VT_API_KEY_ENV}=your_api_key_here")
                output.append("")
                output.append("2. Or set an environment variable:")
                output.append(f"   export {VT_API_KEY_ENV}=your_api_key_here")
                output.append("")
                output.append("Get your API key from: https://www.virustotal.com/gui/my-apikey")
                return "\n".join(output)

            # Mask the API key
            masked_key = api_key[:4] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            output.append(f"API key configured: {masked_key}")

            # Test with a known hash (EICAR test file)
            test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

            try:
                result = lookup_hash(test_hash)
                output.append("API connection successful")
                output.append("")
                output.append("Test lookup (EICAR test file):")
                summary = format_detection_summary(result)
                output.append(f"  Detection: {summary['detection_ratio']}")
            except VirusTotalError as e:
                if "rate limit" in str(e).lower():
                    output.append("API rate limit reached")
                else:
                    output.append(f"API test failed: {e}")

            quota_lines = _quota_lines()
            if quota_lines:
                output.append("")
                output.extend(quota_lines)

            return "\n".join(output)

        except Exception as e:
            logger.error(f"vt_check_api failed: {e}")
            return safe_error_message("Failed to check API status", e)

    logger.info("Registered 4 VirusTotal tools")


def _quota_lines() -> list[str]:
    """
    Render the API key's quota, or nothing if VT will not report it.

    The quota endpoint addresses the user BY API KEY (``/users/{key}/overall_quotas``),
    so the key is in the request path. Failures here are summarised rather than
    surfaced: a urllib error string can quote the URL it was building, and that
    URL contains the operator's API key. ``vt_check_api``'s job is the key
    check, and the EICAR lookup above has already established whether the key
    works, so a quota failure is worth one line and no detail.
    """
    api_key = _get_api_key()
    if not api_key:
        return []

    try:
        response = _vt_request(f"/users/{quote(api_key, safe='')}/overall_quotas")
        quotas = response.get("data", {})
    except Exception:
        logger.debug("VirusTotal quota lookup failed", exc_info=False)
        return ["Quota: not reported (the key may not have access to this endpoint)"]

    if not isinstance(quotas, dict) or not quotas:
        return []

    lines = ["Quota:"]
    for name in ("api_requests_hourly", "api_requests_daily", "api_requests_monthly"):
        entry = quotas.get(name)
        if not isinstance(entry, dict):
            continue
        scope = entry.get("user") if isinstance(entry.get("user"), dict) else entry
        used = scope.get("used")
        allowed = scope.get("allowed")
        if used is None and allowed is None:
            continue
        label = name.replace("api_requests_", "").capitalize()
        lines.append(f"  {label}: {used} used of {allowed}")

    return lines if len(lines) > 1 else []
