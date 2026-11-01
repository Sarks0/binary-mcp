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
nothing on the host ever holds a runnable copy that this server put there. The
write itself is an atomic create-or-fail at mode ``0o600``: an archive already
on disk is never overwritten, and a sample this server stores is readable only
by the user running it.
"""

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError

from src.integrations import IntegrationClient, IntegrationError, ProviderConfig
from src.integrations.hashes import normalise_hash as _normalise_hash
from src.tools.error_hygiene import safe_path_error
from src.utils.formatters import flatten_to_one_line, wrap_untrusted

logger = logging.getLogger(__name__)


class MalwareBazaarError(IntegrationError):
    """
    A MalwareBazaar failure whose message this module wrote itself.

    Same contract as :class:`src.tools.vt_tools.VirusTotalError` (audit F-10):
    the handlers pass these through verbatim because this module authored the
    sentence, while every other exception goes to ``safe_error_message``.
    """


MB_API_BASE = "https://mb-api.abuse.ch/api/v1/"

#: One abuse.ch Auth-Key covers MalwareBazaar, ThreatFox, URLhaus, YARAify
#: and SSLBL, so the canonical variable is service-neutral. MB_API_KEY is
#: still honoured: it shipped first, and silently ignoring a variable an
#: operator already set is a worse failure than carrying an alias.
ABUSECH_API_KEY_ENV = "ABUSECH_API_KEY"
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

#: Open flags for the one write this server makes into ``MB_DOWNLOAD_DIR``.
#:
#: ``O_WRONLY | O_CREAT | O_EXCL`` is an atomic create-or-fail, the same
#: contract as ``src/utils/carving.py::_BLOB_OPEN_FLAGS``. It matters more here
#: than almost anywhere else in the server: the file that would be clobbered is
#: a live malware sample an analyst may already be working from.
#:
#: ``O_BINARY`` is Windows-only (hence the ``getattr`` -- POSIX does not define
#: it, where it resolves to 0 and changes nothing). On Windows ``os.open()``
#: returns a descriptor in the C runtime's *text* mode without it, and that
#: translation lives in the descriptor: ``os.fdopen(fd, "wb")`` does not undo
#: it, so every 0x0A in the zip would be expanded to 0x0D 0x0A and the archive
#: would no longer open. Note why it has to be named here at all -- the
#: ``Path.write_bytes()`` this replaced applied the identical guard for us
#: inside ``io.FileIO`` (``flags |= getattr(os, 'O_BINARY', 0)``), so taking
#: the descriptor by hand means taking the flag by hand too. Do not drop it
#: because the tests still pass: CI is POSIX, where there is nothing to see.
_ARCHIVE_OPEN_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)

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

#: Rows rendered in one report, matching the abuse.ch tools next door.
#:
#: The query limit and the render limit are different numbers on purpose. A
#: caller asking for 1000 wants the COUNT -- "this imphash has 847 samples" is
#: the finding -- not 847 rendered blocks, which measured ~200KB of model
#: context for one call. The count line above the rows carries the total.
_ROW_LIMIT = 15

#: ``query_status`` values worth an explanation rather than an echo. Anything
#: not listed is reported with its raw token so a new status is visible rather
#: than swallowed.
_STATUS_MESSAGES: dict[str, str] = {
    # The four "nothing matched" statuses are not here: see _EMPTY_STATUSES.
    # file_not_found is, because it answers mb_download, which asks for one
    # specific archive rather than a result set.
    "file_not_found": "MalwareBazaar has no downloadable file for that SHA256.",
    # abuse.ch's catch-all, and the one status reachable by a query a caller
    # chose: mb_search sends a limit up to 1000, and a broad tag exceeds the
    # server's execution-time threshold. This sentence is read by all five
    # tools, so it names the condition instead of prescribing a repair only
    # mb_search could make -- mb_lookup and mb_download have no selector and
    # no limit, mb_recent's selector is a two-value enum, and mb_check_api
    # probes with a single hash.
    "error": (
        "MalwareBazaar returned status: error, its generic failure. On a "
        "corpus pivot this is usually a selector too broad to finish inside "
        "the server's execution-time threshold (tag:exe is one): retry with a "
        "narrower selector or a lower limit."
    ),
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
        f"MalwareBazaar requires an Auth-Key. Set {ABUSECH_API_KEY_ENV} "
        "(free from https://auth.abuse.ch/)."
    ),
    "unknown_auth_key": (
        f"MalwareBazaar rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
    ),
    "invalid_auth_key": (
        f"MalwareBazaar rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
    ),
    "unauthorized": (
        f"MalwareBazaar rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
    ),
}

#: Control characters in a caller-chosen archive name. Refused rather than
#: written: a newline in a file name is legal on POSIX and rejected outright
#: by the Windows CRT, so writing one means the same call succeeds on one
#: platform and fails on the other with an OSError the caller cannot act on.
#: It is also the F-7 problem at its source. Every line of a download report
#: echoes this name outside any untrusted envelope, and a break in it would
#: start a line the reader cannot attribute, able to name a real tool in this
#: server. The report flattens the name as well, because defence for a claim
#: this load-bearing should not rest on one check; this is the one that keeps
#: such a name off the filesystem, where it would go on to confuse every
#: shell, archiver and script the analyst points at the download directory.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

#: A name of this shape is this server's content-addressed slot for one
#: sample, so only that sample may be written to it. Matched case-folded
#: because a case-insensitive filesystem makes "AAAA....zip" the same slot.
_HASH_SLOT_RE = re.compile(r"\A[0-9a-f]{64}\.zip\Z")

#: The trailer on every download report. Hoisted out of the handler so the
#: "already present" and "freshly written" replies cannot drift apart.
_MB_ENCRYPTED_NOTE = (
    "The archive is left encrypted on purpose. Extract it only inside an "
    "isolated analysis VM -- extracting it here puts a live sample on this "
    "host, where your own AV will likely quarantine it."
)


def _looks_like_archive(destination: Path) -> bool:
    """
    Whether the file already at ``destination`` is a zip at all.

    ``exists()`` is not identity, and the no-overwrite contract makes that
    gap permanent: a zero-byte residue, a directory, or a text file at the
    content-addressed name would otherwise be announced as "this sample,
    already present" -- with its extraction password -- and no later call
    could repair it. Reads two bytes, the same ``b"PK"`` test
    :func:`download_sample` already applies to the wire, and never decrypts:
    this module does not open these archives.
    """
    try:
        with open(destination, "rb") as handle:
            return handle.read(2) == b"PK"
    except OSError:
        # A directory, a permission failure, a dangling symlink: not something
        # this server may claim is the sample.
        return False


def _refusal(headline: str, name: str, default_name: str, *body: str) -> str:
    """
    One shape for every "nothing was downloaded" reply.

    Echoes the caller's OWN argument and nothing else -- not the resolved
    destination, which is rooted at ``Path.home()`` and so carries the
    operator's username (audit F-10, the same reasoning as the OSError arm of
    the handler). These are refusals, so the success path's deliberate path
    disclosure does not extend to them.

    flatten_to_one_line because the value is caller-chosen and printed OUTSIDE
    any untrusted envelope (audit F-7): a line break is a legal POSIX file
    name character, and one here would start a second line the reader cannot
    attribute -- a working injection channel, since the name reaches the model
    verbatim and can name a real tool in this server.
    """
    return "\n".join([
        f"Nothing was downloaded: {headline}",
        f"Name: {flatten_to_one_line(name)}",
        *body,
        f'Retry with output_name="{flatten_to_one_line(default_name)}" -- or '
        "omit output_name, which uses that same SHA256-derived default.",
    ])


def _control_character_message(name: str, default_name: str) -> str:
    """Refuse an ``output_name`` carrying a control character."""
    return _refusal(
        "that name contains a control character.", name, default_name,
        "Archive names are restricted to printable characters: a line break "
        "or a NUL is legal in a POSIX file name and rejected outright by "
        "Windows, and either way it would start a line of this report that "
        "the reader cannot tell from the server's own.",
    )


def _name_taken_message(name: str, default_name: str) -> str:
    """Refuse a caller-chosen ``output_name`` that already holds an archive."""
    return _refusal(
        "that archive name is already in use.", name, default_name,
        "mb_download never overwrites. The file already under that name may "
        "be a different sample, and replacing it would destroy the only copy "
        "while an earlier report still points at it.",
    )


def _reserved_name_message(name: str, default_name: str) -> str:
    """
    Refuse writing one sample into another sample's content-addressed slot.

    This is the hole an ``exists()``-only guard leaves open, and never
    overwriting is what makes it lasting. A ``<sha256>.zip`` name means "this
    is that sample" everywhere in this server, and the slot being EMPTY is not
    permission to put something else in it:
    ``mb_download(A, output_name="<B's digest>.zip")`` passes every existence
    check, writes A there with a plain success report, and a later honest
    ``mb_download(B)`` then finds the slot occupied and reports "already
    present -- that name is this sample's own SHA256" about a file that is not
    B. So the reservation is checked on the name's SHAPE, before the file
    system is consulted at all.
    """
    return _refusal(
        "that name is another sample's SHA256.", name, default_name,
        "A <sha256>.zip name is how this server records which sample a file "
        "is, so only that sample may be written to it -- an empty slot is not "
        "permission to put a different sample in it.",
    )


def _unusable_archive_message(name: str, default_name: str) -> str:
    """
    Refuse when something that is not a zip already occupies the name.

    Deliberately a refusal rather than a replacement, even at the sample's own
    content-addressed name where the occupant cannot be another sample: this
    is the one tool that writes malware to disk, and it does not delete what
    it did not create. A successful write unlinks its own partial output, so
    reaching this state means something unusual happened -- the process was
    killed mid-write, or a human put the file there -- and the caller is told
    exactly what to remove rather than having it removed for them.
    """
    return _refusal(
        "something that is not a zip archive already has that name.",
        name, default_name,
        "It may be a directory, or the residue of a write that was killed "
        "part-way. mb_download will not replace a file it did not write: "
        "delete that name from the download directory (mb_check_api names the "
        "directory) and retry.",
    )


class _MalwareBazaarClient(IntegrationClient):
    """abuse.ch's status codes; most failures arrive inside a 200 instead."""

    def map_http_error(self, error: HTTPError) -> Exception:
        if error.code == 401:
            return MalwareBazaarError(
                f"MalwareBazaar rejected the Auth-Key. Check {ABUSECH_API_KEY_ENV}."
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
        key_config_keys=(ABUSECH_API_KEY_ENV, MB_API_KEY_ENV),
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
        ``(parsed_json, raw_body)``. ``parsed_json`` is ``{}`` only when
        ``expect_json`` is ``False`` and the body was not a JSON object --
        which for ``get_file`` is the success case. With ``expect_json=True``
        a body that is not a JSON object raises instead of arriving empty.

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


#: ``query_status`` values that mean the query ran and matched nothing.
#:
#: An empty answer is a result, not a failure. Raising on these turned a clean
#: miss into "MalwareBazaar error: Hash not found in MalwareBazaar.", which
#: discarded the report header the caller had already built -- including the
#: SHA256 this server computed locally, which is the one line that makes the
#: miss worth reading -- and left the no-rows branch in every caller dead.
_EMPTY_STATUSES = frozenset({
    "no_results",
    "hash_not_found",
    "tag_not_found",
    "signature_not_found",
})

#: The hash ``mb_check_api`` probes with. It is the digest of a fixed string
#: written here, not a round number: a degenerate value such as 64 zeroes is
#: the kind of input a service may special-case as malformed, and
#: ``illegal_hash`` is in :data:`_STATUS_MESSAGES`, so it would RAISE -- the
#: same false alarm this probe exists to remove, reached a different way.
#:
#: The probe has two things to prove -- the service answered, and the Auth-Key
#: was accepted -- and it has to prove them the same way on every host, on
#: every day, against every key. The probe it replaces proved them by scanning
#: a selector: ``get_taginfo`` with ``tag="exe"`` and ``limit=1``. ``limit``
#: bounds the rows RETURNED, not the work done to find them, and ``exe`` is
#: one of the largest tags in the corpus, so against a live key that query
#: answers ``query_status: error`` -- "Query execution time exceeded
#: threshold. Try a different query." -- confirmed twice, minutes apart, while
#: lighter tags answered at once. A health check that reports a failure on a
#: fully working key is worse than no health check, and a narrower tag is not
#: the fix: tag weight is corpus state, so today's light tag is next year's
#: ``exe``.
#:
#: A hash lookup is the one query whose cost cannot grow with the corpus -- it
#: is a primary-key fetch -- and BOTH of its answers are success-shaped here.
#: A miss arrives as ``hash_not_found``, which is in :data:`_EMPTY_STATUSES`,
#: so :func:`query` returns no rows instead of raising; a hit returns rows the
#: probe discards. Nothing is riding on this digest being unmatchable. What is
#: left that CAN raise is exactly what this tool exists to report: a rejected
#: Auth-Key, an unreachable service, a reply the module did not expect.
_PROBE_SHA256 = hashlib.sha256(b"binary-mcp mb_check_api probe").hexdigest()


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

    A ``query_status`` in :data:`_EMPTY_STATUSES` yields no rows, and the
    caller reports the miss in its own words against its own header.

    Raises:
        MalwareBazaarError: With a curated sentence when ``query_status`` is
            neither ``ok`` nor a documented way of saying nothing matched.
    """
    payload, _ = _request(fields)
    status = _status(payload)
    if status in _EMPTY_STATUSES:
        return []
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


# Rendering
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
    """
    Render one MalwareBazaar field value as a single line.

    Every branch flattens line breaks. A field printed OUTSIDE the F-7 envelope
    has to occupy exactly the line it was given, and a list of tags carrying
    one would have started a second line the envelope does not cover. The
    dict branch was already safe -- json.dumps escapes them -- which is
    exactly why the gap in the branch beside it was easy to miss. The
    shared helper covers U+2028, U+2029 and U+0085 as well as CR and LF.
    """
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        text = ", ".join(str(item) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, sort_keys=True, default=str)
    else:
        text = str(value)
    return flatten_to_one_line(text)


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
                output.append(f"   {ABUSECH_API_KEY_ENV}=your_auth_key_here")
                output.append(
                    f"   (or export {ABUSECH_API_KEY_ENV}=... in the environment)"
                )
                output.append(
                    f"   {MB_API_KEY_ENV} is still read as an alias, but new setups "
                    f"should use {ABUSECH_API_KEY_ENV}: one key covers MalwareBazaar, "
                    "ThreatFox, URLhaus and YARAify."
                )
                return "\n".join(output)

            masked = api_key[:4] + "..." + api_key[-4:] if len(api_key) > 12 else "***"
            output.append(f"Auth-Key configured: {masked}")

            try:
                query({"query": "get_info", "hash": _PROBE_SHA256})
                output.append("API connection successful")
                output.append(
                    "Probe: get_info on one hash -- a primary-key fetch, the "
                    "cheapest query here. It matches nothing, which is the "
                    "expected answer and proves the Auth-Key was accepted"
                )
            except MalwareBazaarError as e:
                # The probe cannot fail by matching nothing: a miss is the
                # DESIGNED answer and arrives as a successful reply with no
                # rows, reported as a connection above. What reaches this
                # branch is a rejected Auth-Key, an unreachable service, or a
                # reply the module did not expect -- the distinction this tool
                # exists to draw. The sentence is this module's own apart from
                # a bare query_status token, already constrained to
                # [a-z0-9_]{1,64} before it is echoed (audit F-7, F-10).
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
        pivot: Literal[
            "tag", "signature", "file_type", "clamav", "imphash",
            "tlsh", "telfhash", "gimphash", "dhash_icon", "yara_rule",
        ],
        value: str,
        limit: int = 20,
    ) -> str:
        """
        Find samples on MalwareBazaar by one corpus pivot.

        MalwareBazaar has a separate query per selector, so a search takes
        exactly one: name it in `pivot` and put the term in `value`.

        After a static pass the structural ones are what to reach for --
        imphash and gimphash cluster by import table, TLSH by byte similarity,
        dhash_icon by icon, yara_rule by a rule that fired.

        Args:
            pivot: Which selector to search by, from the list above
            value: The term to search for, e.g. "AgentTesla" for a tag
            limit: Maximum samples to return (1-1000, default 20)

        Returns:
            Matching samples with hashes, family labels and tags.

        Example:
            mb_search("tag", "AgentTesla", limit=10)
            mb_search("imphash", "f34d5f2d4577ed6d9ceec516c1f5a744")
            mb_search("signature", "Emotet", limit=50)
        """
        try:
            # One parameter naming the selector, rather than one parameter per
            # selector. The API takes exactly one, and eleven optional
            # arguments of which ten must be empty said the opposite in the
            # schema -- the rule only appeared at runtime, after the model had
            # already been shown a shape that allowed any combination.
            argument = (pivot or "").strip().lower()
            value = (value or "").strip()

            names = ", ".join(a for a, _q, _f in MB_SEARCH_PIVOTS)
            if not argument:
                return f"Error: Provide a search pivot. One of: {names}"

            # Literal puts the valid names in the schema, so a conforming
            # client rejects an unknown pivot before it arrives. This check
            # stays because that depends on the client honouring the schema,
            # and it is what the direct callers in the tests exercise.
            match = next((row for row in MB_SEARCH_PIVOTS if row[0] == argument), None)
            if match is None:
                return f"Error: Unknown pivot {pivot!r}. One of: {names}"
            if not value:
                return f"Error: Provide a value to search for with pivot {argument!r}"

            _argument, api_query, api_field = match

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
            if len(rows) > _ROW_LIMIT:
                output.append(f"(showing {_ROW_LIMIT} of {len(rows)})")
            output.append("")

            # F-7: every row leads with a submitter-chosen file name and carries
            # community tags and a family label -- free text from the corpus.
            body: list[str] = []
            for index, entry in enumerate(rows[:_ROW_LIMIT], 1):
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
            if len(rows) > _ROW_LIMIT:
                output.append(f"(showing {_ROW_LIMIT} of {len(rows)})")
            output.append("")

            body: list[str] = []
            for index, entry in enumerate(rows[:_ROW_LIMIT], 1):
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

        DISABLED BY DEFAULT: the operator must set MB_ALLOW_DOWNLOAD=1. This is
        the only tool here that writes malware to disk. It saves abuse.ch's
        password-protected zip (password "infected") under
        ~/.binary_mcp_output/malwarebazaar/ and NEVER extracts it -- do that
        yourself, in an isolated analysis VM.

        It also never overwrites. If an archive is already at the target path
        the download is skipped and the existing file is left untouched, so a
        repeat call cannot destroy a sample you are working from. Delete it
        yourself, or pass output_name, to fetch a fresh copy.

        Args:
            sha256: Full SHA256 of the sample (MalwareBazaar requires SHA256)
            output_name: Optional file name for the archive, relative to the
                download directory. Defaults to "<sha256>.zip". A name that is
                a different sample's SHA256 is refused.

        Returns:
            The path written, the archive size, and the extraction password --
            or, if an archive was already there, a note that nothing was
            downloaded and the existing file was kept.

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
            # Strip BEFORE the fallback, not after. `or` binds first, so a
            # whitespace-only output_name counted as supplied and then stripped
            # to nothing -- every such download landing on the same empty name
            # instead of its own hash.
            default_name = f"{digest}.zip"
            name = (output_name or "").strip() or default_name
            if not name.lower().endswith(".zip"):
                name = f"{name}.zip"

            # Before the path is resolved, because a control character makes
            # this a caller error on every platform rather than a name that is
            # writeable here and rejected there.
            if _CONTROL_CHARS_RE.search(name):
                return _control_character_message(name, default_name)

            MB_DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
            try:
                destination = sanitize_output_path(Path(name), MB_DOWNLOAD_DIR)
            except ValueError as e:
                # sanitize_output_path's ValueError arms interpolate a RESOLVED
                # path ("Parent directory does not exist: ...", "Invalid path:
                # ..."), rooted at Path.home(), so they carry the operator's
                # username. The handler's `except ValueError` arm below echoes
                # its exception verbatim, which is right for normalise_hash --
                # that one quotes the caller's own argument -- and wrong for
                # this one, so it is routed here rather than widening that arm
                # (audit F-10).
                return safe_path_error("mb_download", e, "output path")

            # Which sample a name claims to hold. Split by NAME SHAPE, not by
            # bytes: the archive is an encrypted zip whose bytes differ between
            # two downloads of the same sample, and comparing contents would
            # mean decrypting it, which this module never does.
            slot = destination.name.lower()
            own_slot = slot == default_name

            def _already_present() -> str:
                """The reply for an archive this tool declined to overwrite."""
                try:
                    size = f"{destination.stat().st_size} bytes"
                except OSError:
                    # Raced away between the check and here. Not worth failing
                    # the call over -- the only claim that matters is that
                    # this tool did not write anything.
                    size = "unknown"
                return "\n".join([
                    "MALWAREBAZAAR DOWNLOAD -- ALREADY PRESENT",
                    f"SHA256: {digest}",
                    # flatten_to_one_line for the same F-7 reason as the
                    # success path below: the tail of this path is a
                    # caller-chosen name.
                    f"Kept: {flatten_to_one_line(str(destination))}",
                    f"Size: {size} (existing archive, left untouched)",
                    f'Password: "{MB_ZIP_PASSWORD}"',
                    "",
                    "Nothing was downloaded or written: that name is this "
                    "sample's own SHA256 and the archive there is a zip, so it "
                    "is this sample. Delete it yourself for a fresh copy.",
                    "",
                    _MB_ENCRYPTED_NOTE,
                ])

            # The reservation is checked FIRST, and on the shape alone: an
            # empty slot is the hole an exists()-only guard leaves open, and
            # never overwriting is what makes it lasting. See
            # _reserved_name_message.
            if not own_slot and _HASH_SLOT_RE.match(slot):
                return _reserved_name_message(name, default_name)

            def _occupied() -> str:
                """
                What to say when something already holds this name.

                One function for both arms below, because the exists() check
                and the O_EXCL failure are the same question asked at two
                moments, and a reply that differed between them would be a
                difference in what the server claims about the same file.
                """
                if not _looks_like_archive(destination):
                    return _unusable_archive_message(name, default_name)
                if own_slot:
                    return _already_present()
                return _name_taken_message(name, default_name)

            # Fast path only. The point is to not spend a multi-megabyte
            # transfer fetching a sample that is already on disk; it is NOT the
            # guard. This check can lose a race, O_EXCL below cannot, and the
            # FileExistsError arm is what actually enforces no-overwrite.
            if destination.exists():
                return _occupied()

            archive = download_sample(digest)

            # Atomic create-or-fail (see _ARCHIVE_OPEN_FLAGS). 0o600 keeps a
            # live sample readable only by the owning user, which write_bytes
            # did not do -- it left the archive at the process umask, normally
            # 0o644, i.e. world-readable malware.
            try:
                fd = os.open(str(destination), _ARCHIVE_OPEN_FLAGS, 0o600)
            except FileExistsError:
                # Lost the race. Re-report rather than overwrite: whichever
                # call won wrote a whole archive, and under the default name
                # that archive is this sample.
                return _occupied()

            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(archive)
            except BaseException:
                # Never leave a short write looking like a complete sample --
                # under never-overwrite, no later call could repair it.
                #
                # Not `except OSError`: a MemoryError or a KeyboardInterrupt
                # inside the write would otherwise skip this cleanup entirely.
                # And os.fdopen only takes ownership of the descriptor once it
                # RETURNS, so if that call raises, nothing closes the fd and it
                # leaks for the life of the server. The close is guarded
                # because in the common case the `with` block's own exit
                # already closed it, and a second close raises EBADF -- which
                # would skip the unlink below.
                try:
                    os.close(fd)
                except OSError:
                    pass
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    pass
                raise

            return "\n".join([
                "MALWAREBAZAAR DOWNLOAD",
                f"SHA256: {digest}",
                # flatten_to_one_line: output_name is caller-chosen, a line
                # break is a legal POSIX file name character, and this line is
                # printed outside any untrusted envelope -- so without it the
                # name is a working injection channel into the model's own
                # transcript, able to name a real tool in this server (F-7).
                f"Saved: {flatten_to_one_line(str(destination))}",
                f"Size: {len(archive)} bytes (zip archive, not extracted)",
                f'Password: "{MB_ZIP_PASSWORD}"',
                "",
                _MB_ENCRYPTED_NOTE,
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
