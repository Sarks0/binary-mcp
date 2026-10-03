"""
Microsoft Symbol Server PDB fetcher.

Reads the CodeView debug record from a PE file (RSDS signature -> GUID +
age + PDB filename), constructs the canonical symbol-server URL, and
downloads the PDB into a local cache. Designed to make ``load_pdb`` work
without the user having to run ``symchk`` first.

URL format per Microsoft's symbol-server protocol::

    https://msdl.microsoft.com/download/symbols/<pdb-name>/<GUID><AGE>/<pdb-name>

Example::

    diagtrack.pdb/8F9B5A0E5C9D4C3F8B7A6E5D4C3B2A1B1/diagtrack.pdb
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)

# Hard cap on PDB download size. Largest realistic PDB in the wild is the
# Windows kernel at ~120 MB; 256 MB gives plenty of headroom while still
# preventing a hostile/redirected server from filling the cache disk.
MAX_PDB_DOWNLOAD_BYTES = 256 * 1024 * 1024

# Env var that opts out of host validation. For users who legitimately host
# an internal symbol server on RFC1918 / loopback (e.g. a corporate
# symstore).
ALLOW_PRIVATE_SERVERS_ENV = "BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS"


class SymbolServerConfigError(RuntimeError):
    """Every configured symbol server was rejected, so there is none to try.

    Distinct from "none configured": silently substituting the Microsoft
    public server for an operator's internal symstore would send the
    binary's PDB name and GUID somewhere they did not choose.
    """


class SymbolsOfflineError(RuntimeError):
    """``BINARY_MCP_SYMBOL_OFFLINE=1`` and the PDB was not already cached.

    Distinct from every other failure: nothing was sent to any server, and
    the absence says nothing about whether the PDB exists upstream.
    """


class PdbNotPublishedError(RuntimeError):
    """Every symbol server answered 404: the PDB is genuinely not published.

    Raised only when *every* server said "not found". A network error, a
    size-cap refusal, or an empty body (a redirect that landed nowhere) is not
    evidence the PDB doesn't exist, and surfaces as a plain ``RuntimeError``
    so a caller doesn't record "no PDB available" on a transient failure.
    """


def _is_private_or_local_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP is non-routable/sensitive from the agent's POV.

    Catches:
      - Loopback (127.0.0.0/8, ::1)
      - Link-local (169.254.0.0/16, fe80::/10) -- this also covers the
        EC2/GCP/Azure cloud-metadata address 169.254.169.254
      - RFC1918 private (10/8, 172.16/12, 192.168/16) and IPv6 ULA
      - Unspecified (0.0.0.0, ::)
      - Reserved / multicast (defence in depth)
    """
    # ``is_private`` covers RFC1918 + IPv6 ULA + loopback + link-local on
    # modern Python, but we add explicit checks so the intent stays obvious
    # if the stdlib semantics ever drift.
    return (
        ip.is_loopback
        or ip.is_link_local        # covers 169.254.169.254 cloud metadata
        or ip.is_private           # RFC1918 + ULA
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def _is_safe_symbol_server_host(host: str) -> bool:
    """Return True if ``host`` is safe to use as a symbol-server target.

    Rejects loopback, link-local (incl. 169.254.169.254 cloud-metadata),
    RFC1918, and DNS names that resolve to any of the above. Honours the
    ``BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS=1`` opt-out so users running
    a corporate internal symstore can keep working.

    Factored out as a module-level function so tests can exercise it
    directly without monkeypatching urlopen.
    """
    if not host:
        return False

    if os.environ.get(ALLOW_PRIVATE_SERVERS_ENV) == "1":
        return True

    # Strip an optional bracketed IPv6 literal: ``[::1]`` -> ``::1``.
    bare = host
    if bare.startswith("[") and bare.endswith("]"):
        bare = bare[1:-1]

    # Direct IP literal? Validate without DNS.
    try:
        ip = ipaddress.ip_address(bare)
        return not _is_private_or_local_ip(ip)
    except ValueError:
        pass  # Not a literal -- fall through to DNS resolution.

    # DNS name -- resolve every A/AAAA and reject if ANY answer is private.
    # An attacker controlling the DNS for a public-looking name could
    # otherwise pin one record to a public IP and another to 127.0.0.1.
    try:
        infos = socket.getaddrinfo(bare, None)
    except socket.gaierror as e:
        # If we can't resolve, let the urlopen call surface the real
        # network error rather than masquerading as a validation failure.
        logger.debug("Could not resolve symbol-server host %r: %s", bare, e)
        return True

    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            continue
        if _is_private_or_local_ip(ip):
            return False
    return True


def _host_from_url(url: str) -> str | None:
    """Extract the hostname from a URL, lowercased. Returns None on parse failure."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    host = parsed.hostname
    return host.lower() if host else None


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """HTTPRedirectHandler that re-validates each redirect target.

    Default urllib behaviour silently follows 30x redirects, which a
    hostile public symbol server could exploit to bounce us at an internal
    IP (169.254.169.254 / 127.0.0.1 / RFC1918). Validating on every hop
    closes that hole.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        host = _host_from_url(newurl)
        if host is None or not _is_safe_symbol_server_host(host):
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"Refusing redirect to disallowed host: {host!r} "
                f"(set {ALLOW_PRIVATE_SERVERS_ENV}=1 to opt in)",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_symbol_cache() -> Path:
    """Resolve the default symbol cache path, honoring XDG_CACHE_HOME on POSIX.

    Override priority:
      1. ``BINARY_MCP_SYMBOL_CACHE`` env var (unified across static
         analysis and dynamic WinDbg debugging - both surfaces share
         the same cache so a PDB downloaded for analyze_binary is
         immediately available to a live KDNET session).
      2. Platform default (Windows: ``~/.binary_mcp_cache/symbols``;
         POSIX: ``$XDG_CACHE_HOME/binary_mcp/symbols``).
    """
    explicit = os.environ.get("BINARY_MCP_SYMBOL_CACHE")
    if explicit:
        # .expanduser() matters: security.default_quarantine_dirs() and
        # carving._default_carve_dir() both expand '~' on this variable, and
        # this one did not. With BINARY_MCP_SYMBOL_CACHE=~/symbols the fetcher
        # created a LITERAL directory named '~' under the process CWD while
        # confinement allowed $HOME/symbols -- so the server downloaded a PDB
        # and then refused to read it back. That write-then-refuse class has
        # already shipped from this branch twice; the three resolvers now agree.
        return Path(explicit).expanduser()
    if sys.platform == "win32":
        return Path.home() / ".binary_mcp_cache" / "symbols"
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "binary_mcp" / "symbols"


DEFAULT_SYMBOL_CACHE = _default_symbol_cache()
DEFAULT_SYMBOL_SERVER = os.environ.get(
    "BINARY_MCP_SYMBOL_SERVER",
    "https://msdl.microsoft.com/download/symbols",
)

# Air-gap switch. Documented in config.py and honoured by the WinDbg
# sympath builder; fetch_pdb has to honour it too, because the automatic
# fetch on first import now reaches the network without an operator asking.
SYMBOL_OFFLINE_ENV = "BINARY_MCP_SYMBOL_OFFLINE"


def symbols_offline() -> bool:
    """True when the operator has asked for cache-only symbol resolution."""
    return os.environ.get(SYMBOL_OFFLINE_ENV) == "1"


MAX_CODEVIEW_BYTES = 64 * 1024
_PDB_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.pdb$", re.IGNORECASE)
_GUID_RE = re.compile(r"^[0-9A-F]{32}$")


def _sanitize_pdb_name(name: str | bytes | None) -> str | None:
    """Return a safe PDB filename or None if the input is not acceptable.

    Accepts only basenames matching ``[A-Za-z0-9._-]+\\.pdb`` (case-insensitive),
    strips embedded NULs, rejects ``.`` / ``..`` and anything with path
    separators after `Path(...).name` collapsing.
    """
    if name is None:
        return None
    if isinstance(name, bytes):
        name = name.rstrip(b"\x00").decode("utf-8", errors="replace")
    name = name.replace("\x00", "").strip()
    if not name or name in (".", ".."):
        return None
    if "/" in name or "\\" in name:
        return None
    if not name or len(name) > 256:
        return None
    if not _PDB_NAME_RE.match(name):
        return None
    return name


def _sanitize_guid(guid: str | bytes | None) -> str | None:
    """Validate a CodeView GUID string (32 uppercase hex chars)."""
    if guid is None:
        return None
    if isinstance(guid, bytes):
        guid = guid.decode("ascii", errors="replace")
    guid = guid.strip().upper().replace("-", "")
    if not _GUID_RE.match(guid):
        return None
    return guid


def parse_symbol_path(
    symbol_path: str | None = None,
) -> tuple[Path, list[str]]:
    """
    Parse a Windows-style ``_NT_SYMBOL_PATH`` into (local_cache, [servers]).

    Recognised entry forms (separated by ``;``):
      - ``srv*<localcache>*<url>`` - standard symbol-server entry
      - ``srv*<url>`` - server with no explicit cache (uses default)
      - ``cache*<localcache>`` - override local cache only
      - ``<url>`` - bare URL, treated as a server with default cache

    Resolution order:
      1. Explicit ``symbol_path`` argument
      2. ``BINARY_MCP_SYMBOL_PATH`` env var
      3. ``_NT_SYMBOL_PATH`` env var
      4. Built-in default

    ``http://`` URLs are dropped with a warning unless
    ``BINARY_MCP_ALLOW_HTTP_SYMBOLS=1`` is set in the environment, since PDBs
    are parsed by Ghidra and a MITM-modified PDB can poison symbol/type data.

    Unrecognised entries are logged and skipped (instead of being silently
    dropped) so misconfiguration is easier to debug.

    Returns an EMPTY server list when every configured server was rejected.
    The built-in default is substituted only when nothing was configured at
    all -- an operator whose internal symstore we dropped must not have their
    binary's PDB name and GUID sent to Microsoft instead.
    """
    if symbol_path is None:
        symbol_path = (
            os.environ.get("BINARY_MCP_SYMBOL_PATH")
            or os.environ.get("_NT_SYMBOL_PATH")
        )

    allow_http = os.environ.get("BINARY_MCP_ALLOW_HTTP_SYMBOLS") == "1"

    cache_dir: Path = DEFAULT_SYMBOL_CACHE
    servers: list[str] = []
    cache_set = False
    # Did the configuration name a server that we then refused? That is not
    # the same as naming none, and the two must not resolve the same way.
    rejected: list[str] = []

    def _maybe_add_server(url: str) -> None:
        if not url:
            return
        lower = url.lower()
        if lower.startswith("http://") and not allow_http:
            logger.warning(
                "Insecure symbol server (http://) dropped; set "
                "BINARY_MCP_ALLOW_HTTP_SYMBOLS=1 to permit: %s",
                url,
            )
            rejected.append(url)
            return
        if not (lower.startswith("http://") or lower.startswith("https://")):
            logger.warning("Ignoring non-http symbol-server entry: %r", url)
            rejected.append(url)
            return
        host = _host_from_url(url)
        if host is None:
            logger.warning("Ignoring symbol-server entry with unparseable host: %r", url)
            rejected.append(url)
            return
        if not _is_safe_symbol_server_host(host):
            logger.warning(
                "Symbol server %s resolves to a private/loopback/link-local "
                "address and was dropped to prevent SSRF; set "
                "'%s=1' to allow internal symbol servers.",
                url,
                ALLOW_PRIVATE_SERVERS_ENV,
            )
            rejected.append(url)
            return
        servers.append(url)

    if symbol_path:
        for entry in symbol_path.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("*")
            head = parts[0].lower()
            if head == "srv":
                if len(parts) == 2:
                    _maybe_add_server(parts[1])
                elif len(parts) >= 3:
                    if not cache_set:
                        cache_dir = Path(parts[1])
                        cache_set = True
                    for p in parts[2:]:
                        _maybe_add_server(p)
                else:
                    logger.warning("Ignoring malformed srv* entry: %r", entry)
            elif head == "cache":
                if len(parts) >= 2 and not cache_set:
                    cache_dir = Path(parts[1])
                    cache_set = True
                else:
                    logger.warning("Ignoring malformed cache* entry: %r", entry)
            elif entry.lower().startswith(("http://", "https://")):
                _maybe_add_server(entry)
            else:
                logger.warning(
                    "Ignoring unrecognized _NT_SYMBOL_PATH entry: %r", entry
                )

    if not servers and not rejected:
        # Nothing was configured, so the built-in default applies. When
        # something WAS configured and we refused all of it, the list stays
        # empty: fetch_pdb turns that into a clear configuration error
        # rather than quietly asking Microsoft about the operator's binary.
        servers = [DEFAULT_SYMBOL_SERVER]
    return cache_dir, servers


# Distinguishes "no handle was passed" (open one) from "the caller's shared
# open already failed" (there is nothing to read, and retrying it here is how
# a single read of a 400 MB binary became three).
_NO_PE = object()


def open_pe_for_symbols(binary_path: str | Path):
    """A ``pefile.PE`` with the debug AND resource directories parsed, or None.

    One open, one whole-file read, for a caller that needs both the CodeView
    record and the version resource. ``auto_fetch_pdb`` needs both and then
    hands the record to ``fetch_pdb``: done separately that is three full
    reads of the binary on the first-import path -- ~1.2 GB of I/O on a
    400 MB target, for data already in hand. The caller closes it.
    """
    try:
        import pefile
    except ImportError:
        logger.debug("pefile unavailable - cannot read PE symbol metadata")
        return None
    try:
        pe = pefile.PE(str(binary_path), fast_load=True)
    except Exception as e:
        logger.debug(f"PE parse failed for {binary_path}: {e}")
        return None
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
        ])
    except Exception as e:
        # A binary with no debug or no resource directory is ordinary; the
        # readers below simply find nothing.
        logger.debug(f"Could not parse data directories for {binary_path}: {e}")
    return pe


def extract_codeview_record(binary_path: str | Path, pe=_NO_PE) -> dict | None:
    """
    Extract the CodeView (RSDS) debug record from a PE file.

    Returns a dict with ``guid`` (uppercase hex string, no dashes), ``age``
    (int), and ``pdb_filename`` (basename only). Returns None if the binary
    isn't PE, has no CodeView record, or the record fails sanity checks.

    ``pe`` is an already-open :func:`open_pe_for_symbols` handle to read from
    instead of opening the file again; the caller keeps ownership of it, and
    passing an explicit ``None`` (its open failed) returns None without
    re-opening.
    """
    owned = pe is _NO_PE
    if owned:
        pe = open_pe_for_symbols(binary_path)
    if pe is None:
        return None

    try:
        debug = getattr(pe, "DIRECTORY_ENTRY_DEBUG", None) or []
        for entry in debug:
            data = getattr(entry, "entry", None)
            if data is None and not getattr(entry, "struct", None):
                continue
            cv = _decode_codeview(entry, pe)
            if cv:
                return cv
        return None
    except Exception as e:
        logger.debug(f"CodeView read failed for {binary_path}: {e}")
        return None
    finally:
        if owned:
            try:
                pe.close()
            except Exception:
                pass


def _decode_codeview(entry, pe) -> dict | None:
    """Decode an RSDS CodeView entry into {guid, age, pdb_filename}."""
    if getattr(entry.struct, "Type", None) != 2:
        return None

    raw = getattr(entry, "entry", None)

    # Some pefile versions emit Signature_String as bytes instead of str.
    if raw is not None and hasattr(raw, "Signature_String") and hasattr(raw, "Age"):
        try:
            sig = _sanitize_guid(getattr(raw, "Signature_String", None))
            age = int(getattr(raw, "Age", 0))
            pdb_name = _sanitize_pdb_name(getattr(raw, "PdbFileName", None))
            if sig and pdb_name:
                return {
                    "guid": sig,
                    "age": age,
                    "pdb_filename": pdb_name,
                }
        except Exception as e:
            logger.debug(f"pefile RSDS decode failed: {e}")

    file_off = getattr(entry.struct, "PointerToRawData", 0) or 0
    size = getattr(entry.struct, "SizeOfData", 0) or 0
    # Bound size: CodeView records are tiny. An attacker-controlled SizeOfData
    # could otherwise trigger a multi-GB slice.
    if size <= 0 or size > MAX_CODEVIEW_BYTES:
        logger.debug(f"CodeView SizeOfData out of bounds: {size}")
        return None

    raw_bytes = b""
    if file_off:
        try:
            data = pe.__data__
            if file_off + size <= len(data):
                raw_bytes = data[file_off:file_off + size]
        except Exception as e:
            logger.debug(f"Direct read of debug bytes failed: {e}")

    if not raw_bytes:
        try:
            raw_bytes = pe.get_data(
                entry.struct.AddressOfRawData, size
            )
        except Exception as e:
            logger.debug(f"RVA read of debug bytes failed: {e}")
            return None

    if len(raw_bytes) < 24 or raw_bytes[:4] != b"RSDS":
        return None
    try:
        guid_bytes = raw_bytes[4:20]
        age = struct.unpack("<I", raw_bytes[20:24])[0]
        name = raw_bytes[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        d1 = struct.unpack("<I", guid_bytes[0:4])[0]
        d2 = struct.unpack("<H", guid_bytes[4:6])[0]
        d3 = struct.unpack("<H", guid_bytes[6:8])[0]
        d4 = guid_bytes[8:16]
        guid_str = "{:08X}{:04X}{:04X}{}".format(
            d1, d2, d3, "".join(f"{b:02X}" for b in d4)
        )
        guid = _sanitize_guid(guid_str)
        pdb_name = _sanitize_pdb_name(name)
        if not guid or not pdb_name:
            return None
        return {
            "guid": guid,
            "age": age,
            "pdb_filename": pdb_name,
        }
    except Exception as e:
        logger.debug(f"Manual RSDS decode failed: {e}")
        return None


def build_symbol_server_url(
    cv: dict, server: str = DEFAULT_SYMBOL_SERVER
) -> str:
    """Build the canonical symbol-server URL for a CodeView record."""
    encoded_name = urllib.parse.quote(cv["pdb_filename"], safe="")
    return (
        f"{server.rstrip('/')}/"
        f"{encoded_name}/"
        f"{cv['guid']}{cv['age']:X}/"
        f"{encoded_name}"
    )


def _ensure_writable(cache_dir: Path) -> None:
    """Verify the cache dir is writable; raise RuntimeError with a clear message."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    sentinel = cache_dir / ".binary_mcp_writable"
    try:
        sentinel.write_bytes(b"")
        sentinel.unlink()
    except OSError as e:
        raise RuntimeError(f"Symbol cache dir is not writable: {cache_dir}: {e}")


def fetch_pdb(
    binary_path: str | Path,
    cache_dir: Path | None = None,
    server: str | None = None,
    symbol_path: str | None = None,
    timeout: int = 300,
    codeview: dict | None = None,
) -> Path:
    """
    Locate or download the PDB matching a binary.

    Order of operations:
      1. Read the CodeView record from the PE (or take ``codeview``).
      2. Resolve cache_dir + server list.
      3. Compute canonical cache path; assert it stays inside cache_dir.
      4. If already cached, return it.
      5. Otherwise stream each server in order until one succeeds.

    Raises:
        ValueError: if the binary has no usable CodeView record OR the cache
            path would escape ``cache_dir``.
        SymbolServerConfigError: if every configured symbol server was
            rejected. Nothing was sent anywhere, and no default was assumed.
        SymbolsOfflineError: if ``BINARY_MCP_SYMBOL_OFFLINE=1`` and the PDB
            is not already in the local cache. Nothing was sent anywhere.
        PdbNotPublishedError: if every configured server answered 404.
        RuntimeError: if every configured server fails for any other reason
            (network, empty body, size cap) or the cache dir is not writable.
    """
    # `codeview`: a record the caller already read, so a first import does
    # not re-read the whole binary to recover what it just had.
    cv = codeview or extract_codeview_record(binary_path)
    if cv is None:
        raise ValueError(
            f"No CodeView (RSDS) debug record found in {binary_path}. "
            f"The binary was likely built without /DEBUG, or the debug "
            f"directory has been stripped, or the record failed validation."
        )

    parsed_cache, servers = parse_symbol_path(symbol_path)
    if cache_dir is None:
        cache_dir = parsed_cache
    if server is not None:
        servers = [server]
    if not servers:
        raise SymbolServerConfigError(
            "every configured symbol server was rejected (see the warnings "
            "logged by parse_symbol_path -- http:// needs "
            "BINARY_MCP_ALLOW_HTTP_SYMBOLS=1, a private or loopback host "
            f"needs {ALLOW_PRIVATE_SERVERS_ENV}=1). No request was made, and "
            "the Microsoft public server was NOT substituted."
        )

    cache_dir = Path(cache_dir)
    cache_path = (
        cache_dir
        / cv["pdb_filename"]
        / f"{cv['guid']}{cv['age']:X}"
        / cv["pdb_filename"]
    )

    # Defence-in-depth: even with sanitized inputs, assert the resolved path
    # lives under cache_dir. Catches surprises from symlinks or odd CWDs.
    try:
        resolved_root = cache_dir.resolve()
        # parents may not exist yet; use absolute() for the candidate.
        resolved_candidate = cache_path.absolute()
        if not resolved_candidate.is_relative_to(resolved_root):
            raise ValueError(
                f"Refusing to write PDB outside cache dir: {cache_path}"
            )
    except ValueError:
        raise
    except Exception as e:
        logger.debug(f"Path containment check error (non-fatal): {e}")

    if cache_path.exists() and cache_path.stat().st_size > 0:
        logger.info(f"PDB cache hit: {cache_path}")
        return cache_path

    # Cache-only mode: the hit above is all an air-gapped session gets. Check
    # here rather than earlier so a pre-populated cache still resolves.
    if symbols_offline():
        # Deliberately no cache path in the message: it is echoed verbatim by
        # load_pdb and stored in the analysis note, and a resolved
        # ~/.cache/... path is host detail (audit F-10). The env var names
        # where to look.
        raise SymbolsOfflineError(
            f"{SYMBOL_OFFLINE_ENV}=1 and {cv['pdb_filename']} is not in the "
            f"local symbol cache; no symbol server was contacted. "
            f"Pre-populate the cache (BINARY_MCP_SYMBOL_CACHE) or unset "
            f"{SYMBOL_OFFLINE_ENV}."
        )

    _ensure_writable(cache_path.parent)

    # Build an opener that re-validates the host on every redirect hop.
    # We avoid install_opener() so we don't mutate global state -- callers
    # of urllib elsewhere in the process should remain unaffected.
    opener = urllib.request.build_opener(_SafeRedirectHandler())

    errors: list[str] = []
    # Did every server positively say "not found"? Anything else leaves the
    # question open, and the caller must not report "not published".
    all_not_found = True
    for srv in servers:
        url = build_symbol_server_url(cv, srv)
        logger.info(f"Trying symbol server: {url}")
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Microsoft-Symbol-Server/10.0.0.0",
            },
        )
        part_path = cache_path.with_suffix(cache_path.suffix + ".part")
        try:
            with opener.open(req, timeout=timeout) as resp:  # nosec B310
                code = resp.getcode()
                if code != 200:
                    errors.append(f"{url} -> HTTP {code}")
                    all_not_found = False
                    continue

                # Reject before streaming if the server advertises a size
                # that exceeds the cap. Saves disk + bandwidth on hostile
                # responses.
                content_length_raw = resp.headers.get("Content-Length")
                if content_length_raw is not None:
                    try:
                        content_length = int(content_length_raw)
                    except (TypeError, ValueError):
                        content_length = None
                    else:
                        if content_length > MAX_PDB_DOWNLOAD_BYTES:
                            errors.append(
                                f"{url} -> Content-Length {content_length} "
                                f"exceeds cap {MAX_PDB_DOWNLOAD_BYTES}"
                            )
                            all_not_found = False
                            continue

                try:
                    bytes_written = 0
                    oversized = False
                    chunk_size = 64 * 1024
                    with open(part_path, "wb") as f:
                        while True:
                            chunk = resp.read(chunk_size)
                            if not chunk:
                                break
                            bytes_written += len(chunk)
                            if bytes_written > MAX_PDB_DOWNLOAD_BYTES:
                                oversized = True
                                break
                            f.write(chunk)
                    if oversized:
                        errors.append(
                            f"{url} -> response exceeded size cap "
                            f"({MAX_PDB_DOWNLOAD_BYTES} bytes)"
                        )
                        all_not_found = False
                        # Cleanup happens in the finally below.
                        continue
                    if bytes_written == 0:
                        # Typically a 302 whose target served nothing. Caching
                        # a zero-byte "PDB" would hand Ghidra garbage, and it
                        # is not a "not published" answer either.
                        errors.append(
                            f"{url} -> empty response body (HTTP {code}, final "
                            f"URL {resp.geturl() if hasattr(resp, 'geturl') else url}); "
                            f"not evidence the PDB is unpublished -- retry"
                        )
                        all_not_found = False
                        continue
                    os.replace(part_path, cache_path)
                finally:
                    try:
                        if part_path.exists():
                            part_path.unlink()
                    except OSError:
                        pass
        except urllib.error.HTTPError as e:
            errors.append(f"{url} -> {e.code} {e.reason}")
            if e.code != 404:
                all_not_found = False
            continue
        except urllib.error.URLError as e:
            errors.append(f"{url} -> network error: {e.reason}")
            all_not_found = False
            continue

        size = cache_path.stat().st_size
        logger.info(f"PDB cached at {cache_path} ({size} bytes)")
        return cache_path

    message = "All configured symbol servers failed:\n  " + "\n  ".join(errors)
    if all_not_found and errors:
        raise PdbNotPublishedError(message)
    raise RuntimeError(message)


# Automatic fetch on first analysis
#
# Fetching sends the PDB name and GUID to the symbol server, which for a
# malware sample tells a third party what you are looking at. The default
# therefore only reaches out for binaries that claim to be Microsoft's --
# the case the symbol server can actually answer -- and the operator can
# widen or disable it.
AUTO_PDB_ENV = "BINARY_MCP_AUTO_PDB"
AUTO_PDB_POLICIES = ("microsoft", "always", "never")
AUTO_PDB_DEFAULT = "microsoft"
AUTO_PDB_TIMEOUT_SECONDS = 120


def auto_pdb_policy() -> str:
    """The configured policy, falling back to the default on a bad value."""
    value = (os.environ.get(AUTO_PDB_ENV) or AUTO_PDB_DEFAULT).strip().lower()
    if value not in AUTO_PDB_POLICIES:
        logger.warning(
            "%s=%r is not one of %s; using %r",
            AUTO_PDB_ENV, value, ", ".join(AUTO_PDB_POLICIES), AUTO_PDB_DEFAULT,
        )
        return AUTO_PDB_DEFAULT
    return value


def _pefile_available() -> bool:
    """True if ``pefile`` can be imported. Kept separate so the vendor gate
    can tell "this is not a Microsoft binary" apart from "we could not read
    the version resource at all"."""
    try:
        import pefile  # noqa: F401
    except ImportError:
        return False
    return True


def version_info_company(binary_path: str | Path, pe=_NO_PE) -> str | None:
    """``CompanyName`` from the PE's version resource, or None.

    ``pe`` is an already-open :func:`open_pe_for_symbols` handle to read from
    instead of opening the file again; the caller keeps ownership of it, and
    passing an explicit ``None`` (its open failed) returns None without
    re-opening.
    """
    owned = pe is _NO_PE
    if owned:
        pe = open_pe_for_symbols(binary_path)
    if pe is None:
        return None
    try:
        try:
            for file_info_list in getattr(pe, "FileInfo", None) or []:
                for entry in file_info_list:
                    for table in getattr(entry, "StringTable", None) or []:
                        for key, value in table.entries.items():
                            k = key.decode("utf-8", "ignore") if isinstance(key, bytes) else str(key)
                            if k == "CompanyName":
                                v = value.decode("utf-8", "ignore") if isinstance(value, bytes) else str(value)
                                return v.strip() or None
        finally:
            if owned:
                pe.close()
    except Exception as e:
        logger.debug(f"Could not read version info from {binary_path}: {e}")
    return None


# Hosts that only ever serve Microsoft's own PDBs. The vendor gate below
# applies only when EVERY configured server is one of these: a corporate
# symstore, or a vendor's own server (Chromium, Mozilla, Unity all run one),
# may legitimately hold symbols for non-Microsoft code and must not be
# second-guessed.
MICROSOFT_ONLY_SYMBOL_HOSTS = frozenset({
    "msdl.microsoft.com",
    "symweb.azurefd.net",
})


# CompanyName comes out of the sample's own version resource. Server-authored
# text that quotes it has to bound it and strip the envelope spellings, or the
# sample chooses what the model reads around it.
MAX_COMPANY_CHARS = 120


def safe_company(company: str | None) -> str:
    """A bounded, delimiter-neutralised rendering of a sample's CompanyName.

    For embedding in server-authored prose (log lines, cache notes). A block
    a reader will treat as sample data belongs in ``wrap_untrusted`` instead.
    """
    if not company:
        return "None"
    from src.utils.formatters import neutralise_untrusted_delimiters

    text = neutralise_untrusted_delimiters(str(company))
    text = text.replace("\r", " ").replace("\n", " ")
    if len(text) > MAX_COMPANY_CHARS:
        text = text[:MAX_COMPANY_CHARS] + "..."
    return repr(text)


def symbol_servers_are_microsoft_only(symbol_path: str | None = None) -> bool:
    """True if every configured symbol server is a Microsoft-only public one.

    Resolves the same server list ``fetch_pdb`` would use, so the answer
    reflects ``symbol_path`` / ``BINARY_MCP_SYMBOL_PATH`` / ``_NT_SYMBOL_PATH``
    / ``BINARY_MCP_SYMBOL_SERVER``, not an assumption about the default.
    """
    _, servers = parse_symbol_path(symbol_path)
    if not servers:
        # Every configured server was rejected. Not "Microsoft-only": there
        # is no server at all, and fetch_pdb will say so.
        return False
    for srv in servers:
        host = _host_from_url(srv)
        if host is None or host not in MICROSOFT_ONLY_SYMBOL_HOSTS:
            return False
    return True


def symbol_server_prognosis(
    binary_path: str | Path, symbol_path: str | None = None, pe=_NO_PE
) -> dict:
    """Judge, before any network call, whether a fetch can plausibly succeed.

    The public Microsoft symbol server holds PDBs for Microsoft's own builds
    and nothing else, so asking it about a third-party binary (steam.exe,
    a game, a vendor driver) buys a guaranteed 404 -- plus a disclosure of
    the PDB name and GUID to Microsoft, and, via ``load_pdb``, a discarded
    cache and a full Ghidra re-analysis for no symbols at all.

    Returns a dict with:
      ``is_microsoft``   -- version info names Microsoft
      ``company``        -- the ``CompanyName`` string, or None if absent
      ``microsoft_only_servers`` -- every configured server is MS-public-only
      ``likely``         -- worth attempting: a Microsoft binary, or a server
                            set that might serve third-party symbols
      ``reason``         -- one line explaining the verdict, for the caller
                            to put in front of the model
    """
    company = version_info_company(binary_path, pe=pe)
    is_microsoft = bool(company) and "microsoft" in company.lower()
    ms_only = symbol_servers_are_microsoft_only(symbol_path)

    if company is None and not _pefile_available():
        # No verdict is possible -- don't turn a missing dependency into a
        # refusal to fetch symbols for a genuine Microsoft binary.
        return {
            "is_microsoft": False,
            "company": None,
            "microsoft_only_servers": ms_only,
            "likely": True,
            "reason": (
                "the vendor could not be determined (pefile is not "
                "installed), so the fetch is attempted rather than refused"
            ),
        }

    # ``reason`` is server-authored and carries NO text read out of the
    # sample: ``company`` comes from the PE's own version resource, so a
    # caller that renders it has to fence it (wrap_untrusted) first.
    if is_microsoft:
        reason = "the binary's version info names Microsoft"
    elif not ms_only:
        reason = (
            "the version info does not name Microsoft, but the configured "
            "symbol path points somewhere other than the Microsoft public "
            "server, which may hold third-party symbols"
        )
    elif company:
        reason = (
            "the version info names a third-party vendor, and the Microsoft "
            "public symbol server only serves Microsoft's own PDBs"
        )
    else:
        reason = (
            "the binary carries no CompanyName in its version resource, so "
            "there is nothing to suggest the Microsoft public symbol server "
            "has its PDB"
        )

    return {
        "is_microsoft": is_microsoft,
        "company": company,
        "microsoft_only_servers": ms_only,
        "likely": is_microsoft or not ms_only,
        "reason": reason,
    }


def auto_fetch_pdb(
    binary_path: str | Path,
    policy: str | None = None,
    timeout: int = AUTO_PDB_TIMEOUT_SECONDS,
) -> tuple[str | None, dict | None]:
    """Try to fetch the PDB for a first analysis. Never raises.

    Returns ``(pdb_path_or_None, note)``; ``note`` is None for a non-PE. ``note`` is recorded in the analysis
    metadata so the summary can say why names are or aren't there:
    ``{"source": "auto", "status": ..., "detail": ...}`` where status is one
    of ``fetched``, ``not_published``, ``fetch_failed``, ``no_codeview`` or
    ``skipped``. Only ``not_published`` means the PDB doesn't exist;
    ``fetch_failed`` means nobody knows yet.
    """
    try:
        with open(binary_path, "rb") as fh:
            if fh.read(2) != b"MZ":
                return None, None  # not a PE: PDBs don't apply, nothing to report
    except OSError:
        return None, None

    policy = policy or auto_pdb_policy()
    note: dict = {"source": "auto", "policy": policy}

    if policy == "never":
        return None, {**note, "status": "skipped", "detail": f"{AUTO_PDB_ENV}=never"}

    # One open for both reads below, and the record travels on to fetch_pdb.
    pe = open_pe_for_symbols(binary_path)
    try:
        codeview = extract_codeview_record(binary_path, pe=pe)
        prognosis = (
            symbol_server_prognosis(binary_path, pe=pe)
            if policy == "microsoft"
            else None
        )
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    if codeview is None:
        return None, {
            **note,
            "status": "no_codeview",
            "detail": "binary has no CodeView (RSDS) record, so there is no PDB to look up",
        }

    if prognosis is not None:
        # `likely`, not `is_microsoft`: a third-party binary is only hopeless
        # when every configured server is a Microsoft-only public one. An
        # operator who pointed us at a vendor server or a corporate symstore
        # gets the fetch -- load_pdb's gate makes the same call.
        if not prognosis["likely"]:
            return None, {
                **note,
                "status": "skipped",
                "detail": (
                    f"not a Microsoft binary "
                    f"(CompanyName={safe_company(prognosis['company'])}); the "
                    f"Microsoft public symbol server only serves Microsoft's "
                    f"own PDBs, so there is nothing there to fetch -- do NOT "
                    f"retry with load_pdb unless you have the vendor's PDB on "
                    f"disk (pdb_path=...) or a symbol server that carries it "
                    f"(symbol_path=...). Set {AUTO_PDB_ENV}=always to attempt "
                    f"a fetch anyway"
                ),
            }

    try:
        path = fetch_pdb(binary_path, timeout=timeout, codeview=codeview)
    except SymbolServerConfigError as e:
        # A misconfiguration, not a transient failure: retrying changes
        # nothing until the operator fixes the symbol path.
        return None, {**note, "status": "skipped", "detail": str(e)}
    except SymbolsOfflineError as e:
        # Not a failure: the operator asked for cache-only resolution and the
        # cache did not have it. Nothing was sent anywhere.
        return None, {**note, "status": "skipped", "detail": str(e)}
    except PdbNotPublishedError as e:
        return None, {**note, "status": "not_published", "detail": str(e)}
    except (RuntimeError, ValueError, OSError) as e:
        return None, {**note, "status": "fetch_failed", "detail": str(e)}
    return str(path), {**note, "status": "fetched", "pdb_path": str(path)}
