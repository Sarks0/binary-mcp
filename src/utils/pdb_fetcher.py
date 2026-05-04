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

import logging
import os
import re
import shutil
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


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
        return Path(explicit)
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
            return
        if not (lower.startswith("http://") or lower.startswith("https://")):
            logger.warning("Ignoring non-http symbol-server entry: %r", url)
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

    if not servers:
        servers = [DEFAULT_SYMBOL_SERVER]
    return cache_dir, servers


def extract_codeview_record(binary_path: str | Path) -> dict | None:
    """
    Extract the CodeView (RSDS) debug record from a PE file.

    Returns a dict with ``guid`` (uppercase hex string, no dashes), ``age``
    (int), and ``pdb_filename`` (basename only). Returns None if the binary
    isn't PE, has no CodeView record, or the record fails sanity checks.
    """
    try:
        import pefile
    except ImportError:
        logger.debug("pefile unavailable - cannot extract CodeView record")
        return None

    try:
        pe = pefile.PE(str(binary_path), fast_load=True)
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]]
            )
        except Exception as e:
            logger.debug(f"Could not parse debug directory: {e}")
            return None

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
        logger.debug(f"PE parse failed for {binary_path}: {e}")
        return None
    finally:
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
) -> Path:
    """
    Locate or download the PDB matching a binary.

    Order of operations:
      1. Read CodeView record from the PE.
      2. Resolve cache_dir + server list.
      3. Compute canonical cache path; assert it stays inside cache_dir.
      4. If already cached, return it.
      5. Otherwise stream each server in order until one succeeds.

    Raises:
        ValueError: if the binary has no usable CodeView record OR the cache
            path would escape ``cache_dir``.
        RuntimeError: if every configured server fails or the cache dir is
            not writable.
    """
    cv = extract_codeview_record(binary_path)
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

    _ensure_writable(cache_path.parent)

    errors: list[str] = []
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
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                code = resp.getcode()
                if code != 200:
                    errors.append(f"{url} -> HTTP {code}")
                    continue
                try:
                    with open(part_path, "wb") as f:
                        shutil.copyfileobj(resp, f, length=64 * 1024)
                    os.replace(part_path, cache_path)
                finally:
                    try:
                        if part_path.exists():
                            part_path.unlink()
                    except OSError:
                        pass
        except urllib.error.HTTPError as e:
            errors.append(f"{url} -> {e.code} {e.reason}")
            continue
        except urllib.error.URLError as e:
            errors.append(f"{url} -> network error: {e.reason}")
            continue

        size = cache_path.stat().st_size
        logger.info(f"PDB cached at {cache_path} ({size} bytes)")
        return cache_path

    raise RuntimeError(
        "All configured symbol servers failed:\n  " + "\n  ".join(errors)
    )
