"""
Microsoft Symbol Server PDB fetcher.

Reads the CodeView debug record from a PE file (RSDS signature → GUID +
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
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SYMBOL_CACHE = Path.home() / ".binary_mcp_cache" / "symbols"
DEFAULT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


def parse_symbol_path(
    symbol_path: str | None = None,
) -> tuple[Path, list[str]]:
    """
    Parse a Windows-style ``_NT_SYMBOL_PATH`` into (local_cache, [servers]).

    Recognised entry forms (separated by ``;``):
      - ``srv*<localcache>*<url>`` -- standard symbol-server entry
      - ``srv*<url>`` -- server with no explicit cache (uses default)
      - ``cache*<localcache>`` -- override local cache only
      - ``<url>`` -- bare URL, treated as a server with default cache

    Resolution order:
      1. Explicit ``symbol_path`` argument
      2. ``BINARY_MCP_SYMBOL_PATH`` env var
      3. ``_NT_SYMBOL_PATH`` env var
      4. Built-in default (msdl.microsoft.com + ~/.binary_mcp_cache/symbols)

    Returns the first ``cache*`` value (or default) and the ordered list of
    server URLs to try. Cache lookup uses the single returned cache_dir;
    downloads iterate the server list and stop on the first success.
    """
    if symbol_path is None:
        symbol_path = (
            os.environ.get("BINARY_MCP_SYMBOL_PATH")
            or os.environ.get("_NT_SYMBOL_PATH")
        )

    cache_dir: Path = DEFAULT_SYMBOL_CACHE
    servers: list[str] = []
    cache_set = False

    if symbol_path:
        for entry in symbol_path.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            parts = entry.split("*")
            head = parts[0].lower()
            if head == "srv":
                # srv*url     | srv*cache*url   | srv*cache*url1*url2...
                if len(parts) == 2:
                    servers.append(parts[1])
                elif len(parts) >= 3:
                    if not cache_set:
                        cache_dir = Path(parts[1])
                        cache_set = True
                    servers.extend(p for p in parts[2:] if p)
            elif head == "cache":
                if len(parts) >= 2 and not cache_set:
                    cache_dir = Path(parts[1])
                    cache_set = True
            elif entry.lower().startswith(("http://", "https://")):
                servers.append(entry)
            # Anything else (e.g. plain local path) is ignored -- those are
            # legitimate _NT_SYMBOL_PATH entries on Windows but we have no
            # way to scan them remotely.

    if not servers:
        servers = [DEFAULT_SYMBOL_SERVER]
    return cache_dir, servers


def extract_codeview_record(binary_path: str | Path) -> dict | None:
    """
    Extract the CodeView (RSDS) debug record from a PE file.

    Returns a dict with ``guid`` (uppercase hex string, no dashes), ``age``
    (int), and ``pdb_filename`` (basename only — server doesn't accept paths).
    Returns None if the binary isn't PE, has no CodeView record, or the
    record is malformed.
    """
    try:
        import pefile
    except ImportError:
        logger.debug("pefile unavailable — cannot extract CodeView record")
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
            if data is None:
                continue
            # CodeView entry exposes PdbFileName + Signature_(Data1..Data4) +
            # Age, but only when pefile recognises RSDS. Fall back to manual
            # parsing if not.
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
    raw = entry.entry
    # pefile's parsed RSDS object has these fields directly
    if hasattr(raw, "PdbFileName") and hasattr(raw, "Signature_Data1"):
        try:
            d1 = raw.Signature_Data1
            d2 = raw.Signature_Data2
            d3 = raw.Signature_Data3
            d4 = raw.Signature_Data4  # 8 bytes
            age = raw.Age
            pdb_name = bytes(raw.PdbFileName).rstrip(b"\x00").decode(
                "utf-8", errors="replace"
            )
            # Microsoft's GUID format: little-endian for first three groups,
            # then big-endian for the 8 trailing bytes -- printed as one
            # uppercase hex string with no separators.
            guid = "{:08X}{:04X}{:04X}{}".format(
                d1, d2, d3,
                "".join(f"{b:02X}" for b in d4),
            )
            return {
                "guid": guid,
                "age": age,
                "pdb_filename": Path(pdb_name).name,
            }
        except Exception as e:
            logger.debug(f"RSDS decode failed: {e}")
            return None

    # Manual fallback: walk raw debug bytes for "RSDS"
    raw_bytes = pe.get_data(
        entry.struct.AddressOfRawData, entry.struct.SizeOfData
    )
    if raw_bytes[:4] != b"RSDS":
        return None
    try:
        # RSDS layout: 'RSDS' (4) + GUID (16) + Age (4 LE) + name (null-term ASCII)
        guid_bytes = raw_bytes[4:20]
        age = struct.unpack("<I", raw_bytes[20:24])[0]
        name = raw_bytes[24:].split(b"\x00", 1)[0].decode("utf-8", "replace")
        d1 = struct.unpack("<I", guid_bytes[0:4])[0]
        d2 = struct.unpack("<H", guid_bytes[4:6])[0]
        d3 = struct.unpack("<H", guid_bytes[6:8])[0]
        d4 = guid_bytes[8:16]
        guid = "{:08X}{:04X}{:04X}{}".format(
            d1, d2, d3, "".join(f"{b:02X}" for b in d4)
        )
        return {
            "guid": guid,
            "age": age,
            "pdb_filename": Path(name).name,
        }
    except Exception as e:
        logger.debug(f"Manual RSDS decode failed: {e}")
        return None


def build_symbol_server_url(
    cv: dict, server: str = DEFAULT_SYMBOL_SERVER
) -> str:
    """Build the canonical symbol-server URL for a CodeView record."""
    return (
        f"{server.rstrip('/')}/"
        f"{cv['pdb_filename']}/"
        f"{cv['guid']}{cv['age']:X}/"
        f"{cv['pdb_filename']}"
    )


def fetch_pdb(
    binary_path: str | Path,
    cache_dir: Path | None = None,
    server: str | None = None,
    symbol_path: str | None = None,
    timeout: int = 60,
) -> Path:
    """
    Locate or download the PDB matching a binary.

    Order of operations:
      1. Read CodeView record from the PE.
      2. Resolve cache_dir + server list (explicit args override
         ``symbol_path`` / env vars; see :func:`parse_symbol_path`).
      3. Compute the canonical cache path
         ``<cache_dir>/<pdb_filename>/<GUID><AGE>/<pdb_filename>``.
      4. If already cached, return it.
      5. Otherwise try each server in order until one succeeds.

    Args:
        cache_dir: Override cache root (else from symbol_path / env).
        server: Single server URL (legacy convenience -- prefer symbol_path).
        symbol_path: Windows-style ``_NT_SYMBOL_PATH`` string.
        timeout: Per-request timeout in seconds.

    Raises:
        ValueError: if the binary has no usable CodeView record.
        RuntimeError: if every configured server fails.
    """
    cv = extract_codeview_record(binary_path)
    if cv is None:
        raise ValueError(
            f"No CodeView (RSDS) debug record found in {binary_path}. "
            f"The binary was likely built without /DEBUG, or the debug "
            f"directory has been stripped."
        )

    parsed_cache, servers = parse_symbol_path(symbol_path)
    if cache_dir is None:
        cache_dir = parsed_cache
    if server is not None:
        servers = [server]

    cache_path = (
        Path(cache_dir)
        / cv["pdb_filename"]
        / f"{cv['guid']}{cv['age']:X}"
        / cv["pdb_filename"]
    )
    if cache_path.exists() and cache_path.stat().st_size > 0:
        logger.info(f"PDB cache hit: {cache_path}")
        return cache_path

    cache_path.parent.mkdir(parents=True, exist_ok=True)

    import urllib.error
    import urllib.request

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
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
                if resp.status != 200:
                    errors.append(f"{url} -> HTTP {resp.status}")
                    continue
                data = resp.read()
        except urllib.error.HTTPError as e:
            errors.append(f"{url} -> {e.code} {e.reason}")
            continue
        except urllib.error.URLError as e:
            errors.append(f"{url} -> network error: {e.reason}")
            continue

        cache_path.write_bytes(data)
        logger.info(f"PDB cached at {cache_path} ({len(data)} bytes)")
        return cache_path

    raise RuntimeError(
        "All configured symbol servers failed:\n  " + "\n  ".join(errors)
    )
