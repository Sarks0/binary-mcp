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
import struct
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SYMBOL_CACHE = Path.home() / ".binary_mcp_cache" / "symbols"
DEFAULT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"


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
    server: str = DEFAULT_SYMBOL_SERVER,
    timeout: int = 60,
) -> Path:
    """
    Locate or download the PDB matching a binary.

    Order of operations:
      1. Read CodeView record from the PE.
      2. Compute the canonical cache path
         ``<cache_dir>/<pdb_filename>/<GUID><AGE>/<pdb_filename>``.
      3. If already cached, return it.
      4. Otherwise download from the symbol server and cache it.

    Returns the path to the cached PDB.

    Raises:
        ValueError: if the binary has no usable CodeView record.
        RuntimeError: on HTTP failure.
    """
    cache_dir = cache_dir or DEFAULT_SYMBOL_CACHE
    cv = extract_codeview_record(binary_path)
    if cv is None:
        raise ValueError(
            f"No CodeView (RSDS) debug record found in {binary_path}. "
            f"The binary was likely built without /DEBUG, or the debug "
            f"directory has been stripped."
        )

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
    url = build_symbol_server_url(cv, server)
    logger.info(f"Downloading PDB: {url}")

    # Use urllib (stdlib) so we don't add a hard dependency on requests.
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        url,
        headers={
            # Microsoft's symbol server requires a real-looking UA
            "User-Agent": "Microsoft-Symbol-Server/10.0.0.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status != 200:
                raise RuntimeError(
                    f"Symbol server returned {resp.status} for {url}"
                )
            data = resp.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"Symbol server fetch failed ({e.code} {e.reason}) for {url}. "
            f"Microsoft only hosts public PDBs; this binary may not have one."
        ) from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error fetching {url}: {e.reason}") from e

    cache_path.write_bytes(data)
    logger.info(f"PDB cached at {cache_path} ({len(data)} bytes)")
    return cache_path
