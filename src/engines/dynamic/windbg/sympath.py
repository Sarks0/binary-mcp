"""
Symbol-path management for the WinDbg bridge.

Centralises the ``_NT_SYMBOL_PATH`` strategy so:

  - Live WinDbg/KDNET sessions and the static ``analyze_binary`` flow
    share the same on-disk cache (``BINARY_MCP_SYMBOL_CACHE``). A PDB
    downloaded for static analysis is immediately available to a kernel
    debug session and vice versa.
  - We never shell out to the ``.sympath`` meta-command (which is in the
    bridge's command blocklist for good reason - command-string mutation
    is a low-trust path). Instead we call
    ``IDebugSymbols::SetSymbolPath`` directly via pybag's ``_symbols``
    handle, mirroring how :meth:`WinDbgBridge.pause` reaches into
    ``_dbg._control.SetInterrupt``.
  - User overrides flow through a structured tool
    (``windbg_set_sympath``) with element-level validation, so callers
    cannot smuggle UNC paths or unauthenticated http servers.

Reference:
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/symbol-path
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/dbgeng/nf-dbgeng-idebugsymbols-setsymbolpath
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from src.utils.pdb_fetcher import DEFAULT_SYMBOL_CACHE, DEFAULT_SYMBOL_SERVER

logger = logging.getLogger(__name__)


def compute_nt_symbol_path() -> str:
    """Build the canonical ``_NT_SYMBOL_PATH`` for binary-mcp sessions.

    Form: ``srv*<cache>*<server>``. When ``BINARY_MCP_SYMBOL_OFFLINE=1``
    we omit the upstream server so the engine never hits the network -
    useful for air-gapped environments where the cache was pre-populated.
    """
    offline = os.environ.get("BINARY_MCP_SYMBOL_OFFLINE") == "1"
    cache = str(DEFAULT_SYMBOL_CACHE)
    if offline:
        return f"cache*{cache}"
    return f"srv*{cache}*{DEFAULT_SYMBOL_SERVER}"


def validate_sympath_element(element: str) -> str | None:
    """Return None if ``element`` is acceptable, else a reason string.

    Rejects:
      - Empty / whitespace-only entries.
      - ``http://`` URLs unless ``BINARY_MCP_ALLOW_HTTP_SYMBOLS=1``
        (PDBs are parsed by Ghidra and dbgeng - a MITM-rewritten PDB
        poisons types).
      - UNC paths (``\\\\server\\share\\...``); we have no way to reason
        about the trust of an arbitrary SMB host.
      - ``cache*`` entries pointing outside the configured cache root.
    """
    e = element.strip()
    if not e:
        return "empty entry"

    head = e.split("*", 1)[0].lower()
    parts = e.split("*")

    if e.startswith("\\\\") or e.startswith("//"):
        return f"UNC paths are not allowed: {e!r}"

    lower = e.lower()
    if lower.startswith("http://"):
        if os.environ.get("BINARY_MCP_ALLOW_HTTP_SYMBOLS") != "1":
            return (
                "http:// symbol servers are forbidden by default "
                "(set BINARY_MCP_ALLOW_HTTP_SYMBOLS=1 to override)"
            )

    if head == "srv":
        # srv*<cache>*<url>  or  srv*<url>
        if len(parts) == 2:
            url = parts[1]
            if not (url.startswith("http://") or url.startswith("https://")):
                return f"srv* entry must specify an http(s) url: {e!r}"
        elif len(parts) >= 3:
            cache = parts[1]
            if cache:
                # Allow override but require it to live under our cache root.
                cache_root = Path(DEFAULT_SYMBOL_CACHE).resolve()
                try:
                    Path(cache).resolve().relative_to(cache_root)
                except (ValueError, OSError):
                    return (
                        f"srv* cache must be under {cache_root} "
                        f"(got {cache!r})"
                    )
            for url in parts[2:]:
                if url and not (
                    url.startswith("http://") or url.startswith("https://")
                ):
                    return f"srv* upstream must be http(s): {url!r}"
        else:
            return f"malformed srv* entry: {e!r}"
    elif head == "cache":
        if len(parts) < 2:
            return f"malformed cache* entry: {e!r}"
        cache_root = Path(DEFAULT_SYMBOL_CACHE).resolve()
        try:
            Path(parts[1]).resolve().relative_to(cache_root)
        except (ValueError, OSError):
            return f"cache* must be under {cache_root}"
    elif lower.startswith("https://") or lower.startswith("http://"):
        # Bare URL allowed (legacy form); already covered by http:// check above.
        pass
    else:
        # Bare local path. Resolve and ensure it exists; reject magic shares.
        # We don't require it to live under the cache root - users may have
        # private symbol stores - but it must not be a UNC path (already
        # rejected above) and must not contain shell metacharacters.
        if any(ch in e for ch in (";", "|", "&", "$", "`", "\n")):
            return f"local path contains shell metacharacters: {e!r}"

    return None


def join_sympath(elements: list[str]) -> str:
    """Join validated elements into a single ``_NT_SYMBOL_PATH`` string."""
    return ";".join(elements)


def set_engine_sympath(dbg: Any, sympath: str) -> bool:
    """Push ``sympath`` into the live engine via ``IDebugSymbols::SetSymbolPath``.

    Best-effort. Returns False on any failure so the bridge can degrade
    gracefully (the prior _NT_SYMBOL_PATH stays in effect for the engine).
    """
    if dbg is None:
        return False
    symbols = getattr(dbg, "_symbols", None)
    if symbols is None:
        logger.debug("dbg has no _symbols handle; cannot set sympath")
        return False
    try:
        symbols.SetSymbolPath(sympath)
        logger.info("Engine sympath set to: %s", sympath)
        return True
    except Exception as exc:
        logger.warning("SetSymbolPath failed: %s", exc)
        return False


def get_engine_sympath(dbg: Any) -> str | None:
    """Read the current ``_NT_SYMBOL_PATH`` from the engine, or None on error."""
    if dbg is None:
        return None
    symbols = getattr(dbg, "_symbols", None)
    if symbols is None:
        return None
    try:
        return symbols.GetSymbolPath()
    except Exception as exc:
        logger.debug("GetSymbolPath failed: %s", exc)
        return None


def subprocess_env_with_sympath(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an env dict with ``_NT_SYMBOL_PATH`` set to our computed default.

    Used when launching CDB as a subprocess so it inherits the same cache
    + server as the in-process Pybag engine. If the caller already has
    ``_NT_SYMBOL_PATH`` set (test, manual override) we leave it alone.
    """
    env = dict(base_env if base_env is not None else os.environ)
    if "_NT_SYMBOL_PATH" not in env:
        env["_NT_SYMBOL_PATH"] = compute_nt_symbol_path()
    return env


__all__ = [
    "compute_nt_symbol_path",
    "validate_sympath_element",
    "join_sympath",
    "set_engine_sympath",
    "get_engine_sympath",
    "subprocess_env_with_sympath",
]
