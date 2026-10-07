"""
Configuration management with .env file support.

Loads configuration from:
1. .env file in project root (if exists)
2. Environment variables (override .env)

Usage:
    from src.utils.config import get_config
    api_key = get_config("VT_API_KEY")
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

# Configuration cache
_config_cache: dict[str, str] = {}
_env_loaded = False


def _find_env_file() -> Path | None:
    """Find .env file by searching up from current directory."""
    # Start from the module's location and go up
    current = Path(__file__).resolve().parent

    # Search up to 5 levels
    for _ in range(5):
        env_file = current / ".env"
        if env_file.exists():
            return env_file

        # Also check parent
        parent = current.parent
        if parent == current:
            break
        current = parent

    # Also check current working directory
    cwd_env = Path.cwd() / ".env"
    if cwd_env.exists():
        return cwd_env

    return None


def _parse_env_file(env_path: Path) -> dict[str, str]:
    """
    Parse a .env file into a dictionary.

    Supports:
    - KEY=value
    - KEY="value with spaces"
    - KEY='value with spaces'
    - # comments
    - Empty lines
    """
    config = {}

    try:
        with open(env_path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Parse KEY=value
                if "=" not in line:
                    logger.warning(f".env line {line_num}: Invalid format (no '=')")
                    continue

                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip()

                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]

                if key:
                    config[key] = value

    except Exception as e:
        logger.warning(f"Failed to parse .env file: {e}")

    return config


def load_env():
    """Load configuration from .env file."""
    global _env_loaded, _config_cache

    if _env_loaded:
        return

    env_file = _find_env_file()
    if env_file:
        logger.info(f"Loading configuration from: {env_file}")
        _config_cache = _parse_env_file(env_file)
        logger.debug(f"Loaded {len(_config_cache)} config values from .env")
    else:
        logger.debug("No .env file found")

    _env_loaded = True


def get_config(key: str, default: str | None = None) -> str | None:
    """
    Get a configuration value.

    Checks environment variables first, then .env file.

    Args:
        key: Configuration key name
        default: Default value if not found

    Returns:
        Configuration value or default
    """
    # Environment variables take precedence
    env_value = os.environ.get(key)
    if env_value is not None:
        return env_value

    # Load .env if not already done
    load_env()

    # Check .env cache
    return _config_cache.get(key, default)


def get_cache_dir() -> Path:
    """Resolve the shared base directory for all on-disk state.

    The analysis cache, Ghidra projects, saved sessions, and per-engine error
    logs all live under this one root so they stay co-located and can be
    inspected or cleared together -- keeping them in agreement is why every
    module resolves the base here instead of hardcoding its own path.

    Resolution order: ``$BINARY_CACHE_DIR``, then ``~/ghidra_mcp_cache``
    (no leading dot, so the directory is visible for inspection and cleanup).
    """
    configured = get_config("BINARY_CACHE_DIR")
    if configured:
        return Path(configured)
    return Path.home() / "ghidra_mcp_cache"


def get_config_bool(key: str, default: bool = False) -> bool:
    """Get a boolean configuration value."""
    value = get_config(key)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes", "on")


def get_config_int(key: str, default: int = 0) -> int:
    """Get an integer configuration value."""
    value = get_config(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# Available configuration keys
CONFIG_KEYS = {
    # VirusTotal
    "VT_API_KEY": "VirusTotal API key for hash lookups and file analysis",

    # Ghidra
    "GHIDRA_HOME": "Path to Ghidra installation directory",
    "GHIDRA_INSTALL_DIR": "Alias for GHIDRA_HOME, which is the name Ghidra's own tooling uses. Checked after GHIDRA_HOME.",
    "GHIDRA_TIMEOUT": "Default wall-clock timeout for Ghidra analysis (seconds, 30-3600, default 1800)",
    "GHIDRA_FUNCTION_TIMEOUT": "Per-function decompilation timeout (seconds, default 30)",
    "GHIDRA_MAX_FUNCTIONS": "Cap on functions processed per Ghidra run (0 = unlimited)",
    "GHIDRA_SKIP_DECOMPILE": "Skip decompilation for fast structural pass (1/true/yes)",
    "GHIDRA_RESUME_CACHE": "Legacy: path to a prior cache JSON. Loads the full cache in Jython and is OOM-prone on large binaries; prefer GHIDRA_RESUME_MANIFEST.",
    "GHIDRA_RESUME_MANIFEST": "Path to a small {complete_addresses:[...]} sidecar so the script can skip already-analyzed functions without loading the full cache. Set automatically by the server.",
    "GHIDRA_START_ADDRESS": "Hex start address for chunked analysis (e.g. 0x61abbc)",
    "GHIDRA_END_ADDRESS": "Hex end address for chunked analysis",
    "GHIDRA_ENABLE_FID": "Enable Function ID library matching during analysis (1/true/yes)",
    "GHIDRA_MAX_HEAP_MB": "JVM max heap for Ghidra subprocess in MB (default 4096). Bump to 6144-8192 for very large binaries.",
    "BINARY_MCP_INLINE_DEADLINE": "Seconds a Ghidra-invoking tool may block before returning a job handle instead (default 25, max 900). Raise it if your MCP client is patient -- under Claude Code, where long calls move to a background task after 2 min, 90-120 returns more answers inline.",

    # x64dbg (the Obsidian plugin's HTTP listener)
    "X64DBG_HOST": "Host the Obsidian plugin's HTTP listener is reachable on (default 127.0.0.1). A non-loopback host additionally requires BINARY_MCP_REMOTE_ALLOW, X64DBG_TLS_CA and OBSIDIAN_AUTH_TOKEN; a tunnel whose local end is 127.0.0.1 needs none of them.",
    "X64DBG_PORT": "Port for that listener (default 8765, which is the port obsidian_server.exe binds).",
    "X64DBG_TIMEOUT": "Default timeout for x64dbg commands (seconds, default 30)",
    "X64DBG_TLS_CA": "PEM CA bundle that signs the debugger host's server certificate. Setting it selects https and verifies against this CA instead of the system trust store. Required for a non-loopback host. Note obsidian_server.exe does not serve TLS itself yet -- something on that host must terminate it.",
    "X64DBG_TLS_CLIENT_CERT": "PEM client certificate this server presents to the debugger host, for mutual TLS. Requires X64DBG_TLS_CA.",
    "X64DBG_TLS_CLIENT_KEY": "PEM private key matching X64DBG_TLS_CLIENT_CERT.",
    "OBSIDIAN_AUTH_TOKEN": "Bearer token for the Obsidian plugin's HTTP API. For a loopback host it is optional: the bridge falls back to the token file the plugin writes in %TEMP%. For a non-loopback host it is REQUIRED, because that file is on the debugger host and not on this machine.",

    # WinDbg / kernel debugging
    "WINDBG_PATH": "Path to the Windows debuggers installation (auto-detected when unset).",
    "WINDBG_TIMEOUT": "Timeout for a single WinDbg command (seconds, default 30)",
    "WINDBG_DEBUG": "Set to any non-empty value for verbose dbgeng diagnostics.",
    "KDNET_TIMEOUT": "Timeout for establishing a KDNET kernel connection (seconds, default 60)",
    "BINARY_MCP_ENABLE_RAW_WINDBG": "Set to 1 to enable windbg_execute_command behind its fail-closed allowlist. Off by default.",

    # Symbol server (PDB fetch + WinDbg sympath - shared by static analysis and live debugging)
    "BINARY_MCP_SYMBOL_PATH": "Windows-style _NT_SYMBOL_PATH for PDB fetch (overrides _NT_SYMBOL_PATH).",
    "BINARY_MCP_SYMBOL_CACHE": "Override the on-disk symbol cache directory (defaults to ~/.cache/binary_mcp/symbols on POSIX, ~/.binary_mcp_cache/symbols on Windows). Shared by analyze_binary and live WinDbg sessions.",
    "BINARY_MCP_SYMBOL_SERVER": "Override upstream symbol server (default https://msdl.microsoft.com/download/symbols).",
    "BINARY_MCP_SYMBOL_OFFLINE": "Set to 1 to skip the upstream symbol server and serve only from the local cache (air-gapped sessions).",
    "BINARY_MCP_ALLOW_PRIVATE_SYMBOL_SERVERS": "Set to 1 to permit a symbol server on a private or loopback address, for an internal symbol store. Off by default: a public name resolving into your network is an SSRF, not a symbol server.",
    "BINARY_MCP_ALLOW_HTTP_SYMBOLS": "Set to 1 to permit http:// symbol servers (off by default; PDBs are MITM-sensitive).",
    "BINARY_MCP_AUTO_PDB": "Fetch a PDB from the symbol server on a binary's first import: 'microsoft' (default; only binaries whose version info names Microsoft), 'always', or 'never'. Fetching sends the PDB name and GUID to the server, so keep 'microsoft' or 'never' for samples you don't want disclosed. load_pdb's own auto-fetch applies the same vendor check and refuses up front (no network, no re-analysis) when a third-party binary is pointed at the Microsoft-only public server; override per call with allow_non_microsoft=True.",

    # Storage
    #
    # BINARY_CACHE_DIR is the real name of what this dict used to advertise as
    # BINARY_MCP_CACHE_DIR -- a key nothing read. get_cache_dir() below is the
    # only resolver, and it reads BINARY_CACHE_DIR.
    "BINARY_CACHE_DIR": "Base directory for all on-disk state: the analysis cache, Ghidra projects, saved sessions, job records and per-engine error logs (default ~/ghidra_mcp_cache).",
    "BINARY_MCP_CARVE_DIR": "Destination for carved embedded binaries (default ~/.cache/binary_mcp/carved on POSIX, ~/.binary_mcp_cache/carved on Windows).",
    "BINARY_MCP_SESSION_DIR": "Directory for saved analysis sessions (default ~/.binary_mcp_sessions).",

    # Path confinement -- see docs/security.md
    "BINARY_MCP_ALLOWED_DIRS": "Directories analysis is confined to, separated by ':' (POSIX) or ';' (Windows). Unset falls back to the quarantine directories.",
    "BINARY_MCP_REQUIRE_CONFINEMENT": "Fail closed: refuse any binary unless BINARY_MCP_ALLOWED_DIRS is set explicitly.",
    "BINARY_MCP_ALLOW_ANY_PATH": "Opt out of path confinement entirely. Not recommended; ignored when BINARY_MCP_REQUIRE_CONFINEMENT is set.",
    "BINARY_MCP_ALLOW_HARDLINKS": "Re-permit multiply linked regular files. Narrower than BINARY_MCP_ALLOW_ANY_PATH: directory confinement stays in force.",

    # Transport -- see docs/remote-access.md
    "BINARY_MCP_TRANSPORT": "MCP transport: 'stdio' (default) or 'http'. 'http' lets a client on another host connect instead of spawning the server itself.",
    "BINARY_MCP_HTTP_HOST": "Address the HTTP transport binds (default 127.0.0.1). A non-loopback address additionally requires BINARY_MCP_REMOTE_ALLOW, TLS and an explicit token.",
    "BINARY_MCP_HTTP_PORT": "Port the HTTP transport binds (default 8770).",
    "BINARY_MCP_HTTP_PATH": "URL path the MCP endpoint is served at (default /mcp).",
    "BINARY_MCP_HTTP_TOKEN": "Bearer token the HTTP transport requires. Generated and logged once per start when unset on loopback; REQUIRED for a non-loopback bind, so restarts do not invalidate the client's config.",
    "BINARY_MCP_HTTP_ALLOWED_HOSTS": "Extra Host/Origin header values the HTTP transport accepts, comma-separated. The bind address is always accepted; add the DNS name clients dial so a name-based request is not refused as rebinding.",
    "BINARY_MCP_REMOTE_ALLOW": "Master switch for binding the HTTP transport off loopback. Without it a non-loopback bind is refused.",
    "BINARY_MCP_REMOTE_TLS_CERT": "PEM certificate chain for the HTTP transport. Required for a non-loopback bind.",
    "BINARY_MCP_REMOTE_TLS_KEY": "PEM private key matching BINARY_MCP_REMOTE_TLS_CERT.",
    "BINARY_MCP_REMOTE_TLS_CA": "PEM CA bundle used to verify client certificates. Setting it turns on mutual TLS: a client without a certificate this CA signed is refused at the TLS layer.",
    "BINARY_MCP_REMOTE_CLIENT_ALLOWLIST": "Comma-separated client addresses or CIDRs allowed to reach the HTTP transport. Checked before authentication; unset means any address that gets past TLS may present a token.",

    # Logging
    "BINARY_MCP_LOG_LEVEL": "Logging level (DEBUG, INFO, WARNING, ERROR; default INFO).",
}


def list_config_keys() -> dict[str, str]:
    """Return available configuration keys and descriptions."""
    return CONFIG_KEYS.copy()


def get_config_status() -> dict[str, dict]:
    """
    Get status of all configuration keys.

    Returns:
        Dict with key -> {set: bool, source: str, masked_value: str}
    """
    load_env()
    status = {}

    for key in CONFIG_KEYS:
        env_value = os.environ.get(key)
        file_value = _config_cache.get(key)

        if env_value is not None:
            status[key] = {
                "set": True,
                "source": "environment",
                "masked_value": _mask_value(key, env_value),
            }
        elif file_value is not None:
            status[key] = {
                "set": True,
                "source": ".env file",
                "masked_value": _mask_value(key, file_value),
            }
        else:
            status[key] = {
                "set": False,
                "source": None,
                "masked_value": None,
            }

    return status


def _mask_value(key: str, value: str) -> str:
    """Mask sensitive values like API keys."""
    sensitive_keys = ("API_KEY", "SECRET", "PASSWORD", "TOKEN")

    if any(s in key.upper() for s in sensitive_keys):
        if len(value) > 12:
            return value[:4] + "..." + value[-4:]
        else:
            return "***"

    return value
