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
        with open(env_path, "r") as f:
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
    "GHIDRA_TIMEOUT": "Default timeout for Ghidra analysis (seconds)",

    # x64dbg
    "X64DBG_BRIDGE_URL": "URL for x64dbg HTTP bridge (default: http://localhost:27042)",
    "X64DBG_TIMEOUT": "Default timeout for x64dbg commands (seconds)",

    # Analysis
    "BINARY_MCP_CACHE_DIR": "Directory for caching analysis results",
    "BINARY_MCP_SESSION_DIR": "Directory for storing session data",

    # Logging
    "BINARY_MCP_LOG_LEVEL": "Logging level (DEBUG, INFO, WARNING, ERROR)",
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
