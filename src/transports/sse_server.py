"""
Remote MCP access via FastMCP's SSE/HTTP transport.

Integrates with FastMCP's built-in transport layer and adds:
- Bearer token authentication (via TokenVerifier subclass)
- Audit logging middleware (via FastMCP Middleware)
- Rate limiting (via FastMCP RateLimitingMiddleware)
- IP allowlist filtering (via Starlette ASGI middleware)
- TLS encryption (via uvicorn ssl config)
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import time
from typing import Any

from fastmcp.server.auth.auth import AccessToken, TokenVerifier
from fastmcp.server.middleware.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from starlette.middleware import Middleware as ASGIMiddleware
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from src.utils.audit_log import log_access, log_tool_call
from src.utils.auth import TokenEntropyError, TokenFormatError, TokenValidator
from src.utils.config import get_config, get_config_int

logger = logging.getLogger(__name__)


# --- IP Allowlist (pure functions, also used in tests) ---


def check_ip_allowlist(client_ip: str, allowlist: list[str] | None) -> bool:
    """
    Check if IP address is in allowlist.

    Args:
        client_ip: Client IP address string
        allowlist: List of allowed CIDR ranges (e.g., "192.168.1.0/24")

    Returns:
        True if IP is allowed or no allowlist configured
    """
    if not allowlist:
        return True
    if not client_ip:
        return False  # Can't verify IP — deny access

    try:
        client_addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning(f"Invalid client IP: {client_ip}")
        return False

    for allowed in allowlist:
        try:
            if "/" in allowed:
                network = ipaddress.ip_network(allowed, strict=False)
                if client_addr in network:
                    return True
            else:
                if client_addr == ipaddress.ip_address(allowed):
                    return True
        except ValueError:
            logger.warning(f"Invalid allowlist entry: {allowed}")
            continue

    return False


def get_client_ip(headers: dict[str, str]) -> str | None:
    """
    Extract client IP from headers (lowercase keys expected).

    Args:
        headers: HTTP headers dictionary with lowercase keys

    Returns:
        Client IP or None
    """
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    real_ip = headers.get("x-real-ip")
    if real_ip:
        return real_ip

    return None


def extract_bearer_token(auth_header: str | None) -> str | None:
    """
    Extract bearer token from Authorization header.

    Args:
        auth_header: Authorization header value

    Returns:
        Token or None
    """
    if not auth_header:
        return None

    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]

    return None


# --- FastMCP Token Verifier ---


class BinaryMCPTokenVerifier(TokenVerifier):
    """
    Token verifier for binary-mcp that uses constant-time comparison.

    Validates tokens against a pre-configured secret token using
    HMAC-based constant-time comparison to prevent timing attacks.
    """

    def __init__(self, token: str):
        """
        Initialize with the server's auth token.

        Args:
            token: The valid authentication token

        Raises:
            TokenFormatError: If token format is invalid
        """
        super().__init__()

        # Validate token on startup
        try:
            TokenValidator.validate(token, check_entropy=True)
            logger.info("Authentication token validated and loaded")
        except TokenFormatError:
            logger.error("SECURITY WARNING: Token format invalid")
            logger.error("Generate a secure token with: python scripts/generate_token.py")
            raise
        except TokenEntropyError as e:
            logger.warning(f"Token security concern: {e}")

        # Store only the hash — never keep the raw token
        self._token_hash = hashlib.sha256(token.encode()).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        """
        Verify a bearer token using constant-time comparison.

        Returns AccessToken on success, None on failure.
        """
        provided_hash = hashlib.sha256(token.encode()).digest()
        if not hmac.compare_digest(provided_hash, self._token_hash):
            return None

        return AccessToken(
            token="[redacted]",
            client_id="binary-mcp-client",
            scopes=["tools:*"],
        )


# --- FastMCP Audit Middleware ---


class AuditMiddleware(Middleware):
    """
    MCP-level middleware that logs tool calls and access events
    to the audit log.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> Any:
        """Log tool calls to audit log."""
        tool_name = ""
        if hasattr(context.message, "name"):
            tool_name = context.message.name

        start = time.time()
        try:
            result = await call_next(context)
            duration = time.time() - start
            log_tool_call(
                session_id="mcp-session",
                tool_name=tool_name,
                client_ip=None,
                success=True,
                details={"duration_ms": int(duration * 1000)},
            )
            return result
        except Exception as e:
            duration = time.time() - start
            log_tool_call(
                session_id="mcp-session",
                tool_name=tool_name,
                client_ip=None,
                success=False,
                details={"duration_ms": int(duration * 1000), "error": str(e)},
            )
            raise

    async def on_message(
        self,
        context: MiddlewareContext,
        call_next: CallNext,
    ) -> Any:
        """Log all MCP messages to audit log."""
        log_access(
            session_id="mcp-session",
            resource=context.method or "unknown",
            action="request",
            client_ip=None,
            allowed=True,
        )
        return await call_next(context)


# --- ASGI IP Allowlist Middleware ---


class IPAllowlistMiddleware:
    """
    Starlette ASGI middleware that rejects requests from IPs
    not in the configured allowlist.
    """

    def __init__(self, app: ASGIApp, allowlist: list[str]):
        self.app = app
        self.allowlist = allowlist

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract client IP from ASGI scope
        client = scope.get("client")
        client_ip = client[0] if client else None

        if not check_ip_allowlist(client_ip, self.allowlist):
            logger.warning(f"Rejected connection from non-allowed IP: {client_ip}")
            response = JSONResponse(
                {"error": "IP not in allowlist"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)


# --- Server Configuration ---


def configure_remote_access(
    app: Any,
    auth_token: str | None,
) -> None:
    """
    Configure a FastMCP app with security middleware for remote access.

    Rate limit values are read from config (MCP_RATE_LIMIT_REQUESTS env var).

    Args:
        app: FastMCP application instance
        auth_token: Authentication token (sets app.auth)
    """
    # Auth
    if auth_token:
        app.auth = BinaryMCPTokenVerifier(auth_token)
        logger.info("Authentication: enabled (Bearer token)")
    else:
        logger.warning("Authentication: DISABLED — INSECURE")

    # Read rate limit config (MCP_RATE_LIMIT_REQUESTS is per-minute)
    max_requests_per_minute = get_config_int("MCP_RATE_LIMIT_REQUESTS", 100)
    rate_limit_rps = max_requests_per_minute / 60.0
    rate_limit_burst = max(max_requests_per_minute, 20)

    # Rate limiting
    app.add_middleware(
        RateLimitingMiddleware(
            max_requests_per_second=rate_limit_rps,
            burst_capacity=rate_limit_burst,
        )
    )
    logger.info(f"Rate limiting: {rate_limit_rps:.2f} req/s, burst {rate_limit_burst}")

    # Audit logging
    app.add_middleware(AuditMiddleware())
    logger.info("Audit logging middleware: enabled")


def build_uvicorn_config(
    host: str,
    port: int,
    ssl_context: Any = None,
) -> dict[str, Any]:
    """
    Build uvicorn config dict for FastMCP's run() method.

    Args:
        host: Bind host
        port: Listen port
        ssl_context: Pre-configured ssl.SSLContext with hardened settings

    Returns:
        Dict suitable for FastMCP's uvicorn_config parameter
    """
    config: dict[str, Any] = {}

    if ssl_context:
        config["ssl"] = ssl_context
        logger.info(f"TLS enabled on {host}:{port}")
    else:
        logger.warning(f"No TLS — connections to {host}:{port} are UNENCRYPTED")

    return config


def get_ip_allowlist_middleware() -> ASGIMiddleware | None:
    """
    Create IP allowlist ASGI middleware from config, or None if not configured.
    """
    ip_allowlist_str = get_config("MCP_ALLOWED_IPS", "")
    if not ip_allowlist_str:
        return None

    allowlist = [ip.strip() for ip in ip_allowlist_str.split(",") if ip.strip()]
    if not allowlist:
        return None

    logger.info(f"IP allowlist configured: {allowlist}")
    return ASGIMiddleware(IPAllowlistMiddleware, allowlist=allowlist)
