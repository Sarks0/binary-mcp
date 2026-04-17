"""
Transport implementations for Binary MCP server.

Provides:
- stdio: Standard input/output (default, local only)
- sse: HTTP with Server-Sent Events (remote capable, secure)

Remote transport integrates with:
- Authentication (Bearer token via FastMCP TokenVerifier)
- TLS encryption (via uvicorn)
- Rate limiting (via FastMCP middleware)
- IP allowlisting (via ASGI middleware)
- Audit logging (via FastMCP middleware)
"""

from src.transports.sse_server import (
    AuditMiddleware,
    BinaryMCPTokenVerifier,
    IPAllowlistMiddleware,
    build_uvicorn_config,
    check_ip_allowlist,
    configure_remote_access,
    extract_bearer_token,
    get_client_ip,
    get_ip_allowlist_middleware,
)

__all__ = [
    "AuditMiddleware",
    "BinaryMCPTokenVerifier",
    "IPAllowlistMiddleware",
    "build_uvicorn_config",
    "check_ip_allowlist",
    "configure_remote_access",
    "extract_bearer_token",
    "get_client_ip",
    "get_ip_allowlist_middleware",
]
