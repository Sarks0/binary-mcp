"""
SSE (Server-Sent Events) transport for remote MCP access.

Provides HTTP-based bidirectional communication:
- POST /message - Client sends requests
- GET /sse - Server-sent events stream for responses

Security features:
- Bearer token authentication
- IP allowlist filtering
- Rate limiting per session
- TLS encryption support
- CORS configuration
- Audit logging

Based on MCP specification for HTTP with SSE transport.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any

from src.utils.audit_log import log_security_event
from src.utils.auth import AuthContext, AuthenticationFailedError, AuthManager
from src.utils.config import get_config
from src.utils.rate_limit import RateLimiter, RateLimitExceededError, RateLimitTier

logger = logging.getLogger(__name__)


class IPAllowlistError(Exception):
    """Client IP not in allowlist."""

    pass


def check_ip_allowlist(client_ip: str, allowlist: list[str] | None) -> bool:
    """
    Check if IP address is in allowlist.

    Args:
        client_ip: Client IP address string
        allowlist: List of allowed CIDR ranges (e.g., "192.168.1.0/24")

    Returns:
        True if IP is allowed or no allowlist configured
    """
    if not allowlist or not client_ip:
        return True

    try:
        client_addr = ipaddress.ip_address(client_ip)
    except ValueError:
        logger.warning(f"Invalid client IP: {client_ip}")
        return False

    for allowed in allowlist:
        try:
            if "/" in allowed:
                # CIDR notation
                network = ipaddress.ip_network(allowed, strict=False)
                if client_addr in network:
                    return True
            else:
                # Single IP
                if client_addr == ipaddress.ip_address(allowed):
                    return True
        except ValueError:
            logger.warning(f"Invalid allowlist entry: {allowed}")
            continue

    return False


def get_client_ip(headers: dict[str, str]) -> str | None:
    """
    Extract client IP from headers.

    Checks X-Forwarded-For, X-Real-IP, then defaults to connection info.

    Args:
        headers: HTTP headers dictionary

    Returns:
        Client IP or None
    """
    # Check forwarded headers
    forwarded = headers.get("X-Forwarded-For")
    if forwarded:
        # Take first IP in chain (closest to original client)
        return forwarded.split(",")[0].strip()

    real_ip = headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Will be filled in from connection info
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


class MCPRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP request handler with security middleware.

    Handles:
    - Authentication on /sse and /message endpoints
    - Rate limiting
    - IP allowlist
    - CORS headers
    - Audit logging
    """

    # Class-level security components (set by server)
    auth_manager: AuthManager | None = None
    rate_limiter: RateLimiter | None = None
    ip_allowlist: list[str] | None = None
    server_session_map: dict[str, Any] = {}
    mcp_read_stream: Any = None
    mcp_write_stream: Any = None

    def log_message(self, format: str, *args) -> None:
        """Override to use our logger."""
        logger.debug(f"{self.client_address[0]} - {format % args}")

    def send_cors_headers(self) -> None:
        """Send CORS headers for cross-origin requests."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")

    def send_security_headers(self) -> None:
        """Send security headers."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()

    def _get_headers(self) -> dict[str, str]:
        """Extract headers into dictionary."""
        return {k.lower(): v for k, v in self.headers.items()}

    def _check_ip_allowlist(self) -> bool:
        """Check if client IP is in allowlist."""
        if not self.ip_allowlist:
            return True

        client_ip = get_client_ip(self._get_headers()) or self.client_address[0]

        if not check_ip_allowlist(client_ip, self.ip_allowlist):
            logger.warning(f"Rejected connection from non-allowed IP: {client_ip}")
            return False

        return True

    def _authenticate(self) -> tuple[str | None, dict[str, Any] | None]:
        """
        Authenticate request and return session info.

        Returns:
            Tuple of (session_id, metadata) or (None, None) if unauthenticated
        """
        # If no auth manager configured, skip authentication
        if not self.auth_manager:
            return (None, None)

        headers = self._get_headers()
        auth_header = headers.get("authorization")
        client_ip = get_client_ip(headers) or self.client_address[0]

        # Check rate limit for auth attempts
        try:
            from src.utils.rate_limit import check_auth_rate_limit

            check_auth_rate_limit(client_ip)
        except RateLimitExceededError:
            log_security_event("auth", "rate_limit_exceeded", False, client_ip, {"path": self.path})
            return (None, {"error": "rate_limit_exceeded"})

        # Extract token
        token = extract_bearer_token(auth_header)

        if not token:
            log_security_event("auth", "missing_token", False, client_ip, {"path": self.path})
            return (None, {"error": "missing_token"})

        # Validate token and create/get session
        try:
            context = AuthContext(client_ip=client_ip, headers=headers, transport="sse")
            session = self.auth_manager.authenticate(token, context)

            return (
                session.session_id,
                {
                    "client_ip": client_ip,
                    "session_created": session.created_at,
                },
            )

        except AuthenticationFailedError as e:
            log_security_event(
                "auth", "failed", False, client_ip, {"error": str(e), "path": self.path}
            )
            return (None, {"error": "invalid_token"})
        except RateLimitExceededError:
            log_security_event("auth", "rate_limit_exceeded", False, client_ip, {"path": self.path})
            return (None, {"error": "rate_limit_exceeded"})

    def do_GET(self) -> None:
        """Handle GET requests (SSE endpoint)."""
        # Only handle /sse path
        if self.path not in ("/sse", "/sse/"):
            self.send_response(404)
            self.end_headers()
            return

        # Check IP allowlist
        if not self._check_ip_allowlist():
            self.send_response(403)
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(b'{"error": "IP not in allowlist"}')
            return

        # Authenticate
        session_id, auth_metadata = self._authenticate()

        if self.auth_manager and not session_id:
            # Authentication required but failed
            error_code = (
                auth_metadata.get("error", "authentication_required")
                if auth_metadata
                else "authentication_required"
            )

            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_security_headers()
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "error": error_code,
                        "message": "Authentication required. Provide Bearer token in Authorization header.",
                    }
                ).encode()
            )
            return

        # Check rate limit for streaming
        if session_id and self.rate_limiter:
            try:
                from src.utils.rate_limit import check_stream_rate_limit

                check_stream_rate_limit(session_id)
            except RateLimitExceededError as e:
                self.send_response(429)
                self.send_header("Retry-After", "60")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": "rate_limit_exceeded", "message": str(e)}).encode()
                )
                return

        # Start SSE stream
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_cors_headers()
        self.send_security_headers()

        # Add session ID header for client reference
        if session_id:
            self.send_header("X-Session-ID", session_id)

        self.end_headers()

        # Store session info
        if session_id:
            self.server_session_map[session_id] = {
                "client_ip": self.client_address[0],
                "connected_at": time.time(),
            }

        # Stream SSE events from MCP
        try:
            # This would integrate with FastMCP's SSE transport
            # For now, we write the connection header
            self.wfile.write(b"event: connected\n")
            self.wfile.write(f'data: {{"session_id": "{session_id}"}}\n\n'.encode())
            self.wfile.flush()

            # Keep connection open (simplified - real implementation
            # would bridge between FastMCP and this HTTP response)
            while True:
                time.sleep(1)
                # In real implementation, check for messages from MCP
                # and forward them as SSE events

        except (BrokenPipeError, ConnectionResetError):
            logger.info(f"Client disconnected: {session_id[:8] if session_id else 'unknown'}...")
        finally:
            if session_id:
                self.server_session_map.pop(session_id, None)

    def do_POST(self) -> None:
        """Handle POST requests (message endpoint)."""
        # Only handle /message path
        if not (self.path == "/message" or self.path.startswith("/message?")):
            self.send_response(404)
            self.end_headers()
            return

        # Check IP allowlist
        if not self._check_ip_allowlist():
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"error": "IP not in allowlist"}')
            return

        # Authenticate
        session_id, auth_metadata = self._authenticate()

        if self.auth_manager and not session_id:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            return

        # Check rate limit
        if session_id and self.rate_limiter:
            try:
                self.rate_limiter.assert_rate_limit(session_id, RateLimitTier.STANDARD)
            except RateLimitExceededError as e:
                self.send_response(429)
                self.send_header("Retry-After", "60")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": "rate_limit_exceeded", "message": str(e)}).encode()
                )
                return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            _ = json.loads(body)  # Validate JSON format
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid JSON"}')
            return

        # Process message (forward to MCP)
        # In real implementation, this would route to the MCP server

        # Send response
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_cors_headers()
        self.send_security_headers()
        self.end_headers()

        response = {
            "status": "accepted",
            "session_id": session_id,
        }
        self.wfile.write(json.dumps(response).encode())


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for concurrent connections."""

    allow_reuse_address = True
    daemon_threads = True


def run_sse_server(
    mcp_app: Any,
    host: str,
    port: int,
    ssl_context: ssl.SSLContext | None,
    auth_manager: AuthManager | None,
    rate_limiter: RateLimiter | None,
) -> None:
    """
    Run SSE server with security middleware.

    Args:
        mcp_app: FastMCP application instance
        host: Bind host
        port: Listen port
        ssl_context: SSL context for TLS (or None)
        auth_manager: Authentication manager (or None)
        rate_limiter: Rate limiter (or None)
    """
    # Load configuration
    ip_allowlist_str = get_config("MCP_ALLOWED_IPS", "")
    ip_allowlist = (
        [ip.strip() for ip in ip_allowlist_str.split(",") if ip.strip()]
        if ip_allowlist_str
        else None
    )

    if ip_allowlist:
        logger.info(f"IP allowlist configured: {ip_allowlist}")

    # Set up request handler with security components
    MCPRequestHandler.auth_manager = auth_manager
    MCPRequestHandler.rate_limiter = rate_limiter
    MCPRequestHandler.ip_allowlist = ip_allowlist

    # Create HTTP server
    server = ThreadedHTTPServer((host, port), MCPRequestHandler)

    # Wrap with SSL if configured
    if ssl_context:
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        logger.info(f"TLS enabled on {host}:{port}")
    else:
        logger.warning(f"No TLS - connections to {host}:{port} are UNENCRYPTED")

    # Log startup
    logger.info(f"SSE server listening on http{'s' if ssl_context else ''}://{host}:{port}")
    logger.info("Endpoints:")
    logger.info("  - GET  /sse     - Server-sent events stream")
    logger.info("  - POST /message - Send messages to MCP")

    if auth_manager:
        logger.info("Authentication: Required (Bearer token)")
    else:
        logger.warning("Authentication: DISABLED - INSECURE")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        server.shutdown()
    finally:
        # Log shutdown
        from src.utils.audit_log import log_session_event

        log_session_event(session_id="server", event_subtype="shutdown", client_ip=None, details={})
