"""
Transport implementations for Binary MCP server.

Provides:
- stdio: Standard input/output (default, local only)
- sse: HTTP with Server-Sent Events (remote capable, secure)

Each transport integrates with:
- Authentication (Bearer token)
- TLS encryption
- Rate limiting
- IP allowlisting
- Audit logging
"""

from src.transports.sse_server import run_sse_server

__all__ = ["run_sse_server"]
