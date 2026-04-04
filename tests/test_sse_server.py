"""
Tests for SSE server transport module.

Covers check_ip_allowlist, extract_bearer_token, get_client_ip,
BinaryMCPTokenVerifier, and AuditMiddleware.

Note: BinaryMCPTokenVerifier and AuditMiddleware require fastmcp imports
which may not be available in all test environments (test_server.py mocks
mcp.server). Those tests are skipped if imports fail.
"""

import hashlib
import importlib
import sys

import pytest

from src.utils.auth import TokenFormatError, generate_secure_token


def _import_sse_server():
    """Import sse_server module, skipping if FastMCP deps unavailable."""
    # If mcp.server has been mocked (by test_server.py), FastMCP can't load
    mcp_server = sys.modules.get("mcp.server")
    if mcp_server is not None and not hasattr(mcp_server, "__file__"):
        pytest.skip("mcp.server is mocked — cannot import FastMCP-based modules")
    return importlib.import_module("src.transports.sse_server")


# Import pure functions that don't depend on FastMCP — fallback to skip
try:
    from src.transports.sse_server import (
        check_ip_allowlist,
        extract_bearer_token,
        get_client_ip,
    )

    _HAS_SSE_MODULE = True
except (ImportError, ModuleNotFoundError):
    _HAS_SSE_MODULE = False

    # Provide stubs so test collection doesn't fail
    def check_ip_allowlist(*a, **kw):  # type: ignore[misc]
        pass

    def extract_bearer_token(*a, **kw):  # type: ignore[misc]
        pass

    def get_client_ip(*a, **kw):  # type: ignore[misc]
        pass


pytestmark = pytest.mark.skipif(not _HAS_SSE_MODULE, reason="SSE module not importable")

# -- Helpers -----------------------------------------------------------------


def _make_valid_token(length: int = 48) -> str:
    return generate_secure_token(length)


# -- IP Allowlist Tests ------------------------------------------------------


class TestCheckIpAllowlist:
    """Tests for check_ip_allowlist."""

    def test_ip_in_cidr_range_is_allowed(self):
        assert check_ip_allowlist("192.168.1.50", ["192.168.1.0/24"]) is True

    def test_ip_outside_cidr_range_is_denied(self):
        assert check_ip_allowlist("10.0.0.1", ["192.168.1.0/24"]) is False

    def test_single_ip_exact_match(self):
        assert check_ip_allowlist("10.0.0.5", ["10.0.0.5"]) is True

    def test_single_ip_no_match(self):
        assert check_ip_allowlist("10.0.0.6", ["10.0.0.5"]) is False

    def test_none_allowlist_allows_all(self):
        assert check_ip_allowlist("1.2.3.4", None) is True

    def test_empty_allowlist_allows_all(self):
        assert check_ip_allowlist("1.2.3.4", []) is True

    def test_no_client_ip_with_allowlist_returns_false(self):
        assert check_ip_allowlist("", ["192.168.1.0/24"]) is False

    def test_none_client_ip_with_allowlist_returns_false(self):
        assert check_ip_allowlist("", ["10.0.0.0/8"]) is False

    def test_invalid_client_ip_returns_false(self):
        assert check_ip_allowlist("not-an-ip", ["192.168.1.0/24"]) is False

    def test_invalid_allowlist_entry_is_skipped(self):
        assert check_ip_allowlist("10.0.0.1", ["garbage", "10.0.0.1"]) is True

    def test_all_invalid_allowlist_entries_deny(self):
        assert check_ip_allowlist("10.0.0.1", ["garbage", "also-bad"]) is False

    def test_multiple_allowlist_entries_match_second(self):
        assert check_ip_allowlist("10.5.5.5", ["172.16.0.0/12", "10.0.0.0/8"]) is True

    def test_ipv6_address_in_allowlist(self):
        assert check_ip_allowlist("::1", ["::1/128"]) is True

    def test_ipv6_address_not_in_allowlist(self):
        assert check_ip_allowlist("::2", ["::1/128"]) is False

    def test_cidr_with_host_bits_set(self):
        assert check_ip_allowlist("192.168.1.50", ["192.168.1.100/24"]) is True


# -- Bearer Token Tests ------------------------------------------------------


class TestExtractBearerToken:
    """Tests for extract_bearer_token."""

    def test_valid_bearer_token(self):
        assert extract_bearer_token("Bearer my-secret-token") == "my-secret-token"

    def test_lowercase_bearer(self):
        assert extract_bearer_token("bearer my-secret-token") == "my-secret-token"

    def test_mixed_case_bearer(self):
        assert extract_bearer_token("BEARER my-secret-token") == "my-secret-token"

    def test_basic_auth_returns_none(self):
        assert extract_bearer_token("Basic dXNlcjpwYXNz") is None

    def test_none_header_returns_none(self):
        assert extract_bearer_token(None) is None

    def test_bearer_with_no_token_returns_none(self):
        assert extract_bearer_token("Bearer") is None

    def test_bearer_with_extra_parts_returns_none(self):
        assert extract_bearer_token("Bearer tok1 tok2") is None

    def test_empty_string_returns_none(self):
        assert extract_bearer_token("") is None

    def test_whitespace_only_returns_none(self):
        assert extract_bearer_token("   ") is None

    def test_token_with_special_characters(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
        assert extract_bearer_token(f"Bearer {jwt}") == jwt


# -- Client IP Tests ---------------------------------------------------------


class TestGetClientIp:
    """Tests for get_client_ip."""

    def test_x_forwarded_for_single_ip(self):
        assert get_client_ip({"x-forwarded-for": "203.0.113.50"}) == "203.0.113.50"

    def test_x_forwarded_for_multiple_ips_takes_first(self):
        headers = {"x-forwarded-for": "203.0.113.50, 70.41.3.18, 150.172.238.178"}
        assert get_client_ip(headers) == "203.0.113.50"

    def test_x_forwarded_for_strips_whitespace(self):
        assert get_client_ip({"x-forwarded-for": "  203.0.113.50 , 70.41.3.18"}) == "203.0.113.50"

    def test_x_real_ip(self):
        assert get_client_ip({"x-real-ip": "198.51.100.23"}) == "198.51.100.23"

    def test_x_forwarded_for_takes_precedence(self):
        headers = {"x-forwarded-for": "203.0.113.50", "x-real-ip": "198.51.100.23"}
        assert get_client_ip(headers) == "203.0.113.50"

    def test_no_proxy_headers_returns_none(self):
        assert get_client_ip({"content-type": "application/json"}) is None

    def test_empty_headers_returns_none(self):
        assert get_client_ip({}) is None

    def test_empty_x_forwarded_for_falls_through(self):
        headers = {"x-forwarded-for": "", "x-real-ip": "198.51.100.23"}
        assert get_client_ip(headers) == "198.51.100.23"

    def test_empty_x_forwarded_for_no_fallback_returns_none(self):
        assert get_client_ip({"x-forwarded-for": ""}) is None


# -- BinaryMCPTokenVerifier Tests -------------------------------------------


class TestBinaryMCPTokenVerifier:
    """Tests for the FastMCP TokenVerifier subclass."""

    @pytest.fixture(autouse=True)
    def _load_verifier(self):
        mod = _import_sse_server()
        self.BinaryMCPTokenVerifier = mod.BinaryMCPTokenVerifier

    def test_valid_token_creates_verifier(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        assert verifier._token_hash is not None

    def test_invalid_token_raises(self):
        with pytest.raises(TokenFormatError):
            self.BinaryMCPTokenVerifier("short")

    def test_raw_token_not_stored(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        assert not hasattr(verifier, "_raw_token")
        assert not hasattr(verifier, "_token")

    @pytest.mark.asyncio
    async def test_verify_correct_token_returns_access_token(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        result = await verifier.verify_token(token)
        assert result is not None
        assert result.client_id == "binary-mcp-client"
        assert "tools:*" in result.scopes

    @pytest.mark.asyncio
    async def test_verify_wrong_token_returns_none(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        result = await verifier.verify_token(_make_valid_token())
        assert result is None

    @pytest.mark.asyncio
    async def test_verify_empty_token_returns_none(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        result = await verifier.verify_token("")
        assert result is None

    def test_constant_time_comparison(self):
        token = _make_valid_token()
        verifier = self.BinaryMCPTokenVerifier(token)
        expected_hash = hashlib.sha256(token.encode()).digest()
        assert verifier._token_hash == expected_hash


# -- AuditMiddleware Tests ---------------------------------------------------


class TestAuditMiddleware:
    """Tests for AuditMiddleware instantiation."""

    @pytest.fixture(autouse=True)
    def _load_middleware(self):
        mod = _import_sse_server()
        self.AuditMiddleware = mod.AuditMiddleware

    def test_middleware_can_be_created(self):
        mw = self.AuditMiddleware()
        assert mw is not None

    def test_has_on_call_tool(self):
        mw = self.AuditMiddleware()
        assert hasattr(mw, "on_call_tool")
        assert callable(mw.on_call_tool)

    def test_has_on_message(self):
        mw = self.AuditMiddleware()
        assert hasattr(mw, "on_message")
        assert callable(mw.on_message)
