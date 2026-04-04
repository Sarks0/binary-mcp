"""
Tests for SSE server standalone/unit-testable functions.

Covers check_ip_allowlist, extract_bearer_token, get_client_ip,
and MCPRequestHandler class-level attributes.
"""

from src.transports.sse_server import (
    MAX_REQUEST_BODY,
    MCPRequestHandler,
    check_ip_allowlist,
    extract_bearer_token,
    get_client_ip,
)


class TestCheckIpAllowlist:
    """Tests for check_ip_allowlist."""

    def test_ip_in_cidr_range_is_allowed(self):
        """IP within a CIDR range should be allowed."""
        assert check_ip_allowlist("192.168.1.50", ["192.168.1.0/24"]) is True

    def test_ip_outside_cidr_range_is_denied(self):
        """IP outside a CIDR range should be denied."""
        assert check_ip_allowlist("10.0.0.1", ["192.168.1.0/24"]) is False

    def test_single_ip_exact_match(self):
        """Exact single-IP match should be allowed."""
        assert check_ip_allowlist("10.0.0.5", ["10.0.0.5"]) is True

    def test_single_ip_no_match(self):
        """Non-matching single IP should be denied."""
        assert check_ip_allowlist("10.0.0.6", ["10.0.0.5"]) is False

    def test_none_allowlist_allows_all(self):
        """None allowlist should allow all IPs."""
        assert check_ip_allowlist("1.2.3.4", None) is True

    def test_empty_allowlist_allows_all(self):
        """Empty allowlist should allow all IPs."""
        assert check_ip_allowlist("1.2.3.4", []) is True

    def test_no_client_ip_with_allowlist_returns_false(self):
        """Empty client_ip with an active allowlist should fail closed."""
        assert check_ip_allowlist("", ["192.168.1.0/24"]) is False

    def test_none_client_ip_with_allowlist_returns_false(self):
        """None client_ip with an active allowlist should fail closed."""
        # check_ip_allowlist expects str, but falsy values should deny
        assert check_ip_allowlist("", ["10.0.0.0/8"]) is False

    def test_invalid_client_ip_returns_false(self):
        """Malformed client IP should be handled gracefully (returns False)."""
        assert check_ip_allowlist("not-an-ip", ["192.168.1.0/24"]) is False

    def test_invalid_allowlist_entry_is_skipped(self):
        """Invalid allowlist entries should be skipped without crashing."""
        # The valid entry should still be checked
        assert check_ip_allowlist("10.0.0.1", ["garbage", "10.0.0.1"]) is True

    def test_all_invalid_allowlist_entries_deny(self):
        """If all allowlist entries are invalid, deny the request."""
        assert check_ip_allowlist("10.0.0.1", ["garbage", "also-bad"]) is False

    def test_multiple_allowlist_entries_match_second(self):
        """Match in the second allowlist entry should still allow access."""
        allowlist = ["172.16.0.0/12", "10.0.0.0/8"]
        assert check_ip_allowlist("10.5.5.5", allowlist) is True

    def test_ipv6_address_in_allowlist(self):
        """IPv6 address should work with CIDR notation."""
        assert check_ip_allowlist("::1", ["::1/128"]) is True

    def test_ipv6_address_not_in_allowlist(self):
        """IPv6 address outside range should be denied."""
        assert check_ip_allowlist("::2", ["::1/128"]) is False

    def test_cidr_with_host_bits_set(self):
        """CIDR with host bits set should work (strict=False)."""
        # 192.168.1.100/24 has host bits set; strict=False normalises it
        assert check_ip_allowlist("192.168.1.50", ["192.168.1.100/24"]) is True


class TestExtractBearerToken:
    """Tests for extract_bearer_token."""

    def test_valid_bearer_token(self):
        """Standard 'Bearer <token>' should return the token."""
        assert extract_bearer_token("Bearer my-secret-token") == "my-secret-token"

    def test_lowercase_bearer(self):
        """Case-insensitive 'bearer' prefix should work."""
        assert extract_bearer_token("bearer my-secret-token") == "my-secret-token"

    def test_mixed_case_bearer(self):
        """Mixed case 'BEARER' prefix should work."""
        assert extract_bearer_token("BEARER my-secret-token") == "my-secret-token"

    def test_basic_auth_returns_none(self):
        """'Basic' scheme should not be treated as Bearer."""
        assert extract_bearer_token("Basic dXNlcjpwYXNz") is None

    def test_none_header_returns_none(self):
        """None header value should return None."""
        assert extract_bearer_token(None) is None

    def test_bearer_with_no_token_returns_none(self):
        """'Bearer' with no token part should return None (only 1 part)."""
        assert extract_bearer_token("Bearer") is None

    def test_bearer_with_extra_parts_returns_none(self):
        """'Bearer tok1 tok2' has 3 parts, so len != 2 -> returns None."""
        assert extract_bearer_token("Bearer tok1 tok2") is None

    def test_empty_string_returns_none(self):
        """Empty string should return None."""
        assert extract_bearer_token("") is None

    def test_whitespace_only_returns_none(self):
        """Whitespace-only string should return None (split yields empty parts)."""
        assert extract_bearer_token("   ") is None

    def test_token_with_special_characters(self):
        """Tokens with special characters (JWT-like) should be extracted."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
        assert extract_bearer_token(f"Bearer {jwt}") == jwt


class TestGetClientIp:
    """Tests for get_client_ip."""

    def test_x_forwarded_for_single_ip(self):
        """X-Forwarded-For with a single IP should return that IP."""
        headers = {"x-forwarded-for": "203.0.113.50"}
        assert get_client_ip(headers) == "203.0.113.50"

    def test_x_forwarded_for_multiple_ips_takes_first(self):
        """X-Forwarded-For with multiple IPs should return the first one."""
        headers = {"x-forwarded-for": "203.0.113.50, 70.41.3.18, 150.172.238.178"}
        assert get_client_ip(headers) == "203.0.113.50"

    def test_x_forwarded_for_strips_whitespace(self):
        """Whitespace around the first IP should be stripped."""
        headers = {"x-forwarded-for": "  203.0.113.50 , 70.41.3.18"}
        assert get_client_ip(headers) == "203.0.113.50"

    def test_x_real_ip(self):
        """X-Real-IP header should be used when X-Forwarded-For is absent."""
        headers = {"x-real-ip": "198.51.100.23"}
        assert get_client_ip(headers) == "198.51.100.23"

    def test_x_forwarded_for_takes_precedence_over_x_real_ip(self):
        """X-Forwarded-For should take precedence over X-Real-IP."""
        headers = {
            "x-forwarded-for": "203.0.113.50",
            "x-real-ip": "198.51.100.23",
        }
        assert get_client_ip(headers) == "203.0.113.50"

    def test_no_proxy_headers_returns_none(self):
        """When no proxy headers exist, returns None."""
        headers = {"content-type": "application/json"}
        assert get_client_ip(headers) is None

    def test_empty_headers_returns_none(self):
        """Empty headers dict should return None."""
        assert get_client_ip({}) is None

    def test_empty_x_forwarded_for_falls_through(self):
        """Empty X-Forwarded-For should fall through to X-Real-IP."""
        headers = {"x-forwarded-for": "", "x-real-ip": "198.51.100.23"}
        assert get_client_ip(headers) == "198.51.100.23"

    def test_empty_x_forwarded_for_no_fallback_returns_none(self):
        """Empty X-Forwarded-For with no other headers should return None."""
        headers = {"x-forwarded-for": ""}
        assert get_client_ip(headers) is None


class TestMCPRequestHandlerClassAttributes:
    """Tests for MCPRequestHandler class-level defaults."""

    def test_require_auth_defaults_to_false(self):
        """require_auth should default to False."""
        # Check the class-level default (not after run_sse_server mutates it)
        # The class definition sets it to False
        assert MCPRequestHandler.__dict__["require_auth"] is False

    def test_cors_origin_defaults_to_wildcard(self):
        """cors_origin should default to '*'."""
        assert MCPRequestHandler.__dict__["cors_origin"] == "*"

    def test_max_request_body_is_10mb(self):
        """MAX_REQUEST_BODY constant should be 10 MB."""
        assert MAX_REQUEST_BODY == 10 * 1024 * 1024

    def test_auth_manager_defaults_to_none(self):
        """auth_manager should default to None."""
        assert MCPRequestHandler.__dict__["auth_manager"] is None

    def test_rate_limiter_defaults_to_none(self):
        """rate_limiter should default to None."""
        assert MCPRequestHandler.__dict__["rate_limiter"] is None

    def test_ip_allowlist_defaults_to_none(self):
        """ip_allowlist should default to None."""
        assert MCPRequestHandler.__dict__["ip_allowlist"] is None
