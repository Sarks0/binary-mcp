"""
Tests for authentication and authorization module.

Covers TokenValidator, AuthManager, generate_secure_token,
and create_auth_manager_from_config with comprehensive edge cases.
"""

import math
import time

import pytest

from src.utils.auth import (
    AUTH_RATE_LIMIT_MAX_ATTEMPTS,
    MAX_TOKEN_LENGTH,
    MIN_TOKEN_LENGTH,
    AuthContext,
    AuthenticationFailedError,
    AuthManager,
    RateLimitExceededError,
    SecurityError,
    TokenEntropyError,
    TokenExpiredError,
    TokenFormatError,
    TokenValidator,
    create_auth_manager_from_config,
    generate_secure_token,
)

# -- Helpers -----------------------------------------------------------------


def _make_valid_token(length: int = 48) -> str:
    """Generate a token that passes all validation checks."""
    return generate_secure_token(length)


def _make_manager(token: str | None = None, expiry: int | None = None) -> AuthManager:
    """Create an AuthManager with a known valid token."""
    if token is None:
        token = _make_valid_token()
    return AuthManager(required_token=token, token_expiry_seconds=expiry, enable_audit_log=False)


class TestTokenValidatorValidate:
    """Tests for TokenValidator.validate() and validate_format()."""

    def test_valid_token_passes(self):
        """A properly generated token passes full validation."""
        token = _make_valid_token()
        TokenValidator.validate(token, check_entropy=True)

    def test_too_short_raises_token_format_error(self):
        """Tokens shorter than MIN_TOKEN_LENGTH are rejected."""
        short = "Aa1-" * 4  # 16 chars, below 32 minimum
        assert len(short) < MIN_TOKEN_LENGTH
        with pytest.raises(TokenFormatError, match="too short"):
            TokenValidator.validate(short, check_entropy=False)

    def test_too_long_raises_token_format_error(self):
        """Tokens exceeding MAX_TOKEN_LENGTH are rejected."""
        long_token = "A" * (MAX_TOKEN_LENGTH + 1)
        with pytest.raises(TokenFormatError, match="too long"):
            TokenValidator.validate(long_token, check_entropy=False)

    def test_empty_token_raises_token_format_error(self):
        """Empty string is rejected."""
        with pytest.raises(TokenFormatError, match="empty"):
            TokenValidator.validate("", check_entropy=False)

    def test_invalid_characters_raise_token_format_error(self):
        """Tokens with characters outside the allowed set are rejected."""
        token = "A" * 31 + "!" + "a" * 10  # '!' is not allowed
        with pytest.raises(TokenFormatError, match="invalid characters"):
            TokenValidator.validate(token, check_entropy=False)

    def test_spaces_rejected(self):
        """Whitespace characters are not allowed."""
        token = "A" * 16 + " " + "a" * 16
        with pytest.raises(TokenFormatError, match="invalid characters"):
            TokenValidator.validate_format(token)

    def test_exact_min_length_accepted(self):
        """A token of exactly MIN_TOKEN_LENGTH passes format validation."""
        token = _make_valid_token(MIN_TOKEN_LENGTH)
        TokenValidator.validate_format(token)

    def test_exact_max_length_accepted(self):
        """A token of exactly MAX_TOKEN_LENGTH passes format validation."""
        # Build a long token with valid characters and sufficient entropy
        token = _make_valid_token(MAX_TOKEN_LENGTH)
        TokenValidator.validate_format(token)


class TestTokenValidatorCheckEntropy:
    """Tests for TokenValidator.check_entropy()."""

    def test_all_lowercase_rejected(self):
        """Tokens using only lowercase letters are rejected."""
        token = "a" * MIN_TOKEN_LENGTH
        with pytest.raises(TokenEntropyError, match="low complexity"):
            TokenValidator.check_entropy(token)

    def test_all_uppercase_rejected(self):
        """Tokens using only uppercase letters are rejected."""
        token = "A" * MIN_TOKEN_LENGTH
        with pytest.raises(TokenEntropyError, match="low complexity"):
            TokenValidator.check_entropy(token)

    def test_all_digits_rejected(self):
        """Tokens using only digits are rejected."""
        token = "1234567890" * 4  # 40 chars, all digits
        with pytest.raises(TokenEntropyError, match="low complexity"):
            TokenValidator.check_entropy(token)

    def test_mixed_high_entropy_passes(self):
        """A properly generated mixed-case token passes entropy checks."""
        token = _make_valid_token()
        # Should not raise
        TokenValidator.check_entropy(token)

    def test_low_shannon_entropy_rejected(self):
        """A repetitive token with low Shannon entropy is rejected."""
        # "AaAaAa..." has only 2 unique chars but mixes cases, so it
        # passes the weak-pattern checks. However, Shannon entropy is
        # 1 bit/char * length which for 32 chars = 32 bits < 128 bits.
        token = "Aa" * (MIN_TOKEN_LENGTH // 2)
        assert len(token) >= MIN_TOKEN_LENGTH
        with pytest.raises(TokenEntropyError):
            TokenValidator.check_entropy(token)

    def test_high_repetition_rejected(self):
        """Tokens where unique chars < 50% of length are rejected."""
        # 3 unique chars repeated to fill 36 chars: unique ratio = 3/36 < 0.5
        token = "Ab1" * 12
        assert len(token) >= MIN_TOKEN_LENGTH
        with pytest.raises(TokenEntropyError, match="low complexity"):
            TokenValidator.check_entropy(token)


class TestTokenValidatorCalculateEntropy:
    """Tests for TokenValidator.calculate_entropy()."""

    def test_empty_string_zero_entropy(self):
        """Empty string has zero entropy."""
        assert TokenValidator.calculate_entropy("") == 0.0

    def test_single_char_repeated_zero_entropy(self):
        """A string of repeated characters has zero Shannon entropy."""
        assert TokenValidator.calculate_entropy("aaaa") == 0.0

    def test_four_unique_chars_approx_two_bits_per_char(self):
        """'abcd' has ~2 bits/char Shannon entropy, total ~8 bits."""
        entropy = TokenValidator.calculate_entropy("abcd")
        # Shannon entropy of 4 equally-distributed chars = log2(4) = 2 bits/char
        # Effective = 2.0 * 4 = 8.0
        assert math.isclose(entropy, 8.0, rel_tol=1e-9)

    def test_two_unique_chars_one_bit_per_char(self):
        """A string of two equally-distributed chars has 1 bit/char."""
        entropy = TokenValidator.calculate_entropy("abab")
        # Shannon entropy = 1 bit/char, effective = 1.0 * 4 = 4.0
        assert math.isclose(entropy, 4.0, rel_tol=1e-9)

    def test_entropy_increases_with_diversity(self):
        """More diverse characters produce higher entropy."""
        low = TokenValidator.calculate_entropy("aabb")
        high = TokenValidator.calculate_entropy("abcd")
        assert high > low


class TestGenerateSecureToken:
    """Tests for generate_secure_token()."""

    def test_default_length_is_48(self):
        """Default token length is 48 characters."""
        token = generate_secure_token()
        assert len(token) == 48

    def test_custom_length(self):
        """Custom length produces a token of that length."""
        token = generate_secure_token(length=64)
        assert len(token) == 64

    def test_output_passes_full_validation(self):
        """Generated tokens pass format and entropy validation."""
        token = generate_secure_token()
        TokenValidator.validate(token, check_entropy=True)

    def test_tokens_are_unique(self):
        """Successive calls produce distinct tokens."""
        tokens = {generate_secure_token() for _ in range(50)}
        assert len(tokens) == 50

    def test_roundtrip_validate_with_entropy(self):
        """generate_secure_token output passes validate with check_entropy=True."""
        for _ in range(10):
            token = generate_secure_token()
            TokenValidator.validate(token, check_entropy=True)


class TestAuthManagerConstruction:
    """Tests for AuthManager initialization."""

    def test_valid_token_creates_manager(self):
        """AuthManager initializes successfully with a valid token."""
        token = _make_valid_token()
        manager = AuthManager(
            required_token=token, token_expiry_seconds=3600, enable_audit_log=False
        )
        assert manager.is_configured()

    def test_invalid_token_format_raises(self):
        """AuthManager raises TokenFormatError if the token is too short."""
        with pytest.raises(TokenFormatError):
            AuthManager(required_token="short", enable_audit_log=False)

    def test_none_token_creates_unconfigured_manager(self):
        """AuthManager with no token is unconfigured."""
        manager = AuthManager(required_token=None, enable_audit_log=False)
        assert not manager.is_configured()

    def test_raw_token_cleared_after_init(self):
        """The raw token attribute is set to None after initialization (FIX 5)."""
        token = _make_valid_token()
        manager = AuthManager(required_token=token, enable_audit_log=False)
        assert manager._token is None

    def test_token_hash_stored_after_init(self):
        """The token hash is retained even though the raw token is cleared."""
        token = _make_valid_token()
        manager = AuthManager(required_token=token, enable_audit_log=False)
        assert manager._token_hash is not None
        assert isinstance(manager._token_hash, bytes)


class TestAuthManagerConstantTimeCompare:
    """Tests for AuthManager._constant_time_compare()."""

    def test_correct_token_matches(self):
        """Correct token hash matches."""
        token = _make_valid_token()
        manager = _make_manager(token)
        assert manager._constant_time_compare(token) is True

    def test_wrong_token_does_not_match(self):
        """A different token does not match."""
        token = _make_valid_token()
        other = _make_valid_token()
        manager = _make_manager(token)
        assert manager._constant_time_compare(other) is False

    def test_empty_token_does_not_match(self):
        """An empty string does not match any stored hash."""
        token = _make_valid_token()
        manager = _make_manager(token)
        # Empty string will fail format validation before reaching compare
        # in the authenticate flow, but the compare method itself should return False.
        assert manager._constant_time_compare("") is False

    def test_unconfigured_manager_returns_false(self):
        """Manager with no token always returns False."""
        manager = AuthManager(required_token=None, enable_audit_log=False)
        assert manager._constant_time_compare("anything") is False


class TestAuthManagerAuthenticate:
    """Tests for AuthManager.authenticate()."""

    def test_valid_token_creates_session(self):
        """Authenticating with the correct token returns a session."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        assert session.session_id
        assert session.created_at > 0
        assert session.request_count == 0

    def test_invalid_token_raises_authentication_failed(self):
        """Wrong token raises AuthenticationFailedError."""
        token = _make_valid_token()
        manager = _make_manager(token)
        wrong = _make_valid_token()

        with pytest.raises(AuthenticationFailedError, match="Authentication failed"):
            manager.authenticate(wrong)

    def test_malformed_token_raises_authentication_failed(self):
        """A token too short to pass format validation raises AuthenticationFailedError."""
        token = _make_valid_token()
        manager = _make_manager(token)

        with pytest.raises(AuthenticationFailedError, match="Invalid token format"):
            manager.authenticate("short")

    def test_session_has_expiry_when_configured(self):
        """Session has expires_at when token_expiry_seconds is set."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=3600)
        session = manager.authenticate(token)

        assert session.expires_at is not None
        assert session.expires_at > session.created_at

    def test_session_no_expiry_when_not_configured(self):
        """Session has no expiration when token_expiry_seconds is None."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=None)
        session = manager.authenticate(token)

        assert session.expires_at is None

    def test_context_ip_recorded(self):
        """Client IP from AuthContext is stored in the session."""
        token = _make_valid_token()
        manager = _make_manager(token)
        ctx = AuthContext(client_ip="192.168.1.10")
        session = manager.authenticate(token, context=ctx)

        assert session.client_ip == "192.168.1.10"


class TestAuthManagerRateLimiting:
    """Tests for authentication rate limiting."""

    def test_rate_limit_exceeded_after_max_attempts(self):
        """After AUTH_RATE_LIMIT_MAX_ATTEMPTS + 1 rapid attempts, RateLimitExceededError is raised."""
        token = _make_valid_token()
        manager = _make_manager(token)
        wrong = _make_valid_token()
        ctx = AuthContext(client_ip="10.0.0.1")

        # Make MAX_ATTEMPTS wrong attempts (these count but don't exceed yet)
        for _ in range(AUTH_RATE_LIMIT_MAX_ATTEMPTS):
            with pytest.raises(AuthenticationFailedError):
                manager.authenticate(wrong, context=ctx)

        # The next attempt should trigger the rate limit
        with pytest.raises(RateLimitExceededError, match="Too many authentication attempts"):
            manager.authenticate(wrong, context=ctx)

    def test_rate_limit_not_applied_to_stdio(self):
        """Rate limiting is not applied when client_ip is None (stdio transport)."""
        token = _make_valid_token()
        manager = _make_manager(token)
        wrong = _make_valid_token()
        ctx = AuthContext(client_ip=None)

        # Should not raise RateLimitExceededError regardless of attempt count
        for _ in range(AUTH_RATE_LIMIT_MAX_ATTEMPTS + 5):
            with pytest.raises(AuthenticationFailedError):
                manager.authenticate(wrong, context=ctx)

    def test_rate_limit_per_ip(self):
        """Rate limiting is tracked per IP address independently."""
        token = _make_valid_token()
        manager = _make_manager(token)
        wrong = _make_valid_token()

        ctx_a = AuthContext(client_ip="10.0.0.1")
        ctx_b = AuthContext(client_ip="10.0.0.2")

        # Exhaust rate limit for IP A
        for _ in range(AUTH_RATE_LIMIT_MAX_ATTEMPTS):
            with pytest.raises(AuthenticationFailedError):
                manager.authenticate(wrong, context=ctx_a)

        # IP A is now rate limited
        with pytest.raises(RateLimitExceededError):
            manager.authenticate(wrong, context=ctx_a)

        # IP B should still be allowed
        with pytest.raises(AuthenticationFailedError):
            manager.authenticate(wrong, context=ctx_b)

    def test_rate_limit_resets_after_window(self, monkeypatch):
        """Rate limit resets once the time window elapses."""
        token = _make_valid_token()
        manager = _make_manager(token)
        wrong = _make_valid_token()
        ctx = AuthContext(client_ip="10.0.0.1")

        base_time = 1000000.0
        current_time = base_time

        def mock_time():
            return current_time

        monkeypatch.setattr(time, "time", mock_time)

        # Exhaust rate limit
        for _ in range(AUTH_RATE_LIMIT_MAX_ATTEMPTS):
            with pytest.raises(AuthenticationFailedError):
                manager.authenticate(wrong, context=ctx)

        with pytest.raises(RateLimitExceededError):
            manager.authenticate(wrong, context=ctx)

        # Advance time past the window (60 seconds + 1)
        current_time = base_time + 61.0

        # Should be allowed again (wrong token, but not rate limited)
        with pytest.raises(AuthenticationFailedError):
            manager.authenticate(wrong, context=ctx)


class TestAuthManagerValidateSession:
    """Tests for AuthManager.validate_session()."""

    def test_valid_session_returns_session(self):
        """Validating an active session returns the session object."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        validated = manager.validate_session(session.session_id)
        assert validated.session_id == session.session_id

    def test_expired_session_raises_token_expired(self, monkeypatch):
        """Expired sessions raise TokenExpiredError."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=60)

        base_time = 1000000.0
        current_time = base_time
        monkeypatch.setattr(time, "time", lambda: current_time)

        session = manager.authenticate(token)
        assert session.expires_at is not None

        # Advance past expiration
        current_time = base_time + 120.0

        with pytest.raises(TokenExpiredError, match="Session expired"):
            manager.validate_session(session.session_id)

    def test_expired_session_is_removed(self, monkeypatch):
        """Expired session is removed from session storage."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=60)

        base_time = 1000000.0
        current_time = base_time
        monkeypatch.setattr(time, "time", lambda: current_time)

        session = manager.authenticate(token)
        sid = session.session_id

        current_time = base_time + 120.0

        with pytest.raises(TokenExpiredError):
            manager.validate_session(sid)

        # A second attempt should fail with AuthenticationFailedError (not found)
        with pytest.raises(AuthenticationFailedError, match="Invalid session"):
            manager.validate_session(sid)

    def test_unknown_session_raises_authentication_failed(self):
        """Unknown session ID raises AuthenticationFailedError."""
        token = _make_valid_token()
        manager = _make_manager(token)

        with pytest.raises(AuthenticationFailedError, match="Invalid session"):
            manager.validate_session("nonexistent-session-id")

    def test_session_activity_timestamp_updated(self, monkeypatch):
        """Session last_activity is updated on each validation call."""
        token = _make_valid_token()
        manager = _make_manager(token)

        base_time = 1000000.0
        current_time = base_time
        monkeypatch.setattr(time, "time", lambda: current_time)

        session = manager.authenticate(token)
        original_activity = session.last_activity

        # Advance time slightly
        current_time = base_time + 30.0

        validated = manager.validate_session(session.session_id)
        assert validated.last_activity == base_time + 30.0
        assert validated.last_activity > original_activity

    def test_session_request_count_incremented(self):
        """Request count is incremented on each validation."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        assert session.request_count == 0
        manager.validate_session(session.session_id)
        assert session.request_count == 1
        manager.validate_session(session.session_id)
        assert session.request_count == 2

    def test_session_without_expiry_never_expires(self, monkeypatch):
        """Sessions with no expiry (expires_at=None) remain valid indefinitely."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=None)

        base_time = 1000000.0
        current_time = base_time
        monkeypatch.setattr(time, "time", lambda: current_time)

        session = manager.authenticate(token)
        assert session.expires_at is None

        # Advance time by a large amount
        current_time = base_time + 999999.0

        validated = manager.validate_session(session.session_id)
        assert validated.session_id == session.session_id


class TestAuthManagerSessionOperations:
    """Tests for session revocation, cleanup, and stats."""

    def test_revoke_session(self):
        """Revoking an active session removes it."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        assert manager.revoke_session(session.session_id) is True

        with pytest.raises(AuthenticationFailedError):
            manager.validate_session(session.session_id)

    def test_revoke_nonexistent_returns_false(self):
        """Revoking a nonexistent session returns False."""
        manager = _make_manager()
        assert manager.revoke_session("no-such-session") is False

    def test_cleanup_expired_sessions(self, monkeypatch):
        """cleanup_expired_sessions removes only expired sessions."""
        token = _make_valid_token()
        manager = _make_manager(token, expiry=60)

        base_time = 1000000.0
        current_time = base_time
        monkeypatch.setattr(time, "time", lambda: current_time)

        session1 = manager.authenticate(token)
        session2 = manager.authenticate(token)

        # Advance past expiry
        current_time = base_time + 120.0

        cleaned = manager.cleanup_expired_sessions()
        assert cleaned == 2

        # Both are now gone
        with pytest.raises(AuthenticationFailedError):
            manager.validate_session(session1.session_id)
        with pytest.raises(AuthenticationFailedError):
            manager.validate_session(session2.session_id)

    def test_record_tool_call(self):
        """record_tool_call increments the tool_calls_count."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        assert session.tool_calls_count == 0
        manager.record_tool_call(session.session_id)
        assert session.tool_calls_count == 1

    def test_get_session_stats(self):
        """get_session_stats returns correct counts."""
        token = _make_valid_token()
        manager = _make_manager(token)
        session = manager.authenticate(token)

        manager.validate_session(session.session_id)
        manager.record_tool_call(session.session_id)

        stats = manager.get_session_stats()
        assert stats["active_sessions"] == 1
        assert stats["total_requests"] == 1
        assert stats["total_tool_calls"] == 1


class TestCreateAuthManagerFromConfig:
    """Tests for create_auth_manager_from_config()."""

    def test_remote_access_without_token_raises_security_error(self, monkeypatch):
        """Remote access without MCP_AUTH_TOKEN raises SecurityError."""
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": None,
                "MCP_TRANSPORT": "sse",
                "MCP_HOST": "0.0.0.0",
                "MCP_ALLOW_REMOTE": "false",
            }.get(key, default),
        )
        monkeypatch.setattr(
            "src.utils.config.get_config_int",
            lambda key, default=0: 3600,
        )

        with pytest.raises(SecurityError, match="Remote access requires MCP_AUTH_TOKEN"):
            create_auth_manager_from_config()

    def test_allow_remote_without_token_raises_security_error(self, monkeypatch):
        """MCP_ALLOW_REMOTE=true with localhost but no token raises SecurityError."""
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": None,
                "MCP_TRANSPORT": "sse",
                "MCP_HOST": "127.0.0.1",
                "MCP_ALLOW_REMOTE": "true",
            }.get(key, default),
        )

        with pytest.raises(SecurityError):
            create_auth_manager_from_config()

    def test_stdio_transport_returns_none(self, monkeypatch):
        """stdio transport with no token returns None."""
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": None,
                "MCP_TRANSPORT": "stdio",
                "MCP_HOST": "127.0.0.1",
                "MCP_ALLOW_REMOTE": "false",
            }.get(key, default),
        )

        result = create_auth_manager_from_config()
        assert result is None

    def test_no_token_localhost_returns_none(self, monkeypatch):
        """No token with localhost SSE (no allow_remote) returns None."""
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": None,
                "MCP_TRANSPORT": "sse",
                "MCP_HOST": "127.0.0.1",
                "MCP_ALLOW_REMOTE": "false",
            }.get(key, default),
        )

        result = create_auth_manager_from_config()
        assert result is None

    def test_valid_token_returns_configured_manager(self, monkeypatch):
        """Valid token returns a configured AuthManager."""
        token = _make_valid_token()
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": token,
            }.get(key, default),
        )
        monkeypatch.setattr(
            "src.utils.config.get_config_int",
            lambda key, default=0: 7200,
        )

        manager = create_auth_manager_from_config()
        assert manager is not None
        assert manager.is_configured()
        assert manager._token_expiry == 7200

    def test_zero_expiry_means_no_expiration(self, monkeypatch):
        """Token expiry of 0 is treated as no expiration."""
        token = _make_valid_token()
        monkeypatch.setattr(
            "src.utils.config.get_config",
            lambda key, default=None: {
                "MCP_AUTH_TOKEN": token,
            }.get(key, default),
        )
        monkeypatch.setattr(
            "src.utils.config.get_config_int",
            lambda key, default=0: 0,
        )

        manager = create_auth_manager_from_config()
        assert manager is not None
        assert manager._token_expiry is None
