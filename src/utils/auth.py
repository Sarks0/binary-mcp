"""
Authentication and authorization for remote MCP access.

Provides secure token-based authentication with:
- High-entropy token validation
- Session management with expiration
- Rate limiting per session
- Security event logging

Security requirements:
- Minimum 32 character tokens
- High entropy detection (reject low-entropy tokens)
- Optional token expiration
- Immutable audit logging
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Base authentication error."""

    pass


class TokenFormatError(AuthError):
    """Token format is invalid."""

    pass


class TokenExpiredError(AuthError):
    """Token has expired."""

    pass


class TokenEntropyError(AuthError):
    """Token entropy is too low (insecure)."""

    pass


class AuthenticationFailedError(AuthError):
    """Authentication failed (generic)."""

    pass


class RateLimitExceededError(AuthError):
    """Too many authentication attempts."""

    pass


# Token security requirements
MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 256
MIN_TOKEN_ENTROPY_BITS = 128  # Reject tokens with less than 128 bits effective entropy
ALLOWED_TOKEN_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

# Rate limiting
AUTH_RATE_LIMIT_WINDOW = 60  # seconds
AUTH_RATE_LIMIT_MAX_ATTEMPTS = 5


class TokenStatus(Enum):
    """Token validation status."""

    VALID = "valid"
    INVALID_FORMAT = "invalid_format"
    EXPIRED = "expired"
    LOW_ENTROPY = "low_entropy"
    REVOKED = "revoked"


@dataclass
class Session:
    """Authenticated session state."""

    session_id: str
    token_hash: str  # SHA-256 hash of token (never store full token)
    created_at: float
    expires_at: float | None  # None = no expiration
    client_ip: str | None
    last_activity: float
    request_count: int = 0
    tool_calls_count: int = 0


@dataclass
class AuthContext:
    """Context for authentication checks."""

    client_ip: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    transport: str = "stdio"


class TokenValidator:
    """
    Validates authentication tokens for remote MCP access.

    Enforces security requirements:
    - Minimum 32 character length
    - URL-safe base64 character set
    - High entropy (rejects predictable tokens)
    - Optional expiration checking
    """

    @staticmethod
    def validate_format(token: str) -> None:
        """
        Validate token format without checking content.

        Raises:
            TokenFormatError: If token format is invalid
        """
        if not token:
            raise TokenFormatError("Token cannot be empty")

        if not isinstance(token, str):
            raise TokenFormatError("Token must be a string")

        if len(token) < MIN_TOKEN_LENGTH:
            raise TokenFormatError(
                f"Token too short: {len(token)} chars (minimum {MIN_TOKEN_LENGTH})"
            )

        if len(token) > MAX_TOKEN_LENGTH:
            raise TokenFormatError(
                f"Token too long: {len(token)} chars (maximum {MAX_TOKEN_LENGTH})"
            )

        # Check character set (URL-safe base64)
        invalid_chars = set(token) - ALLOWED_TOKEN_CHARS
        if invalid_chars:
            raise TokenFormatError(
                f"Token contains invalid characters: {sorted(invalid_chars)[:10]}"
            )

    @staticmethod
    def calculate_entropy(token: str) -> float:
        """
        Calculate effective entropy of token in bits.

        Uses Shannon entropy calculation on token distribution.
        Higher is better. 128+ bits recommended for security.

        Args:
            token: The token string

        Returns:
            Effective entropy in bits
        """
        if not token:
            return 0.0

        # Calculate Shannon entropy
        length = len(token)
        freq = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * (p).bit_length()  # Approximation

        # More accurate calculation
        import math

        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)

        # Effective entropy = entropy per char * length
        return entropy * length

    @classmethod
    def check_entropy(cls, token: str) -> None:
        """
        Verify token has sufficient entropy.

        Raises:
            TokenEntropyError: If entropy is too low
        """
        # Reject obviously weak patterns
        weak_patterns = [
            token.lower() == token,  # All lowercase
            token.upper() == token,  # All uppercase
            token.isdigit(),  # All digits
            len(set(token)) < len(token) * 0.5,  # High repetition
        ]

        if any(weak_patterns):
            raise TokenEntropyError(
                "Token appears to have low complexity (repeated characters, single case, etc)"
            )

        # Calculate actual entropy
        entropy = cls.calculate_entropy(token)
        if entropy < MIN_TOKEN_ENTROPY_BITS:
            raise TokenEntropyError(
                f"Token entropy too low: {entropy:.0f} bits "
                f"(minimum {MIN_TOKEN_ENTROPY_BITS} bits). "
                "Generate a longer or more random token."
            )

    @classmethod
    def validate(cls, token: str, check_entropy: bool = True) -> None:
        """
        Full token validation.

        Args:
            token: Token to validate
            check_entropy: Whether to check entropy (slower but recommended)

        Raises:
            TokenFormatError: If format is invalid
            TokenEntropyError: If entropy is too low
        """
        cls.validate_format(token)

        if check_entropy:
            cls.check_entropy(token)


class AuthManager:
    """
    Manages authentication for remote MCP access.

    Features:
    - Token validation with expiration
    - Session tracking
    - Rate limiting on auth attempts
    - Audit logging integration
    """

    def __init__(
        self,
        required_token: str | None = None,
        token_expiry_seconds: int | None = None,
        enable_audit_log: bool = True,
    ):
        """
        Initialize authentication manager.

        Args:
            required_token: The valid authentication token (from config)
            token_expiry_seconds: Session expiry time (None = no expiry)
            enable_audit_log: Whether to log auth events
        """
        self._token = required_token
        self._token_expiry = token_expiry_seconds
        self._enable_audit = enable_audit_log

        # Session storage (session_id -> Session)
        self._sessions: dict[str, Session] = {}

        # Rate limiting (IP -> [timestamps])
        self._auth_attempts: dict[str, list[float]] = {}

        # Token hash cache (for constant-time comparison)
        self._token_hash: bytes | None = None
        if required_token:
            self._token_hash = self._hash_token(required_token)
            # Validate token meets security requirements on startup
            try:
                TokenValidator.validate(required_token, check_entropy=True)
                logger.info("Authentication token validated and loaded")
            except TokenFormatError as e:
                logger.error(f"SECURITY WARNING: {e}")
                logger.error("Generate a secure token with: python scripts/generate_token.py")
            except TokenEntropyError as e:
                logger.warning(f"Token security concern: {e}")

    @staticmethod
    def _hash_token(token: str) -> bytes:
        """Hash token for constant-time comparison."""
        return hashlib.sha256(token.encode()).digest()

    def _constant_time_compare(self, token: str) -> bool:
        """
        Constant-time token comparison to prevent timing attacks.

        Args:
            token: Token to compare

        Returns:
            True if token matches
        """
        if not self._token_hash:
            return False

        provided_hash = self._hash_token(token)
        return hmac.compare_digest(provided_hash, self._token_hash)

    def _check_rate_limit(self, client_ip: str | None) -> None:
        """
        Check if client has exceeded auth rate limit.

        Args:
            client_ip: Client IP address (None for stdio)

        Raises:
            RateLimitExceededError: If rate limit exceeded
        """
        if client_ip is None:
            return  # No rate limiting for local/stdio

        now = time.time()
        window_start = now - AUTH_RATE_LIMIT_WINDOW

        # Get attempts in current window
        attempts = self._auth_attempts.get(client_ip, [])
        attempts = [t for t in attempts if t > window_start]
        attempts.append(now)
        self._auth_attempts[client_ip] = attempts

        if len(attempts) > AUTH_RATE_LIMIT_MAX_ATTEMPTS:
            raise RateLimitExceededError(
                f"Too many authentication attempts from {client_ip}. "
                f"Limit: {AUTH_RATE_LIMIT_MAX_ATTEMPTS} per {AUTH_RATE_LIMIT_WINDOW}s"
            )

    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _log_auth_event(
        self,
        event: str,
        success: bool,
        client_ip: str | None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log authentication event for audit trail."""
        if not self._enable_audit:
            return

        from src.utils.audit_log import log_security_event

        log_security_event(
            event_type="auth",
            event_subtype=event,
            success=success,
            client_ip=client_ip,
            details=details or {},
        )

    def authenticate(self, token: str, context: AuthContext | None = None) -> Session:
        """
        Authenticate a client with token.

        Args:
            token: Authentication token
            context: Authentication context (IP, headers, etc)

        Returns:
            Session object on success

        Raises:
            AuthenticationFailedError: If authentication fails
            RateLimitExceededError: If rate limit exceeded
            TokenExpiredError: If session expired (re-authentication)
        """
        context = context or AuthContext()
        client_ip = context.client_ip

        # Check rate limit first
        try:
            self._check_rate_limit(client_ip)
        except RateLimitExceededError:
            self._log_auth_event("rate_limit", False, client_ip)
            raise

        # Validate token format
        try:
            TokenValidator.validate(token, check_entropy=False)
        except (TokenFormatError, TokenEntropyError) as e:
            self._log_auth_event("token_validation", False, client_ip, {"error": str(e)})
            raise AuthenticationFailedError(f"Invalid token format: {e}")

        # Check token matches (constant-time comparison)
        if not self._constant_time_compare(token):
            self._log_auth_event("token_mismatch", False, client_ip)
            raise AuthenticationFailedError("Authentication failed")

        # Create session
        session_id = self._generate_session_id()
        now = time.time()

        expires = None
        if self._token_expiry:
            expires = now + self._token_expiry

        session = Session(
            session_id=session_id,
            token_hash=self._hash_token(token).hex()[:16],  # Partial hash for correlation
            created_at=now,
            expires_at=expires,
            client_ip=client_ip,
            last_activity=now,
        )

        self._sessions[session_id] = session

        self._log_auth_event(
            "authentication",
            True,
            client_ip,
            {"session_id": session_id[:8] + "...", "expires_at": expires},
        )

        logger.info(f"Authenticated session {session_id[:8]}... from {client_ip or 'local'}")
        return session

    def validate_session(self, session_id: str) -> Session:
        """
        Validate existing session.

        Args:
            session_id: Session ID to validate

        Returns:
            Session object

        Raises:
            AuthenticationFailedError: If session invalid
            TokenExpiredError: If session expired
        """
        session = self._sessions.get(session_id)

        if not session:
            raise AuthenticationFailedError("Invalid session")

        # Check expiration
        if session.expires_at and time.time() > session.expires_at:
            del self._sessions[session_id]
            raise TokenExpiredError("Session expired, please re-authenticate")

        # Update activity
        session.last_activity = time.time()
        session.request_count += 1

        return session

    def record_tool_call(self, session_id: str) -> None:
        """Record a tool call in session statistics."""
        session = self._sessions.get(session_id)
        if session:
            session.tool_calls_count += 1

    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke an active session.

        Args:
            session_id: Session to revoke

        Returns:
            True if session was revoked
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"Revoked session {session_id[:8]}...")
            return True
        return False

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        now = time.time()
        expired = [
            sid for sid, sess in self._sessions.items() if sess.expires_at and now > sess.expires_at
        ]

        for sid in expired:
            del self._sessions[sid]

        return len(expired)

    def get_session_stats(self) -> dict[str, Any]:
        """Get session statistics."""
        now = time.time()
        return {
            "active_sessions": len(self._sessions),
            "expired_sessions": sum(
                1 for s in self._sessions.values() if s.expires_at and now > s.expires_at
            ),
            "total_requests": sum(s.request_count for s in self._sessions.values()),
            "total_tool_calls": sum(s.tool_calls_count for s in self._sessions.values()),
        }

    def is_configured(self) -> bool:
        """Check if authentication is configured (has token)."""
        return self._token_hash is not None


def create_auth_manager_from_config() -> AuthManager | None:
    """
    Create authentication manager from configuration.

    Returns:
        AuthManager if remote access is configured, None otherwise
    """
    from src.utils.config import get_config, get_config_int

    token = get_config("MCP_AUTH_TOKEN")

    if not token:
        # Check if remote access is requested without auth
        transport = get_config("MCP_TRANSPORT", "stdio")
        host = get_config("MCP_HOST", "127.0.0.1")
        allow_remote = get_config("MCP_ALLOW_REMOTE", "false").lower() == "true"

        if transport != "stdio" and (host != "127.0.0.1" or allow_remote):
            logger.error("SECURITY ERROR: Remote access requested but MCP_AUTH_TOKEN not set!")
            logger.error("Set a secure token in .env: MCP_AUTH_TOKEN=<your-token>")
            logger.error("Generate one with: python scripts/generate_token.py")
            raise SecurityError(
                "Remote access requires MCP_AUTH_TOKEN. "
                "Authentication is mandatory for non-localhost access."
            )

        return None  # No auth for stdio/local

    expiry = get_config_int("MCP_TOKEN_EXPIRY", 3600)
    if expiry == 0:
        expiry = None  # No expiration

    return AuthManager(required_token=token, token_expiry_seconds=expiry, enable_audit_log=True)


class SecurityError(Exception):
    """Security configuration error."""

    pass


def generate_secure_token(length: int = 48) -> str:
    """
    Generate a secure authentication token.

    Args:
        length: Token length (default 48 = ~256 bits entropy)

    Returns:
        URL-safe base64 token
    """
    # Each byte = 8 bits, base64url encoding expands ~4/3
    # For 256 bits entropy: 32 bytes = 43 chars base64url
    # Using 48 chars for good margin
    import math

    bytes_needed = math.ceil(length * 3 / 4)
    token = secrets.token_urlsafe(bytes_needed)
    return token[:length] if len(token) > length else token


def verify_token_strength(token: str) -> dict[str, Any]:
    """
    Analyze token strength and report issues.

    Args:
        token: Token to analyze

    Returns:
        Dictionary with strength assessment
    """
    issues = []

    # Length check
    if len(token) < MIN_TOKEN_LENGTH:
        issues.append(f"Too short: {len(token)} chars (need {MIN_TOKEN_LENGTH})")

    # Character diversity
    has_lower = any(c.islower() for c in token)
    has_upper = any(c.isupper() for c in token)
    has_digit = any(c.isdigit() for c in token)
    has_special = any(c in "-_" for c in token)

    diversity = sum([has_lower, has_upper, has_digit, has_special])
    if diversity < 3:
        issues.append(f"Low character diversity: {diversity}/4 types")

    # Entropy
    try:
        entropy = TokenValidator.calculate_entropy(token)
        if entropy < MIN_TOKEN_ENTROPY_BITS:
            issues.append(f"Low entropy: {entropy:.0f} bits (need {MIN_TOKEN_ENTROPY_BITS})")
    except Exception as e:
        issues.append(f"Entropy calculation failed: {e}")

    # Repetition
    unique_ratio = len(set(token)) / len(token)
    if unique_ratio < 0.5:
        issues.append(f"High repetition: only {unique_ratio * 100:.0f}% unique chars")

    return {
        "length": len(token),
        "entropy_bits": TokenValidator.calculate_entropy(token) if token else 0,
        "character_diversity": diversity,
        "unique_char_ratio": unique_ratio if token else 0,
        "is_strong": len(issues) == 0,
        "issues": issues,
    }
