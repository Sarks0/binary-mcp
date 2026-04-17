"""
Token validation and generation for remote MCP access.

Provides secure token validation with:
- High-entropy token validation
- Format and character set enforcement
- Token strength analysis
- Secure token generation

Security requirements:
- Minimum 32 character tokens
- High entropy detection (reject low-entropy tokens)
- URL-safe base64 character set
"""

from __future__ import annotations

import logging
import math
import secrets
from typing import Any

logger = logging.getLogger(__name__)


class AuthError(Exception):
    """Base authentication error."""

    pass


class TokenFormatError(AuthError):
    """Token format is invalid."""

    pass


class TokenEntropyError(AuthError):
    """Token entropy is too low (insecure)."""

    pass


class SecurityError(Exception):
    """Security configuration error."""

    pass


# Token security requirements
MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 256
MIN_TOKEN_ENTROPY_BITS = 128  # Reject tokens with less than 128 bits effective entropy
ALLOWED_TOKEN_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


class TokenValidator:
    """
    Validates authentication tokens for remote MCP access.

    Enforces security requirements:
    - Minimum 32 character length
    - URL-safe base64 character set
    - High entropy (rejects predictable tokens)
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

        Uses Shannon entropy calculation on token character distribution.
        Higher is better. 128+ bits recommended for security.

        Args:
            token: The token string

        Returns:
            Effective entropy in bits
        """
        if not token:
            return 0.0

        length = len(token)
        freq: dict[str, int] = {}
        for char in token:
            freq[char] = freq.get(char, 0) + 1

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


def generate_secure_token(length: int = 48) -> str:
    """
    Generate a secure authentication token.

    Args:
        length: Token length (default 48 = ~288 bits entropy)

    Returns:
        URL-safe base64 token
    """
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
