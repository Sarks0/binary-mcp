"""
Tests for token validation and generation module.

Covers TokenValidator, generate_secure_token, and verify_token_strength.
"""

import math

import pytest

from src.utils.auth import (
    MAX_TOKEN_LENGTH,
    MIN_TOKEN_LENGTH,
    TokenEntropyError,
    TokenFormatError,
    TokenValidator,
    generate_secure_token,
    verify_token_strength,
)

# -- Helpers -----------------------------------------------------------------


def _make_valid_token(length: int = 48) -> str:
    """Generate a token that passes all validation checks."""
    return generate_secure_token(length)


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
        TokenValidator.check_entropy(token)

    def test_low_shannon_entropy_rejected(self):
        """A repetitive token with low Shannon entropy is rejected."""
        token = "Aa" * (MIN_TOKEN_LENGTH // 2)
        assert len(token) >= MIN_TOKEN_LENGTH
        with pytest.raises(TokenEntropyError):
            TokenValidator.check_entropy(token)

    def test_high_repetition_rejected(self):
        """Tokens where unique chars < 50% of length are rejected."""
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
        assert math.isclose(entropy, 8.0, rel_tol=1e-9)

    def test_two_unique_chars_one_bit_per_char(self):
        """A string of two equally-distributed chars has 1 bit/char."""
        entropy = TokenValidator.calculate_entropy("abab")
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


class TestVerifyTokenStrength:
    """Tests for verify_token_strength()."""

    def test_strong_token(self):
        """A properly generated token is rated as strong."""
        token = _make_valid_token()
        result = verify_token_strength(token)
        assert result["is_strong"] is True
        assert result["issues"] == []

    def test_short_token_flagged(self):
        """A short token is flagged in issues."""
        result = verify_token_strength("short")
        assert not result["is_strong"]
        assert any("Too short" in issue for issue in result["issues"])

    def test_returns_expected_fields(self):
        """Result dict contains all expected keys."""
        result = verify_token_strength(_make_valid_token())
        assert "length" in result
        assert "entropy_bits" in result
        assert "character_diversity" in result
        assert "unique_char_ratio" in result
        assert "is_strong" in result
        assert "issues" in result
