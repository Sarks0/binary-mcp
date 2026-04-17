"""
Rate limiting for MCP server security.

Provides:
- Token bucket rate limiting per IP/session
- Configurable rate limits per endpoint type
- Burst handling for legitimate traffic spikes
- Automatic cleanup of stale rate limit data

Rate limit tiers:
- Authentication: 5 attempts per minute (security critical)
- Tool calls: 100 calls per minute (normal operation)
- Expensive operations: 10 calls per minute (Ghidra analysis, etc.)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from threading import Lock, RLock
from typing import Any

from src.utils.config import get_config_int

logger = logging.getLogger(__name__)


class RateLimitExceededError(Exception):
    """Rate limit exceeded error."""

    pass


class RateLimitTier(Enum):
    """Rate limiting tiers for different operation types."""

    AUTHENTICATION = "authentication"  # Login attempts
    STANDARD = "standard"  # Regular tool calls
    EXPENSIVE = "expensive"  # Analysis, decompilation
    STREAMING = "streaming"  # SSE streaming (higher limits)


@dataclass
class TokenBucket:
    """
    Token bucket for rate limiting.

    Algorithm:
    - Bucket has maximum capacity
    - Tokens added at fixed rate
    - Each request consumes 1 token
    - If no tokens available, request is rate limited
    """

    capacity: int  # Maximum tokens
    refill_rate: float  # Tokens per second
    tokens: float = field(default=0.0)
    last_update: float = field(default_factory=time.time)
    lock: Lock = field(default_factory=Lock)

    def __post_init__(self) -> None:
        """Initialize tokens to capacity if not explicitly set."""
        if self.tokens == 0.0:
            self.tokens = float(self.capacity)

    def consume(self, tokens: int = 1) -> tuple[bool, float]:
        """
        Attempt to consume tokens from bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            Tuple of (success, wait_time_seconds)
            - success: True if tokens were available
            - wait_time: Seconds until enough tokens available (0 if success)
        """
        with self.lock:
            now = time.time()

            # Refill bucket based on time elapsed
            elapsed = now - self.last_update
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
            self.last_update = now

            # Check if enough tokens available
            if self.tokens >= tokens:
                self.tokens -= tokens
                return (True, 0.0)

            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.refill_rate
            return (False, wait_time)


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit tier."""

    capacity: int  # Burst capacity
    refill_rate: float  # Tokens per second (sustained)


# Default rate limit configurations
DEFAULT_RATE_LIMITS: dict[RateLimitTier, RateLimitConfig] = {
    RateLimitTier.AUTHENTICATION: RateLimitConfig(
        capacity=5,  # Allow 5 burst attempts
        refill_rate=5 / 60,  # 5 per minute = 0.083 per second
    ),
    RateLimitTier.STANDARD: RateLimitConfig(
        capacity=100,  # Allow 100 burst calls
        refill_rate=100 / 60,  # 100 per minute = 1.67 per second
    ),
    RateLimitTier.EXPENSIVE: RateLimitConfig(
        capacity=5,  # Allow 5 burst expensive ops
        refill_rate=10 / 60,  # 10 per minute = 0.167 per second
    ),
    RateLimitTier.STREAMING: RateLimitConfig(
        capacity=1000,  # High burst for SSE
        refill_rate=1000 / 60,  # 1000 per minute = 16.67 per second
    ),
}


class RateLimiter:
    """
    Rate limiter for MCP server.

    Provides:
    - Per-IP rate limiting
    - Per-session rate limiting
    - Tiered rate limits (auth, standard, expensive)
    - Automatic cleanup of stale entries
    """

    def __init__(
        self,
        config: dict[RateLimitTier, RateLimitConfig] | None = None,
        cleanup_interval: int = 300,  # 5 minutes
    ):
        """
        Initialize rate limiter.

        Args:
            config: Rate limit configuration per tier
            cleanup_interval: Seconds between stale entry cleanup
        """
        self.config = config or DEFAULT_RATE_LIMITS
        self.cleanup_interval = cleanup_interval

        # Rate limit storage: (key, tier) -> TokenBucket
        self._buckets: dict[tuple[str, RateLimitTier], TokenBucket] = {}
        self._last_activity: dict[tuple[str, RateLimitTier], float] = {}
        self._lock = RLock()
        self._last_cleanup = time.time()

    def _get_bucket(self, key: str, tier: RateLimitTier) -> TokenBucket:
        """Get or create token bucket for key/tier combination."""
        bucket_key = (key, tier)

        with self._lock:
            # Periodic cleanup
            if time.time() - self._last_cleanup > self.cleanup_interval:
                self._cleanup()

            # Create bucket if not exists
            if bucket_key not in self._buckets:
                tier_config = self.config.get(tier, self.config[RateLimitTier.STANDARD])
                self._buckets[bucket_key] = TokenBucket(
                    capacity=tier_config.capacity, refill_rate=tier_config.refill_rate
                )

            self._last_activity[bucket_key] = time.time()
            return self._buckets[bucket_key]

    def check_rate_limit(
        self, key: str, tier: RateLimitTier = RateLimitTier.STANDARD, tokens: int = 1
    ) -> tuple[bool, float, dict[str, Any]]:
        """
        Check if request is within rate limit.

        Args:
            key: Rate limit key (IP, session ID, etc.)
            tier: Rate limit tier for this operation
            tokens: Number of tokens to consume (default 1)

        Returns:
            Tuple of (allowed, wait_time, metadata)
            - allowed: True if request can proceed
            - wait_time: Seconds to wait if not allowed
            - metadata: Additional rate limit info
        """
        bucket = self._get_bucket(key, tier)
        success, wait_time = bucket.consume(tokens)

        metadata = {
            "tier": tier.value,
            "key": key[:8] + "..." if len(key) > 8 else key,
            "capacity": bucket.capacity,
            "current_tokens": bucket.tokens,
            "refill_rate": bucket.refill_rate,
        }

        return (success, wait_time, metadata)

    def assert_rate_limit(
        self, key: str, tier: RateLimitTier = RateLimitTier.STANDARD, tokens: int = 1
    ) -> dict[str, Any]:
        """
        Check rate limit and raise exception if exceeded.

        Args:
            key: Rate limit key
            tier: Rate limit tier
            tokens: Tokens to consume

        Returns:
            Rate limit metadata if allowed

        Raises:
            RateLimitExceededError: If rate limit exceeded
        """
        allowed, wait_time, metadata = self.check_rate_limit(key, tier, tokens)

        if not allowed:
            tier_config = self.config.get(tier, self.config[RateLimitTier.STANDARD])

            raise RateLimitExceededError(
                f"Rate limit exceeded for {tier.value}. "
                f"Limit: {tier_config.capacity} per {tier_config.capacity / tier_config.refill_rate:.0f}s. "
                f"Please wait {wait_time:.1f} seconds before retrying."
            )

        return metadata

    def _cleanup(self) -> int:
        """
        Remove stale rate limit buckets.

        Returns:
            Number of entries cleaned up
        """
        now = time.time()
        stale_threshold = self.cleanup_interval * 2  # 10 minutes

        with self._lock:
            stale_keys = [
                key for key, last in self._last_activity.items() if now - last > stale_threshold
            ]

            for key in stale_keys:
                self._buckets.pop(key, None)
                self._last_activity.pop(key, None)

            self._last_cleanup = now

            if stale_keys:
                logger.debug(f"Cleaned up {len(stale_keys)} stale rate limit entries")

            return len(stale_keys)

    def get_stats(self) -> dict[str, Any]:
        """Get rate limiter statistics."""
        with self._lock:
            # Group by tier
            tier_counts: dict[str, int] = {}
            for key, tier in self._buckets.keys():
                tier_counts[tier.value] = tier_counts.get(tier.value, 0) + 1

            return {
                "total_buckets": len(self._buckets),
                "by_tier": tier_counts,
                "last_cleanup": self._last_cleanup,
                "config": {
                    tier.value: {"capacity": c.capacity, "rate": c.refill_rate}
                    for tier, c in self.config.items()
                },
            }

    def reset(self, key: str | None = None, tier: RateLimitTier | None = None) -> int:
        """
        Reset rate limit buckets.

        Args:
            key: Specific key to reset, or None for all
            tier: Specific tier to reset, or None for all

        Returns:
            Number of buckets reset
        """
        with self._lock:
            if key is None and tier is None:
                # Reset all
                count = len(self._buckets)
                self._buckets.clear()
                self._last_activity.clear()
                return count

            # Selective reset
            keys_to_reset = [
                k
                for k in self._buckets.keys()
                if (key is None or k[0] == key) and (tier is None or k[1] == tier)
            ]

            for k in keys_to_reset:
                self._buckets.pop(k, None)
                self._last_activity.pop(k, None)

            return len(keys_to_reset)


# Global rate limiter instance
_global_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter."""
    global _global_rate_limiter

    if _global_rate_limiter is None:
        # Load custom configuration from config
        auth_limit = get_config_int("MCP_RATE_LIMIT_AUTH", 5)
        standard_limit = get_config_int("MCP_RATE_LIMIT_REQUESTS", 100)
        window_seconds = get_config_int("MCP_RATE_LIMIT_WINDOW", 60)
        expensive_limit = max(5, standard_limit // 10)  # 10% of standard

        config = {
            RateLimitTier.AUTHENTICATION: RateLimitConfig(
                capacity=auth_limit, refill_rate=auth_limit / window_seconds
            ),
            RateLimitTier.STANDARD: RateLimitConfig(
                capacity=standard_limit, refill_rate=standard_limit / window_seconds
            ),
            RateLimitTier.EXPENSIVE: RateLimitConfig(
                capacity=expensive_limit, refill_rate=expensive_limit / window_seconds
            ),
            RateLimitTier.STREAMING: RateLimitConfig(
                capacity=standard_limit * 10, refill_rate=(standard_limit * 10) / window_seconds
            ),
        }

        _global_rate_limiter = RateLimiter(config)
        logger.info(f"Rate limiter initialized: {standard_limit} req/{window_seconds}s")

    return _global_rate_limiter


def reset_rate_limiter() -> None:
    """Reset global rate limiter (for testing)."""
    global _global_rate_limiter
    _global_rate_limiter = None


# Convenience functions for common use cases


def check_auth_rate_limit(client_ip: str | None) -> None:
    """
    Check rate limit for authentication attempts.

    Args:
        client_ip: Client IP address (None for local)

    Raises:
        RateLimitExceededError: If rate limit exceeded
    """
    key = client_ip or "local"
    get_rate_limiter().assert_rate_limit(key, RateLimitTier.AUTHENTICATION)


def check_tool_rate_limit(session_id: str, expensive: bool = False) -> dict[str, Any]:
    """
    Check rate limit for tool calls.

    Args:
        session_id: Session identifier
        expensive: Whether this is an expensive operation

    Returns:
        Rate limit metadata

    Raises:
        RateLimitExceededError: If rate limit exceeded
    """
    tier = RateLimitTier.EXPENSIVE if expensive else RateLimitTier.STANDARD
    return get_rate_limiter().assert_rate_limit(session_id, tier)


def check_stream_rate_limit(session_id: str) -> dict[str, Any]:
    """
    Check rate limit for SSE streaming.

    Args:
        session_id: Session identifier

    Returns:
        Rate limit metadata
    """
    return get_rate_limiter().assert_rate_limit(session_id, RateLimitTier.STREAMING)
