"""
Tests for rate limiting infrastructure.

Verifies token bucket algorithm, tiered rate limits, stale bucket cleanup,
thread safety, and convenience functions for MCP server security.
"""

import threading
import time
from unittest.mock import patch

import pytest

from src.utils.rate_limit import (
    DEFAULT_RATE_LIMITS,
    RateLimitConfig,
    RateLimiter,
    RateLimitExceededError,
    RateLimitTier,
    TokenBucket,
    check_auth_rate_limit,
    check_stream_rate_limit,
    check_tool_rate_limit,
    get_rate_limiter,
    reset_rate_limiter,
)


class TestTokenBucket:
    """Tests for TokenBucket rate limiting algorithm."""

    def test_new_bucket_starts_full(self):
        """New bucket should start with tokens equal to capacity."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        assert bucket.tokens == 10.0

    def test_consume_within_capacity_succeeds(self):
        """Consuming a token from a non-empty bucket returns success with zero wait."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        success, wait_time = bucket.consume(1)
        assert success is True
        assert wait_time == 0.0

    def test_consume_reduces_token_count(self):
        """Each consume call reduces the available token count."""
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        bucket.consume(1)
        assert bucket.tokens == pytest.approx(9.0, abs=0.1)

    def test_consume_beyond_capacity_fails(self):
        """Consuming more tokens than available returns failure with positive wait time."""
        bucket = TokenBucket(capacity=2, refill_rate=1.0)
        # Drain the bucket
        bucket.consume(2)
        # Next consume should fail
        success, wait_time = bucket.consume(1)
        assert success is False
        assert wait_time > 0.0

    def test_wait_time_is_correct(self):
        """Wait time should reflect how long until enough tokens are available."""
        bucket = TokenBucket(capacity=1, refill_rate=0.5)  # 0.5 tokens/sec
        bucket.consume(1)  # Drain

        success, wait_time = bucket.consume(1)
        assert success is False
        # Need 1 token at 0.5 tokens/sec = 2 seconds
        assert wait_time == pytest.approx(2.0, abs=0.2)

    def test_tokens_refill_after_time_passes(self, monkeypatch):
        """Tokens should refill based on elapsed time since last update."""
        fake_time = [1000.0]

        def mock_time():
            return fake_time[0]

        monkeypatch.setattr(time, "time", mock_time)

        # Construct with explicit last_update to avoid default_factory capturing
        # the original time.time at class-definition time.
        bucket = TokenBucket(capacity=10, refill_rate=2.0, last_update=1000.0)
        bucket.consume(5)  # 5 tokens left

        # Advance time by 2 seconds -> should add 4 tokens (2/sec * 2s)
        fake_time[0] = 1002.0
        success, _ = bucket.consume(1)
        assert success is True
        # Had 5, gained 4, consumed 1 = 8
        assert bucket.tokens == pytest.approx(8.0, abs=0.1)

    def test_refill_does_not_exceed_capacity(self, monkeypatch):
        """Token refill should be capped at bucket capacity."""
        fake_time = [1000.0]

        def mock_time():
            return fake_time[0]

        monkeypatch.setattr(time, "time", mock_time)

        bucket = TokenBucket(capacity=10, refill_rate=100.0, last_update=1000.0)
        bucket.consume(5)  # 5 tokens left

        # Advance a long time -- should cap at capacity
        fake_time[0] = 2000.0
        bucket.consume(1)
        assert bucket.tokens <= 10.0

    def test_burst_consume_up_to_capacity(self):
        """A full bucket should allow consuming up to its entire capacity at once."""
        bucket = TokenBucket(capacity=50, refill_rate=1.0)
        success, wait_time = bucket.consume(50)
        assert success is True
        assert wait_time == 0.0
        assert bucket.tokens == pytest.approx(0.0, abs=0.1)

    def test_burst_consume_exceeds_capacity_fails(self):
        """Consuming more than capacity from a full bucket should fail."""
        bucket = TokenBucket(capacity=5, refill_rate=1.0)
        success, wait_time = bucket.consume(6)
        assert success is False
        assert wait_time > 0.0

    def test_thread_safety_concurrent_consumes(self):
        """Concurrent consume calls should not corrupt the token count."""
        bucket = TokenBucket(capacity=1000, refill_rate=0.0)  # No refill
        results = []
        errors = []

        def consume_one():
            try:
                success, _ = bucket.consume(1)
                results.append(success)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=consume_one) for _ in range(1000)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert not errors
        # Exactly 1000 should succeed (capacity is 1000, no refill)
        assert sum(results) == 1000
        assert bucket.tokens == pytest.approx(0.0, abs=0.1)


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""

    def test_construction_with_valid_values(self):
        """Config should store capacity and refill_rate correctly."""
        config = RateLimitConfig(capacity=50, refill_rate=2.5)
        assert config.capacity == 50
        assert config.refill_rate == 2.5

    def test_fields_store_correctly(self):
        """Fields should be accessible and retain their values."""
        config = RateLimitConfig(capacity=1, refill_rate=0.001)
        assert config.capacity == 1
        assert config.refill_rate == pytest.approx(0.001)


class TestRateLimitTier:
    """Tests for RateLimitTier enum."""

    def test_enum_has_expected_members(self):
        """Enum should have AUTHENTICATION, STANDARD, EXPENSIVE, STREAMING members."""
        assert RateLimitTier.AUTHENTICATION.value == "authentication"
        assert RateLimitTier.STANDARD.value == "standard"
        assert RateLimitTier.EXPENSIVE.value == "expensive"
        assert RateLimitTier.STREAMING.value == "streaming"

    def test_enum_member_count(self):
        """Should have exactly 4 tiers."""
        assert len(RateLimitTier) == 4


class TestDefaultRateLimits:
    """Tests for default rate limit configurations."""

    def test_all_tiers_have_defaults(self):
        """Every tier should have a default config."""
        for tier in RateLimitTier:
            assert tier in DEFAULT_RATE_LIMITS

    def test_authentication_is_most_restrictive(self):
        """Authentication tier should have the lowest capacity of non-streaming tiers."""
        auth = DEFAULT_RATE_LIMITS[RateLimitTier.AUTHENTICATION]
        standard = DEFAULT_RATE_LIMITS[RateLimitTier.STANDARD]
        assert auth.capacity < standard.capacity
        assert auth.refill_rate < standard.refill_rate

    def test_streaming_has_highest_capacity(self):
        """Streaming tier should have the highest capacity."""
        streaming = DEFAULT_RATE_LIMITS[RateLimitTier.STREAMING]
        for tier in RateLimitTier:
            if tier != RateLimitTier.STREAMING:
                assert streaming.capacity > DEFAULT_RATE_LIMITS[tier].capacity

    def test_default_configs_are_reasonable(self):
        """Default configs should have positive capacity and refill rate."""
        for tier, config in DEFAULT_RATE_LIMITS.items():
            assert config.capacity > 0, f"{tier} capacity should be positive"
            assert config.refill_rate > 0, f"{tier} refill_rate should be positive"


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_check_rate_limit_within_limits(self):
        """Within-limit requests should return allowed=True with metadata."""
        limiter = RateLimiter()
        allowed, wait_time, metadata = limiter.check_rate_limit("test-ip", RateLimitTier.STANDARD)

        assert allowed is True
        assert wait_time == 0.0
        assert metadata["tier"] == "standard"
        assert "capacity" in metadata
        assert "current_tokens" in metadata
        assert "refill_rate" in metadata

    def test_check_rate_limit_key_truncation(self):
        """Keys longer than 8 characters should be truncated in metadata."""
        limiter = RateLimiter()
        _, _, metadata = limiter.check_rate_limit("a-very-long-key", RateLimitTier.STANDARD)
        assert metadata["key"] == "a-very-l..."

    def test_check_rate_limit_short_key_not_truncated(self):
        """Keys of 8 characters or fewer should not be truncated."""
        limiter = RateLimiter()
        _, _, metadata = limiter.check_rate_limit("short", RateLimitTier.STANDARD)
        assert metadata["key"] == "short"

    def test_check_rate_limit_exceeding_limit(self):
        """Exceeding the bucket capacity should return allowed=False."""
        config = {
            RateLimitTier.STANDARD: RateLimitConfig(capacity=2, refill_rate=0.001),
        }
        limiter = RateLimiter(config=config)

        # Drain the bucket
        limiter.check_rate_limit("ip", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip", RateLimitTier.STANDARD)

        # Next call should be rate limited
        allowed, wait_time, metadata = limiter.check_rate_limit("ip", RateLimitTier.STANDARD)
        assert allowed is False
        assert wait_time > 0.0

    def test_different_tiers_have_different_limits(self):
        """AUTHENTICATION, STANDARD, and EXPENSIVE tiers should have distinct capacities."""
        config = {
            RateLimitTier.AUTHENTICATION: RateLimitConfig(capacity=2, refill_rate=0.001),
            RateLimitTier.STANDARD: RateLimitConfig(capacity=10, refill_rate=0.001),
            RateLimitTier.EXPENSIVE: RateLimitConfig(capacity=3, refill_rate=0.001),
            RateLimitTier.STREAMING: RateLimitConfig(capacity=100, refill_rate=0.001),
        }
        limiter = RateLimiter(config=config)

        # Auth: capacity 2 -- third call fails
        limiter.check_rate_limit("ip", RateLimitTier.AUTHENTICATION)
        limiter.check_rate_limit("ip", RateLimitTier.AUTHENTICATION)
        allowed, _, _ = limiter.check_rate_limit("ip", RateLimitTier.AUTHENTICATION)
        assert allowed is False

        # Standard: capacity 10 -- third call succeeds
        limiter.check_rate_limit("ip", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip", RateLimitTier.STANDARD)
        allowed, _, _ = limiter.check_rate_limit("ip", RateLimitTier.STANDARD)
        assert allowed is True

    def test_different_keys_have_independent_buckets(self):
        """Different keys should have separate rate limit buckets."""
        config = {
            RateLimitTier.STANDARD: RateLimitConfig(capacity=1, refill_rate=0.001),
        }
        limiter = RateLimiter(config=config)

        # Drain bucket for ip-1
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        allowed_1, _, _ = limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)

        # ip-2 should still have capacity
        allowed_2, _, _ = limiter.check_rate_limit("ip-2", RateLimitTier.STANDARD)

        assert allowed_1 is False
        assert allowed_2 is True

    def test_assert_rate_limit_returns_metadata_when_allowed(self):
        """assert_rate_limit should return metadata when within limits."""
        limiter = RateLimiter()
        metadata = limiter.assert_rate_limit("test-ip", RateLimitTier.STANDARD)
        assert metadata["tier"] == "standard"
        assert "capacity" in metadata

    def test_assert_rate_limit_raises_when_exceeded(self):
        """assert_rate_limit should raise RateLimitExceededError when exceeded."""
        config = {
            RateLimitTier.STANDARD: RateLimitConfig(capacity=1, refill_rate=0.001),
        }
        limiter = RateLimiter(config=config)

        limiter.assert_rate_limit("ip", RateLimitTier.STANDARD)

        with pytest.raises(RateLimitExceededError) as exc_info:
            limiter.assert_rate_limit("ip", RateLimitTier.STANDARD)

        error_msg = str(exc_info.value)
        assert "Rate limit exceeded" in error_msg
        assert "standard" in error_msg
        assert "wait" in error_msg.lower()

    def test_stale_bucket_cleanup(self, monkeypatch):
        """Stale buckets should be removed after cleanup_interval passes."""
        fake_time = 1000.0

        def mock_time():
            return fake_time

        monkeypatch.setattr(time, "time", mock_time)

        limiter = RateLimiter(cleanup_interval=60)

        # Create a bucket
        limiter.check_rate_limit("old-ip", RateLimitTier.STANDARD)
        assert len(limiter._buckets) == 1

        # Advance past cleanup interval so _get_bucket triggers cleanup
        fake_time = 1061.0

        # Create a new bucket -- this triggers cleanup via _get_bucket
        # But old-ip's last_activity is at 1000, and stale_threshold is 120s (60*2)
        # At time 1061, old-ip is 61s old which is < 120s stale threshold
        # So old-ip should NOT be cleaned up yet
        limiter.check_rate_limit("new-ip", RateLimitTier.STANDARD)

        # old-ip should still be present (not stale enough)
        assert ("old-ip", RateLimitTier.STANDARD) in limiter._buckets

        # Advance well past stale threshold (2 * cleanup_interval = 120s)
        fake_time = 1200.0

        # Force cleanup by setting _last_cleanup to old value
        limiter._last_cleanup = 1061.0

        # Trigger cleanup by accessing a bucket
        limiter.check_rate_limit("trigger-ip", RateLimitTier.STANDARD)

        # old-ip and new-ip should be cleaned up (last activity > 120s ago)
        assert ("old-ip", RateLimitTier.STANDARD) not in limiter._buckets

    def test_cleanup_returns_count(self, monkeypatch):
        """_cleanup should return the number of stale entries removed."""
        fake_time = 1000.0

        def mock_time():
            return fake_time

        monkeypatch.setattr(time, "time", mock_time)

        limiter = RateLimiter(cleanup_interval=60)

        # Create 3 buckets
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-2", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-3", RateLimitTier.AUTHENTICATION)

        # Advance past stale threshold
        fake_time = 1200.0

        count = limiter._cleanup()
        assert count == 3
        assert len(limiter._buckets) == 0

    def test_no_deadlock_during_cleanup(self):
        """check_rate_limit triggering cleanup should not deadlock (uses RLock)."""
        config = {
            RateLimitTier.STANDARD: RateLimitConfig(capacity=10000, refill_rate=10000.0),
        }
        limiter = RateLimiter(config=config, cleanup_interval=0)
        # cleanup_interval=0 means every _get_bucket call triggers cleanup

        deadlock_detected = threading.Event()
        completed = threading.Event()

        def hammer():
            try:
                for i in range(100):
                    limiter.check_rate_limit(f"ip-{i}", RateLimitTier.STANDARD)
                completed.set()
            except Exception:
                pass

        t = threading.Thread(target=hammer)
        t.start()
        t.join(timeout=10)

        if t.is_alive():
            deadlock_detected.set()

        assert not deadlock_detected.is_set(), "Deadlock detected in check_rate_limit with cleanup"
        assert completed.is_set(), "Thread did not complete in time"

    def test_get_stats(self):
        """get_stats should return bucket counts grouped by tier."""
        limiter = RateLimiter()
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-2", RateLimitTier.AUTHENTICATION)

        stats = limiter.get_stats()
        assert stats["total_buckets"] == 2
        assert stats["by_tier"]["standard"] == 1
        assert stats["by_tier"]["authentication"] == 1
        assert "config" in stats

    def test_reset_all(self):
        """reset() with no arguments should clear all buckets."""
        limiter = RateLimiter()
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-2", RateLimitTier.AUTHENTICATION)

        count = limiter.reset()
        assert count == 2
        assert len(limiter._buckets) == 0
        assert len(limiter._last_activity) == 0

    def test_reset_by_key(self):
        """reset(key=...) should only clear buckets for that key."""
        limiter = RateLimiter()
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-2", RateLimitTier.STANDARD)

        count = limiter.reset(key="ip-1")
        assert count == 1
        assert ("ip-1", RateLimitTier.STANDARD) not in limiter._buckets
        assert ("ip-2", RateLimitTier.STANDARD) in limiter._buckets

    def test_reset_by_tier(self):
        """reset(tier=...) should only clear buckets for that tier."""
        limiter = RateLimiter()
        limiter.check_rate_limit("ip-1", RateLimitTier.STANDARD)
        limiter.check_rate_limit("ip-1", RateLimitTier.AUTHENTICATION)

        count = limiter.reset(tier=RateLimitTier.AUTHENTICATION)
        assert count == 1
        assert ("ip-1", RateLimitTier.STANDARD) in limiter._buckets
        assert ("ip-1", RateLimitTier.AUTHENTICATION) not in limiter._buckets

    def test_unknown_tier_falls_back_to_standard(self):
        """Requesting a tier not in config should fall back to STANDARD config."""
        config = {
            RateLimitTier.STANDARD: RateLimitConfig(capacity=42, refill_rate=1.0),
        }
        limiter = RateLimiter(config=config)

        # AUTHENTICATION is not in config -- should fall back to STANDARD
        _, _, metadata = limiter.check_rate_limit("ip", RateLimitTier.AUTHENTICATION)
        assert metadata["capacity"] == 42


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def setup_method(self):
        """Reset the global rate limiter before each test."""
        reset_rate_limiter()

    def teardown_method(self):
        """Reset the global rate limiter after each test."""
        reset_rate_limiter()

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_auth_rate_limit_succeeds(self, mock_config):
        """check_auth_rate_limit should not raise when within limits."""
        mock_config.side_effect = lambda key, default: default
        # Should not raise
        check_auth_rate_limit("192.168.1.1")

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_auth_rate_limit_with_none_ip(self, mock_config):
        """check_auth_rate_limit with None IP should use 'local' as key."""
        mock_config.side_effect = lambda key, default: default
        # Should not raise -- uses "local" as key
        check_auth_rate_limit(None)

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_auth_rate_limit_raises_when_exceeded(self, mock_config):
        """check_auth_rate_limit should raise after exceeding auth limit."""
        mock_config.side_effect = lambda key, default: {
            "MCP_RATE_LIMIT_AUTH": 2,
            "MCP_RATE_LIMIT_REQUESTS": 100,
            "MCP_RATE_LIMIT_WINDOW": 60,
        }.get(key, default)

        check_auth_rate_limit("attacker-ip")
        check_auth_rate_limit("attacker-ip")

        with pytest.raises(RateLimitExceededError):
            check_auth_rate_limit("attacker-ip")

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_tool_rate_limit_standard(self, mock_config):
        """check_tool_rate_limit should use STANDARD tier by default."""
        mock_config.side_effect = lambda key, default: default
        metadata = check_tool_rate_limit("session-1")
        assert metadata["tier"] == "standard"

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_tool_rate_limit_expensive(self, mock_config):
        """check_tool_rate_limit with expensive=True should use EXPENSIVE tier."""
        mock_config.side_effect = lambda key, default: default
        metadata = check_tool_rate_limit("session-1", expensive=True)
        assert metadata["tier"] == "expensive"

    @patch("src.utils.rate_limit.get_config_int")
    def test_check_stream_rate_limit_uses_streaming_tier(self, mock_config):
        """check_stream_rate_limit should use STREAMING tier."""
        mock_config.side_effect = lambda key, default: default
        metadata = check_stream_rate_limit("session-1")
        assert metadata["tier"] == "streaming"


class TestGlobalRateLimiter:
    """Tests for get_rate_limiter() and reset_rate_limiter() singleton management."""

    def setup_method(self):
        """Reset the global rate limiter before each test."""
        reset_rate_limiter()

    def teardown_method(self):
        """Reset the global rate limiter after each test."""
        reset_rate_limiter()

    @patch("src.utils.rate_limit.get_config_int")
    def test_get_rate_limiter_returns_singleton(self, mock_config):
        """get_rate_limiter should return the same instance on subsequent calls."""
        mock_config.side_effect = lambda key, default: default
        limiter1 = get_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is limiter2

    @patch("src.utils.rate_limit.get_config_int")
    def test_reset_rate_limiter_clears_singleton(self, mock_config):
        """reset_rate_limiter should cause get_rate_limiter to create a new instance."""
        mock_config.side_effect = lambda key, default: default
        limiter1 = get_rate_limiter()
        reset_rate_limiter()
        limiter2 = get_rate_limiter()
        assert limiter1 is not limiter2

    @patch("src.utils.rate_limit.get_config_int")
    def test_get_rate_limiter_uses_config(self, mock_config):
        """get_rate_limiter should use config values for rate limit setup."""
        mock_config.side_effect = lambda key, default: {
            "MCP_RATE_LIMIT_AUTH": 3,
            "MCP_RATE_LIMIT_REQUESTS": 200,
            "MCP_RATE_LIMIT_WINDOW": 120,
        }.get(key, default)

        limiter = get_rate_limiter()
        # Auth capacity should be 3
        auth_config = limiter.config[RateLimitTier.AUTHENTICATION]
        assert auth_config.capacity == 3
        # Standard capacity should be 200
        standard_config = limiter.config[RateLimitTier.STANDARD]
        assert standard_config.capacity == 200
        # Refill rate for standard: 200/120
        assert standard_config.refill_rate == pytest.approx(200 / 120)


class TestRateLimitExceededError:
    """Tests for RateLimitExceededError exception."""

    def test_is_exception(self):
        """RateLimitExceededError should be an Exception subclass."""
        assert issubclass(RateLimitExceededError, Exception)

    def test_can_be_raised_and_caught(self):
        """RateLimitExceededError should be raisable and catchable."""
        with pytest.raises(RateLimitExceededError):
            raise RateLimitExceededError("Too many requests")

    def test_message_preserved(self):
        """Error message should be preserved."""
        with pytest.raises(RateLimitExceededError, match="Too many requests"):
            raise RateLimitExceededError("Too many requests")
