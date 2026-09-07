"""The Redis sliding-window backend: what it lets through, blocks, and fails on."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from webauth_arrangement import RATE_LIMITED_PATH, a_rate_limited_client

from webauth.rate_limit import RedisRateLimitBackend, RedisRateLimiter


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


class TestRedisRateLimitBackend:
    def test_allows_within_limit(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis)
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True

    def test_blocks_over_limit(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis)
        backend.is_allowed("rl:test", limit=2, window_seconds=60)
        backend.is_allowed("rl:test", limit=2, window_seconds=60)
        assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False

    def test_counts_requests_with_identical_timestamps(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis)
        with patch("webauth.rate_limit.time.time", return_value=1234.5):
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is True
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is True
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False
            for _ in range(1_000):
                assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False
            assert fake_redis.zcard("rl:test") == 2

    def test_different_keys_independent(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis)
        assert backend.is_allowed("rl:a", limit=1, window_seconds=60) is True
        assert backend.is_allowed("rl:b", limit=1, window_seconds=60) is True
        assert backend.is_allowed("rl:a", limit=1, window_seconds=60) is False
        assert backend.is_allowed("rl:b", limit=1, window_seconds=60) is False

    def test_window_expiry(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis)
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is False
        with patch("webauth.rate_limit.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True

    def test_raises_on_redis_failure(self) -> None:
        broken = MagicMock()
        broken.eval.side_effect = ConnectionError("down")
        backend = RedisRateLimitBackend(broken)
        with pytest.raises(ConnectionError):
            backend.is_allowed("rl:test", limit=10, window_seconds=60)

    def test_legacy_name_is_the_same_backend(self) -> None:
        assert RedisRateLimiter is RedisRateLimitBackend


class TestMiddlewareOverRedisBackend:
    def test_allows_within_budget_then_blocks(self) -> None:
        client = a_rate_limited_client(
            RedisRateLimitBackend(fakeredis.FakeRedis(decode_responses=True)),
            max_requests=2,
        )
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        blocked = client.get(RATE_LIMITED_PATH)
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"] == "60"

    def test_rejects_closed_when_the_backend_cannot_answer(self) -> None:
        client = a_rate_limited_client(_AlwaysFailingBackend(), max_requests=5)
        rejected = client.get(RATE_LIMITED_PATH)
        assert rejected.status_code == 503
        assert rejected.headers["Retry-After"] == "5"


class _AlwaysFailingBackend:
    """A backend that can never answer, to prove the middleware fails closed."""

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        raise ConnectionError("rate limiter down")
