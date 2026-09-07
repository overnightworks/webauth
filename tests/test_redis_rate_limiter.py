"""The Redis sliding-window backend: what it lets through, blocks, and fails on."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from webauth_arrangement import RATE_LIMITED_PATH, a_rate_limited_client

from webauth.rate_limit import RedisRateLimitBackend

HOST_PREFIX = "host"


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis(decode_responses=True)


class TestRedisRateLimitBackend:
    def test_allows_within_limit(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True
        assert backend.is_allowed("rl:test", limit=3, window_seconds=60) is True

    def test_blocks_over_limit(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        backend.is_allowed("rl:test", limit=2, window_seconds=60)
        backend.is_allowed("rl:test", limit=2, window_seconds=60)
        assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False

    def test_counts_requests_with_identical_timestamps(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        with patch("webauth.rate_limit.time.time", return_value=1234.5):
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is True
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is True
            assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False
            for _ in range(1_000):
                assert backend.is_allowed("rl:test", limit=2, window_seconds=60) is False
            assert fake_redis.zcard(f"{HOST_PREFIX}:rl:test") == 2

    def test_different_keys_independent(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        assert backend.is_allowed("rl:a", limit=1, window_seconds=60) is True
        assert backend.is_allowed("rl:b", limit=1, window_seconds=60) is True
        assert backend.is_allowed("rl:a", limit=1, window_seconds=60) is False
        assert backend.is_allowed("rl:b", limit=1, window_seconds=60) is False

    def test_two_prefixes_over_one_redis_count_independently(self, fake_redis) -> None:
        host_a = RedisRateLimitBackend(fake_redis, "host-a")
        host_b = RedisRateLimitBackend(fake_redis, "host-b")
        assert host_a.is_allowed("API:1.2.3.4", limit=1, window_seconds=60) is True
        assert host_b.is_allowed("API:1.2.3.4", limit=1, window_seconds=60) is True
        assert host_a.is_allowed("API:1.2.3.4", limit=1, window_seconds=60) is False
        assert host_b.is_allowed("API:1.2.3.4", limit=1, window_seconds=60) is False

    def test_window_expiry(self, fake_redis) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is False
        with patch("webauth.rate_limit.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True

    def test_raises_on_redis_failure(self) -> None:
        broken = MagicMock()
        broken.eval.side_effect = ConnectionError("down")
        backend = RedisRateLimitBackend(broken, HOST_PREFIX)
        with pytest.raises(ConnectionError):
            backend.is_allowed("rl:test", limit=10, window_seconds=60)


class TestMiddlewareOverRedisBackend:
    def test_allows_within_budget_then_blocks(self) -> None:
        client = a_rate_limited_client(
            RedisRateLimitBackend(fakeredis.FakeRedis(decode_responses=True), HOST_PREFIX),
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
