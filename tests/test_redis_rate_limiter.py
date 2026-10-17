"""The Redis sliding-window backend: what it lets through, blocks, and fails on."""

from __future__ import annotations

import time
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import fakeredis
import pytest
from fastapi.testclient import TestClient
from webauth_arrangement import (
    HTTPS_TEST_SERVER,
    RATE_LIMITED_PATH,
    AlwaysFailingRateLimitBackend,
    a_rate_limited_client,
)

import webauth.rate_limit
from webauth.rate_limit import RedisRateLimitBackend

HOST_PREFIX = "host"
WINDOW_SECONDS = 60
ONE_HOUR = 3600
WORLD_START = 1_800_000_000.0


class WorldClock:
    now = WORLD_START

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def world_clock(monkeypatch):
    world = WorldClock()
    monkeypatch.setattr(time, "time", world)
    return world


@contextmanager
def host_clock_offset_by(world: WorldClock, offset_seconds: int):
    skewed_time = SimpleNamespace(
        time=lambda: world.now + offset_seconds,
        monotonic=time.monotonic,
    )
    with patch.object(webauth.rate_limit, "time", skewed_time):
        yield


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

    def test_window_expiry(self, fake_redis, world_clock) -> None:
        backend = RedisRateLimitBackend(fake_redis, HOST_PREFIX)
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is False
        world_clock.now += 2
        assert backend.is_allowed("rl:test", limit=1, window_seconds=1) is True

    def test_raises_on_redis_failure(self) -> None:
        broken = MagicMock()
        broken.eval.side_effect = ConnectionError("down")
        backend = RedisRateLimitBackend(broken, HOST_PREFIX)
        with pytest.raises(ConnectionError):
            backend.is_allowed("rl:test", limit=10, window_seconds=60)


@pytest.mark.parametrize("offset_seconds", [ONE_HOUR, -ONE_HOUR], ids=["ahead", "behind"])
class TestHostsWithSkewedClocksSharingOneRedis:
    @pytest.fixture
    def honest_and_skewed_hosts(self, fake_redis, world_clock):
        return (
            RedisRateLimitBackend(fake_redis, HOST_PREFIX),
            RedisRateLimitBackend(fake_redis, HOST_PREFIX),
        )

    def test_never_pass_more_than_the_limit(
        self, honest_and_skewed_hosts, world_clock, offset_seconds
    ) -> None:
        honest, skewed = honest_and_skewed_hosts
        verdicts = [honest.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS)]
        with host_clock_offset_by(world_clock, offset_seconds):
            verdicts.append(skewed.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS))
            verdicts.append(skewed.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS))
        verdicts.append(honest.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS))
        assert verdicts == [True, True, False, False]

    def test_skewed_host_does_not_deny_the_honest_host_after_the_window_slides(
        self, honest_and_skewed_hosts, world_clock, offset_seconds
    ) -> None:
        honest, skewed = honest_and_skewed_hosts
        with host_clock_offset_by(world_clock, offset_seconds):
            assert skewed.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS) is True
        world_clock.now += WINDOW_SECONDS / 2
        assert honest.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS) is True
        world_clock.now += WINDOW_SECONDS / 2 + 1
        assert honest.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS) is True
        assert honest.is_allowed("rl:k", limit=2, window_seconds=WINDOW_SECONDS) is False


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

    def test_two_addresses_in_one_ipv6_network_share_a_budget(self) -> None:
        client = a_rate_limited_client(
            RedisRateLimitBackend(fakeredis.FakeRedis(decode_responses=True), HOST_PREFIX),
            max_requests=1,
        )
        first, neighbour = (
            TestClient(client.app, base_url=HTTPS_TEST_SERVER, client=(address, 50000))
            for address in ("2001:db8:1:2::1", "2001:db8:1:2::2")
        )
        assert first.get(RATE_LIMITED_PATH).status_code == 200
        assert neighbour.get(RATE_LIMITED_PATH).status_code == 429

    def test_rejects_closed_when_the_backend_cannot_answer(self) -> None:
        client = a_rate_limited_client(AlwaysFailingRateLimitBackend(), max_requests=5)
        rejected = client.get(RATE_LIMITED_PATH)
        assert rejected.status_code == 503
        assert rejected.headers["Retry-After"] == "5"

