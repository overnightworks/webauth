"""The in-process sliding-window backend: counting, expiry, isolation, and bounds."""

from __future__ import annotations

import threading
from unittest.mock import patch

import pytest
from webauth_arrangement import (
    API_PATH,
    MEDIA_PATH,
    RATE_LIMITED_PATH,
    a_class_split_rate_limited_client,
    a_rate_limited_client,
)

from webauth.rate_limit import PRUNE_INTERVAL_SECONDS, SingleProcessRateLimitBackend


class TestCountingAndExpiry:
    def test_counts_events_sharing_a_timestamp(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic", return_value=500.0):
            assert backend.is_allowed("addr", limit=2, window_seconds=60) is True
            assert backend.is_allowed("addr", limit=2, window_seconds=60) is True
            assert backend.is_allowed("addr", limit=2, window_seconds=60) is False
            for _ in range(1_000):
                assert backend.is_allowed("addr", limit=2, window_seconds=60) is False

    def test_window_slides_so_budget_returns(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 100.0
            assert backend.is_allowed("addr", limit=1, window_seconds=10) is True
            assert backend.is_allowed("addr", limit=1, window_seconds=10) is False
            monotonic.return_value = 111.0
            assert backend.is_allowed("addr", limit=1, window_seconds=10) is True

    def test_reusing_a_key_with_a_different_window_raises(self) -> None:
        backend = SingleProcessRateLimitBackend()
        backend.is_allowed("addr", limit=1, window_seconds=60)
        with pytest.raises(ValueError, match="window"):
            backend.is_allowed("addr", limit=1, window_seconds=30)


class TestIsolationAndBounds:
    def test_two_backends_count_independently(self) -> None:
        one = SingleProcessRateLimitBackend()
        two = SingleProcessRateLimitBackend()
        assert one.is_allowed("addr", limit=1, window_seconds=60) is True
        assert two.is_allowed("addr", limit=1, window_seconds=60) is True
        assert one.is_allowed("addr", limit=1, window_seconds=60) is False

    def test_a_key_past_its_window_is_dropped(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 1_000.0
            backend.is_allowed("stale-addr", limit=5, window_seconds=60)
            monotonic.return_value = 1_000.0 + 61
            backend.is_allowed("active-addr", limit=5, window_seconds=60)
        assert backend.active_key_count() == 1

    def test_the_full_sweep_clears_stale_keys_once_the_interval_elapses(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 1_000.0
            for n in range(5):
                backend.is_allowed(f"addr-{n}", limit=1, window_seconds=10)
            assert backend.active_key_count() == 5
            monotonic.return_value = 1_000.0 + PRUNE_INTERVAL_SECONDS + 1
            backend.is_allowed("fresh", limit=1, window_seconds=10)
        assert backend.active_key_count() == 1

    def test_a_sweep_respects_each_keys_own_window(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 1_000.0
            assert backend.is_allowed("long-lived", limit=1, window_seconds=3_600) is True
            monotonic.return_value = 1_000.0 + PRUNE_INTERVAL_SECONDS + 1
            backend.is_allowed("noise", limit=5, window_seconds=30)
            assert backend.is_allowed("long-lived", limit=1, window_seconds=3_600) is False


class TestThreadSafety:
    def test_concurrent_events_never_exceed_the_limit(self) -> None:
        backend = SingleProcessRateLimitBackend()
        limit = 50
        attempts = 500
        verdicts: list[bool] = []
        verdicts_lock = threading.Lock()
        start = threading.Barrier(attempts)

        def hit() -> None:
            start.wait()
            allowed = backend.is_allowed("addr", limit=limit, window_seconds=60)
            with verdicts_lock:
                verdicts.append(allowed)

        threads = [threading.Thread(target=hit) for _ in range(attempts)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sum(verdicts) == limit


class TestMiddlewareOverSingleProcessBackend:
    def test_allows_within_budget_then_blocks(self) -> None:
        client = a_rate_limited_client(SingleProcessRateLimitBackend(), max_requests=2)
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        blocked = client.get(RATE_LIMITED_PATH)
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"] == "60"

    def test_exhausting_the_api_budget_leaves_the_media_path_answering(self) -> None:
        client = a_class_split_rate_limited_client(
            SingleProcessRateLimitBackend(),
            api_max_requests=1,
            media_max_requests=5,
        )
        assert client.get(API_PATH).status_code == 200
        assert client.get(API_PATH).status_code == 429
        assert client.get(MEDIA_PATH).status_code == 200
