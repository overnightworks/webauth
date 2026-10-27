"""The in-process sliding-window backend: counting, expiry, isolation, and bounds."""

from __future__ import annotations

import threading
from collections.abc import Callable
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

import webauth.rate_limit
from tests.support.webauth_arrangement import (
    API_PATH,
    BULK_BUDGET_NAME,
    BULK_PATH,
    DEFAULT_BUDGET_NAME,
    HTTPS_TEST_SERVER,
    RATE_LIMITED_PATH,
    a_policy_rate_limited_client,
    a_rate_limited_client,
)
from webauth.policies import PathRules, RateLimitBudget, RateLimitPolicy, RateLimitRule
from webauth.rate_limit import SingleProcessRateLimitBackend

PRUNE_INTERVAL_SECONDS = 60


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
            assert backend.is_allowed("stale-addr", limit=5, window_seconds=30) is True
            with pytest.raises(ValueError, match="active-addr"):
                backend.is_allowed("active-addr", limit=5, window_seconds=30)

    def test_the_full_sweep_clears_stale_keys_once_the_interval_elapses(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 1_000.0
            for n in range(5):
                backend.is_allowed(f"addr-{n}", limit=1, window_seconds=10)
            for n in range(5):
                with pytest.raises(ValueError, match=f"addr-{n}"):
                    backend.is_allowed(f"addr-{n}", limit=1, window_seconds=20)
            monotonic.return_value = 1_000.0 + PRUNE_INTERVAL_SECONDS + 1
            backend.is_allowed("fresh", limit=1, window_seconds=10)
            for n in range(5):
                assert backend.is_allowed(f"addr-{n}", limit=1, window_seconds=20) is True
            with pytest.raises(ValueError, match="fresh"):
                backend.is_allowed("fresh", limit=1, window_seconds=20)

    def test_a_sweep_respects_each_keys_own_window(self) -> None:
        backend = SingleProcessRateLimitBackend()
        with patch("webauth.rate_limit.time.monotonic") as monotonic:
            monotonic.return_value = 1_000.0
            assert backend.is_allowed("long-lived", limit=1, window_seconds=3_600) is True
            monotonic.return_value = 1_000.0 + PRUNE_INTERVAL_SECONDS + 1
            backend.is_allowed("noise", limit=5, window_seconds=30)
            assert backend.is_allowed("long-lived", limit=1, window_seconds=3_600) is False


class _LockThatSignalsContention:
    def __init__(self, on_contention: Callable[[], None]) -> None:
        self._lock = threading.Lock()
        self._on_contention = on_contention

    def __enter__(self) -> None:
        if not self._lock.acquire(blocking=False):
            self._on_contention()
            self._lock.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self._lock.release()


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

    def test_a_check_that_waits_for_the_lock_cannot_file_an_older_timestamp(self) -> None:
        first_has_read_clock = threading.Event()
        second_is_settled = threading.Event()
        readings = iter((100.0, 130.0, 210.0, 220.0, 220.0))

        def scripted_monotonic() -> float:
            reading = next(readings)
            if reading == 100.0:
                first_has_read_clock.set()
                assert second_is_settled.wait(timeout=5)
            return reading

        contention_signalling_threading = SimpleNamespace(
            Lock=lambda: _LockThatSignalsContention(second_is_settled.set),
        )
        with patch.object(webauth.rate_limit, "threading", contention_signalling_threading):
            backend = SingleProcessRateLimitBackend()

        def check() -> None:
            backend.is_allowed("addr", limit=2, window_seconds=100)

        def second_check() -> None:
            check()
            second_is_settled.set()

        with patch.object(
            webauth.rate_limit, "time", SimpleNamespace(monotonic=scripted_monotonic),
        ):
            first = threading.Thread(target=check)
            first.start()
            assert first_has_read_clock.wait(timeout=5)
            second = threading.Thread(target=second_check)
            second.start()
            first.join(timeout=5)
            second.join(timeout=5)
            backend.is_allowed("other", limit=1, window_seconds=100)

            for key in ("addr", "other"):
                with pytest.raises(ValueError, match=key):
                    backend.is_allowed(key, limit=1, window_seconds=200)


OTHER_PATH = "/other/thing"
EXEMPT_PATH = "/health"
THREE_PATHS = (API_PATH, BULK_PATH, OTHER_PATH)


def _a_three_budget_policy() -> RateLimitPolicy:
    return RateLimitPolicy(
        default=RateLimitBudget(DEFAULT_BUDGET_NAME, max_requests=1, window_seconds=60),
        rules=(
            RateLimitRule(
                PathRules(prefixes=("/bulk/",)),
                RateLimitBudget(BULK_BUDGET_NAME, max_requests=1, window_seconds=60),
            ),
            RateLimitRule(
                PathRules(prefixes=("/other/",)),
                RateLimitBudget("other", max_requests=1, window_seconds=60),
            ),
        ),
    )


class TestMiddlewareOverSingleProcessBackend:
    def test_allows_within_budget_then_blocks(self) -> None:
        client = a_rate_limited_client(SingleProcessRateLimitBackend(), max_requests=2)
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        assert client.get(RATE_LIMITED_PATH).status_code == 200
        blocked = client.get(RATE_LIMITED_PATH)
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"] == "60"

    def test_two_addresses_in_one_ipv6_network_share_a_budget(self) -> None:
        client = a_rate_limited_client(SingleProcessRateLimitBackend(), max_requests=2)
        assert _from_peer(client, "2001:db8:1:2::1").get(RATE_LIMITED_PATH).status_code == 200
        assert _from_peer(client, "2001:db8:1:2::2").get(RATE_LIMITED_PATH).status_code == 200
        assert _from_peer(client, "2001:db8:1:2::3").get(RATE_LIMITED_PATH).status_code == 429
        assert _from_peer(client, "2001:db8:1:3::1").get(RATE_LIMITED_PATH).status_code == 200

    def test_a_configured_ipv6_budget_prefix_pools_a_wider_network(self) -> None:
        client = a_rate_limited_client(
            SingleProcessRateLimitBackend(), max_requests=1, ipv6_budget_prefix=48,
        )
        assert _from_peer(client, "2001:db8:1:2::1").get(RATE_LIMITED_PATH).status_code == 200
        assert _from_peer(client, "2001:db8:1:ff::1").get(RATE_LIMITED_PATH).status_code == 429

    def test_two_ipv4_addresses_keep_budgets_of_their_own(self) -> None:
        client = a_rate_limited_client(SingleProcessRateLimitBackend(), max_requests=1)
        assert _from_peer(client, "203.0.113.7").get(RATE_LIMITED_PATH).status_code == 200
        assert _from_peer(client, "203.0.113.8").get(RATE_LIMITED_PATH).status_code == 200
        assert _from_peer(client, "203.0.113.7").get(RATE_LIMITED_PATH).status_code == 429

    @pytest.mark.parametrize("exhausted_path", [API_PATH, BULK_PATH, OTHER_PATH])
    def test_exhausting_one_budget_leaves_the_others_answering(self, exhausted_path: str) -> None:
        client = a_policy_rate_limited_client(
            SingleProcessRateLimitBackend(), _a_three_budget_policy(), paths=THREE_PATHS,
        )
        assert client.get(exhausted_path).status_code == 200
        assert client.get(exhausted_path).status_code == 429
        for other_path in set(THREE_PATHS) - {exhausted_path}:
            assert client.get(other_path).status_code == 200

    def test_a_429_carries_the_retry_after_of_the_budget_the_path_spent(self) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget(DEFAULT_BUDGET_NAME, max_requests=1, window_seconds=60),
            rules=(RateLimitRule(
                PathRules(prefixes=("/bulk/",)),
                RateLimitBudget(BULK_BUDGET_NAME, max_requests=1, window_seconds=30),
            ),),
        )
        client = a_policy_rate_limited_client(
            SingleProcessRateLimitBackend(), policy, paths=(API_PATH, BULK_PATH),
        )
        for path in (API_PATH, BULK_PATH):
            client.get(path)

        assert client.get(BULK_PATH).headers["Retry-After"] == "30"
        assert client.get(API_PATH).headers["Retry-After"] == "60"

    def test_an_exempt_path_claimed_by_a_rule_spends_no_budget(self) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget(DEFAULT_BUDGET_NAME, max_requests=1, window_seconds=60),
            rules=(RateLimitRule(
                PathRules(exact=frozenset({EXEMPT_PATH, BULK_PATH})),
                RateLimitBudget(BULK_BUDGET_NAME, max_requests=1, window_seconds=60),
            ),),
            exempt=PathRules(exact=frozenset({EXEMPT_PATH})),
        )
        client = a_policy_rate_limited_client(
            SingleProcessRateLimitBackend(), policy, paths=(API_PATH, BULK_PATH, EXEMPT_PATH),
        )
        assert [client.get(EXEMPT_PATH).status_code for _ in range(3)] == [200, 200, 200]
        assert client.get(BULK_PATH).status_code == 200
        assert client.get(API_PATH).status_code == 200

    def test_each_budget_admits_its_own_limit_of_requests(self) -> None:
        client = a_policy_rate_limited_client(
            SingleProcessRateLimitBackend(), _a_budget_pair_policy(), paths=(API_PATH, BULK_PATH),
        )
        assert [client.get(API_PATH).status_code for _ in range(4)] == [200, 200, 200, 429]
        assert [client.get(BULK_PATH).status_code for _ in range(2)] == [200, 429]

    def test_each_budget_expires_after_its_own_window(self) -> None:
        client = a_policy_rate_limited_client(
            SingleProcessRateLimitBackend(), _a_budget_pair_policy(), paths=(API_PATH, BULK_PATH),
        )
        with _monotonic_clock_at(100.0) as clock:
            for _ in range(3):
                client.get(API_PATH)
            client.get(BULK_PATH)

            clock.now = 100.0 + SHORT_WINDOW_SECONDS + 1
            assert client.get(BULK_PATH).status_code == 200
            assert client.get(API_PATH).status_code == 429

            clock.now = 100.0 + LONG_WINDOW_SECONDS + 1
            assert client.get(API_PATH).status_code == 200


SHORT_WINDOW_SECONDS = 30
LONG_WINDOW_SECONDS = 60


def _a_budget_pair_policy() -> RateLimitPolicy:
    return RateLimitPolicy(
        default=RateLimitBudget(DEFAULT_BUDGET_NAME, 3, LONG_WINDOW_SECONDS),
        rules=(RateLimitRule(
            PathRules(prefixes=("/bulk/",)),
            RateLimitBudget(BULK_BUDGET_NAME, 1, SHORT_WINDOW_SECONDS),
        ),),
    )


@contextmanager
def _monotonic_clock_at(start: float):
    """The limiter's clock alone, steered by the yielded object's ``now``."""
    clock = SimpleNamespace(now=start)
    steered_time = SimpleNamespace(monotonic=lambda: clock.now)
    with patch.object(webauth.rate_limit, "time", steered_time):
        yield clock


def _from_peer(client: TestClient, address: str) -> TestClient:
    """A client of the same application connecting from ``address``."""
    return TestClient(client.app, base_url=HTTPS_TEST_SERVER, client=(address, 50000))
