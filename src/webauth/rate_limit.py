"""The sliding-window counter every per-address budget is measured with.

Two backends honour the `RateLimitBackend` port so a deployment picks the one
its scale needs. `RedisRateLimitBackend` shares one window across every process
that reaches the same Redis; `SingleProcessRateLimitBackend` keeps the window
in this process alone, for a single-node host that runs no Redis. The caller
passes the key, the limit, and the window on every check — neither backend
bakes any of them in.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from redis import Redis


class RedisRateLimitBackend:
    """Sliding-window rate limiter backed by Redis sorted sets.

    One sorted set per key holds the timestamps inside the current window; the
    window slides on every check, so a caller regains budget continuously
    rather than at a fixed reset. The whole check is one Lua script so that
    trimming, counting, and recording cannot interleave with another request.
    A Redis that cannot answer raises, and the middleware fails the request
    closed rather than guessing.

    ``key_prefix`` namespaces this host's keys inside the shared store, so two
    applications on one Redis do not spend each other's budgets. The host
    supplies its own prefix when it constructs the backend.
    """

    def __init__(self, redis: Redis, key_prefix: str) -> None:
        self._redis = redis
        self._key_prefix = key_prefix

    _LUA_SLIDING_WINDOW = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_requests = tonumber(ARGV[3])
    local member = ARGV[4]
    redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
    local count = redis.call('ZCARD', key)
    if count >= max_requests then return count + 1 end
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, window)
    return count + 1
    """

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.time()
        count = self._redis.eval(
            self._LUA_SLIDING_WINDOW,
            1,
            f"{self._key_prefix}:{key}",
            now,
            window_seconds,
            limit,
            uuid.uuid4().hex,
        )
        return count <= limit


PRUNE_INTERVAL_SECONDS: Final = 60


@dataclass
class _WindowedEvents:
    """The timestamps recorded for one key, and the span they are measured over."""

    window_seconds: int
    timestamps: list[float] = field(default_factory=list)


class SingleProcessRateLimitBackend:
    """An in-process sliding-window limiter for a single-node deployment.

    Every key's event timestamps live in this process's memory behind one
    lock, so two processes — or two hosts — count independently. It is
    single-node only: a deployment that runs more than one worker, or more
    than one host, needs `RedisRateLimitBackend` so the budget is shared.

    A key is always checked with the one window it was created with; checking
    it with a different window is a caller bug and raises rather than silently
    dropping a long budget on a short check.

    The key it is checked with is trimmed to its window on every check; the
    whole store is swept for keys aged out of their window only every
    ``PRUNE_INTERVAL_SECONDS``, so a many-address flood cannot turn each request
    into a full scan while the store still stays bounded by the addresses
    currently active rather than by every address ever seen.
    """

    def __init__(self) -> None:
        self._events: dict[str, _WindowedEvents] = {}
        self._lock = threading.Lock()
        self._next_prune_at = 0.0

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            self._sweep_expired_when_due(now)
            entry = self._events.get(key)
            if entry is None:
                entry = _WindowedEvents(window_seconds=window_seconds)
                self._events[key] = entry
            elif entry.window_seconds != window_seconds:
                raise ValueError(
                    f"Key {key!r} was created with a {entry.window_seconds}s window "
                    f"and cannot be checked against a {window_seconds}s one.",
                )
            cutoff = now - window_seconds
            entry.timestamps = [stamp for stamp in entry.timestamps if stamp > cutoff]
            if len(entry.timestamps) >= limit:
                return False
            entry.timestamps.append(now)
            return True

    def active_key_count(self) -> int:
        """How many keys the store currently holds, after the last sweep."""
        with self._lock:
            return len(self._events)

    def _sweep_expired_when_due(self, now: float) -> None:
        if now < self._next_prune_at:
            return
        self._next_prune_at = now + PRUNE_INTERVAL_SECONDS
        expired = [
            key
            for key, entry in self._events.items()
            if not entry.timestamps
            or entry.timestamps[-1] + entry.window_seconds <= now
        ]
        for key in expired:
            del self._events[key]
