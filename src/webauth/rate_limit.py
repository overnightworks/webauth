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
from typing import TYPE_CHECKING

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
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

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
            key,
            now,
            window_seconds,
            limit,
            uuid.uuid4().hex,
        )
        return count <= limit


RedisRateLimiter = RedisRateLimitBackend


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

    Each check prunes keys whose newest event has aged past their own window,
    so a key touched once and never again does not linger — the store stays
    bounded by the addresses currently active, not by every address ever seen.
    """

    def __init__(self) -> None:
        self._events: dict[str, _WindowedEvents] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        with self._lock:
            self._drop_expired(now)
            entry = self._events.get(key)
            if entry is None:
                entry = _WindowedEvents(window_seconds=window_seconds)
                self._events[key] = entry
            entry.window_seconds = window_seconds
            cutoff = now - window_seconds
            entry.timestamps = [stamp for stamp in entry.timestamps if stamp > cutoff]
            if len(entry.timestamps) >= limit:
                return False
            entry.timestamps.append(now)
            return True

    def active_key_count(self) -> int:
        """How many keys the store currently holds, after the last check's pruning."""
        with self._lock:
            return len(self._events)

    def _drop_expired(self, now: float) -> None:
        expired = [
            key
            for key, entry in self._events.items()
            if not entry.timestamps
            or entry.timestamps[-1] + entry.window_seconds <= now
        ]
        for key in expired:
            del self._events[key]
