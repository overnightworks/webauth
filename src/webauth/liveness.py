"""The two liveness policies: an expiry-column store's, and an idle-window store's.

`dependencies` owns the wall clock and passes ``now`` in; nothing here calls
``datetime.now()``. Each policy reads only the fields its own store keeps — the
`webauth.ports.SessionLivenessPolicy` port forces neither shape on the other.
"""

from __future__ import annotations

from datetime import timezone
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime

    from webauth.ports import CachedSessionData


class _ExpiryColumnRecord(Protocol):
    created_at: datetime
    expires_at: datetime


class _IdleWindowRecord(Protocol):
    last_seen: datetime


class ExpiryColumnLiveness:
    """Songmaker's model: a stored row carrying ``created_at`` and ``expires_at``.

    Idle expiry is the ``expires_at`` column; the absolute cap is measured from
    ``created_at``. It reproduces v0.1.0's verdicts exactly, including its
    timezone handling — a stored row is read as UTC unconditionally, while a
    cached payload keeps whatever offset it carries and only a naive one is
    assumed UTC.
    """

    def __init__(self, absolute_max_age_seconds: int) -> None:
        self._absolute_max_age_seconds = absolute_max_age_seconds

    def admits_stored_session(self, record: _ExpiryColumnRecord, now: datetime) -> bool:
        if record.expires_at.replace(tzinfo=timezone.utc) < now:
            return False
        return self._within_absolute_cap(record.created_at.replace(tzinfo=timezone.utc), now)

    def admits_cached_session(self, cached: CachedSessionData, now: datetime) -> bool:
        # The cache's own TTL owns idle expiry, and a cached ``expires_at`` can
        # lag the real TTL after a refresh — trusting it here would expire a
        # live session. Only the absolute cap on ``created_at`` remains.
        created_at = cached.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        return self._within_absolute_cap(created_at, now)

    def _within_absolute_cap(self, created_at: datetime, now: datetime) -> bool:
        return (now - created_at).total_seconds() <= self._absolute_max_age_seconds


class IdleWindowLiveness:
    """Agent-presentator's model: a stored row that keeps only ``last_seen``.

    A session stands while it was seen within the idle window; a ``touch`` is a
    put with ``last_seen == now``. The model is store-only: it has no
    ``created_at``/``expires_at``, so it cannot ride the Redis `SessionCache`,
    and `WebAuthConfig` refuses that pairing at construction.
    """

    def __init__(self, idle_window_seconds: int) -> None:
        self._idle_window_seconds = idle_window_seconds

    def admits_stored_session(self, record: _IdleWindowRecord, now: datetime) -> bool:
        return (now - record.last_seen).total_seconds() <= self._idle_window_seconds

    def admits_cached_session(self, cached: CachedSessionData, now: datetime) -> bool:
        raise NotImplementedError(
            "the idle-window model does not use the Redis session cache; a host "
            "that wants a cache uses expiry-column liveness",
        )
