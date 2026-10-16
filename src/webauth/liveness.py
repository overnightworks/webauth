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


def _require_positive_seconds(field: str, value: object) -> None:
    """Refuse a lifetime that is not a positive whole number of seconds.

    A zero, negative or fractional lifetime would not fail loudly later: it
    would expire every session at once and leave its users in a login loop.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive whole number of seconds, not {value!r}")


class _ExpiryColumnRecord(Protocol):
    created_at: datetime
    expires_at: datetime


class _IdleWindowRecord(Protocol):
    last_seen: datetime


class ExpiryColumnLiveness:
    """A stored row carrying ``created_at`` and ``expires_at``.

    Idle expiry is the ``expires_at`` column; the absolute cap is measured from
    ``created_at``. A stored row is read as UTC unconditionally.
    """

    def __init__(self, absolute_max_age_seconds: int) -> None:
        _require_positive_seconds("absolute_max_age_seconds", absolute_max_age_seconds)
        self._absolute_max_age_seconds = absolute_max_age_seconds

    def admits_stored_session(self, record: _ExpiryColumnRecord, now: datetime) -> bool:
        if record.expires_at.replace(tzinfo=timezone.utc) < now:
            return False
        return _within_absolute_cap(
            record.created_at.replace(tzinfo=timezone.utc), now, self._absolute_max_age_seconds,
        )


class IdleWindowLiveness:
    """A stored row that keeps ``last_seen``.

    A session stands while it was seen within the idle window; a ``touch`` is a
    put with ``last_seen == now``. With ``absolute_max_age_seconds`` it also
    falls once it is older than the cap, however recently it was seen — the
    store then has to keep ``created_at`` beside ``last_seen``, and a record
    without it, or with a naive one, raises `TypeError` instead of receiving a
    verdict; a naive ``last_seen`` raises it too.
    """

    def __init__(
        self, idle_window_seconds: int, absolute_max_age_seconds: int | None = None,
    ) -> None:
        _require_positive_seconds("idle_window_seconds", idle_window_seconds)
        if absolute_max_age_seconds is not None:
            _require_positive_seconds("absolute_max_age_seconds", absolute_max_age_seconds)
        self._idle_window_seconds = idle_window_seconds
        self._absolute_max_age_seconds = absolute_max_age_seconds

    def admits_stored_session(self, record: _IdleWindowRecord, now: datetime) -> bool:
        # Both host fields are read before any verdict, so a record missing
        # either one fails the same way whether it is idle, capped, or neither.
        if self._absolute_max_age_seconds is None:
            return self._within_idle_window(record.last_seen, now)
        created_at = _created_at_of_capped(record)
        return self._within_idle_window(record.last_seen, now) and _within_absolute_cap(
            created_at, now, self._absolute_max_age_seconds,
        )

    def _within_idle_window(self, last_seen: datetime, now: datetime) -> bool:
        if last_seen.utcoffset() is None:
            raise TypeError(
                "an IdleWindowLiveness needs a timezone-aware last_seen; "
                "a naive one cannot be measured against now",
            )
        return (now - last_seen).total_seconds() <= self._idle_window_seconds


def _created_at_of_capped(record: _IdleWindowRecord) -> datetime:
    # The host's store record crosses into the library here. A capped policy
    # over a store that keeps no ``created_at`` is a host misconfiguration, so
    # it is named as such rather than surfacing as an AttributeError.
    created_at = getattr(record, "created_at", None)
    if created_at is None:
        raise TypeError(
            "an IdleWindowLiveness with absolute_max_age_seconds needs a stored "
            "session record that carries created_at",
        )
    if created_at.utcoffset() is None:
        raise TypeError(
            "an IdleWindowLiveness with absolute_max_age_seconds needs a "
            "timezone-aware created_at; a naive one cannot be measured against now",
        )
    return created_at


def _within_absolute_cap(
    created_at: datetime, now: datetime, absolute_max_age_seconds: int,
) -> bool:
    return (now - created_at).total_seconds() <= absolute_max_age_seconds
