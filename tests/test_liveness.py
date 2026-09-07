"""The liveness policies: who still stands, judged against an injected clock."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    IDLE_WINDOW_SECONDS,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    IdleSessionRecord,
    IdleSessionsInMemory,
)

from webauth.liveness import ExpiryColumnLiveness, IdleWindowLiveness
from webauth.ports import CachedSessionData

A_TIME_FAR_FROM_REAL_NOW = datetime(2000, 1, 1, tzinfo=timezone.utc)
EXPIRY_POLICY = ExpiryColumnLiveness(SESSION_ABSOLUTE_MAX_AGE_SECONDS)
IDLE_POLICY = IdleWindowLiveness(IDLE_WINDOW_SECONDS)


@dataclass
class _ExpiryRecord:
    created_at: datetime
    expires_at: datetime


def _cached(created_at: datetime, *, expires_at: datetime | None = None) -> CachedSessionData:
    return CachedSessionData(
        user_id="user-1",
        username="alice",
        role="user",
        is_active=True,
        ip_address=CLIENT_ADDRESS,
        user_agent=CLIENT_USER_AGENT,
        expires_at=created_at + timedelta(minutes=30) if expires_at is None else expires_at,
        created_at=created_at,
    )


@pytest.mark.parametrize(
    ("idle_offset", "age", "admitted"),
    [
        pytest.param(timedelta(minutes=30), timedelta(minutes=5), True, id="well within both"),
        pytest.param(timedelta(0), timedelta(minutes=5), True, id="at the idle boundary"),
        pytest.param(-timedelta(seconds=1), timedelta(minutes=5), False, id="just past idle"),
        pytest.param(
            timedelta(minutes=30),
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS),
            True,
            id="at the absolute boundary",
        ),
        pytest.param(
            timedelta(minutes=30),
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS + 1),
            False,
            id="just past the absolute cap",
        ),
    ],
)
def test_the_expiry_column_policy_admits_a_stored_session_within_both_limits(
    idle_offset: timedelta, age: timedelta, admitted: bool,
) -> None:
    now = datetime.now(timezone.utc)
    record = _ExpiryRecord(created_at=now - age, expires_at=now + idle_offset)

    assert EXPIRY_POLICY.admits_stored_session(record, now) is admitted


@pytest.mark.parametrize(
    ("age", "admitted"),
    [
        pytest.param(timedelta(minutes=5), True, id="within the absolute cap"),
        pytest.param(
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS), True, id="at the cap",
        ),
        pytest.param(
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS + 1), False, id="past the cap",
        ),
    ],
)
def test_the_expiry_column_policy_caps_a_cached_session_by_its_creation_time(
    age: timedelta, admitted: bool,
) -> None:
    now = datetime.now(timezone.utc)

    assert EXPIRY_POLICY.admits_cached_session(_cached(now - age), now) is admitted


@pytest.mark.parametrize(
    "strip_offset",
    [
        pytest.param(False, id="a creation time stored with its offset"),
        pytest.param(True, id="a creation time stored bare"),
    ],
)
def test_the_expiry_column_policy_reads_a_naive_cached_creation_time_as_utc(
    strip_offset: bool,
) -> None:
    now = datetime.now(timezone.utc)
    created_at = now - timedelta(days=2)
    cached = _cached(created_at.replace(tzinfo=None) if strip_offset else created_at)

    assert EXPIRY_POLICY.admits_cached_session(cached, now) is False


def test_the_expiry_column_policy_never_trusts_a_stale_cached_expiry() -> None:
    now = datetime.now(timezone.utc)
    cached = _cached(now - timedelta(minutes=5), expires_at=now - timedelta(hours=1))

    assert EXPIRY_POLICY.admits_cached_session(cached, now) is True


def test_the_expiry_column_policy_follows_the_injected_clock_not_the_real_one() -> None:
    record = _ExpiryRecord(
        created_at=A_TIME_FAR_FROM_REAL_NOW - timedelta(minutes=5),
        expires_at=A_TIME_FAR_FROM_REAL_NOW + timedelta(minutes=30),
    )

    assert EXPIRY_POLICY.admits_stored_session(record, A_TIME_FAR_FROM_REAL_NOW) is True


@pytest.mark.parametrize(
    ("idle_age", "admitted"),
    [
        pytest.param(timedelta(seconds=1), True, id="just seen"),
        pytest.param(timedelta(seconds=IDLE_WINDOW_SECONDS), True, id="at the window edge"),
        pytest.param(timedelta(seconds=IDLE_WINDOW_SECONDS + 1), False, id="past the window"),
    ],
)
def test_the_idle_window_policy_admits_a_session_seen_within_the_window(
    idle_age: timedelta, admitted: bool,
) -> None:
    now = datetime.now(timezone.utc)
    record = IdleSessionRecord(id="session-1", user_id="user-1", last_seen=now - idle_age)

    assert IDLE_POLICY.admits_stored_session(record, now) is admitted


def test_the_idle_window_policy_has_no_absolute_cap_for_a_cached_session() -> None:
    now = datetime.now(timezone.utc)

    assert IDLE_POLICY.admits_cached_session(_cached(now - timedelta(days=365)), now) is True


def test_the_idle_window_policy_follows_the_injected_clock_not_the_real_one() -> None:
    record = IdleSessionRecord(
        id="session-1",
        user_id="user-1",
        last_seen=A_TIME_FAR_FROM_REAL_NOW - timedelta(seconds=1),
    )

    assert IDLE_POLICY.admits_stored_session(record, A_TIME_FAR_FROM_REAL_NOW) is True


def test_a_touch_puts_last_seen_at_now() -> None:
    now = datetime.now(timezone.utc)
    record = IdleSessionRecord(
        id="session-1", user_id="user-1", last_seen=A_TIME_FAR_FROM_REAL_NOW,
    )
    store = IdleSessionsInMemory(record)

    store.touch(record, ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT, now=now)

    assert record.last_seen == now
