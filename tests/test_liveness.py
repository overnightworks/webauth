"""The liveness policies: who still stands, judged against an injected clock."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    IDLE_WINDOW_SECONDS,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SEVEN_DAYS_SECONDS,
    THIRTY_DAYS_SECONDS,
    FakeUser,
    IdleSessionRecord,
    IdleSessionsInMemory,
)

from webauth.liveness import ExpiryColumnLiveness, IdleWindowLiveness
from webauth.ports import CachedSessionData

A_TIME_FAR_FROM_REAL_NOW = datetime(2000, 1, 1, tzinfo=timezone.utc)
EXPIRY_POLICY = ExpiryColumnLiveness(SESSION_ABSOLUTE_MAX_AGE_SECONDS)
IDLE_POLICY = IdleWindowLiveness(IDLE_WINDOW_SECONDS)


RECOMMENDED_IDLE_POLICY = IdleWindowLiveness(
    SEVEN_DAYS_SECONDS, absolute_max_age_seconds=THIRTY_DAYS_SECONDS,
)


@dataclass
class _ExpiryRecord:
    created_at: datetime
    expires_at: datetime


@dataclass
class _CappedIdleRecord:
    created_at: datetime
    last_seen: datetime


@dataclass
class _RecordWithoutLastSeen:
    created_at: datetime


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
    record = IdleSessionRecord(id="session-1", user=FakeUser(), last_seen=now - idle_age)

    assert IDLE_POLICY.admits_stored_session(record, now) is admitted


@pytest.mark.parametrize(
    ("age", "admitted"),
    [
        pytest.param(timedelta(days=29), True, id="within the cap"),
        pytest.param(timedelta(seconds=THIRTY_DAYS_SECONDS), True, id="at the cap"),
        pytest.param(timedelta(seconds=THIRTY_DAYS_SECONDS + 1), False, id="past the cap"),
    ],
)
def test_a_capped_idle_window_policy_refuses_a_session_older_than_the_cap_however_recently_seen(
    age: timedelta, admitted: bool,
) -> None:
    now = datetime.now(timezone.utc)
    record = _CappedIdleRecord(created_at=now - age, last_seen=now)

    assert RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now) is admitted


@pytest.mark.parametrize(
    "idle_for",
    [
        pytest.param(timedelta(0), id="recently seen"),
        pytest.param(timedelta(days=8), id="already idle"),
    ],
)
def test_a_capped_idle_window_policy_refuses_to_judge_a_record_without_created_at(
    idle_for: timedelta,
) -> None:
    now = datetime.now(timezone.utc)
    record = IdleSessionRecord(id="session-1", user=FakeUser(), last_seen=now - idle_for)

    with pytest.raises(TypeError, match="created_at"):
        RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now)


class _OffsetlessZone(tzinfo):
    """A zone that knows no offset, which makes its datetimes naive."""

    def utcoffset(self, dt: datetime | None) -> None:
        return None


@pytest.mark.parametrize(
    "zone",
    [
        pytest.param(None, id="without tzinfo"),
        pytest.param(_OffsetlessZone(), id="with a tzinfo that has no offset"),
    ],
)
def test_a_capped_idle_window_policy_refuses_to_judge_a_naive_created_at(
    zone: tzinfo | None,
) -> None:
    now = datetime.now(timezone.utc)
    record = _CappedIdleRecord(created_at=now.replace(tzinfo=zone), last_seen=now)

    with pytest.raises(TypeError, match="timezone-aware created_at"):
        RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now)


@pytest.mark.parametrize(
    "policy",
    [
        pytest.param(IDLE_POLICY, id="uncapped"),
        pytest.param(RECOMMENDED_IDLE_POLICY, id="capped"),
    ],
)
@pytest.mark.parametrize(
    "zone",
    [
        pytest.param(None, id="without tzinfo"),
        pytest.param(_OffsetlessZone(), id="with a tzinfo that has no offset"),
    ],
)
def test_an_idle_window_policy_refuses_to_judge_a_naive_last_seen(
    policy: IdleWindowLiveness, zone: tzinfo | None,
) -> None:
    now = datetime.now(timezone.utc)
    record = _CappedIdleRecord(created_at=now, last_seen=now.replace(tzinfo=zone))

    with pytest.raises(TypeError, match="timezone-aware last_seen"):
        policy.admits_stored_session(record, now)


@pytest.mark.parametrize(
    "age",
    [
        pytest.param(timedelta(days=29), id="within the cap"),
        pytest.param(timedelta(seconds=THIRTY_DAYS_SECONDS + 1), id="past the cap"),
    ],
)
def test_a_capped_idle_window_policy_refuses_to_judge_a_record_without_last_seen(
    age: timedelta,
) -> None:
    now = datetime.now(timezone.utc)
    record = _RecordWithoutLastSeen(created_at=now - age)

    with pytest.raises(AttributeError, match="last_seen"):
        RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now)


def test_a_session_used_every_six_days_stands_after_twenty_days_under_a_seven_day_window() -> None:
    created_at = A_TIME_FAR_FROM_REAL_NOW
    record = _CappedIdleRecord(created_at=created_at, last_seen=created_at)

    for day in (6, 12, 18):
        now = created_at + timedelta(days=day)
        assert RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now) is True
        record.last_seen = now

    assert RECOMMENDED_IDLE_POLICY.admits_stored_session(
        record, created_at + timedelta(days=20),
    ) is True


def test_a_session_left_idle_for_eight_days_is_refused_under_a_seven_day_window() -> None:
    record = _CappedIdleRecord(
        created_at=A_TIME_FAR_FROM_REAL_NOW, last_seen=A_TIME_FAR_FROM_REAL_NOW,
    )

    assert RECOMMENDED_IDLE_POLICY.admits_stored_session(
        record, A_TIME_FAR_FROM_REAL_NOW + timedelta(days=8),
    ) is False


def test_the_idle_window_policy_never_answers_for_a_cached_session() -> None:
    """The idle model is store-only; a cache pairing is refused at config time."""
    now = datetime.now(timezone.utc)

    with pytest.raises(NotImplementedError, match="does not use the Redis session cache"):
        IDLE_POLICY.admits_cached_session(_cached(now - timedelta(days=365)), now)


def test_the_idle_window_policy_follows_the_injected_clock_not_the_real_one() -> None:
    record = IdleSessionRecord(
        id="session-1",
        user=FakeUser(),
        last_seen=A_TIME_FAR_FROM_REAL_NOW - timedelta(seconds=1),
    )

    assert IDLE_POLICY.admits_stored_session(record, A_TIME_FAR_FROM_REAL_NOW) is True


def test_a_touch_puts_last_seen_at_now() -> None:
    now = datetime.now(timezone.utc)
    record = IdleSessionRecord(
        id="session-1", user=FakeUser(), last_seen=A_TIME_FAR_FROM_REAL_NOW,
    )
    store = IdleSessionsInMemory(record)

    store.touch(record, ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT, now=now)

    assert record.last_seen == now
