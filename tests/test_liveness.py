"""The liveness policies: who still stands, judged against an injected clock."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo

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

A_TIME_FAR_FROM_REAL_NOW = datetime(2000, 1, 1, tzinfo=UTC)
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
    now = datetime.now(UTC)
    record = _ExpiryRecord(created_at=now - age, expires_at=now + idle_offset)

    assert EXPIRY_POLICY.admits_stored_session(record, now) is admitted


@pytest.mark.parametrize(
    "stored_zone",
    [
        pytest.param(None, id="naive, read as UTC"),
        pytest.param(timezone(timedelta(hours=2)), id="+02:00"),
        pytest.param(timezone(timedelta(hours=-5)), id="-05:00"),
    ],
)
@pytest.mark.parametrize(
    ("expires_in", "age", "admitted"),
    [
        pytest.param(timedelta(0), timedelta(minutes=5), True, id="at the expiry instant"),
        pytest.param(-timedelta(seconds=1), timedelta(minutes=5), False, id="just past expiry"),
        pytest.param(
            timedelta(minutes=30),
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS),
            True,
            id="at the absolute cap",
        ),
        pytest.param(
            timedelta(minutes=30),
            timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS + 1),
            False,
            id="just past the absolute cap",
        ),
    ],
)
def test_the_expiry_column_policy_compares_a_stored_timestamp_as_the_instant_it_names(
    stored_zone: tzinfo | None, expires_in: timedelta, age: timedelta, admitted: bool,
) -> None:
    def stored(instant: datetime) -> datetime:
        if stored_zone is None:
            return instant.replace(tzinfo=None)
        return instant.astimezone(stored_zone)

    record = _ExpiryRecord(
        created_at=stored(A_TIME_FAR_FROM_REAL_NOW - age),
        expires_at=stored(A_TIME_FAR_FROM_REAL_NOW + expires_in),
    )

    assert EXPIRY_POLICY.admits_stored_session(record, A_TIME_FAR_FROM_REAL_NOW) is admitted


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
    now = datetime.now(UTC)
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
    now = datetime.now(UTC)
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
    now = datetime.now(UTC)
    record = IdleSessionRecord(id="session-1", user=FakeUser(), last_seen=now - idle_for)

    with pytest.raises(TypeError, match="created_at"):
        RECOMMENDED_IDLE_POLICY.admits_stored_session(record, now)


class _OffsetlessZone(tzinfo):
    """A zone that knows no offset, which makes its datetimes naive."""

    def utcoffset(self, dt: datetime | None) -> None:
        return None


_NAIVE_ZONES = pytest.mark.parametrize(
    "zone",
    [
        pytest.param(None, id="without tzinfo"),
        pytest.param(_OffsetlessZone(), id="with a tzinfo that has no offset"),
    ],
)


@_NAIVE_ZONES
def test_a_capped_idle_window_policy_refuses_to_judge_a_naive_created_at(
    zone: tzinfo | None,
) -> None:
    now = datetime.now(UTC)
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
@_NAIVE_ZONES
def test_an_idle_window_policy_refuses_to_judge_a_naive_last_seen(
    policy: IdleWindowLiveness, zone: tzinfo | None,
) -> None:
    now = datetime.now(UTC)
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
    now = datetime.now(UTC)
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


def test_the_idle_window_policy_follows_the_injected_clock_not_the_real_one() -> None:
    record = IdleSessionRecord(
        id="session-1",
        user=FakeUser(),
        last_seen=A_TIME_FAR_FROM_REAL_NOW - timedelta(seconds=1),
    )

    assert IDLE_POLICY.admits_stored_session(record, A_TIME_FAR_FROM_REAL_NOW) is True


def test_a_touch_puts_last_seen_at_now() -> None:
    now = datetime.now(UTC)
    record = IdleSessionRecord(
        id="session-1", user=FakeUser(), last_seen=A_TIME_FAR_FROM_REAL_NOW,
    )
    store = IdleSessionsInMemory(record)

    store.touch(record, ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT, now=now)

    assert record.last_seen == now
