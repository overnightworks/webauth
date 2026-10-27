"""``admit_session`` decides a session id with no request, renewing only what it admits."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SESSION_ID,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    SessionRecordsInMemory,
    SessionsAnsweringTouch,
    SessionsEndedBetweenLoadAndTouch,
    a_session,
    a_web_auth_config,
)
from webauth.config import SessionLifetime
from webauth.dependencies import ConnectionRefusal, admit_session
from webauth.ports import AuthenticatedUser

THIRTY_DAYS = timedelta(days=30)
SECOND = timedelta(seconds=1)
IDLE = timedelta(seconds=SESSION_IDLE_SECONDS)
TOLERANCE = timedelta(seconds=60)
CAP = timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS)
HALF_AN_HOUR = timedelta(minutes=30)
FIVE_MINUTES = timedelta(minutes=5)


def naive(instant: datetime) -> datetime:
    return instant.replace(tzinfo=None)


def at_offset(hours: int) -> Callable[[datetime], datetime]:
    return lambda instant: instant.astimezone(timezone(timedelta(hours=hours)))


def admit(
    session_id: str,
    sessions: SessionRecordsInMemory,
    *,
    wall_clock: Callable[[], float] = FIXED_WALL_CLOCK,
    session_lifetime: SessionLifetime | None = None,
) -> AuthenticatedUser | ConnectionRefusal:
    overrides = {} if session_lifetime is None else {"session_lifetime": session_lifetime}
    return admit_session(
        session_id,
        sessions=sessions,
        config=a_web_auth_config(wall_clock=wall_clock, **overrides),
    )


def test_a_session_inside_its_lifetime_returns_its_account_and_is_renewed() -> None:
    record = a_session(now=FIXED_INSTANT)

    outcome = admit(record.id, SessionRecordsInMemory(record))

    assert outcome == AuthenticatedUser(
        id=record.user.id, username=record.user.username, role=record.user.role,
    )
    assert record.expires_at == FIXED_INSTANT + IDLE


@pytest.mark.parametrize(
    ("age", "remaining", "admitted", "renewed_to"),
    [
        pytest.param(FIVE_MINUTES, IDLE, True, IDLE, id="admitted at the idle bound"),
        pytest.param(
            FIVE_MINUTES, IDLE + TOLERANCE, True, IDLE, id="admitted at the tolerance bound",
        ),
        pytest.param(
            CAP - HALF_AN_HOUR, HALF_AN_HOUR, True, HALF_AN_HOUR,
            id="admitted at the cap bound, renewed only to the cap",
        ),
        pytest.param(FIVE_MINUTES, timedelta(0), True, IDLE, id="admitted at the expiry itself"),
        pytest.param(
            FIVE_MINUTES, HALF_AN_HOUR, True, IDLE, id="admitted and renewed by a full idle window",
        ),
        pytest.param(
            CAP - 1000 * SECOND, 500 * SECOND, True, 1000 * SECOND,
            id="renewed to exactly the cap when the cap is sooner",
        ),
        pytest.param(FIVE_MINUTES, -SECOND, False, None, id="refused one second past the expiry"),
        pytest.param(
            CAP - HALF_AN_HOUR, HALF_AN_HOUR + SECOND, False, None,
            id="refused one second past the cap",
        ),
        pytest.param(
            FIVE_MINUTES, IDLE + TOLERANCE + SECOND, False, None,
            id="refused past the tolerance",
        ),
        pytest.param(
            FIVE_MINUTES, THIRTY_DAYS, False, None, id="refused when a store wrote a 30-day expiry",
        ),
        pytest.param(-TOLERANCE, IDLE, True, IDLE, id="admitted created at the tolerance ahead"),
        pytest.param(
            -TOLERANCE - SECOND, IDLE, False, None, id="refused created past the tolerance ahead",
        ),
    ],
)
@pytest.mark.parametrize(
    "stored_as",
    [lambda instant: instant, naive, at_offset(2), at_offset(-5)],
    ids=["aware", "naive", "+02:00", "-05:00"],
)
def test_a_session_is_admitted_inside_its_lifetime_and_renewed_no_further_than_its_cap(
    age: timedelta,
    remaining: timedelta,
    admitted: bool,
    renewed_to: timedelta | None,
    stored_as: Callable[[datetime], datetime],
) -> None:
    record = a_session(now=FIXED_INSTANT, age=age, remaining=remaining)
    record.created_at = stored_as(record.created_at)
    record.expires_at = stored_as(record.expires_at)
    stored_expiry = record.expires_at

    outcome = admit(record.id, SessionRecordsInMemory(record))

    assert isinstance(outcome, AuthenticatedUser) is admitted
    expected_expiry = stored_expiry if renewed_to is None else FIXED_INSTANT + renewed_to
    assert record.expires_at == expected_expiry


def test_a_session_whose_store_never_renews_ends_once_its_old_expiry_passes() -> None:
    clock = [FIXED_INSTANT.timestamp()]
    record = a_session(now=FIXED_INSTANT, remaining=TOLERANCE)
    sessions = SessionsAnsweringTouch(record, True)

    first = admit(record.id, sessions, wall_clock=lambda: clock[0])
    clock[0] += (TOLERANCE + SECOND).total_seconds()
    second = admit(record.id, sessions, wall_clock=lambda: clock[0])

    assert isinstance(first, AuthenticatedUser)
    assert second is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED


@pytest.mark.parametrize(
    ("session_id", "make_store"),
    [
        pytest.param(
            "unknown-session",
            SessionRecordsInMemory,
            id="an unknown id",
        ),
        pytest.param(
            SESSION_ID,
            lambda record: SessionsAnsweringTouch(record, False),
            id="a touch that finds no row",
        ),
        pytest.param(
            SESSION_ID,
            SessionsEndedBetweenLoadAndTouch,
            id="a session ended between load and touch",
        ),
    ],
)
def test_an_unknown_id_or_a_row_touch_no_longer_finds_is_refused(
    session_id: str, make_store: Callable[[FakeSessionRecord], SessionRecordsInMemory],
) -> None:
    record = a_session(now=FIXED_INSTANT)
    stored_expiry = record.expires_at

    outcome = admit(session_id, make_store(record))

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert record.expires_at == stored_expiry


@pytest.mark.parametrize("answer", [None, 1, "yes"])
def test_a_touch_answering_anything_but_a_bool_raises(answer: object) -> None:
    sessions = SessionsAnsweringTouch(a_session(now=FIXED_INSTANT), answer)

    with pytest.raises(TypeError, match="touch must return a bool"):
        admit(SESSION_ID, sessions)


def test_the_clock_is_read_as_whole_seconds() -> None:
    record = a_session(now=FIXED_INSTANT, remaining=timedelta(0))

    outcome = admit(
        record.id,
        SessionRecordsInMemory(record),
        wall_clock=lambda: FIXED_INSTANT.timestamp() + 0.9,
    )

    assert isinstance(outcome, AuthenticatedUser)
    assert record.expires_at == FIXED_INSTANT + IDLE


BERLIN = ZoneInfo("Europe/Berlin")
CLOCK_CHANGE_LIFETIME = SessionLifetime(3600, 7200)
CREATED_BEFORE_THE_CLOCK_CHANGE = datetime(2026, 10, 25, 1, 30, tzinfo=BERLIN)
CAP_INSTANT_ACROSS_THE_CLOCK_CHANGE = datetime(2026, 10, 25, 1, 30, tzinfo=UTC)


def admit_a_berlin_session(
    *, now: datetime, expires_at: datetime,
) -> tuple[FakeSessionRecord, AuthenticatedUser | ConnectionRefusal]:
    record = a_session(now=now)
    record.created_at = CREATED_BEFORE_THE_CLOCK_CHANGE
    record.expires_at = expires_at.astimezone(BERLIN)
    outcome = admit(
        record.id,
        SessionRecordsInMemory(record),
        wall_clock=now.timestamp,
        session_lifetime=CLOCK_CHANGE_LIFETIME,
    )
    return record, outcome


def test_the_cap_counts_elapsed_seconds_across_a_clock_change() -> None:
    _, outcome = admit_a_berlin_session(
        now=datetime(2026, 10, 25, 1, 45, tzinfo=UTC),
        expires_at=datetime(2026, 10, 25, 2, 0, tzinfo=UTC),
    )

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED


def test_a_session_renewed_across_a_clock_change_is_held_at_the_cap_instant() -> None:
    record, outcome = admit_a_berlin_session(
        now=datetime(2026, 10, 25, 0, 45, tzinfo=UTC),
        expires_at=datetime(2026, 10, 25, 0, 50, tzinfo=UTC),
    )

    assert isinstance(outcome, AuthenticatedUser)
    assert record.expires_at == CAP_INSTANT_ACROSS_THE_CLOCK_CHANGE


@pytest.mark.parametrize(
    "stored_as",
    [
        lambda edge: edge.replace(tzinfo=UTC),
        lambda edge: edge,
        lambda edge: edge.replace(tzinfo=timezone(timedelta(hours=1))),
    ],
    ids=["aware", "naive", "+01:00"],
)
@pytest.mark.parametrize(
    ("edge_field", "edge", "other_field_expired"),
    [
        pytest.param("created_at", datetime.max, True, id="created at the latest, expired"),
        pytest.param("created_at", datetime.min, True, id="created at the earliest, expired"),
        pytest.param("created_at", datetime.max, False, id="created at the latest, live"),
        pytest.param("created_at", datetime.min, False, id="created at the earliest, live"),
        pytest.param("expires_at", datetime.max, False, id="expiring at the latest"),
        pytest.param("expires_at", datetime.min, False, id="expiring at the earliest"),
    ],
)
def test_a_stored_instant_at_the_edge_of_the_calendar_is_refused_not_a_server_error(
    edge_field: str,
    edge: datetime,
    other_field_expired: bool,
    stored_as: Callable[[datetime], datetime],
) -> None:
    record = a_session(now=FIXED_INSTANT, remaining=-SECOND if other_field_expired else TOLERANCE)
    setattr(record, edge_field, stored_as(edge))

    outcome = admit(record.id, SessionRecordsInMemory(record))

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
