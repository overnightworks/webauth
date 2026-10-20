"""The library's one session lifetime: who is admitted, and what renewal writes."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from webauth_arrangement import (
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SESSION_IDLE_SECONDS,
    AuthApp,
    FakeSessionRecord,
    SessionsAnsweringTouch,
    a_session,
    an_auth_app,
)

from webauth.config import SessionLifetime

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


@pytest.mark.parametrize(
    ("age", "remaining", "status", "renewed_to"),
    [
        pytest.param(FIVE_MINUTES, IDLE, 200, IDLE, id="admitted at the idle bound"),
        pytest.param(
            FIVE_MINUTES, IDLE + TOLERANCE, 200, IDLE, id="admitted at the tolerance bound",
        ),
        pytest.param(
            CAP - HALF_AN_HOUR, HALF_AN_HOUR, 200, HALF_AN_HOUR,
            id="admitted at the cap bound, renewed only to the cap",
        ),
        pytest.param(FIVE_MINUTES, timedelta(0), 200, IDLE, id="admitted at the expiry itself"),
        pytest.param(
            FIVE_MINUTES, HALF_AN_HOUR, 200, IDLE, id="admitted and renewed by a full idle window",
        ),
        pytest.param(
            CAP - 1000 * SECOND, 500 * SECOND, 200, 1000 * SECOND,
            id="renewed to exactly the cap when the cap is sooner",
        ),
        pytest.param(FIVE_MINUTES, -SECOND, 401, None, id="refused one second past the expiry"),
        pytest.param(
            CAP - HALF_AN_HOUR, HALF_AN_HOUR + SECOND, 401, None,
            id="refused one second past the cap",
        ),
        pytest.param(
            FIVE_MINUTES, IDLE + TOLERANCE + SECOND, 401, None,
            id="refused past the tolerance",
        ),
        pytest.param(
            FIVE_MINUTES, THIRTY_DAYS, 401, None, id="refused when a store wrote a 30-day expiry",
        ),
        pytest.param(-TOLERANCE, IDLE, 200, IDLE, id="admitted created at the tolerance ahead"),
        pytest.param(
            -TOLERANCE - SECOND, IDLE, 401, None, id="refused created past the tolerance ahead",
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
    status: int,
    renewed_to: timedelta | None,
    stored_as: Callable[[datetime], datetime],
) -> None:
    record = a_session(now=FIXED_INSTANT, age=age, remaining=remaining)
    record.created_at = stored_as(record.created_at)
    record.expires_at = stored_as(record.expires_at)
    stored_expiry = record.expires_at
    app = an_auth_app(record, wall_clock=FIXED_WALL_CLOCK)

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == status
    expected_expiry = stored_expiry if renewed_to is None else FIXED_INSTANT + renewed_to
    assert record.expires_at == expected_expiry


def test_a_session_whose_store_never_renews_ends_once_its_old_expiry_passes() -> None:
    clock = [FIXED_INSTANT.timestamp()]
    record = a_session(now=FIXED_INSTANT, remaining=TOLERANCE)
    app = an_auth_app(
        None, sessions=SessionsAnsweringTouch(record, True), wall_clock=lambda: clock[0],
    )
    cookie = app.signed_cookie()

    first = app.get("/me", cookie=cookie)
    clock[0] += (TOLERANCE + SECOND).total_seconds()
    second = app.get("/me", cookie=cookie)

    assert (first.status_code, second.status_code) == (200, 401)


def test_a_touch_reporting_no_row_refuses_an_otherwise_admitted_session() -> None:
    record = a_session(now=FIXED_INSTANT)
    stored_expiry = record.expires_at
    app = an_auth_app(
        None, sessions=SessionsAnsweringTouch(record, False), wall_clock=FIXED_WALL_CLOCK,
    )

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
    assert record.expires_at == stored_expiry


def test_the_clock_is_read_as_whole_seconds() -> None:
    record = a_session(now=FIXED_INSTANT, remaining=timedelta(0))
    app = an_auth_app(record, wall_clock=lambda: FIXED_INSTANT.timestamp() + 0.9)

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 200
    assert record.expires_at == FIXED_INSTANT + IDLE


BERLIN = ZoneInfo("Europe/Berlin")
CLOCK_CHANGE_LIFETIME = SessionLifetime(3600, 7200)
CREATED_BEFORE_THE_CLOCK_CHANGE = datetime(2026, 10, 25, 1, 30, tzinfo=BERLIN)
CAP_INSTANT_ACROSS_THE_CLOCK_CHANGE = datetime(2026, 10, 25, 1, 30, tzinfo=UTC)


def a_berlin_session(*, now: datetime, expires_at: datetime) -> tuple[FakeSessionRecord, AuthApp]:
    record = a_session(now=now)
    record.created_at = CREATED_BEFORE_THE_CLOCK_CHANGE
    record.expires_at = expires_at.astimezone(BERLIN)
    app = an_auth_app(
        record, session_lifetime=CLOCK_CHANGE_LIFETIME, wall_clock=now.timestamp,
    )
    return record, app


def test_the_cap_counts_elapsed_seconds_across_a_clock_change() -> None:
    now = datetime(2026, 10, 25, 1, 45, tzinfo=UTC)
    record, app = a_berlin_session(now=now, expires_at=datetime(2026, 10, 25, 2, 0, tzinfo=UTC))

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401


def test_a_session_renewed_across_a_clock_change_is_held_at_the_cap_instant() -> None:
    now = datetime(2026, 10, 25, 0, 45, tzinfo=UTC)
    record, app = a_berlin_session(now=now, expires_at=datetime(2026, 10, 25, 0, 50, tzinfo=UTC))

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 200
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
    app = an_auth_app(record, wall_clock=FIXED_WALL_CLOCK)

    response = app.get("/me", cookie=app.signed_cookie())

    assert response.status_code == 401
