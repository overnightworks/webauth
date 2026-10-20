"""``admit_session`` decides a session id with no request, renewing only what it admits."""

from __future__ import annotations

from datetime import timedelta

import pytest
from webauth_arrangement import (
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SESSION_ID,
    SESSION_IDLE_SECONDS,
    SessionRecordsInMemory,
    SessionsAnsweringTouch,
    a_session,
    a_web_auth_config,
)

from webauth.dependencies import ConnectionRefusal, admit_session
from webauth.ports import AuthenticatedUser

IDLE = timedelta(seconds=SESSION_IDLE_SECONDS)
CAP = timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS)
SECOND = timedelta(seconds=1)


def admit(
    session_id: str, sessions: SessionRecordsInMemory,
) -> AuthenticatedUser | ConnectionRefusal:
    return admit_session(
        session_id,
        sessions=sessions,
        config=a_web_auth_config(wall_clock=FIXED_WALL_CLOCK),
    )


def test_a_session_inside_its_lifetime_returns_its_account_and_is_renewed() -> None:
    record = a_session(now=FIXED_INSTANT)

    outcome = admit(record.id, SessionRecordsInMemory(record))

    assert outcome == AuthenticatedUser(
        id=record.user.id, username=record.user.username, role=record.user.role,
    )
    assert record.expires_at == FIXED_INSTANT + IDLE


def test_a_renewal_stops_at_the_absolute_cap() -> None:
    record = a_session(now=FIXED_INSTANT, age=CAP - 500 * SECOND, remaining=100 * SECOND)

    admit(record.id, SessionRecordsInMemory(record))

    assert record.expires_at == FIXED_INSTANT + 500 * SECOND


@pytest.mark.parametrize(
    ("session_id", "sessions", "renewal_is_observable"),
    [
        pytest.param(
            SESSION_ID,
            SessionRecordsInMemory(a_session(now=FIXED_INSTANT, remaining=-SECOND)),
            True,
            id="past its expiry",
        ),
        pytest.param(
            SESSION_ID,
            SessionRecordsInMemory(
                a_session(now=FIXED_INSTANT, age=CAP + SECOND, remaining=SECOND),
            ),
            True,
            id="past the absolute cap",
        ),
        pytest.param(
            "unknown-session",
            SessionRecordsInMemory(a_session(now=FIXED_INSTANT)),
            True,
            id="an unknown id",
        ),
        pytest.param(
            SESSION_ID,
            SessionsAnsweringTouch(a_session(now=FIXED_INSTANT), False),
            False,
            id="a touch that finds no row",
        ),
    ],
)
def test_a_session_the_store_does_not_admit_is_refused_and_not_renewed(
    session_id: str, sessions: SessionRecordsInMemory, renewal_is_observable: bool,
) -> None:
    stored_expiry = sessions.record.expires_at

    outcome = admit(session_id, sessions)

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert not renewal_is_observable or sessions.record.expires_at == stored_expiry


@pytest.mark.parametrize("answer", [None, 1, "yes"])
def test_a_touch_answering_anything_but_a_bool_raises(answer: object) -> None:
    sessions = SessionsAnsweringTouch(a_session(now=FIXED_INSTANT), answer)

    with pytest.raises(TypeError, match="touch must return a bool"):
        admit(SESSION_ID, sessions)
