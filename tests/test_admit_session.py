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
    FakeSessionRecord,
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
    assert record.expires_at == min(FIXED_INSTANT + IDLE, record.created_at + CAP)


def test_a_renewal_stops_at_the_absolute_cap() -> None:
    record = a_session(now=FIXED_INSTANT, age=CAP - 500 * SECOND, remaining=100 * SECOND)

    admit(record.id, SessionRecordsInMemory(record))

    assert record.expires_at == FIXED_INSTANT + 500 * SECOND


@pytest.mark.parametrize(
    "record",
    [
        pytest.param(
            a_session(now=FIXED_INSTANT, remaining=-SECOND), id="past its expiry",
        ),
        pytest.param(
            a_session(now=FIXED_INSTANT, age=CAP + SECOND, remaining=SECOND),
            id="past the absolute cap",
        ),
    ],
)
def test_a_session_outside_its_lifetime_is_refused_and_not_renewed(
    record: FakeSessionRecord,
) -> None:
    stored_expiry = record.expires_at

    outcome = admit(record.id, SessionRecordsInMemory(record))

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert record.expires_at == stored_expiry


def test_an_unknown_session_id_is_refused_and_no_session_is_renewed() -> None:
    record = a_session(now=FIXED_INSTANT)
    stored_expiry = record.expires_at

    outcome = admit("unknown-session", SessionRecordsInMemory(record))

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert record.expires_at == stored_expiry


def test_a_touch_finding_no_row_refuses_an_otherwise_admitted_session() -> None:
    record = a_session(now=FIXED_INSTANT)
    stored_expiry = record.expires_at

    outcome = admit(SESSION_ID, SessionsAnsweringTouch(record, False))

    assert outcome is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert record.expires_at == stored_expiry


@pytest.mark.parametrize("answer", [None, 1, "yes"])
def test_a_touch_answering_anything_but_a_bool_raises(answer: object) -> None:
    record = a_session(now=FIXED_INSTANT)

    with pytest.raises(TypeError, match="touch must return a bool"):
        admit(SESSION_ID, SessionsAnsweringTouch(record, answer))
