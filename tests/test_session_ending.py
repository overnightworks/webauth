"""Ending a session removes it from the host's store, which decides every request."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    UsersInMemory,
    an_auth_app,
)

from webauth.session_ending import end_session, end_user_sessions, prune_sessions

SUBJECT = FakeUser(id="subject", username="member")
BYSTANDER = FakeUser(id="bystander", username="neighbour")
SessionEnding = Callable[[SessionRecordsInMemory, list[FakeSessionRecord]], object]


def a_store_of(*owners: FakeUser) -> tuple[SessionRecordsInMemory, list[FakeSessionRecord]]:
    """One stored session per owner, each opened a minute after the one before."""
    sessions = SessionRecordsInMemory(users=UsersInMemory(SUBJECT, BYSTANDER))
    first_expiry = datetime(2030, 1, 1, tzinfo=timezone.utc)
    records = [
        sessions.create(
            owner.id, first_expiry + timedelta(minutes=minute),
            ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
        )
        for minute, owner in enumerate(owners)
    ]
    return sessions, records


def end_the_first_session(
    sessions: SessionRecordsInMemory, records: list[FakeSessionRecord],
) -> None:
    end_session(sessions, session_id=records[0].id)


def end_every_subject_session(sessions: SessionRecordsInMemory, _: list[FakeSessionRecord]) -> None:
    end_user_sessions(sessions, SUBJECT.id)


def prune_to_the_newest_subject_session(
    sessions: SessionRecordsInMemory, _: list[FakeSessionRecord],
) -> None:
    prune_sessions(sessions, SUBJECT.id, 1)


@pytest.mark.parametrize(("ending", "ended"), [
    pytest.param(end_the_first_session, {0}, id="end_session"),
    pytest.param(end_every_subject_session, {0, 1, 3}, id="end_user_sessions"),
    pytest.param(prune_to_the_newest_subject_session, {0, 1}, id="prune_sessions"),
])
def test_an_ended_sessions_cookie_is_refused_on_the_next_request_and_a_retained_ones_still_works(
    ending: SessionEnding, ended: set[int],
) -> None:
    sessions, records = a_store_of(SUBJECT, SUBJECT, BYSTANDER, SUBJECT)
    app = an_auth_app(None, sessions=sessions)
    ending(sessions, records)

    statuses = [
        app.get("/me", cookie=app.signed_cookie(record.id)).status_code for record in records
    ]

    assert statuses == [401 if index in ended else 200 for index in range(len(records))]


@pytest.mark.parametrize(("max_sessions", "pruned_positions"), [
    pytest.param(1, {0, 2}, id="above_the_cap"),
    pytest.param(3, set(), id="at_the_cap"),
    pytest.param(4, set(), id="below_the_cap"),
])
def test_pruning_ends_only_the_subjects_oldest_sessions_above_the_cap(
    max_sessions: int, pruned_positions: set[int],
) -> None:
    sessions, records = a_store_of(SUBJECT, BYSTANDER, SUBJECT, SUBJECT)
    survivors = [
        record for position, record in enumerate(records) if position not in pruned_positions
    ]

    pruned = prune_sessions(sessions, SUBJECT.id, max_sessions)

    assert sorted(pruned) == sorted(records[position].id for position in pruned_positions)
    assert sessions.list_active() == survivors


def test_ending_an_accounts_sessions_reports_the_stores_count_and_spares_other_accounts() -> None:
    sessions, records = a_store_of(SUBJECT, BYSTANDER, SUBJECT)

    session_count = end_user_sessions(sessions, SUBJECT.id)

    assert session_count == 2
    assert sessions.list_active() == [records[1]]


def test_ending_one_session_spares_the_accounts_other_sessions() -> None:
    sessions, records = a_store_of(SUBJECT, SUBJECT)

    end_session(sessions, session_id=records[0].id)

    assert sessions.list_active() == [records[1]]
