"""Ending a session removes it from the host's store and from the cache alike."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import pytest
from webauth_arrangement import (
    CLIENT_ADDRESS,
    CLIENT_USER_AGENT,
    SESSION_ID,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    UsersInMemory,
    a_session,
    a_session_cache,
    a_session_cache_failing_on,
    an_auth_app,
    cache_session,
)

from webauth.session_ending import end_session, end_user_sessions, prune_sessions
from webauth.session_store import RedisSessionCache

SUBJECT = FakeUser(id="subject", username="member")
BYSTANDER = FakeUser(id="bystander", username="neighbour")
SessionEnding = Callable[
    [SessionRecordsInMemory, RedisSessionCache, list[FakeSessionRecord]], object,
]


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


def a_cache_holding(records: list[FakeSessionRecord]) -> RedisSessionCache:
    cache = a_session_cache()
    for record in records:
        cache_session(cache, record)
    return cache


@pytest.mark.parametrize("with_cache", [True, False])
def test_a_session_ended_on_logout_is_refused_even_where_the_cache_admitted_it(
    with_cache: bool,
) -> None:
    record = a_session()
    cache = a_session_cache() if with_cache else None
    if cache is not None:
        cache_session(cache, record)
    app = an_auth_app(record, cache)
    other_device = app.sessions.create(
        record.user_id, record.expires_at,
        ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
    )
    if cache is not None:
        cache_session(cache, other_device)
    assert app.get("/me", cookie=app.signed_cookie()).status_code == 200

    end_session(app.sessions, cache, session_id=SESSION_ID, user_id=record.user_id)

    assert app.get("/me", cookie=app.signed_cookie()).status_code == 401
    assert app.sessions.load(SESSION_ID) is None
    assert app.sessions.load(other_device.id) is not None
    if cache is not None:
        assert cache.get(SESSION_ID) is None
        assert cache.get(other_device.id) is not None


def end_the_first_session(
    sessions: SessionRecordsInMemory, cache: RedisSessionCache, records: list[FakeSessionRecord],
) -> None:
    end_session(sessions, cache, session_id=records[0].id, user_id=SUBJECT.id)


def end_every_subject_session(
    sessions: SessionRecordsInMemory, cache: RedisSessionCache, _: list[FakeSessionRecord],
) -> None:
    end_user_sessions(sessions, cache, SUBJECT.id)


def prune_to_the_newest_subject_session(
    sessions: SessionRecordsInMemory, cache: RedisSessionCache, _: list[FakeSessionRecord],
) -> None:
    prune_sessions(sessions, cache, SUBJECT.id, 1)


@pytest.mark.parametrize(("ending", "failing_command", "ended"), [
    pytest.param(end_the_first_session, "pipeline", [0], id="end_session"),
    pytest.param(end_every_subject_session, "smembers", [0, 1], id="end_user_sessions"),
    pytest.param(prune_to_the_newest_subject_session, "pipeline", [0], id="prune_sessions"),
])
def test_a_cache_that_fails_to_delete_raises_after_the_store_has_ended_the_session(
    ending: SessionEnding, failing_command: str, ended: list[int],
) -> None:
    sessions, records = a_store_of(SUBJECT, SUBJECT)

    cache = a_session_cache_failing_on(failing_command)
    with pytest.raises(ConnectionError):
        ending(sessions, cache, records)

    for index in ended:
        assert sessions.load(records[index].id) is None


@pytest.mark.parametrize("with_cache", [True, False])
@pytest.mark.parametrize(("max_sessions", "pruned_positions"), [
    pytest.param(1, {0, 2}, id="above_the_cap"),
    pytest.param(3, set(), id="at_the_cap"),
    pytest.param(4, set(), id="below_the_cap"),
])
def test_pruning_ends_only_the_subjects_oldest_sessions_above_the_cap(
    with_cache: bool, max_sessions: int, pruned_positions: set[int],
) -> None:
    sessions, records = a_store_of(SUBJECT, BYSTANDER, SUBJECT, SUBJECT)
    cache = a_cache_holding(records) if with_cache else None
    survives = [position not in pruned_positions for position in range(len(records))]

    pruned = prune_sessions(sessions, cache, SUBJECT.id, max_sessions)

    assert sorted(pruned) == sorted(records[position].id for position in pruned_positions)
    assert sessions.list_active() == [
        record for record, kept in zip(records, survives, strict=True) if kept
    ]
    if cache is not None:
        assert [cache.get(record.id) is not None for record in records] == survives


def test_ending_an_accounts_sessions_reports_the_stores_count_and_spares_other_accounts() -> None:
    sessions, records = a_store_of(SUBJECT, BYSTANDER, SUBJECT)
    cache = a_cache_holding(records)

    session_count = end_user_sessions(sessions, cache, SUBJECT.id)

    assert session_count == 2
    assert sessions.list_active() == [records[1]]
    assert [cache.get(record.id) is not None for record in records] == [False, True, False]
