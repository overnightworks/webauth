"""``SessionGroups``: a signed-in person's groups, fresh at each call, for an async host."""

from __future__ import annotations

import anyio
import pytest
from pydantic import SecretStr

from tests.support.current_groups_arrangement import (
    GROUPS,
    SESSION_ENDED,
    SESSION_ID,
    SIGN_IN_AGAIN,
    Arrangement,
    a_websocket_connection,
    an_arrangement,
)
from tests.support.oidc_arrangement import ISSUED_REFRESH_TOKEN, GrantHeldUntilReleased
from webauth.oidc_login import AccessTokenRefusal

DEADLINE_SECONDS = 10


async def _groups_of_the_session(arrangement: Arrangement) -> object:
    return await arrangement.session_groups().of_session(SESSION_ID)


async def _groups_of_the_connection(arrangement: Arrangement) -> object:
    return await arrangement.session_groups().of_connection(arrangement.connection_of_the_session())


READERS = pytest.mark.parametrize(
    "read",
    [
        pytest.param(_groups_of_the_session, id="session"),
        pytest.param(_groups_of_the_connection, id="connection"),
    ],
)


@READERS
def test_a_members_session_answers_its_groups_as_a_frozenset(read) -> None:
    """GROUPS-28: the groups of a session, or of the session a connection carries."""
    arrangement = an_arrangement()

    groups = anyio.run(read, arrangement)

    assert groups == frozenset(GROUPS)
    assert isinstance(groups, frozenset)


def test_a_connection_without_a_session_cookie_answers_sign_in_again_and_makes_no_grant() -> None:
    """GROUPS-29: a connection without a session answers `SIGN_IN_AGAIN` and makes no grant."""
    arrangement = an_arrangement()
    connection = a_websocket_connection([])

    refusal = anyio.run(arrangement.session_groups().of_connection, connection)

    assert refusal == SIGN_IN_AGAIN
    assert arrangement.requests_made == 0


def test_each_call_is_its_own_grant() -> None:
    """The reader holds no answer: one instance asked twice for a session makes two grants."""
    arrangement = an_arrangement()
    session_groups = arrangement.session_groups()

    async def ask_twice() -> None:
        await session_groups.of_session(SESSION_ID)
        requests_after_the_first = arrangement.requests_made
        await session_groups.of_session(SESSION_ID)
        assert arrangement.requests_made == 2 * requests_after_the_first

    anyio.run(ask_twice)

    assert arrangement.requests_made > 0


def test_a_session_whose_refresh_token_was_already_used_still_reads_its_groups() -> None:
    """GROUPS-26, GROUPS-28: where the issuer lets a refresh token be used again, a session
    holding the token an earlier call spent still reads its groups."""
    arrangement = an_arrangement()
    anyio.run(_groups_of_the_session, arrangement)
    assert arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN
    arrangement.sessions.replace_refresh_token(
        SESSION_ID, refresh_token=SecretStr(ISSUED_REFRESH_TOKEN)
    )

    groups = anyio.run(_groups_of_the_session, arrangement)

    assert groups == frozenset(GROUPS)


@pytest.mark.parametrize(
    ("refresh_token", "ended", "refusal"),
    [
        pytest.param(None, False, SIGN_IN_AGAIN, id="no-refresh-token"),
        pytest.param(ISSUED_REFRESH_TOKEN, True, SESSION_ENDED, id="ended"),
    ],
)
def test_a_refusal_of_current_groups_comes_back_unchanged(
    refresh_token: str | None,
    ended: bool,
    refusal: AccessTokenRefusal,
) -> None:
    """GROUPS-06, GROUPS-07, GROUPS-28: the refusal of `current_groups` is the answer."""
    arrangement = an_arrangement(refresh_token=refresh_token)
    if ended:
        arrangement.sessions.delete(SESSION_ID)

    answer = anyio.run(_groups_of_the_session, arrangement)

    assert answer == refusal


def test_a_cancelled_callers_grant_still_stores_its_rotated_refresh_token() -> None:
    """GROUPS-30: cancelling the caller does not stop the grant, and the caller gets no answer."""
    arrangement = an_arrangement()
    held = GrantHeldUntilReleased(DEADLINE_SECONDS)
    arrangement.issuer.before_exchange = held
    answers: list[object] = []

    async def drive() -> None:
        async def ask() -> None:
            answers.append(await arrangement.session_groups().of_session(SESSION_ID))

        with anyio.fail_after(DEADLINE_SECONDS):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(ask)
                try:
                    await anyio.to_thread.run_sync(held.wait_until_reached)
                    tasks.cancel_scope.cancel()
                finally:
                    held.release()
        assert arrangement.stored_refresh_token not in {None, ISSUED_REFRESH_TOKEN}

    anyio.run(drive)

    assert answers == []
