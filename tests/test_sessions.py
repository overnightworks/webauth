"""The session a host opens after its own proof, and its sign-out: `open_session`, `end_session`.

Each test names the OWNPROOF rule of `docs/host-contract.md` it proves. The host is built without
OpenID Connect and its stand-in proof routes call the two functions with the response they return.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from tests.support.account_arrangement import FakeUser
from tests.support.oidc_login_host import NOW, SUBJECT, StoreDown, is_cleared, set_cookies
from tests.support.request_line_arrangement import request_lines_written
from tests.support.web_auth_host_arrangement import (
    A_MEMBER,
    ME_PATH,
    PROOF_SIGN_IN_PATH,
    PROOF_SIGN_OUT_PATH,
    ComposedHost,
    HostWorld,
    a_client_of,
    a_composed_host,
    a_composition,
    a_host_that_proves_its_own,
    a_host_world,
    a_stored_session,
    the_routes_of_a_host_that_proves_its_own,
)
from tests.support.webauth_arrangement import (
    SAME_ORIGIN_REQUEST,
    SESSION_COOKIE_NAME,
    SESSION_ID,
    SESSION_IDLE_SECONDS,
    session_cookie_header,
    signed_without_bound,
)
from webauth.cookies import MAX_SESSION_COOKIE_CHARS, sign_session_id
from webauth.ports import StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Callable

    from httpx import Response as HttpxResponse

A_BYSTANDER = FakeUser(id="a-subject-of-a-bystander", username="bo")
THE_CAP = 2


def _world_with_a_stored_session(owner: FakeUser) -> HostWorld:
    return a_host_world(A_MEMBER, A_BYSTANDER, stored_session=a_stored_session(owner))


def _proof_headers(cookie: str | None = None) -> dict[str, str]:
    return SAME_ORIGIN_REQUEST if cookie is None else {**SAME_ORIGIN_REQUEST, "cookie": cookie}


def _sign_in(host: ComposedHost, *, cookie: str | None = None) -> HttpxResponse:
    return host.client.post(PROOF_SIGN_IN_PATH, headers=_proof_headers(cookie))


def _sign_out(host: ComposedHost, *, cookie: str | None = None) -> HttpxResponse:
    return host.client.post(PROOF_SIGN_OUT_PATH, headers=_proof_headers(cookie))


def _the_valid_cookie(world: HostWorld) -> str:
    return world.signed_cookie()["cookie"]


def _a_forged_cookie(world: HostWorld) -> str:
    return session_cookie_header(sign_session_id(SESSION_ID, b"another-secret-" * 4))


def _a_duplicated_cookie(world: HostWorld) -> str:
    signed = sign_session_id(SESSION_ID, world.config.signing_key)
    return session_cookie_header(signed, signed)


def _an_oversized_cookie(world: HostWorld) -> str:
    return session_cookie_header(
        signed_without_bound(SESSION_ID + "x" * MAX_SESSION_COOKIE_CHARS, world.config.signing_key)
    )


COOKIES_THAT_NAME_NO_SESSION = [
    pytest.param(_a_forged_cookie, id="a-forged-cookie"),
    pytest.param(_a_duplicated_cookie, id="a-duplicated-cookie"),
    pytest.param(_an_oversized_cookie, id="an-oversized-cookie"),
]

FAILURES_OF_THE_ENTRY_OR_ITS_EXIT = [
    pytest.param("entry_failure", StoreDown(), 500, id="a-failing-entry"),
    pytest.param("exit_failure", StoreDown(), 500, id="a-failing-exit"),
    pytest.param("entry_failure", StoreUnavailableError(), 503, id="an-unreachable-store-at-entry"),
    pytest.param("exit_failure", StoreUnavailableError(), 503, id="an-unreachable-store-at-exit"),
]


def test_ownproof_01_a_proven_account_gets_a_fresh_session_its_cookie_names_in_one_clock_reading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """OWNPROOF-01"""
    world = a_host_world(A_MEMBER)
    world.wall_clock.step = 1.0
    host = a_host_that_proves_its_own(world)

    with request_lines_written(capsys) as lines:
        response = _sign_in(host)

    (opened_id,) = world.session_ids
    record = world.sessions.stored_record
    opened_at = datetime.fromtimestamp(NOW, UTC)
    assert response.status_code == 204
    assert record.id == opened_id
    assert (record.created_at, (record.expires_at - record.created_at).total_seconds()) == (
        opened_at,
        SESSION_IDLE_SECONDS,
    )
    assert (record.refresh_token, record.id_token, record.account_language) == (None, None, None)
    assert world.wall_clock.now == NOW + 1
    assert "no-store" in response.headers["cache-control"]
    assert host.client.get(ME_PATH).json() == {"username": A_MEMBER.username}
    assert lines[-1]["sub"] == SUBJECT


def test_ownproof_01_each_proof_opens_a_session_under_a_new_id() -> None:
    """OWNPROOF-01"""
    world = a_host_world(A_MEMBER)
    host = a_host_that_proves_its_own(world)

    _sign_in(host)
    host.client.cookies.clear()
    _sign_in(host)

    first, second = world.session_ids
    assert first != second


@pytest.mark.parametrize("owner", [A_MEMBER, A_BYSTANDER], ids=["of-the-account", "of-another"])
def test_ownproof_02_the_session_the_cookie_names_is_ended_whoever_it_belongs_to(
    owner: FakeUser,
) -> None:
    """OWNPROOF-02"""
    world = _world_with_a_stored_session(owner)
    host = a_host_that_proves_its_own(world)

    _sign_in(host, cookie=_the_valid_cookie(world))

    (opened_id,) = world.session_ids
    assert [record.id for record in world.sessions.list_active()] == [opened_id]
    assert world.sessions.stored_record.user is A_MEMBER


@pytest.mark.parametrize("cookie_of", COOKIES_THAT_NAME_NO_SESSION)
def test_ownproof_02_a_cookie_that_names_no_session_ends_none(
    cookie_of: Callable[[HostWorld], str],
) -> None:
    """OWNPROOF-02"""
    world = _world_with_a_stored_session(A_MEMBER)
    host = a_host_that_proves_its_own(world)

    _sign_in(host, cookie=cookie_of(world))

    (opened_id,) = world.session_ids
    assert {record.id for record in world.sessions.list_active()} == {SESSION_ID, opened_id}


def test_ownproof_03_under_a_cap_the_accounts_newest_sessions_stay_and_the_new_one_counts() -> None:
    """OWNPROOF-03"""
    world = a_host_world(A_MEMBER)
    settings = replace(a_composition(world).settings, max_sessions=THE_CAP)
    host = a_host_that_proves_its_own(world, settings=settings)
    for _ in range(THE_CAP + 1):
        host.client.cookies.clear()
        _sign_in(host)
        world.wall_clock.now += 10

    stored = {record.id for record in world.sessions.list_active()}
    assert stored == set(world.session_ids[-THE_CAP:])


@pytest.mark.parametrize(("failing", "failure", "status"), FAILURES_OF_THE_ENTRY_OR_ITS_EXIT)
def test_ownproof_04_a_failure_in_the_entry_or_at_its_exit_sets_no_cookie_and_reaches_the_route(
    failing: str, failure: Exception, status: int
) -> None:
    """OWNPROOF-04"""
    world = a_host_world(A_MEMBER)
    host = a_host_that_proves_its_own(world)
    setattr(world.sign_in, failing, failure)

    response = _sign_in(host)

    assert response.status_code == status
    assert SESSION_COOKIE_NAME not in set_cookies(response)
    assert world.session_ids == []


@pytest.mark.parametrize(("failing", "failure", "_status"), FAILURES_OF_THE_ENTRY_OR_ITS_EXIT)
def test_ownproof_04_the_response_a_host_returns_after_a_failure_carries_no_session_cookie(
    failing: str, failure: Exception, _status: int
) -> None:
    """OWNPROOF-04"""
    world = a_host_world(A_MEMBER)
    caught: list[Exception] = []
    host = a_host_that_proves_its_own(world, caught_failures=caught)
    setattr(world.sign_in, failing, failure)

    response = _sign_in(host)

    assert caught == [failure]
    assert SESSION_COOKIE_NAME not in set_cookies(response)
    assert "cache-control" not in response.headers


def test_ownproof_05_the_sign_out_ends_the_session_clears_the_cookie_and_returns_its_id() -> None:
    """OWNPROOF-05"""
    world = _world_with_a_stored_session(A_MEMBER)
    host = a_host_that_proves_its_own(world)

    response = _sign_out(host, cookie=_the_valid_cookie(world))

    assert response.status_code == 204
    assert world.session_ids == [SESSION_ID]
    assert world.sessions.list_active() == []
    assert world.sign_in.entries == 1
    assert is_cleared(response, SESSION_COOKIE_NAME)
    assert "no-store" in response.headers["cache-control"]


def test_ownproof_06_the_sign_out_returns_the_id_the_cookie_names_when_no_row_stands_under_it() -> (
    None
):
    """OWNPROOF-06"""
    world = a_host_world(A_MEMBER)
    host = a_host_that_proves_its_own(world)

    response = _sign_out(host, cookie=_the_valid_cookie(world))

    assert world.session_ids == [SESSION_ID]
    assert is_cleared(response, SESSION_COOKIE_NAME)


@pytest.mark.parametrize(
    "cookie_of",
    [pytest.param(lambda _world: None, id="no-cookie"), *COOKIES_THAT_NAME_NO_SESSION],
)
def test_ownproof_06_the_sign_out_of_a_cookie_that_names_no_session_returns_none_and_enters_none(
    cookie_of: Callable[[HostWorld], str | None],
) -> None:
    """OWNPROOF-06"""
    world = _world_with_a_stored_session(A_MEMBER)
    host = a_host_that_proves_its_own(world)

    response = _sign_out(host, cookie=cookie_of(world))

    assert world.session_ids == [None]
    assert world.sign_in.entries == 0
    assert [record.id for record in world.sessions.list_active()] == [SESSION_ID]
    assert is_cleared(response, SESSION_COOKIE_NAME)


@pytest.mark.parametrize(("failing", "failure", "status"), FAILURES_OF_THE_ENTRY_OR_ITS_EXIT)
def test_ownproof_07_a_failure_in_the_sign_outs_entry_or_exit_clears_nothing_and_reaches_the_route(
    failing: str, failure: Exception, status: int
) -> None:
    """OWNPROOF-07"""
    world = _world_with_a_stored_session(A_MEMBER)
    host = a_host_that_proves_its_own(world)
    setattr(world.sign_in, failing, failure)

    response = _sign_out(host, cookie=_the_valid_cookie(world))

    assert response.status_code == status
    assert SESSION_COOKIE_NAME not in set_cookies(response)
    assert world.session_ids == []


@pytest.mark.parametrize(("failing", "failure", "_status"), FAILURES_OF_THE_ENTRY_OR_ITS_EXIT)
def test_ownproof_07_the_response_a_host_returns_after_a_failure_clears_no_cookie(
    failing: str, failure: Exception, _status: int
) -> None:
    """OWNPROOF-07"""
    world = _world_with_a_stored_session(A_MEMBER)
    caught: list[Exception] = []
    host = a_host_that_proves_its_own(world, caught_failures=caught)
    setattr(world.sign_in, failing, failure)

    response = _sign_out(host, cookie=_the_valid_cookie(world))

    assert caught == [failure]
    assert SESSION_COOKIE_NAME not in set_cookies(response)
    assert "cache-control" not in response.headers


@pytest.mark.parametrize("path", [PROOF_SIGN_IN_PATH, PROOF_SIGN_OUT_PATH])
def test_ownproof_08_both_functions_are_refused_on_a_handle_with_oidc_before_any_store_call(
    path: str,
) -> None:
    """OWNPROOF-08"""
    world = a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))
    host = a_composed_host(world, routes=the_routes_of_a_host_that_proves_its_own(world))
    client = a_client_of(host.app, raise_server_exceptions=True)

    with pytest.raises(RuntimeError, match="oidc"):
        client.post(path, headers=_proof_headers(_the_valid_cookie(world)))

    assert (world.sign_in.entries, world.sessions.events) == (0, [])
