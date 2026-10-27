"""`open_session`: the new session, its cap, and the sessions it replaces."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import NoReturn

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    opened_session,
)
from tests.support.oidc_login_host import (
    OTHER_SUBJECT,
    SUBJECT,
    after_signing_in,
    an_oidc_host,
)
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    UsersInMemory,
    WriteLockInMemory,
    a_web_auth_config,
    seeded_session,
    signed_without_bound,
)
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    sign_session_id,
)
from webauth.oidc_login import (
    AdmittedLogin,
)
from webauth.ports import (
    SessionRecord,
)

ACCOUNT = FakeUser(id=SUBJECT, username="lena")
BYSTANDER = FakeUser(id=OTHER_SUBJECT, username="omar")
FIRST_EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)
FIRST_CREATED_AT = FIXED_INSTANT - timedelta(hours=1)
IDLE = timedelta(seconds=SESSION_IDLE_SECONDS)
OPENING_CONFIG = a_web_auth_config(wall_clock=FIXED_WALL_CLOCK)


class StoreDown(Exception):
    pass


@dataclass
class OpeningStore:
    """Sessions of ``ACCOUNT`` and ``BYSTANDER`` the way a host's store holds them."""

    sessions: SessionRecordsInMemory
    lock: WriteLockInMemory

    @classmethod
    def holding_session_named(cls, session_id: str) -> OpeningStore:
        lock = WriteLockInMemory()
        record = FakeSessionRecord(
            id=session_id, user=ACCOUNT, created_at=FIRST_EXPIRY, expires_at=FIRST_EXPIRY,
        )
        users = UsersInMemory(ACCOUNT, BYSTANDER, lock=lock)
        return cls(SessionRecordsInMemory(record, users=users, lock=lock), lock)

    @classmethod
    def holding(cls, *owners: FakeUser) -> OpeningStore:
        """One session per owner, each created a minute after the one before."""
        lock = WriteLockInMemory()
        users = UsersInMemory(ACCOUNT, BYSTANDER, lock=lock)
        sessions = SessionRecordsInMemory(users=users, lock=lock)
        store = cls(sessions, lock)
        for minute, owner in enumerate(owners):
            store.create_for(owner, FIRST_CREATED_AT + timedelta(minutes=minute))
        return store

    def create_for(self, owner: FakeUser, now: datetime) -> str:
        return seeded_session(self.sessions, self.lock.hold(), owner.id, now, now + IDLE).id

    def ids(self) -> list[str]:
        return [record.id for record in self.sessions.list_active()]

    def open_session(
        self, *cookie_values: str, max_sessions: int | None = None,
        refresh_token: SecretStr | None = None,
        id_token: SecretStr | None = None,
    ) -> SessionRecord:
        return opened_session(
            OPENING_CONFIG,
            AdmittedLogin(
                account=ACCOUNT, return_to=None, refresh_token=refresh_token,
                id_token=id_token or SecretStr("id-token-of-the-login"),
            ),
            *cookie_values, sessions=self.sessions, lock=self.lock, max_sessions=max_sessions,
        )


def signed(session_id: str) -> str:
    return sign_session_id(session_id, OPENING_CONFIG.signing_key)


def test_a_new_session_holds_the_refresh_token_and_id_token_of_the_admitted_login() -> None:
    store = OpeningStore.holding()

    session = store.open_session(refresh_token=SecretStr("rt-1"), id_token=SecretStr("id-1"))

    assert (session.refresh_token, session.id_token) == (SecretStr("rt-1"), SecretStr("id-1"))
    assert store.sessions.load(session.id) == session


def test_a_new_session_has_a_fresh_id() -> None:
    store = OpeningStore.holding(ACCOUNT)
    [replaced] = store.ids()

    session = store.open_session(signed(replaced))

    assert session.id != replaced
    assert store.ids() == [session.id]
    assert (session.user.id, session.created_at, session.expires_at) == (
        ACCOUNT.id, FIXED_INSTANT, FIXED_INSTANT + IDLE,
    )


@pytest.mark.parametrize(("cookie_values_of", "ended"), [
    pytest.param(lambda ids: [signed(ids[0])], [0], id="verified-same-account"),
    pytest.param(lambda ids: [signed(ids[1])], [1], id="verified-other-account"),
    pytest.param(lambda ids: [f"{ids[0]}.{'0' * 64}"], [], id="forged"),
    pytest.param(lambda ids: [ids[0]], [], id="unsigned"),
    pytest.param(lambda ids: [signed(ids[0]), signed(ids[0])], [], id="duplicated"),
])
def test_only_the_session_a_verified_cookie_names_is_ended_whoever_it_belongs_to(
    cookie_values_of: Callable[[list[str]], list[str]], ended: list[int],
) -> None:
    store = OpeningStore.holding(ACCOUNT, BYSTANDER)
    before = store.ids()

    session = store.open_session(*cookie_values_of(before))

    assert store.ids() == [
        *(session_id for index, session_id in enumerate(before) if index not in ended),
        session.id,
    ]


@pytest.mark.parametrize(("cookie_chars", "ended"), [
    pytest.param(MAX_SESSION_COOKIE_CHARS, True, id="at-the-bound"),
    pytest.param(MAX_SESSION_COOKIE_CHARS + 1, False, id="above-the-bound"),
])
def test_a_signed_cookie_longer_than_the_bound_ends_nothing_though_the_store_holds_its_session(
    cookie_chars: int, ended: bool,
) -> None:
    signature_chars = len(signed("x")) - 1
    long_id = "x" * (cookie_chars - signature_chars)
    store = OpeningStore.holding_session_named(long_id)
    cookie = signed_without_bound(long_id, OPENING_CONFIG.signing_key)
    assert len(cookie) == cookie_chars

    session = store.open_session(cookie)

    assert store.ids() == ([] if ended else [long_id]) + [session.id]


@pytest.mark.parametrize(("existing", "cookie", "max_sessions", "surviving"), [
    pytest.param(2, 1, 2, [0], id="the-replaced-session-never-counts-against-the-cap"),
    pytest.param(3, None, 2, [2], id="the-oldest-above-the-cap-are-ended"),
    pytest.param(2, None, 1, [], id="a-cap-of-one-keeps-only-the-new-session"),
    pytest.param(1, None, 3, [0], id="a-session-below-the-cap-is-kept"),
    pytest.param(3, None, None, [0, 1, 2], id="no-cap-prunes-nothing"),
])
def test_the_account_holds_at_most_its_cap_afterwards_with_the_oldest_ended(
    existing: int, cookie: int | None, max_sessions: int | None, surviving: list[int],
) -> None:
    store = OpeningStore.holding(*[ACCOUNT] * existing)
    bystander = store.create_for(BYSTANDER, FIRST_CREATED_AT)
    before = store.ids()
    cookie_values = [] if cookie is None else [signed(before[cookie])]

    session = store.open_session(*cookie_values, max_sessions=max_sessions)

    assert sorted(store.ids()) == sorted(
        [*(before[index] for index in surviving), bystander, session.id],
    )


@pytest.mark.parametrize("max_sessions", [
    pytest.param(0, id="zero"),
    pytest.param(-1, id="negative"),
    pytest.param(True, id="bool"),
    pytest.param("2", id="text"),
    pytest.param(2.0, id="float"),
])
def test_a_cap_that_is_not_a_positive_whole_number_is_refused_before_anything_is_written(
    max_sessions: object,
) -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()
    cookie = signed(before[0])

    with pytest.raises(ValueError, match="max_sessions"):
        store.open_session(
            cookie,
            max_sessions=max_sessions,  # pyright: ignore[reportArgumentType] -- not an int on purpose
        )

    assert store.ids() == before


def test_a_failed_host_commit_after_open_session_keeps_the_replaced_session_only() -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()
    store.sessions.commit_failure = StoreDown()
    cookie = signed(before[0])

    with pytest.raises(StoreDown), store.sessions.transaction():
        store.open_session(cookie)

    assert store.ids() == before


def test_a_create_that_raises_after_the_delete_leaves_the_replaced_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = OpeningStore.holding(ACCOUNT)
    before = store.ids()

    def store_down(*_: object, **__: object) -> NoReturn:
        raise StoreDown

    monkeypatch.setattr(store.sessions, "create", store_down)
    cookie = signed(before[0])

    with pytest.raises(StoreDown), store.sessions.transaction():
        store.open_session(cookie)

    assert store.ids() == before


def test_two_same_tick_logins_at_a_cap_of_one_both_succeed_and_the_later_remains() -> None:
    store = OpeningStore.holding()

    first = store.open_session(max_sessions=1)
    second = store.open_session(max_sessions=1)

    assert first.created_at == second.created_at
    assert store.ids() == [second.id]


def test_a_second_login_in_the_same_browser_replaces_the_first_session() -> None:
    host = after_signing_in(an_oidc_host())
    [first] = [record.id for record in host.sessions.list_active()]

    host.callback(host.sign_in_at_issuer())

    assert [record.id for record in host.sessions.list_active()] != [first]
    assert host.sessions.count_active() == 1


def test_a_failed_commit_after_the_login_issues_no_cookie_and_keeps_the_replaced_session() -> None:
    host = after_signing_in(an_oidc_host())
    before = [record.id for record in host.sessions.list_active()]
    cookie_before = host.client.cookies[host.config.session_cookie_name]
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()

    with pytest.raises(StoreDown):
        host.callback(query)

    assert [record.id for record in host.sessions.list_active()] == before
    assert host.client.cookies[host.config.session_cookie_name] == cookie_before
