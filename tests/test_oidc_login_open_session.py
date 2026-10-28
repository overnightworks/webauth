"""The session a callback opens: its tokens, its cap, and the sessions it replaces."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from httpx import Response as HttpxResponse
from pydantic import SecretStr

from tests.support.oidc_arrangement import ISSUED_REFRESH_TOKEN
from tests.support.oidc_login_host import (
    OTHER_SUBJECT,
    SUBJECT,
    OidcHost,
    TransactionKind,
    after_signing_in,
    an_oidc_host,
    set_cookies,
)
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    FIXED_WALL_CLOCK,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    seeded_session,
    session_cookie_header,
    signed_without_bound,
)
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    sign_session_id,
)
from webauth.ports import SessionRecord

ACCOUNT = FakeUser(id=SUBJECT, username="lena")
BYSTANDER = FakeUser(id=OTHER_SUBJECT, username="omar")
FIRST_EXPIRY = datetime(2030, 1, 1, tzinfo=UTC)
FIRST_CREATED_AT = FIXED_INSTANT - timedelta(hours=1)
IDLE = timedelta(seconds=SESSION_IDLE_SECONDS)


class StoreDown(Exception):
    pass


class OpeningHost:
    """A host holding sessions of ``ACCOUNT`` and ``BYSTANDER``, which ``ACCOUNT`` signs in to."""

    def __init__(
        self, *, max_sessions: int | None = None,
        transaction_kind: TransactionKind = TransactionKind.PER_CALL,
        stored_session: FakeSessionRecord | None = None,
    ) -> None:
        self.host: OidcHost = an_oidc_host(
            ACCOUNT, BYSTANDER, wall_clock=FIXED_WALL_CLOCK, max_sessions=max_sessions,
            transaction_kind=transaction_kind, stored_session=stored_session,
        )

    @classmethod
    def holding_session_named(cls, session_id: str) -> OpeningHost:
        return cls(stored_session=FakeSessionRecord(
            id=session_id, user=ACCOUNT, created_at=FIRST_EXPIRY, expires_at=FIRST_EXPIRY,
        ))

    @classmethod
    def holding(
        cls, *owners: FakeUser, max_sessions: int | None = None,
        transaction_kind: TransactionKind = TransactionKind.PER_CALL,
    ) -> OpeningHost:
        """One session per owner, each created a minute after the one before."""
        opening = cls(max_sessions=max_sessions, transaction_kind=transaction_kind)
        for minute, owner in enumerate(owners):
            opening.create_for(owner, FIRST_CREATED_AT + timedelta(minutes=minute))
        return opening

    def create_for(self, owner: FakeUser, now: datetime) -> str:
        return seeded_session(
            self.host.sessions, self.host.lock.hold_uncounted(), owner.id, now, now + IDLE,
        ).id

    def ids(self) -> list[str]:
        return [record.id for record in self.host.sessions.list_active()]

    def sign_in(self, *cookie_values: str) -> HttpxResponse:
        """``ACCOUNT`` signs in through the callback, the browser carrying the session cookies."""
        query = self.host.sign_in_at_issuer()
        cookies = [self.host.pending_cookie(query)]
        if cookie_values:
            cookies.append(session_cookie_header(*cookie_values))
        return self.host.callback(query, cookie="; ".join(cookies))

    def open_session(self, *cookie_values: str) -> SessionRecord:
        before = set(self.ids())
        assert self.sign_in(*cookie_values).status_code == 303
        [opened] = [
            record for record in self.host.sessions.list_active() if record.id not in before
        ]
        return opened

    def signed(self, session_id: str) -> str:
        return sign_session_id(session_id, self.host.config.signing_key)


def test_a_new_session_holds_the_refresh_token_and_id_token_of_the_admitted_login() -> None:
    store = OpeningHost.holding()

    session = store.open_session()

    assert (session.refresh_token, session.id_token) == (
        SecretStr(ISSUED_REFRESH_TOKEN), SecretStr(store.host.issued_id_tokens[-1]),
    )
    assert store.host.sessions.load(session.id) == session


def test_a_new_session_has_a_fresh_id() -> None:
    store = OpeningHost.holding(ACCOUNT)
    [replaced] = store.ids()

    session = store.open_session(store.signed(replaced))

    assert session.id != replaced
    assert store.ids() == [session.id]
    assert (session.user.id, session.created_at, session.expires_at) == (
        ACCOUNT.id, FIXED_INSTANT, FIXED_INSTANT + IDLE,
    )


@pytest.mark.parametrize(("cookie_values_of", "ended"), [
    pytest.param(lambda store, ids: [store.signed(ids[0])], [0], id="verified-same-account"),
    pytest.param(lambda store, ids: [store.signed(ids[1])], [1], id="verified-other-account"),
    pytest.param(lambda _store, ids: [f"{ids[0]}.{'0' * 64}"], [], id="forged"),
    pytest.param(lambda _store, ids: [ids[0]], [], id="unsigned"),
    pytest.param(
        lambda store, ids: [store.signed(ids[0]), store.signed(ids[0])], [], id="duplicated",
    ),
])
def test_only_the_session_a_verified_cookie_names_is_ended_whoever_it_belongs_to(
    cookie_values_of: Callable[[OpeningHost, list[str]], list[str]], ended: list[int],
) -> None:
    store = OpeningHost.holding(ACCOUNT, BYSTANDER)
    before = store.ids()

    session = store.open_session(*cookie_values_of(store, before))

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
    signature_chars = len(sign_session_id("x", OpeningHost().host.config.signing_key)) - 1
    long_id = "x" * (cookie_chars - signature_chars)
    store = OpeningHost.holding_session_named(long_id)
    cookie = signed_without_bound(long_id, store.host.config.signing_key)
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
    store = OpeningHost.holding(*[ACCOUNT] * existing, max_sessions=max_sessions)
    bystander = store.create_for(BYSTANDER, FIRST_CREATED_AT)
    before = store.ids()
    cookie_values = [] if cookie is None else [store.signed(before[cookie])]

    session = store.open_session(*cookie_values)

    assert sorted(store.ids()) == sorted(
        [*(before[index] for index in surviving), bystander, session.id],
    )


def test_two_same_tick_logins_at_a_cap_of_one_both_succeed_and_the_later_remains() -> None:
    store = OpeningHost.holding(max_sessions=1)

    first = store.open_session()
    second = store.open_session()

    assert first.created_at == second.created_at
    assert store.ids() == [second.id]


def test_a_second_login_in_the_same_browser_replaces_the_first_session() -> None:
    host = after_signing_in(an_oidc_host())
    [first] = [record.id for record in host.sessions.list_active()]

    host.callback(host.sign_in_at_issuer())

    assert [record.id for record in host.sessions.list_active()] != [first]
    assert host.sessions.count_active() == 1


def test_a_failed_commit_after_the_login_issues_no_cookie_and_keeps_the_replaced_session() -> None:
    host = after_signing_in(an_oidc_host(transaction_kind=TransactionKind.ROLLING_BACK))
    before = [record.id for record in host.sessions.list_active()]
    cookie_before = host.client.cookies[host.config.session_cookie_name]
    host.sessions.commit_failure = StoreDown()
    query = host.sign_in_at_issuer()

    response = host.callback(query)

    assert response.status_code == 500
    assert host.config.session_cookie_name not in set_cookies(response)
    assert [record.id for record in host.sessions.list_active()] == before
    assert host.client.cookies[host.config.session_cookie_name] == cookie_before
