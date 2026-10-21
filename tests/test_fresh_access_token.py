"""The fresh access token: a person's session turned into a token for one agent call.

Each case drives ``fresh_access_token`` through a real ``OidcRelyingParty`` whose
issuer is ``FakeIssuer``, over both shapes of ``SessionTransaction``: a host
transaction (``in_transaction``) and a store that commits every statement
(``nullcontext``).
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import get_ident
from typing import TYPE_CHECKING, Any

import pytest
from oidc_arrangement import (
    ABSENT,
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    a_fake_id_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from pydantic import SecretStr
from webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    SessionsEndedBeforeReplacingTheRefreshToken,
    SessionsRecordingTheirTransaction,
    a_web_auth_config,
)

from webauth.config import WebAuthConfig
from webauth.oidc import OidcClientConfig, OidcRelyingParty
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    fresh_access_token,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.ports import SessionTransaction

_ISSUER = "https://login.example.org/realms/workshop"
_SESSION_ID = "session-under-test"

_SHAPES = pytest.mark.parametrize(
    "provider_of",
    [
        pytest.param(lambda sessions: sessions.in_transaction, id="transaction"),
        pytest.param(lambda sessions: (lambda: nullcontext(sessions)), id="nullcontext"),
    ],
)


@dataclass
class Arrangement:
    """A live session at ``FIXED_INSTANT`` holding ``rt-1``, and the issuer it renews at."""

    issuer: FakeIssuer
    sessions: SessionRecordsInMemory
    clock: FakeClock
    config: WebAuthConfig
    relying_party: OidcRelyingParty

    def fresh_access_token(
        self, provider: SessionTransaction,
    ) -> SecretStr | AccessTokenRefusal:
        return fresh_access_token(
            self.relying_party,
            _SESSION_ID,
            session_transaction=provider,
            config=self.config,
        )

    @property
    def stored_refresh_token(self) -> str | None:
        record = self.sessions.load(_SESSION_ID)
        if record is None or record.refresh_token is None:
            return None
        return record.refresh_token.get_secret_value()


def an_arrangement(
    sessions_of: Callable[[FakeSessionRecord], SessionRecordsInMemory] = SessionRecordsInMemory,
    *,
    refresh_token: str | None = ISSUED_REFRESH_TOKEN,
    age: timedelta = timedelta(minutes=5),
) -> Arrangement:
    clock = FakeClock(FIXED_INSTANT.timestamp())
    issuer = FakeIssuer(mint_id_token=a_fake_id_token)
    config = a_web_auth_config(wall_clock=clock)
    now = datetime.fromtimestamp(clock.now, UTC)
    record = FakeSessionRecord(
        id=_SESSION_ID,
        user=FakeUser(),
        created_at=now - age,
        expires_at=now + timedelta(seconds=SESSION_IDLE_SECONDS),
        refresh_token=None if refresh_token is None else SecretStr(refresh_token),
    )
    relying_party = OidcRelyingParty(
        OidcClientConfig(
            issuer=_ISSUER,
            authorization_endpoint=f"{_ISSUER}/protocol/openid-connect/auth",
            token_endpoint=f"{_ISSUER}/protocol/openid-connect/token",
            jwks_url=f"{_ISSUER}/protocol/openid-connect/certs",
            end_session_endpoint=f"{_ISSUER}/protocol/openid-connect/logout",
            client_id="notes-app",
            client_secret=SecretStr("client-secret"),
            redirect_uri="https://notes.example.org/auth/callback",
            post_logout_redirect_uri="https://notes.example.org/",
            logout_path="/auth/logout",
            leeway_seconds=30,
        ),
        post_token_request=issuer,
        fetch_key_set=FakeKeySetEndpoint(
            key_set_document(public_jwk(rsa_key("current"), "current-key"))
        ),
        wall_clock=clock,
        monotonic_clock=FakeClock(5_000.0),
    )
    return Arrangement(issuer, sessions_of(record), clock, config, relying_party)


SESSION_ENDED = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)

_REFRESH_ANSWERS = pytest.mark.parametrize(
    "refresh_answer_members",
    [
        pytest.param({}, id="rotated"),
        pytest.param({"refresh_token": ISSUED_REFRESH_TOKEN}, id="unchanged"),
        pytest.param({"refresh_token": ABSENT}, id="omitted"),
    ],
)


class TestTheTwoTransactions:
    def test_no_transaction_is_open_during_the_grant(self) -> None:
        arrangement = an_arrangement(SessionsRecordingTheirTransaction)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsRecordingTheirTransaction)
        arrangement.issuer.before_exchange = lambda: sessions.events.append(("grant", get_ident()))

        outcome = arrangement.fresh_access_token(sessions.in_transaction)

        assert isinstance(outcome, SecretStr)
        assert sessions.event_names == [
            "open", "load", "commit", "grant", "open", "load", "replace", "commit",
        ]

    @_SHAPES
    @_REFRESH_ANSWERS
    def test_a_session_deleted_during_the_grant_ends_whatever_token_the_issuer_returned(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        refresh_answer_members: dict[str, Any],
    ) -> None:
        arrangement = an_arrangement()
        arrangement.issuer.refresh_answer_members = refresh_answer_members
        arrangement.issuer.before_exchange = lambda: arrangement.sessions.delete(_SESSION_ID)

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    @_SHAPES
    @_REFRESH_ANSWERS
    def test_a_session_past_its_expiry_after_the_grant_ends_and_keeps_its_row(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        refresh_answer_members: dict[str, Any],
    ) -> None:
        arrangement = an_arrangement()
        arrangement.issuer.refresh_answer_members = refresh_answer_members

        def let_the_session_expire() -> None:
            arrangement.clock.now += SESSION_IDLE_SECONDS + 1

        arrangement.issuer.before_exchange = let_the_session_expire

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN

    def test_a_row_deleted_between_the_second_load_and_the_replace_ends_the_session(self) -> None:
        arrangement = an_arrangement(SessionsEndedBeforeReplacingTheRefreshToken)

        outcome = arrangement.fresh_access_token(lambda: nullcontext(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    @_SHAPES
    def test_overlapping_calls_that_complete_in_reverse_order_leave_the_last_written_token(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement()
        provider = provider_of(arrangement.sessions)
        inner: list[SecretStr | AccessTokenRefusal] = []
        stored_by_second_call: list[str | None] = []

        def run_the_second_call_inside_the_first_grant() -> None:
            arrangement.issuer.before_exchange = lambda: None
            inner.append(arrangement.fresh_access_token(provider))
            stored_by_second_call.append(arrangement.stored_refresh_token)

        arrangement.issuer.before_exchange = run_the_second_call_inside_the_first_grant

        outer = arrangement.fresh_access_token(provider)

        [second] = inner
        assert isinstance(outer, SecretStr)
        assert isinstance(second, SecretStr)
        assert outer != second
        assert [request.form["refresh_token"] for request in arrangement.issuer.requests] == [
            ISSUED_REFRESH_TOKEN, ISSUED_REFRESH_TOKEN,
        ]
        stored = arrangement.stored_refresh_token
        assert stored not in (None, ISSUED_REFRESH_TOKEN, *stored_by_second_call)
        assert isinstance(arrangement.fresh_access_token(provider), SecretStr)
        assert arrangement.issuer.requests[-1].form["refresh_token"] == stored
