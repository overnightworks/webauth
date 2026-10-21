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
    FakeTokenEndpoint,
    a_fake_id_token,
    key_set_document,
    public_jwk,
    rsa_key,
    token_endpoint_answer,
)
from pydantic import SecretStr
from webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    SESSION_IDLE_SECONDS,
    FakeSessionRecord,
    FakeUser,
    SessionRecordsInMemory,
    SessionsAnsweringReplace,
    SessionsEndedBeforeReplacingTheRefreshToken,
    SessionsFailingToLoad,
    SessionsRecordingTheirTransaction,
    a_web_auth_config,
)

from webauth.config import WebAuthConfig
from webauth.dependencies import admit_session
from webauth.oidc import (
    OidcClientConfig,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    TokenEndpointError,
)
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    fresh_access_token,
)
from webauth.ports import AuthenticatedUser

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
    token_endpoint: FakeIssuer | FakeTokenEndpoint

    def fresh_access_token(
        self, provider: SessionTransaction, session_id: str = _SESSION_ID,
    ) -> SecretStr | AccessTokenRefusal:
        return fresh_access_token(
            self.relying_party,
            session_id,
            session_transaction=provider,
            config=self.config,
        )

    @property
    def instants(self) -> tuple[datetime, datetime] | None:
        [record] = self.sessions.list_active() or [None]
        return None if record is None else (record.created_at, record.expires_at)

    @property
    def stored_refresh_token(self) -> str | None:
        [record] = self.sessions.list_active() or [None]
        if record is None or record.refresh_token is None:
            return None
        return record.refresh_token.get_secret_value()


def an_arrangement(
    sessions_of: Callable[[FakeSessionRecord], SessionRecordsInMemory] = SessionRecordsInMemory,
    *,
    refresh_token: str | None = ISSUED_REFRESH_TOKEN,
    age: timedelta = timedelta(minutes=5),
    token_endpoint: FakeTokenEndpoint | None = None,
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
        post_token_request=issuer if token_endpoint is None else token_endpoint,
        fetch_key_set=FakeKeySetEndpoint(
            key_set_document(public_jwk(rsa_key("current"), "current-key"))
        ),
        wall_clock=clock,
        monotonic_clock=FakeClock(5_000.0),
    )
    return Arrangement(
        issuer, sessions_of(record), clock, config, relying_party, token_endpoint or issuer,
    )


SESSION_ENDED = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)
SIGN_IN_AGAIN = AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)
GRANTED_ACCESS_TOKEN = "access-token-canary-granted"  # noqa: S105

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

    @_SHAPES
    def test_a_call_whose_grant_echoes_the_token_it_sent_does_not_write_it_over_a_newer_one(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement()
        provider = provider_of(arrangement.sessions)
        stored_by_second_call: list[str | None] = []

        def run_the_second_call_then_echo_the_sent_token() -> None:
            arrangement.issuer.before_exchange = lambda: None
            arrangement.fresh_access_token(provider)
            stored_by_second_call.append(arrangement.stored_refresh_token)
            arrangement.issuer.refresh_answer_members = {"refresh_token": ISSUED_REFRESH_TOKEN}

        arrangement.issuer.before_exchange = run_the_second_call_then_echo_the_sent_token

        outer = arrangement.fresh_access_token(provider)

        assert isinstance(outer, SecretStr)
        assert arrangement.stored_refresh_token == stored_by_second_call[0] != ISSUED_REFRESH_TOKEN


class TestAGrantedToken:
    @_SHAPES
    def test_a_live_session_yields_the_grants_token_and_stores_the_rotated_refresh_token(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement()
        arrangement.issuer.refresh_answer_members = {"access_token": GRANTED_ACCESS_TOKEN}
        before = arrangement.instants

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions))

        assert isinstance(outcome, SecretStr)
        assert outcome.get_secret_value() == GRANTED_ACCESS_TOKEN
        [request] = arrangement.issuer.requests
        assert request.form["refresh_token"] == ISSUED_REFRESH_TOKEN
        stored = arrangement.stored_refresh_token
        assert stored != ISSUED_REFRESH_TOKEN
        assert stored in arrangement.issuer.refresh_tokens
        assert arrangement.instants == before

    @_SHAPES
    def test_two_calls_in_a_row_yield_two_tokens_and_the_second_sends_the_rotated_one(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement()
        provider = provider_of(arrangement.sessions)

        first = arrangement.fresh_access_token(provider)
        stored_after_first = arrangement.stored_refresh_token
        second = arrangement.fresh_access_token(provider)

        assert isinstance(first, SecretStr)
        assert isinstance(second, SecretStr)
        assert first != second
        assert len(arrangement.issuer.requests) == 2
        assert arrangement.issuer.requests[1].form["refresh_token"] == stored_after_first

    @pytest.mark.parametrize(
        "refresh_answer_members",
        [
            pytest.param({"refresh_token": ISSUED_REFRESH_TOKEN}, id="unchanged"),
            pytest.param({"refresh_token": ABSENT}, id="omitted"),
        ],
    )
    def test_an_unchanged_or_omitted_refresh_token_writes_nothing(
        self, refresh_answer_members: dict[str, Any],
    ) -> None:
        arrangement = an_arrangement(SessionsRecordingTheirTransaction)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsRecordingTheirTransaction)
        arrangement.issuer.refresh_answer_members = {
            "access_token": GRANTED_ACCESS_TOKEN, **refresh_answer_members,
        }

        outcome = arrangement.fresh_access_token(sessions.in_transaction)

        assert isinstance(outcome, SecretStr)
        assert outcome.get_secret_value() == GRANTED_ACCESS_TOKEN
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN
        assert "replace" not in sessions.event_names


_ISSUER_FAILURES = [
    pytest.param(
        token_endpoint_answer(401, {"error": "invalid_client"}),
        OidcRefusalReason.TOKEN_REQUEST_REFUSED,
        id="invalid-client",
    ),
    pytest.param(
        token_endpoint_answer(503, {"error": "server_error"}),
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED,
        id="server-error",
    ),
    pytest.param(
        token_endpoint_answer(200, b"<html>signed in</html>"),
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED,
        id="malformed-answer",
    ),
    pytest.param(
        token_endpoint_answer(200, {"access_token": "granted", "token_type": "MAC"}),
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED,
        id="not-a-bearer-token",
    ),
    pytest.param(
        TokenEndpointError("connection refused"),
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED,
        id="transport-error",
    ),
]


class TestRefusals:
    @_SHAPES
    def test_a_refresh_token_the_issuer_ended_means_sign_in_again_and_nothing_is_written(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement(SessionsRecordingTheirTransaction)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsRecordingTheirTransaction)
        arrangement.issuer.end_sso_session()
        before = arrangement.instants

        outcome = arrangement.fresh_access_token(provider_of(sessions))

        assert outcome == SIGN_IN_AGAIN
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN
        assert arrangement.instants == before
        assert sessions.event_names.count("load") == 1
        assert "replace" not in sessions.event_names
        admitted = admit_session(_SESSION_ID, sessions=sessions, config=arrangement.config)
        assert isinstance(admitted, AuthenticatedUser)

    @_SHAPES
    def test_a_session_without_a_refresh_token_means_sign_in_again_without_asking_the_issuer(
        self, provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
    ) -> None:
        arrangement = an_arrangement(refresh_token=None)

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions))

        assert outcome == SIGN_IN_AGAIN
        assert arrangement.issuer.requests == []

    @_SHAPES
    @pytest.mark.parametrize(("answer", "reason"), _ISSUER_FAILURES)
    def test_an_issuer_that_does_not_answer_usefully_is_unavailable_and_nothing_is_written(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        answer: Any,
        reason: OidcRefusalReason,
    ) -> None:
        arrangement = an_arrangement(token_endpoint=FakeTokenEndpoint(answer=answer))
        before = arrangement.instants

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions))

        assert isinstance(outcome, AccessTokenRefusal)
        assert outcome.reason is AccessTokenRefusalReason.ISSUER_UNAVAILABLE
        assert isinstance(outcome.issuer_refusal, OidcRefusal)
        assert outcome.issuer_refusal.reason is reason
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN
        assert arrangement.instants == before

    @_SHAPES
    @pytest.mark.parametrize(
        ("session_id", "age", "idle_for"),
        [
            pytest.param("session-nobody-holds", timedelta(minutes=5), 0, id="no-row"),
            pytest.param(_SESSION_ID, timedelta(minutes=5), SESSION_IDLE_SECONDS + 1, id="idle"),
            pytest.param(
                _SESSION_ID, timedelta(seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS), 0, id="past-cap",
            ),
        ],
    )
    def test_a_session_that_is_gone_or_outside_its_lifetime_has_ended_without_asking_the_issuer(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        session_id: str,
        age: timedelta,
        idle_for: int,
    ) -> None:
        arrangement = an_arrangement(age=age)
        arrangement.clock.now += idle_for

        outcome = arrangement.fresh_access_token(provider_of(arrangement.sessions), session_id)

        assert outcome == SESSION_ENDED
        assert arrangement.issuer.requests == []
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN


class TestAFailingStore:
    @_SHAPES
    @pytest.mark.parametrize("answer", [None, 1, "yes"], ids=["none", "int", "str"])
    def test_a_replace_that_answers_no_bool_raises_and_hands_out_no_token(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        answer: Any,
    ) -> None:
        arrangement = an_arrangement(lambda record: SessionsAnsweringReplace(record, answer))

        with pytest.raises(TypeError, match="replace_refresh_token"):
            arrangement.fresh_access_token(provider_of(arrangement.sessions))

    @_SHAPES
    @pytest.mark.parametrize("fails_in_transaction", [1, 2])
    def test_a_load_that_raises_reaches_the_caller_from_either_transaction(
        self,
        provider_of: Callable[[SessionRecordsInMemory], SessionTransaction],
        fails_in_transaction: int,
    ) -> None:
        arrangement = an_arrangement(SessionsFailingToLoad)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsFailingToLoad)
        if fails_in_transaction == 2:
            sessions.failing = False
            arrangement.issuer.before_exchange = lambda: setattr(sessions, "failing", True)

        with pytest.raises(ConnectionError):
            arrangement.fresh_access_token(provider_of(sessions))

    def test_a_commit_of_the_second_transaction_that_fails_reaches_the_caller(self) -> None:
        arrangement = an_arrangement()
        failure = RuntimeError("commit failed")
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.sessions, "commit_failure", failure,
        )

        with pytest.raises(RuntimeError, match="commit failed"):
            arrangement.fresh_access_token(arrangement.sessions.in_transaction)
