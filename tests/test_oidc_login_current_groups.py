"""A person's current groups: ``current_groups`` from the ID token of a refresh grant.

Each case drives ``current_groups`` through a real ``OidcRelyingParty`` whose issuer is
``FakeIssuer`` answering refresh grants with an ID token signed by the key the relying party
trusts, over both shapes of ``SessionTransaction``: a host transaction (``in_transaction``) and
a store that commits every statement (``nullcontext``).
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import get_ident
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    APP_CLIENT_ID,
    ISSUED_REFRESH_TOKEN,
    REALM_ISSUER,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    FakeTokenEndpoint,
    a_fake_id_token,
    a_realm_client_config,
    a_relying_party,
    changed,
    jws,
    rs256,
    rsa_key,
    segment,
    token_endpoint_answer,
)
from tests.support.oidc_relying_party import a_relying_party_for
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
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
from webauth.https_client import KeySetFetchError
from webauth.oidc import OidcRefusalReason, OidcRelyingParty, TokenEndpointError
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    current_groups,
    fresh_access_token,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.config import WebAuthConfig
    from webauth.ports import SessionTransaction

_SESSION_ID = "session-under-test"
_NONCE = "nonce-of-the-login"
_LEEWAY = a_realm_client_config().leeway_seconds
_GROUPS = ["/apps/notes", "/apps/notes/billing"]

_SHAPES = pytest.mark.parametrize(
    "provider_of",
    [
        pytest.param(lambda sessions: sessions.in_transaction, id="transaction"),
        pytest.param(lambda sessions: (lambda: nullcontext(sessions)), id="nullcontext"),
    ],
)
_ROTATIONS = pytest.mark.parametrize(
    "rotation",
    [
        pytest.param({}, id="rotated"),
        pytest.param({"refresh_token": ISSUED_REFRESH_TOKEN}, id="echoed"),
        pytest.param({"refresh_token": ABSENT}, id="omitted"),
    ],
)
SESSION_ENDED = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)
SIGN_IN_AGAIN = AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)


def a_stored_id_token(**claims: Any) -> SecretStr:
    """What the login stored: a token the call never reads."""
    payload = changed({"sub": "user-1", "nonce": _NONCE, "exp": 1}, claims)
    return SecretStr(f"{segment({'typ': 'JWT'})}.{segment(payload)}.signature")


_STORED_ID_TOKEN = a_stored_id_token()


@dataclass
class Arrangement:
    """A live session at ``FIXED_INSTANT`` holding ``rt-1`` and a stored ID token, and the
    issuer whose refresh grant answers a signed ID token."""

    issuer: FakeIssuer
    sessions: SessionRecordsInMemory
    clock: FakeClock
    config: WebAuthConfig
    relying_party: OidcRelyingParty
    answered_tokens: list[str] = field(default_factory=list)

    def answer_with_id_token(self, **claim_changes: Any) -> str:
        now = int(self.clock.now)
        claims = changed(
            {
                "iss": REALM_ISSUER, "aud": APP_CLIENT_ID, "sub": "user-1", "exp": now + 300,
                "iat": now, "groups": _GROUPS,
            },
            claim_changes,
        )
        token = jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"}, claims,
            rs256(rsa_key("current")),
        )
        self.issuer.refresh_answer_members["id_token"] = token
        self.answered_tokens.append(token)
        return token

    def current_groups(
        self, provider: SessionTransaction,
    ) -> tuple[str, ...] | AccessTokenRefusal:
        return current_groups(
            self.relying_party, _SESSION_ID, session_transaction=provider, config=self.config,
        )

    @property
    def stored_refresh_token(self) -> str | None:
        record = self.sessions.load(_SESSION_ID)
        if record is None or record.refresh_token is None:
            return None
        return record.refresh_token.get_secret_value()

    @property
    def requests_made(self) -> int:
        return len(self.issuer.requests)


def an_arrangement(
    sessions_of: Callable[[FakeSessionRecord], SessionRecordsInMemory] = SessionRecordsInMemory,
    *,
    refresh_token: str | None = ISSUED_REFRESH_TOKEN,
    id_token: SecretStr | None = _STORED_ID_TOKEN,
    leeway_seconds: int = _LEEWAY,
    answer: bool = True,
    clock_now: float = FIXED_INSTANT.timestamp(),
) -> Arrangement:
    clock = FakeClock(clock_now)
    issuer = FakeIssuer(mint_id_token=a_fake_id_token)
    config = a_web_auth_config(wall_clock=clock)
    now = datetime.fromtimestamp(clock.now, UTC)
    record = FakeSessionRecord(
        id=_SESSION_ID,
        user=FakeUser(),
        created_at=now - timedelta(minutes=5),
        expires_at=now + timedelta(seconds=SESSION_IDLE_SECONDS),
        refresh_token=None if refresh_token is None else SecretStr(refresh_token),
        id_token=id_token,
    )
    relying_party = a_relying_party_for(
        issuer, a_realm_client_config(leeway_seconds=leeway_seconds), clock,
    )
    arrangement = Arrangement(issuer, sessions_of(record), clock, config, relying_party)
    if answer:
        arrangement.answer_with_id_token()
    return arrangement


def an_issuer_reason(outcome: object) -> OidcRefusalReason | None:
    assert isinstance(outcome, AccessTokenRefusal), outcome
    assert outcome.reason is AccessTokenRefusalReason.ISSUER_UNAVAILABLE
    assert outcome.issuer_refusal is not None
    return outcome.issuer_refusal.reason


class TestTheGroupsReturned:
    @_SHAPES
    def test_the_full_paths_of_the_refreshed_id_token_are_returned(self, provider_of: Any) -> None:
        arrangement = an_arrangement()

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == tuple(_GROUPS)

    def test_a_missing_groups_claim_is_no_membership(self) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(groups=ABSENT)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == ()

    @pytest.mark.parametrize(
        "groups", ["/apps/notes", [1], ["/apps/notes", None], {"path": "/apps/notes"}, None],
        ids=["string", "number", "null-member", "object", "null"],
    )
    def test_a_malformed_groups_claim_is_refused_and_never_empty(self, groups: object) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(groups=groups)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.INVALID_IDENTITY_CLAIM
        assert arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN

    def test_the_groups_of_the_reply_come_from_this_calls_grant_only(self) -> None:
        arrangement = an_arrangement()
        arrangement.issuer.refresh_answer_members["access_token"] = "different.access.token"
        provider = arrangement.sessions.in_transaction

        first = arrangement.current_groups(provider)
        arrangement.answer_with_id_token(groups=["/apps/notes"])
        second = arrangement.current_groups(provider)

        assert (first, second) == (tuple(_GROUPS), ("/apps/notes",))
        assert arrangement.requests_made == 2


class TestTheStoredIdTokenPlaysNoPart:
    @pytest.mark.parametrize(
        "stored",
        [
            None, _STORED_ID_TOKEN, a_stored_id_token(exp=1),
            SecretStr("not-a-compact-jws"), SecretStr(f"e30.{segment({'nonce': 7})}.sig"),
        ],
        ids=["none", "readable", "expired", "unreadable", "unreadable-nonce"],
    )
    def test_a_session_answers_alike_whatever_it_stored(self, stored: SecretStr | None) -> None:
        arrangement = an_arrangement(id_token=stored)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(_GROUPS)

    @pytest.mark.parametrize(
        ("record_change", "expected"),
        [("delete", SESSION_ENDED), ("no-refresh-token", SIGN_IN_AGAIN)],
    )
    def test_the_refusals_before_the_grant_hold(
        self, record_change: str, expected: AccessTokenRefusal
    ) -> None:
        arrangement = an_arrangement(id_token=None)
        if record_change == "delete":
            arrangement.sessions.delete(_SESSION_ID)
        else:
            arrangement.sessions.stored_record.refresh_token = None

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert outcome == expected
        assert arrangement.requests_made == 0


_REJECTED = OidcRefusalReason.ID_TOKEN_REJECTED
_PARTY = OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH
_SUBJECT = OidcRefusalReason.SUBJECT_MISMATCH
_NONCE_REFUSED = OidcRefusalReason.NONCE_MISMATCH
_STALE = OidcRefusalReason.STALE_ID_TOKEN
_ISSUER_REFUSALS = [
    pytest.param({"iss": "https://elsewhere.example/realms/x"}, _REJECTED, id="other-issuer"),
    pytest.param({"aud": "another-client"}, _REJECTED, id="other-audience"),
    pytest.param({"aud": [APP_CLIENT_ID, "another"]}, _PARTY, id="two-audiences-no-azp"),
    pytest.param({"azp": "another-client"}, _PARTY, id="other-azp"),
    pytest.param({"sub": "someone-else"}, _SUBJECT, id="other-sub"),
    pytest.param({"sub": ABSENT}, _SUBJECT, id="no-sub"),
    pytest.param({"exp": 1}, _REJECTED, id="expired"),
    pytest.param({"iat": 4_000_000_000}, _REJECTED, id="iat-in-the-future"),
    pytest.param({"nbf": 4_000_000_000}, _REJECTED, id="not-yet-valid"),
    pytest.param({"nonce": _NONCE}, _NONCE_REFUSED, id="the-logins-nonce"),
    pytest.param({"nonce": "another-nonce"}, _NONCE_REFUSED, id="other-nonce"),
    pytest.param({"nonce": None}, _NONCE_REFUSED, id="null-nonce"),
    pytest.param({"nonce": 7}, _NONCE_REFUSED, id="non-string-nonce"),
    pytest.param(
        {"iat": int(FIXED_INSTANT.timestamp()) - _LEEWAY - 1}, _STALE, id="older-than-the-leeway",
    ),
]


class TestTheNewIdTokenIsVerified:
    @_SHAPES
    @pytest.mark.parametrize(("changes", "reason"), _ISSUER_REFUSALS)
    def test_each_failure_is_named_and_the_rotation_is_still_stored(
        self, provider_of: Any, changes: dict[str, Any], reason: OidcRefusalReason,
    ) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(**changes)

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert an_issuer_reason(outcome) is reason
        assert arrangement.stored_refresh_token in arrangement.issuer.refresh_tokens - {
            ISSUED_REFRESH_TOKEN
        }

    def test_a_token_signed_by_another_key_is_refused(self) -> None:
        arrangement = an_arrangement()
        forged = jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"},
            {"iss": REALM_ISSUER, "aud": APP_CLIENT_ID, "sub": "user-1", "exp": 4_000_000_000,
             "iat": int(arrangement.clock.now)},
            rs256(rsa_key("forger")),
        )
        arrangement.issuer.refresh_answer_members["id_token"] = forged

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED

    def test_an_unavailable_key_set_is_refused_after_the_rotation_is_stored(self) -> None:
        arrangement = an_arrangement()

        arrangement.relying_party = a_relying_party(
            post_token_request=arrangement.issuer,
            fetch_key_set=FakeKeySetEndpoint(KeySetFetchError("the issuer is down")),
            wall_clock=arrangement.clock,
        )

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED
        assert arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN

    def test_a_token_longer_than_the_verifier_reads_is_refused(self) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(padding="p" * 9000)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED

    def test_a_token_without_a_nonce_holds(self) -> None:
        arrangement = an_arrangement()

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(_GROUPS)


class TestFreshness:
    @pytest.mark.parametrize("age", [0, _LEEWAY], ids=["at-the-start", "the-leeway-older"])
    def test_an_iat_within_the_leeway_of_the_grants_start_holds(self, age: int) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - age)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(_GROUPS)

    def test_a_fractional_start_is_judged_by_its_whole_second(self) -> None:
        arrangement = an_arrangement(answer=False, clock_now=FIXED_INSTANT.timestamp() + 0.9)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - _LEEWAY)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(_GROUPS)

    def test_a_grant_longer_than_the_leeway_does_not_age_the_token(self) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token()
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.clock, "now", arrangement.clock.now + _LEEWAY + 1,
        )

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(_GROUPS)

    @pytest.mark.parametrize(("age", "holds"), [(0, True), (1, False)])
    def test_without_leeway_the_iat_must_be_the_grants_second(self, age: int, holds: bool) -> None:
        arrangement = an_arrangement(answer=False, leeway_seconds=0)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - age)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        if holds:
            assert outcome == tuple(_GROUPS)
        else:
            assert an_issuer_reason(outcome) is OidcRefusalReason.STALE_ID_TOKEN


class TestTheReply:
    @_ROTATIONS
    @pytest.mark.parametrize(
        "id_token", [ABSENT, None, 7], ids=["absent", "null", "not-a-string"],
    )
    def test_a_reply_without_an_id_token_is_refused(
        self, id_token: object, rotation: dict[str, Any]
    ) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.issuer.refresh_answer_members = {
            **rotation, **({} if id_token is ABSENT else {"id_token": id_token}),
        }

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.TOKEN_ENDPOINT_FAILED

    @pytest.mark.parametrize(
        ("answer", "expected"),
        [
            (token_endpoint_answer(400, {"error": "invalid_grant"}), SIGN_IN_AGAIN),
            (token_endpoint_answer(400, {"error": "invalid_client"}), None),
            (token_endpoint_answer(500, b""), None),
            (TokenEndpointError("down"), None),
            (token_endpoint_answer(200, {"id_token": "x", "refresh_token": "bad\n"}), None),
        ],
        ids=["invalid-grant", "other-error", "5xx", "transport", "malformed-rotated-token"],
    )
    def test_a_failed_grant_is_refused_and_stores_nothing(
        self, answer: object, expected: AccessTokenRefusal | None
    ) -> None:
        arrangement = an_arrangement()
        endpoint = FakeTokenEndpoint(answer=answer)  # type: ignore[arg-type]
        arrangement.relying_party = a_relying_party_for(
            endpoint, a_realm_client_config(), arrangement.clock,
        )

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        if expected is not None:
            assert outcome == expected
        else:
            assert isinstance(outcome, AccessTokenRefusal)
            assert outcome.reason is AccessTokenRefusalReason.ISSUER_UNAVAILABLE
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN


class TestTheRotationSurvives:
    @_SHAPES
    @_ROTATIONS
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_replacement_refresh_token_is_stored_whatever_the_id_token_said(
        self, provider_of: Any, rotation: dict[str, Any], id_token_holds: bool,
    ) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="x" if not id_token_holds else "user-1")
        arrangement.issuer.refresh_answer_members |= rotation

        arrangement.current_groups(provider_of(arrangement.sessions))

        rotated = "refresh_token" not in rotation
        stored_a_replacement = arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN
        assert stored_a_replacement is rotated


class TestADeletedSessionIsNeverRecreated:
    @_SHAPES
    @_ROTATIONS
    @pytest.mark.parametrize("id_token_holds", [True, False], ids=["holds", "refused"])
    def test_a_session_deleted_during_the_grant_ends_whatever_the_id_token_said(
        self, provider_of: Any, rotation: dict[str, Any], id_token_holds: bool,
    ) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="user-1" if id_token_holds else "x")
        arrangement.issuer.refresh_answer_members |= rotation
        arrangement.issuer.before_exchange = lambda: arrangement.sessions.delete(_SESSION_ID)

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    @_SHAPES
    def test_a_session_past_its_expiry_after_the_grant_ends_and_keeps_its_row(
        self, provider_of: Any,
    ) -> None:
        arrangement = an_arrangement()
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.clock, "now", arrangement.clock.now + SESSION_IDLE_SECONDS + 1,
        )
        arrangement.answer_with_id_token(exp=4_000_000_000)

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == SESSION_ENDED
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN

    def test_a_row_deleted_between_the_second_load_and_the_replace_ends_the_session(self) -> None:
        arrangement = an_arrangement(SessionsEndedBeforeReplacingTheRefreshToken)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert outcome == SESSION_ENDED
        assert arrangement.sessions.list_active() == []

    def test_a_replace_that_stores_nothing_ends_the_session_whatever_the_id_token_said(
        self,
    ) -> None:
        arrangement = an_arrangement(lambda record: SessionsAnsweringReplace(record, False))

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == SESSION_ENDED


class TestNothingElseIsStored:
    def test_only_the_refresh_token_changes(self) -> None:
        arrangement = an_arrangement()
        before = arrangement.sessions.stored_record
        instants, stored_id_token = (before.created_at, before.expires_at), before.id_token

        arrangement.current_groups(arrangement.sessions.in_transaction)

        after = arrangement.sessions.stored_record
        assert ((after.created_at, after.expires_at), after.id_token) == (instants, stored_id_token)
        assert after.refresh_token != SecretStr(ISSUED_REFRESH_TOKEN)


class TestTheTransactions:
    def test_no_transaction_is_open_during_the_grant(self) -> None:
        arrangement = an_arrangement(SessionsRecordingTheirTransaction)
        sessions = arrangement.sessions
        assert isinstance(sessions, SessionsRecordingTheirTransaction)
        arrangement.issuer.before_exchange = lambda: sessions.events.append(("grant", get_ident()))

        outcome = arrangement.current_groups(sessions.in_transaction)

        assert outcome == tuple(_GROUPS)
        assert sessions.event_names == [
            "open", "load", "commit", "grant", "open", "load", "replace", "commit",
        ]

    def test_a_failing_load_raises_and_hands_out_no_groups(self) -> None:
        arrangement = an_arrangement(SessionsFailingToLoad)

        with pytest.raises(ConnectionError):
            arrangement.current_groups(arrangement.sessions.in_transaction)

    def test_a_failing_exit_raises_and_hands_out_no_groups(self) -> None:
        arrangement = an_arrangement()
        arrangement.sessions.commit_failure = RuntimeError("commit failed")

        with pytest.raises(RuntimeError, match="commit failed"):
            arrangement.current_groups(arrangement.sessions.in_transaction)

    def test_a_replace_answering_a_non_bool_raises(self) -> None:
        arrangement = an_arrangement(lambda record: SessionsAnsweringReplace(record, "yes"))

        with pytest.raises(TypeError, match="bool"):
            arrangement.current_groups(arrangement.sessions.in_transaction)


class TestTheTokenNeverLeaves:
    def test_no_outcome_shows_a_token(self) -> None:
        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(sub="someone-else")
        secrets_held = [
            *arrangement.answered_tokens, "access-token-at-2", ISSUED_REFRESH_TOKEN,
            _STORED_ID_TOKEN.get_secret_value(),
        ]

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        shown = repr(outcome)
        assert not any(secret in shown for secret in secrets_held)


class TestOverlap:
    def test_the_last_replacement_wins_when_two_calls_overlap(self) -> None:
        arrangement = an_arrangement()
        provider = arrangement.sessions.in_transaction
        inner: list[object] = []

        def overlapping_call() -> None:
            arrangement.issuer.before_exchange = lambda: None
            inner.append(arrangement.current_groups(provider))

        arrangement.issuer.before_exchange = overlapping_call

        outer = arrangement.current_groups(provider)

        assert (outer, inner) == (tuple(_GROUPS), [tuple(_GROUPS)])
        assert arrangement.stored_refresh_token == "refresh-token-rt-3"

    def test_an_echoed_token_never_overwrites_a_replacement(self) -> None:
        arrangement = an_arrangement()
        provider = arrangement.sessions.in_transaction
        arrangement.issuer.refresh_answer_members["refresh_token"] = ISSUED_REFRESH_TOKEN
        replaced: list[object] = []

        def beside_fresh_access_token() -> None:
            arrangement.issuer.before_exchange = lambda: None
            echoed = arrangement.issuer.refresh_answer_members.pop("refresh_token")
            replaced.append(
                fresh_access_token(
                    arrangement.relying_party, _SESSION_ID,
                    session_transaction=provider, config=arrangement.config,
                )
            )
            arrangement.issuer.refresh_answer_members["refresh_token"] = echoed

        arrangement.issuer.before_exchange = beside_fresh_access_token

        outcome = arrangement.current_groups(provider)

        assert outcome == tuple(_GROUPS)
        assert isinstance(replaced[0], SecretStr)
        assert arrangement.stored_refresh_token == "refresh-token-rt-2"
