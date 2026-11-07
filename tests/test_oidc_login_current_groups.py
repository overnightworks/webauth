"""A person's current groups: what the groups, the outcomes and the new ID token's checks answer."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from tests.support.current_groups_arrangement import (
    GROUPS,
    LEEWAY,
    NONCE,
    ROTATIONS,
    SESSION_ENDED,
    SESSION_ID,
    SHAPES,
    SIGN_IN_AGAIN,
    STORED_ID_TOKEN,
    a_stored_id_token,
    an_arrangement,
    an_issuer_reason,
    unreadable_id_token_of,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    APP_CLIENT_ID,
    ISSUED_REFRESH_TOKEN,
    REALM_ISSUER,
    FakeKeySetEndpoint,
    FakeTokenEndpoint,
    a_realm_client_config,
    a_relying_party,
    jws,
    rs256,
    rsa_key,
    segment,
    token_endpoint_answer,
)
from tests.support.oidc_login_host import ADMISSION, LOGIN_GROUP, NO_ADMINS
from tests.support.oidc_relying_party import a_relying_party_for
from tests.support.webauth_arrangement import (
    FIXED_INSTANT,
    SESSION_IDLE_SECONDS,
)
from webauth.admission import AppRole, app_role
from webauth.https_client import KeySetFetchError
from webauth.oidc import OidcRefusalReason, TokenEndpointError
from webauth.oidc_login import (
    AccessTokenRefusal,
)


class TestTheGroupsReturned:
    @SHAPES
    def test_the_full_paths_of_the_refreshed_id_token_are_returned(self, provider_of: Any) -> None:
        """GROUPS-01, GROUPS-04: the answer is the groups of the refreshed ID token, over both
        transaction shapes."""

        arrangement = an_arrangement()

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert outcome == tuple(GROUPS)

    def test_a_missing_groups_claim_is_no_membership(self) -> None:
        """GROUPS-05: a missing groups claim answers `()`, which `app_role` does not admit."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(groups=ABSENT)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert isinstance(outcome, tuple)
        assert outcome == ()
        assert app_role(outcome, ADMISSION) is None

    @pytest.mark.parametrize(
        ("group", "role"),
        [
            pytest.param(LOGIN_GROUP, AppRole.USER, id="the login group"),
            pytest.param(f"{LOGIN_GROUP}/staff", AppRole.USER, id="a login subgroup"),
            pytest.param(f"{LOGIN_GROUP}2", None, id="a group named like the login group"),
        ],
    )
    def test_the_tuple_passed_to_app_role_admits_the_group_and_its_subgroups(
        self, group: str, role: AppRole | None
    ) -> None:
        """GROUPS-12: `app_role` admits a member of the login group or of a subgroup, not a group
        named alike."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(groups=[group])

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert isinstance(outcome, tuple)
        assert app_role(outcome, NO_ADMINS) is role

    @pytest.mark.parametrize(
        "groups",
        ["/apps/notes", [1], ["/apps/notes", None], {"path": "/apps/notes"}, None],
        ids=["string", "number", "null-member", "object", "null"],
    )
    def test_a_malformed_groups_claim_is_refused_and_never_empty(self, groups: object) -> None:
        """GROUPS-08, GROUPS-22: a groups claim that is no list of strings is refused as an issuer
        failure, never `()`."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(groups=groups)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.INVALID_IDENTITY_CLAIM
        assert arrangement.stored_refresh_token != ISSUED_REFRESH_TOKEN

    def test_the_groups_of_the_reply_come_from_this_calls_grant_only(self) -> None:
        """GROUPS-01, GROUPS-25: each call makes one grant and answers the groups of its reply."""

        arrangement = an_arrangement()
        arrangement.issuer.refresh_answer_members["access_token"] = "different.access.token"
        provider = arrangement.sessions.in_transaction

        first = arrangement.current_groups(provider)
        arrangement.answer_with_id_token(groups=["/apps/notes"])
        second = arrangement.current_groups(provider)

        assert (first, second) == (tuple(GROUPS), ("/apps/notes",))
        assert arrangement.requests_made == 2


class TestTheStoredIdTokenPlaysNoPart:
    @pytest.mark.parametrize(
        "stored",
        [
            None,
            STORED_ID_TOKEN,
            a_stored_id_token(exp=1),
            SecretStr("not-a-compact-jws"),
            SecretStr(f"e30.{segment({'nonce': 7})}.sig"),
        ],
        ids=["none", "readable", "expired", "unreadable", "unreadable-nonce"],
    )
    def test_a_session_answers_alike_whatever_it_stored(self, stored: SecretStr | None) -> None:
        """GROUPS-09: a session with no stored ID token, or one of any state, answers the same
        groups."""

        arrangement = an_arrangement(id_token=stored)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    def test_a_session_whose_stored_id_token_cannot_be_read_still_answers(self) -> None:
        """GROUPS-09: the call never reads the stored ID token."""

        arrangement = an_arrangement(unreadable_id_token_of)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    @pytest.mark.parametrize(
        ("record_change", "expected"),
        [
            ("delete", SESSION_ENDED),
            ("outside-its-lifetime", SESSION_ENDED),
            ("no-refresh-token", SIGN_IN_AGAIN),
        ],
    )
    def test_the_refusals_before_the_grant_hold(
        self, record_change: str, expected: AccessTokenRefusal
    ) -> None:
        """GROUPS-06, GROUPS-07: a deleted or expired session ends and one without a refresh token
        signs in again, before any grant."""

        arrangement = an_arrangement(id_token=None)
        if record_change == "delete":
            arrangement.sessions.delete(SESSION_ID)
        elif record_change == "outside-its-lifetime":
            arrangement.clock.now += SESSION_IDLE_SECONDS + 1
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
    pytest.param(
        {"exp": int(FIXED_INSTANT.timestamp()) - LEEWAY - 1},
        _REJECTED,
        id="expired-past-the-leeway",
    ),
    pytest.param({"iat": 4_000_000_000}, _REJECTED, id="iat-in-the-future"),
    pytest.param({"nbf": 4_000_000_000}, _REJECTED, id="not-yet-valid"),
    pytest.param({"nonce": NONCE}, _NONCE_REFUSED, id="the-logins-nonce"),
    pytest.param({"nonce": "another-nonce"}, _NONCE_REFUSED, id="other-nonce"),
    pytest.param({"nonce": None}, _NONCE_REFUSED, id="null-nonce"),
    pytest.param({"nonce": 7}, _NONCE_REFUSED, id="non-string-nonce"),
    pytest.param(
        {"iat": int(FIXED_INSTANT.timestamp()) - LEEWAY - 1},
        _STALE,
        id="older-than-the-leeway",
    ),
]


class TestTheNewIdTokenIsVerified:
    @SHAPES
    @pytest.mark.parametrize(("changes", "reason"), _ISSUER_REFUSALS)
    def test_each_failure_is_named_and_the_rotation_is_still_stored(
        self,
        provider_of: Any,
        changes: dict[str, Any],
        reason: OidcRefusalReason,
    ) -> None:
        """GROUPS-08, GROUPS-13, GROUPS-14, GROUPS-15, GROUPS-16, GROUPS-17, GROUPS-18, GROUPS-19,
        GROUPS-23: each failed claim of the new ID token is refused with its reason, and the
        rotation is stored."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(**changes)

        outcome = arrangement.current_groups(provider_of(arrangement.sessions))

        assert an_issuer_reason(outcome) is reason
        assert arrangement.stored_refresh_token in arrangement.issuer.refresh_tokens - {
            ISSUED_REFRESH_TOKEN
        }

    def test_a_token_signed_by_another_key_is_refused(self) -> None:
        """GROUPS-08: a new ID token signed by another key is refused."""

        arrangement = an_arrangement()
        forged = jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"},
            {
                "iss": REALM_ISSUER,
                "aud": APP_CLIENT_ID,
                "sub": "user-1",
                "exp": 4_000_000_000,
                "iat": int(arrangement.clock.now),
            },
            rs256(rsa_key("forger")),
        )
        arrangement.issuer.refresh_answer_members["id_token"] = forged

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED

    def test_a_token_whose_header_advertises_an_unsupported_algorithm_is_refused(self) -> None:
        """GROUPS-08: a new ID token with an unsupported algorithm is refused."""

        arrangement = an_arrangement()
        now = int(arrangement.clock.now)
        other = jws(
            {"alg": "HS256", "kid": "current-key", "typ": "JWT"},
            {
                "iss": REALM_ISSUER,
                "aud": APP_CLIENT_ID,
                "sub": "user-1",
                "exp": now + 300,
                "iat": now,
            },
            rs256(rsa_key("current")),
        )
        arrangement.issuer.refresh_answer_members["id_token"] = other

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED

    def test_an_unavailable_key_set_is_refused_after_the_rotation_is_stored(self) -> None:
        """GROUPS-08, GROUPS-23: an unavailable key set refuses the new ID token and the rotation
        is stored."""

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
        """GROUPS-08: a new ID token longer than the verifier reads is refused."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(padding="p" * 9000)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.ID_TOKEN_REJECTED

    def test_a_token_without_a_nonce_holds(self) -> None:
        """GROUPS-04, GROUPS-18: a new ID token without a nonce key answers its groups."""

        arrangement = an_arrangement()

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)


class TestFreshness:
    @pytest.mark.parametrize("age", [0, LEEWAY], ids=["at-the-start", "the-leeway-older"])
    def test_an_iat_within_the_leeway_of_the_grants_start_holds(self, age: int) -> None:
        """GROUPS-20: an `iat` up to the leeway older than the grant's start holds."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - age)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    def test_an_exp_within_the_leeway_still_holds(self) -> None:
        """GROUPS-17, GROUPS-20: an `exp` that passed within the leeway still holds."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token(exp=int(arrangement.clock.now) - LEEWAY + 1)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    def test_a_fractional_start_is_judged_by_its_whole_second(self) -> None:
        """GROUPS-20: the grant's start is judged by its whole second."""

        arrangement = an_arrangement(answer=False, clock_now=FIXED_INSTANT.timestamp() + 0.9)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - LEEWAY)

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    def test_a_grant_longer_than_the_leeway_does_not_age_the_token(self) -> None:
        """GROUPS-20: freshness is judged against the grant's start, not its end."""

        arrangement = an_arrangement(answer=False)
        arrangement.answer_with_id_token()
        arrangement.issuer.before_exchange = lambda: setattr(
            arrangement.clock,
            "now",
            arrangement.clock.now + LEEWAY + 1,
        )

        assert arrangement.current_groups(arrangement.sessions.in_transaction) == tuple(GROUPS)

    @pytest.mark.parametrize(("age", "holds"), [(0, True), (1, False)])
    def test_without_leeway_the_iat_must_be_the_grants_second(self, age: int, holds: bool) -> None:
        """GROUPS-08, GROUPS-20: without leeway the `iat` must be the grant's second, else the
        token is stale."""

        arrangement = an_arrangement(answer=False, leeway_seconds=0)
        arrangement.answer_with_id_token(iat=int(arrangement.clock.now) - age)

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        if holds:
            assert outcome == tuple(GROUPS)
        else:
            assert an_issuer_reason(outcome) is OidcRefusalReason.STALE_ID_TOKEN


class TestTheReply:
    @ROTATIONS
    @pytest.mark.parametrize(
        "id_token",
        [ABSENT, None, 7],
        ids=["absent", "null", "not-a-string"],
    )
    def test_a_reply_without_an_id_token_is_refused_after_the_rotation_is_stored(
        self, id_token: object, rotation: dict[str, Any]
    ) -> None:
        """GROUPS-08, GROUPS-21, GROUPS-23: a reply without an ID token is an issuer failure, never
        `()`, and the rotation is stored."""

        arrangement = an_arrangement(answer=False)
        arrangement.issuer.refresh_answer_members = {
            **rotation,
            **({} if id_token is ABSENT else {"id_token": id_token}),
        }

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        assert an_issuer_reason(outcome) is OidcRefusalReason.TOKEN_ENDPOINT_FAILED
        if "refresh_token" in rotation:
            assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN
        else:
            assert arrangement.stored_refresh_token in arrangement.issuer.refresh_tokens - {
                ISSUED_REFRESH_TOKEN
            }

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
        """GROUPS-07, GROUPS-08: an `invalid_grant` signs in again, any other failed grant is an
        issuer failure with its reason, nothing is stored, and the session still stands."""

        arrangement = an_arrangement()
        endpoint = FakeTokenEndpoint(answer=answer)  # type: ignore[arg-type]
        arrangement.relying_party = a_relying_party_for(
            endpoint,
            a_realm_client_config(),
            arrangement.clock,
        )

        outcome = arrangement.current_groups(arrangement.sessions.in_transaction)

        if expected is not None:
            assert outcome == expected
        else:
            assert an_issuer_reason(outcome) is not None
        assert arrangement.sessions.load(SESSION_ID) is not None
        assert arrangement.stored_refresh_token == ISSUED_REFRESH_TOKEN
