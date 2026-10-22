"""Verifying an access token the issuer signed for the app: the token profile.

The relying party is the real `OidcRelyingParty`; the key-set endpoint and the
clocks are fakes, so each refusal is observed offline with real RS256 tokens.
"""

from __future__ import annotations

from typing import Any

import pytest
from oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    ACCESS_TOKEN_SUBJECT,
    APP_CLIENT_ID,
    REALM_ISSUER,
    REALM_JWKS_URL,
    FakeClock,
    FakeKeySetEndpoint,
    a_relying_party,
    an_access_token,
    key_set_document,
    public_jwk,
    rsa_key,
)

from webauth.https_client import KeySetFetchError
from webauth.jwt_verification import JwtVerifier, RejectionReason
from webauth.oidc import (
    OidcRefusal,
    OidcRefusalReason,
    VerifiedAccessToken,
)
from webauth.policies import AuthorizedParties

HAL = AuthorizedParties(frozenset({"hal"}))
EXPIRY = ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS
OTHER_APP = "another-app"


def a_key_set() -> FakeKeySetEndpoint:
    return FakeKeySetEndpoint(key_set_document(public_jwk(rsa_key("current"), "current-key")))


def verified(
    token: str,
    *,
    key_sets: FakeKeySetEndpoint | None = None,
    clock: FakeClock | None = None,
    parties: AuthorizedParties = HAL,
) -> VerifiedAccessToken | OidcRefusal:
    relying_party = a_relying_party(fetch_key_set=key_sets or a_key_set(), wall_clock=clock)
    return relying_party.verify_access_token(token, authorized_parties=parties)


def rejected(reason: RejectionReason) -> OidcRefusal:
    return OidcRefusal(OidcRefusalReason.ACCESS_TOKEN_REJECTED, token_rejection=reason)


INVALID_CLAIM = OidcRefusal(OidcRefusalReason.INVALID_ACCESS_CLAIM)
NOT_AN_AUTHORIZED_PARTY = OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH)


def test_a_perfect_access_token_yields_its_subject_and_groups() -> None:
    assert verified(an_access_token()) == VerifiedAccessToken(
        subject=ACCESS_TOKEN_SUBJECT, groups=("/apps/x/admin",),
    )


def test_the_relying_party_names_its_issuer() -> None:
    assert a_relying_party().issuer == REALM_ISSUER


@pytest.mark.parametrize(
    "media_type", ["at+jwt", "application/at+jwt", "at+JWT", "APPLICATION/AT+JWT"],
)
def test_an_access_token_type_is_compared_as_a_media_type(media_type: str) -> None:
    outcome = verified(an_access_token(header={"typ": media_type}))

    assert isinstance(outcome, VerifiedAccessToken)


@pytest.mark.parametrize(
    "typ",
    [
        pytest.param("JWT", id="jwt"),
        pytest.param(ABSENT, id="absent"),
        pytest.param(["at+jwt"], id="an-array"),
        pytest.param("logout+jwt", id="a-logout-token"),
    ],
)
def test_a_token_of_another_type_is_refused_before_any_key_set_is_fetched(typ: Any) -> None:
    key_sets = a_key_set()

    outcome = verified(an_access_token(header={"typ": typ}), key_sets=key_sets)

    assert (outcome, key_sets.fetched_urls) == (rejected(RejectionReason.INVALID_TOKEN_TYPE), [])


def a_jwt_verifier() -> JwtVerifier:
    return JwtVerifier(
        issuer=REALM_ISSUER,
        audiences=[APP_CLIENT_ID],
        jwks_url=REALM_JWKS_URL,
        leeway_seconds=ACCESS_TOKEN_LEEWAY_SECONDS,
        fetch_key_set=a_key_set(),
        wall_clock=FakeClock(float(ACCESS_TOKEN_NOW)),
        monotonic_clock=FakeClock(5_000.0),
    )


@pytest.mark.parametrize(
    "keywords",
    [
        pytest.param({"expected_media_types": "at+jwt"}, id="a-bare-string"),
        pytest.param({"expected_media_types": frozenset({"AT+JWT"})}, id="not-lowercase"),
        pytest.param(
            {"expected_media_types": frozenset({"at+jwt"}), "expected_type": "at+jwt"},
            id="both-keywords",
        ),
    ],
)
def test_the_verifier_refuses_media_types_it_cannot_compare(keywords: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="expected"):
        a_jwt_verifier().verify(an_access_token(), **keywords)


@pytest.mark.parametrize(
    ("claims", "refusal"),
    [
        pytest.param(
            {"aud": OTHER_APP}, rejected(RejectionReason.INVALID_AUDIENCE),
            id="another-client-only",
        ),
        pytest.param({"aud": [APP_CLIENT_ID, OTHER_APP]}, INVALID_CLAIM, id="own-and-another-app"),
        pytest.param({"aud": [APP_CLIENT_ID, "account"]}, INVALID_CLAIM, id="own-and-account"),
    ],
)
def test_the_audience_must_be_the_app_alone(
    claims: dict[str, Any], refusal: OidcRefusal,
) -> None:
    assert verified(an_access_token(claims=claims)) == refusal


def test_a_token_without_an_audience_is_refused_as_rejected() -> None:
    outcome = verified(an_access_token(claims={"aud": ABSENT}))

    assert isinstance(outcome, OidcRefusal)
    assert outcome.reason is OidcRefusalReason.ACCESS_TOKEN_REJECTED


def test_a_singleton_audience_array_of_the_app_is_accepted() -> None:
    outcome = verified(an_access_token(claims={"aud": [APP_CLIENT_ID]}))

    assert isinstance(outcome, VerifiedAccessToken)


@pytest.mark.parametrize(
    "authorized_party",
    [
        pytest.param(ABSENT, id="absent"),
        pytest.param(["hal"], id="a-list"),
        pytest.param("another-client", id="another-client"),
        pytest.param("h", id="a-fragment-of-an-allowed-client"),
    ],
)
def test_an_authorized_party_the_host_did_not_allow_is_refused(authorized_party: Any) -> None:
    outcome = verified(an_access_token(claims={"azp": authorized_party}))

    assert outcome == NOT_AN_AUTHORIZED_PARTY


@pytest.mark.parametrize(
    "client_ids",
    [
        pytest.param("hal", id="a-string"),
        pytest.param(frozenset(), id="empty"),
        pytest.param({"hal"}, id="a-mutable-set"),
        pytest.param(frozenset({""}), id="an-empty-client-id"),
    ],
)
def test_authorized_parties_refuse_what_is_not_a_set_of_client_ids(client_ids: Any) -> None:
    with pytest.raises(ValueError, match="client_ids"):
        AuthorizedParties(client_ids)


@pytest.mark.parametrize("parties", ["hal", frozenset({"hal"})], ids=["string", "frozenset"])
def test_verifying_with_anything_but_authorized_parties_raises_before_any_fetch(
    parties: Any,
) -> None:
    key_sets = a_key_set()

    with pytest.raises(TypeError, match="AuthorizedParties"):
        verified(an_access_token(), key_sets=key_sets, parties=parties)

    assert key_sets.fetched_urls == []


@pytest.mark.parametrize(
    "claims",
    [
        pytest.param({"sub": ABSENT}, id="subject-absent"),
        pytest.param({"groups": "/apps/x/admin"}, id="groups-a-string"),
        pytest.param({"groups": ["/apps/x/admin", 7]}, id="groups-holding-an-int"),
    ],
)
def test_a_token_whose_subject_or_groups_are_unusable_is_an_invalid_claim(
    claims: dict[str, Any],
) -> None:
    assert verified(an_access_token(claims=claims)) == INVALID_CLAIM


def test_a_token_without_groups_is_accepted_with_none() -> None:
    outcome = verified(an_access_token(claims={"groups": ABSENT}))

    assert outcome == VerifiedAccessToken(subject=ACCESS_TOKEN_SUBJECT, groups=())


def test_a_token_of_another_issuer_signed_with_the_right_key_is_refused() -> None:
    outcome = verified(an_access_token(issuer="https://login.example.org/realms/elsewhere"))

    assert outcome == rejected(RejectionReason.INVALID_ISSUER)


@pytest.mark.parametrize(
    ("seconds_past_expiry", "expected"),
    [
        pytest.param(ACCESS_TOKEN_LEEWAY_SECONDS - 1, None, id="one-second-inside-the-leeway"),
        pytest.param(
            ACCESS_TOKEN_LEEWAY_SECONDS, RejectionReason.EXPIRED, id="at-expiry-plus-leeway",
        ),
    ],
)
def test_an_expired_token_is_admitted_until_expiry_plus_leeway(
    seconds_past_expiry: int, expected: RejectionReason | None,
) -> None:
    outcome = verified(an_access_token(), clock=FakeClock(float(EXPIRY + seconds_past_expiry)))

    if expected is None:
        assert isinstance(outcome, VerifiedAccessToken)
    else:
        assert outcome == rejected(expected)


@pytest.mark.parametrize(
    ("claims", "reason"),
    [
        pytest.param(
            {"iat": ACCESS_TOKEN_NOW + ACCESS_TOKEN_LEEWAY_SECONDS + 1},
            RejectionReason.ISSUED_IN_FUTURE, id="issued-in-the-future",
        ),
        pytest.param(
            {"nbf": ACCESS_TOKEN_NOW + ACCESS_TOKEN_LEEWAY_SECONDS + 1},
            RejectionReason.NOT_YET_VALID, id="not-yet-valid",
        ),
    ],
)
def test_a_token_dated_ahead_of_the_leeway_is_refused(
    claims: dict[str, Any], reason: RejectionReason,
) -> None:
    assert verified(an_access_token(claims=claims)) == rejected(reason)


def test_a_token_that_is_expired_and_of_a_foreign_audience_is_refused_as_rejected() -> None:
    token = an_access_token(claims={"aud": OTHER_APP})

    outcome = verified(token, clock=FakeClock(float(EXPIRY + 10 * ACCESS_TOKEN_LEEWAY_SECONDS)))

    assert isinstance(outcome, OidcRefusal)
    assert outcome.reason is OidcRefusalReason.ACCESS_TOKEN_REJECTED


def test_an_unavailable_key_set_refuses_the_token() -> None:
    key_sets = FakeKeySetEndpoint(KeySetFetchError("the issuer is down"))

    outcome = verified(an_access_token(), key_sets=key_sets)

    assert outcome == rejected(RejectionReason.KEY_SET_UNAVAILABLE)
