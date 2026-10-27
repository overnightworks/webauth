"""Back-channel logout tokens through `OidcRelyingParty.verify_logout_token`.

A valid token of the bound issuer yields its subject; every other is refused with its reason.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.oidc_arrangement import (
    ABSENT,
    BACKCHANNEL_LOGOUT_EVENT,
    REALM_ISSUER,
    FakeTokenEndpoint,
    a_logout_token,
)
from tests.support.oidc_relying_party import (
    CLIENT_ID,
    LEEWAY_SECONDS,
    NOW,
    OTHER_REALM,
    SUBJECT,
    LoginScenario,
)
from webauth.jwt_verification import RejectionReason
from webauth.oidc import (
    LOGOUT_TOKEN_MAX_AGE_SECONDS,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    VerifiedLogout,
)


def _logout_token(
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    key_name: str = "current",
) -> str:
    return a_logout_token(
        issuer=REALM_ISSUER,
        audience=CLIENT_ID,
        subject=SUBJECT,
        now=NOW,
        key_name=key_name,
        claims=claims,
        header=header,
    )


_EVENT = BACKCHANNEL_LOGOUT_EVENT
_MAX_LOGOUT_AGE = LOGOUT_TOKEN_MAX_AGE_SECONDS + LEEWAY_SECONDS


def _a_logout_relying_party() -> OidcRelyingParty:
    return LoginScenario(FakeTokenEndpoint()).relying_party


@pytest.mark.parametrize(("claims", "header"), [
    pytest.param({}, {}, id="the token as keycloak signs it"),
    pytest.param({"sid": ABSENT}, {}, id="a subject without a session id"),
    pytest.param({"sid": 7}, {}, id="a session id of any type is never read"),
    pytest.param({"aud": [CLIENT_ID]}, {}, id="a singleton audience array"),
    pytest.param({"events": {_EVENT: {"reason": "admin"}}}, {}, id="an events object with data"),
    pytest.param({"note": "other claims are ignored"}, {}, id="an unknown claim"),
    pytest.param({"iat": NOW + LEEWAY_SECONDS}, {}, id="issued in the future within leeway"),
    pytest.param({"iat": NOW - _MAX_LOGOUT_AGE, "exp": NOW + 1}, {}, id="issued at the limit"),
    pytest.param({"exp": NOW + LEEWAY_SECONDS - 1, "iat": NOW - 100}, {},
                 id="one second before the deadline plus leeway"),
])
def test_a_logout_token_of_the_bound_issuer_yields_its_subject(
    claims: dict[str, Any], header: dict[str, Any],
) -> None:
    outcome = _a_logout_relying_party().verify_logout_token(_logout_token(claims, header))

    assert outcome == VerifiedLogout(subject=SUBJECT)


def _rejected(reason: RejectionReason) -> OidcRefusal:
    return OidcRefusal(OidcRefusalReason.LOGOUT_TOKEN_REJECTED, token_rejection=reason)


_INVALID_LOGOUT_CLAIM = OidcRefusal(OidcRefusalReason.INVALID_LOGOUT_CLAIM)
_LOGOUT_REFUSALS = [
    pytest.param(_logout_token(key_name="forger"), _rejected(RejectionReason.INVALID_SIGNATURE),
                 id="forged-signature"),
    pytest.param(_logout_token(header={"alg": "none"}),
                 _rejected(RejectionReason.UNSUPPORTED_ALGORITHM), id="alg-none"),
    pytest.param(_logout_token(header={"alg": "HS256"}),
                 _rejected(RejectionReason.UNSUPPORTED_ALGORITHM), id="alg-hs256"),
    pytest.param(_logout_token({"iss": OTHER_REALM}),
                 _rejected(RejectionReason.INVALID_ISSUER), id="wrong-issuer"),
    pytest.param(_logout_token({"aud": "another-app"}),
                 _rejected(RejectionReason.INVALID_AUDIENCE), id="wrong-audience"),
    pytest.param(_logout_token({"aud": [CLIENT_ID, "another-app"]}), _INVALID_LOGOUT_CLAIM,
                 id="extra-audience"),
    pytest.param(_logout_token({"events": ABSENT}), _INVALID_LOGOUT_CLAIM, id="events-missing"),
    pytest.param(_logout_token({"events": {}}), _INVALID_LOGOUT_CLAIM, id="events-empty"),
    pytest.param(_logout_token({"events": {_EVENT: {}, "urn:other": {}}}),
                 _INVALID_LOGOUT_CLAIM, id="events-with-another-event"),
    pytest.param(_logout_token({"events": {"urn:other": {}}}), _INVALID_LOGOUT_CLAIM,
                 id="events-of-another-event"),
    pytest.param(_logout_token({"events": {_EVENT: None}}), _INVALID_LOGOUT_CLAIM,
                 id="event-value-null"),
    pytest.param(_logout_token({"events": {_EVENT: []}}), _INVALID_LOGOUT_CLAIM,
                 id="event-value-array"),
    pytest.param(_logout_token({"events": [_EVENT]}), _INVALID_LOGOUT_CLAIM,
                 id="events-an-array"),
    pytest.param(_logout_token({"nonce": "n-0S6_WzA2Mj"}), _INVALID_LOGOUT_CLAIM, id="nonce"),
    pytest.param(_logout_token({"nonce": None}), _INVALID_LOGOUT_CLAIM, id="nonce-null"),
    pytest.param(_logout_token({"sub": ABSENT}), _INVALID_LOGOUT_CLAIM, id="sid-only"),
    pytest.param(_logout_token({"sub": ""}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="sub-empty"),
    pytest.param(_logout_token({"sub": 7}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="sub-not-a-string"),
    pytest.param(_logout_token({"exp": ABSENT}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="exp-missing"),
    pytest.param(_logout_token({"exp": "soon"}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="exp-malformed"),
    pytest.param(_logout_token({"exp": NOW - LEEWAY_SECONDS, "iat": NOW - 100}),
                 _rejected(RejectionReason.EXPIRED), id="exp-at-the-deadline"),
    pytest.param(_logout_token({"exp": NOW - 10}), _INVALID_LOGOUT_CLAIM,
                 id="exp-equal-to-iat"),
    pytest.param(_logout_token({"exp": NOW - 11}), _INVALID_LOGOUT_CLAIM,
                 id="exp-before-iat"),
    pytest.param(_logout_token({"iat": ABSENT}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="iat-missing"),
    pytest.param(_logout_token({"iat": "now"}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="iat-malformed"),
    pytest.param(_logout_token({"iat": float(NOW - 10)}),
                 _rejected(RejectionReason.INVALID_CLAIM), id="iat-not-an-integer"),
    pytest.param(_logout_token({"iat": NOW + LEEWAY_SECONDS + 1}),
                 _rejected(RejectionReason.ISSUED_IN_FUTURE), id="iat-past-the-leeway"),
    pytest.param(_logout_token({"iat": NOW - _MAX_LOGOUT_AGE - 1, "exp": NOW + 1}),
                 _INVALID_LOGOUT_CLAIM, id="iat-past-the-age-limit"),
    pytest.param(_logout_token(header={"typ": ABSENT}),
                 _rejected(RejectionReason.INVALID_TOKEN_TYPE), id="typ-missing"),
    pytest.param(_logout_token(header={"typ": "JWT"}),
                 _rejected(RejectionReason.INVALID_TOKEN_TYPE), id="typ-jwt"),
    pytest.param(_logout_token(header={"typ": ["logout+jwt"]}),
                 _rejected(RejectionReason.INVALID_TOKEN_TYPE), id="typ-not-a-string"),
    pytest.param("not.a.token", _rejected(RejectionReason.MALFORMED_TOKEN), id="malformed"),
]


@pytest.mark.parametrize(("logout_token", "refusal"), _LOGOUT_REFUSALS)
def test_a_logout_token_that_does_not_hold_is_refused_with_its_reason(
    logout_token: str, refusal: OidcRefusal,
) -> None:
    assert _a_logout_relying_party().verify_logout_token(logout_token) == refusal


def test_an_id_token_is_not_a_logout_token() -> None:
    login = LoginScenario(FakeTokenEndpoint())
    pending = login.relying_party.begin_login().pending

    outcome = login.relying_party.verify_logout_token(login.id_token(pending, {}))

    assert outcome == _rejected(RejectionReason.INVALID_TOKEN_TYPE)
