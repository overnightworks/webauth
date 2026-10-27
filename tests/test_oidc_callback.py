"""OpenID Connect login through `OidcRelyingParty`, the way a host's routes drive it.

Every scenario begins a login, answers it with the callback query a browser
would bring back and completes it. The token endpoint, the key-set endpoint
and the clocks are fakes, so each refusal is observed offline; the ID tokens
are real RS256 tokens verified by the relying party's own `JwtVerifier`.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import urllib.parse
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import SecretStr

from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_NOW,
    APP_CLIENT_ID,
    AUTHORIZATION_ENDPOINT,
    CLIENT_SECRET,
    ISSUED_ACCESS_TOKEN_CANARY,
    ISSUED_REFRESH_TOKEN,
    REALM_ISSUER,
    REDIRECT_URI,
    TOKEN_ENDPOINT,
    FakeTokenEndpoint,
    a_fake_id_token,
    a_realm_client_config,
    assert_holds_only_the_refresh_token,
    s256_code_challenge,
    token_endpoint_answer,
)
from tests.support.oidc_relying_party import (
    BASIC_AUTHORIZATION,
    CODE,
    GROUPS,
    OTHER_REALM,
    OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR,
    SESSION_ID,
    SUBJECT,
    TOKEN_AT_BOTH_ENDS,
    Attempt,
    LoginScenario,
    issued,
)
from webauth.cookies import PendingLogin
from webauth.jwt_verification import RejectionReason
from webauth.oidc import (
    MAX_AUTHORIZATION_CODE_CHARS,
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcIdentity,
    OidcRefusal,
    OidcRefusalReason,
    TokenEndpointAnswer,
    TokenEndpointError,
)

_IDENTITY = OidcIdentity(
    subject=SUBJECT,
    issuer=REALM_ISSUER,
    groups=GROUPS,
    session_id=SESSION_ID,
    preferred_username="operator",
    id_token=a_fake_id_token("the-identity-every-login-yields"),
    refresh_token=SecretStr(ISSUED_REFRESH_TOKEN),
)


_MARKUP = "<script>alert('signed in')</script>"


def _issued_with(**changes: Any) -> Callable[[str], TokenEndpointAnswer]:
    return lambda id_token: issued(id_token, **changes)


def _naming_id_token_twice(id_token: str) -> TokenEndpointAnswer:
    return token_endpoint_answer(
        200, f'{{"id_token": "not-a-token", "id_token": {json.dumps(id_token)}}}'.encode()
    )


@pytest.fixture
def login() -> LoginScenario:
    return LoginScenario(FakeTokenEndpoint())


def test_a_login_from_its_begin_through_the_callback_yields_the_verified_identity(
    login: LoginScenario,
) -> None:
    request = login.relying_party.begin_login()
    login.token_endpoint.answer = issued(login.id_token(request.pending, {}))
    callback_query = login.callback(request.pending, {})

    outcome = login.relying_party.complete_login(request.pending, callback_query)

    assert outcome == login.identity_with_the_minted_token(_IDENTITY)


@pytest.mark.parametrize(
    ("attempt", "identity"),
    [
        pytest.param(
            Attempt(claims={"aud": [APP_CLIENT_ID, "agent-service"], "azp": APP_CLIENT_ID}),
            _IDENTITY,
            id="several-audiences-with-this-client-as-azp",
        ),
        pytest.param(Attempt(claims={"azp": APP_CLIENT_ID}), _IDENTITY, id="one-audience-with-azp"),
        pytest.param(Attempt(claims={"aud": [APP_CLIENT_ID]}), _IDENTITY, id="one-audience-list"),
        pytest.param(
            Attempt(claims={"exp": ACCESS_TOKEN_NOW - ACCESS_TOKEN_LEEWAY_SECONDS + 1}),
            _IDENTITY,
            id="expired-within-the-leeway",
        ),
        pytest.param(
            Attempt(claims={"groups": ABSENT}),
            dataclasses.replace(_IDENTITY, groups=()),
            id="without-groups",
        ),
        pytest.param(
            Attempt(claims={"sid": ABSENT, "preferred_username": ABSENT}),
            dataclasses.replace(_IDENTITY, session_id=None, preferred_username=None),
            id="without-sid-and-preferred-username",
        ),
        pytest.param(
            Attempt(token_answer=_naming_id_token_twice),
            dataclasses.replace(_IDENTITY, refresh_token=None),
            id="token-answer-naming-id-token-twice-keeps-the-last",
        ),
        pytest.param(
            Attempt(token_answer=_issued_with(refresh_token=ABSENT)),
            dataclasses.replace(_IDENTITY, refresh_token=None),
            id="answer-without-a-refresh-token",
        ),
        pytest.param(
            Attempt(token_answer=_issued_with(access_token=ABSENT, token_type=ABSENT)),
            _IDENTITY,
            id="answer-without-access-token-and-token-type",
        ),
        pytest.param(
            Attempt(token_answer=_issued_with(refresh_token=TOKEN_AT_BOTH_ENDS)),
            dataclasses.replace(_IDENTITY, refresh_token=SecretStr(TOKEN_AT_BOTH_ENDS)),
            id="refresh-token-at-both-ends-of-the-grammar",
        ),
        pytest.param(Attempt(callback={"iss": ABSENT}), _IDENTITY, id="callback-without-iss"),
        pytest.param(
            Attempt(callback={"code": "c" * MAX_AUTHORIZATION_CODE_CHARS}),
            _IDENTITY,
            id="code-at-the-length-limit",
        ),
        pytest.param(
            Attempt(elapsed_seconds=PENDING_LOGIN_MAX_AGE_SECONDS),
            _IDENTITY,
            id="callback-at-the-end-of-the-pending-lifetime",
        ),
    ],
)
def test_a_login_the_issuer_vouched_for_yields_its_identity(
    login: LoginScenario, attempt: Attempt, identity: OidcIdentity
) -> None:
    _pending, outcome = login.attempt(attempt)

    assert outcome == login.identity_with_the_minted_token(identity)


def test_the_issued_refresh_token_is_in_no_repr_and_the_access_token_is_nowhere(
    login: LoginScenario,
) -> None:
    _pending, outcome = login.attempt(Attempt())

    assert isinstance(outcome, OidcIdentity)
    assert ISSUED_REFRESH_TOKEN not in repr(outcome)
    assert ISSUED_ACCESS_TOKEN_CANARY not in repr(outcome)
    assert ISSUED_ACCESS_TOKEN_CANARY not in repr(dataclasses.asdict(outcome))
    assert_holds_only_the_refresh_token(outcome)


def _answered(
    status: int, document: dict[str, Any] | bytes
) -> Callable[[str], TokenEndpointAnswer]:
    return lambda _id_token: token_endpoint_answer(status, document)


def _padded_past_the_limit(id_token: str) -> TokenEndpointAnswer:
    return token_endpoint_answer(
        200, {"id_token": id_token, "padding": "x" * MAX_TOKEN_RESPONSE_BYTES}
    )


_CALLBACK_REFUSALS = [
    pytest.param(
        Attempt(callback={"state": "a-forged-state"}),
        OidcRefusal(OidcRefusalReason.STATE_MISMATCH),
        id="forged-state",
    ),
    pytest.param(
        Attempt(callback={"state": "a-forged-state", "code": ABSENT, "error": "access_denied"}),
        OidcRefusal(OidcRefusalReason.STATE_MISMATCH),
        id="forged-state-reporting-an-idp-error",
    ),
    pytest.param(
        Attempt(callback={"state": ABSENT}),
        OidcRefusal(OidcRefusalReason.STATE_MISMATCH),
        id="state-missing",
    ),
    pytest.param(
        Attempt(appended_to_callback="&state=a-forged-state"),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="state-repeated",
    ),
    pytest.param(
        Attempt(appended_to_callback="&code=another-code"),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="code-repeated",
    ),
    pytest.param(
        Attempt(callback={"code": ABSENT}),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="code-missing",
    ),
    pytest.param(
        Attempt(callback={"code": ""}),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="code-empty",
    ),
    pytest.param(
        Attempt(callback={"code": "c" * (MAX_AUTHORIZATION_CODE_CHARS + 1)}),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="code-past-the-length-limit",
    ),
    pytest.param(
        Attempt(elapsed_seconds=PENDING_LOGIN_MAX_AGE_SECONDS + 1),
        OidcRefusal(OidcRefusalReason.PENDING_LOGIN_EXPIRED),
        id="pending-login-past-its-lifetime",
    ),
    pytest.param(
        Attempt(elapsed_seconds=-1),
        OidcRefusal(OidcRefusalReason.PENDING_LOGIN_EXPIRED),
        id="pending-login-dated-in-the-future",
    ),
    pytest.param(
        Attempt(appended_to_callback="&note=%ff"),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="not-utf-8",
    ),
    pytest.param(
        Attempt(appended_to_callback="&note=\ud800"),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="lone-surrogate-not-percent-encoded",
    ),
    pytest.param(
        Attempt(appended_to_callback="&&"),
        OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK),
        id="empty-field",
    ),
    pytest.param(
        Attempt(callback={"iss": OTHER_REALM}),
        OidcRefusal(OidcRefusalReason.ISSUER_MISMATCH),
        id="callback-iss-of-another-realm",
    ),
    pytest.param(
        Attempt(callback={"iss": OTHER_REALM, "code": ABSENT, "error": "access_denied"}),
        OidcRefusal(OidcRefusalReason.ISSUER_MISMATCH),
        id="callback-iss-of-another-realm-reporting-an-idp-error",
    ),
    pytest.param(
        Attempt(callback={"code": ABSENT, "error": "access_denied", "error_description": _MARKUP}),
        OidcRefusal(OidcRefusalReason.AUTHORIZATION_DENIED, idp_error="access_denied"),
        id="idp-denied",
    ),
    pytest.param(
        Attempt(callback={"code": ABSENT, "error": _MARKUP}),
        OidcRefusal(OidcRefusalReason.AUTHORIZATION_DENIED),
        id="idp-error-that-is-no-error-code",
    ),
]


_EXCHANGE_REFUSALS = [
    pytest.param(
        Attempt(
            token_answer=_answered(
                400, {"error": "invalid_grant", "error_description": "Code not valid"}
            )
        ),
        OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="invalid_grant"),
        id="wrong-verifier-or-replayed-code",
    ),
    pytest.param(
        Attempt(token_answer=_answered(401, {"error": "invalid_client"})),
        OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="invalid_client"),
        id="wrong-client-secret",
    ),
    pytest.param(
        Attempt(token_answer=_answered(400, {"error": _MARKUP})),
        OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED),
        id="token-error-that-is-no-error-code",
    ),
    pytest.param(
        Attempt(token_answer=_answered(500, {"error": "server_error"})),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="server-error",
    ),
    pytest.param(
        Attempt(token_answer=_answered(200, b"<html>signed in</html>")),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="non-json-answer",
    ),
    pytest.param(
        Attempt(token_answer=_answered(400, b"Bad Request")),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="non-json-error",
    ),
    pytest.param(
        Attempt(token_answer=_answered(200, b"[" * (MAX_TOKEN_RESPONSE_BYTES // 2))),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="nested-past-the-parsers-recursion-limit",
    ),
    pytest.param(
        Attempt(token_answer=_answered(200, {"access_token": "an-access-token"})),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="answer-without-id-token",
    ),
    *(
        pytest.param(
            Attempt(token_answer=_issued_with(refresh_token=refresh_token)),
            OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
            id=f"refresh-token-{name}",
        )
        for name, refresh_token in OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.items()
    ),
    pytest.param(
        Attempt(token_answer=_padded_past_the_limit),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="answer-past-the-size-limit",
    ),
    pytest.param(
        Attempt(token_answer=lambda _id_token: TokenEndpointError("connection refused")),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="transport-error",
    ),
    pytest.param(
        Attempt(claims={"nonce": "the-nonce-of-another-login"}),
        OidcRefusal(OidcRefusalReason.NONCE_MISMATCH),
        id="token-minted-for-another-login",
    ),
    pytest.param(
        Attempt(claims={"nonce": ABSENT}),
        OidcRefusal(OidcRefusalReason.NONCE_MISMATCH),
        id="token-without-nonce",
    ),
    pytest.param(
        Attempt(claims={"nonce": "\ud800"}),
        OidcRefusal(OidcRefusalReason.NONCE_MISMATCH),
        id="nonce-a-lone-surrogate",
    ),
    pytest.param(
        Attempt(claims={"iss": OTHER_REALM}),
        OidcRefusal(
            OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=RejectionReason.INVALID_ISSUER
        ),
        id="token-of-another-realm",
    ),
    pytest.param(
        Attempt(claims={"aud": "other-app"}),
        OidcRefusal(
            OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=RejectionReason.INVALID_AUDIENCE
        ),
        id="token-for-another-app",
    ),
    pytest.param(
        Attempt(claims={"exp": ACCESS_TOKEN_NOW - ACCESS_TOKEN_LEEWAY_SECONDS}),
        OidcRefusal(OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=RejectionReason.EXPIRED),
        id="expired-past-the-leeway",
    ),
    pytest.param(
        Attempt(claims={"azp": "other-app"}),
        OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH),
        id="azp-of-another-app",
    ),
    pytest.param(
        Attempt(claims={"aud": [APP_CLIENT_ID, "agent-service"]}),
        OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH),
        id="several-audiences-without-azp",
    ),
    pytest.param(
        Attempt(claims={"groups": "/workshop/admins"}),
        OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM),
        id="groups-not-a-list",
    ),
    pytest.param(
        Attempt(claims={"groups": ["/workshop/admins", 7]}),
        OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM),
        id="groups-with-a-non-string",
    ),
    pytest.param(
        Attempt(claims={"sub": ABSENT}),
        OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM),
        id="subject-missing",
    ),
    pytest.param(
        Attempt(claims={"sid": 7}),
        OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM),
        id="sid-not-a-string",
    ),
]


@pytest.mark.parametrize(("attempt", "refusal"), _CALLBACK_REFUSALS + _EXCHANGE_REFUSALS)
def test_a_login_that_does_not_stand_is_refused_with_its_reason_and_leaks_nothing(
    login: LoginScenario,
    attempt: Attempt,
    refusal: OidcRefusal,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)

    pending, outcome = login.attempt(attempt)

    assert outcome == refusal
    for secret in (CLIENT_SECRET, CODE, pending.code_verifier, _MARKUP):
        assert secret not in repr(outcome)
        assert secret not in caplog.text


def test_a_token_endpoint_error_raised_without_a_failure_carries_none() -> None:
    assert TokenEndpointError("connection refused").failure is None


@pytest.mark.parametrize(("attempt", "refusal"), _CALLBACK_REFUSALS)
def test_a_callback_refused_on_its_own_sends_no_token_request(
    login: LoginScenario, attempt: Attempt, refusal: OidcRefusal
) -> None:
    _pending, outcome = login.attempt(attempt)

    assert outcome == refusal
    assert login.token_endpoint.requests == []


@pytest.mark.parametrize(
    "pending",
    [
        pytest.param(
            PendingLogin(
                state="",
                nonce="a-real-nonce",
                code_verifier="a-real-verifier",
                issued_at=ACCESS_TOKEN_NOW,
            ),
            id="empty-state",
        ),
        pytest.param(
            PendingLogin(state="", nonce="", code_verifier="", issued_at=ACCESS_TOKEN_NOW),
            id="empty-state-and-nonce",
        ),
    ],
)
def test_an_empty_pending_state_never_matches_and_sends_no_token_request(
    login: LoginScenario, pending: PendingLogin
) -> None:
    login.token_endpoint.answer = issued(login.id_token(pending, {}))

    outcome = login.relying_party.complete_login(pending, login.callback(pending, {}))

    assert outcome == OidcRefusal(OidcRefusalReason.STATE_MISMATCH)
    assert login.token_endpoint.requests == []


def test_an_empty_pending_nonce_never_matches_a_token_minted_with_an_empty_nonce(
    login: LoginScenario,
) -> None:
    pending = dataclasses.replace(login.relying_party.begin_login().pending, nonce="")
    login.token_endpoint.answer = issued(login.id_token(pending, {}))

    outcome = login.relying_party.complete_login(pending, login.callback(pending, {}))

    assert outcome == OidcRefusal(OidcRefusalReason.NONCE_MISMATCH)


def test_the_authorization_url_carries_exactly_the_code_flow_parameters(
    login: LoginScenario,
) -> None:
    request = login.relying_party.begin_login()
    url = urllib.parse.urlsplit(request.url)
    pending = request.pending

    assert url._replace(query="").geturl() == AUTHORIZATION_ENDPOINT
    assert urllib.parse.parse_qs(url.query, strict_parsing=True) == {
        "response_type": ["code"],
        "client_id": [APP_CLIENT_ID],
        "redirect_uri": [REDIRECT_URI],
        "scope": ["openid profile"],
        "state": [pending.state],
        "nonce": [pending.nonce],
        "code_challenge": [s256_code_challenge(pending.code_verifier)],
        "code_challenge_method": ["S256"],
    }
    assert url.fragment == ""


@pytest.mark.parametrize(
    ("client_id", "client_secret", "authorization"),
    [
        pytest.param(APP_CLIENT_ID, CLIENT_SECRET, BASIC_AUTHORIZATION, id="plain-credentials"),
        pytest.param(
            APP_CLIENT_ID,
            "se:cr+et %",
            "Basic bm90ZXMtYXBwOnNlJTNBY3IlMkJldCslMjU=",
            id="secret-form-encoded-before-basic-encoding",
        ),
        pytest.param(
            "web app:1",
            CLIENT_SECRET,
            "Basic d2ViK2FwcCUzQTE6Y2xpZW50LXMzY3IzdC12YWx1ZQ==",
            id="client-id-form-encoded-before-basic-encoding",
        ),
    ],
)
def test_the_token_endpoint_receives_the_code_and_verifier_with_basic_client_authentication(
    client_id: str, client_secret: str, authorization: str
) -> None:
    login = LoginScenario(
        FakeTokenEndpoint(),
        a_realm_client_config(client_id=client_id, client_secret=SecretStr(client_secret)),
    )
    pending, _outcome = login.attempt(Attempt())

    [request] = login.token_endpoint.requests
    assert request.url == TOKEN_ENDPOINT
    assert dict(request.form) == {
        "grant_type": "authorization_code",
        "code": CODE,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": pending.code_verifier,
    }
    assert request.authorization.get_secret_value() == authorization


def test_a_pending_login_is_stamped_with_the_wall_clock_second_it_began(
    login: LoginScenario,
) -> None:
    login.wall_clock.now = ACCESS_TOKEN_NOW + 0.75

    assert login.relying_party.begin_login().pending.issued_at == ACCESS_TOKEN_NOW


def test_two_logins_never_share_a_state_nonce_or_verifier(login: LoginScenario) -> None:
    first, second = (login.relying_party.begin_login().pending for _ in range(2))

    values = [first.state, first.nonce, first.code_verifier]
    values += [second.state, second.nonce, second.code_verifier]
    assert len(set(values)) == len(values)


def test_the_identity_carries_the_id_token_the_issuer_gave_and_no_repr_shows_it(
    login: LoginScenario,
) -> None:
    _pending, outcome = login.attempt(Attempt())

    assert isinstance(outcome, OidcIdentity)
    [minted] = login.minted_id_tokens
    assert outcome.id_token == minted
    assert minted not in repr(outcome)


def test_no_repr_shows_the_client_secret_the_code_the_tokens_or_the_pending_login(
    login: LoginScenario,
) -> None:
    pending, _outcome = login.attempt(Attempt())
    [request] = login.token_endpoint.requests
    answer = login.token_endpoint.answer

    shown = " ".join(repr(each) for each in (a_realm_client_config(), request, answer, pending))

    for secret in (
        CLIENT_SECRET,
        BASIC_AUTHORIZATION,
        CODE,
        "an-access-token",
        pending.state,
        pending.nonce,
        pending.code_verifier,
    ):
        assert secret not in shown
