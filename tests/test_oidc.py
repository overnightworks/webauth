"""OpenID Connect login through `OidcRelyingParty`, the way a host's routes drive it.

Every scenario begins a login, answers it with the callback query a browser
would bring back and completes it. The token endpoint, the key-set endpoint
and the clocks are fakes, so each refusal is observed offline; the ID tokens
are real RS256 tokens verified by the relying party's own `JwtVerifier`.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from oidc_arrangement import (
    ABSENT,
    BACKCHANNEL_LOGOUT_EVENT,
    ISSUED_ACCESS_TOKEN_CANARY,
    ISSUED_REFRESH_TOKEN,
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    FakeTokenEndpoint,
    a_fake_id_token,
    a_logout_token,
    assert_holds_only_the_refresh_token,
    changed,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
    s256_code_challenge,
    token_endpoint_answer,
)
from pydantic import SecretStr

from webauth.cookies import PendingLogin
from webauth.jwt_verification import RejectionReason
from webauth.oidc import (
    LOGOUT_TOKEN_MAX_AGE_SECONDS,
    MAX_AUTHORIZATION_CODE_CHARS,
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    RenewedAccess,
    TokenEndpointAnswer,
    TokenEndpointError,
    TokenRequestPost,
    VerifiedLogout,
)

_ISSUER = "https://login.example.org/realms/workshop"
_OTHER_REALM = "https://login.example.org/realms/elsewhere"
_AUTHORIZATION_ENDPOINT = f"{_ISSUER}/protocol/openid-connect/auth"
_TOKEN_ENDPOINT = f"{_ISSUER}/protocol/openid-connect/token"
_JWKS_URL = f"{_ISSUER}/protocol/openid-connect/certs"
_CLIENT_ID = "notes-app"
# Canary whose recognisable text is the point
_CLIENT_SECRET = "client-s3cr3t-value"  # noqa: S105
_END_SESSION_ENDPOINT = f"{_ISSUER}/protocol/openid-connect/logout"
_REDIRECT_URI = "https://notes.example.org/auth/callback"
_POST_LOGOUT_REDIRECT_URI = "https://notes.example.org/"
_LOGOUT_PATH = "/auth/logout"
_LEEWAY_SECONDS = 30
_NOW = 1_800_000_000
_CODE = "authorization-code-from-the-callback"
_SUBJECT = "7335d417-61da-459d-899c-0a01c76a2f94"
_SESSION_ID = "4c2a9f0e-session"
# The grammar's two ends: a space and a tilde.
_TOKEN_AT_BOTH_ENDS = " ~"  # noqa: S105
_OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR = {
    "empty": "",
    "a-number": 42,
    "null": None,
    "with-a-nul": "rt\x00",
    "with-a-carriage-return": "rt\r",
    "with-a-line-feed": "rt\n",
    "with-a-del": "rt\x7f",
    "non-ascii": "rté",
    "a-lone-surrogate": "rt\ud800",
}
_GROUPS = ("/workshop/admins", "/workshop/makers")
_IDENTITY = OidcIdentity(
    subject=_SUBJECT,
    issuer=_ISSUER,
    groups=_GROUPS,
    session_id=_SESSION_ID,
    preferred_username="operator",
    id_token=a_fake_id_token("the-identity-every-login-yields"),
    refresh_token=SecretStr(ISSUED_REFRESH_TOKEN),
)
_BASIC_AUTHORIZATION = (
    "Basic " + base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
)
_MARKUP = "<script>alert('signed in')</script>"


def _config(**changes: Any) -> OidcClientConfig:
    arguments = {
        "issuer": _ISSUER,
        "authorization_endpoint": _AUTHORIZATION_ENDPOINT,
        "token_endpoint": _TOKEN_ENDPOINT,
        "jwks_url": _JWKS_URL,
        "end_session_endpoint": _END_SESSION_ENDPOINT,
        "client_id": _CLIENT_ID,
        "client_secret": SecretStr(_CLIENT_SECRET),
        "redirect_uri": _REDIRECT_URI,
        "post_logout_redirect_uri": _POST_LOGOUT_REDIRECT_URI,
        "logout_path": _LOGOUT_PATH,
        "scopes": ("openid", "profile"),
        "leeway_seconds": _LEEWAY_SECONDS,
    }
    return OidcClientConfig(**{**arguments, **changes})


def _issued(id_token: str, **changes: Any) -> TokenEndpointAnswer:
    return token_endpoint_answer(
        200,
        changed(
            {
                "access_token": ISSUED_ACCESS_TOKEN_CANARY,
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": ISSUED_REFRESH_TOKEN,
                "id_token": id_token,
            },
            changes,
        ),
    )


def _issued_with(**changes: Any) -> Callable[[str], TokenEndpointAnswer]:
    return lambda id_token: _issued(id_token, **changes)


def _naming_id_token_twice(id_token: str) -> TokenEndpointAnswer:
    return token_endpoint_answer(
        200, f'{{"id_token": "not-a-token", "id_token": {json.dumps(id_token)}}}'.encode()
    )


@dataclass(frozen=True)
class Attempt:
    """One login: changes to the callback the browser brings back, raw text
    appended to its query, changes to the ID token's claims, the token
    endpoint's answer given the ID token minted for this login, and the
    seconds the wall clock moves between the login's begin and its callback."""

    callback: dict[str, Any] = field(default_factory=dict)
    appended_to_callback: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    token_answer: Callable[[str], TokenEndpointAnswer | Exception] = _issued
    elapsed_seconds: float = 0


def _relying_party(
    token_endpoint: TokenRequestPost, config: OidcClientConfig, wall_clock: FakeClock
) -> OidcRelyingParty:
    return OidcRelyingParty(
        config,
        post_token_request=token_endpoint,
        fetch_key_set=FakeKeySetEndpoint(
            key_set_document(public_jwk(rsa_key("current"), "current-key"))
        ),
        wall_clock=wall_clock,
        monotonic_clock=FakeClock(5_000.0),
    )


@dataclass
class LoginScenario:
    token_endpoint: FakeTokenEndpoint
    config: OidcClientConfig = field(default_factory=_config)
    wall_clock: FakeClock = field(default_factory=lambda: FakeClock(float(_NOW)))
    relying_party: OidcRelyingParty = field(init=False)
    minted_id_tokens: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.relying_party = _relying_party(self.token_endpoint, self.config, self.wall_clock)

    def id_token(self, pending: PendingLogin, changes: dict[str, Any]) -> str:
        now = int(self.wall_clock.now)
        claims = {
            "iss": _ISSUER,
            "aud": _CLIENT_ID,
            "sub": _SUBJECT,
            "exp": now + 300,
            "iat": now - 10,
            "nonce": pending.nonce,
            "sid": _SESSION_ID,
            "preferred_username": "operator",
            "groups": list(_GROUPS),
        }
        id_token = jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"},
            changed(claims, changes),
            rs256(rsa_key("current")),
        )
        self.minted_id_tokens.append(id_token)
        return id_token

    def identity_with_the_minted_token(self, identity: OidcIdentity) -> OidcIdentity:
        return dataclasses.replace(identity, id_token=self.minted_id_tokens[-1])

    def callback(self, pending: PendingLogin, changes: dict[str, Any]) -> str:
        parameters = {
            "state": pending.state,
            "session_state": "e1b6c2d0-keycloak-session",
            "iss": _ISSUER,
            "code": _CODE,
        }
        return urllib.parse.urlencode(changed(parameters, changes))

    def attempt(self, attempt: Attempt) -> tuple[PendingLogin, OidcIdentity | OidcRefusal]:
        pending = self.relying_party.begin_login().pending
        self.wall_clock.now += attempt.elapsed_seconds
        self.token_endpoint.answer = attempt.token_answer(self.id_token(pending, attempt.claims))
        callback_query = self.callback(pending, attempt.callback) + attempt.appended_to_callback
        return pending, self.relying_party.complete_login(pending, callback_query)


@pytest.fixture
def login() -> LoginScenario:
    return LoginScenario(FakeTokenEndpoint())


def test_a_login_from_its_begin_through_the_callback_yields_the_verified_identity(
    login: LoginScenario,
) -> None:
    request = login.relying_party.begin_login()
    login.token_endpoint.answer = _issued(login.id_token(request.pending, {}))
    callback_query = login.callback(request.pending, {})

    outcome = login.relying_party.complete_login(request.pending, callback_query)

    assert outcome == login.identity_with_the_minted_token(_IDENTITY)


@pytest.mark.parametrize(
    ("attempt", "identity"),
    [
        pytest.param(
            Attempt(claims={"aud": [_CLIENT_ID, "agent-service"], "azp": _CLIENT_ID}),
            _IDENTITY,
            id="several-audiences-with-this-client-as-azp",
        ),
        pytest.param(Attempt(claims={"azp": _CLIENT_ID}), _IDENTITY, id="one-audience-with-azp"),
        pytest.param(Attempt(claims={"aud": [_CLIENT_ID]}), _IDENTITY, id="one-audience-list"),
        pytest.param(
            Attempt(claims={"exp": _NOW - _LEEWAY_SECONDS + 1}),
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
            Attempt(token_answer=_issued_with(refresh_token=_TOKEN_AT_BOTH_ENDS)),
            dataclasses.replace(_IDENTITY, refresh_token=SecretStr(_TOKEN_AT_BOTH_ENDS)),
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
        Attempt(callback={"iss": _OTHER_REALM}),
        OidcRefusal(OidcRefusalReason.ISSUER_MISMATCH),
        id="callback-iss-of-another-realm",
    ),
    pytest.param(
        Attempt(callback={"iss": _OTHER_REALM, "code": ABSENT, "error": "access_denied"}),
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
        for name, refresh_token in _OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.items()
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
        Attempt(claims={"iss": _OTHER_REALM}),
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
        Attempt(claims={"exp": _NOW - _LEEWAY_SECONDS}),
        OidcRefusal(OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=RejectionReason.EXPIRED),
        id="expired-past-the-leeway",
    ),
    pytest.param(
        Attempt(claims={"azp": "other-app"}),
        OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH),
        id="azp-of-another-app",
    ),
    pytest.param(
        Attempt(claims={"aud": [_CLIENT_ID, "agent-service"]}),
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
    for secret in (_CLIENT_SECRET, _CODE, pending.code_verifier, _MARKUP):
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
                state="", nonce="a-real-nonce", code_verifier="a-real-verifier", issued_at=_NOW
            ),
            id="empty-state",
        ),
        pytest.param(
            PendingLogin(state="", nonce="", code_verifier="", issued_at=_NOW),
            id="empty-state-and-nonce",
        ),
    ],
)
def test_an_empty_pending_state_never_matches_and_sends_no_token_request(
    login: LoginScenario, pending: PendingLogin
) -> None:
    login.token_endpoint.answer = _issued(login.id_token(pending, {}))

    outcome = login.relying_party.complete_login(pending, login.callback(pending, {}))

    assert outcome == OidcRefusal(OidcRefusalReason.STATE_MISMATCH)
    assert login.token_endpoint.requests == []


def test_an_empty_pending_nonce_never_matches_a_token_minted_with_an_empty_nonce(
    login: LoginScenario,
) -> None:
    pending = dataclasses.replace(login.relying_party.begin_login().pending, nonce="")
    login.token_endpoint.answer = _issued(login.id_token(pending, {}))

    outcome = login.relying_party.complete_login(pending, login.callback(pending, {}))

    assert outcome == OidcRefusal(OidcRefusalReason.NONCE_MISMATCH)


def test_the_authorization_url_carries_exactly_the_code_flow_parameters(
    login: LoginScenario,
) -> None:
    request = login.relying_party.begin_login()
    url = urllib.parse.urlsplit(request.url)
    pending = request.pending

    assert f"{url.scheme}://{url.netloc}{url.path}" == _AUTHORIZATION_ENDPOINT
    assert urllib.parse.parse_qs(url.query, strict_parsing=True) == {
        "response_type": ["code"],
        "client_id": [_CLIENT_ID],
        "redirect_uri": [_REDIRECT_URI],
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
        pytest.param(_CLIENT_ID, _CLIENT_SECRET, _BASIC_AUTHORIZATION, id="plain-credentials"),
        pytest.param(
            _CLIENT_ID,
            "se:cr+et %",
            "Basic bm90ZXMtYXBwOnNlJTNBY3IlMkJldCslMjU=",
            id="secret-form-encoded-before-basic-encoding",
        ),
        pytest.param(
            "web app:1",
            _CLIENT_SECRET,
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
        _config(client_id=client_id, client_secret=SecretStr(client_secret)),
    )
    pending, _outcome = login.attempt(Attempt())

    [request] = login.token_endpoint.requests
    assert request.url == _TOKEN_ENDPOINT
    assert dict(request.form) == {
        "grant_type": "authorization_code",
        "code": _CODE,
        "redirect_uri": _REDIRECT_URI,
        "code_verifier": pending.code_verifier,
    }
    assert request.authorization.get_secret_value() == authorization


def test_a_pending_login_is_stamped_with_the_wall_clock_second_it_began(
    login: LoginScenario,
) -> None:
    login.wall_clock.now = _NOW + 0.75

    assert login.relying_party.begin_login().pending.issued_at == _NOW


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

    shown = " ".join(repr(each) for each in (_config(), request, answer, pending))

    for secret in (
        _CLIENT_SECRET,
        _BASIC_AUTHORIZATION,
        _CODE,
        "an-access-token",
        pending.state,
        pending.nonce,
        pending.code_verifier,
    ):
        assert secret not in shown


def _text_of(value: object) -> str:
    return value.get_secret_value() if isinstance(value, SecretStr) else str(value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        pytest.param("issuer", "http://login.example.org/realms/workshop", id="issuer-http"),
        pytest.param(
            "authorization_endpoint",
            f"{_AUTHORIZATION_ENDPOINT}?prompt=login",
            id="authorization-endpoint-with-query",
        ),
        pytest.param(
            "token_endpoint", f"{_TOKEN_ENDPOINT}#fragment", id="token-endpoint-with-fragment"
        ),
        pytest.param("jwks_url", "ftp://login.example.org/certs", id="jwks-url-not-https"),
        pytest.param(
            "redirect_uri", "http://example.test/auth/callback", id="redirect-uri-http-remote"
        ),
        pytest.param(
            "redirect_uri",
            "https://user:pass@notes.example.org/auth/callback",
            id="redirect-uri-with-credentials",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org:99999/auth/callback",
            id="redirect-uri-with-invalid-port",
        ),
        pytest.param(
            "authorization_endpoint",
            "https://login.exa\nmple.org/auth",
            id="authorization-endpoint-with-a-newline-in-its-host",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org/auth/call\rback",
            id="redirect-uri-with-a-carriage-return-in-its-path",
        ),
        pytest.param(
            "redirect_uri",
            "https://notes.example.org/auth/call\x85back",
            id="redirect-uri-with-a-c1-control-character",
        ),
        pytest.param("issuer", f"\n{_ISSUER}", id="issuer-led-by-a-newline"),
        pytest.param(
            "end_session_endpoint", f"{_END_SESSION_ENDPOINT}?client_id=x",
            id="end-session-endpoint-with-a-query",
        ),
        pytest.param(
            "post_logout_redirect_uri", "http://notes.example.org/",
            id="post-logout-redirect-uri-over-http",
        ),
        pytest.param(
            "post_logout_redirect_uri", f"{_POST_LOGOUT_REDIRECT_URI}#signed-out",
            id="post-logout-redirect-uri-with-a-fragment",
        ),
        pytest.param("jwks_url", f"{_JWKS_URL}\x00", id="jwks-url-with-a-nul"),
        pytest.param("token_endpoint", f"{_TOKEN_ENDPOINT} ", id="token-endpoint-with-a-space"),
        pytest.param("client_id", "", id="client-id-empty"),
        pytest.param("client_secret", SecretStr(""), id="client-secret-empty"),
        pytest.param("client_secret", "a-plain-string-secret", id="client-secret-not-secret-str"),
        pytest.param("scopes", ("profile", "email"), id="scopes-without-openid"),
        pytest.param("scopes", "openid profile", id="scopes-as-one-string"),
        pytest.param("scopes", ("openid", "two words"), id="scope-with-a-space"),
    ],
)
def test_a_client_configuration_is_refused_by_the_field_it_breaks_never_its_value(
    field_name: str, value: object
) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must ") as refusal:
        _config(**{field_name: value})

    text = _text_of(value)
    assert not text or text not in str(refusal.value)


_LOOPBACK_HTTP_URLS = [
    "http://localhost",
    "http://LOCALHOST:8080/cb",
    "http://127.0.0.1:8080/cb",
    "http://[::1]:8080/cb",
    "HTTP://localhost/cb",
    "Http://127.0.0.1:8080/cb",
]


@pytest.mark.parametrize("field_name", ["redirect_uri", "post_logout_redirect_uri"])
@pytest.mark.parametrize("url", _LOOPBACK_HTTP_URLS)
def test_the_apps_own_two_urls_may_be_http_on_a_loopback_host(
    field_name: str, url: str
) -> None:
    config = _config(**{field_name: url})

    assert getattr(config, field_name) == url


@pytest.mark.parametrize(
    "field_name",
    ["issuer", "authorization_endpoint", "token_endpoint", "jwks_url", "end_session_endpoint"],
)
@pytest.mark.parametrize("url", _LOOPBACK_HTTP_URLS)
def test_an_issuer_url_stays_https_even_on_a_loopback_host(field_name: str, url: str) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must "):
        _config(**{field_name: url})


@pytest.mark.parametrize("field_name", ["redirect_uri", "post_logout_redirect_uri"])
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.2/cb",
        "http://localhost.example/cb",
        "http://0.0.0.0/cb",
        "http://example.test/cb",
        "http://user:pass@localhost:8080/cb",
        "http://localhost:8080/cb?next=/",
        "http://localhost:8080/cb#top",
        "ftp://localhost/cb",
        "ws://localhost/cb",
        "http://127.0.0.1.nip.io/cb",
        "http://localhost./cb",
        "http://local\thost/cb",
        "http://local\nhost/cb",
        "http://localhost /cb",
        "http://localhost:99999/cb",
        "http://localhost@evil.test/cb",
    ],
)
def test_the_apps_own_two_urls_refuse_http_unless_the_host_is_loopback_and_the_rest_is_plain(
    field_name: str, url: str
) -> None:
    with pytest.raises(ValueError, match=f"^{field_name} must "):
        _config(**{field_name: url})


@pytest.mark.parametrize("client_id", [
    pytest.param(_CLIENT_ID, id="plain-client-id"),
    pytest.param("lab app&x=1/\u00e9", id="client-id-needing-encoding"),
])
def test_the_logout_url_carries_exactly_the_client_id_and_the_post_logout_redirect_uri(
    client_id: str,
) -> None:
    scenario = LoginScenario(FakeTokenEndpoint(), config=_config(client_id=client_id))

    parts = urllib.parse.urlsplit(scenario.relying_party.logout_url())

    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == _END_SESSION_ENDPOINT
    assert urllib.parse.parse_qs(parts.query) == {
        "client_id": [client_id],
        "post_logout_redirect_uri": [_POST_LOGOUT_REDIRECT_URI],
    }


@pytest.mark.parametrize("client_id", [
    pytest.param(_CLIENT_ID, id="plain-client-id"),
    pytest.param("lab app&x=1/\u00e9", id="client-id-needing-encoding"),
])
def test_the_logout_url_carries_the_id_token_hint_after_the_other_parameters(
    client_id: str,
) -> None:
    scenario = LoginScenario(FakeTokenEndpoint(), config=_config(client_id=client_id))
    hint = a_fake_id_token("the-hint")

    parts = urllib.parse.urlsplit(scenario.relying_party.logout_url(id_token_hint=hint))

    assert list(urllib.parse.parse_qsl(parts.query)) == [
        ("client_id", client_id),
        ("post_logout_redirect_uri", _POST_LOGOUT_REDIRECT_URI),
        ("id_token_hint", hint),
    ]


def test_the_relying_party_exposes_the_configured_logout_path(login: LoginScenario) -> None:
    assert login.relying_party.logout_path == _LOGOUT_PATH


@pytest.mark.parametrize("logout_path", [
    pytest.param("/", id="the-root"),
    pytest.param("/logout", id="a-route"),
    pytest.param("/app/log-out_1.2~x/", id="unreserved-characters-and-a-trailing-slash"),
    pytest.param("/a%20b/c:d@e!$&'()*+,=", id="percent-encoding-and-sub-delimiters"),
])
def test_a_logout_path_of_url_path_characters_is_accepted(logout_path: str) -> None:
    assert _config(logout_path=logout_path).logout_path == logout_path


@pytest.mark.parametrize("logout_path", [
    pytest.param("", id="empty"),
    pytest.param("relative-route", id="not-absolute"),
    pytest.param("https://notes.example.org/logout", id="a-url"),
    pytest.param("/semi;colon", id="semicolon"),
    pytest.param("/with?query=1", id="query"),
    pytest.param("/with#fragment", id="fragment"),
    pytest.param("/with space", id="space"),
    pytest.param("/log\nout", id="newline"),
    pytest.param("/log\x00out", id="nul"),
    pytest.param("/log%zzout", id="bad-percent-encoding"),
    pytest.param("/log%", id="trailing-percent"),
    pytest.param("/log%2", id="percent-with-one-hex-digit"),
    pytest.param("/log\u00e9out", id="non-ascii"),
    pytest.param(None, id="not-a-string"),
])
def test_a_logout_path_that_is_not_a_url_path_is_refused_without_its_value(
    logout_path: object,
) -> None:
    with pytest.raises(ValueError, match="^logout_path must ") as refusal:
        _config(logout_path=logout_path)

    assert not logout_path or str(logout_path) not in str(refusal.value)


@pytest.mark.parametrize(
    "missing", ["end_session_endpoint", "post_logout_redirect_uri", "logout_path"],
)
def test_a_client_configuration_missing_a_logout_field_fails_at_construction(
    missing: str,
) -> None:
    arguments = {
        "issuer": _ISSUER,
        "authorization_endpoint": _AUTHORIZATION_ENDPOINT,
        "token_endpoint": _TOKEN_ENDPOINT,
        "jwks_url": _JWKS_URL,
        "end_session_endpoint": _END_SESSION_ENDPOINT,
        "client_id": _CLIENT_ID,
        "client_secret": SecretStr(_CLIENT_SECRET),
        "redirect_uri": _REDIRECT_URI,
        "post_logout_redirect_uri": _POST_LOGOUT_REDIRECT_URI,
        "logout_path": _LOGOUT_PATH,
        "leeway_seconds": _LEEWAY_SECONDS,
    }
    del arguments[missing]

    with pytest.raises(TypeError, match=missing):
        OidcClientConfig(**arguments)


def _logout_token(
    claims: dict[str, Any] | None = None,
    header: dict[str, Any] | None = None,
    key_name: str = "current",
) -> str:
    return a_logout_token(
        issuer=_ISSUER,
        audience=_CLIENT_ID,
        subject=_SUBJECT,
        now=_NOW,
        key_name=key_name,
        claims=claims,
        header=header,
    )


_EVENT = BACKCHANNEL_LOGOUT_EVENT
_MAX_LOGOUT_AGE = LOGOUT_TOKEN_MAX_AGE_SECONDS + _LEEWAY_SECONDS


def _a_logout_relying_party() -> OidcRelyingParty:
    return LoginScenario(FakeTokenEndpoint()).relying_party


@pytest.mark.parametrize(("claims", "header"), [
    pytest.param({}, {}, id="the token as keycloak signs it"),
    pytest.param({"sid": ABSENT}, {}, id="a subject without a session id"),
    pytest.param({"sid": 7}, {}, id="a session id of any type is never read"),
    pytest.param({"aud": [_CLIENT_ID]}, {}, id="a singleton audience array"),
    pytest.param({"events": {_EVENT: {"reason": "admin"}}}, {}, id="an events object with data"),
    pytest.param({"note": "other claims are ignored"}, {}, id="an unknown claim"),
    pytest.param({"iat": _NOW + _LEEWAY_SECONDS}, {}, id="issued in the future within leeway"),
    pytest.param({"iat": _NOW - _MAX_LOGOUT_AGE, "exp": _NOW + 1}, {}, id="issued at the limit"),
    pytest.param({"exp": _NOW + _LEEWAY_SECONDS - 1, "iat": _NOW - 100}, {},
                 id="one second before the deadline plus leeway"),
])
def test_a_logout_token_of_the_bound_issuer_yields_its_subject(
    claims: dict[str, Any], header: dict[str, Any],
) -> None:
    outcome = _a_logout_relying_party().verify_logout_token(_logout_token(claims, header))

    assert outcome == VerifiedLogout(subject=_SUBJECT)


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
    pytest.param(_logout_token({"iss": _OTHER_REALM}),
                 _rejected(RejectionReason.INVALID_ISSUER), id="wrong-issuer"),
    pytest.param(_logout_token({"aud": "another-app"}),
                 _rejected(RejectionReason.INVALID_AUDIENCE), id="wrong-audience"),
    pytest.param(_logout_token({"aud": [_CLIENT_ID, "another-app"]}), _INVALID_LOGOUT_CLAIM,
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
    pytest.param(_logout_token({"exp": _NOW - _LEEWAY_SECONDS, "iat": _NOW - 100}),
                 _rejected(RejectionReason.EXPIRED), id="exp-at-the-deadline"),
    pytest.param(_logout_token({"exp": _NOW - 10}), _INVALID_LOGOUT_CLAIM,
                 id="exp-equal-to-iat"),
    pytest.param(_logout_token({"exp": _NOW - 11}), _INVALID_LOGOUT_CLAIM,
                 id="exp-before-iat"),
    pytest.param(_logout_token({"iat": ABSENT}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="iat-missing"),
    pytest.param(_logout_token({"iat": "now"}), _rejected(RejectionReason.INVALID_CLAIM),
                 id="iat-malformed"),
    pytest.param(_logout_token({"iat": float(_NOW - 10)}),
                 _rejected(RejectionReason.INVALID_CLAIM), id="iat-not-an-integer"),
    pytest.param(_logout_token({"iat": _NOW + _LEEWAY_SECONDS + 1}),
                 _rejected(RejectionReason.ISSUED_IN_FUTURE), id="iat-past-the-leeway"),
    pytest.param(_logout_token({"iat": _NOW - _MAX_LOGOUT_AGE - 1, "exp": _NOW + 1}),
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


def _renewed_access_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    outcome = relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN))
    return outcome.access_token if isinstance(outcome, RenewedAccess) else outcome


def _workload_access_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    return relying_party.workload_access_token()


_BOTH_GRANTS = pytest.mark.parametrize(
    "grant",
    [
        pytest.param(_renewed_access_token, id="refresh-grant"),
        pytest.param(_workload_access_token, id="workload-grant"),
    ],
)


def _granting(endpoint: TokenRequestPost) -> OidcRelyingParty:
    return _relying_party(endpoint, _config(), FakeClock(float(_NOW)))


def _grant_answer(status: int = 200, **changes: Any) -> FakeTokenEndpoint:
    document = changed({"access_token": "granted-token", "token_type": "Bearer"}, changes)
    return FakeTokenEndpoint(answer=token_endpoint_answer(status, document))


def _an_issuer() -> FakeIssuer:
    return FakeIssuer(mint_id_token=a_fake_id_token)


def test_renewing_access_posts_the_refresh_grant_and_yields_the_rotated_tokens() -> None:
    issuer = _an_issuer()

    outcome = _granting(issuer).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    [request] = issuer.requests
    assert request.url == _TOKEN_ENDPOINT
    assert dict(request.form) == {
        "grant_type": "refresh_token",
        "refresh_token": ISSUED_REFRESH_TOKEN,
    }
    assert request.authorization.get_secret_value() == _BASIC_AUTHORIZATION
    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token is not None
    assert outcome.refresh_token.get_secret_value() != ISSUED_REFRESH_TOKEN
    assert isinstance(_granting(issuer).renew_access(outcome.refresh_token), RenewedAccess)


def test_a_refresh_answer_without_a_refresh_token_yields_none() -> None:
    issuer = _an_issuer()
    issuer.refresh_answer_members = {"refresh_token": ABSENT}

    outcome = _granting(issuer).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token is None


@_BOTH_GRANTS
@pytest.mark.parametrize("token_type", ["Bearer", "bearer", "BEARER"])
def test_a_grant_accepts_a_bearer_token_type_in_any_ascii_case(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal], token_type: str
) -> None:
    outcome = grant(_granting(_grant_answer(token_type=token_type)))

    assert outcome == SecretStr("granted-token")


_NOT_A_BEARER_ACCESS_TOKEN = {
    "token-type-missing": {"token_type": ABSENT},
    "token-type-a-number": {"token_type": 7},
    "token-type-mac": {"token_type": "MAC"},
    "token-type-with-a-trailing-space": {"token_type": "Bearer "},
    "token-type-a-non-ascii-look-alike": {"token_type": "B\u0435arer"},
    "access-token-missing": {"access_token": ABSENT},
    "access-token-a-number": {"access_token": 7},
    "access-token-empty": {"access_token": ""},
    "access-token-with-a-carriage-return": {"access_token": "token\r"},
    "access-token-with-a-line-feed": {"access_token": "token\n"},
    "access-token-with-a-space": {"access_token": "to ken"},
}


@_BOTH_GRANTS
@pytest.mark.parametrize(
    "changes", _NOT_A_BEARER_ACCESS_TOKEN.values(), ids=list(_NOT_A_BEARER_ACCESS_TOKEN)
)
def test_a_grant_answer_that_is_no_bearer_access_token_is_refused(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal], changes: dict[str, Any]
) -> None:
    assert grant(_granting(_grant_answer(**changes))) == OidcRefusal(
        OidcRefusalReason.TOKEN_ENDPOINT_FAILED
    )


@pytest.mark.parametrize(
    "refresh_token",
    _OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.values(),
    ids=list(_OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR),
)
def test_a_refresh_answer_with_a_refresh_token_outside_the_grammar_is_refused(
    refresh_token: object,
) -> None:
    endpoint = _grant_answer(refresh_token=refresh_token)

    outcome = _granting(endpoint).renew_access(SecretStr(ISSUED_REFRESH_TOKEN))

    assert outcome == OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)


@pytest.mark.parametrize(
    "refresh_token",
    [value for value in _OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.values() if isinstance(value, str)],
    ids=[
        name for name, value in _OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR.items() if isinstance(value, str)
    ],
)
def test_a_refresh_token_outside_the_grammar_is_refused_without_a_request(
    refresh_token: str,
) -> None:
    endpoint = _grant_answer()

    outcome = _granting(endpoint).renew_access(SecretStr(refresh_token))

    assert outcome == OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)
    assert endpoint.requests == []


def test_a_refresh_token_at_both_ends_of_the_grammar_is_sent_and_received_exactly() -> None:
    issuer = _an_issuer()
    issuer.refresh_tokens.add(_TOKEN_AT_BOTH_ENDS)
    issuer.refresh_answer_members = {"refresh_token": _TOKEN_AT_BOTH_ENDS}

    outcome = _granting(issuer).renew_access(SecretStr(_TOKEN_AT_BOTH_ENDS))

    [request] = issuer.requests
    assert request.form["refresh_token"] == _TOKEN_AT_BOTH_ENDS
    assert isinstance(outcome, RenewedAccess)
    assert outcome.refresh_token == SecretStr(_TOKEN_AT_BOTH_ENDS)


_REFUSED_GRANT_ANSWERS = [
    pytest.param(
        token_endpoint_answer(status, {"error": error}),
        OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error=error),
        id=f"{status}-{error}",
    )
    for status, error in [
        (400, "invalid_grant"),
        (401, "invalid_client"),
        (400, "unauthorized_client"),
    ]
] + [
    pytest.param(answer, OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED), id=name)
    for name, answer in {
        "server-error": token_endpoint_answer(503, {"error": "server_error"}),
        "non-json-answer": token_endpoint_answer(200, b"<html>signed in</html>"),
        "transport-error": TokenEndpointError("connection refused"),
    }.items()
]


@_BOTH_GRANTS
@pytest.mark.parametrize(("answer", "refusal"), _REFUSED_GRANT_ANSWERS)
def test_a_grant_the_issuer_refuses_or_fails_is_refused_with_its_reason(
    grant: Callable[[OidcRelyingParty], SecretStr | OidcRefusal],
    answer: TokenEndpointAnswer | Exception,
    refusal: OidcRefusal,
) -> None:
    assert grant(_granting(FakeTokenEndpoint(answer=answer))) == refusal


def test_a_refresh_token_the_issuer_never_issued_or_ended_is_invalid_grant() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)
    invalid_grant = OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="invalid_grant")

    assert relying_party.renew_access(SecretStr("never-issued")) == invalid_grant
    issuer.end_sso_session()
    assert relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN)) == invalid_grant


def test_a_workload_token_is_refused_while_the_client_has_no_service_account() -> None:
    issuer = _an_issuer()
    issuer.service_accounts_enabled = False

    assert _granting(issuer).workload_access_token() == OidcRefusal(
        OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error="unauthorized_client"
    )


def test_the_workload_grant_posts_only_the_grant_type_with_the_clients_authorization() -> None:
    issuer = _an_issuer()

    outcome = _granting(issuer).workload_access_token()

    [request] = issuer.requests
    assert request.url == _TOKEN_ENDPOINT
    assert dict(request.form) == {"grant_type": "client_credentials"}
    assert request.authorization.get_secret_value() == _BASIC_AUTHORIZATION
    assert isinstance(outcome, SecretStr)


def test_two_workload_calls_post_twice_and_yield_two_different_tokens() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)

    first = relying_party.workload_access_token()
    second = relying_party.workload_access_token()

    assert len(issuer.requests) == 2
    assert isinstance(first, SecretStr)
    assert isinstance(second, SecretStr)
    assert first != second


def test_no_repr_shows_a_token_a_grant_sent_or_received() -> None:
    issuer = _an_issuer()
    relying_party = _granting(issuer)
    renewed = relying_party.renew_access(SecretStr(ISSUED_REFRESH_TOKEN))
    workload = relying_party.workload_access_token()
    assert isinstance(renewed, RenewedAccess)
    assert renewed.refresh_token is not None
    assert isinstance(workload, SecretStr)

    shown = " ".join(repr(each) for each in (renewed, workload, *issuer.requests))

    for secret in (
        ISSUED_REFRESH_TOKEN,
        renewed.access_token.get_secret_value(),
        renewed.refresh_token.get_secret_value(),
        workload.get_secret_value(),
        _CLIENT_SECRET,
        _BASIC_AUTHORIZATION,
    ):
        assert secret not in shown
