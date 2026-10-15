"""OpenID Connect login through `OidcRelyingParty`, the way a host's routes drive it.

Every scenario begins a login, answers it with the callback query a browser
would bring back and completes it. The token endpoint, the key-set endpoint
and the clocks are fakes, so each refusal is observed offline; the ID tokens
are real RS256 tokens verified by the relying party's own `JwtVerifier`.
"""

from __future__ import annotations

import base64
import dataclasses
import logging
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from oidc_arrangement import (
    ABSENT,
    FakeClock,
    FakeKeySetEndpoint,
    FakeTokenEndpoint,
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
    MAX_AUTHORIZATION_CODE_CHARS,
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenEndpointError,
)

_ISSUER = "https://login.example.org/realms/workshop"
_OTHER_REALM = "https://login.example.org/realms/elsewhere"
_AUTHORIZATION_ENDPOINT = f"{_ISSUER}/protocol/openid-connect/auth"
_TOKEN_ENDPOINT = f"{_ISSUER}/protocol/openid-connect/token"
_JWKS_URL = f"{_ISSUER}/protocol/openid-connect/certs"
_CLIENT_ID = "songmaker"
_CLIENT_SECRET = "client-s3cr3t-value"
_REDIRECT_URI = "https://songmaker.example.org/auth/callback"
_LEEWAY_SECONDS = 30
_NOW = 1_800_000_000
_CODE = "authorization-code-from-the-callback"
_SUBJECT = "7335d417-61da-459d-899c-0a01c76a2f94"
_SESSION_ID = "4c2a9f0e-session"
_GROUPS = ("/workshop/admins", "/workshop/makers")
_IDENTITY = OidcIdentity(
    subject=_SUBJECT,
    issuer=_ISSUER,
    groups=_GROUPS,
    session_id=_SESSION_ID,
    preferred_username="operator",
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
        "client_id": _CLIENT_ID,
        "client_secret": SecretStr(_CLIENT_SECRET),
        "redirect_uri": _REDIRECT_URI,
        "scopes": ("openid", "profile"),
        "leeway_seconds": _LEEWAY_SECONDS,
    }
    return OidcClientConfig(**{**arguments, **changes})


def _issued(id_token: str) -> TokenEndpointAnswer:
    return token_endpoint_answer(
        200,
        {
            "access_token": "an-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token,
        },
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


@dataclass
class LoginScenario:
    token_endpoint: FakeTokenEndpoint
    config: OidcClientConfig = field(default_factory=_config)
    wall_clock: FakeClock = field(default_factory=lambda: FakeClock(float(_NOW)))
    relying_party: OidcRelyingParty = field(init=False)

    def __post_init__(self) -> None:
        self.relying_party = OidcRelyingParty(
            self.config,
            post_token_request=self.token_endpoint,
            fetch_key_set=FakeKeySetEndpoint(
                key_set_document(public_jwk(rsa_key("current"), "current-key"))
            ),
            wall_clock=self.wall_clock,
            monotonic_clock=FakeClock(5_000.0),
        )

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
        return jws(
            {"alg": "RS256", "kid": "current-key", "typ": "JWT"},
            changed(claims, changes),
            rs256(rsa_key("current")),
        )

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

    assert outcome == _IDENTITY


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

    assert outcome == identity


def _answered(
    status: int, document: dict[str, Any] | bytes
) -> Callable[[str], TokenEndpointAnswer]:
    return lambda _id_token: token_endpoint_answer(status, document)


def _answered_raw(status: int, json_text: str) -> TokenEndpointAnswer:
    return TokenEndpointAnswer(status, json_text.encode())


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
        Attempt(token_answer=lambda id_token: _answered_raw(
            200, f'{{"id_token": "{id_token}", "id_token": "{id_token}"}}'
        )),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="answer-naming-id-token-twice",
    ),
    pytest.param(
        Attempt(token_answer=lambda id_token: _answered_raw(
            200, f'{{"id_token": "{id_token}", "profile": {{"name": "a", "name": "b"}}}}'
        )),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="answer-naming-a-nested-member-twice",
    ),
    pytest.param(
        Attempt(token_answer=_answered(200, {"access_token": "an-access-token"})),
        OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED),
        id="answer-without-id-token",
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
            "Basic c29uZ21ha2VyOnNlJTNBY3IlMkJldCslMjU=",
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
        pytest.param("redirect_uri", "http://localhost:8000/auth/callback", id="redirect-uri-http"),
        pytest.param(
            "redirect_uri",
            "https://user:pass@songmaker.example.org/auth/callback",
            id="redirect-uri-with-credentials",
        ),
        pytest.param(
            "redirect_uri",
            "https://songmaker.example.org:99999/auth/callback",
            id="redirect-uri-with-invalid-port",
        ),
        pytest.param(
            "authorization_endpoint",
            "https://login.exa\nmple.org/auth",
            id="authorization-endpoint-with-a-newline-in-its-host",
        ),
        pytest.param(
            "redirect_uri",
            "https://songmaker.example.org/auth/call\rback",
            id="redirect-uri-with-a-carriage-return-in-its-path",
        ),
        pytest.param(
            "redirect_uri",
            "https://songmaker.example.org/auth/call\x85back",
            id="redirect-uri-with-a-c1-control-character",
        ),
        pytest.param("issuer", f"\n{_ISSUER}", id="issuer-led-by-a-newline"),
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
