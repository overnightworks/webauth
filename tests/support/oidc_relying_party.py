"""The relying party, client configuration and login scenario the OIDC relying-party tests drive."""

from __future__ import annotations

import base64
import dataclasses
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_NOW,
    APP_CLIENT_ID,
    CLIENT_SECRET,
    ISSUED_ACCESS_TOKEN_CANARY,
    ISSUED_REFRESH_TOKEN,
    REALM_ISSUER,
    FakeClock,
    FakeKeySetEndpoint,
    FakeTokenEndpoint,
    a_realm_client_config,
    changed,
    jws,
    key_set_document,
    public_jwk,
    rs256,
    rsa_key,
    token_endpoint_answer,
)
from webauth.cookies import PendingLogin
from webauth.oidc import (
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenRequestPost,
)

OTHER_REALM = "https://login.example.org/realms/elsewhere"
CODE = "authorization-code-from-the-callback"
SUBJECT = "7335d417-61da-459d-899c-0a01c76a2f94"
SESSION_ID = "4c2a9f0e-session"
# The grammar's two ends: a space and a tilde.
TOKEN_AT_BOTH_ENDS = " ~"  # noqa: S105
OUTSIDE_THE_REFRESH_TOKEN_GRAMMAR = {
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
GROUPS = ("/workshop/admins", "/workshop/makers")
BASIC_AUTHORIZATION = (
    "Basic " + base64.b64encode(f"{APP_CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
)


def issued(id_token: str, **changes: Any) -> TokenEndpointAnswer:
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


@dataclass(frozen=True)
class Attempt:
    """One login: changes to the callback the browser brings back, raw text
    appended to its query, changes to the ID token's claims, the token
    endpoint's answer given the ID token minted for this login, and the
    seconds the wall clock moves between the login's begin and its callback."""

    callback: dict[str, Any] = field(default_factory=dict)
    appended_to_callback: str = ""
    claims: dict[str, Any] = field(default_factory=dict)
    token_answer: Callable[[str], TokenEndpointAnswer | Exception] = issued
    elapsed_seconds: float = 0


def a_relying_party_for(
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
    config: OidcClientConfig = field(default_factory=a_realm_client_config)
    wall_clock: FakeClock = field(default_factory=lambda: FakeClock(float(ACCESS_TOKEN_NOW)))
    relying_party: OidcRelyingParty = field(init=False)
    minted_id_tokens: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.relying_party = a_relying_party_for(self.token_endpoint, self.config, self.wall_clock)

    def id_token(self, pending: PendingLogin, changes: dict[str, Any]) -> str:
        now = int(self.wall_clock.now)
        claims = {
            "iss": REALM_ISSUER,
            "aud": APP_CLIENT_ID,
            "sub": SUBJECT,
            "exp": now + 300,
            "iat": now - 10,
            "nonce": pending.nonce,
            "sid": SESSION_ID,
            "preferred_username": "operator",
            "groups": list(GROUPS),
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
            "iss": REALM_ISSUER,
            "code": CODE,
        }
        return urllib.parse.urlencode(changed(parameters, changes))

    def attempt(self, attempt: Attempt) -> tuple[PendingLogin, OidcIdentity | OidcRefusal]:
        pending = self.relying_party.begin_login().pending
        self.wall_clock.now += attempt.elapsed_seconds
        self.token_endpoint.answer = attempt.token_answer(self.id_token(pending, attempt.claims))
        callback_query = self.callback(pending, attempt.callback) + attempt.appended_to_callback
        return pending, self.relying_party.complete_login(pending, callback_query)
