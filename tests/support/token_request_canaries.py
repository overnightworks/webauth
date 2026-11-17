"""One token request whose every secret is a recognisable canary, and the check
that none of them reaches a text a test reads back.
"""

from __future__ import annotations

import base64
from types import MappingProxyType

from pydantic import SecretStr

from webauth.https_client import _post_form_over_https
from webauth.oidc import TokenRequest

CANARY_URL_QUERY = "session=canary-url-query"
CANARY_CODE = "canary-authorization-code"
CANARY_TOKEN_FORM = MappingProxyType(
    {
        "grant_type": "authorization_code",
        "code": CANARY_CODE,
        "redirect_uri": "https://notes.example.org/auth/callback",
        "code_verifier": "canary-code-verifier",
    }
)
_CANARY_CLIENT_ID = "notes-app"
_CANARY_CLIENT_SECRET = "canary-client-secret"  # noqa: S105
_CANARY_BASIC_CREDENTIALS = base64.b64encode(
    f"{_CANARY_CLIENT_ID}:{_CANARY_CLIENT_SECRET}".encode()
).decode()
CANARY_BASIC_AUTHORIZATION = f"Basic {_CANARY_BASIC_CREDENTIALS}"
# The client secret travels only inside the Basic credentials.
_CANARIES = (
    _CANARY_CLIENT_SECRET,
    _CANARY_BASIC_CREDENTIALS,
    CANARY_CODE,
    CANARY_TOKEN_FORM["code_verifier"],
    CANARY_URL_QUERY,
)


def a_canary_token_request(url: str) -> TokenRequest:
    return TokenRequest(
        url=url, form=CANARY_TOKEN_FORM, authorization=SecretStr(CANARY_BASIC_AUTHORIZATION)
    )


def post_canary_token_form(url: str, timeout_seconds: float = 5, **limits: float) -> object:
    return _post_form_over_https(
        url,
        CANARY_TOKEN_FORM,
        authorization=SecretStr(CANARY_BASIC_AUTHORIZATION),
        max_body_bytes=64 * 1024,
        timeout_seconds=timeout_seconds,
        **limits,
    )


def assert_no_canary_in(text: str) -> None:
    assert not [canary for canary in _CANARIES if canary in text]
