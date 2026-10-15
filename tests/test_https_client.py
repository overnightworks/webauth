"""The production token POST, driven against a loopback TLS server.

`post_token_request_over_https` is the `TokenRequestPost` a host hands its
`OidcRelyingParty`; every scenario sends a real form POST through
`webauth.https_client` to the server of `oidc_arrangement`, carrying canary
secrets in the client secret, the code and the PKCE verifier.
"""

from __future__ import annotations

import base64
import logging
import socket
import time
import traceback
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from types import MappingProxyType

import pytest
from oidc_arrangement import (
    REFUSED_TOKEN_ANSWER,
    SERVED_TOKEN_ANSWER,
    SILENT_HOLD_SECONDS,
    LoopbackHttpsServer,
    loopback_https_server,
)
from pydantic import SecretStr

import webauth.jwt_verification
from webauth.https_client import fetch_key_set_over_https
from webauth.oidc import TokenEndpointError, TokenRequest
from webauth.oidc_login import post_token_request_over_https

_CLIENT_ID = "songmaker"
_CLIENT_SECRET = "canary-client-secret"
_CODE = "canary-authorization-code"
_CODE_VERIFIER = "canary-code-verifier"
_CANARIES = (_CLIENT_SECRET, _CODE, _CODE_VERIFIER)
_FORM = {
    "grant_type": "authorization_code",
    "code": _CODE,
    "redirect_uri": "https://songmaker.example.org/auth/callback",
    "code_verifier": _CODE_VERIFIER,
}
_BASIC_CREDENTIALS = base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
_BASIC_AUTHORIZATION = f"Basic {_BASIC_CREDENTIALS}"


@pytest.fixture
def token_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LoopbackHttpsServer]:
    with loopback_https_server(tmp_path, monkeypatch) as server:
        yield server


@pytest.fixture
def closed_port() -> Iterator[int]:
    """A loopback port bound by nobody listening on it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        yield probe.getsockname()[1]


@pytest.fixture(autouse=True)
def every_log_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)


def _token_request(url: str) -> TokenRequest:
    return TokenRequest(
        url=url, form=MappingProxyType(_FORM), authorization=SecretStr(_BASIC_AUTHORIZATION)
    )


def _assert_no_canary_in(text: str) -> None:
    assert not [canary for canary in _CANARIES if canary in text]


def test_a_token_answer_comes_back_with_its_status_and_body(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    answer = post_token_request_over_https(_token_request(f"{token_server.base_url}/token"))

    assert (answer.status, answer.body) == (200, SERVED_TOKEN_ANSWER)
    _assert_no_canary_in(repr(answer) + caplog.text)


def test_an_issuer_refusal_comes_back_as_an_answer_not_an_error(
    token_server: LoopbackHttpsServer,
) -> None:
    answer = post_token_request_over_https(
        _token_request(f"{token_server.base_url}/token-refused")
    )

    assert (answer.status, answer.body) == (400, REFUSED_TOKEN_ANSWER)


def test_the_token_request_is_one_form_post_authenticated_with_basic(
    token_server: LoopbackHttpsServer,
) -> None:
    post_token_request_over_https(_token_request(f"{token_server.base_url}/token"))

    [received] = token_server.received
    assert (received.method, received.path) == ("POST", "/token")
    assert received.headers["authorization"] == _BASIC_AUTHORIZATION
    assert received.headers["accept"] == "application/json"
    assert received.headers["content-type"] == "application/x-www-form-urlencoded"
    assert dict(urllib.parse.parse_qsl(received.body.decode(), strict_parsing=True)) == _FORM


def _redirecting(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    return f"{server.base_url}/moved"


def _oversized(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    return f"{server.base_url}/oversized"


def _stalled(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    return f"{server.base_url}/silent"


def _untrusted(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.delenv("SSL_CERT_FILE")
    return f"{server.base_url}/token"


def _plain_http(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    return f"{server.base_url.replace('https://', 'http://')}/token"


@pytest.mark.parametrize(
    ("target", "refusal", "requests_sent"),
    [
        pytest.param(
            _redirecting,
            "the token request failed: the origin answered with a redirect,"
            " which is never followed",
            1,
            id="redirect",
        ),
        pytest.param(
            _oversized,
            "the token request failed: the origin's answer exceeds its size limit",
            1,
            id="oversized-body",
        ),
        pytest.param(
            _stalled,
            "the token request failed: the origin did not answer within the timeout",
            1,
            id="stalled-server",
        ),
        pytest.param(
            _untrusted,
            "the token request failed: the TLS handshake with the origin failed"
            " or its certificate is not trusted",
            0,
            id="untrusted-certificate",
        ),
        pytest.param(
            _plain_http,
            "the token request failed: refusing the request: not an https URL",
            0,
            id="plain-http",
        ),
    ],
)
def test_a_token_request_without_a_usable_answer_is_refused_in_the_librarys_words(
    token_server: LoopbackHttpsServer,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    target: Callable[[LoopbackHttpsServer, pytest.MonkeyPatch], str],
    refusal: str,
    requests_sent: int,
) -> None:
    started = time.monotonic()
    with pytest.raises(TokenEndpointError) as refused:
        post_token_request_over_https(
            _token_request(target(token_server, monkeypatch)), timeout_seconds=0.2
        )

    assert str(refused.value).startswith(refusal)
    assert len(token_server.received) == requests_sent
    assert time.monotonic() - started < SILENT_HOLD_SECONDS / 2
    _assert_no_canary_in("".join(traceback.format_exception(refused.value)) + caplog.text)
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None


def test_a_token_endpoint_nobody_listens_on_is_refused_as_unreachable(
    closed_port: int, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(
        TokenEndpointError, match="^the token request failed: the origin could not be reached$"
    ) as refused:
        post_token_request_over_https(_token_request(f"https://127.0.0.1:{closed_port}/token"))

    _assert_no_canary_in("".join(traceback.format_exception(refused.value)) + caplog.text)
    assert refused.value.__context__ is None


def test_the_key_set_fetch_is_still_wired_from_jwt_verification() -> None:
    assert webauth.jwt_verification.fetch_key_set_over_https is fetch_key_set_over_https
