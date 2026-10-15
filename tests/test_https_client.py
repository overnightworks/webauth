"""The production token POST, driven against a loopback TLS server.

`post_token_request_over_https` is the `TokenRequestPost` a host hands its
`OidcRelyingParty`; its scenarios send a real form POST through
`webauth.https_client` to the server of `oidc_arrangement`, carrying canary
secrets in the client secret, the code and the PKCE verifier.
"""

from __future__ import annotations

import base64
import logging
import time
import traceback
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from types import MappingProxyType

import pytest
import urllib3
from oidc_arrangement import (
    DRIP_INTERVAL_SECONDS,
    REFUSED_TOKEN_ANSWER,
    SERVED_TOKEN_ANSWER,
    SILENT_HOLD_SECONDS,
    LoopbackHttpsServer,
    closed_loopback_port,
    loopback_https_server,
)
from pydantic import SecretStr

import webauth.https_client
import webauth.jwt_verification
from webauth.https_client import (
    ExchangeFailure,
    HttpsExchangeError,
    KeySetFetchError,
    fetch_key_set_over_https,
    post_form_over_https,
)
from webauth.oidc import MAX_TOKEN_RESPONSE_BYTES, TokenEndpointError, TokenRequest
from webauth.oidc_login import post_token_request_over_https

_CLIENT_ID = "songmaker"
_CLIENT_SECRET = "canary-client-secret"
_CODE = "canary-authorization-code"
_CODE_VERIFIER = "canary-code-verifier"
_URL_QUERY = "session=canary-url-query"
_FORM = {
    "grant_type": "authorization_code",
    "code": _CODE,
    "redirect_uri": "https://songmaker.example.org/auth/callback",
    "code_verifier": _CODE_VERIFIER,
}
_BASIC_CREDENTIALS = base64.b64encode(f"{_CLIENT_ID}:{_CLIENT_SECRET}".encode()).decode()
_BASIC_AUTHORIZATION = f"Basic {_BASIC_CREDENTIALS}"
# The client secret travels only inside the Basic credentials.
_CANARIES = (_CLIENT_SECRET, _BASIC_CREDENTIALS, _CODE, _CODE_VERIFIER, _URL_QUERY)


@pytest.fixture
def token_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[LoopbackHttpsServer]:
    with loopback_https_server(tmp_path, monkeypatch) as server:
        yield server


@pytest.fixture
def closed_port() -> Iterator[int]:
    with closed_loopback_port() as port:
        yield port


@pytest.fixture(autouse=True)
def every_log_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)


def _token_request(url: str) -> TokenRequest:
    return TokenRequest(
        url=url, form=MappingProxyType(_FORM), authorization=SecretStr(_BASIC_AUTHORIZATION)
    )


def _assert_no_canary_in(text: str) -> None:
    assert not [canary for canary in _CANARIES if canary in text]


def _urllib3_records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [record for record in caplog.records if record.name.partition(".")[0] == "urllib3"]


def test_a_token_answer_comes_back_with_its_status_and_body(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    answer = post_token_request_over_https(
        _token_request(f"{token_server.base_url}/token?{_URL_QUERY}")
    )

    assert (answer.status, answer.body) == (200, SERVED_TOKEN_ANSWER)
    _assert_no_canary_in(repr(answer) + caplog.text)


def test_an_answer_reflecting_the_request_in_its_headers_leaves_no_urllib3_record_and_no_canary(
    token_server: LoopbackHttpsServer, caplog: pytest.LogCaptureFixture
) -> None:
    post_token_request_over_https(_token_request(f"{token_server.base_url}/token-reflecting"))

    [received] = token_server.received
    assert _CODE.encode() in received.body
    assert _urllib3_records(caplog) == []
    _assert_no_canary_in(caplog.text)


# Modules `import urllib3` does not load: webauth.https_client creates their
# loggers when it is imported, before urllib3 ever loads the modules.
@pytest.mark.parametrize(
    "module_name",
    [
        "urllib3.contrib.pyopenssl",
        "urllib3.http2.connection",
        "urllib3.contrib.emscripten.response",
    ],
)
def test_a_urllib3_module_loaded_later_logs_nothing_during_an_exchange(
    module_name: str,
    token_server: LoopbackHttpsServer,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    send = urllib3.PoolManager.request

    def send_logging_the_url(pool: urllib3.PoolManager, method: str, url: str, **kwargs: object):
        logging.getLogger(module_name).warning("sending to %s", url)
        return send(pool, method, url, **kwargs)

    monkeypatch.setattr(urllib3.PoolManager, "request", send_logging_the_url)

    post_token_request_over_https(_token_request(f"{token_server.base_url}/token?{_URL_QUERY}"))

    assert _urllib3_records(caplog) == []


def test_urllib3_still_logs_for_the_host_outside_an_exchange(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logging.getLogger("urllib3.connectionpool").warning("the host's own urllib3 record")

    assert "the host's own urllib3 record" in caplog.text


def test_an_issuer_refusal_comes_back_as_an_answer_not_an_error(
    token_server: LoopbackHttpsServer,
) -> None:
    answer = post_token_request_over_https(
        _token_request(f"{token_server.base_url}/token-refused")
    )

    assert (answer.status, answer.body) == (400, REFUSED_TOKEN_ANSWER)


def test_a_token_answer_of_exactly_the_size_limit_comes_back_whole(
    token_server: LoopbackHttpsServer,
) -> None:
    answer = post_token_request_over_https(
        _token_request(f"{token_server.base_url}/token-at-limit")
    )

    assert len(answer.body) == MAX_TOKEN_RESPONSE_BYTES


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


def _one_byte_past_the_limit(server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch) -> str:
    return f"{server.base_url}/token-past-limit"


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
            _one_byte_past_the_limit,
            "the token request failed: the origin's answer exceeds its size limit",
            1,
            id="one-byte-past-the-limit",
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
            _token_request(f"{target(token_server, monkeypatch)}?{_URL_QUERY}"),
            timeout_seconds=0.2,
        )

    assert str(refused.value).startswith(refusal)
    assert len(token_server.received) == requests_sent
    assert time.monotonic() - started < SILENT_HOLD_SECONDS / 2
    _assert_no_canary_in("".join(traceback.format_exception(refused.value)) + caplog.text)
    assert refused.value.__cause__ is None
    assert refused.value.__context__ is None


@pytest.mark.parametrize(
    ("exchange", "error", "refusal"),
    [
        pytest.param(
            lambda url: fetch_key_set_over_https(url, timeout_seconds=0.2),
            KeySetFetchError,
            "^the key set origin answered 302, not 200$",
            id="key-set-fetch",
        ),
        pytest.param(
            lambda url: post_token_request_over_https(_token_request(url), timeout_seconds=0.2),
            TokenEndpointError,
            "^the token request failed: the origin answered with a redirect,"
            " which is never followed$",
            id="token-post",
        ),
    ],
)
def test_an_answer_whose_body_is_never_read_is_judged_by_its_status_alone(
    token_server: LoopbackHttpsServer,
    exchange: Callable[[str], object],
    error: type[Exception],
    refusal: str,
) -> None:
    with pytest.raises(error, match=refusal):
        exchange(f"{token_server.base_url}/moved-stalling")


_TEST_DEADLINE_SECONDS = 1.0


def _fetch_key_set_under_the_test_deadline(url: str) -> object:
    return fetch_key_set_over_https(url, deadline_seconds=_TEST_DEADLINE_SECONDS)


def _post_token_form_under_the_test_deadline(url: str) -> object:
    return post_form_over_https(
        url,
        _FORM,
        authorization=SecretStr(_BASIC_AUTHORIZATION),
        max_body_bytes=MAX_TOKEN_RESPONSE_BYTES,
        timeout_seconds=5,
        deadline_seconds=_TEST_DEADLINE_SECONDS,
    )


@pytest.mark.parametrize("route", ["/dripping-head", "/dripping-body"])
@pytest.mark.parametrize(
    ("exchange", "error", "refusal"),
    [
        pytest.param(
            _fetch_key_set_under_the_test_deadline,
            KeySetFetchError,
            # The key-set fetch names every transport failure alike.
            "^fetching the key set failed: ",
            id="key-set-fetch",
        ),
        pytest.param(
            _post_token_form_under_the_test_deadline,
            HttpsExchangeError,
            f"^{ExchangeFailure.TIMED_OUT}$",
            id="token-post",
        ),
    ],
)
def test_an_origin_dripping_its_answer_is_cut_off_at_the_total_deadline(
    token_server: LoopbackHttpsServer,
    exchange: Callable[[str], object],
    error: type[Exception],
    refusal: str,
    route: str,
) -> None:
    started = time.monotonic()
    with pytest.raises(error, match=refusal):
        exchange(f"{token_server.base_url}{route}")
    held = time.monotonic() - started

    assert _TEST_DEADLINE_SECONDS <= held < _TEST_DEADLINE_SECONDS + DRIP_INTERVAL_SECONDS


def test_a_token_endpoint_nobody_listens_on_is_refused_as_unreachable(
    closed_port: int, caplog: pytest.LogCaptureFixture
) -> None:
    with pytest.raises(
        TokenEndpointError, match="^the token request failed: the origin could not be reached$"
    ) as refused:
        post_token_request_over_https(
            _token_request(f"https://127.0.0.1:{closed_port}/token?{_URL_QUERY}")
        )

    _assert_no_canary_in("".join(traceback.format_exception(refused.value)) + caplog.text)
    assert refused.value.__context__ is None


@pytest.mark.parametrize(
    "moved_name",
    [
        "KEY_SET_FETCH_TIMEOUT_SECONDS",
        "MAX_KEY_SET_BYTES",
        "KeySetFetchError",
        "fetch_key_set_over_https",
    ],
)
def test_the_key_set_fetch_is_still_wired_from_jwt_verification(moved_name: str) -> None:
    assert getattr(webauth.jwt_verification, moved_name) is getattr(
        webauth.https_client, moved_name
    )
