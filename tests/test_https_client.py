"""The production token POST, driven against a loopback TLS server.

`post_token_request_over_https` is the `TokenRequestPost` a host hands its
`OidcRelyingParty`; its scenarios send a real form POST through
`webauth.https_client` to the server of `oidc_arrangement`, carrying canary
secrets in the client secret, the code and the PKCE verifier.
"""

from __future__ import annotations

import base64
import contextlib
import inspect
import logging
import socket
import sys
import time
import traceback
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

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
    unanswering_loopback_port,
    unconnectable_loopback_port,
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


@pytest.mark.parametrize(
    ("target", "failure"),
    [
        pytest.param(
            lambda server, monkeypatch: f"{server.base_url}/moved-stalling",
            None,
            id="answered-another-status",
        ),
        pytest.param(_plain_http, ExchangeFailure.NOT_AN_HTTPS_URL, id="plain-http"),
    ],
)
def test_a_key_set_fetch_refusal_names_why_only_when_the_exchange_itself_failed(
    token_server: LoopbackHttpsServer,
    monkeypatch: pytest.MonkeyPatch,
    target: Callable[[LoopbackHttpsServer, pytest.MonkeyPatch], str],
    failure: ExchangeFailure | None,
) -> None:
    with pytest.raises(KeySetFetchError) as refused:
        fetch_key_set_over_https(target(token_server, monkeypatch), timeout_seconds=0.2)

    assert refused.value.failure is failure


_TEST_DEADLINE_SECONDS = 1.0
# Room for closing the connection and for a loaded runner, still far below the
# per-step timeout of five seconds and the drip that would run on for longer.
_TEST_DEADLINE_SLACK_SECONDS = 1.0


def _fetch_key_set(url: str, **limits: float) -> object:
    return fetch_key_set_over_https(url, **limits)


def _post_token_form(url: str, timeout_seconds: float = 5, **limits: float) -> object:
    return post_form_over_https(
        url,
        _FORM,
        authorization=SecretStr(_BASIC_AUTHORIZATION),
        max_body_bytes=MAX_TOKEN_RESPONSE_BYTES,
        timeout_seconds=timeout_seconds,
        **limits,
    )


_EXCHANGES_UNDER_A_DEADLINE = pytest.mark.parametrize(
    ("exchange", "error"),
    [
        pytest.param(_fetch_key_set, KeySetFetchError, id="key-set-fetch"),
        pytest.param(_post_token_form, HttpsExchangeError, id="token-post"),
    ],
)


_StalledTarget = Callable[[LoopbackHttpsServer, pytest.MonkeyPatch, contextlib.ExitStack], str]


def _route(path: str) -> _StalledTarget:
    return lambda server, monkeypatch, stack: f"{server.base_url}{path}"


def _unconnectable_on_every_address(
    server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch, stack: contextlib.ExitStack
) -> str:
    port = stack.enter_context(unconnectable_loopback_port())
    [address] = socket.getaddrinfo("127.0.0.1", port, type=socket.SOCK_STREAM)
    # A host name resolving to three addresses, none of which answers.
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [address] * 3)
    return f"https://issuer.example:{port}/certs"


def _unanswering_tls_handshake(
    server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch, stack: contextlib.ExitStack
) -> str:
    return f"https://127.0.0.1:{stack.enter_context(unanswering_loopback_port())}/certs"


@pytest.mark.parametrize(
    "target",
    [
        pytest.param(_unconnectable_on_every_address, id="connect-on-every-address"),
        pytest.param(_unanswering_tls_handshake, id="tls-handshake"),
        pytest.param(_route("/dripping-status"), id="dripping-status-line"),
        pytest.param(_route("/dripping-head"), id="dripping-head"),
        pytest.param(_route("/dripping-body"), id="dripping-body"),
    ],
)
@_EXCHANGES_UNDER_A_DEADLINE
def test_an_exchange_held_past_the_total_deadline_is_cut_off_as_timed_out(
    token_server: LoopbackHttpsServer,
    monkeypatch: pytest.MonkeyPatch,
    exchange: Callable[..., object],
    error: type[KeySetFetchError | HttpsExchangeError],
    target: _StalledTarget,
) -> None:
    with contextlib.ExitStack() as stack:
        url = target(token_server, monkeypatch, stack)
        started = time.monotonic()
        with pytest.raises(error) as refused:
            exchange(url, deadline_seconds=_TEST_DEADLINE_SECONDS)
        held = time.monotonic() - started

    assert refused.value.failure is ExchangeFailure.TIMED_OUT
    assert _TEST_DEADLINE_SECONDS <= held < _TEST_DEADLINE_SECONDS + _TEST_DEADLINE_SLACK_SECONDS


@pytest.mark.parametrize(
    "host",
    [
        pytest.param("issuer..example", id="empty-label"),
        pytest.param("a" * 64 + ".example", id="label-over-63-characters"),
    ],
)
@_EXCHANGES_UNDER_A_DEADLINE
def test_a_host_name_no_resolver_can_encode_is_refused_as_broken_off(
    exchange: Callable[..., object],
    error: type[KeySetFetchError | HttpsExchangeError],
    host: str,
) -> None:
    with pytest.raises(error) as refused:
        exchange(f"https://{host}/certs?{_URL_QUERY}")

    assert refused.value.failure is ExchangeFailure.BROKEN_OFF
    _assert_no_canary_in("".join(traceback.format_exception(refused.value)))


_DEFAULT_DEADLINE_SECONDS = 10
_FAST_CLOCK_SPEED = 10


@_EXCHANGES_UNDER_A_DEADLINE
def test_each_call_is_cut_off_at_a_ten_second_deadline_by_default(
    token_server: LoopbackHttpsServer,
    monkeypatch: pytest.MonkeyPatch,
    exchange: Callable[..., object],
    error: type[KeySetFetchError | HttpsExchangeError],
) -> None:
    started = time.monotonic()

    def fast_monotonic() -> float:
        return started + (time.monotonic() - started) * _FAST_CLOCK_SPEED

    # The deadline's clock runs fast, so its ten seconds pass in one.
    monkeypatch.setattr(webauth.https_client, "time", SimpleNamespace(monotonic=fast_monotonic))
    with pytest.raises(error) as refused:
        exchange(f"{token_server.base_url}/dripping-body")
    held = fast_monotonic() - started

    assert refused.value.failure is ExchangeFailure.TIMED_OUT
    assert (
        _DEFAULT_DEADLINE_SECONDS
        <= held
        < _DEFAULT_DEADLINE_SECONDS + _TEST_DEADLINE_SLACK_SECONDS * _FAST_CLOCK_SPEED
    )


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(fetch_key_set_over_https, id="key-set-fetch"),
        pytest.param(post_form_over_https, id="token-post"),
    ],
)
def test_each_calls_default_deadline_is_exactly_ten_seconds(call: Callable[..., object]) -> None:
    # The fast-clock test above proves the default is wired; its band cannot
    # tell ten seconds from fifteen, so the public default itself is pinned.
    deadline = inspect.signature(call).parameters["deadline_seconds"].default

    assert deadline == _DEFAULT_DEADLINE_SECONDS


@_EXCHANGES_UNDER_A_DEADLINE
@pytest.mark.parametrize("deadline_seconds", [0, -1])
def test_a_deadline_of_zero_or_less_is_refused_naming_the_parameter(
    exchange: Callable[..., object], error: type[Exception], deadline_seconds: float
) -> None:
    with pytest.raises(ValueError, match="deadline_seconds"):
        exchange("https://127.0.0.1:1/token", deadline_seconds=deadline_seconds)


@pytest.mark.parametrize(
    "exchange", [_fetch_key_set, _post_token_form], ids=["key-set-fetch", "token-post"]
)
@pytest.mark.parametrize("timeout_seconds", [0, -1])
def test_a_timeout_of_zero_or_less_is_refused_naming_the_parameter(
    exchange: Callable[..., object], timeout_seconds: float
) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        exchange("https://127.0.0.1:1/token", timeout_seconds=timeout_seconds)


def test_a_token_request_with_a_non_positive_timeout_is_refused_naming_the_timeout() -> None:
    request = _token_request("https://127.0.0.1:1/token")

    with pytest.raises(ValueError, match="timeout_seconds must be positive"):
        post_token_request_over_https(request, timeout_seconds=0)


def test_a_key_set_fetch_that_timed_out_says_so_in_its_message(
    token_server: LoopbackHttpsServer,
) -> None:
    with pytest.raises(KeySetFetchError, match=str(ExchangeFailure.TIMED_OUT)) as refused:
        fetch_key_set_over_https(f"{token_server.base_url}/silent", timeout_seconds=0.2)

    assert refused.value.failure is ExchangeFailure.TIMED_OUT


_connect_events: list[tuple[str, int]] = []
_recording_connect_events = False


def _record_connect_event(event: str, args: tuple) -> None:
    if _recording_connect_events and event == "http.client.connect":
        _connect_events.append((args[1], args[2]))


sys.addaudithook(_record_connect_event)


def test_one_exchange_raises_exactly_one_connect_audit_event(
    token_server: LoopbackHttpsServer,
) -> None:
    global _recording_connect_events
    origin = urllib.parse.urlsplit(token_server.base_url)
    _connect_events.clear()
    _recording_connect_events = True
    try:
        _fetch_key_set(f"{token_server.base_url}/jwks")
    finally:
        _recording_connect_events = False

    assert _connect_events == [(origin.hostname, origin.port)]


@pytest.mark.parametrize("deadline_seconds", [0, -1])
def test_a_token_request_with_a_non_positive_deadline_is_refused_naming_the_deadline(
    deadline_seconds: float,
) -> None:
    with pytest.raises(ValueError, match="deadline_seconds must be positive"):
        post_token_request_over_https(
            _token_request("https://127.0.0.1:1/token"), deadline_seconds=deadline_seconds
        )


def test_a_token_request_that_timed_out_names_the_timeout_as_its_failure(
    token_server: LoopbackHttpsServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(TokenEndpointError) as refused:
        post_token_request_over_https(
            _token_request(_stalled(token_server, monkeypatch)), timeout_seconds=0.2
        )

    assert refused.value.failure is ExchangeFailure.TIMED_OUT


def test_a_token_request_cut_off_by_the_total_deadline_names_the_timeout(
    token_server: LoopbackHttpsServer,
) -> None:
    # The drip keeps every single step inside timeout_seconds, so only the
    # supplied total deadline can end the exchange.
    started = time.monotonic()
    with pytest.raises(TokenEndpointError) as refused:
        post_token_request_over_https(
            _token_request(f"{token_server.base_url}/dripping-body"),
            timeout_seconds=DRIP_INTERVAL_SECONDS * 2.5,
            deadline_seconds=_TEST_DEADLINE_SECONDS,
        )
    held = time.monotonic() - started

    assert refused.value.failure is ExchangeFailure.TIMED_OUT
    assert _TEST_DEADLINE_SECONDS <= held < _TEST_DEADLINE_SECONDS + _TEST_DEADLINE_SLACK_SECONDS


def test_a_per_step_timeout_above_the_total_deadline_is_refused_not_capped() -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        post_token_request_over_https(
            _token_request("https://127.0.0.1:1/token"), timeout_seconds=3, deadline_seconds=2
        )


def test_the_token_posts_default_deadline_is_the_https_clients_token_exchange_deadline() -> None:
    deadline = inspect.signature(post_token_request_over_https).parameters["deadline_seconds"]

    assert deadline.default == webauth.https_client.TOKEN_EXCHANGE_DEADLINE_SECONDS


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
