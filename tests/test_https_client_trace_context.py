"""The trace context an issuer call carries, driven against a loopback TLS server."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from logline.testing import configured

from tests.support.oidc_arrangement import LoopbackHttpsServer, ReceivedRequest
from tests.support.token_request_canaries import a_canary_token_request
from tests.support.trace_context import (
    TRACEPARENT,
    TRACESTATE,
    global_propagator_writing,
    inside_a_trace,
)
from webauth.https_client import fetch_key_set_over_https
from webauth.oidc_transport import post_token_request_over_https

pytestmark = pytest.mark.usefixtures("every_log_record")


def _fetching_the_key_set(server: LoopbackHttpsServer) -> object:
    return fetch_key_set_over_https(f"{server.base_url}/certs")


def _posting_a_token_request(server: LoopbackHttpsServer) -> object:
    return post_token_request_over_https(a_canary_token_request(f"{server.base_url}/token"))


_ISSUER_CALLS = [
    pytest.param(_fetching_the_key_set, id="key-set-fetch"),
    pytest.param(_posting_a_token_request, id="token-post"),
]


@pytest.mark.parametrize("call", _ISSUER_CALLS)
@pytest.mark.parametrize("tracestate", [None, TRACESTATE])
def test_an_issuer_call_inside_a_trace_carries_traceparent_and_tracestate_only_when_present(
    call: Callable[[LoopbackHttpsServer], object],
    tracestate: str | None,
    token_server: LoopbackHttpsServer,
) -> None:
    with configured("webauth-test"), inside_a_trace(tracestate=tracestate):
        call(token_server)

    [received] = token_server.received
    assert received.headers["traceparent"] == TRACEPARENT
    assert received.headers.get("tracestate") == tracestate


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_an_issuer_call_never_carries_the_callers_baggage(
    call: Callable[[LoopbackHttpsServer], object], token_server: LoopbackHttpsServer
) -> None:
    with configured("webauth-test"), inside_a_trace(baggage_entry="a-session-id"):
        call(token_server)

    [received] = token_server.received
    assert "baggage" not in received.headers
    assert "a-session-id" not in repr(received.headers)


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_an_issuer_call_outside_a_trace_sends_the_request_it_sent_before_propagation(
    call: Callable[[LoopbackHttpsServer], object], token_server: LoopbackHttpsServer
) -> None:
    with global_propagator_writing({}):
        call(token_server)
    with configured("webauth-test"):
        call(token_server)

    [without_propagation, with_propagation] = token_server.received
    assert with_propagation.headers == without_propagation.headers
    assert with_propagation.body == without_propagation.body


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_a_raising_propagator_leaves_the_calls_outcome_and_its_log_unchanged(
    call: Callable[[LoopbackHttpsServer], object],
    token_server: LoopbackHttpsServer,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with global_propagator_writing({}):
        expected_outcome = call(token_server)
    records_without_failure = [(record.name, record.levelno) for record in caplog.records]
    caplog.clear()

    with global_propagator_writing({"traceparent": TRACEPARENT}, then_raise=True):
        outcome = call(token_server)

    assert outcome == expected_outcome
    assert [(record.name, record.levelno) for record in caplog.records] == records_without_failure
    assert "canary" not in caplog.text
    assert "traceparent" not in token_server.received[-1].headers


_OWNED_HEADERS = ("authorization", "accept", "content-type", "host")


def _lines_named(received: ReceivedRequest, name: str) -> list[str]:
    return [value for line_name, value in received.header_lines if line_name.lower() == name]


@pytest.mark.parametrize(
    "written",
    [
        pytest.param(
            {
                "Authorization": "Bearer from-a-propagator",
                "Accept": "text/html",
                "Content-Type": "text/plain",
                "Host": "elsewhere.example",
            },
            id="same-case",
        ),
        pytest.param(
            {
                "authorization": "Bearer from-a-propagator",
                "accept": "text/html",
                "content-type": "text/plain",
                "host": "elsewhere.example",
            },
            id="lower-case",
        ),
    ],
)
def test_the_headers_a_token_post_owns_arrive_once_and_unchanged_whatever_a_propagator_writes(
    written: dict[str, str], token_server: LoopbackHttpsServer
) -> None:
    with global_propagator_writing({}):
        _posting_a_token_request(token_server)
    with global_propagator_writing({**written, "traceparent": TRACEPARENT}):
        _posting_a_token_request(token_server)

    [owned, propagated] = token_server.received
    for name in _OWNED_HEADERS:
        assert len(_lines_named(owned, name)) == 1
        assert _lines_named(propagated, name) == _lines_named(owned, name)
    assert propagated.headers["traceparent"] == TRACEPARENT


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_an_issuer_call_keeps_the_host_of_its_url_whatever_a_propagator_writes(
    call: Callable[[LoopbackHttpsServer], object], token_server: LoopbackHttpsServer
) -> None:
    with global_propagator_writing({"Host": "elsewhere.example"}):
        call(token_server)

    [received] = token_server.received
    assert _lines_named(received, "host") == [received.headers["host"]]
    assert "elsewhere.example" not in received.headers["host"]
