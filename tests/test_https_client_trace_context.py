"""The trace context an issuer call carries, driven against a loopback TLS server."""

from __future__ import annotations

import json
from collections.abc import Callable

import pytest
from logline.testing import configured

from tests.support.loopback_arrangement import LoopbackHttpsServer
from tests.support.token_request_canaries import a_canary_token_request
from tests.support.trace_context import (
    PROPAGATOR_FAILURE_MESSAGE,
    TRACEPARENT,
    TRACESTATE,
    a_raising_global_propagator,
    inside_a_trace,
)
from webauth.https_client import fetch_key_set_over_https
from webauth.oidc_transport import post_token_request_over_https


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
    """TRACE-01: inside a trace the call carries `traceparent`, and `tracestate` if present."""
    with configured("webauth-test"), inside_a_trace(tracestate=tracestate):
        call(token_server)

    [received] = token_server.received
    version, trace_id, _span_the_call_runs_in, flags = received.headers["traceparent"].split("-")
    expected_version, expected_trace_id, _caller_span, expected_flags = TRACEPARENT.split("-")
    assert (version, trace_id, flags) == (expected_version, expected_trace_id, expected_flags)
    assert received.headers.get("tracestate") == tracestate


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_an_issuer_call_outside_a_trace_sends_the_request_it_sent_before_propagation(
    call: Callable[[LoopbackHttpsServer], object], token_server: LoopbackHttpsServer
) -> None:
    """TRACE-01: outside a trace the call is the request it was before."""
    call(token_server)
    with configured("webauth-test"):
        call(token_server)

    [without_propagation, with_propagation] = token_server.received
    assert with_propagation.headers == without_propagation.headers
    assert with_propagation.body == without_propagation.body


@pytest.mark.parametrize("call", _ISSUER_CALLS)
def test_a_propagator_that_raises_fails_the_call_without_its_message_in_any_log_line(
    call: Callable[[LoopbackHttpsServer], object],
    token_server: LoopbackHttpsServer,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """LOG-05: the propagator's exception escapes the call, its line is `failed` with the class
    as `error_type`, and no log line carries its message."""
    with configured("webauth-test"), a_raising_global_propagator(), inside_a_trace():
        with pytest.raises(RuntimeError):
            call(token_server)

    written = capsys.readouterr()
    [ended] = [json.loads(line) for line in written.out.splitlines() if ".ended" in line]
    assert (ended["outcome"], ended["error_type"]) == ("failed", "RuntimeError")
    assert "reason" not in ended
    assert PROPAGATOR_FAILURE_MESSAGE not in written.out + written.err
