"""The exchange of an admitted token: a resource route trades the token its gate admitted, at the
issuer of the gate's relying party, for one the app may send on.

The app is the real stack of `an_exchange_app`; its gate's relying party posts to a fake token
endpoint, and a relying party built without a poster raises on any POST, so "no POST" is read
from that endpoint's requests.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.middleware import Middleware
from starlette.requests import HTTPConnection

from tests.support.exchange_arrangement import (
    ACCESS_TOKEN_TYPE,
    EXCHANGE_PATH,
    EXCHANGE_SCOPES,
    EXCHANGE_SOCKET_PATH,
    EXCHANGED_LIFETIME_SECONDS,
    EXCHANGED_TOKEN,
    MACHINE_EXCHANGE_PATH,
    OTHER_ISSUER,
    PERSON_EXCHANGE_PATH,
    ExchangeApp,
    an_exchange_answer,
    an_exchange_app,
)
from tests.support.gate_arrangement import RewritingTheRequest, a_token
from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_NOW,
    FakeTokenEndpoint,
    GrantHeldUntilReleased,
    a_relying_party,
    token_endpoint_answer,
)
from webauth.middleware import exchanged_access_token
from webauth.oidc import (
    ExchangedAccess,
    OidcRefusal,
    OidcRefusalReason,
    TokenEndpointError,
)

DEADLINE_SECONDS = 10
FAILED = OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)


def refused(code: str) -> OidcRefusal:
    return OidcRefusal(OidcRefusalReason.TOKEN_REQUEST_REFUSED, idp_error=code)


def the_raised(exchange: ExchangeApp) -> list[str]:
    return [type(error).__name__ for error in exchange.raised]


@pytest.mark.parametrize(
    ("path", "bearer", "changes"),
    [
        pytest.param(EXCHANGE_PATH, "none", {}, id="session"),
        pytest.param(PERSON_EXCHANGE_PATH, "path", {}, id="person-path-bearer"),
        pytest.param(MACHINE_EXCHANGE_PATH, "path", {}, id="machine-path-bearer"),
        pytest.param(EXCHANGE_PATH, "resource", {"app": FastAPI()}, id="sub-app"),
        pytest.param(
            EXCHANGE_PATH,
            "resource",
            {"headers": [(b"authorization", b"Bearer other")]},
            id="header-changed",
        ),
        pytest.param(EXCHANGE_PATH, "resource", {"method": "POST"}, id="method-changed"),
        pytest.param(
            EXCHANGE_PATH,
            "resource",
            {"query_string": b"access_token=other"},
            id="access-token-in-the-query",
        ),
    ],
)
def test_the_call_raises_where_resource_person_raises_and_posts_nothing(
    path: str, bearer: str, changes: dict[str, object]
) -> None:
    """EXCHANGE-01, EXCHANGE-02: it raises `RuntimeError` for a session, a person-path or
    machine-path bearer, a sub-app, a changed header or method, and an `access_token` added to the
    query after admission; no request reaches the issuer."""
    exchange = an_exchange_app(
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),) if changes else ()
    )
    tokens = {"none": None, "path": a_token(), "resource": exchange.admitted_token()}

    exchange.exchange(path, token=tokens[bearer], cookie=bearer == "none")

    assert (the_raised(exchange), exchange.outcomes) == (["RuntimeError"], [])
    assert exchange.issuer.requests == []


def test_the_call_raises_on_a_websocket_and_posts_nothing() -> None:
    """EXCHANGE-01: a WebSocket is no admission, a bearer header or not."""
    exchange = an_exchange_app()
    auth = exchange.app.auth
    headers = [("authorization", f"Bearer {exchange.admitted_token()}")]

    with (
        auth.client,
        auth.connect(EXCHANGE_SOCKET_PATH, cookie=auth.signed_cookie(), headers=headers) as socket,
    ):
        answer = socket.receive_json()

    assert (answer, the_raised(exchange)) == ({"raised": 1}, ["RuntimeError"])
    assert exchange.issuer.requests == []


@pytest.mark.parametrize(
    "scopes",
    [
        pytest.param((), id="empty-tuple"),
        pytest.param(["calendar:read"], id="list"),
        pytest.param(("calendar read",), id="element-with-a-space"),
        pytest.param(("calendar:read", 7), id="non-string"),
        pytest.param("calendar:read", id="string"),
    ],
)
def test_scopes_that_are_not_a_non_empty_tuple_of_scope_tokens_raise_and_post_nothing(
    scopes: object,
) -> None:
    """EXCHANGE-03: an admitted request with bad `scopes` raises `ValueError`."""
    exchange = an_exchange_app()
    exchange.scopes = scopes

    exchange.exchange()

    assert (the_raised(exchange), exchange.outcomes) == (["ValueError"], [])
    assert exchange.issuer.requests == []


def test_admission_is_judged_before_scopes() -> None:
    """EXCHANGE-03: a request without admission raises `RuntimeError` whatever `scopes` are."""
    exchange = an_exchange_app()
    exchange.scopes = ()

    exchange.exchange(cookie=True)

    assert the_raised(exchange) == ["RuntimeError"]


def test_the_token_is_posted_only_to_the_token_endpoint_of_the_gate_that_admitted_it() -> None:
    """EXCHANGE-04: each call goes to its own gate's issuer, two gates over two issuers."""
    first = an_exchange_app()
    second = an_exchange_app(issuer_url=OTHER_ISSUER)

    for exchange in (first, second, first):
        exchange.exchange()

    assert [request.url for request in first.issuer.requests] == [first.token_endpoint] * 2
    assert [request.url for request in second.issuer.requests] == [second.token_endpoint]
    assert first.token_endpoint != second.token_endpoint


def test_the_exchange_posts_the_token_exchange_form_authenticated_as_the_gates_client() -> None:
    """EXCHANGE-05: the form is the five members, `subject_token` is the admitted token byte for
    byte and several scopes are joined by one space; the client authenticates as it does for its
    other grants."""
    exchange = an_exchange_app()
    token = exchange.admitted_token()
    exchange.scopes = ("calendar:read", "calendar:write", "notes:read")

    exchange.exchange(token=token)
    exchange.issuer.answer = token_endpoint_answer(
        200, {"access_token": "workload-token", "token_type": "Bearer"}
    )
    exchange.relying_party.workload_access_token(scopes=("calendar:read",))

    exchanged, workload = exchange.issuer.requests
    assert dict(exchanged.form) == {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": token,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "requested_token_type": ACCESS_TOKEN_TYPE,
        "scope": "calendar:read calendar:write notes:read",
    }
    assert exchanged.authorization == workload.authorization


def test_the_post_runs_off_the_event_loop() -> None:
    """EXCHANGE-06: the grant runs on a worker thread, not on the route's."""
    exchange = an_exchange_app()

    exchange.exchange()

    assert exchange.issuer.threads
    assert exchange.route_threads
    assert set(exchange.issuer.threads).isdisjoint(exchange.route_threads)


def an_admitted_connection(exchange: ExchangeApp, token: str) -> HTTPConnection:
    """The entry point's request as the gate left it, for a call made outside the route."""
    exchange.exchange(exchange.resource.entry_point, token=token)
    return HTTPConnection(
        {
            "type": "http",
            "app": exchange.app.auth.app,
            "path": exchange.resource.entry_point,
            "method": "GET",
            "query_string": b"",
            "headers": [(b"authorization", f"Bearer {token}".encode("latin-1"))],
            **exchange.relay.added,
        }
    )


def test_a_cancelled_caller_gets_no_answer_and_its_cancellation_after_the_post_ends() -> None:
    """EXCHANGE-07: cancelling the caller does not stop the post, and the cancellation arrives
    once the post has ended."""
    exchange = an_exchange_app()
    connection = an_admitted_connection(exchange, exchange.admitted_token())
    held = GrantHeldUntilReleased(DEADLINE_SECONDS)
    exchange.issuer.before_answer = held
    answers: list[object] = []

    async def ask() -> None:
        try:
            answers.append(await exchanged_access_token(connection, scopes=EXCHANGE_SCOPES))
        finally:
            exchange.issuer.events.append("caller-left")

    async def drive() -> None:
        with anyio.fail_after(DEADLINE_SECONDS):
            async with anyio.create_task_group() as tasks:
                tasks.start_soon(ask)
                try:
                    await anyio.to_thread.run_sync(held.wait_until_reached)
                    tasks.cancel_scope.cancel()
                finally:
                    held.release()

    anyio.run(drive)

    assert answers == []
    assert exchange.issuer.events == ["post-ended", "caller-left"]


@pytest.mark.parametrize("token_type", ["Bearer", "bearer", "BEARER"])
def test_an_accepted_answer_expires_when_the_clock_before_the_post_says_and_reads_nothing_else(
    token_type: str,
) -> None:
    """EXCHANGE-08, EXCHANGE-12: `expires_at` is the whole-second clock before the post plus
    `expires_in`, which may lie after the admitted token's own expiry; `refresh_token` and `scope`
    are not read and the token type is read in any case."""
    lifetime = 10 * EXCHANGED_LIFETIME_SECONDS
    exchange = an_exchange_app(
        an_exchange_answer(
            token_type=token_type, expires_in=lifetime, refresh_token=7, scope=["unread"]
        )
    )
    exchange.moving_the_clock_during_the_post(40)

    exchange.exchange()

    assert exchange.outcomes == [
        ExchangedAccess(SecretStr(EXCHANGED_TOKEN), ACCESS_TOKEN_NOW + lifetime)
    ]


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(an_exchange_answer(issued_token_type=ABSENT), id="no-issued-token-type"),
        pytest.param(
            an_exchange_answer(issued_token_type="urn:ietf:params:oauth:token-type:id_token"),
            id="an-id-token-type",
        ),
        pytest.param(
            an_exchange_answer(issued_token_type=ACCESS_TOKEN_TYPE.upper()), id="another-case"
        ),
        pytest.param(an_exchange_answer(expires_in=ABSENT), id="no-expires-in"),
        pytest.param(an_exchange_answer(expires_in=0), id="expires-in-zero"),
        pytest.param(an_exchange_answer(expires_in=-1), id="expires-in-negative"),
        pytest.param(an_exchange_answer(expires_in=True), id="expires-in-true"),
        pytest.param(an_exchange_answer(expires_in=1.5), id="expires-in-float"),
        pytest.param(an_exchange_answer(expires_in="300"), id="expires-in-string"),
        pytest.param(an_exchange_answer(token_type="N_A"), id="token-type-n-a"),
        pytest.param(an_exchange_answer(access_token=ABSENT), id="no-access-token"),
        pytest.param(token_endpoint_answer(200, b"<html>"), id="not-json"),
        pytest.param(TokenEndpointError("unreachable"), id="transport-error"),
        pytest.param(token_endpoint_answer(500, {}), id="server-error"),
        pytest.param(token_endpoint_answer(403, {}), id="forbidden-without-an-error"),
    ],
)
def test_an_answer_that_does_not_hold_is_refused_as_token_endpoint_failed(
    answer: Any,
) -> None:
    """EXCHANGE-09: the bearer check, an `issued_token_type` of exactly the access-token URN and
    an `expires_in` of a whole number of at least 1 (stricter than RFC 8693 section 2.2.1, which
    recommends `expires_in`) each close as `TOKEN_ENDPOINT_FAILED`."""
    exchange = an_exchange_app(answer)

    exchange.exchange()

    assert exchange.outcomes == [FAILED]


@pytest.mark.parametrize(
    ("status", "code"),
    [(400, "invalid_request"), (401, "invalid_client"), (403, "access_denied")],
)
def test_an_issuer_error_is_refused_with_its_code(status: int, code: str) -> None:
    """EXCHANGE-10: an `error` answered 400, 401 or, for this grant, 403 is
    `TOKEN_REQUEST_REFUSED` carrying that code and no free text."""
    exchange = an_exchange_app(
        token_endpoint_answer(status, {"error": code, "error_description": "free text"})
    )

    exchange.exchange()

    assert exchange.outcomes == [refused(code)]


def test_a_forbidden_answer_to_the_workload_grant_stays_token_endpoint_failed() -> None:
    """EXCHANGE-10: only the exchange reads a 403 `error`; the workload grant is as it was."""
    issuer = FakeTokenEndpoint(token_endpoint_answer(403, {"error": "access_denied"}))

    refusal = a_relying_party(post_token_request=issuer).workload_access_token(scopes=("x",))

    assert refusal == FAILED


def test_no_token_and_no_issuer_text_reaches_a_response_a_log_the_scope_or_a_repr(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """EXCHANGE-11: neither token is in the result's, the request's or the admission record's
    repr, in a DEBUG log of a success and a refusal, or in a response, and the call adds no key
    to the scope."""
    exchange = an_exchange_app()
    token = exchange.admitted_token()
    caplog.set_level(logging.DEBUG)

    exchange.exchange(exchange.resource.entry_point, token=token)
    entry_keys, scopes = set(exchange.relay.added), [repr(exchange.relay.added)]
    admitted = exchange.exchange(token=token)
    exchange_keys = set(exchange.relay.added)
    scopes.append(repr(exchange.relay.added))
    exchange.issuer.answer = token_endpoint_answer(
        400, {"error": "invalid_request", "error_description": EXCHANGED_TOKEN}
    )
    refusal = exchange.exchange(token=token)
    scopes.append(repr(exchange.relay.added))

    shown = [
        *(f"{response.headers}{response.text}" for response in (admitted, refusal)),
        caplog.text,
        repr(exchange.outcomes),
        repr(exchange.issuer.requests),
        *scopes,
    ]
    assert all(secret not in text for secret in (token, EXCHANGED_TOKEN) for text in shown)
    assert exchange_keys == entry_keys
