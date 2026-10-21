"""The security headers reach every response, including an unhandled exception's 500."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, StreamingResponse
from webauth_arrangement import (
    a_web_auth_config,
    an_http_scope,
    assert_carries_policy_headers,
    drive,
    no_receive,
    starts,
)

from webauth.config import install_web_auth_config
from webauth.middleware import SecurityHeadersMiddleware
from webauth.policies import (
    CacheControlRule,
    CspDirective,
    PathRules,
    SecurityHeadersPolicy,
    default_content_security_policy,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.types import Message, Receive, Scope, Send

POLICY = SecurityHeadersPolicy(default_content_security_policy([]))
SERVER_ERROR_BODY = "Internal Server Error"
HSTS_SETTINGS = [pytest.param(True, id="hsts-on"), pytest.param(False, id="hsts-off")]


class RouteFailure(RuntimeError):
    pass


def an_app(
    *,
    cookie_secure: bool = True,
    configured: bool = True,
    debug: bool = False,
    policy: SecurityHeadersPolicy = POLICY,
) -> FastAPI:
    app = FastAPI(debug=debug)
    app.add_middleware(SecurityHeadersMiddleware, policy=policy)
    if configured:
        install_web_auth_config(app, a_web_auth_config(cookie_secure=cookie_secure))
    return app


def with_failing_route(app: FastAPI, failure: Exception) -> None:
    @app.get("/boom")
    def boom() -> None:
        raise failure


@pytest.mark.parametrize("cookie_secure", HSTS_SETTINGS)
def test_an_unhandled_exception_answers_a_500_carrying_the_security_headers(
    cookie_secure: bool,
) -> None:
    app = an_app(cookie_secure=cookie_secure)
    with_failing_route(app, RouteFailure())

    response = TestClient(app, raise_server_exceptions=False).get("/boom")

    assert (response.status_code, response.text) == (500, SERVER_ERROR_BODY)
    assert_carries_policy_headers(response.headers, POLICY, hsts=cookie_secure)


def test_a_default_test_client_raises_the_exception_the_route_raised() -> None:
    failure = RouteFailure()
    app = an_app()
    with_failing_route(app, failure)

    client = TestClient(app)

    with pytest.raises(RouteFailure) as raised:
        client.get("/boom")

    assert raised.value is failure


@pytest.mark.anyio
@pytest.mark.parametrize("cookie_secure", HSTS_SETTINGS)
async def test_one_response_start_carries_the_headers_and_the_exception_reaches_the_server(
    cookie_secure: bool,
) -> None:
    failure = RouteFailure()
    app = an_app(cookie_secure=cookie_secure)
    with_failing_route(app, failure)

    sent, raised = await drive(app, an_http_scope(app))

    (start,) = starts(sent)
    assert_carries_policy_headers(Headers(raw=start["headers"]), POLICY, hsts=cookie_secure)
    assert raised is failure


def test_a_host_exception_handler_runs_once_but_its_response_is_not_sent() -> None:
    app = an_app()
    with_failing_route(app, RouteFailure())
    handled: list[Exception] = []
    background_ran: list[bool] = []

    @app.exception_handler(Exception)
    async def handle(_request: object, error: Exception) -> JSONResponse:
        handled.append(error)
        tasks = BackgroundTasks()
        tasks.add_task(background_ran.append, True)
        return JSONResponse({"handled": True}, status_code=500, background=tasks)

    response = TestClient(app, raise_server_exceptions=False).get("/boom")

    assert (response.status_code, response.text) == (500, SERVER_ERROR_BODY)
    assert_carries_policy_headers(response.headers, POLICY, hsts=True)
    assert len(handled) == 1
    assert background_ran == []
    client = TestClient(app)

    with pytest.raises(RouteFailure):
        client.get("/boom")


def test_debug_mode_answers_the_library_500_without_a_traceback_page() -> None:
    app = an_app(debug=True)
    with_failing_route(app, RouteFailure())

    response = TestClient(app, raise_server_exceptions=False).get("/boom")

    assert (response.status_code, response.text) == (500, SERVER_ERROR_BODY)
    assert_carries_policy_headers(response.headers, POLICY, hsts=True)
    client = TestClient(app)

    with pytest.raises(RouteFailure):
        client.get("/boom")


def test_a_missing_configuration_answers_a_500_without_hsts_before_the_route_runs() -> None:
    route_ran: list[bool] = []
    app = an_app(configured=False)

    @app.get("/side-effect")
    def side_effect() -> None:
        route_ran.append(True)

    response = TestClient(app, raise_server_exceptions=False).get("/side-effect")

    assert (response.status_code, response.text) == (500, SERVER_ERROR_BODY)
    assert_carries_policy_headers(response.headers, POLICY, hsts=False)
    assert route_ran == []
    client = TestClient(app)

    with pytest.raises(RuntimeError, match="install_web_auth_config"):
        client.get("/side-effect")


@pytest.mark.parametrize(("path", "status"), [
    pytest.param("/moved", 307, id="redirect"),
    pytest.param("/forbidden", 403, id="handled-error"),
    pytest.param("/route-pins-https", 200, id="route-sets-its-own-hsts"),
])
@pytest.mark.parametrize(("cookie_secure", "hsts"), [
    pytest.param(True, "max-age=31536000; includeSubDomains", id="secure"),
    pytest.param(False, None, id="secure-off"),
])
def test_every_answer_carries_exactly_the_hsts_cookie_secure_decides(
    path: str, status: int, cookie_secure: bool, hsts: str | None,
) -> None:
    app = an_app(cookie_secure=cookie_secure)

    @app.get("/moved")
    def moved() -> RedirectResponse:
        return RedirectResponse("/elsewhere")

    @app.get("/forbidden")
    def forbidden() -> None:
        raise HTTPException(status_code=403)

    @app.get("/route-pins-https")
    def route_pins_https() -> Response:
        return Response(headers={"Strict-Transport-Security": "max-age=60"})

    response = TestClient(app).get(path, follow_redirects=False)

    assert response.status_code == status
    assert response.headers.get("strict-transport-security") == hsts


@pytest.mark.anyio
async def test_an_exception_after_the_first_chunk_truncates_the_started_response() -> None:
    failure = RouteFailure()
    app = an_app()

    @app.get("/stream")
    def stream() -> StreamingResponse:
        async def chunks() -> AsyncIterator[bytes]:
            yield b"first"
            raise failure

        return StreamingResponse(chunks())

    sent, raised = await drive(app, an_http_scope(app, "/stream"))

    (start,) = starts(sent)
    assert start["status"] == 200
    assert_carries_policy_headers(Headers(raw=start["headers"]), POLICY, hsts=True)
    assert b"".join(m["body"] for m in sent if m["type"] == "http.response.body") == b"first"
    assert raised is failure


@pytest.mark.anyio
async def test_a_start_without_headers_gains_them_and_keeps_its_other_fields() -> None:
    app = an_app()

    async def bare_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 204, "trailers": True,
                    "extension": "kept"})
        await send({"type": "http.response.body", "body": b"x", "more_body": True})
        await send({"type": "http.response.trailers", "headers": [(b"x-trailer", b"1")]})

    sent, raised = await drive(SecurityHeadersMiddleware(bare_app, POLICY), an_http_scope(app))

    start, body, trailers = sent
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), POLICY, hsts=True)
    assert {key: start[key] for key in ("status", "trailers", "extension")} == {
        "status": 204, "trailers": True, "extension": "kept",
    }
    assert body == {"type": "http.response.body", "body": b"x", "more_body": True}
    assert trailers == {"type": "http.response.trailers", "headers": [(b"x-trailer", b"1")]}


@pytest.mark.anyio
async def test_a_downstream_send_that_fails_on_the_start_is_tried_once_and_propagates() -> None:
    app = an_app()
    failure = ConnectionResetError()
    attempts: list[Message] = []

    async def responding_app(_scope: Scope, _receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    async def failing_send(message: Message) -> None:
        attempts.append(message)
        raise failure

    middleware = SecurityHeadersMiddleware(responding_app, POLICY)
    scope = an_http_scope(app)

    with pytest.raises(ConnectionResetError) as raised:
        await middleware(scope, no_receive, failing_send)

    assert raised.value is failure
    assert len(attempts) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("failing_message_type", ["http.response.start", "http.response.body"])
async def test_a_500_that_cannot_be_sent_still_raises_the_route_exception_with_a_note(
    failing_message_type: str,
) -> None:
    failure = RouteFailure()
    send_failure = ConnectionResetError("client gone")
    app = an_app()

    async def failing_app(_scope: Scope, _receive: Receive, _send: Send) -> None:
        raise failure

    async def failing_send(message: Message) -> None:
        if message["type"] == failing_message_type:
            raise send_failure

    middleware = SecurityHeadersMiddleware(failing_app, POLICY)
    scope = an_http_scope(app)

    with pytest.raises(RouteFailure) as raised:
        await middleware(scope, no_receive, failing_send)

    assert raised.value is failure
    assert any(repr(send_failure) in note for note in failure.__notes__)


def test_a_cache_control_rule_applies_to_a_normal_response_and_to_the_library_500() -> None:
    cacheable = "public, max-age=60"
    policy = SecurityHeadersPolicy(
        default_content_security_policy([]),
        cache_control_rules=(CacheControlRule(PathRules(prefixes=("/boom", "/ok")), cacheable),),
    )
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, policy=policy)
    install_web_auth_config(app, a_web_auth_config())
    with_failing_route(app, RouteFailure())

    @app.get("/ok")
    def ok() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)

    normal, failed = client.get("/ok"), client.get("/boom")

    assert (normal.status_code, failed.status_code) == (200, 500)
    assert (normal.headers["cache-control"], failed.headers["cache-control"]) == (
        cacheable, cacheable,
    )


@pytest.mark.anyio
async def test_a_websocket_passes_through_untouched() -> None:
    seen: list[Scope] = []

    async def websocket_app(scope: Scope, _receive: Receive, _send: Send) -> None:
        seen.append(scope)

    async def no_send(_message: Message) -> None:
        raise AssertionError("the middleware sent on a websocket")

    scope: Scope = {"type": "websocket", "path": "/ws"}

    await SecurityHeadersMiddleware(websocket_app, POLICY)(scope, no_receive, no_send)

    assert seen == [{"type": "websocket", "path": "/ws"}]


def test_a_normal_response_keeps_its_background_task() -> None:
    app = an_app()
    background_ran: list[bool] = []

    @app.get("/ok")
    def ok(tasks: BackgroundTasks) -> dict[str, bool]:
        tasks.add_task(background_ran.append, True)
        return {"ok": True}

    response = TestClient(app).get("/ok")

    assert response.json() == {"ok": True}
    assert_carries_policy_headers(response.headers, POLICY, hsts=True)
    assert background_ran == [True]


def test_a_customised_policy_reaches_the_response_header_as_returned() -> None:
    customised = default_content_security_policy(
        added_sources={CspDirective.STYLE_SRC: ["'unsafe-inline'"]},
    )
    app = an_app(policy=SecurityHeadersPolicy(customised))

    @app.get("/ok")
    def ok() -> dict[str, bool]:
        return {"ok": True}

    response = TestClient(app).get("/ok")

    assert response.headers["content-security-policy"] == customised
    assert "style-src 'self' 'unsafe-inline';" in customised


def the_hsts_header_of(policy: SecurityHeadersPolicy, *, cookie_secure: bool = True) -> str | None:
    app = an_app(cookie_secure=cookie_secure, policy=policy)

    @app.get("/ok")
    def ok() -> dict[str, str]:
        return {}

    return TestClient(app).get("/ok").headers.get("strict-transport-security")


def test_hsts_is_sent_when_cookies_are_secure() -> None:
    assert the_hsts_header_of(POLICY) == "max-age=31536000; includeSubDomains"


def test_hsts_is_absent_without_secure_cookies() -> None:
    assert the_hsts_header_of(POLICY, cookie_secure=False) is None
