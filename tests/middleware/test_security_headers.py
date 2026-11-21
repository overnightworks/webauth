"""The security headers reach every response, including an unhandled exception's 500."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, StreamingResponse

from tests.support.account_arrangement import UsersInMemory, WriteLockInMemory
from tests.support.client_address_arrangement import (
    add_the_client_address_writer,
    behind_the_client_address_writer,
)
from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.oidc_arrangement import LogoutPage
from tests.support.security_headers_arrangement import (
    a_content_security_policy_rule,
    a_policy_with_content_security_policy_rules,
    assert_carries_policy_headers,
)
from tests.support.session_store_arrangement import SessionRecordsInMemory
from tests.support.webauth_arrangement import (
    RecordingAuditSink,
    a_web_auth_config,
    an_http_scope,
    drive,
    no_receive,
    starts,
)
from webauth.middleware.security_headers import _SecurityHeadersMiddleware
from webauth.policies import (
    CacheControlRule,
    CspDirective,
    PathRules,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import SignInStores
from webauth.sign_in_routes import SignInPaths

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from httpx import Response as HttpxResponse
    from starlette.middleware.base import RequestResponseEndpoint
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

POLICY = SecurityHeadersPolicy(default_content_security_policy([]))
SERVER_ERROR_BODY = "Internal Server Error"
HSTS_SETTINGS = [pytest.param(True, id="hsts-on"), pytest.param(False, id="hsts-off")]


class RouteFailure(RuntimeError):
    pass


def an_app(
    *,
    cookie_secure: bool = True,
    debug: bool = False,
    policy: SecurityHeadersPolicy = POLICY,
) -> FastAPI:
    app = FastAPI(debug=debug)
    install_the_gated_stack(
        app, config=a_web_auth_config(cookie_secure=cookie_secure), security_headers=policy
    )
    return app


def an_app_without_a_configuration() -> FastAPI:
    app = FastAPI()
    app.add_middleware(_SecurityHeadersMiddleware, policy=POLICY)
    add_the_client_address_writer(app)
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
    app = an_app_without_a_configuration()

    @app.get("/side-effect")
    def side_effect() -> None:
        route_ran.append(True)

    response = TestClient(app, raise_server_exceptions=False).get("/side-effect")

    assert (response.status_code, response.text) == (500, SERVER_ERROR_BODY)
    assert_carries_policy_headers(response.headers, POLICY, hsts=False)
    assert route_ran == []
    client = TestClient(app)

    with pytest.raises(RuntimeError, match="WebAuth"):
        client.get("/side-effect")


@pytest.mark.parametrize(
    ("path", "status"),
    [
        pytest.param("/moved", 307, id="redirect"),
        pytest.param("/forbidden", 403, id="handled-error"),
        pytest.param("/route-pins-https", 200, id="route-sets-its-own-hsts"),
    ],
)
@pytest.mark.parametrize(
    ("cookie_secure", "hsts"),
    [
        pytest.param(True, "max-age=31536000; includeSubDomains", id="secure"),
        pytest.param(False, None, id="secure-off"),
    ],
)
def test_every_answer_carries_exactly_the_hsts_cookie_secure_decides(
    path: str,
    status: int,
    cookie_secure: bool,
    hsts: str | None,
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
        await send(
            {"type": "http.response.start", "status": 204, "trailers": True, "extension": "kept"}
        )
        await send({"type": "http.response.body", "body": b"x", "more_body": True})
        await send({"type": "http.response.trailers", "headers": [(b"x-trailer", b"1")]})

    sent, raised = await drive(
        behind_the_client_address_writer(_SecurityHeadersMiddleware(bare_app, POLICY)),
        an_http_scope(app),
    )

    start, body, trailers = sent
    assert raised is None
    assert_carries_policy_headers(Headers(raw=start["headers"]), POLICY, hsts=True)
    assert {key: start[key] for key in ("status", "trailers", "extension")} == {
        "status": 204,
        "trailers": True,
        "extension": "kept",
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

    middleware = behind_the_client_address_writer(
        _SecurityHeadersMiddleware(responding_app, POLICY)
    )
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

    middleware = behind_the_client_address_writer(_SecurityHeadersMiddleware(failing_app, POLICY))
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
    app = an_app(policy=policy)
    with_failing_route(app, RouteFailure())

    @app.get("/ok")
    def ok() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app, raise_server_exceptions=False)

    normal, failed = client.get("/ok"), client.get("/boom")

    assert (normal.status_code, failed.status_code) == (200, 500)
    assert (normal.headers["cache-control"], failed.headers["cache-control"]) == (
        cacheable,
        cacheable,
    )


@pytest.mark.anyio
async def test_a_websocket_passes_through_without_a_response() -> None:
    ran: list[str] = []

    async def websocket_app(scope: Scope, _receive: Receive, _send: Send) -> None:
        ran.append(scope["path"])

    async def no_send(_message: Message) -> None:
        raise AssertionError("the middleware sent on a websocket")

    scope: Scope = {"type": "websocket", "path": "/ws", "headers": []}
    middleware = behind_the_client_address_writer(_SecurityHeadersMiddleware(websocket_app, POLICY))

    await middleware(scope, no_receive, no_send)

    assert ran == ["/ws"]


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


OWN_POLICY_ANSWER_HEADERS = {
    "webauth-own-policy": "1",
    "content-security-policy": "default-src 'none'",
    "cache-control": "no-store",
}


@pytest.mark.parametrize(
    ("answer_headers", "expected_policy", "expected_cache_control"),
    [
        pytest.param(
            {"content-security-policy": "default-src *", "cache-control": "public"},
            POLICY.content_security_policy,
            "max-age=60",
            id="without-the-marker-the-policy-overwrites",
        ),
        pytest.param(
            OWN_POLICY_ANSWER_HEADERS,
            "default-src 'none'",
            "no-store",
            id="with-the-marker-the-answers-own-stand",
        ),
    ],
)
def test_an_answer_with_the_own_policy_marker_keeps_its_policy_and_loses_the_marker(
    answer_headers: dict[str, str],
    expected_policy: str,
    expected_cache_control: str,
) -> None:
    policy = SecurityHeadersPolicy(
        POLICY.content_security_policy,
        cache_control_rules=(
            CacheControlRule(PathRules(exact=frozenset({"/page"})), "max-age=60"),
        ),
    )
    app = an_app(policy=policy)

    @app.get("/page")
    def page() -> Response:
        return Response("page", headers=answer_headers)

    response = TestClient(app).get("/page")

    assert response.headers["content-security-policy"] == expected_policy
    assert response.headers["cache-control"] == expected_cache_control
    assert "webauth-own-policy" not in response.headers
    assert_carries_policy_headers(
        response.headers,
        replace(policy, content_security_policy=expected_policy),
        hsts=True,
    )


LOGOUT_PATH = "/logout"
HOST_POLICY = SecurityHeadersPolicy(
    "default-src 'self'",
    cache_control_rules=(
        CacheControlRule(PathRules(exact=frozenset({LOGOUT_PATH})), "public, max-age=600"),
    ),
)


def add_a_base_http_host_middleware(app: FastAPI) -> None:
    @app.middleware("http")
    async def pass_through(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)


class PureAsgiHostMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)


def add_a_pure_asgi_host_middleware(app: FastAPI) -> None:
    app.add_middleware(PureAsgiHostMiddleware)


def the_logout_app(
    *,
    host_policy: SecurityHeadersPolicy = HOST_POLICY,
    cookie_secure: bool = True,
    host_middleware: Callable[[FastAPI], None] | None = None,
) -> FastAPI:
    """An app with the logout route behind this stack."""
    lock = WriteLockInMemory()
    users = UsersInMemory(lock=lock)
    sessions = SessionRecordsInMemory(users=users, lock=lock)
    stores = SignInStores(users, sessions, RecordingAuditSink())
    app = FastAPI()
    if host_middleware is not None:
        host_middleware(app)
    install_the_gated_stack(
        app,
        config=a_web_auth_config(cookie_secure=cookie_secure),
        sessions=sessions.in_transaction,
        sign_in=lambda: nullcontext(stores),
        sign_in_paths=SignInPaths(start="/login", callback="/callback", logout=LOGOUT_PATH),
        security_headers=host_policy,
    )
    return app


def the_logout_page(
    *,
    host_policy: SecurityHeadersPolicy = HOST_POLICY,
    cookie_secure: bool = True,
    host_middleware: Callable[[FastAPI], None] | None = None,
) -> HttpxResponse:
    """What a browser gets from a logout route behind this stack."""
    app = the_logout_app(
        host_policy=host_policy,
        cookie_secure=cookie_secure,
        host_middleware=host_middleware,
    )
    return TestClient(app).post(LOGOUT_PATH, headers={"sec-fetch-site": "same-origin"})


def the_logout_policy_of(page: HttpxResponse) -> str:
    return "; ".join(
        (
            "default-src 'none'",
            f"script-src {LogoutPage(page.text).script_source}",
            "form-action https://login.example.org https://notes.example.org",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        )
    )


@pytest.mark.parametrize("cookie_secure", HSTS_SETTINGS)
def test_the_logout_page_keeps_its_policy_and_no_store_and_gets_the_other_headers(
    cookie_secure: bool,
) -> None:
    """APP-30: the logout page is no-store."""
    page = the_logout_page(cookie_secure=cookie_secure)

    assert page.headers["cache-control"] == "no-store"
    assert "webauth-own-policy" not in page.headers
    assert_carries_policy_headers(
        page.headers,
        replace(HOST_POLICY, content_security_policy=the_logout_policy_of(page)),
        hsts=cookie_secure,
    )


@pytest.mark.parametrize(
    "host_middleware",
    [
        pytest.param(add_a_base_http_host_middleware, id="base-http-middleware"),
        pytest.param(add_a_pure_asgi_host_middleware, id="pure-asgi-middleware"),
    ],
)
def test_a_host_middleware_inside_the_stack_does_not_cost_the_page_its_policy(
    host_middleware: Callable[[FastAPI], None],
) -> None:
    page = the_logout_page(host_middleware=host_middleware)

    assert page.headers["content-security-policy"] == the_logout_policy_of(page)
    assert page.headers["cache-control"] == "no-store"
    assert "webauth-own-policy" not in page.headers


FRAMER_POLICY = default_content_security_policy(
    added_sources={CspDirective.FRAME_ANCESTORS: ("https://call.example.org",)}
)


@pytest.mark.parametrize(
    ("content_security_policy", "expected_frame_options"),
    [
        pytest.param(default_content_security_policy([]), "DENY", id="default-policy"),
        pytest.param(FRAMER_POLICY, None, id="added-framer"),
        pytest.param("default-src 'self'", "DENY", id="no-frame-ancestors"),
        pytest.param("default-src 'self'; frame-ancestors 'none'", "DENY", id="none"),
        pytest.param("frame-ancestors 'NONE'", "DENY", id="none-in-capitals"),
        pytest.param(
            "default-src 'self' ;  Frame-Ancestors  'none'",
            "DENY",
            id="directive-name-in-other-case",
        ),
        pytest.param("FRAME-ANCESTORS https://a.example", None, id="framer-directive-in-capitals"),
        pytest.param("frame-ancestors 'self'", None, id="self"),
        pytest.param("frame-ancestors 'none' https://a.example", None, id="none-with-a-framer"),
        pytest.param("frame-ancestors", "DENY", id="empty-source-list"),
        pytest.param(
            "frame-ancestors 'none'; frame-ancestors https://a.example",
            "DENY",
            id="first-directive-counts-none",
        ),
        pytest.param(
            "frame-ancestors https://a.example; frame-ancestors 'none'",
            None,
            id="first-directive-counts-framer",
        ),
    ],
)
def test_x_frame_options_follows_the_frame_ancestors_the_answer_leaves_with(
    content_security_policy: str, expected_frame_options: str | None
) -> None:
    policy = SecurityHeadersPolicy(content_security_policy)
    app = an_app(policy=policy)

    @app.get("/page")
    def page() -> Response:
        return Response("page", headers={"X-Frame-Options": "SAMEORIGIN"})

    response = TestClient(app).get("/page")

    assert_carries_policy_headers(
        response.headers, policy, hsts=True, frame_options=expected_frame_options
    )


def test_the_logout_page_keeps_deny_under_a_host_policy_that_allows_a_framer() -> None:
    page = the_logout_page(host_policy=SecurityHeadersPolicy(FRAMER_POLICY))

    assert_carries_policy_headers(
        page.headers,
        SecurityHeadersPolicy(the_logout_policy_of(page)),
        hsts=True,
        frame_options="DENY",
    )


@pytest.mark.parametrize(
    ("path", "rule_applies"),
    [
        pytest.param("/t/token/index.html", True, id="below-the-rule-prefix"),
        pytest.param("/t", False, id="near-miss-without-the-trailing-slash"),
        pytest.param("/tt/token", False, id="near-miss-sharing-the-letters"),
        pytest.param("/page", False, id="other-path-keeps-the-default"),
    ],
)
def test_a_path_with_a_content_security_policy_rule_answers_the_rule_s_policy(
    path: str,
    rule_applies: bool,
) -> None:
    """STACK-15: a rule's path gets its policy, every other path the default."""
    policy = a_policy_with_content_security_policy_rules(
        a_content_security_policy_rule("sandbox allow-scripts", prefixes=("/t/",))
    )
    app = an_app(policy=policy)
    app.get(path)(lambda: Response("body"))

    response = TestClient(app).get(path)

    expected_policy = "sandbox allow-scripts" if rule_applies else policy.content_security_policy
    assert_carries_policy_headers(
        response.headers,
        SecurityHeadersPolicy(expected_policy),
        hsts=True,
    )


@pytest.mark.parametrize(
    ("rules", "expected_policy"),
    [
        pytest.param(
            [("/t/", "first"), ("/t/token/", "second")],
            "first",
            id="the-earlier-of-two-overlapping-rules-wins",
        ),
        pytest.param(
            [("/t/token/", "second"), ("/t/", "first")],
            "second",
            id="the-order-decides-not-the-longer-prefix",
        ),
        pytest.param(
            [("/other/", "first"), ("/t/", "second")],
            "second",
            id="a-rule-that-does-not-match-is-skipped",
        ),
    ],
)
def test_the_first_matching_content_security_policy_rule_wins_in_the_order_given(
    rules: list[tuple[str, str]], expected_policy: str
) -> None:
    policy = a_policy_with_content_security_policy_rules(
        *(a_content_security_policy_rule(value, prefixes=(prefix,)) for prefix, value in rules)
    )
    app = an_app(policy=policy)
    app.get("/t/token/page")(lambda: Response("body"))

    response = TestClient(app).get("/t/token/page")

    assert response.headers["content-security-policy"] == expected_policy


def test_a_rule_policy_that_allows_a_framer_leaves_x_frame_options_off() -> None:
    policy = a_policy_with_content_security_policy_rules(
        a_content_security_policy_rule(FRAMER_POLICY, prefixes=("/embed/",))
    )
    app = an_app(policy=policy)
    app.get("/embed/a")(lambda: Response("body"))
    app.get("/other")(lambda: Response("body"))

    framed = TestClient(app).get("/embed/a")
    default = TestClient(app).get("/other")

    assert "x-frame-options" not in framed.headers
    assert default.headers["x-frame-options"] == "DENY"


def test_the_logout_page_keeps_its_own_policy_under_a_rule_for_its_path() -> None:
    rule_policy = "sandbox allow-scripts"
    host_policy = replace(
        HOST_POLICY,
        content_security_policy_rules=(
            a_content_security_policy_rule(rule_policy, prefixes=(LOGOUT_PATH,)),
        ),
    )

    def add_a_notes_page(app: FastAPI) -> None:
        app.get(f"{LOGOUT_PATH}/notes")(lambda: Response("body"))

    app = the_logout_app(host_policy=host_policy, host_middleware=add_a_notes_page)
    client = TestClient(app)

    page = client.post(LOGOUT_PATH, headers={"sec-fetch-site": "same-origin"})
    notes = client.get(f"{LOGOUT_PATH}/notes")

    assert page.headers["content-security-policy"] == the_logout_policy_of(page)
    assert "webauth-own-policy" not in page.headers
    assert notes.headers["content-security-policy"] == rule_policy
