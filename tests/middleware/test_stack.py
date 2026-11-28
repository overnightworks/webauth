"""The stack WebAuth.install places: one order, so the library's refusals carry the headers."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass, replace

import anyio
import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tests.support.full_stack_arrangement import (
    BACKGROUND_PATH,
    BODY_LIMIT_BYTES,
    CONTEXT_SETTING_PATH,
    DOWNSTREAM_MARK,
    FAILING_STREAM_PATH,
    HEADERS_POLICY,
    RAISING_PATH,
    READING_PATH,
    ROUTE_FAILURE,
    TYPED_PATH,
    WEBHOOK_PATH,
    WEBHOOK_PREFIX,
    a_fresh_app,
    install_full_stack,
)
from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.rate_limit_arrangement import AlwaysFailingRateLimitBackend
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.session_store_arrangement import SessionRecordsInMemory
from tests.support.webauth_arrangement import (
    ALLOWED_ORIGIN,
    API_PATH,
    HTTPS_TEST_SERVER,
    SAME_ORIGIN_REQUEST,
    SPEC_WITH_CONCURRENT_READER,
    SPEC_WITHOUT_CONCURRENT_READER,
    a_signed_in_same_origin_request,
    a_web_auth_config,
    an_auth_app,
    an_http_scope,
    completed,
    drive,
    starts,
)
from webauth.dependencies import LoginRedirect
from webauth.middleware import BearerGate, MachinePaths, SessionGate
from webauth.middleware.bearer_gate import _BearerGateMiddleware
from webauth.middleware.body_size import _BodySizeLimitMiddleware
from webauth.middleware.csrf import _CsrfOriginMiddleware
from webauth.middleware.path_refusal import _PathRefusalMiddleware
from webauth.middleware.rate_limit import _IpRateLimitMiddleware
from webauth.middleware.security_headers import _SecurityHeadersMiddleware
from webauth.middleware.session_gate import _SessionGateMiddleware
from webauth.middleware.store_outage import _StoreOutageMiddleware
from webauth.policies import (
    AuthorizedParties,
    CsrfPolicy,
    PathRules,
    PathShape,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
)
from webauth.ports import RateLimitBackend
from webauth.web_auth import ServedBehind, WebAuth, WebAuthSettings

FOREIGN_ORIGIN = "https://evil.test"
A_SESSION_GATE = SessionGate(login_redirect=None, public=())


def a_bearer_gate_of(_auth: WebAuth) -> BearerGate:
    return BearerGate(
        machine_paths=MachinePaths(
            PathRules(prefixes=("/api/admin/",)),
            AuthorizedParties(frozenset({"hal"})),
        ),
    )


FOREIGN = {"origin": FOREIGN_ORIGIN}
FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
OVERSIZED_BODY = b"x" * (BODY_LIMIT_BYTES + 1)
A_CONFIG = a_web_auth_config()
TWO_CHUNKS_UNDER_THE_LIMIT_EACH = (b"x" * 60, b"x" * 60)


INNER_MIDDLEWARE_MARK: ContextVar[str] = ContextVar("inner_middleware_mark", default="unset")


class ContextSettingMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        INNER_MIDDLEWARE_MARK.set("set-by-the-inner-middleware")
        await self.app(scope, receive, send)


def a_full_stack_client(
    *,
    max_requests: int = 100,
    rate_limits: RateLimitBackend | None = None,
    cookie_secure: bool = True,
) -> TestClient:
    app = a_fresh_app()
    install_full_stack(
        app, max_requests=max_requests, rate_limits=rate_limits, cookie_secure=cookie_secure
    )
    return TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)


def post_oversized(client: TestClient) -> Response:
    return client.post(API_PATH, content=OVERSIZED_BODY, headers=SAME_ORIGIN_REQUEST)


def post_cross_origin(client: TestClient) -> Response:
    return client.post(API_PATH, json={"n": 1}, headers=FOREIGN)


def post_without_provenance(client: TestClient) -> Response:
    return client.post(API_PATH, json={"n": 1})


def get_api(client: TestClient) -> Response:
    return client.get(API_PATH)


def get_api_twice(client: TestClient) -> Response:
    get_api(client)
    return get_api(client)


@dataclass
class HostSightings:
    reached_inside: list[str]
    seen_outside: list[Response]


def a_client_between_host_middlewares(
    *,
    max_requests: int = 100,
    rate_limits: RateLimitBackend | None = None,
    session_gate: SessionGate | None = None,
    cookie_secure: bool = True,
) -> tuple[TestClient, HostSightings]:
    app = a_fresh_app()
    sightings = HostSightings(reached_inside=[], seen_outside=[])

    @app.middleware("http")
    async def inside(request: Request, call_next):  # type: ignore[no-untyped-def]
        sightings.reached_inside.append(request.url.path)
        return await call_next(request)

    install_full_stack(
        app,
        max_requests=max_requests,
        rate_limits=rate_limits,
        cookie_secure=cookie_secure,
        session_gate=session_gate,
    )

    @app.middleware("http")
    async def outside(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        sightings.seen_outside.append(response)
        return response

    client = TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)
    return client, sightings


def get_api_as_a_browser(client: TestClient) -> Response:
    return client.get(API_PATH, headers={"accept": "text/html"}, follow_redirects=False)


A_REDIRECTING_SESSION_GATE = replace(
    A_SESSION_GATE,
    login_redirect=LoginRedirect(path="/login", redirect_query_param="next"),
)


@dataclass(frozen=True)
class Refusal:
    status: int
    retry_after: str | None = None
    hsts: bool = True
    admitted_before: int = 0


class TestHostMiddlewarePlacement:
    @pytest.mark.parametrize(
        ("arrange", "send", "refusal"),
        [
            pytest.param(
                a_client_between_host_middlewares,
                post_oversized,
                Refusal(413),
                id="413-by-content-length",
            ),
            pytest.param(
                lambda: a_client_between_host_middlewares(max_requests=1),
                get_api_twice,
                Refusal(429, retry_after="60", admitted_before=1),
                id="429-budget-exhausted",
            ),
            pytest.param(
                lambda: a_client_between_host_middlewares(max_requests=1, cookie_secure=False),
                get_api_twice,
                Refusal(429, retry_after="60", hsts=False, admitted_before=1),
                id="429-without-hsts-when-cookies-are-not-secure",
            ),
            pytest.param(
                lambda: a_client_between_host_middlewares(
                    rate_limits=AlwaysFailingRateLimitBackend(),
                ),
                get_api,
                Refusal(503, retry_after="5"),
                id="503-limiter-unavailable",
            ),
            pytest.param(
                a_client_between_host_middlewares,
                post_cross_origin,
                Refusal(403),
                id="403-foreign-origin",
            ),
            pytest.param(
                a_client_between_host_middlewares,
                post_without_provenance,
                Refusal(403),
                id="403-missing-provenance",
            ),
            pytest.param(
                lambda: a_client_between_host_middlewares(session_gate=A_REDIRECTING_SESSION_GATE),
                get_api_as_a_browser,
                Refusal(302),
                id="session-gate-302",
            ),
            pytest.param(
                lambda: a_client_between_host_middlewares(session_gate=A_SESSION_GATE),
                get_api,
                Refusal(401),
                id="session-gate-401",
            ),
            pytest.param(
                a_client_between_host_middlewares,
                lambda client: client.get(RAISING_PATH),
                Refusal(500, admitted_before=1),
                id="500-raising-route",
            ),
        ],
    )
    def test_a_host_middleware_before_the_call_never_sees_a_refusal_one_after_it_sees_it_with_the_headers_set(  # noqa: E501
        self,
        arrange: Callable[[], tuple[TestClient, HostSightings]],
        send: Callable[[TestClient], Response],
        refusal: Refusal,
    ) -> None:
        """STACK-01, STACK-02: only the middleware after the call sees a refusal, with headers."""
        client, sightings = arrange()

        response = send(client)

        assert response.status_code == refusal.status
        assert response.headers.get("retry-after") == refusal.retry_after
        assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=refusal.hsts)
        assert len(sightings.reached_inside) == refusal.admitted_before
        seen = sightings.seen_outside[-1]
        assert seen.status_code == refusal.status
        assert_carries_policy_headers(seen.headers, HEADERS_POLICY, hsts=refusal.hsts)

    @pytest.mark.parametrize(
        "outside",
        [
            pytest.param(lambda: JSONResponse({}, status_code=204), id="response"),
            pytest.param(lambda: _raise(RuntimeError("host failed")), id="exception"),
        ],
    )
    def test_what_a_host_middleware_after_the_call_produces_itself_carries_no_library_headers(
        self,
        outside: Callable[[], Response],
    ) -> None:
        """STACK-03: a response or exception made outside the library stack has no headers."""
        app = a_fresh_app()
        install_full_stack(app)

        @app.middleware("http")
        async def outside_the_library(request: Request, call_next):  # type: ignore[no-untyped-def]
            return outside()

        response = TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            raise_server_exceptions=False,
        ).get(API_PATH)

        assert response.status_code in {204, 500}
        assert response.headers.get("x-frame-options") is None


def _raise(error: Exception) -> Response:
    raise error


class TestAnExemptWebhookPrefix:
    @staticmethod
    def a_client() -> TestClient:
        app = a_fresh_app()
        install_the_gated_stack(
            app,
            config=A_CONFIG,
            sessions=SessionRecordsInMemory().in_transaction,
            security_headers=HEADERS_POLICY,
            csrf_origin=CsrfPolicy(exempt=PathRules(prefixes=(WEBHOOK_PREFIX,))),
        )
        return TestClient(app, base_url=HTTPS_TEST_SERVER)

    @pytest.mark.parametrize(
        ("path", "headers", "content_type", "status"),
        [
            pytest.param(API_PATH, FOREIGN, FORM, 403, id="cross-origin-form"),
            pytest.param(WEBHOOK_PATH, FOREIGN, JSON, 200, id="exempt-webhook-passes"),
        ],
    )
    def test_decides_each_request_with_the_headers_set(
        self,
        path: str,
        headers: dict[str, str],
        content_type: str,
        status: int,
    ) -> None:
        response = self.a_client().post(
            path,
            content=b"n=1",
            headers={**headers, "content-type": content_type},
        )
        assert response.status_code == status
        assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


class TestRefusedInstallation:
    def test_settings_without_csrf_origin_are_refused(self) -> None:
        """CSRF-01, CSRF-02: the settings of the composition call require `csrf_origin`."""
        with pytest.raises(TypeError, match="csrf_origin"):
            WebAuthSettings(  # type: ignore[call-arg]
                config=A_CONFIG,
                max_sessions=None,
                security_headers=HEADERS_POLICY,
            )

    def test_a_full_install_with_a_bearer_gate_runs_the_library_in_one_order(self) -> None:
        app = a_fresh_app()
        install_full_stack(
            app,
            session_gate=A_SESSION_GATE,
            bearer_of=a_bearer_gate_of,
            front=ServedBehind.SHARED_FRONT,
        )
        assert [entry.cls for entry in app.user_middleware][1:] == [
            _SecurityHeadersMiddleware,
            _PathRefusalMiddleware,
            _BodySizeLimitMiddleware,
            _IpRateLimitMiddleware,
            _StoreOutageMiddleware,
            _BearerGateMiddleware,
            _CsrfOriginMiddleware,
            _SessionGateMiddleware,
        ]

    def test_refused_repeat_leaves_the_budget_charged_once(self) -> None:
        app = a_fresh_app()
        install_full_stack(app, max_requests=2)
        with pytest.raises(RuntimeError, match="already carries"):
            install_full_stack(app, max_requests=2)
        client = TestClient(app, base_url=HTTPS_TEST_SERVER)
        assert [get_api(client).status_code for _ in range(3)] == [200, 200, 429]


class TestBudgetSemantics:
    @pytest.mark.parametrize(
        ("refused_request", "refusal_status", "next_status"),
        [
            pytest.param(post_oversized, 413, 200, id="content-length-413-spends-nothing"),
            pytest.param(post_without_provenance, 403, 429, id="csrf-403-spends-one"),
            pytest.param(
                lambda client: client.get(RAISING_PATH),
                500,
                429,
                id="raising-route-spends-one",
            ),
        ],
    )
    def test_refusal_spends_the_budget_as_documented(
        self,
        refused_request: Callable[[TestClient], Response],
        refusal_status: int,
        next_status: int,
    ) -> None:
        client = a_full_stack_client(max_requests=1)
        assert refused_request(client).status_code == refusal_status
        assert get_api(client).status_code == next_status


class TestARateLimitRuleIsChosenByThePathTheRouterRoutes:
    @pytest.mark.parametrize("encoded", ["%3F", "%23"])
    def test_a_shape_budget_is_spent_for_an_encoded_delimiter_in_a_path_parameter(
        self,
        encoded: str,
    ) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget("default", max_requests=1, window_seconds=60),
            rules=(
                RateLimitRule(
                    PathRules(shapes=(PathShape("/api/people/", "/export"),)),
                    RateLimitBudget("export", max_requests=2, window_seconds=60),
                ),
            ),
        )
        auth = an_auth_app(
            None,
            gate=True,
            public=(PublicRule(PathRules(prefixes=("/api/",))),),
            stack_policies={"rate_limit": policy},
        )
        auth.app.add_api_route(
            "/api/people/{subject}/export",
            lambda: {"status": "ok"},
            methods=["GET"],
        )

        statuses = [
            auth.client.get(f"/api/people/alice{encoded}x/export").status_code for _ in range(3)
        ]

        assert statuses == [200, 200, 429]


class BarrierRateLimitBackend:
    """Admits a check only once a second check is in flight beside it."""

    def __init__(self) -> None:
        self._barrier = threading.Barrier(2, timeout=5)

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        self._barrier.wait()
        return True


class TestASlowRateLimiterDoesNotStallTheEventLoop:
    @pytest.mark.anyio
    async def test_two_concurrent_requests_are_checked_side_by_side(self) -> None:
        app = a_fresh_app()
        install_full_stack(app, rate_limits=BarrierRateLimitBackend())
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url=HTTPS_TEST_SERVER) as client:
            responses = await asyncio.gather(client.get(API_PATH), client.get(API_PATH))

        assert [response.status_code for response in responses] == [200, 200]


class HeldRateLimitBackend:
    """Signals that a check is running, then holds it until released, then fails or allows."""

    def __init__(self, *, fails_after_release: bool) -> None:
        self.fails_after_release = fails_after_release
        self.entered = threading.Event()
        self.release = threading.Event()

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        self.entered.set()
        assert self.release.wait(timeout=5)
        if self.fails_after_release:
            raise ConnectionError("rate limit store unreachable")
        return True


class TestARequestCancelledDuringItsRateLimitCheck:
    @pytest.mark.anyio
    @pytest.mark.parametrize("fails_after_release", [False, True], ids=["allowing", "failing"])
    async def test_neither_runs_the_app_nor_sends_a_response(
        self, fails_after_release: bool
    ) -> None:
        backend = HeldRateLimitBackend(fails_after_release=fails_after_release)
        app = a_fresh_app()
        route_runs: list[str] = []

        async def cancelled_route() -> dict[str, bool]:
            route_runs.append("ran")
            return {"ok": True}

        app.add_api_route("/cancelled", cancelled_route, methods=["GET"])
        install_full_stack(app, rate_limits=backend)
        sent: list[str] = []
        request_scope = anyio.CancelScope()

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: Message) -> None:
            sent.append(message["type"])

        async def drive_request() -> None:
            with request_scope:
                await app(an_http_scope(app, "/cancelled"), receive, send)

        async with anyio.create_task_group() as tasks:
            tasks.start_soon(drive_request)
            await anyio.to_thread.run_sync(backend.entered.wait)
            request_scope.cancel()
            backend.release.set()

        assert (route_runs, sent) == ([], [])


def an_authenticated_full_stack_app(*, max_requests: int = 100) -> FastAPI:
    app = a_fresh_app()
    install_full_stack(app, max_requests=max_requests)
    return app


def a_signed_in_same_origin_client(app: FastAPI) -> TestClient:
    client = TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)
    client.headers.update(
        {name.decode(): value.decode() for name, value in a_signed_in_same_origin_request(A_CONFIG)}
    )
    client.headers["origin"] = ALLOWED_ORIGIN
    return client


def streamed(*chunks: bytes) -> Iterator[bytes]:
    yield from chunks


class TestAStreamedBodyOverTheLimit:
    def test_a_streamed_413_spends_exactly_one_request_of_the_budget(self) -> None:
        client = a_signed_in_same_origin_client(an_authenticated_full_stack_app(max_requests=2))

        streamed_over_the_limit = streamed(*TWO_CHUNKS_UNDER_THE_LIMIT_EACH)
        statuses = [
            client.post(READING_PATH, content=streamed_over_the_limit).status_code,
            client.get(API_PATH).status_code,
            client.get(API_PATH).status_code,
        ]

        assert statuses == [413, 200, 429]

    def test_a_parsed_body_over_the_limit_reaches_the_hosts_http_exception_handler_and_its_background_task(  # noqa: E501
        self,
    ) -> None:
        app = an_authenticated_full_stack_app()
        handled: list[str] = []

        @app.exception_handler(StarletteHTTPException)
        async def host_handler(request: Request, error: StarletteHTTPException) -> JSONResponse:
            handled.append("handler")
            return JSONResponse(
                {"host": error.status_code},
                status_code=error.status_code,
                background=BackgroundTask(handled.append, "task"),
            )

        response = a_signed_in_same_origin_client(app).post(
            TYPED_PATH,
            content=streamed(b'{"text":"' + b"x" * 54, b"x" * 60 + b'"}'),
            headers={"content-type": JSON},
        )

        assert (response.status_code, response.json()) == (400, {"host": 400})
        assert handled == ["handler", "task"]


class TestResponsesBehindThePureAsgiMiddlewares:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "spec_version",
        [
            pytest.param(SPEC_WITH_CONCURRENT_READER, id="spec-2.3"),
            pytest.param(SPEC_WITHOUT_CONCURRENT_READER, id="spec-2.4"),
        ],
    )
    async def test_a_response_that_fails_mid_stream_ends_incomplete_and_its_exception_reaches_the_server(  # noqa: E501
        self, spec_version: str
    ) -> None:
        app = an_authenticated_full_stack_app()
        scope = an_http_scope(app, FAILING_STREAM_PATH, spec_version=spec_version)

        sent, raised = await drive(app, scope, body_chunks=(b"",))

        assert [start["status"] for start in starts(sent)] == [200]
        assert not completed(sent)
        assert raised is ROUTE_FAILURE

    @pytest.mark.anyio
    async def test_a_context_variable_set_downstream_is_visible_to_the_caller_after_the_call(
        self,
    ) -> None:
        """STACK-04: the middlewares run the app in the caller's task."""
        app = an_authenticated_full_stack_app()
        scope = an_http_scope(
            app, CONTEXT_SETTING_PATH, spec_version=SPEC_WITHOUT_CONCURRENT_READER
        )

        sent, _ = await drive(app, scope, body_chunks=(b"",))

        assert DOWNSTREAM_MARK.get() == "set-by-the-route"
        [start] = starts(sent)
        assert start["status"] == 200
        assert completed(sent)
        assert_carries_policy_headers(Headers(raw=start["headers"]), HEADERS_POLICY, hsts=True)

    @pytest.mark.anyio
    async def test_a_context_variable_set_by_an_inner_middleware_is_visible_to_the_caller_after_the_call(  # noqa: E501
        self,
    ) -> None:
        """STACK-04: the middlewares run an inner middleware in the caller's task."""
        app = a_fresh_app()
        app.add_middleware(ContextSettingMiddleware)
        install_full_stack(app)
        scope = an_http_scope(app, API_PATH, spec_version=SPEC_WITHOUT_CONCURRENT_READER)

        await drive(app, scope, body_chunks=(b"",))

        assert INNER_MIDDLEWARE_MARK.get() == "set-by-the-inner-middleware"

    def test_an_admitted_routes_background_task_runs(self) -> None:
        app = an_authenticated_full_stack_app()

        response = a_signed_in_same_origin_client(app).get(BACKGROUND_PATH)

        assert response.status_code == 200
        assert app.state.background_ran == [BACKGROUND_PATH]
