"""install_web_auth_middleware: one order, so the library's refusals carry the headers."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import nullcontext
from contextvars import ContextVar
from dataclasses import dataclass, replace

import anyio
import httpx
import pytest
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Mount, Route
from starlette.types import Message, Receive, Scope, Send
from webauth_arrangement import (
    ALLOWED_ORIGIN,
    API_PATH,
    HTTPS_TEST_SERVER,
    SPEC_WITH_CONCURRENT_READER,
    SPEC_WITHOUT_CONCURRENT_READER,
    AlwaysFailingRateLimitBackend,
    AuthApp,
    SessionRecordsInMemory,
    a_csrf_passing_request_headers,
    a_web_auth_config,
    an_auth_app,
    an_http_scope,
    assert_carries_policy_headers,
    completed,
    drive,
    starts,
)

from webauth.config import install_web_auth_config
from webauth.middleware import (
    CsrfOriginMiddleware,
    CsrfTokenMiddleware,
    IpRateLimitMiddleware,
    SecurityHeadersMiddleware,
    SessionGate,
    SessionGateMiddleware,
    install_web_auth_middleware,
)
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PathShape,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)
from webauth.ports import RateLimitBackend

FOREIGN_ORIGIN = "https://evil.test"
BODY_LIMIT_BYTES = 100
RAISING_PATH = "/boom"
LOGIN_PATH = "/login"
WEBHOOK_PREFIX = "/webhook/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
PROTECTED_PATH = "/api/protected"
HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
A_SESSION_GATE = SessionGate(
    session_transaction=lambda: nullcontext(SessionRecordsInMemory()),
    login_redirect=None,
    public=(),
)
SAME_ORIGIN = {"origin": ALLOWED_ORIGIN, "sec-fetch-site": "same-origin"}
FOREIGN = {"origin": FOREIGN_ORIGIN}
FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
OVERSIZED_BODY = b"x" * (BODY_LIMIT_BYTES + 1)
READING_PATH = "/reads-body"
TYPED_PATH = "/typed"
FAILING_STREAM_PATH = "/fails-mid-stream"
BACKGROUND_PATH = "/with-background"
CONTEXT_SETTING_PATH = "/sets-context"
NO_STORE = "no-store"
A_CONFIG = a_web_auth_config()
TWO_CHUNKS_UNDER_THE_LIMIT_EACH = (b"x" * 60, b"x" * 60)


class TypedBody(BaseModel):
    text: str


class RouteFailure(RuntimeError):
    pass


ROUTE_FAILURE = RouteFailure("mid-stream")
DOWNSTREAM_MARK: ContextVar[str] = ContextVar("downstream_mark", default="unset")


def a_rate_limit_policy(max_requests: int) -> RateLimitPolicy:
    return RateLimitPolicy(default=RateLimitBudget("api", max_requests, 60))


def a_fresh_app(
    *,
    rate_limits: RateLimitBackend | None = None,
    cookie_secure: bool = True,
) -> FastAPI:
    app = an_app_without_config()
    config = a_web_auth_config(cookie_secure=cookie_secure)
    if rate_limits is not None:
        config = replace(config, rate_limits=rate_limits)
    install_web_auth_config(app, config)
    return app


def an_app_without_config() -> FastAPI:
    app = FastAPI()
    app.state.background_ran = []
    for path in (API_PATH, PROTECTED_PATH, WEBHOOK_PATH):
        app.add_api_route(path, lambda: {"status": "ok"}, methods=["GET", "POST"])

    @app.get(RAISING_PATH)
    def raising() -> None:
        raise RuntimeError("route failed")

    @app.post(READING_PATH)
    async def reading(request: Request) -> dict[str, int]:
        return {"length": len(await request.body())}

    @app.post(TYPED_PATH)
    async def typed(body: TypedBody) -> dict[str, int]:
        return {"length": len(body.text)}

    @app.get(FAILING_STREAM_PATH)
    async def failing_stream() -> StreamingResponse:
        async def stream() -> AsyncIterator[bytes]:
            yield b"first"
            raise ROUTE_FAILURE

        return StreamingResponse(stream())

    @app.get(CONTEXT_SETTING_PATH)
    async def context_setting() -> dict[str, bool]:
        DOWNSTREAM_MARK.set("set-by-the-route")
        return {"ok": True}

    @app.get(BACKGROUND_PATH)
    async def with_background(tasks: BackgroundTasks) -> dict[str, bool]:
        tasks.add_task(app.state.background_ran.append, BACKGROUND_PATH)
        return {"ok": True}

    return app


def install_full_stack(
    app: FastAPI, *, max_requests: int = 100, session_gate: SessionGate | None = None,
) -> None:
    install_web_auth_middleware(
        app,
        security_headers=HEADERS_POLICY,
        body_size=BodySizePolicy(default_max_bytes=BODY_LIMIT_BYTES),
        rate_limit=a_rate_limit_policy(max_requests),
        csrf_origin=CsrfPolicy(),
        csrf_token=CsrfPolicy(),
        session_gate=session_gate,
    )


def a_full_stack_client(
    *,
    max_requests: int = 100,
    rate_limits: RateLimitBackend | None = None,
    cookie_secure: bool = True,
) -> TestClient:
    app = a_fresh_app(rate_limits=rate_limits, cookie_secure=cookie_secure)
    install_full_stack(app, max_requests=max_requests)
    return TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)


def post_oversized(client: TestClient) -> Response:
    return client.post(API_PATH, content=OVERSIZED_BODY, headers=SAME_ORIGIN)


def post_cross_origin(client: TestClient) -> Response:
    return client.post(API_PATH, json={"n": 1}, headers=FOREIGN)


def post_without_token(client: TestClient) -> Response:
    return client.post(API_PATH, json={"n": 1}, headers=SAME_ORIGIN)


def get_api(client: TestClient) -> Response:
    return client.get(API_PATH)


def get_api_twice(client: TestClient) -> Response:
    get_api(client)
    return get_api(client)


@dataclass(frozen=True)
class Refusal:
    status: int
    retry_after: str | None = None
    hsts: bool = True


class TestLibraryRefusalsCarryTheSecurityHeaders:
    @pytest.mark.parametrize(
        ("client_factory", "send", "refusal"),
        [
            pytest.param(
                a_full_stack_client, post_oversized, Refusal(413), id="413-by-content-length",
            ),
            pytest.param(
                lambda: a_full_stack_client(max_requests=1),
                get_api_twice,
                Refusal(429, retry_after="60"),
                id="429-budget-exhausted",
            ),
            pytest.param(
                lambda: a_full_stack_client(max_requests=1, cookie_secure=False),
                get_api_twice,
                Refusal(429, retry_after="60", hsts=False),
                id="429-without-hsts-when-cookies-are-not-secure",
            ),
            pytest.param(
                lambda: a_full_stack_client(rate_limits=AlwaysFailingRateLimitBackend()),
                get_api,
                Refusal(503, retry_after="5"),
                id="503-limiter-unavailable",
            ),
            pytest.param(
                a_full_stack_client, post_cross_origin, Refusal(403), id="403-foreign-origin",
            ),
            pytest.param(
                a_full_stack_client, post_without_token, Refusal(403), id="403-missing-token",
            ),
            pytest.param(
                a_full_stack_client,
                lambda client: client.get(RAISING_PATH),
                Refusal(500),
                id="500-raising-route",
            ),
        ],
    )
    def test_refusal_carries_the_policy_headers(
        self,
        client_factory: Callable[[], TestClient],
        send: Callable[[TestClient], Response],
        refusal: Refusal,
    ) -> None:
        response = send(client_factory())
        assert response.status_code == refusal.status
        assert response.headers.get("retry-after") == refusal.retry_after
        assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=refusal.hsts)


class TestHostMiddlewarePlacement:
    def test_host_middleware_added_around_the_call_sees_refusals_only_from_outside(self) -> None:
        app = a_fresh_app()
        reached_inside: list[str] = []
        seen_outside: list[tuple[int, str | None]] = []

        @app.middleware("http")
        async def inside(request: Request, call_next):  # type: ignore[no-untyped-def]
            reached_inside.append(request.url.path)
            return await call_next(request)

        install_full_stack(app)

        @app.middleware("http")
        async def outside(request: Request, call_next):  # type: ignore[no-untyped-def]
            response = await call_next(request)
            seen_outside.append((response.status_code, response.headers.get("x-frame-options")))
            return response

        response = post_without_token(
            TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False),
        )

        assert response.status_code == 403
        assert reached_inside == []
        assert seen_outside == [(403, "DENY")]


class TestWebhookPrefixOriginExemptionWithExactTokenProtection:
    @staticmethod
    def a_client() -> TestClient:
        app = a_fresh_app()
        install_web_auth_middleware(
            app,
            security_headers=HEADERS_POLICY,
            csrf_origin=CsrfPolicy(exempt=PathRules(prefixes=(WEBHOOK_PREFIX,))),
            csrf_token=CsrfPolicy(protected=PathRules(exact=(PROTECTED_PATH,))),
        )
        return TestClient(app, base_url=HTTPS_TEST_SERVER)

    @pytest.mark.parametrize(
        ("path", "headers", "content_type", "status"),
        [
            pytest.param(API_PATH, FOREIGN, FORM, 403, id="cross-origin-form"),
            pytest.param(PROTECTED_PATH, SAME_ORIGIN, JSON, 403, id="protected-path-without-token"),
            pytest.param(WEBHOOK_PATH, FOREIGN, JSON, 200, id="exempt-webhook-passes"),
        ],
    )
    def test_decides_each_request_with_the_headers_set(
        self, path: str, headers: dict[str, str], content_type: str, status: int,
    ) -> None:
        response = self.a_client().post(
            path, content=b"n=1", headers={**headers, "content-type": content_type},
        )
        assert response.status_code == status
        assert_carries_policy_headers(response.headers, HEADERS_POLICY, hsts=True)


class TestRefusedInstallation:
    def test_token_policy_without_origin_policy_is_refused_before_touching_the_app(self) -> None:
        app = a_fresh_app()
        token_policy = CsrfPolicy()
        with pytest.raises(ValueError, match="csrf_origin"):
            install_web_auth_middleware(
                app, security_headers=HEADERS_POLICY, csrf_token=token_policy,
            )
        assert app.user_middleware == []

    def test_token_exemption_outside_the_origin_check_is_refused_before_touching_the_app(
        self,
    ) -> None:
        app = a_fresh_app()
        token_policy = CsrfPolicy(token_exempt=PathRules(exact=frozenset({LOGIN_PATH})))
        origin_policy = CsrfPolicy(protected=PathRules(prefixes=("/api",)))
        with pytest.raises(ValueError, match="does not check"):
            install_web_auth_middleware(
                app,
                security_headers=HEADERS_POLICY,
                csrf_origin=origin_policy,
                csrf_token=token_policy,
            )
        assert app.user_middleware == []

    def test_token_exemption_covered_by_the_origin_check_is_installed(self) -> None:
        app = a_fresh_app()
        install_web_auth_middleware(
            app,
            security_headers=HEADERS_POLICY,
            csrf_origin=CsrfPolicy(),
            csrf_token=CsrfPolicy(token_exempt=PathRules(exact=frozenset({LOGIN_PATH}))),
        )
        client = TestClient(app)
        assert client.post(LOGIN_PATH, json={}, headers=FOREIGN).status_code == 403

    @pytest.mark.parametrize(
        "arrange",
        [
            pytest.param(install_full_stack, id="second-installer-call"),
            pytest.param(
                lambda app: app.add_middleware(SecurityHeadersMiddleware, policy=HEADERS_POLICY),
                id="hand-added-library-middleware",
            ),
        ],
    )
    def test_repeated_installation_is_refused(self, arrange: Callable[[FastAPI], None]) -> None:
        app = a_fresh_app()
        arrange(app)
        with pytest.raises(RuntimeError, match="already carries"):
            install_full_stack(app)

    @pytest.mark.parametrize(
        "subclass",
        [
            pytest.param(type("OwnHeaders", (SecurityHeadersMiddleware,), {}), id="headers"),
            pytest.param(type("OwnLimiter", (IpRateLimitMiddleware,), {}), id="rate-limit"),
            pytest.param(type("OwnOriginCheck", (CsrfOriginMiddleware,), {}), id="csrf-origin"),
            pytest.param(type("OwnTokenCheck", (CsrfTokenMiddleware,), {}), id="csrf-token"),
            pytest.param(type("OwnGate", (SessionGateMiddleware,), {}), id="session-gate"),
        ],
    )
    def test_hand_added_subclass_of_library_middleware_is_refused_and_leaves_the_app_alone(
        self, subclass: type,
    ) -> None:
        app = a_fresh_app()
        app.add_middleware(subclass, policy=HEADERS_POLICY)
        before = list(app.user_middleware)
        with pytest.raises(RuntimeError, match="already carries"):
            install_full_stack(app)
        assert app.user_middleware == before

    def test_every_middleware_a_full_install_adds_is_one_the_installer_refuses_to_find_present(
        self,
    ) -> None:
        installed = a_fresh_app()
        install_full_stack(installed, session_gate=A_SESSION_GATE)
        accepted = []
        for entry in installed.user_middleware:
            carrier = a_fresh_app()
            carrier.add_middleware(entry.cls, *entry.args, **entry.kwargs)
            try:
                install_full_stack(carrier)
            except RuntimeError:
                continue
            accepted.append(entry.cls.__name__)
        assert accepted == []

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
            pytest.param(post_without_token, 403, 429, id="csrf-403-spends-one"),
            pytest.param(
                lambda client: client.get(RAISING_PATH), 500, 429, id="raising-route-spends-one",
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

    def test_a_request_before_the_config_is_installed_answers_500_and_the_next_one_is_served(
        self,
    ) -> None:
        app = an_app_without_config()
        install_full_stack(app, max_requests=1)
        client = TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)
        assert get_api(client).status_code == 500
        install_web_auth_config(app, a_web_auth_config())
        assert get_api(client).status_code == 200


class TestARateLimitRuleIsChosenByThePathTheRouterRoutes:
    @pytest.mark.parametrize("encoded", ["%3F", "%23"])
    def test_a_shape_budget_is_spent_for_an_encoded_delimiter_in_a_path_parameter(
        self, encoded: str,
    ) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget("default", max_requests=1, window_seconds=60),
            rules=(RateLimitRule(
                PathRules(shapes=(PathShape("/api/people/", "/export"),)),
                RateLimitBudget("export", max_requests=2, window_seconds=60),
            ),),
        )
        auth = an_auth_app(
            None,
            gate=True,
            public=(PublicRule(PathRules(prefixes=("/api/",))),),
            stack_policies={"rate_limit": policy},
        )
        auth.app.add_api_route(
            "/api/people/{subject}/export", lambda: {"status": "ok"}, methods=["GET"],
        )

        statuses = [
            auth.client.get(f"/api/people/alice{encoded}x/export").status_code
            for _ in range(3)
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
        app = a_fresh_app(rate_limits=BarrierRateLimitBackend())
        install_full_stack(app)
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
        app = a_fresh_app(rate_limits=backend)
        route_runs: list[str] = []

        async def cancelled_route() -> dict[str, bool]:
            route_runs.append("ran")
            return {"ok": True}

        app.add_api_route("/cancelled", cancelled_route, methods=["GET"])
        install_full_stack(app)
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


class TestCompetingRefusals:
    def test_a_request_failing_origin_and_token_gets_the_origin_refusal(self) -> None:
        response = post_cross_origin(a_full_stack_client())
        assert response.json() == {"detail": "Cross-origin request rejected"}


def an_authenticated_full_stack_app(*, max_requests: int = 100) -> FastAPI:
    app = a_fresh_app()
    install_full_stack(app, max_requests=max_requests)
    return app


def a_csrf_passing_client(app: FastAPI) -> TestClient:
    client = TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)
    client.headers.update(
        {name.decode(): value.decode() for name, value in a_csrf_passing_request_headers(A_CONFIG)}
    )
    client.headers["origin"] = ALLOWED_ORIGIN
    return client


def streamed(*chunks: bytes) -> Iterator[bytes]:
    yield from chunks


class TestAStreamedBodyOverTheLimit:
    def test_a_streamed_413_spends_exactly_one_request_of_the_budget(self) -> None:
        client = a_csrf_passing_client(an_authenticated_full_stack_app(max_requests=2))

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

        response = a_csrf_passing_client(app).post(
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
        """Documented change: the middlewares run the app in the caller's task, where
        BaseHTTPMiddleware gave it a task of its own."""
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

    def test_an_admitted_routes_background_task_runs(self) -> None:
        app = an_authenticated_full_stack_app()

        response = a_csrf_passing_client(app).get(BACKGROUND_PATH)

        assert response.status_code == 200
        assert app.state.background_ran == [BACKGROUND_PATH]


@dataclass(frozen=True)
class RootPathForm:
    """How a request reaches the route at ``ROUTED_PATH`` under a ``root_path``."""

    application_root_path: str
    server_root_path: str
    asked_for: str


ROUTED_PATH = "/health"
EVERY_ROOT_PATH_FORM = [
    pytest.param(RootPathForm("", "", ROUTED_PATH), id="no-root-path"),
    pytest.param(RootPathForm("/app", "", ROUTED_PATH), id="application-root-path-stripped"),
    pytest.param(
        RootPathForm("/app", "", f"/app{ROUTED_PATH}"), id="application-root-path-unstripped",
    ),
    pytest.param(RootPathForm("", "/app", f"/app{ROUTED_PATH}"), id="server-root-path"),
]
THE_ROUTED_PATH = PathRules(exact=frozenset({ROUTED_PATH}))


def a_no_store_policy(paths: PathRules) -> SecurityHeadersPolicy:
    return SecurityHeadersPolicy(
        content_security_policy="default-src 'self'",
        cache_control_rules=(CacheControlRule(paths, NO_STORE),),
    )


def a_routed_app(form: RootPathForm, **stack_policies: object) -> AuthApp:
    """An application whose ``ROUTED_PATH`` route is public, under the policies given."""
    return an_auth_app(
        None,
        gate=True,
        public=(PublicRule(THE_ROUTED_PATH),),
        root_path=form.application_root_path,
        server_root_path=form.server_root_path,
        stack_policies=stack_policies,
    )


@pytest.mark.parametrize("form", EVERY_ROOT_PATH_FORM)
class TestEveryPolicySelectsByThePathTheRouterRoutes:
    def test_a_token_rule_that_protects_the_routed_path_refuses_a_request_without_one(
        self, form: RootPathForm,
    ) -> None:
        rules = CsrfPolicy(protected=THE_ROUTED_PATH)
        auth = a_routed_app(form, csrf_origin=rules, csrf_token=rules)

        response = auth.client.post(form.asked_for, headers=SAME_ORIGIN)

        assert (response.status_code, auth.route_runs) == (403, [])

    def test_a_token_rule_that_exempts_the_routed_path_lets_the_route_run(
        self, form: RootPathForm,
    ) -> None:
        auth = a_routed_app(
            form, csrf_origin=CsrfPolicy(), csrf_token=CsrfPolicy(exempt=THE_ROUTED_PATH),
        )

        response = auth.client.post(form.asked_for, headers=SAME_ORIGIN)

        assert (response.status_code, len(auth.route_runs)) == (200, 1)

    def test_an_origin_rule_that_protects_the_routed_path_refuses_a_foreign_origin(
        self, form: RootPathForm,
    ) -> None:
        auth = a_routed_app(form, csrf_origin=CsrfPolicy(protected=THE_ROUTED_PATH))

        response = auth.client.post(form.asked_for, headers=FOREIGN)

        assert (response.status_code, auth.route_runs) == (403, [])

    def test_an_origin_rule_that_exempts_the_routed_path_lets_the_route_run(
        self, form: RootPathForm,
    ) -> None:
        auth = a_routed_app(form, csrf_origin=CsrfPolicy(exempt=THE_ROUTED_PATH))

        response = auth.client.post(form.asked_for, headers=FOREIGN)

        assert (response.status_code, len(auth.route_runs)) == (200, 1)

    def test_a_rate_limit_rule_for_the_routed_path_spends_its_own_budget(
        self, form: RootPathForm,
    ) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget("default", max_requests=100, window_seconds=60),
            rules=(RateLimitRule(
                THE_ROUTED_PATH, RateLimitBudget("tight", max_requests=1, window_seconds=60),
            ),),
        )
        auth = a_routed_app(form, rate_limit=policy)

        statuses = [auth.client.get(form.asked_for).status_code for _ in range(2)]

        assert statuses == [200, 429]

    def test_a_body_size_rule_for_the_routed_path_applies_its_limit(
        self, form: RootPathForm,
    ) -> None:
        policy = BodySizePolicy(
            default_max_bytes=10, rules=(BodySizeRule(THE_ROUTED_PATH, max_bytes=1_000),),
        )
        auth = a_routed_app(form, body_size=policy)

        response = auth.client.post(form.asked_for, content=b"x" * 50)

        assert (response.status_code, len(auth.route_runs)) == (200, 1)

    def test_a_cache_control_rule_for_the_routed_path_sends_its_value(
        self, form: RootPathForm,
    ) -> None:
        auth = a_routed_app(form, security_headers=a_no_store_policy(THE_ROUTED_PATH))

        response = auth.client.get(form.asked_for)

        assert (response.status_code, response.headers["cache-control"]) == (200, NO_STORE)


class TestAPathNextToTheRootPathIsNotStripped:
    @pytest.mark.parametrize(("rule_path", "cache_control"), [
        pytest.param("/application/health", NO_STORE, id="written-as-the-router-routes"),
        pytest.param(ROUTED_PATH, None, id="written-below-a-root-path-it-does-not-have"),
    ])
    def test_a_rule_selects_the_path_only_when_it_names_it(
        self, rule_path: str, cache_control: str | None,
    ) -> None:
        form = RootPathForm("", "/app", "/application/health")
        auth = a_routed_app(
            form,
            security_headers=a_no_store_policy(PathRules(exact=frozenset({rule_path}))),
        )

        response = auth.client.get(form.asked_for)

        assert response.headers.get("cache-control") == cache_control


class TestACacheControlRuleOfTheParentSelectsThroughAMount:
    @pytest.mark.parametrize(("asked_for", "status"), [
        pytest.param("/api/x/y", 200, id="the-route-answers"),
        pytest.param("/api/x/boom", 500, id="the-route-raises"),
        pytest.param("/api/x/raw/z", 500, id="the-library-answers-500"),
    ])
    def test_the_rule_for_the_full_path_is_sent_whatever_the_mount_does_to_the_scope(
        self, asked_for: str, status: int,
    ) -> None:
        async def raising_app(scope: Scope, receive: Receive, send: Send) -> None:
            raise RouteFailure(asked_for)

        def failing() -> None:
            raise RouteFailure(asked_for)

        sub = Starlette(routes=[
            Route("/x/y", lambda request: JSONResponse({"ok": True})),
            Route("/x/boom", failing),
            Mount("/x/raw", app=raising_app),
        ])
        parent = FastAPI()
        install_web_auth_config(parent, a_web_auth_config())
        install_web_auth_middleware(
            parent, security_headers=a_no_store_policy(PathRules(prefixes=("/api/x/",))),
        )
        parent.mount("/api", sub)
        client = TestClient(parent, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)

        response = client.get(asked_for)

        assert (response.status_code, response.headers["cache-control"]) == (status, NO_STORE)
