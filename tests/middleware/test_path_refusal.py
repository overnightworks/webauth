"""The standard stack refuses a route path that carries a control character."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from importlib import import_module
from pkgutil import iter_modules
from types import ModuleType

import pytest
from fastapi import FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from httpx import Response
from starlette.responses import JSONResponse

import webauth.middleware
from tests.support.rate_limit_arrangement import RecordingRateLimitBackend
from tests.support.security_headers_arrangement import assert_carries_policy_headers
from tests.support.session_store_arrangement import SessionsRecordingTheirTransaction
from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    a_session,
    a_signed_in_same_origin_request,
    a_web_auth_config,
)
from webauth.config import install_web_auth_config
from webauth.dependencies import LoginRedirect
from webauth.middleware import SessionGate, install_web_auth_middleware
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy
from webauth.sign_in_routes import SignInPaths


def a_headers_policy() -> SecurityHeadersPolicy:
    return SecurityHeadersPolicy(content_security_policy="default-src 'self'")


def public_middleware_modules() -> list[ModuleType]:
    return [
        webauth.middleware,
        *(
            import_module(f"webauth.middleware.{module.name}")
            for module in iter_modules(webauth.middleware.__path__)
            if not module.name.startswith("_")
        ),
    ]


def some_sign_in_paths() -> SignInPaths:
    return SignInPaths(
        start="/sign-in/start",
        callback="/sign-in/callback",
        logout="/sign-in/logout",
        backchannel_logout="/sign-in/backchannel",
    )


@dataclass
class Arrangement:
    app: FastAPI
    rate_limits: RecordingRateLimitBackend
    sessions: SessionsRecordingTheirTransaction
    signed_in: dict[str, str]
    headers_policy: SecurityHeadersPolicy
    routes: dict[str, str]
    route_runs: list[str] = field(default_factory=list)
    host_middleware_runs: list[str] = field(default_factory=list)
    lifespan_events: list[str] = field(default_factory=list)

    def client(self, *, root_path: str = "") -> TestClient:
        return TestClient(
            self.app,
            base_url=HTTPS_TEST_SERVER,
            root_path=root_path,
            headers=self.signed_in,
            follow_redirects=False,
            raise_server_exceptions=False,
        )


def some_routes(sign_in_paths: SignInPaths) -> dict[str, str]:
    return {
        "start": sign_in_paths.start,
        "callback": sign_in_paths.callback,
        "logout": str(sign_in_paths.logout),
        "backchannel": str(sign_in_paths.backchannel_logout),
        "host": "/api/thing",
        "websocket": "/ws",
    }


def an_app_recording_its_lifespan(lifespan_events: list[str]) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        lifespan_events.append("startup")
        yield
        lifespan_events.append("shutdown")

    return FastAPI(lifespan=lifespan)


def a_stack_over_every_route() -> Arrangement:
    """A host with the sign-in routes, one host route and a WebSocket route behind the stack.

    Its client is signed in, so a request the stack admits reaches its route.
    """
    lifespan_events: list[str] = []
    app = an_app_recording_its_lifespan(lifespan_events)
    rate_limits = RecordingRateLimitBackend()
    sessions = SessionsRecordingTheirTransaction(a_session())
    config = replace(a_web_auth_config(), rate_limits=rate_limits)
    signed_in = {
        name.decode(): value.decode() for name, value in a_signed_in_same_origin_request(config)
    }
    sign_in_paths = some_sign_in_paths()
    headers_policy = a_headers_policy()
    routes = some_routes(sign_in_paths)
    arrangement = Arrangement(
        app,
        rate_limits,
        sessions,
        signed_in,
        headers_policy,
        routes,
        lifespan_events=lifespan_events,
    )
    install_web_auth_config(app, config)

    def run(request: Request) -> JSONResponse:
        arrangement.route_runs.append(request.scope["path"])
        return JSONResponse({"status": "ok"})

    for name, path in routes.items():
        if name != "websocket":
            app.add_api_route(path, run, methods=["GET", "POST"])

    @app.websocket(routes["websocket"])
    async def socket(websocket: WebSocket) -> None:
        arrangement.route_runs.append(websocket.scope["path"])
        await websocket.accept()
        await websocket.close()

    @app.middleware("http")
    async def before_the_call(request: Request, call_next):  # type: ignore[no-untyped-def]
        arrangement.host_middleware_runs.append(request.scope["path"])
        return await call_next(request)

    install_web_auth_middleware(
        app,
        sign_in_paths=sign_in_paths,
        security_headers=headers_policy,
        csrf_origin=CsrfPolicy(),
        session_gate=SessionGate(
            session_transaction=sessions.in_transaction,
            login_redirect=LoginRedirect(path="/login", redirect_query_param="next"),
            public=(),
        ),
    )
    return arrangement


def a_malformed_path_is_refused(response: Response, headers_policy: SecurityHeadersPolicy) -> None:
    assert response.status_code == 400
    assert response.json() == {"detail": "Malformed request path"}
    assert_carries_policy_headers(response.headers, headers_policy, hsts=True)


class TestARouteWithAControlCharacterInItsPath:
    @pytest.mark.parametrize("route", ["start", "callback", "logout", "backchannel", "host"])
    def test_a_trailing_line_feed_on_any_route_is_refused_with_the_headers_and_no_handler_runs(
        self, route: str
    ) -> None:
        """STACK-08: a route path with a control character gets 400 with the headers."""
        arrangement = a_stack_over_every_route()

        response = arrangement.client().post(f"{arrangement.routes[route]}%0A")

        a_malformed_path_is_refused(response, arrangement.headers_policy)
        assert arrangement.route_runs == []

    @pytest.mark.parametrize(
        "path",
        [
            pytest.param("/api/thing%09", id="tab-at-the-end"),
            pytest.param("/api/thing%0D", id="carriage-return-at-the-end"),
            pytest.param("/api/thing%0D%0A", id="carriage-return-and-line-feed-at-the-end"),
            pytest.param("/api/thing%00", id="nul-at-the-end"),
            pytest.param("/api/thing%7F", id="delete-at-the-end"),
            pytest.param("/api/thing%1F", id="last-of-the-lower-range-at-the-end"),
            pytest.param("/api/th%0Aing", id="line-feed-in-the-middle"),
            pytest.param("/%0Aapi/thing", id="line-feed-at-the-start"),
            pytest.param("/sign-in/start%0A?next=%2F", id="line-feed-before-a-query"),
        ],
    )
    def test_any_control_character_anywhere_in_the_path_is_refused(self, path: str) -> None:
        """STACK-08: U+0000 to U+001F and U+007F, anywhere in the route path."""
        arrangement = a_stack_over_every_route()

        response = arrangement.client().get(path)

        a_malformed_path_is_refused(response, arrangement.headers_policy)

    def test_a_refused_request_spends_no_budget_opens_no_session_and_meets_no_host_middleware(
        self,
    ) -> None:
        """STACK-09: it sits ahead of the rate limit and the session gate, inside the call."""
        arrangement = a_stack_over_every_route()

        response = arrangement.client().get(f"{arrangement.routes['host']}%0A")

        a_malformed_path_is_refused(response, arrangement.headers_policy)
        assert arrangement.rate_limits.checked == {}
        assert arrangement.sessions.event_names == []
        assert arrangement.host_middleware_runs == []

    @pytest.mark.parametrize(
        ("root_path", "path_template", "refused"),
        [
            pytest.param("/app", "/app{host}%0A", True, id="control-character-below-root"),
            pytest.param("/ap\np", "/ap%0Ap{host}", False, id="control-character-in-root"),
        ],
    )
    def test_under_a_root_path_the_route_path_decides(
        self, root_path: str, path_template: str, refused: bool
    ) -> None:
        """STACK-10: the path below ``root_path`` is the one the refusal reads."""
        arrangement = a_stack_over_every_route()

        response = arrangement.client(root_path=root_path).get(
            path_template.format(host=arrangement.routes["host"])
        )

        if refused:
            a_malformed_path_is_refused(response, arrangement.headers_policy)
        else:
            assert response.status_code == 200
            assert arrangement.route_runs != []

    def test_a_minimal_install_refuses_and_no_public_middleware_module_exports_the_class(
        self,
    ) -> None:
        """STACK-11: always installed, no policy and no option, not exported."""
        app = FastAPI()
        headers_policy = a_headers_policy()
        install_web_auth_config(app, a_web_auth_config())
        app.add_api_route("/api/thing", lambda: {"status": "ok"})
        install_web_auth_middleware(
            app,
            sign_in_paths=some_sign_in_paths(),
            security_headers=headers_policy,
            csrf_origin=CsrfPolicy(),
        )

        response = TestClient(app, base_url=HTTPS_TEST_SERVER).get("/api/thing%0A")

        a_malformed_path_is_refused(response, headers_policy)
        assert not [
            module.__name__
            for module in public_middleware_modules()
            if "PathRefusalMiddleware" in module.__all__
        ]

    def test_a_websocket_handshake_and_the_lifespan_pass_the_stack(self) -> None:
        """STACK-12: WebSocket and lifespan scopes pass."""
        arrangement = a_stack_over_every_route()
        socket_path = arrangement.routes["websocket"]

        with arrangement.client() as client:
            with client.websocket_connect(f"{socket_path}%0A"):
                pass
            events_while_running = list(arrangement.lifespan_events)

        assert events_while_running == ["startup"]
        assert arrangement.lifespan_events == ["startup", "shutdown"]
        assert arrangement.route_runs == [f"{socket_path}\n"]

    @pytest.mark.parametrize(
        ("path", "status"),
        [
            pytest.param("/api/thing%20", 404, id="space"),
            pytest.param("/api/thing;a=b", 404, id="semicolon-parameter"),
            pytest.param("/api/thing/", 307, id="trailing-slash"),
            pytest.param("/api/th%C3%A9ing", 404, id="non-ascii-character"),
        ],
    )
    def test_a_path_without_a_control_character_keeps_its_answer(
        self, path: str, status: int
    ) -> None:
        """STACK-13: a space, a parameter, a trailing slash and a non-ASCII character pass."""
        response = a_stack_over_every_route().client().get(path)

        assert response.status_code == status
