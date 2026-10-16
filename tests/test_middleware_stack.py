"""install_web_auth_middleware: one order, so the library's refusals carry the headers."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response
from webauth_arrangement import (
    ALLOWED_ORIGIN,
    API_PATH,
    HTTPS_TEST_SERVER,
    AlwaysFailingRateLimitBackend,
    a_web_auth_config,
    assert_carries_policy_headers,
)

from webauth.config import WEB_AUTH_STATE_ATTRIBUTE, install_web_auth_config
from webauth.middleware import (
    IpRateLimitMiddleware,
    SecurityHeadersMiddleware,
    install_web_auth_middleware,
)
from webauth.policies import (
    BodySizePolicy,
    CsrfPolicy,
    PathRules,
    PathShape,
    RateLimitBudget,
    RateLimitClass,
    RateLimitPolicy,
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
SAME_ORIGIN = {"origin": ALLOWED_ORIGIN, "sec-fetch-site": "same-origin"}
FOREIGN = {"origin": FOREIGN_ORIGIN}
FORM = "application/x-www-form-urlencoded"
JSON = "application/json"
OVERSIZED_BODY = b"x" * (BODY_LIMIT_BYTES + 1)


def a_rate_limit_policy(max_requests: int) -> RateLimitPolicy:
    budget = RateLimitBudget(max_requests, 60)
    return RateLimitPolicy(budgets=dict.fromkeys(RateLimitClass, budget))


def a_fresh_app(
    *, rate_limits: RateLimitBackend | None = None, cookie_secure: bool = True,
) -> FastAPI:
    app = FastAPI()
    config = a_web_auth_config(cookie_secure=cookie_secure)
    if rate_limits is not None:
        config = replace(config, rate_limits=rate_limits)
    install_web_auth_config(app, config)
    for path in (API_PATH, PROTECTED_PATH, WEBHOOK_PATH):
        app.add_api_route(path, lambda: {"status": "ok"}, methods=["GET", "POST"])

    @app.get(RAISING_PATH)
    def raising() -> None:
        raise RuntimeError("route failed")

    return app


def install_full_stack(app: FastAPI, *, max_requests: int = 100) -> None:
    install_web_auth_middleware(
        app,
        security_headers=HEADERS_POLICY,
        body_size=BodySizePolicy(default_max_bytes=BODY_LIMIT_BYTES),
        rate_limit=a_rate_limit_policy(max_requests),
        csrf_origin=CsrfPolicy(),
        csrf_token=CsrfPolicy(),
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


class TestAgentPresentatorShape:
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

    @pytest.mark.parametrize(
        "token_exempt",
        [
            pytest.param(PathRules(exact=frozenset({LOGIN_PATH})), id="exact-path"),
            pytest.param(PathRules(prefixes=("/login",)), id="prefix"),
            pytest.param(PathRules(shapes=(PathShape("/log", "in"),)), id="unverifiable-shape"),
        ],
    )
    def test_token_exemption_outside_the_origin_check_is_refused_before_touching_the_app(
        self, token_exempt: PathRules,
    ) -> None:
        app = a_fresh_app()
        origin_policy = CsrfPolicy(protected=PathRules(prefixes=("/api",)))
        token_policy = CsrfPolicy(token_exempt=token_exempt)
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
        assert len(app.user_middleware) == 3

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

    def test_missing_config_500_spends_nothing(self) -> None:
        app = a_fresh_app()
        install_full_stack(app, max_requests=1)
        client = TestClient(app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=False)
        config = getattr(app.state, WEB_AUTH_STATE_ATTRIBUTE)
        delattr(app.state, WEB_AUTH_STATE_ATTRIBUTE)
        assert get_api(client).status_code == 500
        install_web_auth_config(app, config)
        assert get_api(client).status_code == 200


class TestCompetingRefusals:
    def test_a_request_failing_origin_and_token_gets_the_origin_refusal(self) -> None:
        response = post_cross_origin(a_full_stack_client())
        assert response.json() == {"detail": "Cross-origin request rejected"}
