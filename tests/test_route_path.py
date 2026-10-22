"""Which path a policy rule is matched against: the one the application's router routes."""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import Receive, Scope, Send
from webauth_arrangement import (
    ALLOWED_ORIGIN,
    HTTPS_TEST_SERVER,
    AuthApp,
    a_web_auth_config,
    an_auth_app,
    an_http_scope,
)

from webauth.config import install_web_auth_config
from webauth.middleware import install_web_auth_middleware
from webauth.middleware._route_path import route_path
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)

NO_STORE = "no-store"
SAME_ORIGIN = {"origin": ALLOWED_ORIGIN, "sec-fetch-site": "same-origin"}
FOREIGN = {"origin": "https://evil.test"}


class RouteFailure(RuntimeError):
    pass


@pytest.mark.parametrize(("root_path", "asked_for", "routed"), [
    pytest.param("", "/api/x", "/api/x", id="an-empty-root-keeps-the-path"),
    pytest.param("/app", "/app/api/x", "/api/x", id="the-root-is-stripped"),
    pytest.param("/app", "/api/x", "/api/x", id="a-path-outside-the-root-stays-whole"),
    pytest.param("/app", "/application/x", "/application/x", id="a-segment-boundary-is-kept"),
    pytest.param("/app", "/app", "", id="a-path-equal-to-the-root-is-empty"),
    pytest.param("/app", "/app/", "/", id="the-root-with-a-slash-is-the-slash"),
    pytest.param("/app/", "/app/x", "/app/x", id="a-trailing-slash-root-is-not-trimmed"),
    pytest.param("/app/", "/app/", "", id="a-trailing-slash-root-equal-to-the-path-is-empty"),
    pytest.param("/a%20b", "/a b/x", "/a b/x", id="a-percent-encoded-root-is-not-decoded"),
    pytest.param("/a%20b", "/a%20b/x", "/x", id="a-percent-encoded-root-matches-literally"),
])
def test_the_router_path_strips_the_root_path_as_starlettes_router_does(
    root_path: str, asked_for: str, routed: str,
) -> None:
    scope = an_http_scope(FastAPI(), asked_for, root_path=root_path)

    assert route_path(scope) == routed


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
    auth = an_auth_app(
        None,
        gate=True,
        public=(PublicRule(THE_ROUTED_PATH),),
        root_path=form.application_root_path,
        stack_policies=stack_policies,
    )
    server_client = TestClient(
        auth.app, base_url=HTTPS_TEST_SERVER, cookies={}, root_path=form.server_root_path,
    )
    return replace(auth, client=server_client)


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

    def test_a_rate_limit_exemption_for_the_routed_path_spends_no_budget(
        self, form: RootPathForm,
    ) -> None:
        policy = RateLimitPolicy(
            default=RateLimitBudget("default", max_requests=1, window_seconds=60),
            exempt=THE_ROUTED_PATH,
        )
        auth = a_routed_app(form, rate_limit=policy)

        statuses = [auth.client.get(form.asked_for).status_code for _ in range(3)]

        assert statuses == [200, 200, 200]

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


NEXT_TO_THE_ROOT_PATH = "/application/api/x/y"


class TestAPathNextToTheRootPathIsNotStripped:
    """The server root ``/app`` does not own ``/application/...``; a rule names the whole path."""

    @staticmethod
    def an_app_serving_next_to_the_root_path(
        **stack_policies: object,
    ) -> tuple[TestClient, list[str]]:
        route_runs: list[str] = []
        app = FastAPI()
        install_web_auth_config(app, a_web_auth_config())
        install_web_auth_middleware(
            app,
            **{"security_headers": a_no_store_policy(PathRules()), **stack_policies},
        )

        @app.api_route(NEXT_TO_THE_ROOT_PATH, methods=["GET", "POST"])
        def route() -> dict[str, bool]:
            route_runs.append(NEXT_TO_THE_ROOT_PATH)
            return {"ok": True}

        client = TestClient(app, base_url=HTTPS_TEST_SERVER, cookies={}, root_path="/app")
        return client, route_runs

    @pytest.mark.parametrize(("rule_prefix", "cache_control"), [
        pytest.param("/application/api/x/", NO_STORE, id="written-as-the-router-routes"),
        pytest.param("/api/x/", None, id="written-below-a-root-path-it-does-not-have"),
    ])
    def test_a_cache_control_rule_selects_the_path_only_when_it_names_it(
        self, rule_prefix: str, cache_control: str | None,
    ) -> None:
        client, route_runs = self.an_app_serving_next_to_the_root_path(
            security_headers=a_no_store_policy(PathRules(prefixes=(rule_prefix,))),
        )

        response = client.get(NEXT_TO_THE_ROOT_PATH)

        assert (response.status_code, response.headers.get("cache-control"), len(route_runs)) == (
            200, cache_control, 1,
        )

    @pytest.mark.parametrize(("rule_prefix", "selected"), [
        pytest.param("/application/api/x/", True, id="written-as-the-router-routes"),
        pytest.param("/api/x/", False, id="written-below-a-root-path-it-does-not-have"),
    ])
    @pytest.mark.parametrize(("headers", "checked"), [
        pytest.param(SAME_ORIGIN, ("csrf_origin", "csrf_token"), id="token-without-one"),
        pytest.param(FOREIGN, ("csrf_origin",), id="origin-foreign"),
    ])
    def test_a_csrf_rule_protects_the_path_only_when_it_names_it(
        self, rule_prefix: str, selected: bool, headers: dict[str, str],
        checked: tuple[str, ...],
    ) -> None:
        protecting = CsrfPolicy(protected=PathRules(prefixes=(rule_prefix,)))
        policies = {"csrf_origin": CsrfPolicy()} | dict.fromkeys(checked, protecting)
        client, route_runs = self.an_app_serving_next_to_the_root_path(**policies)

        response = client.post(NEXT_TO_THE_ROOT_PATH, headers=headers)

        outcome = (response.status_code, len(route_runs))
        expected = (403, 0) if selected else (200, 1)
        assert outcome == expected


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
