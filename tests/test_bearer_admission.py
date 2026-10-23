"""What a bearer admission changes for the cookie, CSRF and the session, and where it stops.

Each scenario runs the real stack of `a_bearer_app`; a recorded admission is
carried between requests by `relayed`, the way a host's outer middleware could.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from oidc_arrangement import (
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
)
from starlette.middleware import Middleware
from test_bearer_gate import (
    A_TOKEN,
    EXPORT_PATH,
    MACHINE_PATHS,
    REALM,
    REALM_INVALID_TOKEN,
    UNDECLARED_PATH,
    UNGATED_EXPORT_PATH,
    BearerApp,
    a_bearer_app,
    a_bearer_gate,
    assert_answers_no_store,
    bearing,
)
from test_session_gate import (
    ADMITTED_ADMIN_PATH,
    ADMITTED_ADMIN_PATHS,
    relayed,
    with_admitted_admin_routes,
)
from webauth_arrangement import (
    ALL_DEPENDENCIES_PATH,
    HTTPS_TEST_SERVER,
    LOGIN_REDIRECT,
    SessionsThatMustNotBeAsked,
    a_web_auth_config,
    session_cookie_header,
)

from webauth.config import install_web_auth_config
from webauth.dependencies import current_user_dependency
from webauth.middleware import bearer_caller, install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import BearerCaller

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.types import ASGIApp, Receive, Scope, Send

EXPIRY = ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS
HEALTH_PATH = "/health"
SESSION_PATHS = ("/me", "/admin", "/session-id", *ADMITTED_ADMIN_PATHS)
FOREIGN_PAGE = {
    "origin": "https://evil.example.test",
    "sec-fetch-site": "cross-site",
}


def never_asked() -> Any:
    raise AssertionError("the session transaction was opened")


def test_a_bearer_request_needs_no_csrf_origin_header_or_cookie() -> None:
    app = a_bearer_app()

    response = app.ask(method="DELETE", authorization=bearing(A_TOKEN), headers=FOREIGN_PAGE)

    assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
    assert_answers_no_store(response)


def test_the_cookie_and_the_csrf_token_count_for_nothing_beside_a_token() -> None:
    auth_headers = {"x-csrf-token": "not-the-token-of-any-session"}
    app = a_bearer_app(
        sessions=SessionsThatMustNotBeAsked(), session_transaction=never_asked,
    )
    other_accounts_cookie = session_cookie_header(app.auth.signed_cookie("another-account"))

    response = app.ask(
        method="DELETE",
        authorization=bearing(A_TOKEN),
        headers={**auth_headers, "cookie": other_accounts_cookie},
    )

    assert (response.status_code, response.json()) == (200, {"subject": OPERATOR_SUBJECT})
    assert_answers_no_store(response)


@pytest.mark.parametrize("path", [EXPORT_PATH, UNDECLARED_PATH])
def test_an_admin_cookie_alone_opens_no_machine_path_even_without_a_declared_dependency(
    path: str,
) -> None:
    app = a_bearer_app()

    response = app.ask(path, cookie=True)

    assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
    assert_answers_no_store(response)
    assert app.auth.route_runs == []


@pytest.mark.parametrize("path", SESSION_PATHS)
@pytest.mark.parametrize("accept", ["text/html", "application/json"])
def test_a_session_dependency_on_a_bearer_admitted_request_is_a_host_mistake(
    path: str, accept: str,
) -> None:
    app = a_bearer_app(
        paths=PathRules(exact=frozenset(SESSION_PATHS)), login_redirect=LOGIN_REDIRECT,
    )
    with_admitted_admin_routes(app.auth)

    response = app.ask(
        path, authorization=bearing(A_TOKEN), cookie=True, headers={"accept": accept},
    )

    assert response.status_code == 500
    assert_answers_no_store(response)


def test_the_admitted_admin_of_a_bearer_request_is_an_error_the_public_reader_raises() -> None:
    app = a_bearer_app(paths=PathRules(exact=frozenset({ADMITTED_ADMIN_PATH})))
    with_admitted_admin_routes(app.auth)
    client = TestClient(app.auth.app, base_url=HTTPS_TEST_SERVER, raise_server_exceptions=True)
    headers = {"authorization": bearing(A_TOKEN)[0]}

    with pytest.raises(RuntimeError):
        client.get(ADMITTED_ADMIN_PATH, headers=headers)


def test_the_admitted_user_of_a_bearer_request_is_nobody() -> None:
    app = a_bearer_app(paths=PathRules(exact=frozenset({HEALTH_PATH})))

    response = app.ask(HEALTH_PATH, authorization=bearing(A_TOKEN))

    assert (response.status_code, response.json()) == (200, {"username": None})
    assert_answers_no_store(response)


@pytest.mark.parametrize(
    "opened",
    [
        pytest.param({"public": (PublicRule(MACHINE_PATHS),)}, id="public"),
        pytest.param({"optional": MACHINE_PATHS}, id="optional"),
    ],
)
class TestAMachinePrefixTheSessionGateAlsoOpens:
    def test_without_a_token_the_gate_still_refuses(self, opened: dict[str, Any]) -> None:
        app = a_bearer_app(**opened)

        response = app.ask()

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)

    def test_with_a_token_the_session_store_is_not_asked(self, opened: dict[str, Any]) -> None:
        app = a_bearer_app(**opened, sessions=SessionsThatMustNotBeAsked())

        response = app.ask(authorization=bearing(A_TOKEN))

        assert response.status_code == 200
        assert_answers_no_store(response)


def a_sub_app(auth: BearerApp, *, csrf: bool) -> FastAPI:
    inner = FastAPI()
    install_web_auth_config(inner, auth.auth.config)
    if csrf:
        install_web_auth_middleware(
            inner,
            security_headers=SecurityHeadersPolicy(content_security_policy="default-src 'self'"),
            csrf_origin=CsrfPolicy(),
            csrf_token=CsrfPolicy(),
        )
    sessions = current_user_dependency(
        session_store=lambda: auth.auth.sessions, on_authenticated=lambda user: None,
    )

    @inner.api_route(EXPORT_PATH, methods=["DELETE"])
    def machine_route(_caller: BearerCaller = Depends(bearer_caller)) -> dict[str, str]:
        return {"ran": "the sub-app's machine route"}

    @inner.api_route(ALL_DEPENDENCIES_PATH, methods=["DELETE"])
    def session_route(user: Any = Depends(sessions.current_user)) -> dict[str, str]:
        return {"ran": user.username}

    return inner


class TestASubAppBelowAGatedPathDoesNotOwnTheAdmission:
    def a_mounted_app(self, *, csrf: bool) -> BearerApp:
        app = a_bearer_app(paths=PathRules(prefixes=("/sub/",)))
        app.auth.app.mount("/sub", a_sub_app(app, csrf=csrf))
        return app

    def test_its_own_csrf_stack_still_applies(self) -> None:
        app = self.a_mounted_app(csrf=True)

        response = app.ask(f"/sub{EXPORT_PATH}", method="DELETE", authorization=bearing(A_TOKEN))

        assert (response.status_code, response.json()) == (
            403, {"detail": "Missing Origin header"},
        )
        assert_answers_no_store(response)

    @pytest.mark.parametrize(
        "path", [EXPORT_PATH, ALL_DEPENDENCIES_PATH], ids=["bearer_caller", "current_user"],
    )
    def test_its_routes_raise_when_they_ask_for_the_admission(self, path: str) -> None:
        app = self.a_mounted_app(csrf=False)

        response = app.ask(f"/sub{path}", method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 500
        assert_answers_no_store(response)


class Relay:
    """An admitted request's scope entries that the gate wrote, ready to be planted in another."""

    def __init__(self, app: BearerApp) -> None:
        self.relay = relayed(app.auth)
        control = a_bearer_app(gated=False)
        control_relay = relayed(control.auth)
        app.ask(authorization=bearing(A_TOKEN))
        control.ask(authorization=bearing(A_TOKEN), cookie=True)
        app.auth.route_runs.clear()
        self.entries = {
            key: value
            for key, value in self.relay.added.items()
            if key not in control_relay.added
        }
        assert self.entries, "the gate wrote no scope entry for the admission"

    def plant(self, entries: dict[str, Any] | None = None) -> None:
        self.relay.replay = self.entries if entries is None else entries


class TestAnAdmissionBelongsToItsPathAppAndHeader:
    def test_it_is_not_honoured_on_another_path(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask(UNGATED_EXPORT_PATH, method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 403

    def test_it_is_not_honoured_when_the_key_holds_another_object(self) -> None:
        app = a_bearer_app()
        relay = Relay(app)
        relay.plant({key: object() for key in relay.entries})

        response = app.ask(UNGATED_EXPORT_PATH, method="DELETE", authorization=bearing(A_TOKEN))

        assert response.status_code == 403

    def test_it_is_not_a_bearer_caller_on_another_path(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask(UNGATED_EXPORT_PATH, authorization=bearing(A_TOKEN), cookie=True)

        assert response.status_code == 500

    def test_a_replay_on_its_own_path_is_verified_again(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()
        app.clock.now = float(EXPIRY + ACCESS_TOKEN_LEEWAY_SECONDS)

        response = app.ask(authorization=bearing(A_TOKEN))

        assert (response.status_code, response.headers["www-authenticate"]) == (
            401, REALM_INVALID_TOKEN,
        )
        assert_answers_no_store(response)
        assert app.auth.route_runs == []

    def test_a_replay_without_the_header_is_refused(self) -> None:
        app = a_bearer_app()
        Relay(app).plant()

        response = app.ask()

        assert (response.status_code, response.headers["www-authenticate"]) == (401, REALM)
        assert_answers_no_store(response)
        assert app.auth.route_runs == []


class Rewriting:
    """A host middleware inside the stack that rewrites the request's header lines."""

    def __init__(self, app: ASGIApp, rewrite: Callable[[list[tuple[bytes, bytes]]], list[Any]]):
        self._app = app
        self._rewrite = rewrite

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            scope["headers"] = self._rewrite(list(scope["headers"]))
        await self._app(scope, receive, send)


def without_authorization(headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    return [(name, value) for name, value in headers if name != b"authorization"]


@pytest.mark.parametrize(
    "rewrite",
    [
        pytest.param(
            lambda headers: [*without_authorization(headers), (b"authorization", b"Bearer other")],
            id="M03a-replaces",
        ),
        pytest.param(without_authorization, id="M03b-removes"),
        pytest.param(
            lambda headers: [*headers, (b"authorization", b"Bearer second")], id="M03c-duplicates",
        ),
    ],
)
def test_a_header_changed_after_admission_voids_the_caller(
    rewrite: Callable[[list[tuple[bytes, bytes]]], list[Any]],
) -> None:
    app = a_bearer_app(inner_middleware=(Middleware(Rewriting, rewrite=rewrite),))

    response = app.ask(authorization=bearing(A_TOKEN))

    assert response.status_code == 500
    assert_answers_no_store(response)


class TestTheGateSitsInsideTheRateLimitAndBodyLimitAndBehindTheHeaders:
    def test_a_bearer_request_spends_the_same_rate_budget(self) -> None:
        budget = RateLimitPolicy(default=RateLimitBudget("api", 1, 60))
        app = a_bearer_app(policies={"rate_limit": budget})

        app.ask(authorization=bearing(A_TOKEN))
        second = app.ask(authorization=bearing(A_TOKEN))

        assert (second.status_code, "retry-after" in second.headers) == (429, True)
        assert_answers_no_store(second)

    def test_a_body_over_the_limit_is_refused_before_the_token_is_read(self) -> None:
        app = a_bearer_app(policies={"body_size": BodySizePolicy(default_max_bytes=100)})

        response = app.ask(method="DELETE", authorization=bearing(A_TOKEN), content=b"x" * 101)

        assert response.status_code == 413
        assert_answers_no_store(response)
        assert app.key_sets.fetched_urls == []

    def test_a_machine_route_that_raises_answers_the_library_500(self) -> None:
        app = a_bearer_app()

        response = app.ask("/api/admin/boom", authorization=bearing(A_TOKEN))

        assert response.status_code == 500
        assert_answers_no_store(response)

    def test_a_host_cache_rule_on_the_machine_prefix_loses_to_no_store(self) -> None:
        app = FastAPI()
        install_web_auth_config(app, a_web_auth_config())
        install_web_auth_middleware(
            app,
            security_headers=SecurityHeadersPolicy(
                content_security_policy="default-src 'self'",
                cache_control_rules=(CacheControlRule(MACHINE_PATHS, "public, max-age=60"),),
            ),
            bearer_gate=a_bearer_gate(),
        )
        app.add_api_route(EXPORT_PATH, lambda: {"ok": True}, methods=["GET"])
        client = TestClient(app, base_url=HTTPS_TEST_SERVER)

        response = client.get(EXPORT_PATH, headers={"authorization": f"Bearer {A_TOKEN}"})

        assert (response.status_code, response.headers["cache-control"]) == (200, "no-store")
        assert "set-cookie" not in response.headers
