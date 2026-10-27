"""The builders the bearer gate's and the session gate's tests share."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from fastapi import Depends, Request, WebSocket
from httpx import Response
from starlette.middleware import Middleware

from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_NOW,
    FakeClock,
    FakeKeySetEndpoint,
    a_relying_party,
    an_access_token,
    key_set_document,
    public_jwk,
    rsa_key,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    AuthApp,
    FakeUser,
    a_session,
    an_auth_app,
    session_cookie_header,
)
from webauth.dependencies import current_user_dependency
from webauth.middleware import BearerGate, admitted_admin, bearer_caller
from webauth.oidc_login import AdmissionConfig
from webauth.policies import AuthorizedParties, PathRules
from webauth.ports import AuthenticatedUser, BearerCaller

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

MACHINE_PREFIX = "/api/admin/"
EXPORT_PATH = "/api/admin/export"
UNDECLARED_PATH = "/api/admin/forgotten"
RAISING_PATH = "/api/admin/boom"
PEOPLE_PATH = "/api/admin/people/{subject}/export"
UNGATED_EXPORT_PATH = "/ungated-export"
REALM = 'Bearer realm="admin"'
REALM_INVALID_REQUEST = f'{REALM}, error="invalid_request"'
REALM_INVALID_TOKEN = f'{REALM}, error="invalid_token"'
REALM_INSUFFICIENT_SCOPE = f'{REALM}, error="insufficient_scope"'
ADMISSION = AdmissionConfig(
    bound_issuer=a_relying_party().issuer, login_group="/apps/x", admin_group="/apps/x/admin",
)
MACHINE_PATHS = PathRules(prefixes=(MACHINE_PREFIX,))


def a_token(**claims: Any) -> str:
    return an_access_token(claims=claims)


def bearing(token: str) -> tuple[str, ...]:
    return (f"Bearer {token}",)


def a_bearer_gate(
    *,
    paths: PathRules = MACHINE_PATHS,
    key_sets: FakeKeySetEndpoint | None = None,
    clock: FakeClock | None = None,
) -> BearerGate:
    return BearerGate(
        paths=paths,
        relying_party=a_relying_party(fetch_key_set=key_sets, wall_clock=clock),
        admission=ADMISSION,
        authorized_parties=AuthorizedParties(frozenset({"hal"})),
    )


def a_key_set_answering(response: bytes | Exception | None = None) -> FakeKeySetEndpoint:
    document = key_set_document(public_jwk(rsa_key("current"), "current-key"))
    return FakeKeySetEndpoint(document if response is None else response)


@dataclass
class BearerApp:
    auth: AuthApp
    key_sets: FakeKeySetEndpoint
    clock: FakeClock
    cookie: str = field(default="")

    def ask(
        self,
        path: str = EXPORT_PATH,
        *,
        method: str = "GET",
        authorization: tuple[str, ...] = (),
        cookie: bool = False,
        headers: dict[str, str] | None = None,
        **request: Any,
    ) -> Response:
        sent = [("authorization", value) for value in authorization]
        sent += list((headers or {}).items())
        if cookie:
            sent.append(("cookie", self.cookie))
        return self.auth.client.request(method, path, headers=sent, **request)


def add_machine_routes(auth: AuthApp) -> None:
    def ran(request: Request) -> None:
        auth.route_runs.append(request.scope["path"])

    @auth.app.api_route(EXPORT_PATH, methods=["GET", "DELETE"])
    def export(
        request: Request, caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str]:
        ran(request)
        return {"subject": caller.subject}

    @auth.app.api_route(UNDECLARED_PATH, methods=["GET", "DELETE"])
    def forgotten(request: Request) -> dict[str, str]:
        ran(request)
        return {"ran": "without bearer_caller"}

    @auth.app.api_route(PEOPLE_PATH, methods=["GET"])
    def person(request: Request, subject: str) -> dict[str, str]:
        ran(request)
        return {"subject": subject}

    @auth.app.api_route(UNGATED_EXPORT_PATH, methods=["GET", "DELETE"])
    def ungated_export(
        request: Request, caller: BearerCaller = Depends(bearer_caller),
    ) -> dict[str, str]:
        ran(request)
        return {"subject": caller.subject}

    @auth.app.get(RAISING_PATH)
    def raising(_caller: BearerCaller = Depends(bearer_caller)) -> None:
        raise RuntimeError("the route failed")


def a_bearer_app(
    *,
    paths: PathRules = MACHINE_PATHS,
    key_sets: FakeKeySetEndpoint | None = None,
    gated: bool = True,
    policies: dict[str, Any] | None = None,
    inner_middleware: tuple[Middleware, ...] = (),
    **auth_app_keywords: Any,
) -> BearerApp:
    """An app whose machine paths sit behind a bearer gate (or none, when `gated` is false).

    It serves `EXPORT_PATH` and `UNGATED_EXPORT_PATH` (read `bearer_caller`),
    `UNDECLARED_PATH` and `PEOPLE_PATH` (read nothing) and `RAISING_PATH`, besides the
    arrangement's own routes; the session store holds an admin's session, whose cookie
    is `BearerApp.cookie`.
    """
    key_sets = key_sets or a_key_set_answering()
    clock = FakeClock(float(ACCESS_TOKEN_NOW))
    record = a_session(user=FakeUser(role=ADMIN_ROLE))
    gate = a_bearer_gate(paths=paths, key_sets=key_sets, clock=clock)
    stack = {"bearer_gate": gate} if gated else {}
    auth = an_auth_app(
        record,
        gate=True,
        raise_server_exceptions=False,
        stack_policies={**stack, **(policies or {})},
        **auth_app_keywords,
    )

    auth.app.user_middleware.extend(inner_middleware)

    add_machine_routes(auth)

    return BearerApp(
        auth, key_sets, clock, cookie=session_cookie_header(auth.signed_cookie()),
    )


A_TOKEN = a_token()


def assert_no_store_and_no_cookie(headers: Mapping[str, str]) -> None:
    assert headers["cache-control"] == "no-store"
    assert "set-cookie" not in headers


def assert_answers_no_store(response: Response) -> None:
    assert_no_store_and_no_cookie(response.headers)


ADMITTED_ADMIN_PATH = "/admitted-admin"
ADMITTED_ADMIN_DEPENDENCY_PATH = "/admitted-admin-dependency"
ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH = "/admitted-admin-after-current-user"
ADMITTED_ADMIN_PATHS = (ADMITTED_ADMIN_PATH, ADMITTED_ADMIN_DEPENDENCY_PATH)
WEBSOCKET_ADMITTED_ADMIN_PATH = "/ws-admitted-admin"


def with_admitted_admin_routes(app: AuthApp) -> AuthApp:
    """The routes that read ``admitted_admin``, added to an application of the arrangement."""
    dependencies = current_user_dependency(
        session_store=lambda: app.sessions, on_authenticated=app.authenticated.append,
    )

    @app.app.get(ADMITTED_ADMIN_PATH)
    def reading_admitted_admin(request: Request) -> dict[str, str]:
        app.route_runs.append(request.url.path)
        return {"username": admitted_admin(request).username}

    @app.app.get(ADMITTED_ADMIN_DEPENDENCY_PATH)
    def depending_on_admitted_admin(
        request: Request, admin: AuthenticatedUser = Depends(admitted_admin),
    ) -> dict[str, str]:
        app.route_runs.append(request.url.path)
        return {"username": admin.username}

    @app.app.get(ADMITTED_ADMIN_AFTER_CURRENT_USER_PATH)
    def reading_admitted_admin_after_current_user(
        request: Request, _account: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str]:
        return {"username": admitted_admin(request).username}

    @app.app.websocket(WEBSOCKET_ADMITTED_ADMIN_PATH)
    async def reading_admitted_admin_of_a_websocket(websocket: WebSocket) -> None:
        admitted_admin(websocket)
        await websocket.accept()
        await websocket.close()

    return app


@dataclass
class ScopeRelay:
    """What an outer host middleware saw the inner app add to the scope, and what it replays."""

    added: dict[str, Any] = field(default_factory=dict)
    replay: dict[str, Any] = field(default_factory=dict)


class RelayingScope:
    """Outer middleware: records the scope entries the inner app adds, and plants others."""

    def __init__(self, app: ASGIApp, relay: ScopeRelay) -> None:
        self._app = app
        self._relay = relay

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        known = set(scope)
        scope.update(self._relay.replay)
        await self._app(scope, receive, send)
        self._relay.added = {key: scope[key] for key in set(scope) - known}


def relayed(app: AuthApp) -> ScopeRelay:
    relay = ScopeRelay()
    app.app.add_middleware(RelayingScope, relay=relay)
    return relay

