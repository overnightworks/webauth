"""A host built only by the composition call: its fakes, the call's arguments and the app."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Request, Response, WebSocket
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from starlette.concurrency import run_in_threadpool

from tests.support.account_arrangement import FakeUser, WriteLockInMemory
from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.full_stack_arrangement import HEADERS_POLICY
from tests.support.oidc_arrangement import (
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    a_key_set_endpoint,
)
from tests.support.oidc_login_host import (
    ADMISSION,
    CALLBACK_PATH,
    LOGIN_GROUP,
    LOGOUT_PAGE_TEXT,
    NOW,
    SIGN_IN_PATHS,
    START_PATH,
    RecordingSignInTransaction,
    TransactionKind,
    UsersWithSnapshots,
    a_client_config,
    an_id_token,
)
from tests.support.request_line_arrangement import TRUSTED_PEER
from tests.support.session_store_arrangement import (
    FakeSessionRecord,
    SessionsRecordingTheirTransaction,
)
from tests.support.webauth_arrangement import (
    API_PATH,
    HTTPS_TEST_SERVER,
    SESSION_ID,
    WEBSOCKET_PATH,
    RecordingAuditSink,
    a_session,
    a_web_auth_config,
    session_cookie_header,
)
from webauth.admission import AdmissionConfig
from webauth.cookies import sign_session_id
from webauth.dependencies import ConnectionRefusal, admin_user, authenticate_websocket, current_user
from webauth.middleware import BearerGate, SessionGate
from webauth.policies import CsrfPolicy
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.sign_in_routes import SignInRefusal
from webauth.web_auth import (
    IssuerCalls,
    SignInPages,
    WebAuth,
    WebAuthSettings,
    WebAuthStores,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from starlette.middleware import Middleware

    from webauth.config import WebAuthConfig

ME_PATH = "/me"
ADMIN_PATH = "/admin"
THE_REFUSAL_BODY = "the host's refusal"


@dataclass
class HostWorld:
    """What stands behind a host: its stores, its issuer and what its routes recorded."""

    issuer: FakeIssuer
    key_set: FakeKeySetEndpoint
    wall_clock: FakeClock
    config: WebAuthConfig
    accounts: UsersWithSnapshots
    sessions: SessionsRecordingTheirTransaction
    sign_in: RecordingSignInTransaction
    refusals: list[SignInRefusal] = field(default_factory=list)
    routes_ran: list[str] = field(default_factory=list)
    socket_outcomes: list[AuthenticatedUser | ConnectionRefusal] = field(default_factory=list)

    def signed_cookie(self) -> dict[str, str]:
        """The Cookie header of the stored session `a_stored_session` seeds."""
        value = sign_session_id(SESSION_ID, self.config.signing_key)
        return {"cookie": session_cookie_header(value)}


def a_stored_session(user: FakeUser) -> FakeSessionRecord:
    """A live session of `user` at the host's fixed wall clock."""
    return a_session(user=user, now=datetime.fromtimestamp(NOW, UTC))


def a_host_world(
    *users: FakeUser,
    stored_session: FakeSessionRecord | None = None,
    groups_claim: object = (LOGIN_GROUP,),
) -> HostWorld:
    wall_clock = FakeClock(float(NOW))
    lock = WriteLockInMemory()
    accounts = UsersWithSnapshots(*users, lock=lock)
    sessions = SessionsRecordingTheirTransaction(stored_session, users=accounts, lock=lock)
    sign_in = RecordingSignInTransaction(
        TransactionKind.PER_CALL,
        accounts=accounts,
        sessions=sessions,
        audit=RecordingAuditSink(),
        lock=lock,
        strict=False,
    )
    return HostWorld(
        issuer=FakeIssuer(
            mint_id_token=lambda nonce: an_id_token(nonce, wall_clock, groups_claim),
        ),
        key_set=a_key_set_endpoint("issuer"),
        wall_clock=wall_clock,
        config=a_web_auth_config(wall_clock=wall_clock),
        accounts=accounts,
        sessions=sessions,
        sign_in=sign_in,
    )


@dataclass(frozen=True)
class Composition:
    """Every argument of `WebAuth.build`, so a scenario changes the one it is about."""

    settings: WebAuthSettings
    stores: WebAuthStores
    groups: AdmissionConfig
    pages: SignInPages
    front: TrustedProxies
    issuer_calls: IssuerCalls
    gate: SessionGate | None = None
    outside: tuple[Middleware, ...] = ()
    inside: tuple[Middleware, ...] = ()

    def build(self) -> WebAuth:
        return WebAuth.build(
            self.settings,
            stores=self.stores,
            groups=self.groups,
            pages=self.pages,
            front=self.front,
            gate=self.gate,
            outside=self.outside,
            inside=self.inside,
            issuer_calls=self.issuer_calls,
        )


def a_composition(world: HostWorld, **changes: object) -> Composition:
    def refused(_request: Request, refusal: SignInRefusal) -> Response:
        world.refusals.append(refusal)
        return Response(THE_REFUSAL_BODY, status_code=403)

    composition = Composition(
        settings=WebAuthSettings(
            config=world.config,
            client=a_client_config(),
            sign_in_paths=SIGN_IN_PATHS,
            keeps_id_token=True,
            max_sessions=None,
            security_headers=HEADERS_POLICY,
            csrf_origin=CsrfPolicy(),
        ),
        stores=WebAuthStores(sign_in=world.sign_in, sessions=world.sessions.in_transaction),
        groups=ADMISSION,
        pages=SignInPages(
            refused=refused,
            logout_page_text=lambda _request: LOGOUT_PAGE_TEXT,
            ui_language=lambda _request: None,
        ),
        front=TRUSTED_PROXIES,
        issuer_calls=IssuerCalls(
            post_token_request=world.issuer,
            fetch_key_set=world.key_set,
            monotonic_clock=FakeClock(5_000.0),
        ),
    )
    return replace(composition, **changes)


def the_routes_of(world: HostWorld) -> Callable[[FastAPI, WebAuth], None]:
    """A plain route, a route guarded by `current_user`, one by `admin_user` and a socket."""

    def add(app: FastAPI, _auth: WebAuth) -> None:
        @app.api_route(API_PATH, methods=["GET", "POST"])
        def thing() -> dict[str, str]:
            world.routes_ran.append(API_PATH)
            return {"status": "ok"}

        @app.get(ME_PATH)
        def me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
            world.routes_ran.append(ME_PATH)
            return {"username": user.username}

        @app.get(ADMIN_PATH)
        def admin(user: AuthenticatedUser = Depends(admin_user)) -> dict[str, str]:
            world.routes_ran.append(ADMIN_PATH)
            return {"username": user.username}

        @app.websocket(WEBSOCKET_PATH)
        async def socket(websocket: WebSocket) -> None:
            outcome = await run_in_threadpool(authenticate_websocket, websocket)
            world.socket_outcomes.append(outcome)
            if isinstance(outcome, ConnectionRefusal):
                await websocket.close(code=1008)
                return
            await websocket.accept()
            await websocket.close()

    return add


def no_routes(_app: FastAPI, _auth: WebAuth) -> None:
    """The host adds no route of its own."""


def a_client_of(app: FastAPI, *, raise_server_exceptions: bool = False) -> TestClient:
    """A browser reaching `app` through the trusted proxy over https, following no redirect."""
    return TestClient(
        app,
        base_url=HTTPS_TEST_SERVER,
        client=(TRUSTED_PEER, 55000),
        cookies={},
        follow_redirects=False,
        raise_server_exceptions=raise_server_exceptions,
    )


@dataclass
class ComposedHost:
    world: HostWorld
    auth: WebAuth
    app: FastAPI
    client: TestClient

    def sign_in(self, headers: dict[str, str] | None = None) -> HttpxResponse:
        """Sign in at the issuer after a start; the callback's answer."""
        started = self.client.get(START_PATH, headers=headers)
        query = self.world.issuer.authorize(started.headers["location"])
        return self.client.get(f"{CALLBACK_PATH}?{query}", headers=headers)


def a_composed_host(
    world: HostWorld,
    composition: Composition | None = None,
    *,
    routes: Callable[[FastAPI, WebAuth], None] | None = None,
    bearer_of: Callable[[WebAuth], BearerGate] | None = None,
    installed: bool = True,
) -> ComposedHost:
    """An app built only by `WebAuth.build`, the host's routes and `auth.install`."""
    auth = (composition or a_composition(world)).build()
    app = FastAPI()
    (routes or the_routes_of(world))(app, auth)
    if installed:
        auth.install(app, bearer=None if bearer_of is None else bearer_of(auth))
    return ComposedHost(world, auth, app, a_client_of(app))


def the_app_as_it_stands(app: FastAPI) -> tuple[object, object, object]:
    """Routes, middleware and state, to prove a refused call left the app as it was."""
    return list(app.router.routes), list(app.user_middleware), dict(vars(app.state))
