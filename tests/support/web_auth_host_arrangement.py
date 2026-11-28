"""A host built only by the composition call: its fakes, the call's arguments and the app."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from fastapi import Depends, FastAPI, Request, Response, WebSocket
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from starlette.concurrency import run_in_threadpool
from starlette.responses import PlainTextResponse
from starlette.routing import Host, Route, Router

from tests.support.account_arrangement import FakeUser, WriteLockInMemory
from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.full_stack_arrangement import HEADERS_POLICY
from tests.support.gate_arrangement import HAL_ONLY, PERSON_PATHS, a_resource
from tests.support.oidc_arrangement import (
    FakeClock,
    FakeIssuer,
    FakeKeySetEndpoint,
    a_key_set_endpoint,
    an_access_token,
    an_issuer_called_through,
)
from tests.support.oidc_login_host import (
    ADMISSION,
    BOUND_ISSUER,
    CALLBACK_PATH,
    CLIENT_ID,
    LOGIN_GROUP,
    LOGOUT_PAGE_TEXT,
    NOW,
    SIGN_IN_PATHS,
    START_PATH,
    SUBJECT,
    RecordingSignInTransaction,
    TransactionKind,
    UsersWithSnapshots,
    a_client_config,
    an_id_token,
)
from tests.support.request_line_arrangement import FORWARDED_CLIENT, TRUSTED_PEER
from tests.support.session_store_arrangement import (
    FakeSessionRecord,
    SessionsRecordingTheirTransaction,
)
from tests.support.webauth_arrangement import (
    ALLOWED_HOST,
    API_PATH,
    HTTPS_TEST_SERVER,
    SESSION_ID,
    WEBSOCKET_PATH,
    RecordingAuditSink,
    a_session,
    a_web_auth_config,
    session_cookie_header,
)
from webauth.cookies import sign_session_id
from webauth.dependencies import ConnectionRefusal, admin_user, authenticate_websocket, current_user
from webauth.middleware import BearerGate, PersonPaths, SessionGate
from webauth.policies import CsrfPolicy
from webauth.ports import AuthenticatedUser
from webauth.proxies import TrustedProxies
from webauth.sessions import end_session, open_session
from webauth.sign_in_routes import SignInRefusal
from webauth.web_auth import (
    OidcSignIn,
    ServedBehind,
    SignInPages,
    WebAuth,
    WebAuthSettings,
    WebAuthStores,
    web_auth_front,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable

    from starlette.middleware import Middleware
    from starlette.types import ASGIApp

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
    session_ids: list[str | None] = field(default_factory=list)

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
    groups_claim: object = (str(LOGIN_GROUP),),
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
    oidc: OidcSignIn | None
    stores: WebAuthStores
    front: TrustedProxies | ServedBehind
    gate: SessionGate | None = None
    outside: tuple[Middleware, ...] = ()
    inside: tuple[Middleware, ...] = ()

    def build(self) -> WebAuth:
        return WebAuth.build(
            self.settings,
            oidc=self.oidc,
            stores=self.stores,
            front=self.front,
            gate=self.gate,
            outside=self.outside,
            inside=self.inside,
        )


def an_oidc_sign_in(world: HostWorld, **changes: object) -> OidcSignIn:
    """The OpenID Connect block of the host `a_composition` builds; a keyword replaces its field."""

    def refused(_request: Request, refusal: SignInRefusal) -> Response:
        world.refusals.append(refusal)
        return Response(THE_REFUSAL_BODY, status_code=403)

    oidc = OidcSignIn(
        client=a_client_config(),
        sign_in_paths=SIGN_IN_PATHS,
        keeps_id_token=True,
        groups=ADMISSION,
        pages=SignInPages(
            refused=refused,
            logout_page_text=lambda _request: LOGOUT_PAGE_TEXT,
            ui_language=lambda _request: None,
        ),
        issuer_calls=an_issuer_called_through(world.issuer, world.key_set),
    )
    return replace(oidc, **changes)


def a_composition(world: HostWorld, **changes: object) -> Composition:
    """The composition of a host on the provider; `oidc=None` makes the host that proves its own."""
    composition = Composition(
        settings=WebAuthSettings(
            config=world.config,
            max_sessions=None,
            security_headers=HEADERS_POLICY,
            csrf_origin=CsrfPolicy(),
        ),
        oidc=an_oidc_sign_in(world),
        stores=WebAuthStores(sign_in=world.sign_in, sessions=world.sessions.in_transaction),
        front=TRUSTED_PROXIES,
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


PROOF_SIGN_IN_PATH = "/proof/sign-in"
PROOF_SIGN_OUT_PATH = "/proof/sign-out"


def the_routes_of_a_host_that_proves_its_own(
    world: HostWorld,
) -> Callable[[FastAPI, WebAuth], None]:
    """`the_routes_of`, and a stand-in proof: a POST that opens a session of the account its
    `account` query names, and one that ends the session of the request's cookie. Each records
    the id the library returned in `world.session_ids` and answers on the response it passed."""

    def add(app: FastAPI, auth: WebAuth) -> None:
        the_routes_of(world)(app, auth)

        @app.post(PROOF_SIGN_IN_PATH)
        def prove(request: Request) -> Response:
            answer = Response(status_code=204)
            account_id = request.query_params.get("account", A_MEMBER.id)
            world.session_ids.append(open_session(request, answer, account_id))
            return answer

        @app.post(PROOF_SIGN_OUT_PATH)
        def leave(request: Request) -> Response:
            answer = Response(status_code=204)
            world.session_ids.append(end_session(request, answer))
            return answer

    return add


def a_resource_and_person_paths() -> Callable[[WebAuth], BearerGate]:
    def bearer_of(_auth: WebAuth) -> BearerGate:
        return BearerGate(
            person_paths=PersonPaths(PERSON_PATHS, HAL_ONLY),
            resource=a_resource(),
        )

    return bearer_of


def a_member_token() -> str:
    return an_access_token(
        issuer=BOUND_ISSUER,
        client_id=CLIENT_ID,
        key_id="issuer-key",
        key_name="issuer",
        subject=SUBJECT,
        claims={"groups": [str(LOGIN_GROUP)]},
    )


def a_client_of(
    app: ASGIApp, *, base_url: str = HTTPS_TEST_SERVER, raise_server_exceptions: bool = False
) -> TestClient:
    """A browser reaching `app` through the trusted proxy over https, following no redirect."""
    return TestClient(
        app,
        base_url=base_url,
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


def a_host_that_proves_its_own(world: HostWorld, **changes: object) -> ComposedHost:
    """A host built without OpenID Connect, with the stand-in proof routes; a keyword replaces
    the composition's field it names."""
    return a_composed_host(
        world,
        a_composition(world, oidc=None, **changes),
        routes=the_routes_of_a_host_that_proves_its_own(world),
    )


FIRST_HOST = ALLOWED_HOST
SECOND_HOST = "second.example"
SHARED_PATH = "/health"


def a_second_world(*users: FakeUser, stored_session: FakeSessionRecord | None = None) -> HostWorld:
    """A host world whose app is served at `SECOND_HOST`, so its origin is the one it admits."""
    world = a_host_world(*users, stored_session=stored_session)
    world.config = replace(world.config, allowed_hosts_exact=frozenset({SECOND_HOST}))
    return world


SECOND_ORIGIN = f"https://{SECOND_HOST}"


@dataclass(frozen=True)
class SignedInWorlds:
    """Two host worlds, each with a stored session of its own member, made fresh per scenario."""

    first: HostWorld
    second: HostWorld
    first_member: FakeUser
    second_member: FakeUser


A_MEMBER = FakeUser(id=SUBJECT, username="lena")


def a_signed_in_world() -> HostWorld:
    return a_host_world(A_MEMBER, stored_session=a_stored_session(A_MEMBER))


def two_signed_in_worlds() -> SignedInWorlds:
    first_member = A_MEMBER
    second_member = FakeUser(id="a-subject-of-the-second-app", username="mara")
    return SignedInWorlds(
        first=a_host_world(first_member, stored_session=a_stored_session(first_member)),
        second=a_second_world(second_member, stored_session=a_stored_session(second_member)),
        first_member=first_member,
        second_member=second_member,
    )


def forwarded_by_the_proxy() -> dict[str, str]:
    """The header a trusted proxy adds, naming the client."""
    return {"x-forwarded-for": FORWARDED_CLIENT}


def an_unparseable_forward() -> dict[str, str]:
    """A forwarding header the writer ignores."""
    return {"x-forwarded-for": "not-an-address"}


@dataclass
class SharedFrontHost:
    """Two apps built with `SHARED_FRONT`, mounted by `Host` in one router inside the front."""

    first: ComposedHost
    second: ComposedHost
    front: ASGIApp

    def client_at(self, host: str) -> TestClient:
        """A browser reaching the front through the trusted proxy for `host`."""
        return a_client_of(self.front, base_url=f"https://{host}")


def a_shared_front_host(
    first_world: HostWorld,
    second_world: HostWorld,
    *,
    first_composition: Composition | None = None,
    lifespan_events: list[str] | None = None,
) -> SharedFrontHost:
    """Each world's app built and installed once, both served by one `web_auth_front` router."""
    first = a_composed_host(
        first_world,
        first_composition or a_composition(first_world, front=ServedBehind.SHARED_FRONT),
    )
    second = a_composed_host(
        second_world, a_composition(second_world, front=ServedBehind.SHARED_FRONT)
    )

    @asynccontextmanager
    async def lifespan(_router: Router) -> AsyncIterator[None]:
        if lifespan_events is not None:
            lifespan_events.append("startup")
        yield

    router = Router(
        routes=[
            Route(SHARED_PATH, lambda _request: PlainTextResponse("ok"), methods=["GET"]),
            Host(FIRST_HOST, app=first.app),
            Host(SECOND_HOST, app=second.app),
        ],
        lifespan=lifespan,
    )
    return SharedFrontHost(first, second, web_auth_front(router, trusted_proxies=TRUSTED_PROXIES))


def the_app_as_it_stands(app: FastAPI) -> tuple[object, object, object]:
    """Routes, middleware and state, to prove a refused call left the app as it was.

    Starlette's `State` keeps every key in one inner dict, so the state is copied one level down.
    """
    state = {
        name: dict(value) if isinstance(value, dict) else value
        for name, value in vars(app.state).items()
    }
    return list(app.router.routes), list(app.user_middleware), state
