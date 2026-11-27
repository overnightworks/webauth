"""The host application of the proof: start, callback, logout and back-channel
logout routes over the test suite's in-memory doubles, served over TLS.

One process serves one cookie configuration on every origin it is told. Beside
it a plain-http listener on loopback, which no browser is ever pointed at, answers
``GET /state`` with counts only (among them the accounts above the member role, the access
tokens refused as unfit for a header and the back-channel logouts accepted and refused),
clears everything on ``POST /reset`` (the relying parties, with their key-set caches, are
built again).

Where an issuer is told a ``userinfo_endpoint``, the host calls it once, with the
access token of the token answer, after and only after a login was admitted: the
conformance suite finishes an accepting module on that request. A call that fails is
logged by exception type alone and never ends the admitted login."""

from __future__ import annotations

import argparse
import ctypes
import functools
import html
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal

import anyio.to_thread
import httpx
import uvicorn
from client_config import client_config
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from logline import configure
from pydantic import SecretStr
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware

from webauth.admission import AdmissionConfig, EverySubject, GroupPath, NoAdmins
from webauth.config import WebAuthConfig
from webauth.dependencies import (
    admin_user,
    current_user,
    session_id_from_request,
)
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware import (
    BearerGate,
    MachinePaths,
    MarkedRoute,
    PersonPaths,
    ProtectedResource,
    SessionGate,
    bearer_caller,
    resource_person,
)
from webauth.oidc import (
    OidcRefusal,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenRequest,
    TokenRequestPost,
)
from webauth.oidc_login import AccessTokenRefusal, current_groups, fresh_access_token
from webauth.oidc_transport import post_token_request_over_https
from webauth.policies import (
    AuthorizedParties,
    BodySizePolicy,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import (
    AuthenticatedUser,
    BearerCaller,
    SessionRecordStore,
    SessionTransaction,
    SignInStores,
    SignInTransaction,
)
from webauth.sign_in_routes import LogoutPageText, SignInPaths, SignInRefusal
from webauth.web_auth import (
    IssuerCalls,
    SignInPages,
    WebAuth,
    WebAuthSettings,
    WebAuthStores,
)

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
LOGIN_PATH = "/login/oidc"
CALLBACK_PATH = "/auth/callback"
LOGOUT_PATH = "/logout"
BACKCHANNEL_LOGOUT_PATH = "/auth/backchannel-logout"
SIGN_IN_PATHS = SignInPaths(
    start=LOGIN_PATH,
    callback=CALLBACK_PATH,
    logout=LOGOUT_PATH,
    backchannel_logout=BACKCHANNEL_LOGOUT_PATH,
)
LOGOUT_PAGE_TEXT = LogoutPageText(language="en", button_label="Log out")
ACCESS_TOKEN_PATH = "/access-token"  # noqa: S105  # a route, not a credential
WORKLOAD_TOKEN_PATH = "/workload-token"  # noqa: S105  # a route, not a credential
CURRENT_GROUPS_PATH = "/current-groups"
BACKCHANNEL_LOGOUT_MAX_BODY_BYTES = 32 * 1024
DEFAULT_MAX_BODY_BYTES = 1024
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
REPOSITORY = Path(__file__).resolve().parents[3]
SCOPES = ("openid", "profile", "groups")
MACHINE_ROUTES_PREFIX = "/api/admin/"
PERSON_ROUTES_PREFIX = "/api/"
RESOURCE_PATH = "/mcp"
RESOURCE_SCOPE = "mcp:tools"
RESOURCE_GROUP_NAME = "mcp"
AGENT_GROUP = GroupPath("/agents")
MARKED_ROUTES = (
    MarkedRoute("GET", "/notes/{note}"),
    MarkedRoute("POST", "/notes"),
    MarkedRoute("GET", "/notes-admin"),
    MarkedRoute("GET", "/api/notes/{note}"),
)
# A throwaway proof stack runs every sign-in from one address, so no budget may run out.
PROOF_HOST_RATE_LIMIT = RateLimitPolicy(
    default=RateLimitBudget("proof-host", 10_000, 60),
    sign_in=RateLimitBudget("sign-in", 10_000, 60),
)
LEEWAY_SECONDS = 30
USERINFO_TIMEOUT_SECONDS = 10
BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")  # RFC 6750 b64token: fit for a header

PAGE = Template("""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>webauth demo host</title></head>
<body>
<h1>$headline</h1>
$body
</body></html>""")
LOGOUT_BUTTON = (
    f'<form method="post" action="{LOGOUT_PATH}">'
    '<button id="logout" type="submit">Log out</button></form>'
)


@functools.cache
def _arrangement() -> Any:
    """The library suite's in-memory stores, imported as the ``tests.support`` package.

    The host runs as a script, so the repository root is not yet on the import path."""
    sys.path.insert(0, str(REPOSITORY))
    from tests.support import (
        account_arrangement,
        client_address_arrangement,
        session_store_arrangement,
        webauth_arrangement,
    )

    return SimpleNamespace(
        accounts=account_arrangement,
        client_address=client_address_arrangement,
        sessions=session_store_arrangement,
        webauth=webauth_arrangement,
    )


@dataclass(frozen=True)
class HostSettings:
    """Everything a host process is told; the file that carries it is deleted with the run."""

    app_origins: tuple[str, ...]
    port: int
    observe_port: int
    tls_certificate: str
    tls_key: str
    issuer: str
    login_group: str
    """The host's app group, or the value of ``EverySubject.OF_THE_BOUND_ISSUER``."""
    admin_group: str
    """The host's admin group, or the value of ``NoAdmins.IN_THIS_APP``."""
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    end_session_endpoint: str
    client_id: str
    client_secret: str
    session_secret: str
    cookie_samesite: Literal["strict", "lax"] = "strict"
    userinfo_endpoint: str | None = None
    bearer_authorized_parties: tuple[str, ...] = ()
    """The client ids whose access tokens open the machine routes; none means no such routes."""
    discovers_client_config: bool = False
    """Whether the host reads the four endpoints from the issuer's discovery document at start;
    otherwise it takes the endpoint fields above."""

    @property
    def is_bearer_host(self) -> bool:
        return bool(self.bearer_authorized_parties)

    @staticmethod
    def read(path: Path) -> HostSettings:
        fields = json.loads(path.read_text())
        return HostSettings(
            **{
                **fields,
                "app_origins": tuple(fields["app_origins"]),
                "bearer_authorized_parties": tuple(fields["bearer_authorized_parties"]),
            }
        )

    def write(self, path: Path) -> None:
        path.touch(mode=0o600)
        path.write_text(json.dumps(asdict(self)))


class AccessTokenKept:
    """A ``TokenRequestPost`` that passes the answer on and keeps its access token in memory."""

    def __init__(self, post_token_request: TokenRequestPost) -> None:
        self._post_token_request = post_token_request
        self.access_token: str | None = None
        self.refused = 0

    def __call__(self, request: TokenRequest) -> TokenEndpointAnswer:
        answer = self._post_token_request(request)
        self.access_token = self._access_token_in(answer)
        return answer

    def _access_token_in(self, answer: TokenEndpointAnswer) -> str | None:
        try:
            token = json.loads(answer.body).get("access_token")
        except ValueError, AttributeError:
            return None  # the relying party judges an answer that is no token answer
        if token is None:
            return None
        if isinstance(token, str) and BEARER_TOKEN.fullmatch(token):
            return token
        self.refused += 1  # never sent, so no transport error quotes a token no header can carry
        return None


class World:
    """The host's stores and counters; a new ``World`` starts them all again."""

    def __init__(self, settings: HostSettings) -> None:
        arrangement = _arrangement()
        self.token_requests = AccessTokenKept(post_token_request_over_https)
        self.lock = arrangement.accounts.WriteLockInMemory()
        self.accounts = arrangement.accounts.UsersInMemory(lock=self.lock)
        self.sessions = arrangement.sessions.SessionRecordsInMemory(
            users=self.accounts, lock=self.lock
        )
        self.audit = arrangement.webauth.RecordingAuditSink()
        self.callbacks_received = 0
        self.backchannel_accepted = 0
        self.backchannel_refused = 0
        self.logins_admitted = 0
        self.last_refusal: str | None = None
        self.last_token_rejection: str | None = None
        self.userinfo_calls = 0
        self.userinfo_answered = 0
        self.session_transactions = 0
        self.stored_refresh_tokens: set[str] = set()

    def remember_refresh_token_of(self, session_id: str) -> None:
        """Keep the refresh token the session stores now, to count how many differ."""
        record = self.sessions.load(session_id)
        if record is not None and record.refresh_token is not None:
            self.stored_refresh_tokens.add(record.refresh_token.get_secret_value())

    def counts(self) -> dict[str, object]:
        return {
            "accounts": len(self.accounts.list()),
            "privileged_accounts": sum(
                user.role != _arrangement().accounts.MEMBER_ROLE for user in self.accounts.list()
            ),
            "sessions": self.sessions.count_active(),
            "callbacks_received": self.callbacks_received,
            "backchannel_accepted": self.backchannel_accepted,
            "backchannel_refused": self.backchannel_refused,
            "last_refusal": self.last_refusal,
            "token_rejection": self.last_token_rejection,
            "logins_admitted": self.logins_admitted,
            "userinfo_calls": self.userinfo_calls,
            "userinfo_answered": self.userinfo_answered,
            "access_tokens_refused": self.token_requests.refused,
            "session_transactions": self.session_transactions,
            "account_events": len(self.audit.account_events),
        }


class _Observation:
    """The counts-only listener the scenarios read and reset through."""

    def __init__(self, port: int, served: _Served) -> None:
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                """Nothing is logged."""

            def do_GET(self) -> None:
                payload = json.dumps(served.world.counts()).encode()
                self.send_response(200 if self.path == "/state" else 404)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                if self.path == "/reset":
                    served.reset()
                self.send_response(204 if self.path == "/reset" else 404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer((LOOPBACK, port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()


def call_userinfo(settings: HostSettings, current: World) -> None:
    """The one UserInfo request of an admitted login, trusting what ``SSL_CERT_FILE`` names."""
    access_token = current.token_requests.access_token
    if settings.userinfo_endpoint is None or access_token is None:
        return
    current.userinfo_calls += 1
    try:
        httpx.get(
            settings.userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            verify=ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"]),
            timeout=USERINFO_TIMEOUT_SECONDS,
        ).raise_for_status()
    except httpx.HTTPError as error:
        logger.warning("the UserInfo call failed: %s", type(error).__name__)
        return
    current.userinfo_answered += 1


def _sign_in_transaction(world: World) -> SignInTransaction:
    @contextmanager
    def transaction() -> Iterator[SignInStores]:
        with world.lock.hold(), world.sessions.transaction():
            yield SignInStores(world.accounts, world.sessions, world.audit)

    return transaction


def _counted_session_transaction(world: World) -> SessionTransaction:
    """``stores.sessions``: every entry of the session store counts as a session transaction."""

    def counted() -> AbstractContextManager[SessionRecordStore]:
        world.session_transactions += 1
        return world.sessions.in_transaction()

    return counted


# The host without the bearer setting gates only the deep link's album pages, so a browser
# asking for one without a session is sent to the sign-in start with the page as `next`.
_EVERY_PATH_BUT_ALBUMS = PathRules(patterns=(re.compile(r"/(?!albums/)"),))


def _gate_of(settings: HostSettings) -> SessionGate:
    """The session gate: the bearer host's, or the album-page gate of the host without the
    setting."""
    if not settings.is_bearer_host:
        return SessionGate(
            login_redirect=SIGN_IN_PATHS.login_redirect,
            public=(PublicRule(_EVERY_PATH_BUT_ALBUMS),),
        )
    return SessionGate(
        login_redirect=None,
        # The gate would answer a dead cookie with 401 before the route runs; the call
        # answers `session-ended` itself. The install adds the resource's metadata rule.
        public=(
            PublicRule(
                PathRules(exact=frozenset({CURRENT_GROUPS_PATH})),
                methods=frozenset({"GET"}),
            ),
        ),
        optional=PathRules(exact=frozenset({"/"})),
    )


def _bearer_of(settings: HostSettings) -> BearerGate | None:
    """The bearer gate only the bearer host installs; the host without the setting has none."""
    if not settings.is_bearer_host:
        return None
    parties = AuthorizedParties(frozenset(settings.bearer_authorized_parties))
    return BearerGate(
        resource=_resource_of(settings),
        machine_paths=MachinePaths(PathRules(prefixes=(MACHINE_ROUTES_PREFIX,)), parties),
        person_paths=PersonPaths(PathRules(prefixes=(PERSON_ROUTES_PREFIX,)), parties),
    )


def _resource_of(settings: HostSettings) -> ProtectedResource:
    (origin,) = settings.app_origins
    return ProtectedResource(
        f"{origin}{RESOURCE_PATH}",
        RESOURCE_SCOPE,
        GroupPath(f"{settings.login_group}/{RESOURCE_GROUP_NAME}"),
        AGENT_GROUP,
        AuthorizedParties(frozenset(settings.bearer_authorized_parties)),
        frozenset(MARKED_ROUTES),
    )


def _admission_of(settings: HostSettings) -> AdmissionConfig:
    return AdmissionConfig(
        bound_issuer=settings.issuer,
        login_group=(
            EverySubject.OF_THE_BOUND_ISSUER
            if settings.login_group == EverySubject.OF_THE_BOUND_ISSUER.value
            else GroupPath(settings.login_group)
        ),
        admin_group=(
            NoAdmins.IN_THIS_APP
            if settings.admin_group == NoAdmins.IN_THIS_APP.value
            else GroupPath(settings.admin_group)
        ),
    )


def _admitted(answer: Response, config: WebAuthConfig) -> bool:
    """Whether the callback's answer redirects with a session cookie: the login was admitted."""
    session_cookie = f"{config.session_cookie_name}="
    return answer.status_code == 303 and any(
        header.startswith(session_cookie) for header in answer.headers.getlist("set-cookie")
    )


def _counting_callbacks_and_back_channel_answers(
    settings: HostSettings, world: World, config: WebAuthConfig
) -> Middleware:
    async def count_callbacks_and_back_channel_answers(
        request: Request,
        call_next: Any,
    ) -> Response:
        if request.url.path == BACKCHANNEL_LOGOUT_PATH:
            answer = await call_next(request)
            if answer.status_code == 200:
                world.backchannel_accepted += 1
            else:
                world.backchannel_refused += 1
            return answer
        if request.url.path != CALLBACK_PATH:
            return await call_next(request)
        world.callbacks_received += 1
        answer = await call_next(request)
        if _admitted(answer, config):
            world.logins_admitted += 1
            await anyio.to_thread.run_sync(call_userinfo, settings, world)
        return answer

    return Middleware(BaseHTTPMiddleware, dispatch=count_callbacks_and_back_channel_answers)


def _web_auth_for(settings: HostSettings, world: World, origin: str) -> WebAuth:
    arrangement = _arrangement()
    config: WebAuthConfig = arrangement.webauth.a_web_auth_config(
        session_secret=SecretStr(settings.session_secret),
        cookie_samesite=settings.cookie_samesite,
        allowed_hosts_exact=frozenset(
            origin.removeprefix("https://") for origin in settings.app_origins
        ),
    )
    return WebAuth.build(
        WebAuthSettings(
            config=config,
            client=client_config(
                settings,
                f"{origin}{CALLBACK_PATH}",
                f"{origin}/",
                scopes=SCOPES,
                leeway_seconds=LEEWAY_SECONDS,
            ),
            sign_in_paths=SIGN_IN_PATHS,
            keeps_id_token=True,
            max_sessions=None,
            security_headers=SecurityHeadersPolicy(default_content_security_policy()),
            csrf_origin=CsrfPolicy(),
            body_size=BodySizePolicy(default_max_bytes=DEFAULT_MAX_BODY_BYTES),
            rate_limit=PROOF_HOST_RATE_LIMIT,
        ),
        stores=WebAuthStores(
            sign_in=_sign_in_transaction(world), sessions=_counted_session_transaction(world)
        ),
        groups=_admission_of(settings),
        pages=SignInPages(
            refused=_remembering_refusal(world),
            logout_page_text=lambda _request: LOGOUT_PAGE_TEXT,
            ui_language=lambda _request: None,
        ),
        front=arrangement.client_address.TRUSTED_PROXIES,
        gate=_gate_of(settings),
        outside=(_counting_callbacks_and_back_channel_answers(settings, world, config),),
        issuer_calls=IssuerCalls(
            post_token_request=world.token_requests,
            fetch_key_set=fetch_key_set_over_https,
            monotonic_clock=time.monotonic,
        ),
    )


def _app_for(settings: HostSettings, world: World, origin: str) -> FastAPI:
    auth = _web_auth_for(settings, world, origin)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def signed_in_user(request: Request) -> AuthenticatedUser | None:
        try:
            return current_user(request)
        except HTTPException:
            return None

    @app.get("/", response_class=HTMLResponse)
    def home(user: AuthenticatedUser | None = Depends(signed_in_user)) -> str:
        if user is None:
            return PAGE.substitute(
                headline="Signed out", body='<a id="sign-in" href="/login/oidc">Sign in</a>'
            )
        return PAGE.substitute(
            headline=f"Signed in as {html.escape(user.username)}", body=LOGOUT_BUTTON
        )

    @app.get("/albums/{album_id}", response_class=HTMLResponse)
    def album(
        album_id: str,
        user: AuthenticatedUser = Depends(current_user),
    ) -> str:
        return PAGE.substitute(headline=f"Album {html.escape(album_id)}", body=LOGOUT_BUTTON)

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
        return {"username": user.username}

    _add_token_routes(app, auth.relying_party, world, auth.config)

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(admin_user)) -> dict[str, str]:
        return {"username": user.username}

    if settings.is_bearer_host:
        _add_bearer_routes(app, settings)
    auth.install(app, bearer=_bearer_of(settings))
    return app


class _ByHost:
    """Hands each request to the app of the origin it was addressed to.

    The issuer posts the back-channel to the bridge's own Host, which names no app origin, so
    an unknown Host gets the first app. The lifespan goes to the first app too.
    """

    def __init__(self, apps: dict[str, FastAPI]) -> None:
        self._apps = apps
        self._first = next(iter(apps.values()))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._first(scope, receive, send)
            return
        host = dict(scope["headers"]).get(b"host", b"").decode()
        await self._apps.get(f"https://{host}", self._first)(scope, receive, send)


def build_app(settings: HostSettings, world: World) -> ASGIApp:
    apps = {origin: _app_for(settings, world, origin) for origin in settings.app_origins}
    return next(iter(apps.values())) if len(apps) == 1 else _ByHost(apps)


class _Served:
    """The app uvicorn serves, over a world that ``/reset`` replaces with every app built on it."""

    def __init__(self, settings: HostSettings) -> None:
        self._settings = settings
        self.world = World(settings)
        self._app = build_app(settings, self.world)

    def reset(self) -> None:
        world = World(self._settings)
        self._app = build_app(self._settings, world)
        self.world = world

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._app(scope, receive, send)


def _remembering_refusal(world: World) -> Callable[[Request, SignInRefusal], Response]:
    """The refusal page, which also records the refusal's reason for the observer."""

    def refused(request: Request, refusal: SignInRefusal) -> Response:
        cause = refusal.cause
        reason = cause.reason.value if isinstance(cause, OidcRefusal) else cause.value
        world.last_refusal = reason
        rejection = cause.token_rejection if isinstance(cause, OidcRefusal) else None
        world.last_token_rejection = rejection.value if rejection else None
        return HTMLResponse(
            PAGE.substitute(headline="Sign-in refused", body=html.escape(reason)), status_code=403
        )

    return refused


def _add_token_routes(
    app: FastAPI,
    relying_party: OidcRelyingParty,
    world: World,
    config: WebAuthConfig,
) -> None:
    """The routes that answer an outcome of a grant, never a token."""

    def session_of(request: Request) -> str:
        session_id = session_id_from_request(request, config)
        if session_id is None:
            raise HTTPException(status_code=401)
        return session_id

    @app.get(ACCESS_TOKEN_PATH)
    def access_token(request: Request) -> dict[str, object]:
        """The outcome of ``fresh_access_token`` for the request's session, never the token."""
        current = world
        session_id = session_of(request)
        outcome = fresh_access_token(
            relying_party,
            session_id,
            session_transaction=current.sessions.in_transaction,
            config=config,
        )
        current.remember_refresh_token_of(session_id)
        return {
            "outcome": "token" if isinstance(outcome, SecretStr) else outcome.reason.value,
            "refresh_tokens_stored": len(current.stored_refresh_tokens),
        }

    @app.get(CURRENT_GROUPS_PATH)
    def groups(request: Request) -> dict[str, object]:
        """The outcome of ``current_groups`` for the request's session, never a token."""
        current = world
        session_id = session_of(request)
        outcome = current_groups(
            relying_party,
            session_id,
            session_transaction=current.sessions.in_transaction,
            config=config,
        )
        current.remember_refresh_token_of(session_id)
        return {
            **_groups_outcome(outcome),
            "refresh_tokens_stored": len(current.stored_refresh_tokens),
        }

    @app.get(WORKLOAD_TOKEN_PATH)
    def workload_token(request: Request) -> dict[str, str | None]:
        """The outcome of the client's own grant, never the token."""
        outcome = relying_party.workload_access_token(scopes=("profile",))
        if isinstance(outcome, OidcRefusal):
            return {"outcome": outcome.reason.value, "issuer_error": outcome.idp_error}
        return {"outcome": "token", "issuer_error": None}


def _groups_outcome(
    outcome: tuple[str, ...] | AccessTokenRefusal,
) -> dict[str, object]:
    if isinstance(outcome, tuple):
        return {"outcome": "groups", "groups": list(outcome), "issuer_refusal": None}
    refusal = outcome.issuer_refusal
    return {
        "outcome": outcome.reason.value,
        "groups": [],
        "issuer_refusal": None if refusal is None else refusal.reason.value,
    }


def _add_machine_routes(app: FastAPI) -> None:
    """The routes under the bearer gate; they echo the caller and change nothing."""

    @app.get(f"{MACHINE_ROUTES_PREFIX}people/{{subject}}/export")
    def export_person(
        subject: str, caller: BearerCaller = Depends(bearer_caller)
    ) -> dict[str, str]:
        return {"caller": caller.subject, "subject": subject}

    @app.delete(f"{MACHINE_ROUTES_PREFIX}people/{{subject}}")
    def delete_person(
        subject: str, caller: BearerCaller = Depends(bearer_caller)
    ) -> dict[str, str]:
        return {"caller": caller.subject, "subject": subject}

    @app.get(f"{MACHINE_ROUTES_PREFIX}session-probe")
    def session_probe(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
        return {"username": user.username}


def _add_person_routes(app: FastAPI) -> None:
    """The routes under the bearer gate's person paths; they echo the account behind the request."""

    @app.api_route(f"{PERSON_ROUTES_PREFIX}me", methods=["GET", "POST"])
    def person_me(user: AuthenticatedUser = Depends(current_user)) -> dict[str, str]:
        return {"id": user.id, "username": user.username, "role": user.role}


def _add_marked_routes(app: FastAPI) -> None:
    """One route per marked route; only ``/notes-admin`` reads ``admin_user``."""

    def echo(user: AuthenticatedUser) -> dict[str, str]:
        return {"id": user.id, "username": user.username, "role": user.role}

    for route in MARKED_ROUTES:
        reader = admin_user if route.template == "/notes-admin" else current_user

        def note(user: AuthenticatedUser = Depends(reader)) -> dict[str, str]:
            return echo(user)

        app.add_api_route(route.template, note, methods=[route.method, "HEAD", "DELETE"])


def _add_bearer_routes(
    app: FastAPI,
    settings: HostSettings,
) -> None:
    """The routes of each kind of path the bearer gate selects."""
    _add_machine_routes(app)
    _add_person_routes(app)
    _add_marked_routes(app)

    @app.api_route(_resource_of(settings).entry_point, methods=["GET", "POST"])
    def entry_point(request: Request) -> dict[str, str]:
        person = resource_person(request)
        return {"id": person.id, "username": person.username, "role": person.role}


def die_with_parent(parent_pid: int) -> None:
    """Linux ``PR_SET_PDEATHSIG``: a host nobody can stop must not outlive its run."""
    pr_set_pdeathsig = 1
    if ctypes.CDLL(None, use_errno=True).prctl(pr_set_pdeathsig, signal.SIGKILL) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_PDEATHSIG) failed")
    if os.getppid() != parent_pid:
        raise SystemExit("the parent ended before the host could watch it")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    arguments = parser.parse_args()
    die_with_parent(arguments.parent_pid)
    settings = HostSettings.read(arguments.settings)
    configure("webauth-e2e-host")
    served = _Served(settings)
    _Observation(settings.observe_port, served)
    uvicorn.run(
        served,
        host=LOOPBACK,
        port=settings.port,
        ssl_certfile=settings.tls_certificate,
        ssl_keyfile=settings.tls_key,
        log_config=None,
    )


if __name__ == "__main__":
    main()
