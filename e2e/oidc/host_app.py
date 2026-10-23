"""The host application of the proof: start, callback, logout and back-channel
logout routes over the library's own in-memory stores, served over TLS.

One process serves one cookie configuration on every origin it is told. Beside
it a plain-http listener on loopback, which no browser is ever pointed at, answers
``GET /state`` with counts only (among them the access tokens refused as unfit for a
header and the back-channel logouts accepted and refused), clears everything on
``POST /reset`` (the relying parties, with their key-set caches, are built again).

Where an issuer is told a ``userinfo_endpoint``, the host calls it once, with the
access token of the token answer, after and only after a login was admitted: the
conformance suite finishes an accepting module on that request. A call that fails is
logged by exception type alone and never ends the admitted login."""

from __future__ import annotations

import argparse
import ctypes
import functools
import html
import importlib.util
import json
import logging
import os
import re
import signal
import ssl
import sys
import threading
import time
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from typing import Any, Literal

import anyio.to_thread
import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import SecretStr

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import issue_session_cookies
from webauth.dependencies import (
    LoginRedirect,
    current_user_dependency,
    session_id_from_request,
)
from webauth.https_client import fetch_key_set_over_https
from webauth.middleware import (
    BearerGate,
    SessionGate,
    bearer_caller,
    install_web_auth_middleware,
)
from webauth.oidc import (
    OidcClientConfig,
    OidcRefusal,
    OidcRelyingParty,
    TokenEndpointAnswer,
    TokenRequest,
    TokenRequestPost,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    BackchannelLogoutResult,
    EverySubject,
    NoAdmins,
    finish_login,
    fresh_access_token,
    log_out,
    open_session,
    receive_backchannel_logout,
    start_login,
)
from webauth.oidc_transport import post_token_request_over_https
from webauth.policies import (
    AuthorizedParties,
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import AuthenticatedUser, BearerCaller, SessionRecordStore

logger = logging.getLogger(__name__)

LOOPBACK = "127.0.0.1"
LOGIN_PATH = "/login/oidc"
CALLBACK_PATH = "/auth/callback"
LOGOUT_PATH = "/logout"
LOGOUT_BUTTON_LABEL = "Log out"
BACKCHANNEL_LOGOUT_PATH = "/auth/backchannel-logout"
ACCESS_TOKEN_PATH = "/access-token"  # noqa: S105  # a route, not a credential
WORKLOAD_TOKEN_PATH = "/workload-token"  # noqa: S105  # a route, not a credential
BACKCHANNEL_LOGOUT_MAX_BODY_BYTES = 32 * 1024
DEFAULT_MAX_BODY_BYTES = 1024
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
REPOSITORY = Path(__file__).resolve().parents[2]
SCOPES = ("openid", "profile", "groups")
MACHINE_ROUTES_PREFIX = "/api/admin/"
BEARER_GATE_LOGGER = "webauth.middleware.bearer_gate"
BEARER_HOST_REQUESTS_PER_MINUTE = 10_000
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
    """The library suite's in-memory stores, loaded by path from ``tests/``."""
    path = REPOSITORY / "tests" / "webauth_arrangement.py"
    spec = importlib.util.spec_from_file_location("webauth_arrangement", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


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

    @property
    def is_bearer_host(self) -> bool:
        return bool(self.bearer_authorized_parties)

    @staticmethod
    def read(path: Path) -> HostSettings:
        fields = json.loads(path.read_text())
        return HostSettings(**{
            **fields,
            "app_origins": tuple(fields["app_origins"]),
            "bearer_authorized_parties": tuple(fields["bearer_authorized_parties"]),
        })

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
        except (ValueError, AttributeError):
            return None  # the relying party judges an answer that is no token answer
        if token is None:
            return None
        if isinstance(token, str) and BEARER_TOKEN.fullmatch(token):
            return token
        self.refused += 1  # never sent, so no transport error quotes a token no header can carry
        return None


class World:
    """The host's stores, relying parties and counters; a new ``World`` starts them all again."""

    def __init__(self, settings: HostSettings) -> None:
        arrangement = _arrangement()
        self.token_requests = AccessTokenKept(post_token_request_over_https)
        self.relying_parties = {
            origin: _relying_party(
                settings, f"{origin}{CALLBACK_PATH}", f"{origin}/", self.token_requests
            )
            for origin in settings.app_origins
        }
        self.lock = arrangement.WriteLockInMemory()
        self.accounts = arrangement.UsersInMemory(lock=self.lock)
        self.sessions = arrangement.SessionRecordsInMemory(users=self.accounts, lock=self.lock)
        self.audit = arrangement.RecordingAuditSink()
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
        }


class _Observation:
    """The counts-only listener the scenarios read and reset through."""

    def __init__(
        self, port: int, world: dict[str, World], new_world: Callable[[], World]
    ) -> None:
        holder = world

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                """Nothing is logged."""

            def do_GET(self) -> None:
                payload = json.dumps(holder["world"].counts()).encode()
                self.send_response(200 if self.path == "/state" else 404)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                if self.path == "/reset":
                    holder["world"] = new_world()
                self.send_response(204 if self.path == "/reset" else 404)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer((LOOPBACK, port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()


def _relying_party(
    settings: HostSettings,
    redirect_uri: str,
    post_logout_redirect_uri: str,
    post_token_request: TokenRequestPost,
) -> OidcRelyingParty:
    return OidcRelyingParty(
        OidcClientConfig(
            issuer=settings.issuer,
            authorization_endpoint=settings.authorization_endpoint,
            token_endpoint=settings.token_endpoint,
            jwks_url=settings.jwks_url,
            end_session_endpoint=settings.end_session_endpoint,
            client_id=settings.client_id,
            client_secret=SecretStr(settings.client_secret),
            redirect_uri=redirect_uri,
            post_logout_redirect_uri=post_logout_redirect_uri,
            scopes=SCOPES,
            leeway_seconds=LEEWAY_SECONDS,
        ),
        post_token_request=post_token_request,
        fetch_key_set=fetch_key_set_over_https,
        wall_clock=time.time,
        monotonic_clock=time.monotonic,
    )


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


def _install_stack(app: FastAPI, settings: HostSettings, world: dict[str, World]) -> None:
    backchannel_path = PathRules(exact=frozenset({BACKCHANNEL_LOGOUT_PATH}))
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            default_content_security_policy(),
            cache_control_rules=(CacheControlRule(paths=backchannel_path, value="no-store"),),
        ),
        body_size=BodySizePolicy(
            default_max_bytes=DEFAULT_MAX_BODY_BYTES,
            rules=(BodySizeRule(
                paths=backchannel_path, max_bytes=BACKCHANNEL_LOGOUT_MAX_BODY_BYTES
            ),),
        ),
        csrf_origin=CsrfPolicy(exempt=backchannel_path),
        **_bearer_policies(settings, world),
    )


def _bearer_policies(settings: HostSettings, world: dict[str, World]) -> dict[str, Any]:
    """The policies only the bearer host installs; the host without the setting has none."""
    if not settings.is_bearer_host:
        return {}

    def counted_session_transaction() -> AbstractContextManager[SessionRecordStore]:
        current = world["world"]  # `/reset` replaces the world, so it is read at call time
        current.session_transactions += 1
        return current.sessions.in_transaction()

    (origin,) = settings.app_origins
    return {
        "rate_limit": RateLimitPolicy(
            default=RateLimitBudget("bearer-host", BEARER_HOST_REQUESTS_PER_MINUTE, 60)
        ),
        "session_gate": SessionGate(
            session_transaction=counted_session_transaction,
            login_redirect=None,
            public=(PublicRule(PathRules(exact=frozenset(
                {LOGIN_PATH, CALLBACK_PATH, BACKCHANNEL_LOGOUT_PATH}
            ))),),
            optional=PathRules(exact=frozenset({"/"})),
        ),
        "bearer_gate": BearerGate(
            paths=PathRules(prefixes=(MACHINE_ROUTES_PREFIX,)),
            relying_party=_relying_party(
                settings, f"{origin}{CALLBACK_PATH}", f"{origin}/", post_token_request_over_https
            ),
            admission=_admission_of(settings),
            authorized_parties=AuthorizedParties(frozenset(settings.bearer_authorized_parties)),
        ),
    }


def _admission_of(settings: HostSettings) -> AdmissionConfig:
    return AdmissionConfig(
        bound_issuer=settings.issuer,
        login_group=(
            EverySubject.OF_THE_BOUND_ISSUER
            if settings.login_group == EverySubject.OF_THE_BOUND_ISSUER.value
            else settings.login_group
        ),
        admin_group=(
            NoAdmins.IN_THIS_APP
            if settings.admin_group == NoAdmins.IN_THIS_APP.value
            else settings.admin_group
        ),
    )


def build_app(settings: HostSettings, world: dict[str, World]) -> FastAPI:
    arrangement = _arrangement()
    config: WebAuthConfig = arrangement.a_web_auth_config(
        session_secret=SecretStr(settings.session_secret),
        cookie_samesite=settings.cookie_samesite,
        allowed_hosts_exact=frozenset(
            origin.removeprefix("https://") for origin in settings.app_origins
        ),
    )

    admission = _admission_of(settings)

    def relying_party_of(request: Request) -> OidcRelyingParty:
        return world["world"].relying_parties[f"https://{request.headers['host']}"]

    dependencies = current_user_dependency(
        session_store=lambda: world["world"].sessions,
        on_authenticated=lambda user: None,
    )
    redirecting_dependencies = current_user_dependency(
        session_store=lambda: world["world"].sessions,
        on_authenticated=lambda user: None,
        login_redirect=LoginRedirect(path=LOGIN_PATH, redirect_query_param="next"),
    )
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    install_web_auth_config(app, config)
    _install_stack(app, settings, world)

    @app.middleware("http")
    async def count_callbacks(request: Request, call_next: Any) -> Response:
        if request.url.path == CALLBACK_PATH:
            world["world"].callbacks_received += 1
        return await call_next(request)

    def signed_in_user(request: Request) -> AuthenticatedUser | None:
        try:
            return dependencies.current_user(request, world["world"].sessions)
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
        user: AuthenticatedUser = Depends(redirecting_dependencies.current_user),
    ) -> str:
        return PAGE.substitute(headline=f"Album {html.escape(album_id)}", body=LOGOUT_BUTTON)

    @app.get(LOGIN_PATH)
    def start(request: Request, next: str | None = None) -> Response:  # noqa: A002
        response = Response(status_code=303)
        response.headers["location"] = start_login(
            relying_party_of(request), request, response, config, return_to=next
        )
        return response

    @app.get(CALLBACK_PATH, response_class=HTMLResponse)
    def callback(request: Request, response: Response) -> str:
        current = world["world"]
        outcome = finish_login(
            relying_party_of(request), request, response, config,
            admission=admission, accounts=current.accounts, lock=current.lock,
            audit=current.audit,
        )
        if isinstance(outcome, (OidcRefusal, AdmissionRefusal)):
            reason = outcome.reason.value if isinstance(outcome, OidcRefusal) else outcome.value
            current.last_refusal = reason
            rejection = outcome.token_rejection if isinstance(outcome, OidcRefusal) else None
            current.last_token_rejection = rejection.value if rejection else None
            response.status_code = 403
            return PAGE.substitute(headline="Sign-in refused", body=html.escape(reason))
        current.logins_admitted += 1
        call_userinfo(settings, current)
        with current.sessions.transaction():
            session = open_session(
                request, config, outcome,
                sessions=current.sessions, lock=current.lock,
                max_sessions=None, keeps_id_token=True,
            )
        issue_session_cookies(response, session.id, config)
        response.status_code = 303
        response.headers["location"] = outcome.return_to or "/"
        return ""

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get(ACCESS_TOKEN_PATH)
    def access_token(request: Request) -> dict[str, object]:
        """The outcome of ``fresh_access_token`` for the request's session, never the token."""
        current = world["world"]
        session_id = session_id_from_request(request, config)
        if session_id is None:
            raise HTTPException(status_code=401)
        outcome = fresh_access_token(
            relying_party_of(request), session_id,
            session_transaction=current.sessions.in_transaction, config=config,
        )
        current.remember_refresh_token_of(session_id)
        return {
            "outcome": "token" if isinstance(outcome, SecretStr) else outcome.reason.value,
            "refresh_tokens_stored": len(current.stored_refresh_tokens),
        }

    @app.get(WORKLOAD_TOKEN_PATH)
    def workload_token(request: Request) -> dict[str, str | None]:
        """The outcome of the client's own grant, never the token."""
        outcome = relying_party_of(request).workload_access_token()
        if isinstance(outcome, OidcRefusal):
            return {"outcome": outcome.reason.value, "issuer_error": outcome.idp_error}
        return {"outcome": "token", "issuer_error": None}

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.post(LOGOUT_PATH)
    def logout(request: Request) -> Response:
        current = world["world"]
        return log_out(
            relying_party_of(request), request, config,
            sessions=current.sessions, lock=current.lock, button_label=LOGOUT_BUTTON_LABEL,
        )

    def end_the_sessions_of(form_body: bytes, content_type: str | None) -> BackchannelLogoutResult:
        current = world["world"]
        with current.sessions.transaction():
            return receive_backchannel_logout(
                next(iter(current.relying_parties.values())), form_body, content_type,
                accounts=current.accounts, sessions=current.sessions,
                lock=current.lock, audit=current.audit,
            )

    @app.post(BACKCHANNEL_LOGOUT_PATH)
    async def backchannel_logout(request: Request) -> Response:
        form_body = await request.body()
        content_type = request.headers.get("content-type")
        current = world["world"]
        result = BackchannelLogoutResult.REFUSED
        try:
            result = await anyio.to_thread.run_sync(end_the_sessions_of, form_body, content_type)
        except Exception:
            logger.exception("back-channel logout failed")
        if result is BackchannelLogoutResult.ACCEPTED:
            current.backchannel_accepted += 1
            return Response(status_code=200)
        current.backchannel_refused += 1
        return Response(status_code=400)

    if settings.is_bearer_host:
        _add_machine_routes(app, dependencies.current_user)
    return app


def _add_machine_routes(
    app: FastAPI, current_user: Callable[..., AuthenticatedUser]
) -> None:
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
    def session_probe(
        user: AuthenticatedUser = Depends(current_user)
    ) -> dict[str, str]:
        return {"username": user.username}


def log_the_bearer_gate() -> None:
    """Uvicorn leaves this logger at WARNING, which would lose the gate's INFO refusals."""
    gate_logger = logging.getLogger(BEARER_GATE_LOGGER)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    gate_logger.addHandler(handler)
    gate_logger.setLevel(logging.INFO)


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
    if settings.is_bearer_host:
        log_the_bearer_gate()
    world = {"world": World(settings)}
    _Observation(settings.observe_port, world, lambda: World(settings))
    uvicorn.run(
        build_app(settings, world),
        host=LOOPBACK,
        port=settings.port,
        ssl_certfile=settings.tls_certificate,
        ssl_keyfile=settings.tls_key,
        log_level="warning",
        access_log=False,
    )


if __name__ == "__main__":
    main()
