"""Shared arrangement for the webauth suites."""

from __future__ import annotations

import enum
import hashlib
import hmac
from collections.abc import Iterable, Mapping, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import get_ident
from typing import TYPE_CHECKING, Any, Final

import anyio
from fastapi import Depends, FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from httpx import Headers as HttpxHeaders
from httpx import Response as HttpxResponse
from pydantic import SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketDisconnect

from tests.support.account_arrangement import FakeUser
from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.session_store_arrangement import (
    FakeSessionRecord,
    SessionRecordsInMemory,
    SessionsRecordingTheirTransaction,
)
from webauth.config import (
    SessionLifetime,
    WebAuthConfig,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import sign_session_id
from webauth.dependencies import (
    ConnectionRefusal,
    LoginRedirect,
    authenticate_websocket,
    current_user_dependency,
    session_id_from_request,
)
from webauth.middleware import (
    IpRateLimitMiddleware,
    SessionGate,
    admitted_user,
)
from webauth.policies import (
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
)
from webauth.ports import (
    AccountEvent,
    AuthenticatedUser,
    RateLimitBackend,
    SessionRecordStore,
    SessionTransaction,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

TRUSTED_PROXY_NETWORK = "172.16.0.0/12"
ALLOWED_HOST = "notes.example"
ALLOWED_ORIGIN = f"https://{ALLOWED_HOST}"
SAME_ORIGIN_REQUEST = {"origin": ALLOWED_ORIGIN, "sec-fetch-site": "same-origin"}
# The suite reaches its applications over https, as production does, so the
# cookie and header flags under test are the ones a deployment really sends.
HTTPS_TEST_SERVER = "https://testserver"
MIN_SESSION_SECRET_CHARS = 32
SESSION_ID = "session-1"
CLIENT_ADDRESS = "testclient"
ADMIN_ROLE = "admin"
SPEC_WITH_CONCURRENT_READER = "2.3"
SPEC_WITHOUT_CONCURRENT_READER = "2.4"
SESSION_IDLE_SECONDS = 3600
SESSION_ABSOLUTE_MAX_AGE_SECONDS = 86400
SEVEN_DAYS_SECONDS = 7 * 24 * 3600
THIRTY_DAYS_SECONDS = 30 * 24 * 3600
FIXED_INSTANT = datetime(2030, 1, 1, 12, tzinfo=UTC)
FIXED_WALL_CLOCK = FIXED_INSTANT.timestamp


if TYPE_CHECKING:
    from starlette.testclient import WebSocketTestSession
    from starlette.types import ASGIApp, Message, Scope

DRIVE_DEADLINE_SECONDS: Final = 5


def web_auth_config_arguments() -> dict[str, Any]:
    """Every argument a complete configuration is built from."""
    return {
        "session_secret": SecretStr("s" * MIN_SESSION_SECRET_CHARS),
        "trusted_proxies": TrustedProxies.parse(TRUSTED_PROXY_NETWORK),
        "rate_limits": SingleProcessRateLimitBackend(),
        "allowed_hosts_exact": frozenset({ALLOWED_HOST}),
        "session_lifetime": SessionLifetime(
            idle_seconds=SESSION_IDLE_SECONDS,
            absolute_max_age_seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS,
        ),
    }


def a_web_auth_config(**overrides: Any) -> WebAuthConfig:
    """A complete configuration; a keyword replaces the field it names."""
    return WebAuthConfig(**{**web_auth_config_arguments(), **overrides})


SESSION_COOKIE_NAME = a_web_auth_config().session_cookie_name


def signed_without_bound(payload: str, secret: bytes) -> str:
    """``payload`` signed like a session cookie but never refused for its length."""
    signature = hmac.new(secret, b"session:" + payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def session_cookie_header(*cookie_values: str) -> str:
    """A Cookie header carrying the default session cookie once per value, in order."""
    return "; ".join(f"{SESSION_COOKIE_NAME}={value}" for value in cookie_values)


API_PATH = "/api/thing"
RATE_LIMITED_PATH = API_PATH
BULK_PATH = "/bulk/thing"
DEFAULT_BUDGET_NAME = "api"
BULK_BUDGET_NAME = "bulk"
DEFAULT_RATE_WINDOW_SECONDS = 60


def a_policy_rate_limited_client(
    rate_limits: RateLimitBackend,
    policy: RateLimitPolicy,
    *,
    paths: tuple[str, ...] = (API_PATH,),
    **config_overrides: Any,
) -> TestClient:
    """A client whose requests spend from ``policy`` over ``rate_limits``.

    Every path in ``paths`` answers 200 when the limiter lets it through; a
    keyword replaces the configuration field it names.
    """
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config(rate_limits=rate_limits, **config_overrides))
    app.add_middleware(IpRateLimitMiddleware, policy=policy)
    for path in paths:
        app.add_api_route(path, lambda: {"status": "ok"}, methods=["GET"])
    return TestClient(app, base_url=HTTPS_TEST_SERVER)


def a_rate_limited_client(
    rate_limits: RateLimitBackend,
    *,
    max_requests: int,
    window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS,
    **config_overrides: Any,
) -> TestClient:
    """A client whose every request spends the one default budget of ``rate_limits``."""
    policy = RateLimitPolicy(
        default=RateLimitBudget(DEFAULT_BUDGET_NAME, max_requests, window_seconds),
    )
    return a_policy_rate_limited_client(rate_limits, policy, **config_overrides)


@dataclass
class RecordingAuditSink:
    account_events: list[AccountEvent] = field(default_factory=list)

    def account_event(self, event: AccountEvent) -> None:
        self.account_events.append(event)


WEBSOCKET_PATH = "/ws"
WEBSOCKET_ADMITTED_PATH = "/ws-admitted"
OPEN_PATHS = ("/health", "/login", "/hooks/x", "/static/x.css", "/optional")
ALL_DEPENDENCIES_PATH = "/all"
LOGIN_REDIRECT = LoginRedirect(path="/login", redirect_query_param="next")
WEBSOCKET_DEPENDENCY_PATH = "/ws-dependency"
POLICY_VIOLATION_CLOSE_CODE = 1008


@dataclass
class AuthApp:
    """A minimal application serving the routes the dependencies protect."""

    client: TestClient
    sessions: SessionRecordsInMemory
    authenticated: list[AuthenticatedUser]
    websocket_outcomes: list[AuthenticatedUser | ConnectionRefusal]
    signing_key: bytes
    app: FastAPI
    config: WebAuthConfig
    route_runs: list[str]
    route_threads: list[int]
    resource_persons: list[AuthenticatedUser] = field(default_factory=list)

    def get(
        self, path: str, *, cookie: str | None = None, accept: str | None = None
    ) -> HttpxResponse:
        headers = {} if cookie is None else {"cookie": f"{SESSION_COOKIE_NAME}={cookie}"}
        if accept is not None:
            headers["accept"] = accept
        return self.client.get(path, headers=headers, follow_redirects=False)

    def connect(
        self,
        path: str = WEBSOCKET_PATH,
        *,
        cookie: str | None = None,
        origin: str | None = ALLOWED_ORIGIN,
        headers: Sequence[tuple[str, str]] = (),
    ) -> WebSocketTestSession:
        """A WebSocket handshake; ``cookie`` and ``origin`` are left out when ``None``."""
        sent = list(headers)
        if cookie is not None:
            sent.append(("cookie", f"{self.config.session_cookie_name}={cookie}"))
        if origin is not None:
            sent.append(("origin", origin))
        return self.client.websocket_connect(path, headers=HttpxHeaders(sent))

    def signed_cookie(self, session_id: str = SESSION_ID) -> str:
        return sign_session_id(session_id, self.signing_key)


def seeded_session(
    sessions: SessionRecordsInMemory,
    hold: AbstractContextManager[None],
    user_id: str,
    now: datetime,
    expires_at: datetime,
    refresh_token: SecretStr | None = None,
) -> FakeSessionRecord:
    """A stored session of ``user_id``, created the way a host does: under its write lock."""
    with hold:
        return sessions.create(
            user_id,
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=None,
        )


def a_session(
    *,
    age: timedelta = timedelta(minutes=5),
    remaining: timedelta = timedelta(minutes=30),
    user: FakeUser | None = None,
    now: datetime | None = None,
) -> FakeSessionRecord:
    now = now or datetime.now(UTC)
    return FakeSessionRecord(
        id=SESSION_ID,
        user=user or FakeUser(),
        created_at=now - age,
        expires_at=now + remaining,
    )


def _add_websocket_routes(
    app: FastAPI,
    sessions: SessionRecordStore,
    outcomes: list[AuthenticatedUser | ConnectionRefusal],
) -> None:
    """The host recipe: authenticate in a worker and a finished transaction, then accept.

    ``WEBSOCKET_PATH`` answers every message by authenticating again;
    ``WEBSOCKET_DEPENDENCY_PATH`` wraps the helper in a dependency.
    """
    transaction = (
        sessions.transaction if isinstance(sessions, SessionRecordsInMemory) else nullcontext
    )

    def authenticate(connection: HTTPConnection) -> AuthenticatedUser | ConnectionRefusal:
        with transaction():
            outcome = authenticate_websocket(connection, sessions=sessions)
        outcomes.append(outcome)
        return outcome

    @app.websocket(WEBSOCKET_PATH)
    async def watched(websocket: WebSocket) -> None:
        outcome = await run_in_threadpool(authenticate, websocket)
        if isinstance(outcome, ConnectionRefusal):
            await websocket.close(code=POLICY_VIOLATION_CLOSE_CODE)
            return
        await websocket.accept()
        session_id = session_id_from_request(websocket, web_auth_config(websocket))
        await websocket.send_json({"username": outcome.username, "session_id": session_id})
        try:
            while True:
                await websocket.receive_text()
                outcome = await run_in_threadpool(authenticate, websocket)
                if isinstance(outcome, ConnectionRefusal):
                    await websocket.close(code=POLICY_VIOLATION_CLOSE_CODE)
                    return
                await websocket.send_json({"username": outcome.username})
        except WebSocketDisconnect:
            return

    @app.websocket(WEBSOCKET_ADMITTED_PATH)
    async def reading_admission(websocket: WebSocket) -> None:
        admitted_user(websocket)
        await websocket.accept()
        await websocket.close()

    @app.websocket(WEBSOCKET_DEPENDENCY_PATH)
    async def through_a_dependency(
        websocket: WebSocket,
        outcome: AuthenticatedUser | ConnectionRefusal = Depends(authenticate),
    ) -> None:
        if isinstance(outcome, ConnectionRefusal):
            await websocket.close(code=POLICY_VIOLATION_CLOSE_CODE)
            return
        await websocket.accept()
        await websocket.send_json({"username": outcome.username})
        await websocket.close()


def _add_session_routes(auth: AuthApp, login_redirect: LoginRedirect | None) -> None:
    app, sessions = auth.app, auth.sessions
    route_runs, route_threads = auth.route_runs, auth.route_threads
    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        on_authenticated=auth.authenticated.append,
        login_redirect=login_redirect,
    )

    @app.get("/me")
    def me(
        request: Request, user: AuthenticatedUser = Depends(dependencies.current_user)
    ) -> dict[str, str]:
        route_runs.append(request.url.path)
        return {"username": user.username, "role": user.role}

    @app.get(ALL_DEPENDENCIES_PATH)
    def all_dependencies(
        user: AuthenticatedUser = Depends(dependencies.current_user),
        admin: AuthenticatedUser = Depends(dependencies.admin_user),
    ) -> dict[str, str]:
        return {"username": user.username, "admin": admin.username}

    async def reading_admission(request: Request) -> dict[str, str | None]:
        route_runs.append(request.url.path)
        route_threads.append(get_ident())
        if isinstance(sessions, SessionsRecordingTheirTransaction):
            sessions.events.append(("route", get_ident()))
        user = admitted_user(request)
        return {"username": None if user is None else user.username}

    for path in OPEN_PATHS:
        app.add_api_route(path, reading_admission, methods=["GET", "POST", "HEAD", "OPTIONS"])

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}


def an_auth_app(
    record: FakeSessionRecord | None,
    *,
    login_redirect: LoginRedirect | None = None,
    sessions: SessionRecordsInMemory | None = None,
    config: WebAuthConfig | None = None,
    gate: bool = False,
    public: tuple[PublicRule, ...] = (),
    optional: PathRules | None = None,
    session_transaction: SessionTransaction | None = None,
    root_path: str = "",
    raise_server_exceptions: bool = True,
    stack_policies: Mapping[str, Any] | None = None,
    **config_overrides: Any,
) -> AuthApp:
    """An application serving one protected, one admin, one session-id route.

    It also serves the WebSocket routes of ``_add_websocket_routes`` and, at ``OPEN_PATHS``, a
    route that reads ``admitted_user``. A keyword replaces the configuration field it names;
    ``config`` is an existing instance instead (no overrides then). ``gate`` installs the library
    middleware with a ``SessionGate`` over ``public`` and ``optional``, its transaction
    ``session_transaction`` or else the store's ``in_transaction``; ``stack_policies`` adds the
    other policies the installer takes, or replaces the headers.
    """
    config = config or a_web_auth_config(**config_overrides)
    if sessions is None:
        sessions = SessionRecordsInMemory(record)
    app = FastAPI(root_path=root_path)
    install_web_auth_config(app, config)
    if gate:
        session_gate = SessionGate(
            session_transaction=session_transaction or sessions.in_transaction,
            login_redirect=login_redirect,
            public=public,
            optional=optional or PathRules(),
        )
        install_the_gated_stack(app, session_gate=session_gate, **(stack_policies or {}))
    auth = AuthApp(
        client=TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            cookies={},
            raise_server_exceptions=raise_server_exceptions,
        ),
        sessions=sessions,
        authenticated=[],
        websocket_outcomes=[],
        signing_key=config.signing_key,
        app=app,
        config=config,
        route_runs=[],
        route_threads=[],
    )
    _add_session_routes(auth, login_redirect)
    _add_websocket_routes(app, sessions, auth.websocket_outcomes)
    return auth


class StartSend(enum.Enum):
    """How the server takes the response start; the suspended modes need a concurrent
    reader of the body (ASGI spec before 2.4), because the excess arrives while the start
    is still in its send. HELD_PAST_THE_DEADLINE holds the start in its send for longer than
    the drive deadline and only then records it, so a send left unbounded shows as a start."""

    PLAIN = enum.auto()
    SUSPENDED_BEFORE_ACCEPTING = enum.auto()
    SUSPENDED_AFTER_ACCEPTING = enum.auto()
    HELD_PAST_THE_DEADLINE = enum.auto()


async def no_receive() -> Message:
    return {"type": "http.disconnect"}


def an_http_scope(
    app: FastAPI,
    path: str = "/boom",
    *,
    method: str = "GET",
    headers: Iterable[tuple[bytes, bytes]] = (),
    spec_version: str | None = None,
    raw_path: bytes | None = None,
    root_path: str = "",
) -> Scope:
    asgi = {"version": "3.0"}
    if spec_version is not None:
        asgi["spec_version"] = spec_version
    return {
        "type": "http",
        "asgi": asgi,
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": path,
        "raw_path": path.encode() if raw_path is None else raw_path,
        "query_string": b"",
        "headers": list(headers),
        "client": ("203.0.113.7", 1234),
        "server": ("testserver", 443),
        "root_path": root_path,
        "app": app,
    }


async def drive(
    app: ASGIApp,
    scope: Scope,
    *,
    body_chunks: Sequence[bytes] | None = None,
    start_send: StartSend = StartSend.PLAIN,
) -> tuple[list[Message], BaseException | None]:
    sent: list[Message] = []
    start_entered, excess_handed, response_complete = anyio.Event(), anyio.Event(), anyio.Event()
    pending = list(body_chunks or ())

    async def receive() -> Message:
        if body_chunks is None:
            return await no_receive()
        if pending:
            if start_send is not StartSend.PLAIN:
                await start_entered.wait()
            chunk = pending.pop(0)
            if not pending:
                excess_handed.set()
            return {"type": "http.request", "body": chunk, "more_body": bool(pending)}
        await response_complete.wait()
        return await no_receive()

    async def record(message: Message) -> None:
        is_start = message["type"] == "http.response.start"
        if is_start and start_send is not StartSend.PLAIN:
            start_entered.set()
            if start_send is StartSend.HELD_PAST_THE_DEADLINE:
                await anyio.sleep(DRIVE_DEADLINE_SECONDS)
            if start_send is StartSend.SUSPENDED_BEFORE_ACCEPTING:
                await _until_excess_is_handled(excess_handed)
        sent.append(message)
        if completed([message]):
            response_complete.set()
        if is_start and start_send is StartSend.SUSPENDED_AFTER_ACCEPTING:
            await _until_excess_is_handled(excess_handed)

    raised: BaseException | None = None
    with anyio.fail_after(DRIVE_DEADLINE_SECONDS):
        try:
            await app(scope, receive, record)
        except Exception as error:  # noqa: BLE001
            raised = error
    return sent, raised


async def _until_excess_is_handled(excess_handed: anyio.Event) -> None:
    await excess_handed.wait()
    await anyio.wait_all_tasks_blocked()


def a_signed_in_same_origin_request(config: WebAuthConfig) -> list[tuple[bytes, bytes]]:
    cookie = f"{config.session_cookie_name}={sign_session_id(SESSION_ID, config.signing_key)}"
    return [(b"sec-fetch-site", b"same-origin"), (b"cookie", cookie.encode())]


def starts(messages: list[Message]) -> list[Message]:
    return [message for message in messages if message["type"] == "http.response.start"]


def completed(messages: list[Message]) -> bool:
    return any(
        message["type"] == "http.response.body" and not message.get("more_body", False)
        for message in messages
    )


def body_of(messages: list[Message]) -> bytes:
    return b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
