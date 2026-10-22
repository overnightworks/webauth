"""Shared arrangement for the webauth suites.

A plain builder rather than a `conftest.py`: pytest puts every test directory
on `sys.path`, so a second `conftest` module here would shadow the repository
one that the rest of the suite imports `TEST_SECRET` and its factories from.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from itertools import count
from threading import RLock, get_ident
from typing import TYPE_CHECKING, Any, Final

import anyio
from fastapi import Depends, FastAPI, Request, WebSocket
from fastapi.testclient import TestClient
from httpx import Headers as HttpxHeaders
from httpx import Response as HttpxResponse
from pydantic import SecretStr
from starlette.concurrency import run_in_threadpool
from starlette.requests import HTTPConnection
from starlette.responses import Response
from starlette.websockets import WebSocketDisconnect

from webauth.config import (
    SessionLifetime,
    WebAuthConfig,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import _generate_csrf_token, sign_session_id
from webauth.dependencies import (
    ConnectionRefusal,
    LoginRedirect,
    authenticate_websocket,
    current_user_dependency,
    session_id_from_request,
    unauthenticated_response,
)
from webauth.middleware import (
    IpRateLimitMiddleware,
    SessionGate,
    admitted_user,
    install_web_auth_middleware,
)
from webauth.middleware.security_headers import (
    CONTENT_TYPE_OPTIONS,
    FRAME_OPTIONS,
    REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY,
)
from webauth.policies import (
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import (
    AccountEvent,
    AuthenticatedUser,
    RateLimitBackend,
    SessionRecordStore,
    SessionTransaction,
    UsernameTakenError,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend

TRUSTED_PROXY_NETWORK = "172.16.0.0/12"
ALLOWED_HOST = "notes.example"
ALLOWED_ORIGIN = f"https://{ALLOWED_HOST}"
# The suite reaches its applications over https, as production does, so the
# cookie and header flags under test are the ones a deployment really sends.
HTTPS_TEST_SERVER = "https://testserver"
MIN_SESSION_SECRET_CHARS = 32
SESSION_ID = "session-1"
CLIENT_ADDRESS = "testclient"
ADMIN_ROLE = "admin"
MEMBER_ROLE = "user"
SPEC_WITH_CONCURRENT_READER = "2.3"
SPEC_WITHOUT_CONCURRENT_READER = "2.4"
SESSION_IDLE_SECONDS = 3600
SESSION_ABSOLUTE_MAX_AGE_SECONDS = 86400
DOCUMENTED_ID_TOKEN_HINT_BOUND = 3_072
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
        "allowed_hosts_patterns": (re.compile(r"^[^:]+\.example(:\d+)?$"),),
        "session_lifetime": SessionLifetime(
            idle_seconds=SESSION_IDLE_SECONDS,
            absolute_max_age_seconds=SESSION_ABSOLUTE_MAX_AGE_SECONDS,
        ),
    }


def a_web_auth_config(**overrides: Any) -> WebAuthConfig:
    """A complete configuration; a keyword replaces the field it names."""
    return WebAuthConfig(**{**web_auth_config_arguments(), **overrides})


SESSION_COOKIE_NAME = a_web_auth_config().session_cookie_name


def assert_carries_policy_headers(
    headers: Mapping[str, str], policy: SecurityHeadersPolicy, *, hsts: bool,
) -> None:
    """Every header ``policy`` puts on a response is there; HSTS only when ``hsts``."""
    expected = {
        "x-content-type-options": CONTENT_TYPE_OPTIONS,
        "x-frame-options": FRAME_OPTIONS,
        "content-security-policy": policy.content_security_policy,
        "referrer-policy": REFERRER_POLICY,
        "permissions-policy": policy.permissions_policy,
    }
    if hsts:
        expected["strict-transport-security"] = STRICT_TRANSPORT_SECURITY
    carried = {name: headers.get(name) for name in (*expected, "strict-transport-security")}
    assert carried == {"strict-transport-security": None, **expected}


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


class AlwaysFailingRateLimitBackend:
    """A backend that can never answer, to prove the middleware fails closed."""

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        raise ConnectionError("rate limiter down")


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
    install_web_auth_config(
        app, a_web_auth_config(rate_limits=rate_limits, **config_overrides),
    )
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
class FakeUser:
    id: str = "user-1"
    username: str = "alice"
    role: str = MEMBER_ROLE


class UnknownAccountError(LookupError):
    """A session was requested for an account the arrangement does not hold."""


class LockNotHeldError(RuntimeError):
    """A store operation requires the host's write lock."""


def _require_held_lock(lock: WriteLockInMemory | None) -> None:
    if lock is not None and not lock.held:
        raise LockNotHeldError("Store operation requires a held write lock")


class UsersInMemory:
    """Accounts sharing the same mutable records as the host's session store."""

    def __init__(self, *users: FakeUser, lock: WriteLockInMemory | None = None) -> None:
        self._lock = lock
        self._users = {user.id: user for user in users}
        self._usernames = {user.username: user for user in users}

    def get(self, user_id: str) -> FakeUser | None:
        return self._users.get(user_id)

    def create_for_subject(self, subject: str, username: str, role: str) -> FakeUser:
        return self._add(FakeUser(id=subject, username=username, role=role))

    def set_role(self, user_id: str, role: str) -> FakeUser:
        _require_held_lock(self._lock)
        user = self._users[user_id]
        user.role = role
        return user

    def _add(self, user: FakeUser) -> FakeUser:
        _require_held_lock(self._lock)
        if user.username in self._usernames:
            raise UsernameTakenError("Username is already taken")
        self._users[user.id] = user
        self._usernames[user.username] = user
        return user

    def list(self) -> list[FakeUser]:
        return list(self._users.values())


class UsersWithCaseInsensitiveUsernames(UsersInMemory):
    """A store whose unique index ignores case."""

    def create_for_subject(self, subject: str, username: str, role: str) -> FakeUser:
        if any(user.username.casefold() == username.casefold() for user in self.list()):
            raise UsernameTakenError("Username is already taken")
        return super().create_for_subject(subject, username, role)


class UsersWithoutUniqueUsernames(UsersInMemory):
    """A store with no unique index on the username."""

    def create_for_subject(self, subject: str, username: str, role: str) -> FakeUser:
        _require_held_lock(self._lock)
        user = FakeUser(id=subject, username=username, role=role)
        self._users[subject] = user
        return user


@dataclass
class WriteLockInMemory:
    _lock: RLock = field(default_factory=RLock)
    _hold_depth: int = field(default=0, init=False)

    @property
    def held(self) -> bool:
        return self._hold_depth > 0

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self._lock:
            self._hold_depth += 1
            try:
                yield
            finally:
                self._hold_depth -= 1


@dataclass
class FakeSessionRecord:
    id: str
    user: FakeUser
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None = None
    id_token: SecretStr | None = None


class SessionRecordsInMemory:
    """Stored sessions, renewed in place and never committed.

    ``create`` and ``touch`` write the instants they are given.
    """

    def __init__(
        self,
        record: FakeSessionRecord | None = None,
        *,
        users: UsersInMemory | None = None,
        lock: WriteLockInMemory | None = None,
    ) -> None:
        self._lock = lock
        self._records = {} if record is None else {record.id: record}
        self._users = users if users is not None else UsersInMemory(
            *(() if record is None else (record.user,)),
        )
        self._ids = count(1)
        self.commit_failure: Exception | None = None

    @property
    def record(self) -> FakeSessionRecord | None:
        return next(iter(self._records.values()), None)

    def create(
        self,
        user_id: str,
        *,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None = None,
    ) -> FakeSessionRecord:
        _require_held_lock(self._lock)
        user = self._users.get(user_id)
        if user is None:
            raise UnknownAccountError("Account does not exist")
        session_id = f"session-{next(self._ids)}"
        while session_id in self._records:
            session_id = f"session-{next(self._ids)}"
        record = FakeSessionRecord(
            session_id, user, now, expires_at, refresh_token, id_token,
        )
        self._records[record.id] = record
        return record

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """The host's transaction: leaving the block commits unless ``commit_failure``
        is set, and an exception rolls back."""
        committed = {session_id: replace(record) for session_id, record in self._records.items()}
        try:
            yield
            if self.commit_failure is not None:
                raise self.commit_failure
        except BaseException:
            self._records = committed
            raise

    def in_transaction(self) -> AbstractContextManager[SessionRecordStore]:
        """The store inside its ``transaction``: a ``SessionTransaction`` provider."""
        return self._store_in_transaction()

    @contextmanager
    def _store_in_transaction(self) -> Iterator[SessionRecordStore]:
        with self.transaction():
            yield self

    def load(self, session_id: str) -> FakeSessionRecord | None:
        return self._records.get(session_id)

    def touch(
        self,
        session_id: str,
        *,
        expires_at: datetime,
    ) -> bool:
        record = self._records.get(session_id)
        if record is None:
            return False
        record.expires_at = expires_at
        return True

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        record = self._records.get(session_id)
        if record is None:
            return False
        record.refresh_token = refresh_token
        return True

    def delete(self, session_id: str) -> None:
        _require_held_lock(self._lock)
        self._remove_record(session_id)

    def _remove_record(self, session_id: str) -> None:
        self._records.pop(session_id, None)

    def delete_for_user(self, user_id: str) -> int:
        sessions = self.sessions_of(user_id)
        for record in sessions:
            self._remove_record(record.id)
        return len(sessions)

    def sessions_of(self, user_id: str) -> list[FakeSessionRecord]:
        return [record for record in self._records.values() if record.user.id == user_id]

    def list_active(self) -> list[FakeSessionRecord]:
        return list(self._records.values())

    def count_active(self) -> int:
        return len(self._records)

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        _require_held_lock(self._lock)
        records = sorted(
            self.sessions_of(user_id),
            key=lambda record: record.created_at,
            reverse=True,
        )
        for record in records[keep_newest:]:
            self._remove_record(record.id)


class SessionsRecordingTheirTransaction(SessionRecordsInMemory):
    """A store that records, with the thread each ran on, the factory call (``open``),
    ``load``, ``touch``, ``replace``, a clean exit (``commit``) and an exit by exception
    (``rollback``)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.events: list[tuple[str, int]] = []

    @property
    def event_names(self) -> list[str]:
        return [name for name, _thread in self.events]

    @property
    def threads(self) -> set[int]:
        return {thread for _name, thread in self.events}

    def in_transaction(self) -> AbstractContextManager[SessionRecordStore]:
        self.events.append(("open", get_ident()))
        return self._recorded_transaction()

    @contextmanager
    def _recorded_transaction(self) -> Iterator[SessionRecordStore]:
        try:
            with super().in_transaction() as store:
                yield store
        except BaseException:
            self.events.append(("rollback", get_ident()))
            raise
        self.events.append(("commit", get_ident()))

    def load(self, session_id: str) -> FakeSessionRecord | None:
        self.events.append(("load", get_ident()))
        return super().load(session_id)

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        self.events.append(("touch", get_ident()))
        return super().touch(session_id, expires_at=expires_at)

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        self.events.append(("replace", get_ident()))
        return super().replace_refresh_token(session_id, refresh_token=refresh_token)


class SessionsFailingToLoad(SessionRecordsInMemory):
    """A store whose ``load`` raises while ``failing``, as a database that went away does."""

    failing = True

    def load(self, session_id: str) -> FakeSessionRecord | None:
        if self.failing:
            raise ConnectionError("session store down")
        return super().load(session_id)


class SessionsEndedBetweenLoadAndTouch(SessionRecordsInMemory):
    """A store whose session is ended by another request right after ``load`` reads it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        record = super().load(session_id)
        if record is not None:
            self.delete(session_id)
        return record


class SessionsEndedBeforeReplacingTheRefreshToken(SessionRecordsInMemory):
    """A store whose session is ended by another request right before the replace lands."""

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        self._remove_record(session_id)
        return super().replace_refresh_token(session_id, refresh_token=refresh_token)


class SessionsThatMustNotBeAsked(SessionRecordsInMemory):
    """A store that fails the test on the first question put to it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        raise AssertionError("the store was asked to load a session")

    def touch(
        self,
        session_id: str,
        *,
        expires_at: datetime,
    ) -> bool:
        raise AssertionError("the store was asked to touch a session")

    def delete(self, session_id: str) -> None:
        raise AssertionError("the store was asked to delete a session")


class SessionsAnsweringTouch(SessionRecordsInMemory):
    """A store whose ``touch`` writes nothing and gives a fixed answer."""

    def __init__(self, record: FakeSessionRecord, touch_answer: Any) -> None:
        super().__init__(record)
        self.touch_answer = touch_answer

    def touch(
        self,
        session_id: str,
        *,
        expires_at: datetime,
    ) -> bool:
        return self.touch_answer


class SessionsAnsweringReplace(SessionRecordsInMemory):
    """A store whose ``replace_refresh_token`` writes nothing and gives a fixed answer."""

    def __init__(self, record: FakeSessionRecord, replace_answer: Any) -> None:
        super().__init__(record)
        self.replace_answer = replace_answer

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return self.replace_answer


@dataclass
class RecordingAuditSink:
    account_events: list[AccountEvent] = field(default_factory=list)

    def account_event(self, event: AccountEvent) -> None:
        self.account_events.append(event)


WEBSOCKET_PATH = "/ws"
WEBSOCKET_ADMITTED_PATH = "/ws-admitted"
OPEN_PATHS = ("/health", "/login", "/hooks/x", "/static/x.css", "/optional")
ALL_DEPENDENCIES_PATH = "/all"
GATED_APP_HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
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

    def get(
        self, path: str, *, cookie: str | None = None, accept: str | None = None,
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
            sent.append(("cookie", f"{SESSION_COOKIE_NAME}={cookie}"))
        if origin is not None:
            sent.append(("origin", origin))
        return self.client.websocket_connect(path, headers=HttpxHeaders(sent))

    def signed_cookie(self, session_id: str = SESSION_ID) -> str:
        return sign_session_id(session_id, self.signing_key)


def seeded_session(
    sessions: SessionRecordsInMemory, hold: AbstractContextManager[None],
    user_id: str, now: datetime, expires_at: datetime, refresh_token: SecretStr | None = None,
) -> FakeSessionRecord:
    """A stored session of ``user_id``, created the way a host does: under its write lock."""
    with hold:
        return sessions.create(
            user_id,
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
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


UNAUTHENTICATED_RESPONSE_PATH = "/unauthenticated-response"


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

    It also serves the WebSocket routes of ``_add_websocket_routes`` and, at
    ``OPEN_PATHS``, a route that reads ``admitted_user``. A keyword replaces
    the configuration field it names; ``config`` is an existing instance
    instead (no overrides then). ``gate`` installs the library middleware with
    a ``SessionGate`` over ``public`` and ``optional``, its transaction
    ``session_transaction`` or else the store's ``in_transaction``;
    ``stack_policies`` adds the other policies the installer takes, or replaces
    the headers.

    ``UNAUTHENTICATED_RESPONSE_PATH`` answers with ``unauthenticated_response``
    called directly, over the same ``login_redirect``, so a test can compare
    it against a dependency-guarded route for the same request.
    """
    if config is None:
        config = a_web_auth_config(admin_role=ADMIN_ROLE, **config_overrides)
    if sessions is None:
        sessions = SessionRecordsInMemory(record)
    authenticated: list[AuthenticatedUser] = []
    websocket_outcomes: list[AuthenticatedUser | ConnectionRefusal] = []

    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        on_authenticated=authenticated.append,
        login_redirect=login_redirect,
    )

    route_runs: list[str] = []
    route_threads: list[int] = []

    app = FastAPI(root_path=root_path)
    install_web_auth_config(app, config)
    if gate:
        install_web_auth_middleware(
            app,
            **{"security_headers": GATED_APP_HEADERS_POLICY, **(stack_policies or {})},
            session_gate=SessionGate(
                session_transaction=session_transaction or sessions.in_transaction,
                login_redirect=login_redirect,
                public=public,
                optional=optional or PathRules(),
            ),
        )

    @app.get("/me")
    def me(
        request: Request, user: AuthenticatedUser = Depends(dependencies.current_user),
    ) -> dict[str, str]:
        route_runs.append(request.url.path)
        return {"username": user.username, "role": user.role}

    @app.get(ALL_DEPENDENCIES_PATH)
    def all_dependencies(
        user: AuthenticatedUser = Depends(dependencies.current_user),
        admin: AuthenticatedUser = Depends(dependencies.admin_user),
        verified: str = Depends(dependencies.verified_session_id),
    ) -> dict[str, str]:
        return {"username": user.username, "admin": admin.username, "session_id": verified}

    async def reading_admission(request: Request) -> dict[str, str | None]:
        route_runs.append(request.url.path)
        route_threads.append(get_ident())
        if isinstance(sessions, SessionsRecordingTheirTransaction):
            sessions.events.append(("route", get_ident()))
        user = admitted_user(request)
        return {"username": None if user is None else user.username}

    for path in OPEN_PATHS:
        app.add_api_route(
            path, reading_admission, methods=["GET", "POST", "HEAD", "OPTIONS"],
        )

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get("/session-id")
    def session_id(
        verified: str = Depends(dependencies.verified_session_id),
    ) -> dict[str, str]:
        return {"session_id": verified}

    @app.get(UNAUTHENTICATED_RESPONSE_PATH)
    def unauthenticated(request: Request) -> Response:
        return unauthenticated_response(request, login_redirect)

    _add_websocket_routes(app, sessions, websocket_outcomes)

    return AuthApp(
        client=TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            cookies={},
            raise_server_exceptions=raise_server_exceptions,
        ),
        sessions=sessions,
        authenticated=authenticated,
        websocket_outcomes=websocket_outcomes,
        signing_key=config.signing_key,
        app=app,
        config=config,
        route_runs=route_runs,
        route_threads=route_threads,
    )


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
        "type": "http", "asgi": asgi, "http_version": "1.1", "method": method,
        "scheme": "https", "path": path,
        "raw_path": path.encode() if raw_path is None else raw_path, "query_string": b"",
        "headers": list(headers), "client": ("203.0.113.7", 1234), "server": ("testserver", 443),
        "root_path": root_path, "app": app,
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


def a_csrf_passing_request_headers(config: WebAuthConfig) -> list[tuple[bytes, bytes]]:
    cookie = f"{config.session_cookie_name}={sign_session_id(SESSION_ID, config.signing_key)}"
    token = _generate_csrf_token(SESSION_ID, config.signing_key)
    return [
        (b"sec-fetch-site", b"same-origin"),
        (b"cookie", cookie.encode()),
        (config.csrf_header_name.encode(), token.encode()),
    ]


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
