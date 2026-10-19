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
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import count
from threading import RLock
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
    MIN_SESSION_SECRET_CHARS,
    WebAuthConfig,
    install_web_auth_config,
    web_auth_config,
)
from webauth.cookies import generate_csrf_token, sign_session_id
from webauth.dependencies import (
    AuthenticatedUser,
    LoginRedirect,
    WebSocketRefusal,
    authenticate_websocket,
    current_user_dependency,
    session_id_from_request,
    unauthenticated_response,
)
from webauth.liveness import ExpiryColumnLiveness, IdleWindowLiveness
from webauth.middleware import IpRateLimitMiddleware
from webauth.middleware.security_headers import (
    CONTENT_TYPE_OPTIONS,
    FRAME_OPTIONS,
    REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY,
)
from webauth.policies import (
    RateLimitBudget,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import (
    AccountEvent,
    RateLimitBackend,
    SessionIdentityChanged,
    SessionRecordStore,
    UsernameTakenError,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend
from webauth.session_administration import SessionAdministration
from webauth.session_ending import end_session

TRUSTED_PROXY_NETWORK = "172.16.0.0/12"
ALLOWED_HOST = "songmaker.example"
ALLOWED_ORIGIN = f"https://{ALLOWED_HOST}"
# The suite reaches its applications over https, as production does, so the
# cookie and header flags under test are the ones a deployment really sends.
HTTPS_TEST_SERVER = "https://testserver"
SESSION_ID = "session-1"
CLIENT_ADDRESS = "testclient"
CLIENT_USER_AGENT = "TestBrowser/1.0"
ADMIN_ROLE = "admin"
MEMBER_ROLE = "user"
SPEC_WITH_CONCURRENT_READER = "2.3"
SPEC_WITHOUT_CONCURRENT_READER = "2.4"
SESSION_MAX_AGE_SECONDS = 3600
SESSION_ABSOLUTE_MAX_AGE_SECONDS = 86400
IDLE_WINDOW_SECONDS = 1800
DOCUMENTED_ID_TOKEN_HINT_BOUND = 3_072
SEVEN_DAYS_SECONDS = 7 * 24 * 3600
THIRTY_DAYS_SECONDS = 30 * 24 * 3600


if TYPE_CHECKING:
    from starlette.testclient import WebSocketTestSession
    from starlette.types import ASGIApp, Message, Scope

DRIVE_DEADLINE_SECONDS: Final = 5



def web_auth_config_arguments() -> dict[str, object]:
    """Every argument a complete configuration is built from."""
    return {
        "session_secret": SecretStr("s" * MIN_SESSION_SECRET_CHARS),
        "trusted_proxies": TrustedProxies.parse(TRUSTED_PROXY_NETWORK),
        "rate_limits": SingleProcessRateLimitBackend(),
        "allowed_hosts_exact": frozenset({ALLOWED_HOST}),
        "allowed_hosts_patterns": (re.compile(r"^[^:]+\.example(:\d+)?$"),),
        "cookie_max_age_seconds": SESSION_MAX_AGE_SECONDS,
        "session_liveness": ExpiryColumnLiveness(SESSION_ABSOLUTE_MAX_AGE_SECONDS),
    }


def a_web_auth_config(**overrides: object) -> WebAuthConfig:
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


def signed_like_release_0_14(session_id: str, secret: bytes) -> str:
    """``session_id`` signed bare, the way 0.14.x and earlier issued session cookies."""
    return f"{session_id}.{hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest()}"


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
    **config_overrides: object,
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
    **config_overrides: object,
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
    is_active: bool = True


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

    def get_by_username(self, username: str) -> FakeUser | None:
        return self._usernames.get(username)

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
    """A store whose unique index ignores case, while its lookup does not."""

    def create_for_subject(self, subject: str, username: str, role: str) -> FakeUser:
        if any(user.username.casefold() == username.casefold() for user in self.list()):
            raise UsernameTakenError("Username is already taken")
        return super().create_for_subject(subject, username, role)


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
    ip_address: str = CLIENT_ADDRESS
    user_agent: str = CLIENT_USER_AGENT

    @property
    def user_id(self) -> str:
        return self.user.id


class SessionRecordsInMemory:
    """Stored sessions, renewed in place and never committed.

    The expiry-column store owns its max age and computes the new expiry from
    the ``now`` the caller passes, so no clock is read outside ``dependencies``.
    """

    def __init__(
        self,
        record: FakeSessionRecord | None = None,
        max_age_seconds: int = SESSION_MAX_AGE_SECONDS,
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
        self.max_age_seconds = max_age_seconds
        self.commit_failure: Exception | None = None

    @property
    def record(self) -> FakeSessionRecord | None:
        return next(iter(self._records.values()), None)

    def create(
        self,
        user_id: str,
        expires_at: datetime,
        *,
        ip_address: str,
        user_agent: str,
    ) -> FakeSessionRecord:
        _require_held_lock(self._lock)
        user = self._users.get(user_id)
        if user is None:
            raise UnknownAccountError("Account does not exist")
        session_id = f"session-{next(self._ids)}"
        while session_id in self._records:
            session_id = f"session-{next(self._ids)}"
        record = FakeSessionRecord(
            id=session_id,
            user=user,
            created_at=expires_at - timedelta(seconds=self.max_age_seconds),
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self._records[record.id] = record
        return record

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """The host's transaction: leaving the block commits unless ``commit_failure``
        is set, and an exception rolls back."""
        committed = dict(self._records)
        try:
            yield
            if self.commit_failure is not None:
                raise self.commit_failure
        except BaseException:
            self._records = committed
            raise

    def load(self, session_id: str) -> FakeSessionRecord | None:
        return self._records.get(session_id)

    def touch(
        self,
        record: FakeSessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> bool:
        if record.id not in self._records:
            return False
        record.ip_address = ip_address
        record.user_agent = user_agent
        record.expires_at = now + timedelta(seconds=self.max_age_seconds)
        return True


    def delete(self, session_id: str) -> None:
        _require_held_lock(self._lock)
        self._remove_record(session_id)

    def _remove_record(self, session_id: str) -> None:
        self._records.pop(session_id, None)

    def delete_for_user(self, user_id: str) -> int:
        session_ids = [
            record.id for record in self._records.values() if record.user_id == user_id
        ]
        for session_id in session_ids:
            self._remove_record(session_id)
        return len(session_ids)

    def list_active(
        self, *, offset: int = 0, limit: int | None = None,
    ) -> list[FakeSessionRecord]:
        records = list(self._records.values())
        return records[offset:None if limit is None else offset + limit]

    def count_active(self) -> int:
        return len(self._records)

    def prune_overflow(self, user_id: str, max_sessions: int) -> list[str]:
        _require_held_lock(self._lock)
        records = sorted(
            (record for record in self._records.values() if record.user_id == user_id),
            key=lambda record: record.created_at,
            reverse=True,
        )
        removed = [record.id for record in records[max_sessions:]]
        for session_id in removed:
            self._remove_record(session_id)
        return removed


@dataclass
class IdleSessionRecord:
    """A session an idle-window store keeps: identity, origin, and when last seen.

    It has no ``created_at``/``expires_at``; liveness is ``last_seen`` alone.
    """

    id: str
    user: FakeUser
    last_seen: datetime
    ip_address: str = CLIENT_ADDRESS
    user_agent: str = CLIENT_USER_AGENT

    @property
    def user_id(self) -> str:
        return self.user.id


@dataclass
class IdleSessionsInMemory:
    """The one idle-window session; a touch puts ``last_seen`` at ``now``."""

    record: IdleSessionRecord | None

    def load(self, session_id: str) -> IdleSessionRecord | None:
        if self.record is None or self.record.id != session_id:
            return None
        return self.record

    def touch(
        self,
        record: IdleSessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> bool:
        if self.record is None or self.record.id != record.id:
            return False
        record.last_seen = now
        return True


class SessionsEndedBetweenLoadAndTouch(SessionRecordsInMemory):
    """A store whose session is ended by another request right after ``load`` reads it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        record = super().load(session_id)
        if record is not None:
            end_session(self, session_id=session_id)
        return record


class SessionsReusingEndedIds(SessionRecordsInMemory):
    """A store whose ids restart from the first one, so a replaced session's id comes back."""

    def create(
        self,
        user_id: str,
        expires_at: datetime,
        *,
        ip_address: str,
        user_agent: str,
    ) -> FakeSessionRecord:
        self._ids = count(1)
        return super().create(
            user_id, expires_at, ip_address=ip_address, user_agent=user_agent,
        )


class SessionsThatMustNotBeAsked(SessionRecordsInMemory):
    """A store that fails the test on the first question put to it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        raise AssertionError("the store was asked to load a session")

    def touch(
        self,
        record: FakeSessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
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
        record: FakeSessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> bool:
        return self.touch_answer


@dataclass
class RecordingAuditSink:
    events: list[SessionIdentityChanged] = field(default_factory=list)
    account_events: list[AccountEvent] = field(default_factory=list)

    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        self.events.append(event)

    def account_event(self, event: AccountEvent) -> None:
        self.account_events.append(event)


def a_session_administration(*users: FakeUser, config: WebAuthConfig) -> SessionAdministration:
    lock = WriteLockInMemory()
    return SessionAdministration(
        sessions=SessionRecordsInMemory(users=UsersInMemory(*users, lock=lock), lock=lock),
        audit=RecordingAuditSink(),
        lock=lock,
        config=config,
    )


WEBSOCKET_PATH = "/ws"
WEBSOCKET_DEPENDENCY_PATH = "/ws-dependency"
POLICY_VIOLATION_CLOSE_CODE = 1008


@dataclass
class AuthApp:
    """A minimal application serving the routes the dependencies protect."""

    client: TestClient
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    authenticated: list[AuthenticatedUser]
    websocket_outcomes: list[AuthenticatedUser | WebSocketRefusal]
    signing_key: bytes

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
    user_id: str, expires_at: datetime,
) -> FakeSessionRecord:
    """A stored session of ``user_id``, created the way a host does: under its write lock."""
    with hold:
        return sessions.create(
            user_id, expires_at, ip_address=CLIENT_ADDRESS, user_agent=CLIENT_USER_AGENT,
        )


def a_session(
    *,
    age: timedelta = timedelta(minutes=5),
    remaining: timedelta = timedelta(minutes=30),
    user: FakeUser | None = None,
    ip_address: str = CLIENT_ADDRESS,
    user_agent: str = CLIENT_USER_AGENT,
) -> FakeSessionRecord:
    now = datetime.now(UTC)
    return FakeSessionRecord(
        id=SESSION_ID,
        user=user or FakeUser(),
        created_at=now - age,
        expires_at=now + remaining,
        ip_address=ip_address,
        user_agent=user_agent,
    )


UNAUTHENTICATED_RESPONSE_PATH = "/unauthenticated-response"


def _add_websocket_routes(
    app: FastAPI,
    sessions: SessionRecordStore,
    audit: RecordingAuditSink,
    outcomes: list[AuthenticatedUser | WebSocketRefusal],
) -> None:
    """The host recipe: authenticate in a worker and a finished transaction, then accept.

    ``WEBSOCKET_PATH`` answers every message by authenticating again;
    ``WEBSOCKET_DEPENDENCY_PATH`` wraps the helper in a dependency.
    """
    transaction = (
        sessions.transaction if isinstance(sessions, SessionRecordsInMemory) else nullcontext
    )

    def authenticate(connection: HTTPConnection) -> AuthenticatedUser | WebSocketRefusal:
        with transaction():
            outcome = authenticate_websocket(connection, sessions=sessions, audit=audit)
        outcomes.append(outcome)
        return outcome

    @app.websocket(WEBSOCKET_PATH)
    async def watched(websocket: WebSocket) -> None:
        outcome = await run_in_threadpool(authenticate, websocket)
        if isinstance(outcome, WebSocketRefusal):
            await websocket.close(code=POLICY_VIOLATION_CLOSE_CODE)
            return
        await websocket.accept()
        session_id = session_id_from_request(websocket, web_auth_config(websocket))
        await websocket.send_json({"username": outcome.username, "session_id": session_id})
        try:
            while True:
                await websocket.receive_text()
                outcome = await run_in_threadpool(authenticate, websocket)
                if isinstance(outcome, WebSocketRefusal):
                    await websocket.close(code=POLICY_VIOLATION_CLOSE_CODE)
                    return
                await websocket.send_json({"username": outcome.username})
        except WebSocketDisconnect:
            return

    @app.websocket(WEBSOCKET_DEPENDENCY_PATH)
    async def through_a_dependency(
        websocket: WebSocket,
        outcome: AuthenticatedUser | WebSocketRefusal = Depends(authenticate),
    ) -> None:
        if isinstance(outcome, WebSocketRefusal):
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
    **config_overrides: object,
) -> AuthApp:
    """An application serving one protected, one admin, one session-id route.

    It also serves the two WebSocket routes of ``_add_websocket_routes``; a
    keyword replaces the configuration field it names.

    ``UNAUTHENTICATED_RESPONSE_PATH`` answers with ``unauthenticated_response``
    called directly, over the same ``login_redirect``, so a test can compare
    it against a dependency-guarded route for the same request.
    """
    config = a_web_auth_config(admin_role=ADMIN_ROLE, **config_overrides)
    if sessions is None:
        sessions = SessionRecordsInMemory(record)
    audit = RecordingAuditSink()
    authenticated: list[AuthenticatedUser] = []
    websocket_outcomes: list[AuthenticatedUser | WebSocketRefusal] = []

    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        audit_sink=lambda: audit,
        on_authenticated=authenticated.append,
        login_redirect=login_redirect,
    )

    app = FastAPI()
    install_web_auth_config(app, config)

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username, "role": user.role}

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

    _add_websocket_routes(app, sessions, audit, websocket_outcomes)

    return AuthApp(
        client=TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            cookies={},
            headers={"user-agent": CLIENT_USER_AGENT},
        ),
        sessions=sessions,
        audit=audit,
        authenticated=authenticated,
        websocket_outcomes=websocket_outcomes,
        signing_key=config.signing_key,
    )


def an_idle_session(
    *, seen_ago: timedelta = timedelta(minutes=5), user: FakeUser | None = None,
) -> IdleSessionRecord:
    return IdleSessionRecord(
        id=SESSION_ID, user=user or FakeUser(), last_seen=datetime.now(UTC) - seen_ago,
    )


def an_idle_auth_app(record: IdleSessionRecord | None) -> AuthApp:
    """The supported idle-window liveness config."""
    config = a_web_auth_config(
        admin_role=ADMIN_ROLE, session_liveness=IdleWindowLiveness(IDLE_WINDOW_SECONDS),
    )
    sessions = IdleSessionsInMemory(record)
    audit = RecordingAuditSink()
    authenticated: list[AuthenticatedUser] = []
    websocket_outcomes: list[AuthenticatedUser | WebSocketRefusal] = []

    dependencies = current_user_dependency(
        session_store=lambda: sessions,
        audit_sink=lambda: audit,
        on_authenticated=authenticated.append,
    )

    app = FastAPI()
    install_web_auth_config(app, config)

    @app.get("/me")
    def me(user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {"username": user.username, "role": user.role}

    _add_websocket_routes(app, sessions, audit, websocket_outcomes)

    return AuthApp(
        client=TestClient(
            app,
            base_url=HTTPS_TEST_SERVER,
            cookies={},
            headers={"user-agent": CLIENT_USER_AGENT},
        ),
        sessions=sessions,
        audit=audit,
        authenticated=authenticated,
        websocket_outcomes=websocket_outcomes,
        signing_key=config.signing_key,
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
) -> Scope:
    asgi = {"version": "3.0"}
    if spec_version is not None:
        asgi["spec_version"] = spec_version
    return {
        "type": "http", "asgi": asgi, "http_version": "1.1", "method": method,
        "scheme": "https", "path": path, "raw_path": path.encode(), "query_string": b"",
        "headers": list(headers), "client": ("203.0.113.7", 1234), "server": ("testserver", 443),
        "root_path": "", "app": app,
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
    token = generate_csrf_token(SESSION_ID, config.signing_key)
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
