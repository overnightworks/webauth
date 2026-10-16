"""Shared arrangement for the webauth suites.

A plain builder rather than a `conftest.py`: pytest puts every test directory
on `sys.path`, so a second `conftest` module here would shadow the repository
one that the rest of the suite imports `TEST_SECRET` and its factories from.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from itertools import count
from threading import RLock
from typing import Any

from argon2.profiles import CHEAPEST
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient
from httpx import Response as HttpxResponse
from pydantic import SecretStr
from starlette.responses import Response

from webauth.config import (
    MIN_SESSION_SECRET_CHARS,
    WebAuthConfig,
    install_web_auth_config,
)
from webauth.cookies import sign_session_id
from webauth.dependencies import (
    AuthenticatedUser,
    LoginRedirect,
    current_user_dependency,
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
from webauth.passwords import Argon2idPasswordHasher
from webauth.policies import (
    PathRules,
    RateLimitBudget,
    RateLimitClass,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)
from webauth.ports import (
    RateLimitBackend,
    SessionIdentityChanged,
    UnknownUserError,
    UserManagementEvent,
    UsernameTakenError,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend
from webauth.session_ending import end_session
from webauth.users import UserManagement

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
SESSION_MAX_AGE_SECONDS = 3600
SESSION_ABSOLUTE_MAX_AGE_SECONDS = 86400
IDLE_WINDOW_SECONDS = 1800
SEVEN_DAYS_SECONDS = 7 * 24 * 3600
THIRTY_DAYS_SECONDS = 30 * 24 * 3600


def a_cheap_argon2id_hasher() -> Argon2idPasswordHasher:
    """The real Argon2id hasher at argon2-cffi's cheapest costs, so tests stay fast."""
    return Argon2idPasswordHasher(CHEAPEST)


def a_web_auth_config(**overrides: object) -> WebAuthConfig:
    """A complete configuration; a keyword replaces the field it names."""
    defaults = {
        "session_secret": SecretStr("s" * MIN_SESSION_SECRET_CHARS),
        "trusted_proxies": TrustedProxies.parse(TRUSTED_PROXY_NETWORK),
        "password_hasher": a_cheap_argon2id_hasher(),
        "rate_limits": SingleProcessRateLimitBackend(),
        "allowed_hosts_exact": frozenset({ALLOWED_HOST}),
        "allowed_hosts_patterns": (re.compile(r"^[^:]+\.example(:\d+)?$"),),
        "session_max_age_seconds": SESSION_MAX_AGE_SECONDS,
        "session_liveness": ExpiryColumnLiveness(SESSION_ABSOLUTE_MAX_AGE_SECONDS),
        "login_rate_limit": 5,
        "login_lockout_threshold": 15,
        "login_lockout_window_seconds": 3600,
    }
    return WebAuthConfig(**{**defaults, **overrides})


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
    signature = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def session_cookie_header(*cookie_values: str) -> str:
    """A Cookie header carrying the default session cookie once per value, in order."""
    return "; ".join(f"{SESSION_COOKIE_NAME}={value}" for value in cookie_values)


API_PATH = "/api/thing"
RATE_LIMITED_PATH = API_PATH
MEDIA_PATH = "/media/thing"
DEFAULT_RATE_WINDOW_SECONDS = 60


def _rate_limited_client(
    rate_limits: RateLimitBackend,
    policy: RateLimitPolicy,
    paths: tuple[str, ...],
    config_overrides: dict[str, object],
) -> TestClient:
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
    """A client whose every request spends one budget of ``rate_limits``.

    Every class shares one budget so the test drives the limiter through the
    real middleware regardless of how a path classifies; a keyword replaces the
    configuration field it names.
    """
    budget = RateLimitBudget(max_requests, window_seconds)
    policy = RateLimitPolicy(
        budgets={rate_limit_class: budget for rate_limit_class in RateLimitClass},
    )
    return _rate_limited_client(rate_limits, policy, (API_PATH,), config_overrides)


def a_class_split_rate_limited_client(
    rate_limits: RateLimitBackend,
    *,
    api_max_requests: int,
    media_max_requests: int,
    window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS,
) -> TestClient:
    """A client whose API and media paths spend separate budgets.

    ``MEDIA_PATH`` classifies as the media budget, ``API_PATH`` as the API one,
    so a test can prove one class's exhaustion never spends another's.
    """
    policy = RateLimitPolicy(
        budgets={
            RateLimitClass.API: RateLimitBudget(api_max_requests, window_seconds),
            RateLimitClass.MEDIA: RateLimitBudget(media_max_requests, window_seconds),
            RateLimitClass.STREAM: RateLimitBudget(media_max_requests, window_seconds),
        },
        media=PathRules(prefixes=(MEDIA_PATH,)),
    )
    return _rate_limited_client(rate_limits, policy, (API_PATH, MEDIA_PATH), {})


@dataclass
class FakeUser:
    id: str = "user-1"
    username: str = "alice"
    role: str = MEMBER_ROLE
    is_active: bool = True
    password_hash: str = "unused"


@dataclass
class PasswordlessUser:
    """An account an identity provider vouches for: its id is the issuer's subject."""

    id: str = "5f0c2a1e-subject"
    username: str = "lena"
    role: str = MEMBER_ROLE
    is_active: bool = True
    password_hash: None = None


StoredUser = FakeUser | PasswordlessUser


class LockNotHeldError(RuntimeError):
    """A store operation requires the host's write lock."""


def _require_held_lock(lock: WriteLockInMemory | None) -> None:
    if lock is not None and not lock.held:
        raise LockNotHeldError("Store operation requires a held write lock")


class UsersInMemory:
    """Accounts sharing the same mutable records as the host's session store."""

    def __init__(self, *users: StoredUser, lock: WriteLockInMemory | None = None) -> None:
        self._lock = lock
        self._users = {user.id: user for user in users}
        self._usernames = {user.username: user for user in users}
        self._ids = count(1)

    def get(self, user_id: str) -> StoredUser | None:
        return self._users.get(user_id)

    def get_by_username(self, username: str) -> StoredUser | None:
        return self._usernames.get(username)

    def count(self) -> int:
        _require_held_lock(self._lock)
        return len(self._users)

    def create(self, username: str, password_hash: str, role: str) -> FakeUser:
        user_id = f"user-{next(self._ids)}"
        while user_id in self._users:
            user_id = f"user-{next(self._ids)}"
        return self._add(FakeUser(
            id=user_id, username=username, password_hash=password_hash, role=role,
        ))

    def create_for_subject(self, subject: str, username: str, role: str) -> PasswordlessUser:
        return self._add(PasswordlessUser(id=subject, username=username, role=role))

    def _add[UserT: StoredUser](self, user: UserT) -> UserT:
        _require_held_lock(self._lock)
        if user.username in self._usernames:
            raise UsernameTakenError("Username is already taken")
        self._users[user.id] = user
        self._usernames[user.username] = user
        return user

    def list(self) -> list[StoredUser]:
        return list(self._users.values())

    def update(
        self,
        user_id: str,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        password_hash: str | None = None,
    ) -> StoredUser:
        _require_held_lock(self._lock)
        user = self.get(user_id)
        if user is None:
            raise UnknownUserError("Account does not exist")
        if role is not None:
            user.role = role
        if is_active is not None:
            user.is_active = is_active
        if password_hash is not None:
            user.password_hash = password_hash
        return user

    def count_active_admins(self, role: str) -> int:
        _require_held_lock(self._lock)
        return sum(user.is_active and user.role == role for user in self._users.values())


class UsersWithCaseInsensitiveUsernames(UsersInMemory):
    """A store whose unique index ignores case, while its lookup does not."""

    def create_for_subject(self, subject: str, username: str, role: str) -> PasswordlessUser:
        if any(user.username.casefold() == username.casefold() for user in self.list()):
            raise UsernameTakenError("Username is already taken")
        return super().create_for_subject(subject, username, role)


class UsersWithSetupRace(UsersInMemory):
    """A store exposing a second creator that escaped the host's setup lock."""

    def create(self, username: str, password_hash: str, role: str) -> FakeUser:
        user = super().create(username, password_hash, role)
        super().create("concurrent-account", "unused", role)
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
class LegibleHasher:
    """A host-supplied ``PasswordHasher`` double whose hashes are legible.

    It stands in for a host that plugs in its own algorithm: a test can inject
    it and read straight off the stored hash which password produced it.
    """

    prefix: str = "argon2"

    def hash(self, password: str) -> str:
        return f"{self.prefix}:{password}"

    def verify(self, password: str, stored_hash: str | None) -> bool:
        return stored_hash == f"{self.prefix}:{password}"


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
        user = self._users.get(user_id)
        if user is None:
            raise UnknownUserError("Account does not exist")
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
    user_management_events: list[UserManagementEvent] = field(default_factory=list)

    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        self.events.append(event)

    def user_management_event(self, event: UserManagementEvent) -> None:
        self.user_management_events.append(event)


def a_user_management(*users: StoredUser, config: WebAuthConfig) -> UserManagement:
    lock = WriteLockInMemory()
    user_store = UsersInMemory(*users, lock=lock)
    return UserManagement(
        users=user_store,
        sessions=SessionRecordsInMemory(users=user_store, lock=lock),
        audit=RecordingAuditSink(),
        lock=lock,
        config=config,
    )


@dataclass
class AuthApp:
    """A minimal application serving the routes the dependencies protect."""

    client: TestClient
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    authenticated: list[AuthenticatedUser]
    signing_key: bytes

    def get(
        self, path: str, *, cookie: str | None = None, accept: str | None = None,
    ) -> HttpxResponse:
        headers = {} if cookie is None else {"cookie": f"{SESSION_COOKIE_NAME}={cookie}"}
        if accept is not None:
            headers["accept"] = accept
        return self.client.get(path, headers=headers, follow_redirects=False)

    def signed_cookie(self, session_id: str = SESSION_ID) -> str:
        return sign_session_id(session_id, self.signing_key)


def a_session(
    *,
    age: timedelta = timedelta(minutes=5),
    remaining: timedelta = timedelta(minutes=30),
    user: FakeUser | None = None,
    ip_address: str = CLIENT_ADDRESS,
    user_agent: str = CLIENT_USER_AGENT,
) -> FakeSessionRecord:
    now = datetime.now(timezone.utc)
    return FakeSessionRecord(
        id=SESSION_ID,
        user=user or FakeUser(),
        created_at=now - age,
        expires_at=now + remaining,
        ip_address=ip_address,
        user_agent=user_agent,
    )


UNAUTHENTICATED_RESPONSE_PATH = "/unauthenticated-response"


def an_auth_app(
    record: FakeSessionRecord | None,
    *,
    login_redirect: LoginRedirect | None = None,
    sessions: SessionRecordsInMemory | None = None,
) -> AuthApp:
    """An application serving one protected, one admin, one session-id route.

    ``UNAUTHENTICATED_RESPONSE_PATH`` answers with ``unauthenticated_response``
    called directly, over the same ``login_redirect``, so a test can compare
    it against a dependency-guarded route for the same request.
    """
    config = a_web_auth_config(admin_role=ADMIN_ROLE)
    if sessions is None:
        sessions = SessionRecordsInMemory(record)
    audit = RecordingAuditSink()
    authenticated: list[AuthenticatedUser] = []

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
        signing_key=config.signing_key,
    )


def an_idle_session(
    *, seen_ago: timedelta = timedelta(minutes=5), user: FakeUser | None = None,
) -> IdleSessionRecord:
    return IdleSessionRecord(
        id=SESSION_ID, user=user or FakeUser(), last_seen=datetime.now(timezone.utc) - seen_ago,
    )


def an_idle_auth_app(record: IdleSessionRecord | None) -> AuthApp:
    """The supported presentator config: idle-window liveness."""
    config = a_web_auth_config(
        admin_role=ADMIN_ROLE, session_liveness=IdleWindowLiveness(IDLE_WINDOW_SECONDS),
    )
    sessions = IdleSessionsInMemory(record)
    audit = RecordingAuditSink()
    authenticated: list[AuthenticatedUser] = []

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
        signing_key=config.signing_key,
    )
