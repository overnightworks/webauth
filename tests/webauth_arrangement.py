"""Shared arrangement for the webauth suites.

A plain builder rather than a `conftest.py`: pytest puts every test directory
on `sys.path`, so a second `conftest` module here would shadow the repository
one that the rest of the suite imports `TEST_SECRET` and its factories from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import fakeredis
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from pydantic import SecretStr

from webauth.config import (
    MIN_SESSION_SECRET_CHARS,
    WebAuthConfig,
    install_web_auth_config,
)
from webauth.cookies import sign_session_id
from webauth.dependencies import AuthenticatedUser, current_user_dependency
from webauth.liveness import ExpiryColumnLiveness
from webauth.middleware import IpRateLimitMiddleware
from webauth.passwords import BcryptPasswordHasher
from webauth.policies import (
    PathRules,
    RateLimitBudget,
    RateLimitClass,
    RateLimitPolicy,
)
from webauth.ports import RateLimitBackend, SessionIdentityChanged
from webauth.proxies import TrustedProxies
from webauth.rate_limit import SingleProcessRateLimitBackend
from webauth.session_store import RedisSessionCache, SessionKeyPrefixes

TRUSTED_PROXY_NETWORK = "172.16.0.0/12"
SESSION_KEY_PREFIXES = SessionKeyPrefixes(
    session="app:session", user_sessions="app:user_sessions",
)
SESSION_ID = "session-1"
CLIENT_ADDRESS = "testclient"
CLIENT_USER_AGENT = "TestBrowser/1.0"
ADMIN_ROLE = "admin"
MEMBER_ROLE = "user"
SESSION_MAX_AGE_SECONDS = 3600
SESSION_ABSOLUTE_MAX_AGE_SECONDS = 86400
IDLE_WINDOW_SECONDS = 1800


def a_web_auth_config(**overrides: object) -> WebAuthConfig:
    """A complete configuration; a keyword replaces the field it names."""
    defaults = {
        "session_secret": SecretStr("s" * MIN_SESSION_SECRET_CHARS),
        "trusted_proxies": TrustedProxies.parse(TRUSTED_PROXY_NETWORK),
        "password_hasher": BcryptPasswordHasher(),
        "rate_limits": SingleProcessRateLimitBackend(),
        "session_cache": None,
        "allowed_hosts_exact": frozenset({"songmaker.example"}),
        "allowed_hosts_patterns": (re.compile(r"^[^:]+\.example(:\d+)?$"),),
        "session_max_age_seconds": SESSION_MAX_AGE_SECONDS,
        "session_liveness": ExpiryColumnLiveness(SESSION_ABSOLUTE_MAX_AGE_SECONDS),
        "login_rate_limit": 5,
        "login_lockout_threshold": 15,
        "login_lockout_window_seconds": 3600,
    }
    return WebAuthConfig(**{**defaults, **overrides})


API_PATH = "/api/thing"
RATE_LIMITED_PATH = API_PATH
MEDIA_PATH = "/media/thing"
DEFAULT_RATE_WINDOW_SECONDS = 60


def _rate_limited_client(
    rate_limits: RateLimitBackend, policy: RateLimitPolicy, paths: tuple[str, ...],
) -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config(rate_limits=rate_limits))
    app.add_middleware(IpRateLimitMiddleware, policy=policy)
    for path in paths:
        app.add_api_route(path, lambda: {"status": "ok"}, methods=["GET"])
    return TestClient(app)


def a_rate_limited_client(
    rate_limits: RateLimitBackend,
    *,
    max_requests: int,
    window_seconds: int = DEFAULT_RATE_WINDOW_SECONDS,
) -> TestClient:
    """A client whose every request spends one budget of ``rate_limits``.

    Every class shares one budget so the test drives the limiter through the
    real middleware regardless of how a path classifies.
    """
    budget = RateLimitBudget(max_requests, window_seconds)
    policy = RateLimitPolicy(
        budgets={rate_limit_class: budget for rate_limit_class in RateLimitClass},
    )
    return _rate_limited_client(rate_limits, policy, (API_PATH,))


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
    return _rate_limited_client(rate_limits, policy, (API_PATH, MEDIA_PATH))


def a_session_cache(redis: object | None = None) -> RedisSessionCache:
    """A real cache over a Redis that lives only for this test."""
    return RedisSessionCache(
        redis or fakeredis.FakeRedis(decode_responses=True), SESSION_KEY_PREFIXES,
    )


class _RedisFailingOn:
    """A Redis that answers everything except the one command named here."""

    def __init__(self, redis: object, command: str) -> None:
        self._redis = redis
        self._command = command

    def __getattr__(self, name: str) -> object:
        if name == self._command:
            raise ConnectionError(f"redis {name} is unavailable")
        return getattr(self._redis, name)


def a_session_cache_failing_on(command: str) -> RedisSessionCache:
    """A cache whose Redis refuses exactly one command and serves the rest."""
    return RedisSessionCache(
        _RedisFailingOn(fakeredis.FakeRedis(decode_responses=True), command),
        SESSION_KEY_PREFIXES,
    )


@dataclass
class FakeUser:
    id: str = "user-1"
    username: str = "alice"
    role: str = MEMBER_ROLE
    is_active: bool = True
    password_hash: str = "unused"


@dataclass
class Argon2idStyleHasher:
    """A non-bcrypt ``PasswordHasher`` double whose hashes are legible.

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


@dataclass
class SessionRecordsInMemory:
    """The one stored session, renewed in place and never committed.

    The expiry-column store owns its max age and computes the new expiry from
    the ``now`` the caller passes, so no clock is read outside ``dependencies``.
    """

    record: FakeSessionRecord | None
    max_age_seconds: int = SESSION_MAX_AGE_SECONDS

    def load(self, session_id: str) -> FakeSessionRecord | None:
        if self.record is None or self.record.id != session_id:
            return None
        return self.record

    def touch(
        self,
        record: FakeSessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> None:
        record.ip_address = ip_address
        record.user_agent = user_agent
        record.expires_at = now + timedelta(seconds=self.max_age_seconds)


@dataclass
class IdleSessionRecord:
    """A session an idle-window store keeps: only when it was last seen."""

    id: str
    user_id: str
    last_seen: datetime


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
    ) -> None:
        record.last_seen = now


@dataclass
class RecordingAuditSink:
    events: list[SessionIdentityChanged] = field(default_factory=list)

    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        self.events.append(event)


@dataclass
class AuthApp:
    """A minimal application serving the routes the dependencies protect."""

    client: TestClient
    sessions: SessionRecordsInMemory
    audit: RecordingAuditSink
    authenticated: list[AuthenticatedUser]
    signing_key: bytes

    def get(self, path: str, *, cookie: str | None = None) -> Response:
        headers = {} if cookie is None else {"cookie": f"session_id={cookie}"}
        return self.client.get(path, headers=headers)

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


def an_auth_app(
    record: FakeSessionRecord | None, cache: RedisSessionCache | None = None,
) -> AuthApp:
    """An application serving one protected, one admin, one session-id route."""
    config = a_web_auth_config(admin_role=ADMIN_ROLE, session_cache=cache)
    sessions = SessionRecordsInMemory(record)
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

    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(dependencies.admin_user)) -> dict[str, str]:
        return {"username": user.username}

    @app.get("/session-id")
    def session_id(
        verified: str = Depends(dependencies.verified_session_id),
    ) -> dict[str, str]:
        return {"session_id": verified}

    return AuthApp(
        client=TestClient(app, cookies={}, headers={"user-agent": CLIENT_USER_AGENT}),
        sessions=sessions,
        audit=audit,
        authenticated=authenticated,
        signing_key=config.signing_key,
    )
