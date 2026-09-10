"""What the host supplies: its users, sessions, attempts, audit, hasher, and rate limiter.

Each port is a Protocol the application implements over the persistence it
already owns, so the library needs no schema and no ORM of its own. None of
them commits: the caller owns the transaction boundary, so a request that
fails leaves nothing behind that the auth machinery wrote.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel


class UserRecord(Protocol):
    """The account fields the auth machinery reads."""

    id: str
    username: str
    role: str
    is_active: bool
    password_hash: str


class SessionRecord(Protocol):
    """One stored session and the account it belongs to.

    The fields every liveness policy leaves alone: identity and origin. When
    and whether the session still stands is the policy's to read from the
    concrete record its own store produces — the base contract assumes no
    ``created_at``, ``expires_at``, or ``last_seen``.
    """

    id: str
    user_id: str
    ip_address: str
    user_agent: str
    user: UserRecord


@runtime_checkable
class UserStore(Protocol):
    def get(self, user_id: str) -> UserRecord | None: ...

    def get_by_username(self, username: str) -> UserRecord | None: ...

    def count(self) -> int: ...

    def create(self, username: str, password_hash: str, role: str) -> UserRecord:
        """Add an account, including whatever else the application ties to one."""
        ...


class UserManagementError(Exception):
    """A refused user-management operation, translated by the host."""


class UsernameTakenError(UserManagementError):
    """The store could not create an account because its username is taken."""


class UnknownUserError(UserManagementError):
    """The requested account does not exist."""


@runtime_checkable
class UserAdministrationStore(UserStore, Protocol):
    """Account administration over the host's model and transaction.

    ``create`` raises ``UsernameTakenError`` for a duplicate username. Store
    errors carry no passwords, hashes, or raw session identifiers.
    """

    def list(self) -> list[UserRecord]:
        """All accounts, in the order the store chooses."""
        ...

    def update(
        self,
        user_id: str,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        password_hash: str | None = None,
    ) -> UserRecord:
        """Change the supplied fields, or raise ``UnknownUserError``."""
        ...

    def count_active_admins(self, role: str) -> int:
        """Count active accounts with ``role``; the caller holds any lock."""
        ...


@runtime_checkable
class WriteLock(Protocol):
    """Serialize check-then-write operations in the host's transaction.

    All stores used inside ``hold`` share that transaction. The host owns
    commit and rollback, including rollback after ``SetupRacedError``. A
    transaction-scoped database lock may remain held after context exit until
    the host finishes its transaction; exiting never commits implicitly.
    """

    def hold(self) -> AbstractContextManager[None]: ...


@runtime_checkable
class SessionRecordStore(Protocol):
    def create(
        self,
        user_id: str,
        expires_at: datetime,
        *,
        ip_address: str,
        user_agent: str,
    ) -> SessionRecord: ...

    def load(self, session_id: str) -> SessionRecord | None:
        """The session held against concurrent writers until the caller commits."""
        ...

    def touch(
        self,
        record: SessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> None:
        """Renew ``record`` in place: its origin, and an expiry the store owns.

        The store computes its own new expiry from the max age it was built
        with; the caller passes only ``now``, so no code outside
        ``dependencies`` reads the clock.
        """
        ...

    def delete(self, session_id: str) -> None: ...

    def delete_for_user(self, user_id: str) -> int: ...

    def prune_overflow(self, user_id: str, max_sessions: int) -> list[str]:
        """Drop the oldest sessions above ``max_sessions``, newest kept."""
        ...


@runtime_checkable
class SessionAdministrationStore(SessionRecordStore, Protocol):
    """Active sessions selected by the host's liveness and persistence rules."""

    def list_active(
        self, *, offset: int = 0, limit: int | None = None,
    ) -> list[SessionRecord]:
        """Read active sessions in store order without requiring a write lock."""
        ...

    def count_active(self) -> int:
        """Count active sessions without requiring a write lock."""
        ...


StoredSessionT = TypeVar("StoredSessionT", contravariant=True)


class SessionLivenessPolicy(Protocol[StoredSessionT]):
    """Whether a session still stands, decided without reading the wall clock.

    ``now`` is passed in by ``dependencies`` — the one place that reads the
    clock — so a policy is a pure function of a session and that instant. The
    two questions differ by who owns idle expiry. A session loaded from the
    store is judged whole. A session read from a cache has already had idle
    expiry enforced by the cache's own TTL, so only the caps the cache cannot
    see remain — never the cached ``expires_at``, which can lag the real TTL
    after a refresh and would expire a live session if it were trusted here.
    """

    def admits_stored_session(self, record: StoredSessionT, now: datetime) -> bool:
        """Whether a session loaded from the store still stands at ``now``."""
        ...

    def admits_cached_session(self, cached: CachedSessionData, now: datetime) -> bool:
        """Whether a cached session still stands, its idle already the cache's."""
        ...


@runtime_checkable
class LoginAttemptStore(Protocol):
    def record(self, *, ip_address: str, username: str, success: bool) -> None: ...

    def count_recent_failures(
        self,
        *,
        ip_address: str,
        window_seconds: int,
        username: str | None = None,
    ) -> int:
        """Failures within the window, by username when given, else by address."""
        ...


@runtime_checkable
class PasswordHasher(Protocol):
    """The algorithm the host chose to hash and check its passwords with."""

    def hash(self, password: str) -> str: ...

    def verify(self, password: str, stored_hash: str | None) -> bool:
        """Whether ``password`` matches ``stored_hash``, at full cost when it cannot.

        A ``None`` hash — a username nobody holds, or an account with no
        password set — is still verified against a fixed dummy hash rather than
        rejected outright, so a missing account cannot be told from a wrong
        password by how long the answer takes.
        """
        ...


@runtime_checkable
class RateLimitBackend(Protocol):
    """A per-key request budget: one sliding window, counted as it is spent."""

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        """Whether ``key`` still fits ``limit`` events in the last ``window_seconds``.

        The caller owns the window and the limit, so the backend bakes in
        neither: each budget measures its own key, and a key is always checked
        with one window. The check counts the current event, so a caller told
        yes has already spent one of the budget. A backend that cannot answer
        raises rather than guessing, and the caller fails the request closed.
        """
        ...


class CachedSessionData(BaseModel):
    """The session payload a `SessionCache` stores and returns."""

    user_id: str
    username: str
    role: str
    is_active: bool
    ip_address: str
    user_agent: str
    expires_at: datetime
    created_at: datetime


@runtime_checkable
class SessionCache(Protocol):
    """A fast session store the host keeps beside its database, or nothing.

    With a cache installed on ``WebAuthConfig.session_cache``, its own store —
    Redis in the one implementation shipped here — owns idle expiry and the
    host reconciles the database from it; a request's account is read straight
    from the cache and the ``SessionRecordStore`` answers only when the cache
    cannot. A host that runs without one leaves the field ``None`` and every
    read goes to the store, whose per-request ``touch`` then owns idle expiry.
    """

    @property
    def consecutive_failures(self) -> int:
        """Reads that have failed in a row, for the host's cache-health checks."""
        ...

    def store(
        self,
        session_id: str,
        user_id: str,
        username: str,
        role: str,
        is_active: bool,
        ip_address: str,
        user_agent: str,
        expires_at: datetime,
        created_at: datetime,
        max_age_seconds: int,
    ) -> None:
        """Write the whole session payload under ``session_id`` with a TTL."""
        ...

    def get(self, session_id: str) -> CachedSessionData | None:
        """The cached payload, or ``None`` when the cache holds no such session."""
        ...

    def refresh_ttl(self, session_id: str, max_age_seconds: int) -> None: ...

    def update_ip_ua(self, session_id: str, ip_address: str, user_agent: str) -> None: ...

    def delete(self, session_id: str, user_id: str) -> None: ...

    def delete_user_sessions(self, user_id: str) -> list[str]:
        """Forget every session of one account; the ids dropped are returned."""
        ...

    def get_all_sessions(self) -> list[tuple[str, int]]:
        """Each live session id paired with the seconds of TTL it has left."""
        ...


class SessionIdentityChange(Enum):
    """Which part of a session's origin stopped matching the stored one."""

    IP_ADDRESS = auto()
    USER_AGENT = auto()


@dataclass(frozen=True)
class SessionIdentityChanged:
    change: SessionIdentityChange
    user_id: str
    session_id: str
    previous: str
    current: str


class UserManagementEventKind(Enum):
    USER_CREATED = "user_created"
    ROLE_CHANGED = "role_changed"
    USER_DEACTIVATED = "user_deactivated"
    SESSIONS_REVOKED = "sessions_revoked"
    FIRST_ADMIN_CREATED = "first_admin_created"
    PASSWORD_SET_BY_ADMIN = "password_set_by_admin"
    PASSWORD_CHANGED = "password_changed"
    SESSION_REVOKED = "session_revoked"


@dataclass(frozen=True)
class UserManagementEvent:
    """An account operation without credentials, usernames, or session tokens."""

    kind: UserManagementEventKind
    actor_id: str | None
    subject_id: str
    role: str | None = None
    session_count: int | None = None
    session_ref: str | None = None


@runtime_checkable
class AuditSink(Protocol):
    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        """Record that a live session began arriving from somewhere else."""
        ...

    def user_management_event(self, event: UserManagementEvent) -> None:
        """Map an account operation to the host's audit, optionally doing nothing."""
        ...
