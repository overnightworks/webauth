"""What the host supplies: its users, sessions, attempts, audit, hasher, and rate limiter.

Each port is a Protocol the application implements over the persistence it
already owns, so the library needs no schema and no ORM of its own. None of
them commits: the caller owns the transaction boundary, so a request that
fails leaves nothing behind that the auth machinery wrote — except the
rate-limit budget, which counts attempts whether or not the request succeeds.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import Protocol, runtime_checkable


class UserRecord(Protocol):
    """The account fields the auth machinery reads."""

    id: str
    username: str
    role: str
    is_active: bool

    @property
    def password_hash(self) -> str | None:
        """The stored hash, or ``None`` for an account that has no password.

        Read-only, so a host model whose field is typed ``str`` still satisfies
        it: a password-only host never holds an account without one.
        """
        ...


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
class SubjectUserStore(Protocol):
    """Accounts an identity provider vouches for, keyed by its subject.

    The host binds the store to one issuer, so an account's ``id`` is the
    issuer's ``sub`` and a back-channel logout names it directly.
    """

    def get(self, user_id: str) -> UserRecord | None: ...

    def get_by_username(self, username: str) -> UserRecord | None: ...

    def create_for_subject(self, subject: str, username: str, role: str) -> UserRecord:
        """Add an account whose ``id`` is ``subject`` and that has no password.

        Raises ``UsernameTakenError`` for a duplicate username.
        """
        ...


class UserManagementError(Exception):
    """A refused user-management operation, translated by the host."""


class UsernameTakenError(UserManagementError):
    """The store could not create an account because its username is taken."""


@runtime_checkable
class WriteLock(Protocol):
    """Serialize check-then-write operations in the host's transaction.

    All stores used inside ``hold`` share that transaction. The host owns
    commit and rollback. A
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
        """The session held against concurrent writers until the caller commits.

        A concurrent ``delete`` of the same session waits until the caller of
        ``load`` commits, so a revocation never interleaves with a renewal.
        """
        ...

    def touch(
        self,
        record: SessionRecord,
        *,
        ip_address: str,
        user_agent: str,
        now: datetime,
    ) -> bool:
        """Renew ``record`` in place, and say whether a stored row was renewed.

        ``True``: the stored row was renewed. ``False``: the row is gone and
        nothing was written; the request is refused like an expired session.
        ``touch`` only updates an existing row and never creates one, so a
        session deleted meanwhile stays deleted. Any other answer raises
        ``TypeError``: answer ``rowcount == 1``, not ``rowcount``.

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


class SessionLivenessPolicy[StoredSessionT](Protocol):
    """Whether a session still stands, decided without reading the wall clock.

    ``now`` is passed in by ``dependencies`` — the one place that reads the
    clock — so a policy is a pure function of a session and that instant. The
    session loaded from the store is judged whole.
    """

    def admits_stored_session(self, record: StoredSessionT, now: datetime) -> bool:
        """Whether a session loaded from the store still stands at ``now``."""
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


class SessionIdentityChange(Enum):
    """Which part of a session's origin stopped matching the stored one."""

    IP_ADDRESS = auto()
    USER_AGENT = auto()


@dataclass(frozen=True)
class SessionIdentityChanged:
    """A session's origin changed; ``session_ref`` is the SHA-256 hex of its id.

    The raw session identifier never reaches an audit event: it is a bearer
    secret, and ``session_ref`` matches the reference of ``revoke_session``.
    """

    change: SessionIdentityChange
    user_id: str
    session_ref: str
    previous: str
    current: str


class UserManagementEventKind(Enum):
    USER_CREATED = "user_created"
    SESSION_REVOKED = "session_revoked"


@dataclass(frozen=True)
class UserManagementEvent:
    """An account operation without credentials, usernames, or session tokens."""

    kind: UserManagementEventKind
    actor_id: str | None
    subject_id: str
    role: str | None = None
    session_ref: str | None = None


@runtime_checkable
class AuditSink(Protocol):
    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        """Record that a live session began arriving from somewhere else."""
        ...

    def user_management_event(self, event: UserManagementEvent) -> None:
        """Map an account operation to the host's audit, optionally doing nothing."""
        ...
