"""What the host supplies: its users, sessions, audit, and rate limiter.

Each port is a Protocol the application implements over the persistence it
already owns, so the library needs no schema and no ORM of its own. None of
them commits: the caller owns the transaction boundary, so a request that
fails leaves nothing behind that the auth machinery wrote — except the
rate-limit budget, which counts attempts whether or not the request succeeds.

It also holds the records the library hands out and the clock type the host
supplies, so a module that needs only those need not import the FastAPI-bound
`dependencies`.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, auto
from typing import NewType, Protocol

from webauth import WebAuthError

__all__ = [
    "AccountEvent",
    "AccountEventKind",
    "AuditSink",
    "AuthenticatedUser",
    "RateLimitBackend",
    "SessionIdentityChange",
    "SessionIdentityChanged",
    "SessionRecord",
    "SessionRecordStore",
    "SessionReference",
    "SubjectUserStore",
    "UserRecord",
    "UsernameTakenError",
    "WallClock",
    "WriteLock",
]

SessionReference = NewType("SessionReference", str)

WallClock = Callable[[], float]
"""Seconds since the epoch: the host's reading of now."""


@dataclass(frozen=True)
class AuthenticatedUser:
    """The account behind the current request."""

    id: str
    username: str
    role: str


class UserRecord(Protocol):
    """The account fields the auth machinery reads."""

    id: str
    username: str
    role: str


class SessionRecord(Protocol):
    """One stored session and the account it belongs to.

    ``created_at`` and ``expires_at`` are the stored instants the library's
    ``WebAuthConfig.session_lifetime`` is judged against. A timestamp without
    an offset is read as UTC.
    """

    id: str
    user_id: str
    ip_address: str
    user_agent: str
    user: UserRecord

    @property
    def created_at(self) -> datetime: ...

    @property
    def expires_at(self) -> datetime: ...


class SubjectUserStore(Protocol):
    """Accounts an identity provider vouches for, keyed by its subject.

    The host binds the store to one issuer, so an account's ``id`` is the
    issuer's ``sub`` and a back-channel logout names it directly.
    """

    def get(self, user_id: str) -> UserRecord | None:
        """The account whose ``id`` equals ``user_id`` character for character.

        The host must compare exactly here, with no case, accent or
        trailing-space folding, even where its id column's collation folds;
        comparing bytes does (a binary column or a NO PAD binary collation).
        """
        ...

    def create_for_subject(self, subject: str, username: str, role: str) -> UserRecord:
        """Add an account whose ``id`` is ``subject``.

        Raises ``UsernameTakenError`` when the store enforces a unique username and
        ``username`` is taken; uniqueness is not required.
        """
        ...

    def set_role(self, user_id: str, role: str) -> UserRecord:
        """Change the role of the account whose ``id`` is ``user_id`` and return it.

        Runs in the caller's transaction and never commits. Raises when no
        account has ``user_id``: admission only calls it for an account it just
        read, so a missing row is the host's defect and the host rolls back.
        """
        ...


class UsernameTakenError(WebAuthError):
    """The store could not create an account because its username is taken."""


class WriteLock(Protocol):
    """Serialize check-then-write operations in the host's transaction.

    All stores used inside ``hold`` share that transaction. The host owns
    commit and rollback. A
    transaction-scoped database lock may remain held after context exit until
    the host finishes its transaction; exiting never commits implicitly.
    """

    def hold(self) -> AbstractContextManager[None]: ...


class SessionRecordStore(Protocol):
    def create(
        self,
        user_id: str,
        *,
        now: datetime,
        expires_at: datetime,
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
        session_id: str,
        *,
        expires_at: datetime,
        ip_address: str,
        user_agent: str,
    ) -> bool:
        """Renew the session in place, and say whether a stored row was renewed.

        ``True``: the stored row was renewed. ``False``: the row is gone and
        nothing was written; the request is refused like an expired session.
        ``touch`` only updates an existing row and never creates one, so a
        session deleted meanwhile stays deleted. Any other answer raises
        ``TypeError``: answer ``rowcount == 1``, not ``rowcount``.

        The store writes the ``expires_at`` it is given and computes none of
        its own: the library alone applies ``WebAuthConfig.session_lifetime``.
        """
        ...

    def delete(self, session_id: str) -> None:
        """Drop the session. An id the store does not hold is a no-op, never an
        error: a logout names whatever the browser's cookie says."""
        ...

    def delete_for_user(self, user_id: str) -> int: ...

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        """End all but the user's ``keep_newest`` newest sessions by ``created_at``.

        ``0`` keeps none.
        """
        ...


class RateLimitBackend(Protocol):
    """A per-key request budget: one sliding window, counted as it is spent."""

    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        """Whether ``key`` still fits ``limit`` events in the last ``window_seconds``.

        The caller owns the window and the limit, so the backend bakes in
        neither: each budget measures its own key, and a key is always checked
        with one window. The check counts the current event, so a caller told
        yes has already spent one of the budget. ``limit`` and
        ``window_seconds`` must be positive integers, excluding booleans, and
        the caller validates them before invoking the backend. A backend that
        cannot answer raises rather than guessing, and the caller fails the
        request closed.

        The middleware calls this from a worker thread so a slow check does
        not stall the event loop, and calls may run concurrently: an
        implementation must be thread-safe.
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
    secret, so the field is a ``SessionReference``; a host makes one with
    ``webauth.cookies.session_reference``.
    """

    change: SessionIdentityChange
    user_id: str
    session_ref: SessionReference
    previous: str
    current: str


class AccountEventKind(Enum):
    USER_CREATED = "user_created"
    ROLE_CHANGED = "role_changed"
    BACKCHANNEL_LOGOUT = "backchannel_logout"


@dataclass(frozen=True)
class AccountEvent:
    """An account operation without credentials, usernames, or session tokens."""

    kind: AccountEventKind
    actor_id: str | None
    subject_id: str
    role: str | None = None
    previous_role: str | None = None


class AuditSink(Protocol):
    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        """Record that a live session began arriving from somewhere else."""
        ...

    def account_event(self, event: AccountEvent) -> None:
        """Map an account operation to the host's audit, optionally doing nothing."""
        ...
