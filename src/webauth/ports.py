"""What the host supplies: its users, sessions, audit, and rate limiter.

Each port is a Protocol the application implements over the persistence it
already owns, so the library needs no schema and no ORM of its own. The
library commits nothing: a store either applies each of its calls at once or
writes into a transaction the host opens and commits, and `SessionTransaction`
is that transaction when the host hands it to the library, and `SignInTransaction`
is the serialized one the library's sign-in routes and the bearer gate's person paths
enter. Whether a request that fails leaves the auth machinery's writes behind is the host's: a
transaction that rolls back on an exception leaves none, a store that applies
each call keeps them, and the rate-limit budget counts attempts either way.
Behind the session gate, the session renewal is durable before the route runs,
so a route that fails afterwards leaves it in place.

It also holds the records the library hands out and the clock type the host
supplies, so a module that needs only those need not import the FastAPI-bound
`dependencies`.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Protocol

from webauth import WebAuthError

if TYPE_CHECKING:
    from pydantic import SecretStr

__all__ = [
    "AccountEvent",
    "AccountEventKind",
    "AuditSink",
    "AuthenticatedUser",
    "BearerCaller",
    "RateLimitBackend",
    "SessionRecord",
    "SessionRecordStore",
    "SessionTransaction",
    "SignInStores",
    "SignInTransaction",
    "SubjectUserStore",
    "UserRecord",
    "UsernameTakenError",
    "WallClock",
]

WallClock = Callable[[], float]
"""Seconds since the epoch. The library reads it once per session decision, as
whole seconds. A reading within the session cap plus 60 seconds of the end of
year 9999 makes the decision raise, so no session is admitted."""


@dataclass(frozen=True)
class AuthenticatedUser:
    """The account behind the current request."""

    id: str
    username: str
    role: str


@dataclass(frozen=True)
class BearerCaller:
    """The machine behind a request the bearer gate admitted on a machine path: the token's ``sub``.

    No account, no role and no token: the host owns what the subject may do.
    """

    subject: str


class UserRecord(Protocol):
    """The account fields the auth machinery reads."""

    @property
    def id(self) -> str: ...

    @property
    def username(self) -> str: ...

    @property
    def role(self) -> str: ...


class SessionRecord(Protocol):
    """One stored session and the account it belongs to.

    ``created_at`` and ``expires_at`` are the stored instants the library's
    ``WebAuthConfig.session_lifetime`` is judged against. A timestamp without
    an offset is read as UTC.
    """

    @property
    def id(self) -> str: ...

    @property
    def user(self) -> UserRecord: ...

    @property
    def created_at(self) -> datetime: ...

    @property
    def expires_at(self) -> datetime: ...

    @property
    def refresh_token(self) -> SecretStr | None:
        """The refresh token the login's code exchange issued, or ``None`` when
        the issuer gave none or the row was stored before the host held refresh
        tokens."""
        ...

    @property
    def id_token(self) -> SecretStr | None:
        """The login's ID token, a secret of the session that goes back only to
        the issuer as the logout hint. It is part of the row and ends with it.
        The host writes it with ``get_secret_value()`` and returns it wrapped in
        ``SecretStr``; it is at most ``MAX_TOKEN_CHARACTERS`` (8192) ASCII
        characters, the verifier's bound, so the column takes no less. ``None``
        for a row stored before the host held ID tokens, or for a session
        the callback route opened for a host that keeps none (``keeps_id_token=False``)."""
        ...


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


class SessionRecordStore(Protocol):
    """The host's sessions, which the library asks on every request.

    The library caches no sessions: every admission costs one ``load`` and one
    ``touch``, so a session the host ended is refused on its next request. A
    request is admitted once, or twice when the session gate admitted it and a
    mounted application under another ``WebAuthConfig`` admits it again.

    The library ends a session in three places only, by calling ``delete``,
    ``delete_for_user`` or ``prune_overflow``: the logout route, the callback route (the
    session an incoming cookie replaced, and all but the newest ones under the
    cap) and the back-channel logout route.
    """

    def create(
        self,
        user_id: str,
        *,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None,
    ) -> SessionRecord:
        """Create the session and return it.

        The refresh token is part of the session row: whatever ends the row
        ends it, and no other row or table holds it. The host writes it with
        ``get_secret_value()``; the library bounds the value only by the 64 KiB
        token response, so the column takes no smaller length. The ID token is
        part of the row the same way, as ``SessionRecord.id_token`` says, and
        ``None`` when the host keeps none.

        The store mints the new session's id with at least 128 bits from a
        CSPRNG, in at most 135 characters. The cookie signs the id alone, so a
        store that hands out an id again gives every old signed cookie for that
        id the new session.
        """
        ...

    def load(self, session_id: str) -> SessionRecord | None:
        """The stored session, or ``None`` when the store holds none under this id.

        The library hands it the id as the cookie reader bounded it. A host
        that passes ``admit_session`` an id from elsewhere bounds the length
        first.

        The library asks no lock of ``load``: a renewal goes through ``touch``,
        which updates only a row that still exists. A ``delete`` that lands
        before ``touch`` updates the row refuses the request, and a renewal
        never brings a deleted session back. A ``delete`` that lands after
        ``touch`` ends the session for every later request, not for the one
        already admitted.
        """
        ...

    def touch(
        self,
        session_id: str,
        *,
        expires_at: datetime,
    ) -> bool:
        """Renew the session in place, and say whether a stored row was renewed.

        ``True``: the stored row was renewed. ``False``: the row is gone and
        nothing was written; the request is refused like an expired session.
        ``touch`` only updates an existing row and never creates one, so a
        session deleted meanwhile stays deleted. Any other answer raises
        ``TypeError``: answer ``rowcount == 1``, not ``rowcount``.

        The store writes the ``expires_at`` it is given and computes none of
        its own: the library alone applies ``WebAuthConfig.session_lifetime``.
        It leaves the refresh token and the ID token untouched.
        """
        ...

    def replace_refresh_token(
        self,
        session_id: str,
        *,
        refresh_token: SecretStr,
    ) -> bool:
        """Replace the session's refresh token, and say whether the stored row now holds it.

        ``True``: the stored row holds the given token. ``False``: the row is
        gone and nothing was written. Like ``touch``, it only updates an existing
        row and never creates one, so a session deleted meanwhile stays deleted.
        Any other answer raises ``TypeError``: answer ``rowcount == 1``, not
        ``rowcount``. The ID token stays untouched: it is the login's own.
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


class SessionTransaction(Protocol):
    """The host's own transaction around the library's calls to its session store.

    Calling it, entering the context manager, the store calls inside the block
    and leaving it all run in one call on one worker thread, so a thread-bound
    connection is safe. Calls for concurrent requests run on several worker
    threads at once, so a store shared between calls is thread-safe.

    Leaving the block without an exception makes the writes made inside it
    durable. A store that commits each of its own calls meets this with
    ``lambda: nullcontext(store)``.

    An exception raised inside the block, by the store or by the library,
    passes through the context manager's exit, and what that exit rolls back is
    the host's decision: the library promises no rollback. That exception, like
    one the exit raises itself (a failing commit), reaches the caller.
    """

    def __call__(self) -> AbstractContextManager[SessionRecordStore]: ...


@dataclass(frozen=True)
class SignInStores:
    """The stores one sign-in entry uses, not necessarily one database transaction."""

    accounts: SubjectUserStore
    sessions: SessionRecordStore
    audit: AuditSink


class SignInTransaction(Protocol):
    """The host's serialized context around one sign-in, entered by the callback, logout and
    back-channel logout routes, and once per token request on the bearer gate's person paths.

    Creating it, entering the context manager, every store call inside the block
    and leaving it all run on one worker thread, never on the event loop. Entries
    for concurrent requests run on several worker threads, so the context
    serializes every entry over the same stores until its exit returns, and
    against whatever else the host locks the same way. Inside one entry the
    library never nests a transaction, never takes a lock and never calls the
    issuer, so a lock that is not re-entrant works.

    Leaving the block without an exception makes the writes made inside it
    durable. An exception raised inside the block, by a store, by the audit sink
    or by the library, passes through the exit and escapes after the host's
    cleanup; what the exit rolls back is the host's decision, so a host whose
    stores apply each call keeps the account created, the sessions ended and the
    events recorded before the failure, and the next sign-in opens a new session
    and restores nothing. An exception the exit raises itself, such as a failing
    commit, reaches the route with an uncertain outcome.

    The records the stores return are read inside the block only. The audit sink
    is called inside the block only: a sink that writes outside the host's
    transaction keeps the events of a failed block.
    """

    def __call__(self) -> AbstractContextManager[SignInStores]: ...


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


class AccountEventKind(Enum):
    """What happened to an account; the fields beyond ``AccountEvent``'s common ones.

    ``USER_CREATED`` carries ``role``; ``ROLE_CHANGED`` carries ``previous_role``
    and ``role``; ``BACKCHANNEL_LOGOUT`` carries none, and its ``subject_id`` is
    the account whose sessions the issuer ended.
    """

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
    def account_event(self, event: AccountEvent) -> None:
        """Map an account operation to the host's audit, optionally doing nothing.

        On an admission event (``USER_CREATED`` or ``ROLE_CHANGED``),
        ``actor_id=None`` means the issuer's groups decided, not a person. A
        ``BACKCHANNEL_LOGOUT`` also has ``actor_id=None``, with no group decision.
        """
        ...
