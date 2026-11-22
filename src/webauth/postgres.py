"""The session half of the host's durable state over Postgres, for a host with the `postgres` extra.

The host brings its driver and keeps its accounts table, its `SubjectUserStore` and its
`AuditSink`; this module adds the session table, the session store and the sign-in shell over a
`Connection` the host has already opened inside its own transaction. It opens no engine or pool and
never begins, commits or rolls back: the host's `SessionTransaction` and `SignInTransaction` are
`with engine.begin() as connection:` around the store and the shell, so the library still never
commits. The host's migrations create the table `session_table` puts on its `MetaData`; nothing here
runs DDL. `delete_expired` is the sweep the host schedules.

A session id is stored as the SHA-256 hex digest of the id, so a stored row is no live cookie. The
store hands the raw id back from `create` and `load`; account ids are never hashed. That digest is
the session's stored key: `stored_key` computes it, and `PostgresStoredKeySessions` reads and
changes the same rows by it, for a host that keeps the key beside its own rows and has no raw id.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from pydantic import SecretStr
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    MetaData,
    Table,
    Text,
    delete,
    func,
    insert,
    select,
    update,
)
from sqlalchemy.exc import DBAPIError, OperationalError, SQLAlchemyError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from webauth import WebAuthError
from webauth._deferred_audit import DeferredAudit
from webauth.ports import SignInStores, StoreUnavailableError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from sqlalchemy import Row
    from sqlalchemy.engine import Connection

    from webauth.ports import AuditSink, SessionRecord, SubjectUserStore, UserRecord

__all__ = [
    "PostgresSessionStore",
    "PostgresStoredKeySessions",
    "SessionStoreError",
    "database_errors_as_store_errors",
    "delete_expired",
    "session_table",
    "sign_in_entry",
    "stored_key",
]

_TABLE_NAME: Final = "sessions"

_STORE_ERROR_MESSAGE: Final = "The session store failed"
_STORE_UNAVAILABLE_MESSAGE: Final = "The session store cannot be reached"
"""The whole text of a `StoreUnavailableError` and the start of a `SessionStoreError`'s text: a
driver's message names bound parameters, which hold session hashes, tokens and subjects."""

_SHUTDOWN_SQLSTATES: Final = frozenset({"57P01", "57P02", "57P03"})
"""`admin_shutdown`, `crash_shutdown` and `cannot_connect_now`: the server is going or coming up."""
_CONNECTION_SQLSTATE_CLASS: Final = "08"


class SessionStoreError(WebAuthError):
    """The database failed a session store call for a reason other than a connection it cannot
    reach, or failed the host's connection or commit around it.

    Its text names the driver error's class and SQLSTATE and carries no statement, parameter, id,
    token or subject, and it hides the error it replaces. It reaches the request as an ordinary
    exception, a loud 500. A host that retries a deadlock or a serialization failure catches it, and
    retries in a fresh transaction.
    """


def _sqlstate_of(driver_error: BaseException | None) -> str | None:
    return getattr(driver_error, "sqlstate", None)


def _cannot_reach_the_database(error: SQLAlchemyError) -> bool:
    """Whether the structured evidence of `error`, never its text, says the connection is out:
    a pool timeout, a connection SQLAlchemy invalidated, or a driver `OperationalError` that
    carries no SQLSTATE (a connection the client could not open or lost) or one of the connection
    classes and shutdowns. A deadlock (`40P01`) and a serialization failure (`40001`) are
    `OperationalError`s too, but the server answered and aborted one transaction."""
    if isinstance(error, PoolTimeoutError):
        return True
    if not isinstance(error, DBAPIError):
        return False
    if error.connection_invalidated:
        return True
    if not isinstance(error, OperationalError):
        return False
    sqlstate = _sqlstate_of(error.orig)
    return (
        sqlstate is None
        or sqlstate.startswith(_CONNECTION_SQLSTATE_CLASS)
        or sqlstate in _SHUTDOWN_SQLSTATES
    )


def _store_error_for(error: SQLAlchemyError) -> SessionStoreError:
    driver_error = error.orig if isinstance(error, DBAPIError) else error
    sqlstate = _sqlstate_of(driver_error)
    detail = [type(driver_error).__name__, *([] if sqlstate is None else [sqlstate])]
    return SessionStoreError(f"{_STORE_ERROR_MESSAGE} ({', '.join(detail)})")


@contextmanager
def database_errors_as_store_errors() -> Iterator[None]:
    """Raise `StoreUnavailableError` for a database that cannot be reached and `SessionStoreError`
    for every other database error inside the block, and pass every other exception unchanged.

    The host wraps it around its `engine.begin()`, so a connection that cannot open and a commit
    that fails, which happen outside every store call, report the same errors. The store wraps its
    own calls the same way. A connection is out when SQLAlchemy invalidated it, when its pool timed
    out, or when the driver's `OperationalError` carries no SQLSTATE or one of class `08` or
    `57P01` to `57P03`; the driver is read through `sqlstate`, as psycopg 3 sets it.
    """
    try:
        yield
    except SQLAlchemyError as error:
        if _cannot_reach_the_database(error):
            raise StoreUnavailableError(_STORE_UNAVAILABLE_MESSAGE) from None
        raise _store_error_for(error) from None


def session_table(metadata: MetaData, account_id: Column[str]) -> Table:
    """Put the session table on the host's `metadata`, referencing the host's account id column.

    A session ends with its account (`ON DELETE CASCADE`). The host's Alembic creates the table;
    a change to its columns is a host migration that the release notes name.
    """
    return Table(
        _TABLE_NAME,
        metadata,
        Column("id_hash", Text, primary_key=True),
        Column("account_id", Text, ForeignKey(account_id, ondelete="CASCADE"), nullable=False),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("expires_at", DateTime(timezone=True), nullable=False),
        Column("refresh_token", Text),
        Column("id_token", Text),
        Column("account_language", Text),
        Index("sessions_account_created_at", "account_id", "created_at"),
        Index("sessions_expires_at", "expires_at"),
    )


def delete_expired(connection: Connection, sessions_table: Table, now: datetime) -> int:
    """Delete every session whose expiry lies before `now` and return how many went.

    The session gate reads its clock in whole seconds and admits a session until `expires_at`, an
    expiry equal to that second included, so this reads `now` in whole seconds too and deletes
    what the gate refuses. It is one conditional delete inside the host's transaction on
    `connection`: a repeat deletes nothing, and a sweep that meets another pod's waits for that
    transaction and then finds those rows gone. Two sweeps that lock rows in opposite orders can
    deadlock; the database aborts one with `SessionStoreError` and the host retries in a fresh
    transaction or on its next cycle. A naive `now` raises `ValueError` before any statement.
    """
    _require_aware(now)
    with database_errors_as_store_errors():
        return connection.execute(
            delete(sessions_table).where(sessions_table.c.expires_at < now.replace(microsecond=0))
        ).rowcount


@contextmanager
def sign_in_entry(
    connection: Connection,
    *,
    advisory_lock_key: int,
    accounts: SubjectUserStore,
    audit: AuditSink,
    sessions_table: Table,
) -> Iterator[SignInStores]:
    """One sign-in entry inside the host's transaction on `connection`.

    It takes `pg_advisory_xact_lock(advisory_lock_key)` before it yields any store, so entries of
    every pod over this database run one at a time until the host's transaction ends. It yields the
    host's `accounts` and the session store over the same connection, and `audit` collects the
    block's events; they reach the host's `audit` as the last step, so a sink that fails fails the
    entry and the host rolls back. The host's `accounts` and `audit` write over `connection` too,
    or an event can outlive a rolled-back entry.
    """
    with database_errors_as_store_errors():
        connection.execute(select(func.pg_advisory_xact_lock(advisory_lock_key)))
    deferred = DeferredAudit()
    yield SignInStores(  # NOSONAR(S9152) the flush runs only when the block succeeds
        accounts=accounts,
        sessions=PostgresSessionStore(connection, accounts, sessions_table),
        audit=deferred,
    )
    deferred.flush_to(audit)


def stored_key(session_id: str) -> str:
    """The key a session's row carries: the SHA-256 hex digest of its id, which the row never holds.

    A host column may reference it (`ON DELETE SET NULL` is the host's to declare), and
    `PostgresStoredKeySessions` finds the session by it.
    """
    return hashlib.sha256(session_id.encode()).hexdigest()


def _require_aware(*instants: datetime) -> None:
    """Refuse a naive instant before any statement: the database would read it in the session's
    time zone and store or compare a different moment."""
    if any(instant.utcoffset() is None for instant in instants):
        raise ValueError("A session instant needs a timezone")


def _secret(token: str | None) -> SecretStr | None:
    return None if token is None else SecretStr(token)


@dataclass(frozen=True)
class _StoredSession:
    id: str = field(repr=False)
    user: UserRecord
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None = field(repr=False)
    id_token: SecretStr | None = field(repr=False)
    account_language: str | None


def _stored_session(session_id: str, row: Row[Any], user: UserRecord) -> _StoredSession:
    return _StoredSession(
        id=session_id,
        user=user,
        created_at=row.created_at,
        expires_at=row.expires_at,
        refresh_token=_secret(row.refresh_token),
        id_token=_secret(row.id_token),
        account_language=row.account_language,
    )


class _SessionRows(ABC):
    """The calls of both stores that find a row by its key: `_key_of` turns the id a caller gives
    into the row's key. Each call is part of whatever transaction the host has open on
    `connection`; nothing here commits."""

    def __init__(
        self, connection: Connection, accounts: SubjectUserStore, sessions_table: Table
    ) -> None:
        self._connection = connection
        self._accounts = accounts
        self._table = sessions_table

    @abstractmethod
    def _key_of(self, session_id: str) -> str:
        """The key of the row that `session_id` names."""

    def load(self, session_id: str) -> SessionRecord | None:
        with database_errors_as_store_errors():
            row = self._connection.execute(
                select(self._table).where(self._table.c.id_hash == self._key_of(session_id))
            ).one_or_none()
            user = None if row is None else self._accounts.get(row.account_id)
        return None if row is None or user is None else _stored_session(session_id, row, user)

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        _require_aware(expires_at)
        return self._updated(session_id, expires_at=expires_at)

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return self._updated(session_id, refresh_token=refresh_token.get_secret_value())

    def _updated(self, session_id: str, **values: object) -> bool:
        with database_errors_as_store_errors():
            result = self._connection.execute(
                update(self._table)
                .where(self._table.c.id_hash == self._key_of(session_id))
                .values(**values)
            )
        return result.rowcount == 1


class PostgresSessionStore(_SessionRows):
    """The sessions in the host's table, every call run on the host's `connection`.

    Each call is part of whatever transaction the host has open on `connection`; the store commits
    nothing. A database failure raises `StoreUnavailableError` when the database cannot be reached
    and `SessionStoreError` otherwise. `load` reads the account through the
    host's `accounts` store over the same connection, and returns `None` when the account is gone,
    and an expired row as the port says: the gate refuses it.
    """

    def _key_of(self, session_id: str) -> str:
        return stored_key(session_id)

    def create(
        self,
        user_id: str,
        *,
        session_id: str,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None,
        account_language: str | None,
    ) -> SessionRecord:
        """Store the session under the hash of `session_id`; a held hash, an expired row's
        included, is refused by the primary key and leaves the row unchanged. A naive `now` or
        `expires_at` raises `ValueError` before any statement."""
        _require_aware(now, expires_at)
        with database_errors_as_store_errors():
            user = self._accounts.get(user_id)
            if user is None:
                raise SessionStoreError(_STORE_ERROR_MESSAGE)
            row = self._connection.execute(
                insert(self._table)
                .values(
                    id_hash=stored_key(session_id),
                    account_id=user_id,
                    created_at=now,
                    expires_at=expires_at,
                    refresh_token=None
                    if refresh_token is None
                    else refresh_token.get_secret_value(),
                    id_token=None if id_token is None else id_token.get_secret_value(),
                    account_language=account_language,
                )
                .returning(self._table)
            ).one()
        return _stored_session(session_id, row, user)

    def delete(self, session_id: str) -> None:
        with database_errors_as_store_errors():
            self._connection.execute(
                delete(self._table).where(self._table.c.id_hash == self._key_of(session_id))
            )

    def delete_for_user(self, user_id: str) -> int:
        """End every session of the account and keep the account."""
        with database_errors_as_store_errors():
            return self._connection.execute(
                delete(self._table).where(self._table.c.account_id == user_id)
            ).rowcount

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        overflow = (
            select(self._table.c.id_hash)
            .where(self._table.c.account_id == user_id)
            .order_by(self._table.c.created_at.desc(), self._table.c.id_hash)
            .offset(keep_newest)
        )
        with database_errors_as_store_errors():
            self._connection.execute(delete(self._table).where(self._table.c.id_hash.in_(overflow)))


class PostgresStoredKeySessions(_SessionRows):
    """The same rows as `PostgresSessionStore`, found by the stored key, for the host's background
    reads (`current_groups`, `fresh_access_token`) that hold the key beside its own rows and never
    the raw id.

    A call takes the stored key where the raw-keyed store takes the id, and a record's `id` is the
    stored key it was given, so a raw id finds nothing here, as a stored key finds nothing in the
    raw-keyed store.
    """

    def _key_of(self, session_id: str) -> str:
        return session_id
