"""The session half of the host's durable state over Postgres, for a host with the `postgres` extra.

The host brings its driver and keeps its accounts table, its `SubjectUserStore` and its
`AuditSink`; this module adds the session table, the session store and the sign-in shell over a
`Connection` the host has already opened inside its own transaction. It opens no engine or pool and
never begins, commits or rolls back: the host's `SessionTransaction` and `SignInTransaction` are
`with engine.begin() as connection:` around the store and the shell, so the library still never
commits. The host's migrations create the table `session_table` puts on its `MetaData`; nothing here
runs DDL. `delete_expired` is the sweep the host schedules.

A session id is stored as the SHA-256 hex digest of the id, so a stored row is no live cookie. The
store hands the raw id back from `create` and `load`; account ids are never hashed.
"""

from __future__ import annotations

import hashlib
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
from sqlalchemy.exc import SQLAlchemyError

from webauth import WebAuthError
from webauth._deferred_audit import DeferredAudit
from webauth.ports import SignInStores

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from sqlalchemy import Row
    from sqlalchemy.engine import Connection

    from webauth.ports import AuditSink, SessionRecord, SubjectUserStore, UserRecord

__all__ = [
    "PostgresSessionStore",
    "SessionStoreError",
    "database_errors_as_store_errors",
    "delete_expired",
    "session_table",
    "sign_in_entry",
]

_TABLE_NAME: Final = "sessions"

_STORE_ERROR_MESSAGE: Final = "The session store failed"
"""The whole text of a `SessionStoreError`: a driver's message names bound parameters, which hold
session hashes, tokens and subjects."""


class SessionStoreError(WebAuthError):
    """The database failed a session store call, or the host's connection or commit around it.

    It carries no statement, parameter, id, token or subject, and it hides the error it replaces.
    A host that parks work on a store outage catches it, and may retry in a fresh transaction.
    """


@contextmanager
def database_errors_as_store_errors() -> Iterator[None]:
    """Raise `SessionStoreError` for a database error inside the block and pass every other
    exception unchanged.

    The host wraps it around its `engine.begin()`, so a connection that cannot open and a commit
    that fails, which happen outside every store call, report the same error. The store wraps its
    own calls the same way.
    """
    try:
        yield
    except SQLAlchemyError:
        raise SessionStoreError(_STORE_ERROR_MESSAGE) from None


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

    The session gate admits a session until `expires_at` and no longer, so this deletes what it
    refuses. It is one conditional delete inside the host's transaction on `connection`: a repeat
    deletes nothing, and a sweep that meets another pod's waits for that transaction and then finds
    those rows gone. Two sweeps that lock rows in opposite orders can deadlock; the database aborts
    one with `SessionStoreError` and the host retries in a fresh transaction or on its next cycle.
    """
    with database_errors_as_store_errors():
        return connection.execute(
            delete(sessions_table).where(sessions_table.c.expires_at < now)
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


def _stored_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode()).hexdigest()


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


class PostgresSessionStore:
    """The sessions in the host's table, every call run on the host's `connection`.

    Each call is part of whatever transaction the host has open on `connection`; the store commits
    nothing. A database failure raises `SessionStoreError`. `load` reads the account through the
    host's `accounts` store over the same connection, and returns `None` when the account is gone,
    and an expired row as the port says: the gate refuses it.
    """

    def __init__(
        self, connection: Connection, accounts: SubjectUserStore, sessions_table: Table
    ) -> None:
        self._connection = connection
        self._accounts = accounts
        self._table = sessions_table

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
        included, is refused by the primary key and leaves the row unchanged."""
        with database_errors_as_store_errors():
            user = self._accounts.get(user_id)
            if user is None:
                raise SessionStoreError(_STORE_ERROR_MESSAGE)
            row = self._connection.execute(
                insert(self._table)
                .values(
                    id_hash=_stored_key(session_id),
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

    def load(self, session_id: str) -> SessionRecord | None:
        with database_errors_as_store_errors():
            row = self._connection.execute(
                select(self._table).where(self._table.c.id_hash == _stored_key(session_id))
            ).one_or_none()
            user = None if row is None else self._accounts.get(row.account_id)
        return None if row is None or user is None else _stored_session(session_id, row, user)

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return self._updated(session_id, expires_at=expires_at)

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return self._updated(session_id, refresh_token=refresh_token.get_secret_value())

    def delete(self, session_id: str) -> None:
        with database_errors_as_store_errors():
            self._connection.execute(
                delete(self._table).where(self._table.c.id_hash == _stored_key(session_id))
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

    def _updated(self, session_id: str, **values: object) -> bool:
        with database_errors_as_store_errors():
            result = self._connection.execute(
                update(self._table)
                .where(self._table.c.id_hash == _stored_key(session_id))
                .values(**values)
            )
        return result.rowcount == 1
