"""A host over a real Postgres: its accounts table and `SubjectUserStore`, its sign-in transaction
around the extra's shell, and the schema each test owns.

The accounts table follows what a host keeps; the extra owns only the session table."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

import pytest
from sqlalchemy import Column, MetaData, Table, Text, create_engine, insert, select, text, update

from tests.support.account_arrangement import FakeUser
from tests.support.webauth_arrangement import RecordingAuditSink
from webauth.ports import AccountKind, SignInStores, SignInTransaction
from webauth.postgres import (
    PostgresSessionStore,
    database_errors_as_store_errors,
    session_table,
    sign_in_entry,
)

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from sqlalchemy import Row
    from sqlalchemy.engine import Connection, Engine

    from webauth.ports import AuditSink

POSTGRES_URL_VARIABLE: Final = "WEBAUTH_TEST_POSTGRES_URL"
SIGN_IN_LOCK_KEY: Final = 779


def postgres_url() -> str:
    """The database the tests run against: CI provides one, a local run names its own."""
    url = os.environ.get(POSTGRES_URL_VARIABLE)
    if url is not None:
        return url
    if os.environ.get("CI"):
        pytest.fail(f"{POSTGRES_URL_VARIABLE} is unset in CI")
    pytest.skip(f"{POSTGRES_URL_VARIABLE} names no Postgres")


@dataclass(frozen=True)
class DatabaseLocation:
    """A database and the schema one test owns in it; every connection of the location sees only
    that schema, so tests share one database and run in parallel."""

    url: str
    schema: str

    def engine(self) -> Engine:
        return create_engine(
            self.url,
            hide_parameters=True,
            connect_args={"options": f"-csearch_path={self.schema}"},
        )


@contextmanager
def a_schema_of_its_own(url: str) -> Iterator[DatabaseLocation]:
    location = DatabaseLocation(url, f"webauth_test_{uuid.uuid4().hex}")
    engine = create_engine(url)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{location.schema}"'))
    try:
        yield location
    finally:
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{location.schema}" CASCADE'))
        engine.dispose()


@dataclass(frozen=True)
class HostTables:
    metadata: MetaData
    accounts: Table
    sessions: Table


def a_hosts_tables() -> HostTables:
    metadata = MetaData()
    accounts = Table(
        "accounts",
        metadata,
        Column("id", Text, primary_key=True),
        Column("username", Text, nullable=False),
        Column("role", Text, nullable=False),
        Column("kind", Text, nullable=False),
    )
    return HostTables(metadata, accounts, session_table(metadata, accounts.c.id))


class PostgresAccountStore:
    """A host's `SubjectUserStore` over the connection it is given."""

    def __init__(self, connection: Connection, accounts: Table) -> None:
        self._connection = connection
        self._accounts = accounts

    def get(self, user_id: str) -> FakeUser | None:
        row = self._connection.execute(
            select(self._accounts).where(self._accounts.c.id == user_id)
        ).one_or_none()
        return None if row is None else self._user(row)

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> FakeUser:
        row = self._connection.execute(
            insert(self._accounts)
            .values(id=subject, username=username, role=role, kind=kind.value)
            .returning(self._accounts)
        ).one()
        return self._user(row)

    def set_role(self, user_id: str, role: str) -> FakeUser:
        return self._changed(user_id, role=role)

    def set_kind(self, user_id: str, kind: AccountKind) -> FakeUser:
        return self._changed(user_id, kind=kind.value)

    def _changed(self, user_id: str, **values: str) -> FakeUser:
        row = self._connection.execute(
            update(self._accounts)
            .where(self._accounts.c.id == user_id)
            .values(**values)
            .returning(self._accounts)
        ).one_or_none()
        if row is None:
            raise LookupError(user_id)
        return self._user(row)

    @staticmethod
    def _user(row: Row[Any]) -> FakeUser:
        return FakeUser(id=row.id, username=row.username, role=row.role, kind=AccountKind(row.kind))


@dataclass(frozen=True)
class HostSignInTransaction:
    """The host's `SignInTransaction`: its own transaction around the extra's shell."""

    engine: Engine
    tables: HostTables
    audit: AuditSink = field(default_factory=RecordingAuditSink)

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return self._entry()

    @contextmanager
    def _entry(self) -> Iterator[SignInStores]:
        with database_errors_as_store_errors(), self.engine.begin() as connection:
            with sign_in_entry(
                connection,
                advisory_lock_key=SIGN_IN_LOCK_KEY,
                accounts=PostgresAccountStore(connection, self.tables.accounts),
                audit=self.audit,
                sessions_table=self.tables.sessions,
            ) as stores:
                yield stores


@dataclass(frozen=True)
class TransactionInAnotherProcess:
    """Builds, in any process, the host's transaction over the location's database."""

    location: DatabaseLocation

    def __call__(self) -> SignInTransaction:
        return HostSignInTransaction(self.location.engine(), a_hosts_tables())


class PostgresHost:
    """A host's stores and sign-in transaction over one test's schema.

    `accounts` and `sessions` write over a connection that commits each statement, as a store that
    applies each call; `transaction` opens the host's own transaction for each entry. The tables
    are created here, which a host's Alembic does."""

    def __init__(self, location: DatabaseLocation) -> None:
        self.location = location
        self.engine = location.engine()
        self.tables = a_hosts_tables()
        self.tables.metadata.create_all(self.engine)
        self._autocommit = self.engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        self.accounts = PostgresAccountStore(self._autocommit, self.tables.accounts)
        self.sessions = PostgresSessionStore(self._autocommit, self.accounts, self.tables.sessions)
        self.audit = RecordingAuditSink()
        self.transaction = HostSignInTransaction(self.engine, self.tables, self.audit)

    def close(self) -> None:
        self._autocommit.close()
        self.engine.dispose()

    def count_rows(self, table: Table) -> int:
        with self.engine.connect() as connection:
            return len(connection.execute(select(table)).all())
