"""A host over a real Postgres: its accounts table and `SubjectUserStore`, its sign-in transaction
around the extra's shell, and the schema each test owns.

The accounts table follows what a host keeps; the extra owns only the session table."""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Final

import pytest
from pydantic import SecretStr
from sqlalchemy import Column, MetaData, Table, Text, create_engine, insert, select, text, update
from sqlalchemy.pool import QueuePool

from tests.support.account_arrangement import FakeUser
from tests.support.current_groups_arrangement import SESSION_ID, Arrangement, an_arrangement
from tests.support.oidc_arrangement import ISSUED_REFRESH_TOKEN
from tests.support.webauth_arrangement import RecordingAuditSink, a_web_auth_config
from webauth.ports import AccountKind, SignInStores, SignInTransaction
from webauth.postgres import (
    PostgresSessionStore,
    PostgresStoredKeySessions,
    database_errors_as_store_errors,
    delete_expired,
    session_table,
    sign_in_entry,
    stored_key,
)

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from sqlalchemy import Row
    from sqlalchemy.engine import Connection, Engine

    from webauth.config import WebAuthConfig
    from webauth.ports import AuditSink, SessionRecordStore

POSTGRES_URL_VARIABLE: Final = "WEBAUTH_TEST_POSTGRES_URL"
BLOCKED_BACKEND_DEADLINE_SECONDS: Final = 30
_LOCK_KEY_MASK: Final = 0x7FFFFFFF
"""A key below 2**31 is the `objid` of its `pg_locks` row, with `classid` 0."""


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
    that schema, so tests share one database and run in parallel. Its sign-in lock key is as much
    its own: an advisory lock belongs to the whole database, not to a schema."""

    url: str
    schema: str
    advisory_lock_key: int

    def engine(self) -> Engine:
        return create_engine(
            self.url,
            hide_parameters=True,
            connect_args={"options": f"-csearch_path={self.schema}"},
        )


@contextmanager
def a_schema_of_its_own(url: str) -> Iterator[DatabaseLocation]:
    identity = uuid.uuid4()
    location = DatabaseLocation(url, f"webauth_test_{identity.hex}", identity.int & _LOCK_KEY_MASK)
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
    advisory_lock_key: int
    audit: AuditSink = field(default_factory=RecordingAuditSink)

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return self._entry()

    @contextmanager
    def _entry(self) -> Iterator[SignInStores]:
        with database_errors_as_store_errors(), self.engine.begin() as connection:
            with sign_in_entry(
                connection,
                advisory_lock_key=self.advisory_lock_key,
                accounts=PostgresAccountStore(connection, self.tables.accounts),
                audit=self.audit,
                sessions_table=self.tables.sessions,
            ) as stores:
                yield stores


def a_stored_key_view(connection: Connection, tables: HostTables) -> PostgresStoredKeySessions:
    return PostgresStoredKeySessions(
        connection, PostgresAccountStore(connection, tables.accounts), tables.sessions
    )


@dataclass(frozen=True)
class HostStoredKeyTransaction:
    """The host's `SessionTransaction` over the stored-key view, one transaction per call."""

    engine: Engine
    tables: HostTables

    def __call__(self) -> AbstractContextManager[SessionRecordStore]:
        return self._entry()

    @contextmanager
    def _entry(self) -> Iterator[SessionRecordStore]:
        with database_errors_as_store_errors(), self.engine.begin() as connection:
            yield a_stored_key_view(connection, self.tables)


@dataclass(frozen=True)
class TransactionInAnotherProcess:
    """Builds, in any process, the host's transaction over the location's database."""

    location: DatabaseLocation

    def __call__(self) -> SignInTransaction:
        return HostSignInTransaction(
            self.location.engine(), a_hosts_tables(), self.location.advisory_lock_key
        )


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
        self.transaction = HostSignInTransaction(
            self.engine, self.tables, location.advisory_lock_key, self.audit
        )

    def close(self) -> None:
        self._autocommit.close()
        self.engine.dispose()

    def locks_held(self) -> int:
        """The advisory locks held on this host's sign-in key, by any backend of its database."""
        with self.engine.connect() as connection:
            return connection.execute(
                text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted"
                    " AND database = (SELECT oid FROM pg_database"
                    " WHERE datname = current_database())"
                    " AND classid = 0 AND objid = :key"
                ),
                {"key": self.location.advisory_lock_key},
            ).scalar_one()

    def sweep(self, now: datetime) -> int:
        """The host's expiry sweep: `delete_expired` in a transaction of its own."""
        with self.engine.begin() as connection:
            return delete_expired(connection, self.tables.sessions, now)

    def wait_until_blocked_by(self, connection: Connection) -> None:
        """Return once another backend waits for a lock that `connection` holds."""
        blocker = connection.execute(text("SELECT pg_backend_pid()")).scalar_one()
        deadline = time.monotonic() + BLOCKED_BACKEND_DEADLINE_SECONDS
        while not self._is_blocked_by(blocker):
            assert time.monotonic() < deadline, "no backend waits for the lock"

    def _is_blocked_by(self, blocker: int) -> bool:
        with self.engine.connect() as connection:
            return (
                connection.execute(
                    text(
                        "SELECT count(*) FROM pg_stat_activity"
                        " WHERE :blocker = ANY(pg_blocking_pids(pid))"
                    ),
                    {"blocker": blocker},
                ).scalar_one()
                > 0
            )

    def count_rows(self, table: Table) -> int:
        with self.engine.connect() as connection:
            return len(connection.execute(select(table)).all())


def a_stored_session(
    sessions: SessionRecordStore,
    subject: str,
    *,
    now: datetime | None = None,
    expires_at: datetime | None = None,
    session_id: str | None = None,
    refresh_token: str = "refresh-secret",  # noqa: S107
) -> str:
    """Creates a session with tokens and a language, and returns its id; unless told, it starts
    now and lives an hour."""
    started = datetime.now(UTC) if now is None else now
    identifier = uuid.uuid4().hex if session_id is None else session_id
    sessions.create(
        subject,
        session_id=identifier,
        now=started,
        expires_at=started + timedelta(hours=1) if expires_at is None else expires_at,
        refresh_token=SecretStr(refresh_token),
        id_token=SecretStr("identity-secret"),
        account_language="de",
    )
    return identifier


@dataclass(frozen=True)
class ExpirySweepScenario:
    """One deterministic instant at which a host sweeps and its session gate reads the clock.

    A session is created `SESSION_AGE` before the instant and expires at an offset from it, so the
    gate refuses it for its expiry alone; `sweep` and `gate_config` read the instant plus an offset
    for the fractions of a second a wall clock has."""

    host: PostgresHost
    instant: datetime = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
    session_age: timedelta = timedelta(minutes=30)

    def session(self, subject: str, *, expires_after: timedelta) -> str:
        return a_stored_session(
            self.host.sessions,
            subject,
            now=self.instant - self.session_age,
            expires_at=self.instant + expires_after,
        )

    def sweep(self, *, after: timedelta = timedelta(0)) -> int:
        return self.host.sweep(self.instant + after)

    def gate_config(self, *, after: timedelta = timedelta(0)) -> WebAuthConfig:
        return a_web_auth_config(wall_clock=lambda: (self.instant + after).timestamp())


@dataclass
class StoredKeyReads:
    """The session `an_arrangement` describes, stored in the host's table under its account, and
    the host's stored-key `SessionTransaction` on an engine of its own, whose pool shows whether a
    transaction is open."""

    host: PostgresHost
    groups: Arrangement
    engine: Engine
    transaction: HostStoredKeyTransaction
    stored_key: str

    @property
    def refresh_token(self) -> str | None:
        """What the table holds, read through the raw id the cookie carries."""
        record = self.host.sessions.load(SESSION_ID)
        return (
            None
            if record is None or record.refresh_token is None
            else record.refresh_token.get_secret_value()
        )

    @property
    def connections_checked_out(self) -> int:
        assert isinstance(self.engine.pool, QueuePool)
        return self.engine.pool.checkedout()


def stored_key_reads_of(host: PostgresHost) -> StoredKeyReads:
    groups = an_arrangement()
    record = groups.sessions.load(SESSION_ID)
    assert record is not None
    host.accounts.create_for_subject(
        record.user.id, record.user.username, record.user.role, record.user.kind
    )
    a_stored_session(
        host.sessions,
        record.user.id,
        now=record.created_at,
        expires_at=record.expires_at,
        session_id=SESSION_ID,
        refresh_token=ISSUED_REFRESH_TOKEN,
    )
    engine = host.location.engine()
    return StoredKeyReads(
        host,
        groups,
        engine,
        HostStoredKeyTransaction(engine, host.tables),
        stored_key(SESSION_ID),
    )
