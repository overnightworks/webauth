"""The `postgres` extra keeps the session half of the ports over a real Postgres, as the host's
transaction around it commits or rolls back."""

from __future__ import annotations

import traceback
import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from operator import attrgetter

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.operations import Operations
from pydantic import SecretStr
from sqlalchemy import (
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    MetaData,
    Table,
    Text,
    create_engine,
    select,
    text,
)
from sqlalchemy.engine import Connection
from sqlalchemy.exc import OperationalError

from tests.support.postgres_arrangement import (
    ExpirySweepScenario,
    HostSignInTransaction,
    PostgresAccountStore,
    PostgresHost,
    TransactionInAnotherProcess,
    a_hosts_tables,
    a_schema_of_its_own,
    postgres_url,
)
from tests.support.webauth_arrangement import a_web_auth_config
from webauth.dependencies import ConnectionRefusal, admit_session
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AccountKind,
    SessionRecordStore,
    UsernameTakenError,
)
from webauth.postgres import (
    PostgresSessionStore,
    SessionStoreError,
    database_errors_as_store_errors,
    delete_expired,
)
from webauth.store_contract import STORE_CHECKS, StoreAdapter, StoreCheck

# SHA-256 of "abc", the published test vector of FIPS 180-2.
ABC_DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

EXPIRED_SESSIONS_PER_SWEEP = 25
ONE_SECOND = timedelta(seconds=1)


class BlockFailed(Exception):
    pass


class AuditFailed(Exception):
    pass


class FailingAudit:
    def account_event(self, event: AccountEvent) -> None:
        raise AuditFailed


class KnowsNoAccounts(PostgresAccountStore):
    def get(self, user_id: str) -> None:
        return None


class AccountReadFails(PostgresAccountStore):
    def get(self, user_id: str) -> None:
        raise OperationalError("SELECT 1", {"id": user_id}, Exception("secret detail"))


@pytest.fixture
def host() -> Iterator[PostgresHost]:
    with a_schema_of_its_own(postgres_url()) as location:
        arranged = PostgresHost(location)
        try:
            yield arranged
        finally:
            arranged.close()


def a_session(sessions: SessionRecordStore, subject: str, session_id: str | None = None) -> str:
    now = datetime.now(UTC)
    identifier = uuid.uuid4().hex if session_id is None else session_id
    sessions.create(
        subject,
        session_id=identifier,
        now=now,
        expires_at=now + timedelta(hours=1),
        refresh_token=SecretStr("refresh-secret"),
        id_token=SecretStr("identity-secret"),
        account_language="de",
    )
    return identifier


def what_a_log_shows_of(error: SessionStoreError) -> str:
    """The error as a traceback prints it, without the source lines of the frames: its own text
    and, unless the error hides it, the error it replaced."""
    shown = "".join(traceback.format_exception_only(error)) + repr(error)
    if not error.__suppress_context__ and error.__context__ is not None:
        shown += "".join(traceback.format_exception_only(error.__context__))
    return shown


def an_account(host: PostgresHost) -> str:
    subject = str(uuid.uuid4())
    host.accounts.create_for_subject(subject, subject, "user", AccountKind.PERSON)
    return subject


@pytest.mark.parametrize("check", STORE_CHECKS, ids=attrgetter("name"))
def test_the_extra_passes_every_store_check(check: StoreCheck, host: PostgresHost) -> None:
    """PGSTORE-02, PGSTORE-04, PGSTORE-06: the extra keeps every duty of the ports."""
    check.run(
        StoreAdapter(
            accounts=host.accounts,
            sessions=host.sessions,
            transaction=host.transaction,
            transaction_in_another_process=TransactionInAnotherProcess(host.location),
        )
    )


def test_a_block_that_raises_leaves_no_session_and_no_account(host: PostgresHost) -> None:
    """PGSTORE-02: the host's rollback takes the block's writes with it."""

    def sign_in_and_raise() -> None:
        with host.transaction() as stores:
            subject = str(uuid.uuid4())
            stores.accounts.create_for_subject(subject, subject, "user", AccountKind.PERSON)
            a_session(stores.sessions, subject)
            raise BlockFailed

    with pytest.raises(BlockFailed):
        sign_in_and_raise()

    assert host.count_rows(host.tables.sessions) == 0
    assert host.count_rows(host.tables.accounts) == 0


def test_an_audit_sink_that_fails_leaves_no_session_and_raises_its_own_error(
    host: PostgresHost,
) -> None:
    """PGSTORE-03: a failing sink fails the entry."""
    transaction = HostSignInTransaction(
        host.engine, host.tables, host.location.advisory_lock_key, FailingAudit()
    )

    def sign_in_with_an_event() -> None:
        with transaction() as stores:
            subject = str(uuid.uuid4())
            stores.accounts.create_for_subject(subject, subject, "user", AccountKind.PERSON)
            a_session(stores.sessions, subject)
            stores.audit.account_event(
                AccountEvent(AccountEventKind.USER_CREATED, None, subject, role="user")
            )

    with pytest.raises(AuditFailed):
        sign_in_with_an_event()

    assert host.count_rows(host.tables.sessions) == 0
    assert host.count_rows(host.tables.accounts) == 0


def test_a_failing_commit_leaves_no_session_and_raises_the_store_error(host: PostgresHost) -> None:
    """PGSTORE-07: a commit the database refuses leaves no row."""
    subject = an_account(host)
    with host.engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE sessions ADD CONSTRAINT one_session_per_account"
                " UNIQUE (account_id) DEFERRABLE INITIALLY DEFERRED"
            )
        )

    def sign_in_twice() -> None:
        with host.transaction() as stores:
            a_session(stores.sessions, subject)
            a_session(stores.sessions, subject)

    with pytest.raises(SessionStoreError):
        sign_in_twice()

    assert host.count_rows(host.tables.sessions) == 0


def test_the_audit_reaches_the_hosts_sink_after_the_block_and_from_no_failed_block(
    host: PostgresHost,
) -> None:
    """PGSTORE-03: the events wait for the end of the block."""
    subject = str(uuid.uuid4())
    event = AccountEvent(AccountEventKind.USER_CREATED, None, subject, role="user")

    with pytest.raises(BlockFailed), host.transaction() as stores:
        stores.audit.account_event(event)
        raise BlockFailed
    assert host.audit.account_events == []

    with host.transaction() as stores:
        stores.audit.account_event(event)
        assert host.audit.account_events == []

    assert host.audit.account_events == [event]


def test_deleting_an_account_ends_its_sessions_and_ending_a_session_keeps_the_account(
    host: PostgresHost,
) -> None:
    """PGSTORE-06."""
    subject = an_account(host)
    ended = a_session(host.sessions, subject)
    kept = a_session(host.sessions, subject)

    host.sessions.delete(ended)

    assert host.accounts.get(subject) is not None
    assert host.sessions.load(kept) is not None
    with host.engine.begin() as connection:
        connection.execute(host.tables.accounts.delete())
    assert host.count_rows(host.tables.sessions) == 0


@pytest.fixture
def scenario(host: PostgresHost) -> ExpirySweepScenario:
    return ExpirySweepScenario(host)


def test_the_sweep_deletes_the_expired_sessions_and_keeps_the_others_and_the_accounts(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-09: a session expires when its expiry lies before now, as the gate reads it."""
    subject = an_account(host)
    expired = [
        scenario.session(subject, expires_after=-ONE_SECOND),
        scenario.session(subject, expires_after=-timedelta(days=30)),
    ]
    kept = [
        scenario.session(subject, expires_after=timedelta(0)),
        scenario.session(subject, expires_after=ONE_SECOND),
    ]

    deleted = scenario.sweep()

    assert deleted == len(expired)
    assert [host.sessions.load(session_id) is None for session_id in expired + kept] == [
        True,
        True,
        False,
        False,
    ]
    assert host.accounts.get(subject) is not None


def test_a_sweep_within_the_second_of_an_expiry_keeps_the_session_the_gate_admits(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-09: the gate reads its clock in whole seconds, so the sweep does too."""
    fraction = timedelta(milliseconds=500)
    session_id = scenario.session(an_account(host), expires_after=timedelta(0))

    deleted = scenario.sweep(after=fraction)
    admitted = admit_session(
        session_id, sessions=host.sessions, config=scenario.gate_config(after=fraction)
    )

    assert deleted == 0
    assert not isinstance(admitted, ConnectionRefusal)


def test_a_repeated_sweep_deletes_nothing(host: PostgresHost, scenario: ExpirySweepScenario) -> None:
    """PGSTORE-09."""
    scenario.session(an_account(host), expires_after=-ONE_SECOND)
    scenario.sweep()

    assert scenario.sweep() == 0


def test_load_returns_an_expired_session_the_gate_refuses_until_a_sweep_ends_it(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-05, PGSTORE-09."""
    session_id = scenario.session(an_account(host), expires_after=-ONE_SECOND)

    loaded = host.sessions.load(session_id)
    refused = admit_session(session_id, sessions=host.sessions, config=scenario.gate_config())
    scenario.sweep()

    assert loaded is not None
    assert refused is ConnectionRefusal.SESSION_ENDED_OR_EXPIRED
    assert host.sessions.load(session_id) is None


def test_two_sweeps_at_once_leave_no_expired_session_and_delete_each_one_once(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-09: the second sweep waits for the first's transaction, then finds nothing left."""
    subject = an_account(host)
    for _ in range(EXPIRED_SESSIONS_PER_SWEEP):
        scenario.session(subject, expires_after=-ONE_SECOND)
    kept = scenario.session(subject, expires_after=ONE_SECOND)

    with host.engine.connect() as first, ThreadPoolExecutor(max_workers=1) as other_pod:
        with first.begin():
            deleted_by_first = delete_expired(first, host.tables.sessions, scenario.instant)
            second = other_pod.submit(scenario.sweep)
            host.wait_until_blocked_by(first)
        deleted_by_second = second.result()

    assert (deleted_by_first, deleted_by_second) == (EXPIRED_SESSIONS_PER_SWEEP, 0)
    assert host.count_rows(host.tables.sessions) == 1
    assert host.sessions.load(kept) is not None


def test_a_sweep_that_a_rollback_undoes_leaves_the_expired_sessions_for_the_next_sweep(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-09: the host retries a failed sweep in a fresh transaction."""
    scenario.session(an_account(host), expires_after=-ONE_SECOND)

    with host.engine.connect() as connection:
        with connection.begin() as transaction:
            deleted_in_the_failed_one = delete_expired(
                connection, host.tables.sessions, scenario.instant
            )
            transaction.rollback()

    assert (deleted_in_the_failed_one, scenario.sweep()) == (1, 1)


def test_a_failed_sweep_raises_the_store_error_with_nothing_of_its_statement(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-07, PGSTORE-09."""
    unmigrated = Table("unmigrated", MetaData(), Column("expires_at", DateTime(timezone=True)))

    with host.engine.connect() as connection, pytest.raises(SessionStoreError) as raised:
        delete_expired(connection, unmigrated, scenario.instant)

    shown = what_a_log_shows_of(raised.value)
    assert "unmigrated" not in shown
    assert str(scenario.instant) not in shown
    assert scenario.instant.isoformat() not in shown


def test_an_entry_holds_the_advisory_lock_from_its_enter_until_its_exit(
    host: PostgresHost,
) -> None:
    """PGSTORE-03: the lock is held before the first store call."""
    with host.transaction():
        held_inside = host.locks_held()

    assert (held_inside, host.locks_held()) == (1, 0)


def test_an_entry_of_another_host_holds_nothing_on_this_hosts_lock_key(
    host: PostgresHost,
) -> None:
    """The lock key is the host's own, so parallel tests share no lock."""
    with a_schema_of_its_own(postgres_url()) as other_location:
        other = PostgresHost(other_location)
        try:
            with other.transaction():
                held_by_another = host.locks_held()
        finally:
            other.close()

    assert held_by_another == 0


def test_a_session_is_stored_under_the_hash_of_its_id_and_handed_back_under_its_id(
    host: PostgresHost,
) -> None:
    """PGSTORE-04."""
    subject = an_account(host)
    now = datetime.now(UTC)

    created = host.sessions.create(
        subject,
        session_id="abc",
        now=now,
        expires_at=now + timedelta(hours=1),
        refresh_token=SecretStr("refresh-secret"),
        id_token=None,
        account_language=None,
    )

    with host.engine.connect() as connection:
        (stored,) = connection.execute(select(host.tables.sessions)).all()
    loaded = host.sessions.load("abc")
    assert (created.id, loaded and loaded.id) == ("abc", "abc")
    assert stored.id_hash == ABC_DIGEST
    assert "abc" not in {value for value in stored if isinstance(value, str)}
    assert host.sessions.load(ABC_DIGEST) is None
    assert "refresh-secret" not in repr(created)


def test_touch_and_a_replaced_refresh_token_persist_and_keep_the_other_fields(
    host: PostgresHost,
) -> None:
    """PGSTORE-04: `touch` changes only the expiry, `replace_refresh_token` only the token."""
    session_id = a_session(host.sessions, an_account(host))
    before = host.sessions.load(session_id)
    assert before is not None
    later = before.expires_at + timedelta(hours=2)

    assert host.sessions.touch(session_id, expires_at=later)
    touched = host.sessions.load(session_id)
    assert host.sessions.replace_refresh_token(session_id, refresh_token=SecretStr("replacement"))
    replaced = host.sessions.load(session_id)

    assert touched is not None
    assert replaced is not None
    assert touched.expires_at == later
    assert touched.refresh_token == before.refresh_token
    assert replaced.refresh_token == SecretStr("replacement")
    assert (replaced.expires_at, replaced.id_token, replaced.account_language) == (
        later,
        before.id_token,
        before.account_language,
    )


def test_a_failed_call_raises_the_store_error_with_nothing_of_its_parameters(
    host: PostgresHost,
) -> None:
    """PGSTORE-07."""
    subject = an_account(host)
    a_session(host.sessions, subject, session_id="abc")

    with pytest.raises(SessionStoreError) as raised:
        a_session(host.sessions, subject, session_id="abc")

    shown = what_a_log_shows_of(raised.value)
    for private in ("abc", ABC_DIGEST, subject, "refresh-secret", "identity-secret"):
        assert private not in shown


def test_a_session_whose_account_the_hosts_store_no_longer_knows_loads_as_none(
    host: PostgresHost,
) -> None:
    """PGSTORE-05."""
    session_id = a_session(host.sessions, an_account(host))

    with host.engine.connect() as connection:
        store = PostgresSessionStore(
            connection, KnowsNoAccounts(connection, host.tables.accounts), host.tables.sessions
        )
        assert store.load(session_id) is None


def create_a_session(store: PostgresSessionStore, subject: str, session_id: str) -> None:
    a_session(store, subject)


def load_a_session(store: PostgresSessionStore, subject: str, session_id: str) -> None:
    store.load(session_id)


@pytest.mark.parametrize("call", [create_a_session, load_a_session], ids=attrgetter("__name__"))
def test_a_failed_account_read_raises_the_store_error(
    call: Callable[[PostgresSessionStore, str, str], None], host: PostgresHost
) -> None:
    """PGSTORE-07: the host's account read inside a store call is a store call's failure."""
    subject = an_account(host)
    session_id = a_session(host.sessions, subject)
    with host.engine.connect() as connection:
        store = PostgresSessionStore(
            connection, AccountReadFails(connection, host.tables.accounts), host.tables.sessions
        )
        with pytest.raises(SessionStoreError) as raised:
            call(store, subject, session_id)

    assert "secret" not in what_a_log_shows_of(raised.value)


def test_a_connection_that_cannot_open_raises_the_store_error() -> None:
    """PGSTORE-07."""
    unreachable = create_engine("postgresql+psycopg://nobody:secret@127.0.0.1:1/none")

    with (
        pytest.raises(SessionStoreError) as raised,
        database_errors_as_store_errors(),
        unreachable.begin(),
    ):
        pass

    assert "secret" not in what_a_log_shows_of(raised.value)


@pytest.mark.parametrize("error", [UsernameTakenError("taken"), BlockFailed()])
def test_the_wrapper_passes_every_other_exception_unchanged(error: Exception) -> None:
    """PGSTORE-07."""
    with pytest.raises(type(error)) as raised, database_errors_as_store_errors():
        raise error

    assert raised.value is error


def test_the_wrapper_hides_the_database_error_it_replaces() -> None:
    """PGSTORE-07."""
    database_error = OperationalError("SELECT 1", {"token": "secret"}, Exception("secret detail"))

    with pytest.raises(SessionStoreError) as raised, database_errors_as_store_errors():
        raise database_error

    assert "secret" not in what_a_log_shows_of(raised.value)


def apply_the_session_migration(connection: Connection) -> None:
    """The accounts and sessions tables as an Alembic migration creates them."""
    with Operations.context(MigrationContext.configure(connection)) as migration:
        migration.create_table(
            "accounts",
            Column("id", Text(), primary_key=True),
            Column("username", Text(), nullable=False),
            Column("role", Text(), nullable=False),
            Column("kind", Text(), nullable=False),
            CheckConstraint("kind IN ('person', 'agent')", name="accounts_kind_is_a_kind"),
        )
        migration.create_table(
            "sessions",
            Column("id_hash", Text(), primary_key=True),
            Column(
                "account_id", Text(), ForeignKey("accounts.id", ondelete="CASCADE"), nullable=False
            ),
            Column("created_at", DateTime(timezone=True), nullable=False),
            Column("expires_at", DateTime(timezone=True), nullable=False),
            Column("refresh_token", Text()),
            Column("id_token", Text()),
            Column("account_language", Text()),
        )
        migration.create_index(
            "sessions_account_created_at", "sessions", ["account_id", "created_at"]
        )
        migration.create_index("sessions_expires_at", "sessions", ["expires_at"])


def test_an_alembic_autogenerate_against_the_migrated_session_table_shows_no_difference() -> None:
    """PGSTORE-01."""
    with a_schema_of_its_own(postgres_url()) as location:
        engine = location.engine()
        try:
            with engine.begin() as connection:
                apply_the_session_migration(connection)
                differences = compare_metadata(
                    MigrationContext.configure(connection), a_hosts_tables().metadata
                )
        finally:
            engine.dispose()

    assert differences == []
