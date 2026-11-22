"""The `postgres` extra keeps the session half of the ports over a real Postgres, as the host's
transaction around it commits or rolls back."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime, timedelta
from operator import attrgetter

import psycopg.errors
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
from sqlalchemy.exc import ProgrammingError

from tests.support.current_groups_arrangement import GROUPS, SESSION_ENDED, SESSION_ID
from tests.support.oidc_arrangement import ISSUED_REFRESH_TOKEN
from tests.support.postgres_arrangement import (
    ExpirySweepScenario,
    HostSignInTransaction,
    PostgresAccountStore,
    PostgresHost,
    StoredKeyReads,
    TransactionInAnotherProcess,
    a_hosts_tables,
    a_schema_of_its_own,
    a_stored_key_view,
    a_stored_session,
    postgres_url,
    stored_key_reads_of,
    what_a_log_shows_of,
)
from webauth.dependencies import ConnectionRefusal, admit_session
from webauth.oidc_login import AccessTokenRefusal, current_groups, fresh_access_token
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AccountKind,
    StoreUnavailableError,
    UsernameTakenError,
)
from webauth.postgres import (
    PostgresSessionStore,
    SessionStoreError,
    database_errors_as_store_errors,
    delete_expired,
    stored_key,
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
        raise ProgrammingError("SELECT 1", {"id": user_id}, Exception("secret detail"))


@pytest.fixture
def host() -> Iterator[PostgresHost]:
    with a_schema_of_its_own(postgres_url()) as location:
        arranged = PostgresHost(location)
        try:
            yield arranged
        finally:
            arranged.close()


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
            a_stored_session(stores.sessions, subject)
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
            a_stored_session(stores.sessions, subject)
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
            a_stored_session(stores.sessions, subject)
            a_stored_session(stores.sessions, subject)

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
    ended = a_stored_session(host.sessions, subject)
    kept = a_stored_session(host.sessions, subject)

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


def test_a_repeated_sweep_deletes_nothing(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
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

    revealing_engine = create_engine(
        host.location.url, connect_args={"options": f"-csearch_path={host.location.schema}"}
    )
    try:
        with revealing_engine.connect() as connection, pytest.raises(SessionStoreError) as raised:
            delete_expired(connection, unmigrated, scenario.instant)
    finally:
        revealing_engine.dispose()

    shown = what_a_log_shows_of(raised.value)
    assert "unmigrated" not in shown
    assert "[SQL" not in shown
    assert repr(scenario.instant) not in shown


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
    session_id = a_stored_session(host.sessions, an_account(host))
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
    a_stored_session(host.sessions, subject, session_id="abc")

    with pytest.raises(SessionStoreError) as raised:
        a_stored_session(host.sessions, subject, session_id="abc")

    shown = what_a_log_shows_of(raised.value)
    for private in ("abc", ABC_DIGEST, subject, "refresh-secret", "identity-secret"):
        assert private not in shown
    assert psycopg.errors.UniqueViolation.__name__ in shown
    assert (psycopg.errors.UniqueViolation.sqlstate or "") in shown


AWARENESS = pytest.mark.parametrize(
    "aware", [True, False], ids=["aware instant accepted", "naive instant refused"]
)


def an_instant(instant: datetime, *, aware: bool) -> datetime:
    return instant if aware else instant.replace(tzinfo=None)


def refusal_unless(aware: bool) -> AbstractContextManager[object]:
    return nullcontext() if aware else pytest.raises(ValueError)


@AWARENESS
@pytest.mark.parametrize("naive_field", ["now", "expires_at"])
def test_create_refuses_a_naive_instant_and_stores_no_row(
    host: PostgresHost, scenario: ExpirySweepScenario, aware: bool, naive_field: str
) -> None:
    """PGSTORE-09."""
    subject = an_account(host)
    instants = {"now": scenario.instant, "expires_at": scenario.instant + timedelta(hours=1)}
    instants[naive_field] = an_instant(instants[naive_field], aware=aware)

    with refusal_unless(aware):
        host.sessions.create(
            subject,
            session_id="abc",
            refresh_token=None,
            id_token=None,
            account_language=None,
            **instants,
        )

    assert host.count_rows(host.tables.sessions) == int(aware)


@AWARENESS
def test_touch_refuses_a_naive_expiry_and_changes_no_row(
    host: PostgresHost, scenario: ExpirySweepScenario, aware: bool
) -> None:
    """PGSTORE-09."""
    session_id = scenario.session(an_account(host), expires_after=timedelta(hours=1))
    later = an_instant(scenario.instant + timedelta(hours=2), aware=aware)

    with refusal_unless(aware):
        host.sessions.touch(session_id, expires_at=later)

    stored = host.sessions.load(session_id)
    assert stored is not None
    assert stored.expires_at == (
        scenario.instant + timedelta(hours=2) if aware else scenario.instant + timedelta(hours=1)
    )


@AWARENESS
def test_the_sweep_refuses_a_naive_now_and_deletes_no_row(
    host: PostgresHost, scenario: ExpirySweepScenario, aware: bool
) -> None:
    """PGSTORE-09."""
    scenario.session(an_account(host), expires_after=-ONE_SECOND)

    with refusal_unless(aware):
        host.sweep(an_instant(scenario.instant, aware=aware))

    assert host.count_rows(host.tables.sessions) == int(not aware)


def test_a_session_whose_account_the_hosts_store_no_longer_knows_loads_as_none(
    host: PostgresHost,
) -> None:
    """PGSTORE-05."""
    session_id = a_stored_session(host.sessions, an_account(host))

    with host.engine.connect() as connection:
        store = PostgresSessionStore(
            connection, KnowsNoAccounts(connection, host.tables.accounts), host.tables.sessions
        )
        assert store.load(session_id) is None


def create_a_session(store: PostgresSessionStore, subject: str, session_id: str) -> None:
    a_stored_session(store, subject)


def load_a_session(store: PostgresSessionStore, subject: str, session_id: str) -> None:
    store.load(session_id)


@pytest.mark.parametrize("call", [create_a_session, load_a_session], ids=attrgetter("__name__"))
def test_a_failed_account_read_raises_the_store_error(
    call: Callable[[PostgresSessionStore, str, str], None], host: PostgresHost
) -> None:
    """PGSTORE-07: the host's account read inside a store call is a store call's failure."""
    subject = an_account(host)
    session_id = a_stored_session(host.sessions, subject)
    with host.engine.connect() as connection:
        store = PostgresSessionStore(
            connection, AccountReadFails(connection, host.tables.accounts), host.tables.sessions
        )
        with pytest.raises(SessionStoreError) as raised:
            call(store, subject, session_id)

    assert "secret" not in what_a_log_shows_of(raised.value)


def test_a_connection_ended_by_the_server_mid_transaction_is_an_outage(host: PostgresHost) -> None:
    """PGSTORE-07: `pg_terminate_backend` on the host's connection is `StoreUnavailableError`."""
    with host.engine.connect() as connection:
        store = PostgresSessionStore(
            connection, PostgresAccountStore(connection, host.tables.accounts), host.tables.sessions
        )
        store.load("abc")
        host.terminate_the_backend_of(connection)

        with pytest.raises(StoreUnavailableError):
            store.load("abc")


@pytest.mark.parametrize("error", [UsernameTakenError("taken"), BlockFailed()])
def test_the_wrapper_passes_every_other_exception_unchanged(error: Exception) -> None:
    """PGSTORE-07."""
    with pytest.raises(type(error)) as raised, database_errors_as_store_errors():
        raise error

    assert raised.value is error


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


def test_the_stored_key_is_the_sha256_hex_digest_of_the_session_id() -> None:
    """PGSTORE-10."""
    assert stored_key("abc") == ABC_DIGEST


def test_the_stored_key_view_reads_and_changes_the_row_under_its_stored_key(
    host: PostgresHost, scenario: ExpirySweepScenario
) -> None:
    """PGSTORE-10, PGSTORE-11: the view finds the row the raw-keyed store keeps and answers the
    stored key as the record's id, and a raw id finds nothing in it."""
    session_id = scenario.session(an_account(host), expires_after=timedelta(hours=1))
    key = stored_key(session_id)
    later = scenario.instant + timedelta(days=2)

    with host.engine.begin() as connection:
        view = a_stored_key_view(connection, host.tables)
        loaded = view.load(key)
        raw_id_found = view.load(session_id)
        touched = view.touch(key, expires_at=later)
        replaced = view.replace_refresh_token(key, refresh_token=SecretStr("replacement"))

    after = host.sessions.load(session_id)
    assert loaded is not None
    assert loaded.id == key
    assert raw_id_found is None
    assert (touched, replaced) == (True, True)
    assert after is not None
    assert (after.expires_at, after.refresh_token) == (later, SecretStr("replacement"))


@pytest.fixture
def reads(host: PostgresHost) -> Iterator[StoredKeyReads]:
    arranged = stored_key_reads_of(host)
    try:
        yield arranged
    finally:
        arranged.engine.dispose()


def read_groups(reads: StoredKeyReads, session_id: str) -> object:
    return current_groups(
        reads.groups.relying_party,
        session_id,
        session_transaction=reads.transaction,
        config=reads.groups.config,
    )


def read_an_access_token(reads: StoredKeyReads, session_id: str) -> object:
    return fresh_access_token(
        reads.groups.relying_party,
        session_id,
        session_transaction=reads.transaction,
        config=reads.groups.config,
    )


BACKGROUND_READS = pytest.mark.parametrize(
    "read", [read_groups, read_an_access_token], ids=attrgetter("__name__")
)


def test_current_groups_reads_the_groups_of_a_session_named_by_its_stored_key(
    reads: StoredKeyReads,
) -> None:
    """PGSTORE-11."""
    assert read_groups(reads, reads.stored_key) == tuple(GROUPS)


def test_fresh_access_token_reads_a_token_for_a_session_named_by_its_stored_key(
    reads: StoredKeyReads,
) -> None:
    """PGSTORE-11."""
    reads.groups.answer_with_access_token()

    token = read_an_access_token(reads, reads.stored_key)

    assert token == SecretStr(reads.groups.answered_tokens[-1])


@BACKGROUND_READS
def test_a_rotated_refresh_token_is_stored_under_the_original_stored_key(
    reads: StoredKeyReads, read: Callable[[StoredKeyReads, str], object]
) -> None:
    """PGSTORE-11: a rotation replaces the token in the row and adds none, and a later read
    through the view presents the rotated token."""
    read(reads, reads.stored_key)
    rotated = reads.refresh_token

    read(reads, reads.stored_key)

    assert rotated in reads.groups.issuer.refresh_tokens - {ISSUED_REFRESH_TOKEN}
    assert reads.groups.issuer.requests[-1].form["refresh_token"] == rotated
    assert reads.host.count_rows(reads.host.tables.sessions) == 1


@BACKGROUND_READS
def test_a_session_deleted_during_the_grant_is_session_ended_and_never_recreated(
    reads: StoredKeyReads, read: Callable[[StoredKeyReads, str], object]
) -> None:
    """PGSTORE-11."""
    reads.groups.issuer.before_exchange = lambda: reads.host.sessions.delete(SESSION_ID)

    assert read(reads, reads.stored_key) == SESSION_ENDED
    assert reads.host.count_rows(reads.host.tables.sessions) == 0


@BACKGROUND_READS
def test_no_connection_of_the_host_is_out_while_the_issuer_is_asked(
    reads: StoredKeyReads, read: Callable[[StoredKeyReads, str], object]
) -> None:
    """PGSTORE-11: the two host transactions are separate, with none open during the grant."""
    checked_out_during_grant: list[int] = []
    reads.groups.issuer.before_exchange = lambda: checked_out_during_grant.append(
        reads.connections_checked_out
    )

    outcome = read(reads, reads.stored_key)

    assert not isinstance(outcome, AccessTokenRefusal)
    assert checked_out_during_grant == [0]


@BACKGROUND_READS
def test_a_raw_session_id_finds_no_session_through_the_stored_key_view(
    reads: StoredKeyReads, read: Callable[[StoredKeyReads, str], object]
) -> None:
    """PGSTORE-11: one store never accepts both key forms."""
    assert read(reads, SESSION_ID) == SESSION_ENDED
    assert reads.groups.requests_made == 0
