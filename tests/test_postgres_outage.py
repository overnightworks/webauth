"""PGSTORE-07: the wrapper of the `postgres` extra raises `StoreUnavailableError` for evidence that
the database cannot be reached and `SessionStoreError` for every other database error, and hides
what either error was given."""

from __future__ import annotations

import psycopg.errors
import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import DBAPIError, InvalidRequestError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from tests.support.postgres_arrangement import what_a_log_shows_of
from webauth.ports import StoreUnavailableError
from webauth.postgres import SessionStoreError, database_errors_as_store_errors


def test_a_connection_that_cannot_open_is_an_outage_that_hides_its_credentials() -> None:
    """PGSTORE-07: a closed port is `StoreUnavailableError`."""
    unreachable = create_engine("postgresql+psycopg://nobody:secret@127.0.0.1:1/none")

    with (
        pytest.raises(StoreUnavailableError) as raised,
        database_errors_as_store_errors(),
        unreachable.begin(),
    ):
        pass

    assert "secret" not in what_a_log_shows_of(raised.value)


def a_driver_failure(error: Exception, *, connection_invalidated: bool = False) -> DBAPIError:
    """The error SQLAlchemy raises for `error`, as it wraps the driver's own classes."""
    wrapped = DBAPIError.instance(
        "SELECT 1",
        {"token": "secret"},
        error,
        psycopg.Error,
        connection_invalidated=connection_invalidated,
    )
    assert isinstance(wrapped, DBAPIError)
    return wrapped


OUTAGES = [
    pytest.param(a_driver_failure(psycopg.OperationalError("secret")), id="no-sqlstate"),
    *(
        pytest.param(a_driver_failure(connection_error("secret")), id=connection_error.__name__)
        for connection_error in [
            psycopg.errors.ConnectionException,
            psycopg.errors.SqlclientUnableToEstablishSqlconnection,
            psycopg.errors.ConnectionDoesNotExist,
            psycopg.errors.ConnectionFailure,
            psycopg.errors.ProtocolViolation,
        ]
    ),
    pytest.param(a_driver_failure(psycopg.errors.AdminShutdown("secret")), id="admin-shutdown"),
    pytest.param(a_driver_failure(psycopg.errors.CrashShutdown("secret")), id="crash-shutdown"),
    pytest.param(a_driver_failure(psycopg.errors.CannotConnectNow("secret")), id="starting-up"),
    pytest.param(
        a_driver_failure(psycopg.errors.SyntaxError("secret"), connection_invalidated=True),
        id="connection-invalidated",
    ),
    pytest.param(PoolTimeoutError("secret"), id="pool-timeout"),
]
STORE_ERRORS = [
    pytest.param(a_driver_failure(psycopg.errors.DeadlockDetected("secret")), id="deadlock"),
    pytest.param(
        a_driver_failure(psycopg.errors.SerializationFailure("secret")), id="serialization-failure"
    ),
    pytest.param(a_driver_failure(psycopg.errors.QueryCanceled("secret")), id="query-canceled"),
    pytest.param(a_driver_failure(psycopg.errors.UniqueViolation("secret")), id="unique-violation"),
    pytest.param(a_driver_failure(psycopg.errors.SyntaxError("secret")), id="syntax-error"),
    pytest.param(a_driver_failure(psycopg.InterfaceError("secret")), id="interface-error"),
]


@pytest.mark.parametrize("database_error", OUTAGES)
def test_the_wrapper_raises_an_outage_for_connection_evidence_and_hides_the_error(
    database_error: Exception,
) -> None:
    """PGSTORE-07."""
    with pytest.raises(StoreUnavailableError) as raised, database_errors_as_store_errors():
        raise database_error

    assert "secret" not in what_a_log_shows_of(raised.value)


@pytest.mark.parametrize("database_error", STORE_ERRORS)
def test_the_wrapper_raises_the_store_error_for_every_other_database_error_and_hides_it(
    database_error: DBAPIError,
) -> None:
    """PGSTORE-07: the text names the driver error's class and SQLSTATE, and nothing it bound."""
    driver_error = database_error.orig
    assert driver_error is not None

    with pytest.raises(SessionStoreError) as raised, database_errors_as_store_errors():
        raise database_error

    assert not isinstance(raised.value, StoreUnavailableError)
    shown = what_a_log_shows_of(raised.value)
    assert type(driver_error).__name__ in shown
    assert (getattr(driver_error, "sqlstate", None) or "") in shown
    assert "secret" not in shown


def test_a_sqlalchemy_error_that_is_no_pool_timeout_and_no_driver_error_is_no_outage() -> None:
    """PGSTORE-07: the database answered, so a misuse of the session is a store error."""
    with pytest.raises(SessionStoreError) as raised, database_errors_as_store_errors():
        raise InvalidRequestError("secret")

    assert not isinstance(raised.value, StoreUnavailableError)
    assert "secret" not in what_a_log_shows_of(raised.value)
