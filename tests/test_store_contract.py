"""The store contract kit passes an adapter that keeps the ports' duties and refuses broken ones."""

from __future__ import annotations

import pickle
from collections.abc import Callable
from operator import attrgetter
from pathlib import Path

import pytest

from tests.support.store_contract_arrangement import (
    BROKEN_ADAPTERS,
    FailsOnExit,
    FailsToBuild,
    FailsToEnter,
    a_correct_single_process_adapter,
    a_file_locked_adapter,
    a_session_adapter_that_changes_the_row_before_refusing,
    an_adapter_with_a_closed_role_type,
    an_adapter_with_columns_that_fit_only_webauths_ids,
    an_adapter_with_other_process,
    an_adapter_with_unique_usernames,
)
from webauth.ports import SignInTransaction
from webauth.store_contract import STORE_CHECKS, StoreAdapter, StoreCheck

CROSS_PROCESS_CHECKS = [check for check in STORE_CHECKS if check.crosses_processes]
IN_PROCESS_CHECKS = [check for check in STORE_CHECKS if not check.crosses_processes]


def test_every_check_is_paired_with_one_broken_adapter() -> None:
    """STORECHECK-01: every check has a broken adapter it refuses."""
    names = [check.name for check in STORE_CHECKS]

    assert len(set(names)) == len(names)
    assert set(BROKEN_ADAPTERS) == set(names)


@pytest.mark.parametrize(
    "build_adapter",
    [
        a_correct_single_process_adapter,
        an_adapter_with_unique_usernames,
        an_adapter_with_a_closed_role_type,
        an_adapter_with_columns_that_fit_only_webauths_ids,
    ],
)
@pytest.mark.parametrize("check", IN_PROCESS_CHECKS, ids=attrgetter("name"))
def test_a_correct_adapter_passes_every_in_process_check(
    check: StoreCheck, build_adapter: Callable[[], StoreAdapter]
) -> None:
    """STORECHECK-01, STORECHECK-02, STORECHECK-03, MEMSTORE-02, MEMSTORE-03, MEMSTORE-05,
    MEMSTORE-08: whatever a correct adapter arranges differently, a check gives each account a unique username and a role webauth writes, mints
    subjects of a uuid's length and session ids of sign-in's."""
    check.run(build_adapter())


def test_the_file_lock_adapter_passes_the_cross_process_check(tmp_path: Path) -> None:
    """STORECHECK-04, STORECHECK-05: a lock that spans processes passes the cross-process check."""
    (check,) = CROSS_PROCESS_CHECKS

    check.run(a_file_locked_adapter(tmp_path / "sign-in.lock"))


@pytest.mark.parametrize("check", STORE_CHECKS, ids=attrgetter("name"))
def test_each_check_refuses_its_broken_adapter(check: StoreCheck) -> None:
    """STORECHECK-01, STORECHECK-03, STORECHECK-04: a broken adapter fails its check."""
    broken_adapter = BROKEN_ADAPTERS[check.name]()

    with pytest.raises(AssertionError):
        check.run(broken_adapter)


def test_a_refused_create_that_changed_any_field_of_the_row_fails_the_check() -> None:
    """STORECHECK-03: a refused create leaves the whole stored row unchanged."""
    (check,) = (c for c in IN_PROCESS_CHECKS if c.name == "a_stored_id_is_refused_and_its_row_kept")

    adapter = a_session_adapter_that_changes_the_row_before_refusing()

    with pytest.raises(AssertionError):
        check.run(adapter)


@pytest.mark.parametrize(
    "factory",
    [FailsToBuild(), FailsToEnter()],
    ids=["cannot-build", "cannot-enter"],
)
def test_the_cross_process_check_fails_loud_when_the_other_process_cannot_serve(
    factory: Callable[[], SignInTransaction],
    tmp_path: Path,
) -> None:
    """STORECHECK-04: the second process must reach its entry and call the store."""
    (check,) = CROSS_PROCESS_CHECKS

    adapter = an_adapter_with_other_process(factory, tmp_path / "sign-in.lock")

    with pytest.raises(AssertionError):
        check.run(adapter)


def test_the_cross_process_check_fails_loud_when_the_other_process_cannot_leave_its_entry(
    tmp_path: Path,
) -> None:
    """STORECHECK-04: the second process must leave its entry cleanly."""
    (check,) = CROSS_PROCESS_CHECKS
    lock_path = tmp_path / "sign-in.lock"

    adapter = an_adapter_with_other_process(FailsOnExit(lock_path), lock_path)

    with pytest.raises(AssertionError):
        check.run(adapter)


def test_an_unpicklable_transaction_factory_surfaces_its_own_error(tmp_path: Path) -> None:
    """STORECHECK-04: a factory the second process cannot receive raises its own error."""
    (check,) = CROSS_PROCESS_CHECKS
    adapter = an_adapter_with_other_process(lambda: FailsToBuild()(), tmp_path / "sign-in.lock")

    with pytest.raises(pickle.PicklingError):
        check.run(adapter)
