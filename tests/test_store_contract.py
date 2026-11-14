"""The store contract kit passes an adapter that keeps the ports' duties and refuses broken ones."""

from __future__ import annotations

import multiprocessing
from collections.abc import Callable
from operator import attrgetter
from pathlib import Path

import pytest

from tests.support.store_contract_arrangement import (
    BROKEN_ADAPTERS,
    FailsToBuild,
    FailsToEnter,
    FileLockedTransactionFactory,
    a_correct_single_process_adapter,
    a_file_locked_adapter,
    an_adapter_with_other_process,
)
from webauth.ports import SignInTransaction
from webauth.store_contract import STORE_CHECKS, StoreCheck, _enter_in_the_other_process

CROSS_PROCESS_CHECKS = [check for check in STORE_CHECKS if check.crosses_processes]
IN_PROCESS_CHECKS = [check for check in STORE_CHECKS if not check.crosses_processes]


def test_every_check_is_paired_with_one_broken_adapter() -> None:
    names = [check.name for check in STORE_CHECKS]

    assert len(set(names)) == len(names)
    assert set(BROKEN_ADAPTERS) == set(names)


@pytest.mark.parametrize("check", IN_PROCESS_CHECKS, ids=attrgetter("name"))
def test_a_single_process_adapter_passes_every_in_process_check(check: StoreCheck) -> None:
    check.run(a_correct_single_process_adapter())


def test_exactly_one_check_crosses_processes() -> None:
    assert [check.name for check in CROSS_PROCESS_CHECKS] == [
        "sign_in_entries_serialise_across_processes"
    ]


def test_the_file_lock_adapter_passes_the_cross_process_check(tmp_path: Path) -> None:
    (check,) = CROSS_PROCESS_CHECKS

    check.run(a_file_locked_adapter(tmp_path / "sign-in.lock"))


@pytest.mark.parametrize("check", STORE_CHECKS, ids=attrgetter("name"))
def test_each_check_refuses_its_broken_adapter(check: StoreCheck) -> None:
    with pytest.raises(AssertionError):
        check.run(BROKEN_ADAPTERS[check.name]())


@pytest.mark.parametrize(
    "factory",
    [FailsToBuild(), FailsToEnter()],
    ids=["cannot-build", "cannot-enter"],
)
def test_the_cross_process_check_fails_loud_when_the_other_process_cannot_serve(
    factory: Callable[[], SignInTransaction],
    tmp_path: Path,
) -> None:
    (check,) = CROSS_PROCESS_CHECKS

    with pytest.raises(AssertionError):
        check.run(an_adapter_with_other_process(factory, tmp_path / "sign-in.lock"))


def test_the_other_process_signals_before_it_enters_and_after_its_store_call(
    tmp_path: Path,
) -> None:
    # Coverage does not follow the spawned process that runs this function.
    messages, sender = multiprocessing.Pipe(duplex=False)

    _enter_in_the_other_process(
        FileLockedTransactionFactory(tmp_path / "sign-in.lock"), "subject", sender
    )

    assert [messages.recv(), messages.recv()] == ["about to enter", "called the store"]
