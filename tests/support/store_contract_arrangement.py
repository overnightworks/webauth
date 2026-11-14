"""The adapters the store contract kit is proven with: one broken builder per check, and the
file-lock adapter beside its lockless twin for the cross-process check."""

from __future__ import annotations

import fcntl
import unicodedata
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from pydantic import SecretStr

from tests.support.webauth_arrangement import RecordingAuditSink
from webauth.ports import AccountKind, SignInStores, SignInTransaction, UsernameTakenError
from webauth.single_process_stores import (
    SingleProcessAccountStore,
    SingleProcessSessionStore,
    SingleProcessSignInTransaction,
    SingleProcessStores,
    StoredAccount,
    StoredSession,
)
from webauth.store_contract import StoreAdapter


def a_correct_single_process_adapter() -> StoreAdapter:
    stores = SingleProcessStores(audit=RecordingAuditSink())
    return StoreAdapter(
        accounts=stores.accounts, sessions=stores.sessions, transaction=stores.transaction
    )


def _adapter_over(
    accounts: SingleProcessAccountStore, sessions: SingleProcessSessionStore
) -> StoreAdapter:
    return StoreAdapter(
        accounts=accounts,
        sessions=sessions,
        transaction=SingleProcessSignInTransaction(sessions, audit=RecordingAuditSink()),
    )


class MintsItsOwnSessionId(SingleProcessSessionStore):
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
    ) -> StoredSession:
        return super().create(
            user_id,
            session_id=f"minted-{uuid.uuid4().hex}",
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=id_token,
            account_language=account_language,
        )


class OverwritesAStoredSession(SingleProcessSessionStore):
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
    ) -> StoredSession:
        self.delete(session_id)
        return super().create(
            user_id,
            session_id=session_id,
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=id_token,
            account_language=account_language,
        )


class ChangesTheStoredRowThenRefuses(SingleProcessSessionStore):
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
    ) -> StoredSession:
        stored = super().load(session_id)
        if stored is not None:
            self.delete(session_id)
            super().create(
                stored.user.id,
                session_id=session_id,
                now=stored.created_at,
                expires_at=expires_at,
                refresh_token=stored.refresh_token,
                id_token=stored.id_token,
                account_language=stored.account_language,
            )
            message = "the session id is taken"
            raise RuntimeError(message)
        return super().create(
            user_id,
            session_id=session_id,
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=id_token,
            account_language=account_language,
        )


class LoadsDeletedSessions(SingleProcessSessionStore):
    def __init__(self, accounts: SingleProcessAccountStore) -> None:
        super().__init__(accounts)
        self._last_seen: dict[str, StoredSession] = {}

    def load(self, session_id: str) -> StoredSession | None:
        session = super().load(session_id)
        if session is not None:
            self._last_seen[session_id] = session
        return session or self._last_seen.get(session_id)


class PrunesTheNewest(SingleProcessSessionStore):
    def __init__(self, accounts: SingleProcessAccountStore) -> None:
        super().__init__(accounts)
        self._created: dict[str, list[tuple[datetime, str]]] = {}

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
    ) -> StoredSession:
        session = super().create(
            user_id,
            session_id=session_id,
            now=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=id_token,
            account_language=account_language,
        )
        self._created.setdefault(user_id, []).append((now, session_id))
        return session

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        oldest_first = sorted(self._created.get(user_id, []))
        for _created_at, session_id in oldest_first[keep_newest:]:
            self.delete(session_id)


class CountsOneSessionTooMany(SingleProcessSessionStore):
    def delete_for_user(self, user_id: str) -> int:
        return super().delete_for_user(user_id) + 1


class AnswersWithRowCounts(SingleProcessSessionStore):
    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return cast("bool", int(super().touch(session_id, expires_at=expires_at)))

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return cast(
            "bool",
            int(super().replace_refresh_token(session_id, refresh_token=refresh_token)),
        )


class FoldsSubjects(SingleProcessAccountStore):
    def __init__(self) -> None:
        super().__init__()
        self._stored_as: dict[str, str] = {}

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> StoredAccount:
        self._stored_as[_folded(subject)] = subject
        return super().create_for_subject(subject, username, role, kind)

    def get(self, user_id: str) -> StoredAccount | None:
        return super().get(self._stored_as.get(_folded(user_id), user_id))


def _folded(subject: str) -> str:
    return unicodedata.normalize("NFKD", subject).casefold().rstrip()


class RefusesATakenUsername(SingleProcessAccountStore):
    def __init__(self) -> None:
        super().__init__()
        self._usernames: set[str] = set()

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> StoredAccount:
        if username in self._usernames:
            raise UsernameTakenError
        self._usernames.add(username)
        return super().create_for_subject(subject, username, role, kind)


class CreatesAMissingAccountOnWrite(SingleProcessAccountStore):
    def set_role(self, user_id: str, role: str) -> StoredAccount:
        if self.get(user_id) is None:
            self.create_for_subject(user_id, user_id, role, AccountKind.PERSON)
        return super().set_role(user_id, role)


class RefusesARoleWebauthDoesNotWrite(SingleProcessAccountStore):
    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> StoredAccount:
        if role not in {"admin", "user"}:
            raise ValueError(role)
        return super().create_for_subject(subject, username, role, kind)


def _with_sessions(
    sessions_class: Callable[[SingleProcessAccountStore], SingleProcessSessionStore],
) -> Callable[[], StoreAdapter]:
    def build() -> StoreAdapter:
        accounts = SingleProcessAccountStore()
        return _adapter_over(accounts, sessions_class(accounts))

    return build


def _with_accounts(
    accounts_class: Callable[[], SingleProcessAccountStore],
) -> Callable[[], StoreAdapter]:
    def build() -> StoreAdapter:
        accounts = accounts_class()
        return _adapter_over(accounts, SingleProcessSessionStore(accounts))

    return build


@dataclass(frozen=True)
class FileLockedTransaction:
    """A sign-in transaction that holds an exclusive `flock` on a file for each entry, over the
    in-memory entry it wraps."""

    lock_path: Path
    inner: SignInTransaction

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return _locked(self.lock_path, self.inner())


@contextmanager
def _locked(lock_path: Path, entry: AbstractContextManager[SignInStores]) -> Iterator[SignInStores]:
    with lock_path.open("a") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        with entry as stores:
            yield stores


@dataclass(frozen=True)
class FileLockedTransactionFactory:
    """Builds, in any process, the transaction that locks `lock_path`."""

    lock_path: Path

    def __call__(self) -> SignInTransaction:
        stores = SingleProcessStores(audit=RecordingAuditSink())
        return FileLockedTransaction(self.lock_path, stores.transaction)


@dataclass(frozen=True)
class LocklessTransactionFactory:
    """Builds, in any process, the transaction without the file lock: the twin of
    `FileLockedTransactionFactory`."""

    def __call__(self) -> SignInTransaction:
        return SingleProcessStores(audit=RecordingAuditSink()).transaction


def a_file_locked_adapter(lock_path: Path) -> StoreAdapter:
    stores = SingleProcessStores(audit=RecordingAuditSink())
    return StoreAdapter(
        accounts=stores.accounts,
        sessions=stores.sessions,
        transaction=FileLockedTransaction(lock_path, stores.transaction),
        transaction_in_another_process=FileLockedTransactionFactory(lock_path),
    )


def a_lockless_adapter() -> StoreAdapter:
    stores = SingleProcessStores(audit=RecordingAuditSink())
    return StoreAdapter(
        accounts=stores.accounts,
        sessions=stores.sessions,
        transaction=stores.transaction,
        transaction_in_another_process=LocklessTransactionFactory(),
    )


@dataclass(frozen=True)
class FailsToBuild:
    """A factory whose transaction cannot be built in the other process."""

    def __call__(self) -> SignInTransaction:
        message = "the other process cannot build its transaction"
        raise RuntimeError(message)


@dataclass(frozen=True)
class _FailingEntry:
    def __call__(self) -> AbstractContextManager[SignInStores]:
        message = "the other process cannot enter"
        raise RuntimeError(message)


@dataclass(frozen=True)
class FailsToEnter:
    """A factory whose transaction fails when the other process enters it."""

    def __call__(self) -> SignInTransaction:
        return _FailingEntry()


def an_adapter_with_unique_usernames() -> StoreAdapter:
    return _with_accounts(RefusesATakenUsername)()


def an_adapter_with_a_closed_role_type() -> StoreAdapter:
    return _with_accounts(RefusesARoleWebauthDoesNotWrite)()


def a_session_adapter_that_changes_the_row_before_refusing() -> StoreAdapter:
    return _with_sessions(ChangesTheStoredRowThenRefuses)()


@dataclass(frozen=True)
class FailsOnExit:
    """A factory whose locked transaction stores fine and raises when its entry exits."""

    lock_path: Path

    def __call__(self) -> SignInTransaction:
        return _FailingExit(FileLockedTransactionFactory(self.lock_path)())


@dataclass(frozen=True)
class _FailingExit:
    inner: SignInTransaction

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return _raises_on_exit(self.inner())


@contextmanager
def _raises_on_exit(entry: AbstractContextManager[SignInStores]) -> Iterator[SignInStores]:
    with entry as stores:
        yield stores
    message = "the other process cannot leave its entry"
    raise RuntimeError(message)


def an_adapter_with_other_process(
    factory: Callable[[], SignInTransaction], lock_path: Path
) -> StoreAdapter:
    base = a_file_locked_adapter(lock_path)
    return StoreAdapter(
        accounts=base.accounts,
        sessions=base.sessions,
        transaction=base.transaction,
        transaction_in_another_process=factory,
    )


BROKEN_ADAPTERS: dict[str, Callable[[], StoreAdapter]] = {
    "create_keeps_the_given_id": _with_sessions(MintsItsOwnSessionId),
    "a_stored_id_is_refused_and_its_row_kept": _with_sessions(OverwritesAStoredSession),
    "load_answers_none_for_unknown_and_deleted_ids": _with_sessions(LoadsDeletedSessions),
    "prune_overflow_keeps_the_newest": _with_sessions(PrunesTheNewest),
    "delete_for_user_returns_how_many_ended": _with_sessions(CountsOneSessionTooMany),
    "touch_and_replace_refresh_token_answer_a_bool": _with_sessions(AnswersWithRowCounts),
    "get_compares_the_subject_exactly": _with_accounts(FoldsSubjects),
    "a_write_on_a_missing_account_raises": _with_accounts(CreatesAMissingAccountOnWrite),
    "sign_in_entries_serialise_across_processes": a_lockless_adapter,
}
