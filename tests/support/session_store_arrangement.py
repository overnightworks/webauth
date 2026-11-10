"""The session-store doubles the suite arranges its tests with."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from itertools import count
from threading import get_ident
from typing import Any

from pydantic import SecretStr

from tests.support.account_arrangement import (
    FakeUser,
    UnknownAccountError,
    UsersInMemory,
    WriteLockInMemory,
    require_held_lock,
)
from webauth.ports import SessionRecordStore


@dataclass
class FakeSessionRecord:
    id: str
    user: FakeUser
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None = None
    id_token: SecretStr | None = None


class SessionRecordsInMemory:
    """Stored sessions, renewed in place and never committed. ``create`` and ``touch``
    write the instants they are given; a deleted record yields no ID token."""

    def __init__(
        self,
        record: FakeSessionRecord | None = None,
        *,
        users: UsersInMemory | None = None,
        lock: WriteLockInMemory | None = None,
    ) -> None:
        self._lock = lock
        self._records = {} if record is None else {record.id: record}
        seeded_users = () if record is None else (record.user,)
        self._users = users if users is not None else UsersInMemory(*seeded_users)
        self._ids = count(1)
        self.commit_failure: Exception | None = None

    @property
    def record(self) -> FakeSessionRecord | None:
        return next(iter(self._records.values()), None)

    @property
    def stored_record(self) -> FakeSessionRecord:
        """The one record the store holds; a store without one fails the test."""
        record = self.record
        assert record is not None
        return record

    def create(
        self,
        user_id: str,
        *,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None,
    ) -> FakeSessionRecord:
        require_held_lock(self._lock)
        user = self._users.get(user_id)
        if user is None:
            raise UnknownAccountError("Account does not exist")
        session_id = f"session-{next(self._ids)}"
        while session_id in self._records:
            session_id = f"session-{next(self._ids)}"
        record = FakeSessionRecord(session_id, user, now, expires_at, refresh_token, id_token)
        self._records[record.id] = record
        return record

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """The host's transaction: leaving the block commits unless ``commit_failure``
        is set, and an exception rolls back."""
        committed = {session_id: replace(record) for session_id, record in self._records.items()}
        try:
            yield
            if self.commit_failure is not None:
                raise self.commit_failure
        except BaseException:
            self._records = committed
            raise

    def in_transaction(self) -> AbstractContextManager[SessionRecordStore]:
        """The store inside its ``transaction``: a ``SessionTransaction`` provider."""
        return self._store_in_transaction()

    @contextmanager
    def _store_in_transaction(self) -> Iterator[SessionRecordStore]:
        with self.transaction():
            yield self

    def load(self, session_id: str) -> FakeSessionRecord | None:
        return self._records.get(session_id)

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        record = self._records.get(session_id)
        if record is None:
            return False
        record.expires_at = expires_at
        return True

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        record = self._records.get(session_id)
        if record is None:
            return False
        record.refresh_token = refresh_token
        return True

    def delete(self, session_id: str) -> None:
        require_held_lock(self._lock)
        self._remove_record(session_id)

    def _remove_record(self, session_id: str) -> None:
        if (removed := self._records.pop(session_id, None)) is not None:
            removed.id_token = None

    def delete_for_user(self, user_id: str) -> int:
        sessions = self.sessions_of(user_id)
        for record in sessions:
            self._remove_record(record.id)
        return len(sessions)

    def sessions_of(self, user_id: str) -> list[FakeSessionRecord]:
        return [record for record in self._records.values() if record.user.id == user_id]

    def list_active(self) -> list[FakeSessionRecord]:
        return list(self._records.values())

    def count_active(self) -> int:
        return len(self._records)

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        require_held_lock(self._lock)
        records = sorted(
            self.sessions_of(user_id),
            key=lambda record: record.created_at,
            reverse=True,
        )
        for record in records[keep_newest:]:
            self._remove_record(record.id)


class SessionsRecordingTheirTransaction(SessionRecordsInMemory):
    """A store that records, with the thread each ran on, the factory call (``open``),
    ``load``, ``touch``, ``replace``, a clean exit (``commit``) and an exit by exception
    (``rollback``)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.events: list[tuple[str, int]] = []

    @property
    def event_names(self) -> list[str]:
        return [name for name, _thread in self.events]

    @property
    def threads(self) -> set[int]:
        return {thread for _name, thread in self.events}

    def in_transaction(self) -> AbstractContextManager[SessionRecordStore]:
        self.events.append(("open", get_ident()))
        return self._recorded_transaction()

    @contextmanager
    def _recorded_transaction(self) -> Iterator[SessionRecordStore]:
        try:
            with super().in_transaction() as store:
                yield store
        except BaseException:
            self.events.append(("rollback", get_ident()))
            raise
        self.events.append(("commit", get_ident()))

    def load(self, session_id: str) -> FakeSessionRecord | None:
        self.events.append(("load", get_ident()))
        return super().load(session_id)

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        self.events.append(("touch", get_ident()))
        return super().touch(session_id, expires_at=expires_at)

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        self.events.append(("replace", get_ident()))
        return super().replace_refresh_token(session_id, refresh_token=refresh_token)


class SessionsFailingToLoad(SessionRecordsInMemory):
    """A store whose ``load`` raises while ``failing``, as a database that went away does."""

    failing = True

    def load(self, session_id: str) -> FakeSessionRecord | None:
        if self.failing:
            raise ConnectionError("session store down")
        return super().load(session_id)


class SessionsEndedBetweenLoadAndTouch(SessionRecordsInMemory):
    """A store whose session is ended by another request right after ``load`` reads it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        record = super().load(session_id)
        if record is not None:
            self.delete(session_id)
        return record


class SessionsEndedBeforeReplacingTheRefreshToken(SessionRecordsInMemory):
    """A store whose session is ended by another request right before the replace lands."""

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        self._remove_record(session_id)
        return super().replace_refresh_token(session_id, refresh_token=refresh_token)


class SessionsThatMustNotBeAsked(SessionRecordsInMemory):
    """A store that fails the test on the first question put to it."""

    def load(self, session_id: str) -> FakeSessionRecord | None:
        raise AssertionError("the store was asked to load a session")

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        raise AssertionError("the store was asked to touch a session")

    def delete(self, session_id: str) -> None:
        raise AssertionError("the store was asked to delete a session")


class SessionsAnsweringTouch(SessionRecordsInMemory):
    """A store whose ``touch`` writes nothing and gives a fixed answer."""

    def __init__(self, record: FakeSessionRecord, touch_answer: Any) -> None:
        super().__init__(record)
        self.touch_answer = touch_answer

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return self.touch_answer


class SessionsAnsweringReplace(SessionRecordsInMemory):
    """A store whose ``replace_refresh_token`` writes nothing and gives a fixed answer."""

    def __init__(self, record: FakeSessionRecord, replace_answer: Any) -> None:
        super().__init__(record)
        self.replace_answer = replace_answer

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return self.replace_answer
