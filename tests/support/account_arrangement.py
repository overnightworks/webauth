"""The account and write-lock doubles the suite arranges its tests with."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import RLock

from webauth.ports import AccountKind, UsernameTakenError

MEMBER_ROLE = "user"


@dataclass
class FakeUser:
    id: str = "user-1"
    username: str = "alice"
    role: str = MEMBER_ROLE
    kind: AccountKind = AccountKind.PERSON


class UnknownAccountError(LookupError):
    """A session was requested for an account the arrangement does not hold."""


class LockNotHeldError(RuntimeError):
    """A store operation requires the host's write lock."""


def require_held_lock(lock: WriteLockInMemory | None) -> None:
    if lock is not None and not lock.held:
        raise LockNotHeldError("Store operation requires a held write lock")


class UsersInMemory:
    """Accounts sharing the same mutable records as the host's session store."""

    def __init__(self, *users: FakeUser, lock: WriteLockInMemory | None = None) -> None:
        self._lock = lock
        self._users = {user.id: user for user in users}
        self._usernames = {user.username: user for user in users}

    def get(self, user_id: str) -> FakeUser | None:
        return self._users.get(user_id)

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> FakeUser:
        return self._add(FakeUser(id=subject, username=username, role=role, kind=kind))

    def set_role(self, user_id: str, role: str) -> FakeUser:
        require_held_lock(self._lock)
        user = self._users[user_id]
        user.role = role
        return user

    def set_kind(self, user_id: str, kind: AccountKind) -> FakeUser:
        require_held_lock(self._lock)
        user = self._users[user_id]
        user.kind = kind
        return user

    def _add(self, user: FakeUser) -> FakeUser:
        require_held_lock(self._lock)
        if user.username in self._usernames:
            raise UsernameTakenError("Username is already taken")
        self._users[user.id] = user
        self._usernames[user.username] = user
        return user

    def list(self) -> list[FakeUser]:
        return list(self._users.values())


@dataclass
class WriteLockInMemory:
    _lock: RLock = field(default_factory=RLock)
    _hold_depth: int = field(default=0, init=False)

    @property
    def held(self) -> bool:
        return self._hold_depth > 0

    @contextmanager
    def hold(self) -> Iterator[None]:
        with self._lock:
            self._hold_depth += 1
            try:
                yield
            finally:
                self._hold_depth -= 1
