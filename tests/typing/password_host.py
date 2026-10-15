"""A password-only host, written as hosts were before an account could lack a password.

Its account model types ``password_hash`` as ``str`` and its store implements
the password ports but not ``SubjectUserStore``. CI checks this file with a
pinned pyright, so a port change that would break such a host fails the build
instead of the host's next upgrade.
"""

from __future__ import annotations

from dataclasses import dataclass

from webauth.login import LoginOutcome, judge_credentials
from webauth.ports import PasswordHasher, UserAdministrationStore, UserRecord


@dataclass
class HostUser:
    id: str
    username: str
    role: str
    is_active: bool
    password_hash: str


class HostUserStore:
    def __init__(self) -> None:
        self._users: dict[str, HostUser] = {}

    def get(self, user_id: str) -> HostUser | None:
        return self._users.get(user_id)

    def get_by_username(self, username: str) -> HostUser | None:
        return next(
            (user for user in self._users.values() if user.username == username), None,
        )

    def count(self) -> int:
        return len(self._users)

    def create(self, username: str, password_hash: str, role: str) -> HostUser:
        user = HostUser(
            id=f"user-{len(self._users) + 1}", username=username, role=role,
            is_active=True, password_hash=password_hash,
        )
        self._users[user.id] = user
        return user

    def list(self) -> list[UserRecord]:
        return list(self._users.values())

    def update(
        self,
        user_id: str,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        password_hash: str | None = None,
    ) -> HostUser:
        user = self._users[user_id]
        if role is not None:
            user.role = role
        if is_active is not None:
            user.is_active = is_active
        if password_hash is not None:
            user.password_hash = password_hash
        return user

    def count_active_admins(self, role: str) -> int:
        return sum(user.is_active and user.role == role for user in self._users.values())


def sign_in(
    accounts: UserAdministrationStore, username: str, password: str, hasher: PasswordHasher,
) -> LoginOutcome:
    return judge_credentials(password, accounts.get_by_username(username), hasher=hasher)


def a_host_account_is_a_user_record(user: HostUser) -> UserRecord:
    return user


def a_host_store_is_an_administration_store() -> UserAdministrationStore:
    return HostUserStore()
