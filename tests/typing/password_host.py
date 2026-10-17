"""A password host, written as hosts were before an account could lack a password.

Its account model types ``password_hash`` as ``str`` and it implements the
password ports but not ``SubjectUserStore``. CI checks this file with a
pinned pyright, so a port change that would break such a host fails the build
instead of the host's next upgrade.
"""

from __future__ import annotations

from dataclasses import dataclass

from webauth.login import LoginOutcome, judge_credentials
from webauth.ports import PasswordHasher, UserRecord


@dataclass
class HostUser:
    id: str
    username: str
    role: str
    is_active: bool
    password_hash: str


def sign_in(
    account: HostUser | None, password: str, hasher: PasswordHasher,
) -> LoginOutcome:
    return judge_credentials(password, account, hasher=hasher)


def a_host_account_is_a_user_record(user: HostUser) -> UserRecord:
    return user

