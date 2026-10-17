"""A password host, written as hosts were before an account could lack a password.

Its account model, ``HostUser``, types ``password_hash`` as ``str`` and must
remain a ``UserRecord``. CI checks this file
with a pinned pyright, so a port change that would break such a host fails the
build instead of the host's next upgrade.
"""

from __future__ import annotations

from dataclasses import dataclass

from webauth.ports import UserRecord


@dataclass
class HostUser:
    id: str
    username: str
    role: str
    is_active: bool
    password_hash: str


def a_host_account_is_a_user_record(user: HostUser) -> UserRecord:
    return user

