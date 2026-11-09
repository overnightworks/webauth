"""The accounts, sessions and sign-in transaction of a host that runs one worker.

Everything lives in the memory of this process: one worker only, and a restart
forgets every account and session. A host with more than one worker, or one that
must keep its sessions across a restart, implements the ports over its database.

`SingleProcessStores` builds the three adapters over one re-entrant guard and
one set of tables, so a session and its account are both there or both gone for
every reader. The library never imports this module; the host wires it.
"""

from __future__ import annotations

import secrets
import threading
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Final

from webauth.ports import SignInStores

if TYPE_CHECKING:
    from datetime import datetime
    from types import TracebackType

    from pydantic import SecretStr

    from webauth.ports import AccountEvent, AccountKind, AuditSink

__all__ = [
    "SessionTimes",
    "SingleProcessAccountStore",
    "SingleProcessSessionStore",
    "SingleProcessSignInTransaction",
    "SingleProcessStores",
    "StoredAccount",
    "StoredSession",
    "SubjectRecords",
]

_SESSION_ID_BYTES: Final = 32


@dataclass(frozen=True)
class StoredAccount:
    id: str
    username: str
    role: str
    kind: AccountKind


@dataclass(frozen=True)
class StoredSession:
    id: str = field(repr=False)
    user: StoredAccount
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None
    id_token: SecretStr | None = field(repr=False)


@dataclass(frozen=True)
class SessionTimes:
    """One stored session without its id and without any token."""

    started_at: datetime
    expires_at: datetime
    holds_refresh_token: bool
    holds_id_token: bool


@dataclass(frozen=True)
class SubjectRecords:
    """One subject's account, if any, and its sessions, oldest first."""

    account: StoredAccount | None
    sessions: tuple[SessionTimes, ...]


@dataclass(frozen=True)
class _SessionRow:
    id: str = field(repr=False)
    subject: str
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None
    id_token: SecretStr | None = field(repr=False)


@dataclass(frozen=True)
class _Snapshot:
    accounts: dict[str, StoredAccount]
    rows: dict[str, _SessionRow]


class _Tables:
    """The accounts and session rows of one process, and the guard every access takes."""

    def __init__(self) -> None:
        self.guard = threading.RLock()
        self.accounts: dict[str, StoredAccount] = {}
        self.rows: dict[str, _SessionRow] = {}

    def snapshot(self) -> _Snapshot:
        with self.guard:
            return _Snapshot(accounts=dict(self.accounts), rows=dict(self.rows))

    def restore(self, snapshot: _Snapshot) -> None:
        with self.guard:
            self.accounts = dict(snapshot.accounts)
            self.rows = dict(snapshot.rows)

    def drop_expired(self, now: datetime) -> int:
        expired = [session_id for session_id, row in self.rows.items() if row.expires_at < now]
        for session_id in expired:
            del self.rows[session_id]
        return len(expired)


def _joined(row: _SessionRow, user: StoredAccount) -> StoredSession:
    return StoredSession(
        id=row.id,
        user=user,
        created_at=row.created_at,
        expires_at=row.expires_at,
        refresh_token=row.refresh_token,
        id_token=row.id_token,
    )


class SingleProcessAccountStore:
    """Accounts keyed by the issuer's subject and compared exactly.

    `create_for_subject` never raises `UsernameTakenError`: the username is for
    display, and the trusted issuer decides who a subject is. It owns the tables
    that `SingleProcessSessionStore` and the transaction share with it.
    """

    def __init__(self) -> None:
        self._tables = _Tables()

    def get(self, user_id: str) -> StoredAccount | None:
        with self._tables.guard:
            return self._tables.accounts.get(user_id)

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> StoredAccount:
        account = StoredAccount(id=subject, username=username, role=role, kind=kind)
        with self._tables.guard:
            self._tables.accounts[subject] = account
        return account

    def set_role(self, user_id: str, role: str) -> StoredAccount:
        with self._tables.guard:
            account = replace(self._tables.accounts[user_id], role=role)
            self._tables.accounts[user_id] = account
        return account

    def set_kind(self, user_id: str, kind: AccountKind) -> StoredAccount:
        with self._tables.guard:
            account = replace(self._tables.accounts[user_id], kind=kind)
            self._tables.accounts[user_id] = account
        return account


class SingleProcessSessionStore:
    """Sessions; each record answers its account from the account store, as a join would.

    `load` returns an expired row as the port says; the gate decides expiry.
    It shares the tables of the account store it is given.
    """

    def __init__(self, accounts: SingleProcessAccountStore) -> None:
        self._tables = accounts._tables

    def create(
        self,
        user_id: str,
        *,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None,
    ) -> StoredSession:
        """Mint the session under a fresh id and drop every session expired at `now`."""
        row = _SessionRow(
            id=secrets.token_urlsafe(_SESSION_ID_BYTES),
            subject=user_id,
            created_at=now,
            expires_at=expires_at,
            refresh_token=refresh_token,
            id_token=id_token,
        )
        with self._tables.guard:
            user = self._tables.accounts[user_id]
            self._tables.drop_expired(now)
            self._tables.rows[row.id] = row
        return _joined(row, user)

    def load(self, session_id: str) -> StoredSession | None:
        with self._tables.guard:
            row = self._tables.rows.get(session_id)
            if row is None:
                return None
            return _joined(row, self._tables.accounts[row.subject])

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        with self._tables.guard:
            row = self._tables.rows.get(session_id)
            if row is None:
                return False
            self._tables.rows[session_id] = replace(row, expires_at=expires_at)
            return True

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        with self._tables.guard:
            row = self._tables.rows.get(session_id)
            if row is None:
                return False
            self._tables.rows[session_id] = replace(row, refresh_token=refresh_token)
            return True

    def delete(self, session_id: str) -> None:
        with self._tables.guard:
            self._tables.rows.pop(session_id, None)

    def delete_for_user(self, user_id: str) -> int:
        """End every session of the account, remove the account too, and return how many ended."""
        with self._tables.guard:
            ended = [
                session_id
                for session_id, row in self._tables.rows.items()
                if row.subject == user_id
            ]
            for session_id in ended:
                del self._tables.rows[session_id]
            self._tables.accounts.pop(user_id, None)
        return len(ended)

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        with self._tables.guard:
            newest_first = sorted(
                (row for row in self._tables.rows.values() if row.subject == user_id),
                key=lambda row: row.created_at,
                reverse=True,
            )
            for row in newest_first[keep_newest:]:
                del self._tables.rows[row.id]

    def delete_expired(self, now: datetime) -> int:
        """Remove the sessions expired at `now` and return how many went."""
        with self._tables.guard:
            return self._tables.drop_expired(now)

    def records_of(self, subject: str) -> SubjectRecords:
        """The account and the sessions of one subject, with no session id and no token."""
        with self._tables.guard:
            rows = sorted(
                (row for row in self._tables.rows.values() if row.subject == subject),
                key=lambda row: row.created_at,
            )
            account = self._tables.accounts.get(subject)
        return SubjectRecords(
            account=account,
            sessions=tuple(
                SessionTimes(
                    started_at=row.created_at,
                    expires_at=row.expires_at,
                    holds_refresh_token=row.refresh_token is not None,
                    holds_id_token=row.id_token is not None,
                )
                for row in rows
            ),
        )


class _DeferredAudit:
    """Holds an entry's events until it commits, so a rolled-back entry reports none."""

    def __init__(self) -> None:
        self.events: list[AccountEvent] = []

    def account_event(self, event: AccountEvent) -> None:
        self.events.append(event)


class SingleProcessSignInTransaction:
    """One sign-in entry at a time; a block that raises leaves both stores as they were at entry.

    An entry holds the guard from its enter to its exit, so no other thread
    reads or writes either store in between and the rollback undoes only the
    entry's own writes. The audit events reach the sink as the block's last
    step, so a sink that fails rolls the entry back too. Each entry copies both
    tables, so its cost grows with the number of stored accounts and sessions.
    It shares the tables of the account store it is given.
    """

    def __init__(
        self,
        accounts: SingleProcessAccountStore,
        sessions: SingleProcessSessionStore,
        audit: AuditSink,
    ) -> None:
        self._tables = accounts._tables
        self._accounts = accounts
        self._sessions = sessions
        self._audit = audit

    def __call__(self) -> AbstractContextManager[SignInStores]:
        return _SignInEntry(self._tables, self._accounts, self._sessions, self._audit)


class _SignInEntry:
    """One entry into the transaction; it takes the guard on enter and gives it back on exit."""

    def __init__(
        self,
        tables: _Tables,
        accounts: SingleProcessAccountStore,
        sessions: SingleProcessSessionStore,
        audit: AuditSink,
    ) -> None:
        self._tables = tables
        self._accounts = accounts
        self._sessions = sessions
        self._audit = audit
        self._deferred = _DeferredAudit()
        self._held = ExitStack()
        self._snapshot: _Snapshot
        self._entered = False

    def __enter__(self) -> SignInStores:
        if self._entered:
            message = "A sign-in entry is entered once; ask the transaction for a new one"
            raise RuntimeError(message)
        self._entered = True
        self._held.enter_context(self._tables.guard)
        self._snapshot = self._tables.snapshot()
        return SignInStores(accounts=self._accounts, sessions=self._sessions, audit=self._deferred)

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        with self._held:
            if exception_type is not None:
                self._tables.restore(self._snapshot)
                return
            try:
                for event in self._deferred.events:
                    self._audit.account_event(event)
            except BaseException:
                self._tables.restore(self._snapshot)
                raise


class SingleProcessStores:
    """The account store, the session store and the sign-in transaction over one set of tables.

    The host passes its own `AuditSink`; webauth ships none. Hand `transaction`
    to the sign-in routes and `sessions` to the session gate.
    """

    def __init__(self, *, audit: AuditSink) -> None:
        self.accounts: SingleProcessAccountStore = SingleProcessAccountStore()
        self.sessions: SingleProcessSessionStore = SingleProcessSessionStore(self.accounts)
        self.transaction: SingleProcessSignInTransaction = SingleProcessSignInTransaction(
            self.accounts, self.sessions, audit
        )
