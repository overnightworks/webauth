"""User administration through host-owned records, transactions, and audit.

The host supplies the authenticated actor and translates refusals into its
own responses. Write helpers hold the host's lock but never commit; a failed
operation must be rolled back by the host, including a raced first setup.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from webauth.config import WebAuthConfig
from webauth.dependencies import AuthenticatedUser
from webauth.passwords import check_password_strength
from webauth.ports import (
    AuditSink,
    SessionAdministrationStore,
    UnknownUserError,
    UserAdministrationStore,
    UserManagementError,
    UserManagementEvent,
    UserManagementEventKind,
    UserRecord,
    WriteLock,
)


class NotAnAdminError(UserManagementError):
    """The actor does not hold the configured administrator role."""


class UnknownRoleError(UserManagementError):
    """The requested role is neither configured administrator nor user."""


class LastAdminError(UserManagementError):
    """The operation would remove the last active administrator."""


class SelfDeactivationError(UserManagementError):
    """An administrator cannot deactivate their own account."""


class WeakPasswordError(UserManagementError):
    """The proposed password does not satisfy the library's strength rules."""


class WrongPasswordError(UserManagementError):
    """The supplied current password does not match the account's password."""


class UnknownSessionError(UserManagementError):
    """No active session matches the supplied reference."""


class SetupAlreadyDoneError(UserManagementError):
    """First-run setup is closed because an account already exists."""


class SetupRacedError(UserManagementError):
    """Another account appeared during setup; the host must roll back."""


@dataclass(frozen=True)
class SessionSummary:
    session_ref: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str


def session_reference(session_id: str) -> str:
    """Return the public SHA-256 reference for a raw session identifier."""
    return hashlib.sha256(session_id.encode()).hexdigest()


@dataclass(frozen=True)
class UserManagement:
    users: UserAdministrationStore
    sessions: SessionAdministrationStore
    audit: AuditSink
    lock: WriteLock
    config: WebAuthConfig

    def ensure_not_last_admin(self, user_id: str) -> None:
        """Refuse removal of the last active admin, or an unknown account.

        The caller holds ``lock.hold()`` around this check and its write,
        including when a host uses it to guard its own account deletion.
        """
        user = self._user(user_id)
        if (
            user.is_active
            and user.role == self.config.admin_role
            and self.users.count_active_admins(self.config.admin_role) <= 1
        ):
            raise LastAdminError("The last active administrator must remain")

    def create_user(
        self, actor: AuthenticatedUser, username: str, password: str, role: str,
    ) -> UserRecord:
        self._require_admin(actor)
        self._require_role(role)
        password_hash = _hash_password(password, self.config)
        with self.lock.hold():
            user = self.users.create(username, password_hash, role)
            self.audit.user_management_event(UserManagementEvent(
                kind=UserManagementEventKind.USER_CREATED,
                actor_id=actor.id,
                subject_id=user.id,
                role=user.role,
            ))
            return user

    def list_users(self) -> list[UserRecord]:
        """Return the store's order; the host's admin dependency protects access."""
        return self.users.list()

    def change_role(self, actor: AuthenticatedUser, user_id: str, role: str) -> UserRecord:
        self._require_admin(actor)
        self._require_role(role)
        with self.lock.hold():
            user = self._user(user_id)
            if user.role == role:
                return user
            if role != self.config.admin_role:
                self.ensure_not_last_admin(user_id)
            user = self.users.update(user_id, role=role)
            session_count = self._delete_user_sessions(user_id)
            self.audit.user_management_event(UserManagementEvent(
                kind=UserManagementEventKind.ROLE_CHANGED,
                actor_id=actor.id,
                subject_id=user.id,
                role=user.role,
                session_count=session_count,
            ))
            return user

    def deactivate_user(self, actor: AuthenticatedUser, user_id: str) -> None:
        self._require_admin(actor)
        if actor.id == user_id:
            raise SelfDeactivationError("An administrator cannot deactivate themselves")
        with self.lock.hold():
            self.ensure_not_last_admin(user_id)
            self.users.update(user_id, is_active=False)
            session_count = self._delete_user_sessions(user_id)
            self.audit.user_management_event(UserManagementEvent(
                kind=UserManagementEventKind.USER_DEACTIVATED,
                actor_id=actor.id,
                subject_id=user_id,
                session_count=session_count,
            ))

    def revoke_user_sessions(self, actor: AuthenticatedUser, user_id: str) -> int:
        """End all sessions, returning the number deleted from the host's store."""
        self._require_admin(actor)
        with self.lock.hold():
            self._user(user_id)
            session_count = self._delete_user_sessions(user_id)
            self.audit.user_management_event(UserManagementEvent(
                kind=UserManagementEventKind.SESSIONS_REVOKED,
                actor_id=actor.id,
                subject_id=user_id,
                session_count=session_count,
            ))
            return session_count

    def set_password(self, actor: AuthenticatedUser, user_id: str, password: str) -> None:
        """Set an account's password and end all its sessions, including this one."""
        self._require_admin(actor)
        password_hash = _hash_password(password, self.config)
        with self.lock.hold():
            self._user(user_id)
            self._replace_password(
                actor, user_id, password_hash, UserManagementEventKind.PASSWORD_SET_BY_ADMIN,
            )

    def change_own_password(self, actor: AuthenticatedUser, current: str, new: str) -> None:
        """Verify the current password and end every session after changing it.

        The host budgets failed attempts and opens a new session afterwards.
        """
        with self.lock.hold():
            user = self._user(actor.id)
            if not self.config.password_hasher.verify(current, user.password_hash):
                raise WrongPasswordError("Current password is incorrect")
            password_hash = _hash_password(new, self.config)
            self._replace_password(
                actor, actor.id, password_hash, UserManagementEventKind.PASSWORD_CHANGED,
            )

    def list_sessions(self, offset: int = 0, limit: int | None = None) -> list[SessionSummary]:
        """List public references; the host's admin dependency protects access."""
        return [
            SessionSummary(
                session_ref=session_reference(record.id),
                user_id=record.user_id,
                username=record.user.username,
                ip_address=record.ip_address,
                user_agent=record.user_agent,
            )
            for record in self.sessions.list_active(offset=offset, limit=limit)
        ]

    def revoke_session(self, actor: AuthenticatedUser, session_ref: str) -> None:
        """End one active session identified by its public reference."""
        self._require_admin(actor)
        reference = session_ref.encode()
        with self.lock.hold():
            for record in self.sessions.list_active(limit=None):
                if hmac.compare_digest(session_reference(record.id).encode(), reference):
                    self.sessions.delete(record.id)
                    if self.config.session_cache is not None:
                        self.config.session_cache.delete(record.id, record.user_id)
                    self.audit.user_management_event(UserManagementEvent(
                        kind=UserManagementEventKind.SESSION_REVOKED,
                        actor_id=actor.id,
                        subject_id=record.user_id,
                        session_ref=session_ref,
                    ))
                    return
            raise UnknownSessionError("Active session does not exist")

    def _replace_password(
        self, actor: AuthenticatedUser, user_id: str, password_hash: str,
        kind: UserManagementEventKind,
    ) -> None:
        self.users.update(user_id, password_hash=password_hash)
        session_count = self._delete_user_sessions(user_id)
        self.audit.user_management_event(UserManagementEvent(
            kind=kind,
            actor_id=actor.id,
            subject_id=user_id,
            session_count=session_count,
        ))

    def _require_admin(self, actor: AuthenticatedUser) -> None:
        if actor.role != self.config.admin_role:
            raise NotAnAdminError("Administrator access is required")

    def _require_role(self, role: str) -> None:
        if role not in {self.config.admin_role, self.config.user_role}:
            raise UnknownRoleError("Role must be the configured administrator or user role")

    def _user(self, user_id: str) -> UserRecord:
        user = self.users.get(user_id)
        if user is None:
            raise UnknownUserError("Account does not exist")
        return user

    def _delete_user_sessions(self, user_id: str) -> int:
        count = self.sessions.delete_for_user(user_id)
        if self.config.session_cache is not None:
            self.config.session_cache.delete_user_sessions(user_id)
        return count


def complete_first_run_setup(
    management: UserManagement, username: str, password: str,
) -> UserRecord:
    """Create the first admin for either an HTTP setup or a host's bootstrap.

    The host reads bootstrap credentials from its own configuration and rolls
    back the transaction on failure. The second count catches a concurrent
    creator even when the host's lock did not serialize it.
    """
    with management.lock.hold():
        if management.users.count() > 0:
            raise SetupAlreadyDoneError("First-run setup is already complete")
        password_hash = _hash_password(password, management.config)
        user = management.users.create(username, password_hash, management.config.admin_role)
        if management.users.count() > 1:
            raise SetupRacedError("Concurrent first-run setup requires rollback")
        management.audit.user_management_event(UserManagementEvent(
            kind=UserManagementEventKind.FIRST_ADMIN_CREATED,
            actor_id=None,
            subject_id=user.id,
            role=user.role,
        ))
        return user


def _hash_password(password: str, config: WebAuthConfig) -> str:
    try:
        check_password_strength(password)
    except ValueError as error:
        raise WeakPasswordError(str(error)) from error
    return config.password_hasher.hash(password)
