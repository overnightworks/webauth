"""Session administration through the host's session store, audit, and lock.

The host supplies the authenticated actor and translates refusals into its
own responses. Revocation holds the host's lock but never commits; a failed
operation must be rolled back by the host.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from webauth.config import WebAuthConfig
from webauth.cookies import session_reference
from webauth.dependencies import AuthenticatedUser
from webauth.ports import (
    AuditSink,
    SessionAdministrationStore,
    UserManagementError,
    UserManagementEvent,
    UserManagementEventKind,
    WriteLock,
)
from webauth.session_ending import end_session

__all__ = [
    "NotAnAdminError",
    "SessionAdministration",
    "SessionSummary",
    "UnknownSessionError",
]


class NotAnAdminError(UserManagementError):
    """The actor does not hold the configured administrator role."""


def require_admin(actor: AuthenticatedUser, config: WebAuthConfig) -> None:
    if actor.role != config.admin_role:
        raise NotAnAdminError("Administrator access is required")


class UnknownSessionError(UserManagementError):
    """No active session matches the supplied reference."""


@dataclass(frozen=True)
class SessionSummary:
    session_ref: str
    user_id: str
    username: str
    ip_address: str
    user_agent: str


@dataclass(frozen=True)
class SessionAdministration:
    sessions: SessionAdministrationStore
    audit: AuditSink
    lock: WriteLock
    config: WebAuthConfig

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
        require_admin(actor, self.config)
        reference = session_ref.encode()
        with self.lock.hold():
            for record in self.sessions.list_active(limit=None):
                if hmac.compare_digest(session_reference(record.id).encode(), reference):
                    end_session(self.sessions, session_id=record.id)
                    self.audit.user_management_event(UserManagementEvent(
                        kind=UserManagementEventKind.SESSION_REVOKED,
                        actor_id=actor.id,
                        subject_id=record.user_id,
                        session_ref=session_ref,
                    ))
                    return
            raise UnknownSessionError("Active session does not exist")
