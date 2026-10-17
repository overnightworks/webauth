"""A Keycloak-only host: accounts, sessions and sign-in without any local credential.

Every part is typed against the public ports and entry points. CI checks this
file with a pinned pyright, so a port change that would break such a host
fails the build instead of the host's next upgrade.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime

from fastapi import Request, Response
from pydantic import SecretStr

from webauth.config import WebAuthConfig
from webauth.dependencies import AuthDependencies, AuthenticatedUser, current_user_dependency
from webauth.oidc import OidcRelyingParty
from webauth.oidc_login import AdmissionRefusal, OidcRefusal, finish_login
from webauth.ports import (
    AuditSink,
    SessionAdministrationStore,
    SessionIdentityChanged,
    SessionLivenessPolicy,
    SessionRecord,
    SubjectUserStore,
    UserManagementEvent,
    UserRecord,
    WriteLock,
)
from webauth.proxies import TrustedProxies
from webauth.session_administration import SessionAdministration


@dataclass
class HostAccount:
    id: str
    username: str
    role: str
    is_active: bool


@dataclass
class HostSession:
    id: str
    user_id: str
    ip_address: str
    user_agent: str
    user: UserRecord
    expires_at: datetime


class HostAccounts:
    def get(self, user_id: str) -> UserRecord | None:
        return HostAccount(user_id, "someone", "user", True)

    def get_by_username(self, username: str) -> UserRecord | None:
        return HostAccount("subject", username, "user", True)

    def create_for_subject(self, subject: str, username: str, role: str) -> UserRecord:
        return HostAccount(subject, username, role, True)


class HostSessions:
    def create(
        self, user_id: str, expires_at: datetime, *, ip_address: str, user_agent: str,
    ) -> SessionRecord:
        user = HostAccount(user_id, "someone", "user", True)
        return HostSession("id", user_id, ip_address, user_agent, user, expires_at)

    def load(self, session_id: str) -> SessionRecord | None:
        return None

    def touch(
        self, record: SessionRecord, *, ip_address: str, user_agent: str, now: datetime,
    ) -> bool:
        return True

    def delete(self, session_id: str) -> None:
        return None

    def delete_for_user(self, user_id: str) -> int:
        return 0

    def prune_overflow(self, user_id: str, max_sessions: int) -> list[str]:
        return []

    def list_active(
        self, *, offset: int = 0, limit: int | None = None,
    ) -> list[SessionRecord]:
        return []

    def count_active(self) -> int:
        return 0


class HostLock:
    def hold(self) -> AbstractContextManager[None]:
        return nullcontext()


class HostAudit:
    def session_identity_changed(self, event: SessionIdentityChanged) -> None:
        return None

    def user_management_event(self, event: UserManagementEvent) -> None:
        return None


class HostRateLimits:
    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        return True


class HostLiveness:
    def admits_stored_session(self, record: HostSession, now: datetime) -> bool:
        return record.expires_at > now


def a_host_configures_without_local_credentials() -> WebAuthConfig:
    liveness: SessionLivenessPolicy[HostSession] = HostLiveness()
    return WebAuthConfig(
        session_secret=SecretStr("x" * 32),
        trusted_proxies=TrustedProxies.parse("127.0.0.1"),
        rate_limits=HostRateLimits(),
        allowed_hosts_exact=frozenset({"host.example"}),
        allowed_hosts_patterns=(re.compile(r".*\.example"),),
        cookie_max_age_seconds=3600,
        session_liveness=liveness,
    )


def a_host_administers_sessions(config: WebAuthConfig) -> SessionAdministration:
    sessions: SessionAdministrationStore = HostSessions()
    return SessionAdministration(
        sessions=sessions, audit=HostAudit(), lock=HostLock(), config=config,
    )


def a_host_finishes_a_keycloak_login(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig,
) -> UserRecord | OidcRefusal | AdmissionRefusal:
    accounts: SubjectUserStore = HostAccounts()
    lock: WriteLock = HostLock()
    audit: AuditSink = HostAudit()
    return finish_login(
        relying_party, request, response, config,
        bound_issuer="https://keycloak.example/realms/host",
        accounts=accounts, lock=lock, audit=audit,
    )


def a_host_resolves_the_current_user(
    on_authenticated: Callable[[AuthenticatedUser], None],
) -> AuthDependencies:
    return current_user_dependency(
        session_store=HostSessions,
        audit_sink=HostAudit,
        on_authenticated=on_authenticated,
    )
