"""A Keycloak-only host: accounts, sessions and sign-in without any local credential.

Every part is typed against the public ports and entry points. CI checks this
file with a pinned pyright against the built wheel, so a port change or an
export a host cannot import fails the build instead of the host's next upgrade.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime

from fastapi import FastAPI, Request, Response
from pydantic import SecretStr

from webauth import WebAuthError
from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import (
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
    PendingLogin,
    clear_session_cookies,
    issue_session_cookies,
    session_reference,
)
from webauth.dependencies import (
    AuthDependencies,
    AuthenticatedUser,
    LoginRedirect,
    current_user_dependency,
    session_id_from_request,
    unauthenticated_response,
)
from webauth.https_client import (
    KEY_SET_FETCH_DEADLINE_SECONDS,
    MAX_KEY_SET_BYTES,
    TOKEN_EXCHANGE_DEADLINE_SECONDS,
    ExchangeFailure,
    KeySetFetchError,
    fetch_key_set_over_https,
    is_https_url,
)
from webauth.jwt_verification import (
    MAX_KEY_SET_KEYS,
    JwtVerifier,
    KeySetFetch,
    MonotonicClock,
    Rejected,
    VerifiedClaims,
    WallClock,
)
from webauth.liveness import ExpiryColumnLiveness, IdleWindowLiveness
from webauth.middleware import (
    BodySizeLimitMiddleware,
    CsrfOriginMiddleware,
    CsrfTokenMiddleware,
    IpRateLimitMiddleware,
    SecurityHeadersMiddleware,
    install_web_auth_middleware,
)
from webauth.oidc import (
    LOGOUT_TOKEN_MAX_AGE_SECONDS,
    MAX_AUTHORIZATION_CODE_CHARS,
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcClientConfig,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
    TokenEndpointError,
    TokenRequestPost,
    VerifiedLogout,
)
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    BackchannelLogoutResult,
    EverySubject,
    NoAdmins,
    admit_identity,
    finish_login,
    log_out,
    post_token_request_over_https,
    receive_backchannel_logout,
    start_login,
)
from webauth.policies import (
    DEFAULT_PERMISSIONS_POLICY,
    BodySizePolicy,
    CspDirective,
    CsrfPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AuditSink,
    RateLimitBackend,
    SessionAdministrationStore,
    SessionIdentityChanged,
    SessionLivenessPolicy,
    SessionRecord,
    SessionRecordStore,
    SubjectUserStore,
    UsernameTakenError,
    UserRecord,
    WriteLock,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import RedisRateLimitBackend, SingleProcessRateLimitBackend
from webauth.session_administration import (
    NotAnAdminError,
    SessionAdministration,
    SessionSummary,
    UnknownSessionError,
)
from webauth.session_ending import end_session, end_user_sessions, prune_sessions


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

    def set_role(self, user_id: str, role: str) -> UserRecord:
        return HostAccount(user_id, "someone", role, True)


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

    def account_event(self, event: AccountEvent) -> None:
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


def a_host_starts_a_keycloak_login(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig,
) -> str:
    return start_login(relying_party, request, response, config)


def a_host_finishes_a_keycloak_login(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig,
) -> UserRecord | OidcRefusal | AdmissionRefusal:
    accounts: SubjectUserStore = HostAccounts()
    lock: WriteLock = HostLock()
    audit: AuditSink = HostAudit()
    return finish_login(
        relying_party, request, response, config,
        admission=AdmissionConfig(
            bound_issuer="https://keycloak.example/realms/host",
            login_group="/apps/host",
            admin_group="/apps/host/admin",
        ),
        accounts=accounts, lock=lock, audit=audit,
    )


def a_host_logs_out(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig,
) -> str:
    sessions: SessionRecordStore = HostSessions()
    lock: WriteLock = HostLock()
    return log_out(relying_party, request, response, config, sessions=sessions, lock=lock)


def a_host_receives_a_backchannel_logout(
    relying_party: OidcRelyingParty, logout_token: str,
) -> BackchannelLogoutResult:
    accounts: SubjectUserStore = HostAccounts()
    sessions: SessionRecordStore = HostSessions()
    lock: WriteLock = HostLock()
    audit: AuditSink = HostAudit()
    return receive_backchannel_logout(
        relying_party, logout_token,
        accounts=accounts, sessions=sessions, lock=lock, audit=audit,
    )


def a_host_verifies_a_logout_token(
    relying_party: OidcRelyingParty, logout_token: str,
) -> str | None:
    verified = relying_party.verify_logout_token(logout_token)
    return None if isinstance(verified, OidcRefusal) else verified.subject


def a_host_verifies_a_typed_token(verifier: JwtVerifier, token: str) -> VerifiedClaims | Rejected:
    return verifier.verify(token, expected_type="logout+jwt")


def a_host_admits_an_identity(
    identity: OidcIdentity, config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    accounts: SubjectUserStore = HostAccounts()
    lock: WriteLock = HostLock()
    audit: AuditSink = HostAudit()
    return admit_identity(
        identity,
        admission=AdmissionConfig(
            bound_issuer="https://keycloak.example/realms/host",
            login_group=EverySubject.OF_THE_BOUND_ISSUER,
            admin_group=NoAdmins.IN_THIS_APP,
        ),
        accounts=accounts, lock=lock, audit=audit, config=config,
    )


def a_host_uses_the_production_transports() -> tuple[KeySetFetch, TokenRequestPost]:
    key_set_fetch: KeySetFetch = fetch_key_set_over_https
    token_post: TokenRequestPost = post_token_request_over_https
    return key_set_fetch, token_post


def a_host_resolves_the_current_user(
    on_authenticated: Callable[[AuthenticatedUser], None],
) -> AuthDependencies:
    return current_user_dependency(
        session_store=HostSessions,
        audit_sink=HostAudit,
        on_authenticated=on_authenticated,
    )


def a_host_installs_the_middleware(app: FastAPI) -> None:
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            content_security_policy=default_content_security_policy(
                added_sources={
                    CspDirective.STYLE_SRC: ["'unsafe-inline'"],
                    CspDirective.FORM_ACTION: ["https://issuer.example.test"],
                },
            ),
        ),
        csrf_origin=CsrfPolicy(),
        csrf_token=CsrfPolicy(),
    )


def a_host_signs_a_session_in_and_out(response: Response, config: WebAuthConfig) -> None:
    issue_session_cookies(response, "session-id", config)
    clear_session_cookies(response, config)


def a_host_ends_a_session() -> None:
    end_session(HostSessions(), session_id="session-id")


def a_host_names_the_documented_surface() -> tuple[object, ...]:
    return (
        BodySizeLimitMiddleware, BodySizePolicy, CsrfOriginMiddleware,
        CsrfTokenMiddleware, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_PERMISSIONS_POLICY,
        DEFAULT_SESSION_COOKIE_NAME, ExchangeFailure, ExpiryColumnLiveness,
        IdleWindowLiveness, IpRateLimitMiddleware, JwtVerifier,
        KEY_SET_FETCH_DEADLINE_SECONDS, KeySetFetchError, LoginRedirect,
        MAX_AUTHORIZATION_CODE_CHARS, MAX_KEY_SET_BYTES, MAX_KEY_SET_KEYS,
        MAX_SESSION_COOKIE_CHARS, MAX_TOKEN_RESPONSE_BYTES, MonotonicClock,
        LOGOUT_TOKEN_MAX_AGE_SECONDS, NotAnAdminError, OidcClientConfig,
        PENDING_LOGIN_MAX_AGE_SECONDS,
        PLAIN_CSRF_COOKIE_NAME, PLAIN_SESSION_COOKIE_NAME, PendingLogin, RateLimitBackend,
        Rejected, RedisRateLimitBackend, SecurityHeadersMiddleware, SessionRecordStore,
        SessionSummary, SingleProcessRateLimitBackend, TOKEN_EXCHANGE_DEADLINE_SECONDS,
        TokenEndpointError, UnknownSessionError, WebAuthError,
        AccountEventKind.BACKCHANNEL_LOGOUT, UsernameTakenError,
        VerifiedClaims, VerifiedLogout, WallClock, end_user_sessions, install_web_auth_config,
        is_https_url, prune_sessions, session_id_from_request, session_reference,
        unauthenticated_response,
    )
