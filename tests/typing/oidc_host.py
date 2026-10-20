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

from fastapi import FastAPI, Request, Response, WebSocket
from pydantic import SecretStr

from webauth import WebAuthError
from webauth.config import (
    MAX_SESSION_LIFETIME_SECONDS,
    SessionLifetime,
    WebAuthConfig,
    install_web_auth_config,
)
from webauth.cookies import (
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
    PendingLogin,
    clear_session_cookies,
    issue_session_cookies,
)
from webauth.dependencies import (
    AuthDependencies,
    ConnectionRefusal,
    LoginRedirect,
    authenticate_websocket,
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
)
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
    AdmittedLogin,
    BackchannelLogoutResult,
    EverySubject,
    NoAdmins,
    admit_identity,
    finish_login,
    log_out,
    open_session,
    receive_backchannel_logout,
    start_login,
)
from webauth.oidc_transport import post_token_request_over_https
from webauth.policies import (
    DEFAULT_PERMISSIONS_POLICY,
    BodySizePolicy,
    CspDirective,
    CsrfPolicy,
    PathRules,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
    default_content_security_policy,
)
from webauth.ports import (
    AccountEvent,
    AccountEventKind,
    AuditSink,
    AuthenticatedUser,
    RateLimitBackend,
    SessionRecord,
    SessionRecordStore,
    SubjectUserStore,
    UsernameTakenError,
    UserRecord,
    WallClock,
    WriteLock,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import RedisRateLimitBackend, SingleProcessRateLimitBackend


@dataclass(frozen=True)
class HostAccount:
    id: str
    username: str
    role: str


@dataclass(frozen=True)
class HostSession:
    id: str
    user: HostAccount
    created_at: datetime
    expires_at: datetime


class HostAccounts:
    def get(self, user_id: str) -> HostAccount | None:
        return HostAccount(user_id, "someone", "user")

    def create_for_subject(self, subject: str, username: str, role: str) -> HostAccount:
        return HostAccount(subject, username, role)

    def set_role(self, user_id: str, role: str) -> HostAccount:
        return HostAccount(user_id, "someone", role)


class HostSessions:
    def create(
        self, user_id: str, *, now: datetime, expires_at: datetime,
    ) -> HostSession:
        user = HostAccount(user_id, "someone", "user")
        return HostSession("id", user, now, expires_at)

    def load(self, session_id: str) -> HostSession | None:
        return None

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return True

    def delete(self, session_id: str) -> None:
        return None

    def delete_for_user(self, user_id: str) -> int:
        return 0

    def prune_overflow(self, user_id: str, keep_newest: int) -> None:
        return None


class HostLock:
    def hold(self) -> AbstractContextManager[None]:
        return nullcontext()


class HostAudit:
    def account_event(self, event: AccountEvent) -> None:
        assert event.kind


class HostRateLimits:
    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        return True


def a_host_configures_without_local_credentials() -> WebAuthConfig:
    return WebAuthConfig(
        session_secret=SecretStr("x" * 32),
        trusted_proxies=TrustedProxies.parse("127.0.0.1"),
        rate_limits=HostRateLimits(),
        allowed_hosts_exact=frozenset({"host.example"}),
        allowed_hosts_patterns=(re.compile(r".*\.example"),),
        session_lifetime=SessionLifetime(idle_seconds=3600, absolute_max_age_seconds=86400),
    )


def a_host_starts_a_keycloak_login(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig, return_to: str | None,
) -> str:
    return start_login(relying_party, request, response, config, return_to=return_to)


def a_host_finishes_a_keycloak_login(
    relying_party: OidcRelyingParty, request: Request, response: Response,
    config: WebAuthConfig,
) -> AdmittedLogin | OidcRefusal | AdmissionRefusal:
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


def a_host_sends_the_browser_back(admitted: AdmittedLogin) -> tuple[UserRecord, str]:
    return admitted.account, admitted.return_to or "/"


def a_host_opens_a_session(
    request: Request, config: WebAuthConfig, account: UserRecord,
) -> SessionRecord:
    sessions: SessionRecordStore = HostSessions()
    lock: WriteLock = HostLock()
    return open_session(
        request, config, account,
        sessions=sessions, lock=lock, max_sessions=None,
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
        on_authenticated=on_authenticated,
    )


async def a_host_accepts_a_websocket_only_for_a_signed_in_account(
    websocket: WebSocket,
) -> AuthenticatedUser | None:
    outcome = authenticate_websocket(websocket, sessions=HostSessions())
    if isinstance(outcome, ConnectionRefusal):
        await websocket.close(code=1008)
        return None
    await websocket.accept()
    return outcome


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
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget(name="default", max_requests=60, window_seconds=60),
            rules=(
                RateLimitRule(
                    paths=PathRules(exact=frozenset({"/login"})),
                    budget=RateLimitBudget(name="login", max_requests=10, window_seconds=60),
                ),
            ),
        ),
        csrf_origin=CsrfPolicy(),
        csrf_token=CsrfPolicy(),
    )


def a_host_signs_a_session_in_and_out(response: Response, config: WebAuthConfig) -> None:
    issue_session_cookies(response, "session-id", config)
    clear_session_cookies(response, config)


def a_host_ends_a_session() -> None:
    HostSessions().delete("session-id")


def a_host_names_the_documented_surface() -> tuple[object, ...]:
    return (
        BodySizeLimitMiddleware, BodySizePolicy, CsrfOriginMiddleware,
        CsrfTokenMiddleware, DEFAULT_CSRF_COOKIE_NAME, DEFAULT_PERMISSIONS_POLICY,
        DEFAULT_SESSION_COOKIE_NAME, ExchangeFailure, IpRateLimitMiddleware, JwtVerifier,
        KEY_SET_FETCH_DEADLINE_SECONDS, KeySetFetchError, LoginRedirect,
        MAX_AUTHORIZATION_CODE_CHARS, MAX_KEY_SET_BYTES, MAX_KEY_SET_KEYS,
        MAX_SESSION_COOKIE_CHARS, MAX_TOKEN_RESPONSE_BYTES, MonotonicClock,
        LOGOUT_TOKEN_MAX_AGE_SECONDS, OidcClientConfig,
        PENDING_LOGIN_MAX_AGE_SECONDS,
        PLAIN_CSRF_COOKIE_NAME, PLAIN_SESSION_COOKIE_NAME, PendingLogin, RateLimitBackend,
        Rejected, RedisRateLimitBackend, SecurityHeadersMiddleware, SessionLifetime,
        MAX_SESSION_LIFETIME_SECONDS,
        SessionRecordStore,
        SingleProcessRateLimitBackend, TOKEN_EXCHANGE_DEADLINE_SECONDS,
        TokenEndpointError, WebAuthError,
        AccountEventKind.BACKCHANNEL_LOGOUT, UsernameTakenError,
        VerifiedClaims, VerifiedLogout, WallClock, install_web_auth_config,
        is_https_url, session_id_from_request,
        unauthenticated_response,
    )
