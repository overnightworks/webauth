"""A Keycloak-only host: accounts, sessions and sign-in without any local credential.

Every part is typed against the public ports and entry points. CI checks this
file with a pinned pyright against the built wheel, so a port change or an
export a host cannot import fails the build instead of the host's next upgrade.
"""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime

from fastapi import Depends, FastAPI, Request, Response, WebSocket
from pydantic import SecretStr

from webauth import WebAuthError
from webauth.config import (
    MAX_SESSION_LIFETIME_SECONDS,
    SessionLifetime,
    WebAuthConfig,
    install_web_auth_config,
)
from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PLAIN_SESSION_COOKIE_NAME,
    PendingLogin,
    issue_session_cookies,
)
from webauth.dependencies import (
    AuthDependencies,
    ConnectionRefusal,
    LoginRedirect,
    admit_session,
    authenticate_websocket,
    current_user_dependency,
    session_id_from_request,
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
    BearerGate,
    BearerGateMiddleware,
    BodySizeLimitMiddleware,
    CsrfOriginMiddleware,
    IpRateLimitMiddleware,
    SecurityHeadersMiddleware,
    SessionGate,
    SessionGateMiddleware,
    admitted_admin,
    admitted_user,
    bearer_caller,
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
    VerifiedAccessToken,
    VerifiedLogout,
)
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    AdmissionConfig,
    AdmissionRefusal,
    AppRole,
    BackchannelLogoutResult,
    EverySubject,
    NoAdmins,
    app_role,
    fresh_access_token,
    receive_backchannel_logout,
)
from webauth.oidc_transport import post_token_request_over_https
from webauth.policies import (
    DEFAULT_PERMISSIONS_POLICY,
    AuthorizedParties,
    BodySizePolicy,
    CacheControlRule,
    CspDirective,
    CsrfPolicy,
    PathRules,
    PublicRule,
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
    BearerCaller,
    RateLimitBackend,
    SessionRecord,
    SessionRecordStore,
    SessionTransaction,
    SignInStores,
    SignInTransaction,
    SubjectUserStore,
    UsernameTakenError,
    UserRecord,
    WallClock,
    WriteLock,
)
from webauth.proxies import TrustedProxies
from webauth.rate_limit import RedisRateLimitBackend, SingleProcessRateLimitBackend
from webauth.sign_in_routes import (
    RefusalPage,
    SignInPaths,
    SignInRefusal,
    install_sign_in_routes,
)


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
    refresh_token: SecretStr | None
    id_token: SecretStr | None


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
        refresh_token: SecretStr | None, id_token: SecretStr | None,
    ) -> HostSession:
        user = HostAccount(user_id, "someone", "user")
        return HostSession("id", user, now, expires_at, refresh_token, id_token)

    def load(self, session_id: str) -> HostSession | None:
        return None

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return True

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
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
        session_lifetime=SessionLifetime(idle_seconds=3600, absolute_max_age_seconds=86400),
    )


def a_host_sign_in_transaction() -> AbstractContextManager[SignInStores]:
    stores = SignInStores(accounts=HostAccounts(), sessions=HostSessions(), audit=HostAudit())
    return nullcontext(stores)


def a_host_refuses_a_sign_in(request: Request, refusal: SignInRefusal) -> Response:
    return Response(status_code=403 if refusal.page is RefusalPage.NO_ACCESS else 400)


def a_host_installs_the_sign_in_routes(app: FastAPI, relying_party: OidcRelyingParty) -> None:
    transaction: SignInTransaction = a_host_sign_in_transaction
    install_sign_in_routes(
        app,
        paths=SignInPaths(start="/login/oidc", callback="/auth/callback", logout="/logout"),
        relying_party=lambda _request: relying_party,
        admission=AdmissionConfig(
            bound_issuer="https://keycloak.example/realms/host",
            login_group="/apps/host",
            admin_group="/apps/host/admin",
        ),
        transaction=transaction,
        refused=a_host_refuses_a_sign_in,
        keeps_id_token=True,
        max_sessions=None,
        logout_button_label=lambda _request: "Sign out",
    )


def a_host_derives_the_policies_of_its_sign_in_paths(
    paths: SignInPaths,
) -> tuple[tuple[PublicRule, ...], PathRules, CacheControlRule, LoginRedirect]:
    return (
        paths.public_rules, paths.browser_paths, paths.cache_control_rule, paths.login_redirect,
    )


def a_host_gets_a_fresh_access_token(
    relying_party: OidcRelyingParty, session_id: str, config: WebAuthConfig,
) -> SecretStr | AccessTokenRefusalReason:
    outcome = fresh_access_token(
        relying_party, session_id,
        session_transaction=lambda: nullcontext(HostSessions()),
        config=config,
    )
    return outcome.reason if isinstance(outcome, AccessTokenRefusal) else outcome


def a_host_receives_a_backchannel_logout(
    relying_party: OidcRelyingParty, form_body: bytes, content_type: str | None,
) -> BackchannelLogoutResult:
    accounts: SubjectUserStore = HostAccounts()
    sessions: SessionRecordStore = HostSessions()
    lock: WriteLock = HostLock()
    audit: AuditSink = HostAudit()
    return receive_backchannel_logout(
        relying_party, form_body, content_type,
        accounts=accounts, sessions=sessions, lock=lock, audit=audit,
    )


def a_host_verifies_a_logout_token(
    relying_party: OidcRelyingParty, logout_token: str,
) -> str | None:
    verified = relying_party.verify_logout_token(logout_token)
    return None if isinstance(verified, OidcRefusal) else verified.subject


def a_host_verifies_a_typed_token(verifier: JwtVerifier, token: str) -> VerifiedClaims | Rejected:
    return verifier.verify(token, expected_type="logout+jwt")


def a_host_verifies_a_token_of_several_media_types(
    verifier: JwtVerifier, token: str,
) -> VerifiedClaims | Rejected:
    return verifier.verify(token, expected_media_types=frozenset({"at+jwt", "application/at+jwt"}))


def a_host_verifies_an_access_token(
    relying_party: OidcRelyingParty, access_token: str,
) -> VerifiedAccessToken | OidcRefusal:
    return relying_party.verify_access_token(
        access_token, authorized_parties=AuthorizedParties(frozenset({"hal"})),
    )


def a_host_declares_its_machine_paths(
    relying_party: OidcRelyingParty, config: AdmissionConfig,
) -> BearerGate:
    return BearerGate(
        paths=PathRules(prefixes=("/api/admin/",)),
        relying_party=relying_party,
        admission=config,
        authorized_parties=AuthorizedParties(frozenset({"hal"})),
    )


def a_host_serves_a_machine_route(app: FastAPI) -> None:
    @app.get("/api/admin/export")
    def export(caller: BearerCaller = Depends(bearer_caller)) -> str:
        return caller.subject


def a_second_service_reads_the_app_role_of_its_token_groups(groups: list[str]) -> AppRole | None:
    return app_role(groups, AdmissionConfig(
        bound_issuer="https://keycloak.example/realms/host",
        login_group="/apps/host",
        admin_group="/apps/host/admin",
    ))


def a_host_uses_the_production_transports() -> tuple[KeySetFetch, TokenRequestPost]:
    key_set_fetch: KeySetFetch = fetch_key_set_over_https
    token_post: TokenRequestPost = post_token_request_over_https
    return key_set_fetch, token_post


def a_host_gets_a_workload_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    return relying_party.workload_access_token()


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


def a_host_admits_a_session_without_a_request(
    session_id: str, config: WebAuthConfig,
) -> AuthenticatedUser | ConnectionRefusal:
    return admit_session(session_id, sessions=HostSessions(), config=config)


def a_host_installs_the_middleware(app: FastAPI, bearer_gate: BearerGate) -> None:
    install_web_auth_middleware(
        app,
        bearer_gate=bearer_gate,
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
        session_gate=SessionGate(
            session_transaction=a_host_session_transaction,
            login_redirect=LoginRedirect(path="/login", redirect_query_param="next"),
            public=(PublicRule(PathRules(exact=frozenset({"/login"}))),),
        ),
    )


def a_host_session_transaction() -> AbstractContextManager[SessionRecordStore]:
    return nullcontext(HostSessions())


def a_host_reads_the_admitted_user(request: Request) -> str | None:
    user = admitted_user(request)
    return None if user is None else user.username


def a_host_reads_the_admitted_admin(request: Request) -> str:
    return admitted_admin(request).username


def a_host_signs_a_session_in(response: Response, config: WebAuthConfig) -> None:
    issue_session_cookies(response, "session-id", config)


def a_host_ends_a_session() -> None:
    HostSessions().delete("session-id")


def a_host_names_the_documented_surface() -> tuple[object, ...]:
    return (
        AuthorizedParties, BearerCaller, BearerGateMiddleware, BodySizeLimitMiddleware,
        BodySizePolicy, CsrfOriginMiddleware,
        DEFAULT_PERMISSIONS_POLICY,
        DEFAULT_SESSION_COOKIE_NAME, ExchangeFailure, IpRateLimitMiddleware, JwtVerifier,
        KEY_SET_FETCH_DEADLINE_SECONDS, KeySetFetchError, LoginRedirect,
        MAX_AUTHORIZATION_CODE_CHARS, MAX_KEY_SET_BYTES, MAX_KEY_SET_KEYS,
        MAX_SESSION_COOKIE_CHARS, MAX_TOKEN_RESPONSE_BYTES, MonotonicClock,
        LOGOUT_TOKEN_MAX_AGE_SECONDS, OidcClientConfig,
        PENDING_LOGIN_MAX_AGE_SECONDS,
        PLAIN_SESSION_COOKIE_NAME, PendingLogin, RateLimitBackend,
        Rejected, RedisRateLimitBackend, SecurityHeadersMiddleware, SessionLifetime,
        MAX_SESSION_LIFETIME_SECONDS,
        SessionGate, SessionGateMiddleware, SessionRecordStore, SessionTransaction,
        PublicRule, admitted_admin, admitted_user,
        SingleProcessRateLimitBackend, TOKEN_EXCHANGE_DEADLINE_SECONDS,
        TokenEndpointError, WebAuthError,
        AccountEventKind.BACKCHANNEL_LOGOUT, UsernameTakenError,
        AdmissionRefusal, EverySubject, NoAdmins, OidcIdentity, SessionRecord, UserRecord,
        VerifiedAccessToken, VerifiedClaims, VerifiedLogout, WallClock, admit_session,
        bearer_caller, install_web_auth_config,
        is_https_url, session_id_from_request,
    )
