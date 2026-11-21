"""A Keycloak-only host: accounts, sessions and sign-in without any local credential.

Every part is typed against the public ports and entry points. CI checks this
file with a pinned pyright against the built wheel, so a port change or an
export a host cannot import fails the build instead of the host's next upgrade.
"""

from __future__ import annotations

import time
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, assert_never

from fastapi import Depends, FastAPI, Request, Response, WebSocket
from pydantic import SecretStr
from starlette.middleware import Middleware
from starlette.requests import HTTPConnection

from webauth import WebAuthError
from webauth.admission import (
    AdmissionConfig,
    AdmissionRefusal,
    AppRole,
    EverySubject,
    NoAdmins,
    app_role,
)
from webauth.config import (
    SessionLifetime,
    WebAuthConfig,
)
from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    MAX_SESSION_COOKIE_CHARS,
    PendingLogin,
    issue_session_cookies,
)
from webauth.dependencies import (
    ConnectionRefusal,
    LoginRedirect,
    account_language_of_session,
    admin_user,
    admit_session,
    authenticate_websocket,
    current_user,
    session_id_from_request,
)
from webauth.https_client import (
    ExchangeFailure,
    KeySetFetchError,
    ProviderMetadataFetchError,
    fetch_key_set_over_https,
    fetch_provider_metadata_over_https,
    is_https_url,
)
from webauth.jwt_verification import (
    KeySetFetch,
    MonotonicClock,
)
from webauth.languages import AppLanguages, resolve_language
from webauth.middleware import (
    BearerGate,
    MachinePaths,
    MarkedRoute,
    PersonPaths,
    ProtectedResource,
    SessionGate,
    admitted_admin,
    admitted_user,
    bearer_caller,
    exchanged_access_token,
    is_resource_admission,
    resource_person,
)
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    ExchangedAccess,
    OidcClientConfig,
    OidcDiscoveryError,
    OidcIdentity,
    OidcRefusal,
    OidcRelyingParty,
    ProviderMetadataFetch,
    TokenEndpointError,
    TokenRequestPost,
    VerifiedAccessToken,
    VerifiedLogout,
    discover_oidc_client_config,
)
from webauth.oidc_login import (
    AccessTokenRefusal,
    AccessTokenRefusalReason,
    current_groups,
    fresh_access_token,
)
from webauth.oidc_transport import post_token_request_over_https
from webauth.policies import (
    AuthorizedParties,
    BodySizePolicy,
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
    AccountKind,
    AuthenticatedUser,
    BearerCaller,
    RateLimitBackend,
    SessionRecord,
    SessionRecordStore,
    SessionRenewalStore,
    SessionTransaction,
    SignInStores,
    SignInTransaction,
    UsernameTakenError,
    UserRecord,
    WallClock,
)
from webauth.proxies import TrustedProxies, client_address, request_is_https
from webauth.rate_limit import RedisRateLimitBackend, SingleProcessRateLimitBackend
from webauth.session_groups import SessionGroups
from webauth.sign_in_routes import (
    LogoutPageText,
    RefusalPage,
    SignInPaths,
    SignInRefusal,
)
from webauth.web_auth import (
    IssuerCalls,
    ServedBehind,
    SignInPages,
    WebAuth,
    WebAuthSettingError,
    WebAuthSettings,
    WebAuthStores,
    web_auth_front,
)

if TYPE_CHECKING:
    from starlette.types import ASGIApp


@dataclass(frozen=True)
class HostAccount:
    id: str
    username: str
    role: str
    kind: AccountKind


@dataclass(frozen=True)
class HostSession:
    id: str
    user: HostAccount
    created_at: datetime
    expires_at: datetime
    refresh_token: SecretStr | None
    id_token: SecretStr | None
    account_language: str | None


class HostAccounts:
    def get(self, user_id: str) -> HostAccount | None:
        return HostAccount(user_id, "someone", "user", AccountKind.PERSON)

    def create_for_subject(
        self, subject: str, username: str, role: str, kind: AccountKind
    ) -> HostAccount:
        return HostAccount(subject, username, role, kind)

    def set_role(self, user_id: str, role: str) -> HostAccount:
        return HostAccount(user_id, "someone", role, AccountKind.PERSON)

    def set_kind(self, user_id: str, kind: AccountKind) -> HostAccount:
        return HostAccount(user_id, "someone", "user", kind)


class HostSessions:
    def create(
        self,
        user_id: str,
        *,
        session_id: str,
        now: datetime,
        expires_at: datetime,
        refresh_token: SecretStr | None,
        id_token: SecretStr | None,
        account_language: str | None,
    ) -> HostSession:
        user = HostAccount(user_id, "someone", "user", AccountKind.PERSON)
        return HostSession(
            session_id, user, now, expires_at, refresh_token, id_token, account_language
        )

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


class HostRenewals:
    """A request-path view of the sessions: it finds, touches and rotates, and ends nothing."""

    def load(self, session_id: str) -> HostSession | None:
        return None

    def touch(self, session_id: str, *, expires_at: datetime) -> bool:
        return True

    def replace_refresh_token(self, session_id: str, *, refresh_token: SecretStr) -> bool:
        return True


class HostAudit:
    def account_event(self, event: AccountEvent) -> None:
        _ = event.kind


class HostRateLimits:
    def is_allowed(self, key: str, *, limit: int, window_seconds: int) -> bool:
        return True


def a_host_configures_without_local_credentials() -> WebAuthConfig:
    return WebAuthConfig(
        session_secret=SecretStr("x" * 32),
        rate_limits=HostRateLimits(),
        allowed_hosts_exact=frozenset({"host.example"}),
        session_lifetime=SessionLifetime(idle_seconds=3600, absolute_max_age_seconds=86400),
    )


def a_host_sign_in_transaction() -> AbstractContextManager[SignInStores]:
    stores = SignInStores(accounts=HostAccounts(), sessions=HostSessions(), audit=HostAudit())
    return nullcontext(stores)


def a_host_refuses_a_sign_in(request: Request, refusal: SignInRefusal) -> Response:
    return Response(status_code=403 if refusal.page is RefusalPage.NO_ACCESS else 400)


def a_host_settings(client: OidcClientConfig, config: WebAuthConfig) -> WebAuthSettings:
    return WebAuthSettings(
        config=config,
        client=client,
        sign_in_paths=SignInPaths(
            start="/login/oidc",
            callback="/auth/callback",
            logout="/logout",
            backchannel_logout="/auth/backchannel-logout",
        ),
        keeps_id_token=True,
        max_sessions=None,
        security_headers=SecurityHeadersPolicy(
            content_security_policy=default_content_security_policy(
                added_sources={
                    CspDirective.STYLE_SRC: ["'unsafe-inline'"],
                    CspDirective.FORM_ACTION: ["https://issuer.example.test"],
                },
            ),
        ),
        csrf_origin=CsrfPolicy(),
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget(name="default", max_requests=60, window_seconds=60),
            rules=(
                RateLimitRule(
                    paths=PathRules(exact=frozenset({"/login"})),
                    budget=RateLimitBudget(name="login", max_requests=10, window_seconds=60),
                ),
            ),
        ),
    )


def a_host_composes_its_auth(
    client: OidcClientConfig, config: WebAuthConfig, front: TrustedProxies | ServedBehind
) -> WebAuth:
    sign_in: SignInTransaction = a_host_sign_in_transaction
    sessions: SessionTransaction = a_host_renewal_transaction
    key_set_fetch, token_post = a_host_uses_the_production_transports()
    return WebAuth.build(
        a_host_settings(client, config),
        stores=WebAuthStores(sign_in=sign_in, sessions=sessions),
        groups=AdmissionConfig(
            bound_issuer=client.issuer,
            login_group="/apps/host",
            admin_group="/apps/host/admin",
        ),
        pages=SignInPages(
            refused=a_host_refuses_a_sign_in,
            logout_page_text=lambda _request: LogoutPageText(
                language="en", button_label="Sign out"
            ),
            ui_language=a_host_names_the_language_of_a_request,
        ),
        front=front,
        gate=SessionGate(
            login_redirect=LoginRedirect(path="/login", redirect_query_param="next"),
            public=(PublicRule(PathRules(exact=frozenset({"/login"}))),),
        ),
        outside=(Middleware(a_host_middleware_that_sees_every_request),),
        inside=(Middleware(a_host_middleware_that_sees_admitted_requests),),
        issuer_calls=IssuerCalls(
            post_token_request=token_post,
            fetch_key_set=key_set_fetch,
            monotonic_clock=time.monotonic,
        ),
    )


def a_host_serves_its_apps_behind_one_front(router: ASGIApp) -> ASGIApp:
    return web_auth_front(router, trusted_proxies=TrustedProxies.parse("127.0.0.1"))


def a_host_middleware_that_sees_every_request(app: ASGIApp) -> ASGIApp:
    return app


def a_host_middleware_that_sees_admitted_requests(app: ASGIApp) -> ASGIApp:
    return app


def a_host_installs_its_auth(app: FastAPI, auth: WebAuth, bearer: BearerGate | None) -> None:
    auth.install(app, bearer=bearer)


def a_host_names_the_language_of_a_request(request: Request) -> str | None:
    return resolve_language(
        AppLanguages(offered=("en", "de"), default="en"),
        account_tag=None,
        accept_language=request.headers.get("accept-language"),
    )


def a_host_takes_the_login_redirect_of_its_sign_in_paths(paths: SignInPaths) -> LoginRedirect:
    return paths.login_redirect


def a_host_gets_a_fresh_access_token(
    relying_party: OidcRelyingParty,
    session_id: str,
    config: WebAuthConfig,
) -> SecretStr | AccessTokenRefusalReason:
    outcome = fresh_access_token(
        relying_party,
        session_id,
        session_transaction=lambda: nullcontext(HostSessions()),
        config=config,
    )
    return outcome.reason if isinstance(outcome, AccessTokenRefusal) else outcome


def a_host_maps_an_access_token_refusal(refusal: AccessTokenRefusal) -> int:
    match refusal.reason:
        case AccessTokenRefusalReason.SESSION_ENDED:
            return 401
        case AccessTokenRefusalReason.SIGN_IN_AGAIN:
            return 403
        case AccessTokenRefusalReason.ISSUER_UNAVAILABLE:
            return 503
        case unhandled:
            assert_never(unhandled)


def a_host_gets_current_groups(
    relying_party: OidcRelyingParty,
    session_id: str,
    config: WebAuthConfig,
) -> tuple[str, ...] | int:
    outcome = current_groups(
        relying_party,
        session_id,
        session_transaction=lambda: nullcontext(HostSessions()),
        config=config,
    )
    if isinstance(outcome, AccessTokenRefusal):
        return a_host_maps_an_access_token_refusal(outcome)
    return outcome


async def a_host_reads_the_app_role_of_a_sessions_current_groups(
    session_groups: SessionGroups,
    session_id: str,
    connection: HTTPConnection,
    admission: AdmissionConfig,
) -> tuple[AppRole | None, AppRole | None] | AccessTokenRefusal:
    of_session = await session_groups.of_session(session_id)
    of_connection = await session_groups.of_connection(connection)
    if isinstance(of_session, AccessTokenRefusal):
        return of_session
    if isinstance(of_connection, AccessTokenRefusal):
        return of_connection
    return app_role(of_session, admission), app_role(of_connection, admission)


def a_host_verifies_a_logout_token(
    relying_party: OidcRelyingParty,
    logout_token: str,
) -> str | None:
    verified = relying_party.verify_logout_token(logout_token)
    return None if isinstance(verified, OidcRefusal) else verified.subject


def a_host_verifies_an_access_token(
    relying_party: OidcRelyingParty,
    access_token: str,
) -> VerifiedAccessToken | OidcRefusal:
    return relying_party.verify_access_token(
        access_token,
        authorized_parties=AuthorizedParties(frozenset({"hal"})),
    )


def a_host_verifies_a_resource_token(
    relying_party: OidcRelyingParty,
    resource: ProtectedResource,
    access_token: str,
) -> VerifiedAccessToken | OidcRefusal:
    verify = relying_party.resource_token_verifier(
        resource_url=resource.url,
        scope=resource.scope,
        authorized_parties=resource.authorized_parties,
        agent_group=resource.agent_group,
    )
    return verify(access_token)


def a_host_declares_its_machine_paths() -> BearerGate:
    return BearerGate(
        machine_paths=MachinePaths(
            PathRules(prefixes=("/api/admin/",)),
            AuthorizedParties(frozenset({"hal"})),
        ),
    )


def a_host_declares_its_person_paths() -> BearerGate:
    return BearerGate(
        person_paths=PersonPaths(
            PathRules(prefixes=("/api/",)),
            AuthorizedParties(frozenset({"hal"})),
        ),
    )


def a_host_declares_its_resource() -> BearerGate:
    return BearerGate(
        resource=ProtectedResource(
            "https://app.example/mcp",
            "mcp:tools",
            "/apps/host/mcp",
            "/agents",
            AuthorizedParties(frozenset({"agent"})),
            marked_routes=frozenset({MarkedRoute("GET", "/notes/{note}")}),
        ),
    )


def a_host_reads_the_resource_person(app: FastAPI) -> None:
    @app.post("/mcp")
    def mcp(request: Request) -> str:
        return resource_person(request).username


def a_host_exchanges_the_admitted_token(app: FastAPI) -> None:
    @app.post("/mcp/calendar")
    async def calendar(request: Request) -> str:
        exchanged: ExchangedAccess | OidcRefusal = await exchanged_access_token(
            request, scopes=("calendar:read",)
        )
        if isinstance(exchanged, OidcRefusal):
            return exchanged.reason.value
        return f"{exchanged.access_token.get_secret_value()} until {exchanged.expires_at}"


def a_host_reads_whether_the_resource_admitted_the_request(app: FastAPI) -> None:
    @app.post("/share")
    def share(request: Request, user: AuthenticatedUser = Depends(current_user)) -> bool:
        return is_resource_admission(request) and user.agent is None


def a_host_reads_the_token_person(app: FastAPI) -> None:
    @app.get("/api/me")
    def me(user: AuthenticatedUser = Depends(current_user)) -> str:
        return user.username


def a_host_reads_the_admin(app: FastAPI) -> None:
    @app.get("/admin")
    def admin(user: AuthenticatedUser = Depends(admin_user)) -> str:
        return user.username


def a_host_serves_a_machine_route(app: FastAPI) -> None:
    @app.get("/api/admin/export")
    def export(caller: BearerCaller = Depends(bearer_caller)) -> str:
        return caller.subject


def a_second_service_reads_the_app_role_of_its_token_groups(groups: list[str]) -> AppRole | None:
    return app_role(
        groups,
        AdmissionConfig(
            bound_issuer="https://keycloak.example/realms/host",
            login_group="/apps/host",
            admin_group="/apps/host/admin",
        ),
    )


def a_host_uses_the_production_transports() -> tuple[KeySetFetch, TokenRequestPost]:
    key_set_fetch: KeySetFetch = fetch_key_set_over_https
    token_post: TokenRequestPost = post_token_request_over_https
    return key_set_fetch, token_post


def a_host_discovers_its_client_configuration(issuer: str, secret: SecretStr) -> OidcClientConfig:
    provider_metadata_fetch: ProviderMetadataFetch = fetch_provider_metadata_over_https
    return discover_oidc_client_config(
        issuer,
        fetch_provider_metadata=provider_metadata_fetch,
        client_id="host",
        client_secret=secret,
        redirect_uri="https://host.example/auth/callback",
        post_logout_redirect_uri="https://host.example/",
        scopes=("openid", "profile"),
        leeway_seconds=30,
    )


def a_host_gets_a_workload_token(relying_party: OidcRelyingParty) -> SecretStr | OidcRefusal:
    return relying_party.workload_access_token(scopes=("agent-service-audience",))


async def a_host_accepts_a_websocket_only_for_a_signed_in_account(
    websocket: WebSocket,
) -> AuthenticatedUser | None:
    outcome = authenticate_websocket(websocket)
    if isinstance(outcome, ConnectionRefusal):
        await websocket.close(code=1008)
        return None
    await websocket.accept()
    return outcome


def a_host_admits_a_session_without_a_request(
    session_id: str,
    config: WebAuthConfig,
) -> AuthenticatedUser | ConnectionRefusal:
    return admit_session(session_id, sessions=HostRenewals(), config=config)


def a_host_reads_the_account_language(
    connection: HTTPConnection,
    config: WebAuthConfig,
) -> str | None:
    return account_language_of_session(connection, sessions=HostRenewals(), config=config)


def a_host_renewal_transaction() -> AbstractContextManager[HostRenewals]:
    return nullcontext(HostRenewals())


def a_host_reads_the_admitted_user(request: Request) -> str | None:
    user = admitted_user(request)
    return None if user is None else user.username


def a_host_reads_the_client_it_recorded(connection: HTTPConnection) -> tuple[str, bool]:
    return client_address(connection), request_is_https(connection)


def a_host_reads_the_admitted_admin(request: Request) -> str:
    return admitted_admin(request).username


def a_host_signs_a_session_in(response: Response, config: WebAuthConfig) -> None:
    issue_session_cookies(response, "session-id", config)


def a_host_ends_a_session() -> None:
    HostSessions().delete("session-id")


def _surface_of_the_errors_and_the_verified_records() -> tuple[object, ...]:
    return (
        TokenEndpointError,
        WebAuthError,
        AccountEventKind.BACKCHANNEL_LOGOUT,
        UsernameTakenError,
        AdmissionRefusal,
        EverySubject,
        NoAdmins,
        OidcIdentity,
        SessionRecord,
        UserRecord,
        VerifiedAccessToken,
        VerifiedLogout,
        WallClock,
        WebAuthSettingError,
        admit_session,
        bearer_caller,
        is_https_url,
        session_id_from_request,
    )


def _surface_of_the_gates_and_limits() -> tuple[object, ...]:
    return (
        AuthorizedParties,
        BearerCaller,
        MachinePaths,
        PersonPaths,
        ProtectedResource,
        BodySizePolicy,
        DEFAULT_SESSION_COOKIE_NAME,
        ExchangeFailure,
        KeySetFetchError,
        LoginRedirect,
        ProviderMetadataFetchError,
        MAX_SESSION_COOKIE_CHARS,
        MonotonicClock,
    )


def _surface_of_the_login_and_session_flow() -> tuple[object, ...]:
    return (
        OidcClientConfig,
        OidcDiscoveryError,
        PENDING_LOGIN_MAX_AGE_SECONDS,
        discover_oidc_client_config,
        PendingLogin,
        RateLimitBackend,
        RedisRateLimitBackend,
        SessionLifetime,
        SessionGate,
        SessionRecordStore,
        SessionRenewalStore,
        SessionTransaction,
        PublicRule,
        admitted_admin,
        admitted_user,
        SingleProcessRateLimitBackend,
    )


def a_host_names_the_documented_surface() -> tuple[object, ...]:
    return (
        *_surface_of_the_gates_and_limits(),
        *_surface_of_the_login_and_session_flow(),
        *_surface_of_the_errors_and_the_verified_records(),
    )
