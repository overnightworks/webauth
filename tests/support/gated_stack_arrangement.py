"""The one way the suites put the library's stack on an app: the composition call."""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

from fastapi import FastAPI, Response

from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.oidc_arrangement import (
    a_key_set_endpoint,
    a_realm_client_config,
    an_issuer_called_through,
)
from tests.support.security_headers_arrangement import A_CONTENT_SECURITY_POLICY
from tests.support.session_store_arrangement import SessionRecordsInMemory
from webauth.admission import AdmissionConfig, GroupPath
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy
from webauth.sign_in_routes import LogoutPageText, SignInPaths
from webauth.web_auth import (
    IssuerCalls,
    OidcSignIn,
    SignInPages,
    WebAuth,
    WebAuthSettings,
    WebAuthStores,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from starlette.middleware import Middleware

    from webauth.config import WebAuthConfig
    from webauth.jwt_verification import KeySetFetch
    from webauth.middleware import BearerGate, SessionGate
    from webauth.oidc import OidcClientConfig, TokenRequest
    from webauth.policies import BodySizePolicy, RateLimitPolicy
    from webauth.ports import SessionTransaction, SignInTransaction
    from webauth.proxies import TrustedProxies
    from webauth.web_auth import ServedBehind

GATED_APP_HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy=A_CONTENT_SECURITY_POLICY)
GATED_SIGN_IN_PATHS = SignInPaths(start="/sign-in/start", callback="/sign-in/callback")
GATED_APP_LOGOUT_TEXT = LogoutPageText(language="en", button_label="Sign out")


def a_sign_in_that_never_runs() -> NoReturn:
    """The sign-in transaction of an app whose scenario never signs anyone in."""
    raise AssertionError("this app's scenario does not enter a sign-in transaction")


def a_token_post_nobody_makes(request: TokenRequest) -> NoReturn:
    """The token endpoint of an app whose scenario makes no token request."""
    raise AssertionError(f"a token request was posted to {request.url}")


def an_issuer_nobody_calls(fetch_key_set: KeySetFetch | None = None) -> IssuerCalls:
    """The relying party's calls of an app whose scenario signs nobody in; its key set is
    `fetch_key_set`, else one publishing the "issuer" key."""
    return an_issuer_called_through(
        a_token_post_nobody_makes, fetch_key_set or a_key_set_endpoint("issuer")
    )


def _the_admission_of(client: OidcClientConfig) -> AdmissionConfig:
    return AdmissionConfig(
        bound_issuer=client.issuer,
        login_group=GroupPath("/apps/x"),
        admin_group=GroupPath("/apps/x/admin"),
    )


def _the_refusing_pages_of(sign_in_paths: SignInPaths) -> SignInPages:
    return SignInPages(
        refused=lambda _request, _refusal: Response(status_code=403),
        logout_page_text=(
            None if sign_in_paths.logout is None else lambda _request: GATED_APP_LOGOUT_TEXT
        ),
        ui_language=lambda _request: None,
    )


def install_the_gated_stack(
    app: FastAPI,
    *,
    config: WebAuthConfig,
    sessions: SessionTransaction | None = None,
    session_gate: SessionGate | None = None,
    bearer_of: Callable[[WebAuth], BearerGate] | None = None,
    sign_in: SignInTransaction = a_sign_in_that_never_runs,
    sign_in_paths: SignInPaths = GATED_SIGN_IN_PATHS,
    keeps_id_token: bool = False,
    max_sessions: int | None = None,
    pages: SignInPages | None = None,
    security_headers: SecurityHeadersPolicy = GATED_APP_HEADERS_POLICY,
    csrf_origin: CsrfPolicy | None = None,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
    client: OidcClientConfig | None = None,
    groups: AdmissionConfig | None = None,
    issuer_calls: IssuerCalls | None = None,
    inside: Sequence[Middleware] = (),
    outside: Sequence[Middleware] = (),
    front: TrustedProxies | ServedBehind = TRUSTED_PROXIES,
) -> WebAuth:
    """Build the app's auth with the composition call and install it on `app`.

    The sign-in routes answer for `sign_in_paths`; the relying party reaches a fake issuer and
    key set unless `issuer_calls` names others, and the app keeps no session unless `sessions`
    names the store. `bearer_of` makes the bearer gate from the relying party the call built.
    """
    client = client or a_realm_client_config()
    return _build_and_install(
        app,
        OidcSignIn(
            client=client,
            sign_in_paths=sign_in_paths,
            keeps_id_token=keeps_id_token,
            groups=groups or _the_admission_of(client),
            pages=pages or _the_refusing_pages_of(sign_in_paths),
            issuer_calls=issuer_calls or an_issuer_nobody_calls(),
        ),
        config=config,
        sessions=sessions,
        sign_in=sign_in,
        session_gate=session_gate,
        bearer_of=bearer_of,
        max_sessions=max_sessions,
        security_headers=security_headers,
        csrf_origin=csrf_origin,
        body_size=body_size,
        rate_limit=rate_limit,
        inside=inside,
        outside=outside,
        front=front,
    )


def install_the_stack_without_oidc(
    app: FastAPI,
    *,
    config: WebAuthConfig,
    sessions: SessionTransaction | None = None,
    session_gate: SessionGate | None = None,
    sign_in: SignInTransaction = a_sign_in_that_never_runs,
    max_sessions: int | None = None,
    security_headers: SecurityHeadersPolicy = GATED_APP_HEADERS_POLICY,
    csrf_origin: CsrfPolicy | None = None,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
    front: TrustedProxies | ServedBehind = TRUSTED_PROXIES,
) -> WebAuth:
    """Build the app's auth with the composition call and `oidc=None`, and install it on `app`:
    the stack and the readers, no relying party and no sign-in route."""
    return _build_and_install(
        app,
        None,
        config=config,
        sessions=sessions,
        sign_in=sign_in,
        session_gate=session_gate,
        bearer_of=None,
        max_sessions=max_sessions,
        security_headers=security_headers,
        csrf_origin=csrf_origin,
        body_size=body_size,
        rate_limit=rate_limit,
        inside=(),
        outside=(),
        front=front,
    )


def _build_and_install(
    app: FastAPI,
    oidc: OidcSignIn | None,
    *,
    config: WebAuthConfig,
    sessions: SessionTransaction | None,
    sign_in: SignInTransaction,
    session_gate: SessionGate | None,
    bearer_of: Callable[[WebAuth], BearerGate] | None,
    max_sessions: int | None,
    security_headers: SecurityHeadersPolicy,
    csrf_origin: CsrfPolicy | None,
    body_size: BodySizePolicy | None,
    rate_limit: RateLimitPolicy | None,
    inside: Sequence[Middleware],
    outside: Sequence[Middleware],
    front: TrustedProxies | ServedBehind,
) -> WebAuth:
    auth = WebAuth.build(
        WebAuthSettings(
            config=config,
            max_sessions=max_sessions,
            security_headers=security_headers,
            csrf_origin=csrf_origin or CsrfPolicy(),
            body_size=body_size,
            rate_limit=rate_limit,
        ),
        oidc=oidc,
        stores=WebAuthStores(
            sign_in=sign_in, sessions=sessions or SessionRecordsInMemory(None).in_transaction
        ),
        front=front,
        gate=session_gate,
        outside=tuple(outside),
        inside=tuple(inside),
    )
    auth.install(app, bearer=None if bearer_of is None else bearer_of(auth))
    return auth
