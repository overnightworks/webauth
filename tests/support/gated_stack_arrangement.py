"""The one way the suites put the library's stack on an app: the composition call."""

from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

from fastapi import FastAPI, Response

from tests.support.client_address_arrangement import TRUSTED_PROXIES
from tests.support.oidc_arrangement import (
    FakeClock,
    a_key_set_endpoint,
    a_realm_client_config,
)
from tests.support.session_store_arrangement import SessionRecordsInMemory
from webauth.admission import AdmissionConfig
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy
from webauth.sign_in_routes import LogoutPageText, SignInPaths
from webauth.web_auth import (
    IssuerCalls,
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

GATED_APP_HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
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
    return IssuerCalls(
        post_token_request=a_token_post_nobody_makes,
        fetch_key_set=fetch_key_set or a_key_set_endpoint("issuer"),
        monotonic_clock=FakeClock(5_000.0),
    )


def _the_admission_of(client: OidcClientConfig) -> AdmissionConfig:
    return AdmissionConfig(
        bound_issuer=client.issuer, login_group="/apps/x", admin_group="/apps/x/admin"
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
    auth = WebAuth.build(
        WebAuthSettings(
            config=config,
            client=client,
            sign_in_paths=sign_in_paths,
            keeps_id_token=keeps_id_token,
            max_sessions=max_sessions,
            security_headers=security_headers,
            csrf_origin=csrf_origin or CsrfPolicy(),
            body_size=body_size,
            rate_limit=rate_limit,
        ),
        stores=WebAuthStores(
            sign_in=sign_in, sessions=sessions or SessionRecordsInMemory(None).in_transaction
        ),
        groups=groups or _the_admission_of(client),
        pages=pages or _the_refusing_pages_of(sign_in_paths),
        front=front,
        gate=session_gate,
        outside=tuple(outside),
        inside=tuple(inside),
        issuer_calls=issuer_calls or an_issuer_nobody_calls(),
    )
    auth.install(app, bearer=None if bearer_of is None else bearer_of(auth))
    return auth
