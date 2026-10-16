"""The one order the library's middleware runs in, installed in one call."""

from __future__ import annotations

from typing import TYPE_CHECKING

from webauth.middleware.body_size import BodySizeLimitMiddleware
from webauth.middleware.csrf import CsrfOriginMiddleware, CsrfTokenMiddleware
from webauth.middleware.rate_limit import IpRateLimitMiddleware
from webauth.middleware.security_headers import SecurityHeadersMiddleware

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from webauth.policies import (
        BodySizePolicy,
        CsrfPolicy,
        RateLimitPolicy,
        SecurityHeadersPolicy,
    )

_LIBRARY_MIDDLEWARE = (
    SecurityHeadersMiddleware,
    BodySizeLimitMiddleware,
    IpRateLimitMiddleware,
    CsrfOriginMiddleware,
    CsrfTokenMiddleware,
)


def install_web_auth_middleware(
    app: Starlette,
    *,
    security_headers: SecurityHeadersPolicy,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
    csrf_origin: CsrfPolicy | None = None,
    csrf_token: CsrfPolicy | None = None,
) -> None:
    """Install the library's middleware outermost first: security headers, body
    size, rate limit, CSRF origin, CSRF token.

    Security headers sit outside everything so the library's own refusals carry
    them; the rate limit sits outside CSRF so a refused forgery spends budget.
    Refuses, before touching ``app``, a token policy without an origin policy
    (login routes skip the token on the promise that origin checking protects
    them) and an app that already carries any library middleware.
    """
    if csrf_token is not None and csrf_origin is None:
        raise ValueError(
            "csrf_token needs csrf_origin: login routes skip the token on the "
            "promise that the origin check protects them.",
        )
    if any(entry.cls in _LIBRARY_MIDDLEWARE for entry in app.user_middleware):
        raise RuntimeError(
            "The app already carries library middleware; install the stack once "
            "and add no library middleware by hand.",
        )
    outermost_first = (
        (SecurityHeadersMiddleware, security_headers),
        (BodySizeLimitMiddleware, body_size),
        (IpRateLimitMiddleware, rate_limit),
        (CsrfOriginMiddleware, csrf_origin),
        (CsrfTokenMiddleware, csrf_token),
    )
    for middleware, policy in reversed(outermost_first):
        if policy is not None:
            app.add_middleware(middleware, policy=policy)
