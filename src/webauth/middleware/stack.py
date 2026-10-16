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
    Refuses, before touching ``app``: a token policy without an origin policy;
    a token policy whose ``token_exempt`` paths (login routes skip the token on
    the promise that origin checking protects them) are not all covered by the
    origin policy; and an app that already carries any library middleware,
    including a subclass of one.

    Containment is decided by ``CsrfPolicy.token_exemptions_outside_origin_check``: a token
    exemption must be covered by the origin check on every path it exempts,
    and one that cannot be verified (a shape or pattern, or a prefix an origin
    exemption may reach into) is refused; name such paths exactly or by a
    prefix the origin policy protects wholesale.
    """
    if csrf_token is not None and csrf_origin is None:
        raise ValueError(
            "csrf_token needs csrf_origin: login routes skip the token on the "
            "promise that the origin check protects them.",
        )
    if csrf_token is not None and csrf_origin is not None:
        uncovered = csrf_origin.token_exemptions_outside_origin_check(csrf_token)
        if uncovered:
            raise ValueError(
                "csrf_token exempts paths the csrf_origin policy does not check: "
                f"{', '.join(uncovered)}.",
            )
    if any(
        isinstance(entry.cls, type) and issubclass(entry.cls, _LIBRARY_MIDDLEWARE)
        for entry in app.user_middleware
    ):
        raise RuntimeError(
            "The app already carries library middleware; install the stack once "
            "and add no library middleware by hand.",
        )
    policies = (security_headers, body_size, rate_limit, csrf_origin, csrf_token)
    for middleware, policy in reversed(
        list(zip(_LIBRARY_MIDDLEWARE, policies, strict=True)),
    ):
        if policy is not None:
            app.add_middleware(middleware, policy=policy)
