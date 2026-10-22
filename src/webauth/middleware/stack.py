"""The one order the library's middleware runs in, installed in one call."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from starlette.middleware import Middleware

from webauth.middleware.bearer_gate import BearerGate, BearerGateMiddleware
from webauth.middleware.body_size import BodySizeLimitMiddleware
from webauth.middleware.csrf import CsrfOriginMiddleware, CsrfTokenMiddleware
from webauth.middleware.rate_limit import IpRateLimitMiddleware
from webauth.middleware.security_headers import SecurityHeadersMiddleware
from webauth.middleware.session_gate import SessionGate, SessionGateMiddleware
from webauth.policies import CacheControlRule, SecurityHeadersPolicy

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from webauth.policies import BodySizePolicy, CsrfPolicy, RateLimitPolicy

__all__ = [
    "install_web_auth_middleware",
]

_LIBRARY_MIDDLEWARE = (
    SecurityHeadersMiddleware,
    BodySizeLimitMiddleware,
    IpRateLimitMiddleware,
    BearerGateMiddleware,
    CsrfOriginMiddleware,
    CsrfTokenMiddleware,
    SessionGateMiddleware,
)


def _library_middleware(
    *,
    security_headers: SecurityHeadersPolicy,
    body_size: BodySizePolicy | None,
    rate_limit: RateLimitPolicy | None,
    bearer_gate: BearerGate | None,
    csrf_origin: CsrfPolicy | None,
    csrf_token: CsrfPolicy | None,
    session_gate: SessionGate | None,
) -> list[Middleware]:
    """The middleware to install, outermost first, for the policies the host named."""
    if bearer_gate is not None:
        no_store = CacheControlRule(bearer_gate.paths, "no-store")
        security_headers = replace(
            security_headers,
            cache_control_rules=(no_store, *security_headers.cache_control_rules),
        )
    entries = [Middleware(SecurityHeadersMiddleware, policy=security_headers)]
    if body_size is not None:
        entries.append(Middleware(BodySizeLimitMiddleware, policy=body_size))
    if rate_limit is not None:
        entries.append(Middleware(IpRateLimitMiddleware, policy=rate_limit))
    if bearer_gate is not None:
        entries.append(Middleware(BearerGateMiddleware, policy=bearer_gate))
    if csrf_origin is not None:
        entries.append(Middleware(CsrfOriginMiddleware, policy=csrf_origin))
    if csrf_token is not None:
        entries.append(Middleware(CsrfTokenMiddleware, policy=csrf_token))
    if session_gate is not None:
        entries.append(Middleware(SessionGateMiddleware, policy=session_gate))
    return entries


def _refuse_an_unsound_stack(
    app: Starlette,
    *,
    csrf_origin: CsrfPolicy | None,
    csrf_token: CsrfPolicy | None,
) -> None:
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


def install_web_auth_middleware(
    app: Starlette,
    *,
    security_headers: SecurityHeadersPolicy,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
    bearer_gate: BearerGate | None = None,
    csrf_origin: CsrfPolicy | None = None,
    csrf_token: CsrfPolicy | None = None,
    session_gate: SessionGate | None = None,
) -> None:
    """Install the library's middleware outermost first: security headers, body
    size, rate limit, bearer gate, CSRF origin, CSRF token, session gate.

    Security headers sit outside everything so the library's own refusals (the
    413s, the 429 and 503 with ``Retry-After``, the CSRF 403s and the 500)
    carry them; the body size limit refuses a body declared too large before it
    costs a rate-limit budget or a session lookup; the rate limit sits outside
    CSRF so a refused forgery spends budget; the session gate sits inside all
    of them, so a request refused before admission never costs a session lookup
    and a forged state-changing request is refused before it renews a session.
    The bearer gate sits inside the rate limit, so a machine request spends the
    same budget, and outside CSRF and the session gate, so neither decides a
    machine path by a cookie. With a bearer gate the installed security-headers
    policy carries the gate's ``no-store`` rule first, so it beats a host rule.

    Refuses, before touching ``app``: a token policy without an origin policy
    (``ValueError``); a token policy whose ``token_exempt`` paths (login routes
    skip the token on the promise that origin checking protects them) are not
    all covered by the origin policy (``ValueError``); and an app that already
    carries any library middleware, including a subclass of one, from an
    earlier call or added by hand (``RuntimeError``). Install once and add no
    library middleware yourself.

    Containment is decided by ``CsrfPolicy.token_exemptions_outside_origin_check``: a token
    exemption must be covered by the origin check on every path it exempts,
    and one that cannot be verified (a shape or pattern, or a prefix an origin
    exemption may reach into) is refused; name such paths exactly or by a
    prefix the origin policy protects wholesale.

    A route that raises, or an app without an installed ``WebAuthConfig``,
    answers the library 500 with the headers (no HSTS without a config), and
    the exception still reaches the server. Once the response has started no
    500 follows, because a second start cannot be sent; the exception reaches
    the server alone.

    Where a host's own middleware goes: added before this call it sits inside
    the library stack, so a request the library refuses early (413 by
    Content-Length, 429, 503, the CSRF 403s, the session gate's 302 and 401)
    never reaches it; put one that must see only admitted requests (session
    lookups, audit) there. Added after the call it sits outside, sees every
    library refusal with its headers already set, and is the place for
    access logs and metrics; a response or exception it produces itself does
    not carry the library headers. A host ``BaseHTTPMiddleware`` or
    ``@app.middleware("http")`` makes a response that fails mid-stream look
    complete wherever it sits, and added before the call it also turns the 413
    for a streamed body the route reads into the library 500; write a
    middleware that must see admitted requests as pure ASGI. The library
    middleware run the app in the caller's task, so a ``ContextVar`` that the
    app or an inner middleware sets is visible to an outer host middleware
    after the call returns; a host that relied on ``BaseHTTPMiddleware``'s
    task isolation restores its own context, for example by resetting the
    token it set.
    """
    _refuse_an_unsound_stack(app, csrf_origin=csrf_origin, csrf_token=csrf_token)
    entries = _library_middleware(
        security_headers=security_headers, body_size=body_size, rate_limit=rate_limit,
        bearer_gate=bearer_gate, csrf_origin=csrf_origin, csrf_token=csrf_token,
        session_gate=session_gate,
    )
    for entry in reversed(entries):
        app.add_middleware(entry.cls, *entry.args, **entry.kwargs)
