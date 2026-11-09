"""The one order the library's middleware runs in, installed in one call."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from starlette.middleware import Middleware

from webauth.middleware.bearer_gate import BearerGate, BearerGateMiddleware
from webauth.middleware.body_size import BodySizeLimitMiddleware
from webauth.middleware.csrf import CsrfOriginMiddleware
from webauth.middleware.rate_limit import IpRateLimitMiddleware
from webauth.middleware.security_headers import SecurityHeadersMiddleware
from webauth.middleware.session_gate import SessionGate, SessionGateMiddleware
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)

if TYPE_CHECKING:
    from starlette.applications import Starlette

    from webauth.sign_in_routes import SignInPaths

__all__ = [
    "install_web_auth_middleware",
]

_LIBRARY_MIDDLEWARE = (
    SecurityHeadersMiddleware,
    BodySizeLimitMiddleware,
    IpRateLimitMiddleware,
    BearerGateMiddleware,
    CsrfOriginMiddleware,
    SessionGateMiddleware,
)

_BACKCHANNEL_MAX_BODY_BYTES = 32 * 1024
_DEFAULT_RATE_LIMIT = RateLimitPolicy(default=RateLimitBudget("default", 600, 60))
_DEFAULT_BODY_SIZE = BodySizePolicy(default_max_bytes=4 * 1024)


def _with_sign_in_rules(
    sign_in_paths: SignInPaths,
    *,
    security_headers: SecurityHeadersPolicy,
    body_size: BodySizePolicy,
    rate_limit: RateLimitPolicy,
    csrf_origin: CsrfPolicy,
    session_gate: SessionGate | None,
) -> tuple[SecurityHeadersPolicy, BodySizePolicy, RateLimitPolicy, CsrfPolicy, SessionGate | None]:
    """The host's policies with the rules the sign-in paths derive put ahead of the host's own."""
    paths = sign_in_paths
    sign_in_page = PathRules(exact=frozenset({paths.start, paths.callback}))
    browser = PathRules(
        exact=frozenset(path for path in (paths.start, paths.callback, paths.logout) if path)
    )
    posted = frozenset(path for path in (paths.logout, paths.backchannel_logout) if path)
    backchannel = PathRules(
        exact=frozenset()
        if paths.backchannel_logout is None
        else frozenset({paths.backchannel_logout})
    )
    every_route = PathRules(exact=browser.exact | backchannel.exact)
    if session_gate is not None:
        public = (PublicRule(sign_in_page, methods=frozenset({"GET"})),)
        if posted:
            public += (PublicRule(PathRules(exact=posted), methods=frozenset({"POST"})),)
        session_gate = replace(session_gate, public=(*public, *session_gate.public))
    return (
        replace(
            security_headers,
            cache_control_rules=(
                CacheControlRule(every_route, "no-store"),
                *security_headers.cache_control_rules,
            ),
        ),
        replace(
            body_size,
            rules=(
                BodySizeRule(backchannel, _BACKCHANNEL_MAX_BODY_BYTES, methods=frozenset({"POST"})),
                *body_size.rules,
            ),
        ),
        replace(
            rate_limit,
            rules=(RateLimitRule(browser, rate_limit.sign_in), *rate_limit.rules),
            exempt=replace(rate_limit.exempt, exact=rate_limit.exempt.exact | backchannel.exact),
        ),
        replace(
            csrf_origin,
            exempt=replace(csrf_origin.exempt, exact=csrf_origin.exempt.exact | backchannel.exact),
        ),
        session_gate,
    )


def _no_store_paths(bearer_gate: BearerGate) -> list[PathRules]:
    paths = []
    if bearer_gate.machine_paths is not None:
        paths.append(bearer_gate.machine_paths.paths)
    if bearer_gate.resource is not None:
        paths.append(bearer_gate.resource.entry_point_rule)
    return paths


def _library_middleware(
    *,
    sign_in_paths: SignInPaths,
    security_headers: SecurityHeadersPolicy,
    body_size: BodySizePolicy | None,
    rate_limit: RateLimitPolicy | None,
    bearer_gate: BearerGate | None,
    csrf_origin: CsrfPolicy,
    session_gate: SessionGate | None,
) -> list[Middleware]:
    """The middleware to install, outermost first, for the policies the host named."""
    security_headers, body_size, rate_limit, csrf_origin, session_gate = _with_sign_in_rules(
        sign_in_paths,
        security_headers=security_headers,
        body_size=body_size or _DEFAULT_BODY_SIZE,
        rate_limit=rate_limit or _DEFAULT_RATE_LIMIT,
        csrf_origin=csrf_origin,
        session_gate=session_gate,
    )
    if bearer_gate is not None:
        no_store = tuple(
            CacheControlRule(paths, "no-store") for paths in _no_store_paths(bearer_gate)
        )
        security_headers = replace(
            security_headers,
            cache_control_rules=(*no_store, *security_headers.cache_control_rules),
        )
    entries = [Middleware(SecurityHeadersMiddleware, policy=security_headers)]
    entries.append(Middleware(BodySizeLimitMiddleware, policy=body_size))
    entries.append(Middleware(IpRateLimitMiddleware, policy=rate_limit))
    if bearer_gate is not None:
        entries.append(Middleware(BearerGateMiddleware, policy=bearer_gate))
    entries.append(Middleware(CsrfOriginMiddleware, policy=csrf_origin))
    if session_gate is not None:
        entries.append(Middleware(SessionGateMiddleware, policy=session_gate))
    return entries


def _refuse_an_unsound_stack(app: Starlette) -> None:
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
    sign_in_paths: SignInPaths,
    security_headers: SecurityHeadersPolicy,
    csrf_origin: CsrfPolicy,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
    bearer_gate: BearerGate | None = None,
    session_gate: SessionGate | None = None,
) -> None:
    """Install the library's middleware outermost first: security headers, body
    size, rate limit, bearer gate, CSRF origin, session gate.

    ``sign_in_paths`` is the one description of the sign-in routes. From it the installer
    puts these rules ahead of the host's own, so the first match is the derived one:
    ``no-store`` on every sign-in path; the back-channel path's exemption from CSRF and
    from the rate limit and its 32 KiB ``POST`` body rule; with a session gate, the
    public rules of the routes; and the policy's ``sign_in`` budget on start, callback and
    logout. A host adds none of them. Without a ``rate_limit`` the default is 600
    requests per 60 seconds per address, without a ``body_size`` it is 4 KiB.

    Security headers sit outside everything so the library's own refusals (the
    413s, the 429 and 503 with ``Retry-After``, the CSRF 403s and the 500)
    carry them; the body size limit refuses a body declared too large before it
    costs a rate-limit budget or a session lookup; the rate limit sits outside
    CSRF so a refused forgery spends budget; the session gate sits inside all
    of them, so a request refused before admission never costs a session lookup
    and a forged state-changing request is refused before it renews a session.
    The bearer gate sits inside the rate limit, so a machine request spends the
    same budget, and outside CSRF and the session gate, so neither decides a
    machine path by a cookie. With a bearer gate that has machine paths or a resource
    the installed security-headers policy carries their ``no-store`` rule first, so it wins.

    Install once and add no library middleware yourself; an app that already
    carries one, a subclass included, is refused untouched (``RuntimeError``).

    A route that raises, or an app without an installed ``WebAuthConfig``,
    answers the library 500 with the headers (no HSTS without a config), and
    the exception still reaches the server. Once the response has started no
    500 follows, because a second start cannot be sent; the exception reaches
    the server alone.

    Where a host's own middleware goes is in ``docs/host-contract.md``, "Where the host's own
    middleware goes".
    """
    _refuse_an_unsound_stack(app)
    entries = _library_middleware(
        sign_in_paths=sign_in_paths,
        security_headers=security_headers,
        body_size=body_size,
        rate_limit=rate_limit,
        bearer_gate=bearer_gate,
        csrf_origin=csrf_origin,
        session_gate=session_gate,
    )
    for entry in reversed(entries):
        app.add_middleware(entry.cls, *entry.args, **entry.kwargs)
