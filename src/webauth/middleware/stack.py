"""The one order the library's middleware runs in, installed by ``WebAuth.install``."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from logline import RequestLineMiddleware
from starlette.middleware import Middleware

from webauth.middleware.bearer_gate import BearerGate, _BearerGateMiddleware
from webauth.middleware.body_size import _BodySizeLimitMiddleware
from webauth.middleware.client_address import (
    _ClientAddressMiddleware,
    _FrontRequiredMiddleware,
)
from webauth.middleware.csrf import _CsrfOriginMiddleware
from webauth.middleware.path_refusal import _PathRefusalMiddleware
from webauth.middleware.rate_limit import _IpRateLimitMiddleware
from webauth.middleware.security_headers import _SecurityHeadersMiddleware
from webauth.middleware.session_gate import SessionGate, _SessionGateMiddleware
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PublicRule,
    RateLimitPolicy,
    SecurityHeadersPolicy,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from starlette.applications import Starlette

    from webauth.proxies import TrustedProxies
    from webauth.sign_in_routes import SignInPaths

__all__: list[str] = []

_LIBRARY_MIDDLEWARE = (
    _SecurityHeadersMiddleware,
    _PathRefusalMiddleware,
    _BodySizeLimitMiddleware,
    _IpRateLimitMiddleware,
    _BearerGateMiddleware,
    _CsrfOriginMiddleware,
    _SessionGateMiddleware,
)

_BACKCHANNEL_MAX_BODY_BYTES = 32 * 1024


def _with_sign_in_rules(
    sign_in_paths: SignInPaths,
    *,
    body_size: BodySizePolicy,
    rate_limit: RateLimitPolicy,
    csrf_origin: CsrfPolicy,
    session_gate: SessionGate | None,
    bearer_gate: BearerGate | None,
) -> tuple[BodySizePolicy, RateLimitPolicy, CsrfPolicy, SessionGate | None]:
    """The host's policies with the rules the sign-in paths derive put ahead of the host's own,
    and the public rule of the bearer gate's resource behind them."""
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
    if session_gate is not None:
        public = (PublicRule(sign_in_page, methods=frozenset({"GET"})),)
        if posted:
            public += (PublicRule(PathRules(exact=posted), methods=frozenset({"POST"})),)
        resource = None if bearer_gate is None else bearer_gate.resource
        resource_public = () if resource is None else (resource.public_rule,)
        session_gate = replace(
            session_gate, public=(*public, *session_gate.public, *resource_public)
        )
    return (
        replace(
            body_size,
            rules=(
                BodySizeRule(backchannel, _BACKCHANNEL_MAX_BODY_BYTES, methods=frozenset({"POST"})),
                *body_size.rules,
            ),
        ),
        replace(
            rate_limit,
            _sign_in_paths=browser,
            exempt=replace(rate_limit.exempt, exact=rate_limit.exempt.exact | backchannel.exact),
        ),
        replace(
            csrf_origin,
            exempt=replace(csrf_origin.exempt, exact=csrf_origin.exempt.exact | backchannel.exact),
        ),
        session_gate,
    )


def _effective_security_headers(
    sign_in_paths: SignInPaths,
    security_headers: SecurityHeadersPolicy,
    bearer_gate: BearerGate | None,
) -> SecurityHeadersPolicy:
    """The host's policy with the ``no-store`` rules the paths derive put ahead of the host's own:
    the machine paths' and the resource's first, then every sign-in route's."""
    paths = sign_in_paths
    no_store_paths = []
    if bearer_gate is not None and bearer_gate.machine_paths is not None:
        no_store_paths.append(bearer_gate.machine_paths.paths)
    if bearer_gate is not None and bearer_gate.resource is not None:
        no_store_paths.append(bearer_gate.resource.entry_point_rule)
    no_store_paths.append(
        PathRules(
            exact=frozenset(
                path
                for path in (paths.start, paths.callback, paths.logout, paths.backchannel_logout)
                if path
            )
        )
    )
    return SecurityHeadersPolicy(
        content_security_policy=security_headers.content_security_policy,
        cache_control_rules=(
            *(CacheControlRule(rules, "no-store") for rules in no_store_paths),
            *security_headers.cache_control_rules,
        ),
        permissions_policy=security_headers.permissions_policy,
        content_security_policy_rules=security_headers.content_security_policy_rules,
    )


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
    """The middleware to install, outermost first, for the policies the host named;
    ``security_headers`` is the effective policy ``_effective_security_headers`` derives."""
    body_size, rate_limit, csrf_origin, session_gate = _with_sign_in_rules(
        sign_in_paths,
        body_size=body_size or BodySizePolicy(),
        rate_limit=rate_limit or RateLimitPolicy(),
        csrf_origin=csrf_origin,
        session_gate=session_gate,
        bearer_gate=bearer_gate,
    )
    entries = [
        Middleware(_SecurityHeadersMiddleware, policy=security_headers),
        Middleware(_PathRefusalMiddleware),
        Middleware(_BodySizeLimitMiddleware, policy=body_size),
        Middleware(_IpRateLimitMiddleware, policy=rate_limit),
    ]
    if bearer_gate is not None:
        entries.append(Middleware(_BearerGateMiddleware, policy=bearer_gate))
    entries.append(Middleware(_CsrfOriginMiddleware, policy=csrf_origin))
    if session_gate is not None:
        entries.append(Middleware(_SessionGateMiddleware, policy=session_gate))
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
    if any(
        isinstance(entry.cls, type) and issubclass(entry.cls, _ClientAddressMiddleware)
        for entry in app.user_middleware
    ):
        raise RuntimeError(
            "The app already carries a client-address writer; a writer added by hand sits inside "
            "the stack. The composition call places it, and web_auth_front wraps several apps.",
        )


def _add_outermost_first(app: Starlette, entries: Sequence[Middleware]) -> None:
    for entry in reversed(entries):
        app.add_middleware(entry.cls, *entry.args, **entry.kwargs)


def _front_middleware(
    trusted_proxies: TrustedProxies | None, security_headers: SecurityHeadersPolicy
) -> list[Middleware]:
    """The outermost entries: the request line and the writer for ``trusted_proxies``, or, for an
    app a shared front serves (``None``), the guard that refuses a request without that front."""
    if trusted_proxies is None:
        return [Middleware(_FrontRequiredMiddleware, policy=security_headers)]
    return [
        Middleware(RequestLineMiddleware),
        Middleware(_ClientAddressMiddleware, trusted_proxies=trusted_proxies),
    ]


def _install_web_auth_middleware(
    app: Starlette,
    *,
    sign_in_paths: SignInPaths,
    security_headers: SecurityHeadersPolicy,
    csrf_origin: CsrfPolicy,
    body_size: BodySizePolicy | None,
    rate_limit: RateLimitPolicy | None,
    bearer_gate: BearerGate | None,
    session_gate: SessionGate | None,
    trusted_proxies: TrustedProxies | None,
    outside: Sequence[Middleware],
    inside: Sequence[Middleware],
) -> None:
    """Install what ``WebAuth.install`` places, outermost first: logline's request line and the
    client-address writer, only with ``trusted_proxies`` (``None`` for an app a shared front
    serves: a guard refuses a request without that front instead), the host's ``outside`` entries,
    the library stack, the host's ``inside`` entries. An app that already carries library
    middleware is refused untouched.

    The library stack is security headers, path refusal, body size, rate limit, bearer gate, CSRF
    origin, session gate. Security headers sit outside everything so the library's own refusals
    carry them; the path refusal answers 400 to a control character before a rule or route reads
    the path; the body size limit refuses a body declared too large before it costs a rate-limit
    budget or a session lookup; the rate limit sits outside CSRF so a refused forgery spends
    budget; the bearer gate sits inside the rate limit, so a machine request spends the same
    budget, and outside CSRF and the session gate, so neither decides a machine path by a cookie;
    the session gate sits inside all of them, so a request refused before admission never costs a
    session lookup and a forged state-changing request is refused before it renews a session.

    The rules the sign-in paths and the bearer gate's resource derive are put ahead of the host's
    own, so the first match is the derived one.
    """
    _refuse_an_unsound_stack(app)
    effective_security_headers = _effective_security_headers(
        sign_in_paths, security_headers, bearer_gate
    )
    entries = [
        *_front_middleware(trusted_proxies, effective_security_headers),
        *outside,
        *_library_middleware(
            sign_in_paths=sign_in_paths,
            security_headers=effective_security_headers,
            body_size=body_size,
            rate_limit=rate_limit,
            bearer_gate=bearer_gate,
            csrf_origin=csrf_origin,
            session_gate=session_gate,
        ),
        *inside,
    ]
    _add_outermost_first(app, entries)
