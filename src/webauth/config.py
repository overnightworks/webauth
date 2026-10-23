"""The deployment facts the auth machinery reads, supplied by the host application.

The library decides nothing about its own deployment: the application builds
one `WebAuthConfig` at startup and installs it on the ASGI application, and
every reader below takes it from the request. Nothing here reaches for an
environment variable, a settings singleton, or the application's own context.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, get_args

from starlette.requests import HTTPConnection

from webauth._validation import require_positive_whole_number
from webauth.cookies import (
    _DEFAULT_COOKIE_SAMESITE,
    _DEFAULT_CSRF_HEADER_NAME,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_SESSION_COOKIE_NAME,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
    CookieSameSite,
    _default_cookie_name,
    _is_host_only_cookie_name,
    _is_reserved_cookie_name,
    _is_secure_prefixed_cookie_name,
    _is_valid_cookie_name,
)

if TYPE_CHECKING:
    from pydantic import SecretStr
    from starlette.applications import Starlette

    from webauth.ports import (
        RateLimitBackend,
        WallClock,
    )
    from webauth.proxies import TrustedProxies

__all__ = [
    "MAX_SESSION_LIFETIME_SECONDS",
    "SessionLifetime",
    "WebAuthConfig",
    "install_web_auth_config",
    "installed_web_auth_config",
    "web_auth_config",
]

_MIN_SESSION_SECRET_CHARS: Final = 32
_DEFAULT_IPV6_BUDGET_PREFIX: Final = 64
# Shorter than /32 would pool whole providers into one budget; longer than /128
# is not an IPv6 prefix at all.
_IPV6_BUDGET_PREFIX_RANGE: Final = range(32, 129)
_DEFAULT_ADMIN_ROLE: Final = "admin"
_DEFAULT_USER_ROLE: Final = "user"

_WEB_AUTH_STATE_ATTRIBUTE: Final = "webauth"


class _DefaultCookieName(str):
    """A cookie name the library chose because the host named none.

    Every reader sees a plain ``str``. The type alone remembers that the host
    left the name open: ``dataclasses.replace`` rebuilds a configuration from
    its stored values, and a name it forwards must be resolved again against
    the new ``cookie_secure`` instead of passing for the host's own choice.
    """

    __slots__ = ()


MAX_SESSION_LIFETIME_SECONDS: Final = 400 * 24 * 60 * 60
"""Browsers cap a cookie's lifetime at 400 days, so no session may be configured longer."""


@dataclass(frozen=True)
class SessionLifetime:
    """How long a session stands: idle between requests, and at most from creation."""

    idle_seconds: int
    absolute_max_age_seconds: int

    def __post_init__(self) -> None:
        require_positive_whole_number("idle_seconds", self.idle_seconds, unit="seconds")
        require_positive_whole_number(
            "absolute_max_age_seconds", self.absolute_max_age_seconds, unit="seconds",
        )
        if self.absolute_max_age_seconds > MAX_SESSION_LIFETIME_SECONDS:
            raise ValueError(
                "absolute_max_age_seconds must not exceed "
                f"{MAX_SESSION_LIFETIME_SECONDS} seconds (400 days)",
            )
        if self.idle_seconds > self.absolute_max_age_seconds:
            raise ValueError(
                "idle_seconds must not exceed absolute_max_age_seconds; "
                "a session cannot idle longer than it may live",
            )


@dataclass(frozen=True, kw_only=True)
class WebAuthConfig:
    """Every deployment fact the library reads, built by keyword and installed once.

    ``session_secret`` signs every session cookie and must be at least 32
    characters. ``cookie_samesite`` is ``"strict"`` (the default) or ``"lax"``;
    ``None`` is refused, because a cross-site cookie is not what this library
    issues. ``csrf_header_name`` (default ``"x-csrf-token"``) is the request
    header that carries the CSRF token. ``admin_role`` (``"admin"``) and
    ``user_role`` (``"user"``) are the role names the host stores; each must be
    non-blank and they must differ, or every new account would be an admin.
    ``wall_clock`` is the one reading of now behind every HTTP and WebSocket
    session decision, so a test fixes it. ``ipv6_budget_prefix`` (``64``, from
    ``32`` to ``128``) sizes the network whose IPv6 addresses share one
    rate-limit budget, so users behind one ``/64`` limit each other; IPv4
    keeps a budget per address.

    ``cookie_secure`` alone decides whether both cookies carry ``Secure``, when
    they are set and when they are cleared, and whether
    ``SecurityHeadersMiddleware`` sends HSTS. The request's scheme does not
    decide it, so a deployment behind a TLS proxy missing from
    ``trusted_proxies`` still gets both. A browser does not send a ``Secure``
    cookie back over plain http, so a host's own session login over plain http
    works only with ``cookie_secure=False``, which drops ``Secure`` and HSTS
    together. Any value that is not a ``bool`` is refused.

    ``session_cookie_name`` and ``csrf_cookie_name`` default to the ``__Host-``
    names, or to the plain names with ``cookie_secure=False``. A ``__Host-``
    cookie carries ``Secure`` and ``Path=/`` and no ``Domain``, so only this
    exact host can set it and a sibling subdomain cannot plant one with
    ``Domain=parent``. A name a host sets itself is refused at construction
    unless it is:

    - an RFC 6265 token: ASCII letters, digits and ``!#$%&'*+-.^_`|~``;
    - different from the other cookie's name;
    - not a ``__Host-`` or ``__Secure-`` name with ``cookie_secure=False``,
      which a browser drops and which would end in a silent login loop;
    - not a name webauth's own cookies use: the pending-login cookies, in
      both variants whatever ``cookie_secure`` is.

    A client that reads the CSRF cookie by name reads ``csrf_cookie_name``.

    ``allowed_hosts_exact`` lists hostnames, not origins. The CSRF origin check
    compares them with the hostname of ``Origin``. An entry without a port
    matches that hostname on every port; ``host:port`` matches only that port.
    The scheme is never compared. That is sound because cookies do not isolate ports,
    so a service on another port of that hostname, served over https, receives
    the session cookie anyway, and a plain-http page cannot read the ``Secure``
    ``__Host-`` CSRF cookie while schemeful ``SameSite`` (``strict`` or ``lax``)
    withholds the session cookie from its state-changing requests. A
    deployment must therefore never hand another party another port or scheme
    of an allowed hostname.
    """

    session_secret: SecretStr
    trusted_proxies: TrustedProxies
    rate_limits: RateLimitBackend
    allowed_hosts_exact: frozenset[str]
    session_lifetime: SessionLifetime
    session_cookie_name: str = _DefaultCookieName(DEFAULT_SESSION_COOKIE_NAME)
    csrf_cookie_name: str = _DefaultCookieName(DEFAULT_CSRF_COOKIE_NAME)
    csrf_header_name: str = _DEFAULT_CSRF_HEADER_NAME
    cookie_samesite: CookieSameSite = _DEFAULT_COOKIE_SAMESITE
    cookie_secure: bool = True
    ipv6_budget_prefix: int = _DEFAULT_IPV6_BUDGET_PREFIX
    admin_role: str = _DEFAULT_ADMIN_ROLE
    user_role: str = _DEFAULT_USER_ROLE
    wall_clock: WallClock = time.time

    def __post_init__(self) -> None:
        if len(self.session_secret.get_secret_value()) < _MIN_SESSION_SECRET_CHARS:
            raise ValueError(
                "The session secret is too short — it signs every session cookie and "
                f"must be at least {_MIN_SESSION_SECRET_CHARS} characters.",
            )
        if self.cookie_samesite not in get_args(CookieSameSite):
            raise ValueError(
                "cookie_samesite must be 'strict' or 'lax'; a cross-site cookie "
                "is not what this library issues",
            )
        if not isinstance(self.cookie_secure, bool):
            raise ValueError(
                "cookie_secure must be True or False; it alone decides whether the "
                "cookies carry Secure and responses carry HSTS",
            )
        if not self.allowed_hosts_exact:
            raise ValueError(
                "allowed_hosts_exact is empty, so no Origin would be admitted; "
                "list the hosts this application serves. "
                'To admit local development, use allowed_hosts_exact={"localhost", '
                '"127.0.0.1"}',
            )
        self._resolve_cookie_name("session_cookie_name", PLAIN_SESSION_COOKIE_NAME)
        self._resolve_cookie_name("csrf_cookie_name", PLAIN_CSRF_COOKIE_NAME)
        self._require_distinct_cookie_names()
        if (
            type(self.ipv6_budget_prefix) is not int
            or self.ipv6_budget_prefix not in _IPV6_BUDGET_PREFIX_RANGE
        ):
            raise ValueError(
                "ipv6_budget_prefix must be an integer between "
                f"{_IPV6_BUDGET_PREFIX_RANGE.start} "
                f"and {_IPV6_BUDGET_PREFIX_RANGE.stop - 1}; it is the network size "
                "whose addresses share one rate-limit budget",
            )
        self._require_distinct_roles()

    def _require_distinct_roles(self) -> None:
        for field in ("admin_role", "user_role"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field} must name a role")
        if self.admin_role == self.user_role:
            raise ValueError(
                "admin_role and user_role must differ; equal roles would make "
                "every new account an admin",
            )

    def _require_distinct_cookie_names(self) -> None:
        if self.session_cookie_name == self.csrf_cookie_name:
            raise ValueError(
                "session_cookie_name and csrf_cookie_name must differ; both cookies "
                "share one path, so equal names would make one overwrite the other",
            )

    def _resolve_cookie_name(self, field: str, plain_name: str) -> None:
        name = getattr(self, field)
        if isinstance(name, _DefaultCookieName):
            # The dataclass is frozen; resolving a default is part of construction.
            resolved = _default_cookie_name(plain_name, secure=self.cookie_secure)
            object.__setattr__(self, field, _DefaultCookieName(resolved))
        elif not isinstance(name, str):
            raise ValueError(
                f"{field} must be a cookie name; leave it out for the library's default",
            )
        elif not _is_valid_cookie_name(name):
            raise ValueError(
                f"{field} {name!r} is not a valid cookie name; it must be an RFC 6265 "
                "token (ASCII letters, digits and !#$%&'*+-.^_`|~)",
            )
        elif _is_reserved_cookie_name(name):
            raise ValueError(
                f"{field} {name!r} is a name webauth's own cookies use; choose "
                "another, or the browser would send two cookies of that name",
            )
        elif (
            _is_host_only_cookie_name(name) or _is_secure_prefixed_cookie_name(name)
        ) and not self.cookie_secure:
            raise ValueError(
                f"{field} {name!r} needs cookie_secure=True; browsers drop a __Host- "
                "or __Secure- cookie without Secure, so nobody could stay signed in",
            )

    @property
    def signing_key(self) -> bytes:
        """The secret in the form the cookie and CSRF signatures take."""
        return self.session_secret.get_secret_value().encode()


def install_web_auth_config(app: Starlette, config: WebAuthConfig) -> None:
    """Publish ``config`` on ``app`` so every request can reach it."""
    setattr(app.state, _WEB_AUTH_STATE_ATTRIBUTE, config)


def installed_web_auth_config(app: Starlette) -> WebAuthConfig:
    """The configuration ``app`` was started with.

    An application that serves a request without having installed one raises
    ``RuntimeError``.
    """
    config = getattr(app.state, _WEB_AUTH_STATE_ATTRIBUTE, None)
    if config is None:
        raise RuntimeError(
            "This application serves auth-protected requests without a "
            "WebAuthConfig: call install_web_auth_config() while it starts up.",
        )
    return config


def web_auth_config(connection: HTTPConnection) -> WebAuthConfig:
    """The configuration installed on the application serving ``connection``."""
    return installed_web_auth_config(connection.app)
