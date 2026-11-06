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

from webauth._validation import (
    require_collection_not_one_string,
    require_positive_whole_number,
)
from webauth.cookies import (
    _DEFAULT_COOKIE_SAMESITE,
    PLAIN_SESSION_COOKIE_NAME,
    CookieSameSite,
    _default_cookie_name,
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

_WEB_AUTH_STATE_ATTRIBUTE: Final = "webauth"


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
            "absolute_max_age_seconds",
            self.absolute_max_age_seconds,
            unit="seconds",
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
    issues. With ``"strict"``, the page the login's callback redirects to
    carries the session cookie only when the app and the issuer share a site
    (a registrable domain); across sites that first page renders signed out.
    ``wall_clock`` is the one reading of now behind every HTTP and WebSocket
    session decision, so a test fixes it.

    ``cookie_secure`` alone decides whether the session cookie carries
    ``Secure``, when it is set and when it is cleared, and whether
    ``SecurityHeadersMiddleware`` sends HSTS. The request's scheme does not
    decide it, so a deployment behind a TLS proxy missing from
    ``trusted_proxies`` still gets both. A browser does not send a ``Secure``
    cookie back over plain http, so a host's own session login over plain http
    works only with ``cookie_secure=False``, which drops ``Secure`` and HSTS
    together. Any value that is not a ``bool`` is refused.

    ``session_cookie_name`` follows ``cookie_secure``: ``__Host-session_id``, or
    ``session_id`` without it. A ``__Host-`` cookie carries ``Secure`` and
    ``Path=/`` and no ``Domain``, so only this exact host can set it and a
    sibling subdomain cannot plant one with ``Domain=parent``.

    ``allowed_hosts_exact`` lists hostnames, not origins. The CSRF origin check
    compares them with the hostname of ``Origin``. An entry without a port
    matches that hostname on every port; ``host:port`` matches only that port.
    A browser never writes the default port in ``Origin``, so an entry such as
    ``notes.test:443`` matches no browser's https origin; list ``notes.test``.
    With ``cookie_secure`` on, an ``Origin`` is admitted only over https: an
    ``http://`` origin is refused, in the CSRF origin check and in the WebSocket
    handshake alike. With it off, a plain-http deployment such as local
    development, the scheme is not compared. ``Sec-Fetch-Site: same-origin``
    still passes the CSRF origin check before the list is asked. Cookies do not
    isolate ports, so a service on another port of an allowed hostname, served
    over https, receives the session cookie anyway. A deployment must therefore
    never hand another party another port of an allowed hostname.
    """

    session_secret: SecretStr
    trusted_proxies: TrustedProxies
    rate_limits: RateLimitBackend
    allowed_hosts_exact: frozenset[str]
    session_lifetime: SessionLifetime
    cookie_samesite: CookieSameSite = _DEFAULT_COOKIE_SAMESITE
    cookie_secure: bool = True
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
        require_collection_not_one_string(
            "allowed_hosts_exact",
            self.allowed_hosts_exact,
            noun="host",
            example='{"notes.example"}',
        )
        if not self.allowed_hosts_exact:
            raise ValueError(
                "allowed_hosts_exact is empty, so no Origin would be admitted; "
                "list the hosts this application serves. "
                'To admit local development, use allowed_hosts_exact={"localhost", '
                '"127.0.0.1"}',
            )

    @property
    def session_cookie_name(self) -> str:
        """The session cookie's name, which follows ``cookie_secure``."""
        return _default_cookie_name(PLAIN_SESSION_COOKIE_NAME, secure=self.cookie_secure)

    @property
    def signing_key(self) -> bytes:
        """The secret in the form the cookie signatures take."""
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
