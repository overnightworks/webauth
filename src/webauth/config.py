"""The deployment facts the auth machinery reads, supplied by the host application.

The library decides nothing about its own deployment: the application builds
one `WebAuthConfig` at startup and installs it on the ASGI application, and
every reader below takes it from the request. Nothing here reaches for an
environment variable, a settings singleton, or the application's own context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, get_args

from starlette.requests import HTTPConnection

from webauth.cookies import (
    DEFAULT_COOKIE_SAMESITE,
    DEFAULT_CSRF_COOKIE_NAME,
    DEFAULT_CSRF_HEADER_NAME,
    DEFAULT_SESSION_COOKIE_NAME,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
    CookieSameSite,
    default_cookie_name,
    is_host_only_cookie_name,
    is_reserved_cookie_name,
    is_secure_prefixed_cookie_name,
    is_valid_cookie_name,
)
from webauth.validation import require_positive_whole_number

if TYPE_CHECKING:
    import re

    from pydantic import SecretStr
    from starlette.applications import Starlette

    from webauth.ports import (
        RateLimitBackend,
        SessionLivenessPolicy,
    )
    from webauth.proxies import TrustedProxies

__all__ = [
    "WebAuthConfig",
    "install_web_auth_config",
    "installed_web_auth_config",
    "web_auth_config",
]

MIN_SESSION_SECRET_CHARS: Final = 32
DEFAULT_MAX_USER_AGENT_CHARS: Final = 500
DEFAULT_IPV6_BUDGET_PREFIX: Final = 64
# Shorter than /32 would pool whole providers into one budget; longer than /128
# is not an IPv6 prefix at all.
IPV6_BUDGET_PREFIX_RANGE: Final = range(32, 129)
DEFAULT_ADMIN_ROLE: Final = "admin"
DEFAULT_USER_ROLE: Final = "user"

WEB_AUTH_STATE_ATTRIBUTE: Final = "webauth"


class _DefaultCookieName(str):
    """A cookie name the library chose because the host named none.

    Every reader sees a plain ``str``. The type alone remembers that the host
    left the name open: ``dataclasses.replace`` rebuilds a configuration from
    its stored values, and a name it forwards must be resolved again against
    the new ``cookie_secure`` instead of passing for the host's own choice.
    """

    __slots__ = ()


@dataclass(frozen=True, kw_only=True)
class WebAuthConfig:
    session_secret: SecretStr
    trusted_proxies: TrustedProxies
    rate_limits: RateLimitBackend
    allowed_hosts_exact: frozenset[str]
    allowed_hosts_patterns: tuple[re.Pattern[str], ...]
    cookie_max_age_seconds: int
    session_liveness: SessionLivenessPolicy
    session_cookie_name: str = _DefaultCookieName(DEFAULT_SESSION_COOKIE_NAME)
    csrf_cookie_name: str = _DefaultCookieName(DEFAULT_CSRF_COOKIE_NAME)
    csrf_header_name: str = DEFAULT_CSRF_HEADER_NAME
    cookie_samesite: CookieSameSite = DEFAULT_COOKIE_SAMESITE
    cookie_secure: bool = True
    max_user_agent_chars: int = DEFAULT_MAX_USER_AGENT_CHARS
    ipv6_budget_prefix: int = DEFAULT_IPV6_BUDGET_PREFIX
    admin_role: str = DEFAULT_ADMIN_ROLE
    user_role: str = DEFAULT_USER_ROLE

    def __post_init__(self) -> None:
        if len(self.session_secret.get_secret_value()) < MIN_SESSION_SECRET_CHARS:
            raise ValueError(
                "The session secret is too short — it signs every session cookie and "
                f"must be at least {MIN_SESSION_SECRET_CHARS} characters.",
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
        self._resolve_cookie_name("session_cookie_name", PLAIN_SESSION_COOKIE_NAME)
        self._resolve_cookie_name("csrf_cookie_name", PLAIN_CSRF_COOKIE_NAME)
        self._require_distinct_cookie_names()
        require_positive_whole_number(
            "cookie_max_age_seconds", self.cookie_max_age_seconds, unit="seconds",
        )
        if (
            type(self.ipv6_budget_prefix) is not int
            or self.ipv6_budget_prefix not in IPV6_BUDGET_PREFIX_RANGE
        ):
            raise ValueError(
                "ipv6_budget_prefix must be an integer between "
                f"{IPV6_BUDGET_PREFIX_RANGE.start} "
                f"and {IPV6_BUDGET_PREFIX_RANGE.stop - 1}; it is the network size "
                "whose addresses share one rate-limit budget",
            )
        self._require_distinct_roles()
        require_positive_whole_number(
            "max_user_agent_chars", self.max_user_agent_chars, unit="characters",
        )

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
            resolved = default_cookie_name(plain_name, secure=self.cookie_secure)
            object.__setattr__(self, field, _DefaultCookieName(resolved))
        elif not isinstance(name, str):
            raise ValueError(
                f"{field} must be a cookie name; leave it out for the library's default",
            )
        elif not is_valid_cookie_name(name):
            raise ValueError(
                f"{field} {name!r} is not a valid cookie name; it must be an RFC 6265 "
                "token (ASCII letters, digits and !#$%&'*+-.^_`|~)",
            )
        elif is_reserved_cookie_name(name):
            raise ValueError(
                f"{field} {name!r} is a name webauth's own cookies use; choose "
                "another, or the browser would send two cookies of that name",
            )
        elif (
            is_host_only_cookie_name(name) or is_secure_prefixed_cookie_name(name)
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
    setattr(app.state, WEB_AUTH_STATE_ATTRIBUTE, config)


def installed_web_auth_config(app: Starlette) -> WebAuthConfig:
    """The configuration ``app`` was started with."""
    config = getattr(app.state, WEB_AUTH_STATE_ATTRIBUTE, None)
    if config is None:
        raise RuntimeError(
            "This application serves auth-protected requests without a "
            "WebAuthConfig: call install_web_auth_config() while it starts up.",
        )
    return config


def web_auth_config(connection: HTTPConnection) -> WebAuthConfig:
    """The configuration installed on the application serving ``connection``."""
    return installed_web_auth_config(connection.app)
