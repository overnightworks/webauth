"""The deployment facts the auth machinery reads, supplied by the host application.

The library decides nothing about its own deployment: the application builds
one `WebAuthConfig` at startup and installs it on the ASGI application, and
every reader below takes it from the request. Nothing here reaches for an
environment variable, a settings singleton, or the application's own context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, get_args

from starlette.requests import Request

from webauth.cookies import (
    DEFAULT_COOKIE_SAMESITE,
    DEFAULT_CSRF_HEADER_NAME,
    PLAIN_CSRF_COOKIE_NAME,
    PLAIN_SESSION_COOKIE_NAME,
    CookieSameSite,
    default_cookie_name,
    is_host_only_cookie_name,
)
from webauth.liveness import ExpiryColumnLiveness

if TYPE_CHECKING:
    import re

    from pydantic import SecretStr
    from starlette.applications import Starlette

    from webauth.ports import (
        PasswordHasher,
        RateLimitBackend,
        SessionCache,
        SessionLivenessPolicy,
    )
    from webauth.proxies import TrustedProxies

MIN_SESSION_SECRET_CHARS: Final = 32
DEFAULT_LOGIN_RATE_WINDOW_SECONDS: Final = 300
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


@dataclass(frozen=True)
class WebAuthConfig:
    session_secret: SecretStr
    trusted_proxies: TrustedProxies
    password_hasher: PasswordHasher
    rate_limits: RateLimitBackend
    allowed_hosts_exact: frozenset[str]
    allowed_hosts_patterns: tuple[re.Pattern[str], ...]
    session_max_age_seconds: int
    session_liveness: SessionLivenessPolicy
    login_rate_limit: int
    login_lockout_threshold: int
    login_lockout_window_seconds: int
    login_rate_window_seconds: int = DEFAULT_LOGIN_RATE_WINDOW_SECONDS
    session_cookie_name: str | None = None
    csrf_cookie_name: str | None = None
    csrf_header_name: str = DEFAULT_CSRF_HEADER_NAME
    cookie_samesite: CookieSameSite = DEFAULT_COOKIE_SAMESITE
    cookie_secure: bool = True
    max_user_agent_chars: int = DEFAULT_MAX_USER_AGENT_CHARS
    ipv6_budget_prefix: int = DEFAULT_IPV6_BUDGET_PREFIX
    admin_role: str = DEFAULT_ADMIN_ROLE
    user_role: str = DEFAULT_USER_ROLE
    session_cache: SessionCache | None = None

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
        if self.session_cache is not None and not isinstance(
            self.session_liveness, ExpiryColumnLiveness,
        ):
            raise ValueError(
                "a session cache requires expiry-column liveness; the idle-window "
                "model reads sessions straight from the store",
            )

    def _resolve_cookie_name(self, field: str, plain_name: str) -> None:
        name = getattr(self, field)
        if name is None or isinstance(name, _DefaultCookieName):
            # The dataclass is frozen; resolving a default is part of construction.
            resolved = default_cookie_name(plain_name, secure=self.cookie_secure)
            object.__setattr__(self, field, _DefaultCookieName(resolved))
        elif is_host_only_cookie_name(name) and not self.cookie_secure:
            raise ValueError(
                f"{field} {name!r} needs cookie_secure=True; browsers drop a __Host- "
                "cookie without Secure, so nobody could stay signed in",
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


def web_auth_config(request: Request) -> WebAuthConfig:
    """The configuration installed on the application serving ``request``."""
    return installed_web_auth_config(request.app)
