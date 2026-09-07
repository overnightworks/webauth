"""Signing in and out, minus everything that touches a transaction.

The application keeps the login route itself: its advisory lock, the failed
attempt it commits before refusing, and when the request's work becomes
durable. What is left over lives here — the cookies a signed-in browser
carries, the failure budget an address has spent, and whether a password
admits an account at all. None of it reads or writes a store of its own, so
none of it can leave half a login behind.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from fastapi import HTTPException

from webauth.cookies import generate_csrf_token, sign_session_id
from webauth.proxies import request_is_https

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig
    from webauth.ports import LoginAttemptStore, PasswordHasher, UserRecord

ACCOUNT_LOCKED_DETAIL: Final = (
    "Account temporarily locked due to repeated failed attempts. Try again later."
)
TOO_MANY_LOGIN_ATTEMPTS_DETAIL: Final = "Too many login attempts. Try again later."
INVALID_CREDENTIALS_DETAIL: Final = "Invalid username or password"
RETRY_AFTER_HEADER: Final = "Retry-After"

COOKIE_PATH: Final = "/"
COOKIE_SAME_SITE: Final = "strict"


class LoginOutcome(enum.Enum):
    """Every way a login attempt can end, before any transport decides its shape."""

    ADMITTED = enum.auto()
    UNKNOWN_USER = enum.auto()
    WRONG_PASSWORD = enum.auto()
    DEACTIVATED = enum.auto()
    ACCOUNT_LOCKED = enum.auto()
    RATE_LIMITED = enum.auto()


@dataclass(frozen=True)
class LoginRefusal:
    """A login that will not proceed, and how long the refusal stands.

    ``retry_after_seconds`` is ``None`` for a refusal a caller cannot wait out —
    a wrong password reopens the moment the right one is offered, not on a clock.
    """

    outcome: LoginOutcome
    retry_after_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.outcome is LoginOutcome.ADMITTED:
            raise ValueError("ADMITTED is an admission, not a refusal")


def issue_session_cookies(
    response: Response,
    request: Request,
    session_id: str,
    config: WebAuthConfig,
) -> None:
    """Hand the browser its signed session and the CSRF token bound to it.

    Only the session cookie is kept from scripts: the CSRF token has to be
    readable, because the double-submit check compares it against a header the
    client sends back itself.
    """
    secure = request_is_https(request)
    max_age = config.session_max_age_seconds
    response.set_cookie(
        config.session_cookie_name,
        sign_session_id(session_id, config.signing_key),
        max_age=max_age,
        httponly=True,
        samesite=COOKIE_SAME_SITE,
        secure=secure,
        path=COOKIE_PATH,
    )
    response.set_cookie(  # NOSONAR The client must read this CSRF token for double-submit.
        config.csrf_cookie_name,
        generate_csrf_token(session_id, config.signing_key),
        max_age=max_age,
        httponly=False,
        samesite=COOKIE_SAME_SITE,
        secure=secure,
        path=COOKIE_PATH,
    )


def clear_session_cookies(response: Response, config: WebAuthConfig) -> None:
    """Take both cookies back, so the browser stops carrying a dead session."""
    response.delete_cookie(config.session_cookie_name, path=COOKIE_PATH)
    response.delete_cookie(config.csrf_cookie_name, path=COOKIE_PATH)


def login_attempt_budget(
    attempts: LoginAttemptStore,
    *,
    ip_address: str,
    username: str,
    config: WebAuthConfig,
) -> LoginRefusal | None:
    """The refusal an attempt has earned from either failure budget, else ``None``.

    The lockout counts this account's failures over a long window wherever
    they came from; the rate limit counts the address on its own and the
    account over a short one, and each refusal names how long it stands.
    """
    lockout_failures = attempts.count_recent_failures(
        ip_address=ip_address,
        window_seconds=config.login_lockout_window_seconds,
        username=username,
    )
    if lockout_failures >= config.login_lockout_threshold:
        return LoginRefusal(
            LoginOutcome.ACCOUNT_LOCKED,
            retry_after_seconds=config.login_lockout_window_seconds,
        )

    window = config.login_rate_window_seconds
    address_failures = attempts.count_recent_failures(
        ip_address=ip_address, window_seconds=window,
    )
    account_failures = attempts.count_recent_failures(
        ip_address=ip_address, window_seconds=window, username=username,
    )
    if (
        address_failures >= config.login_rate_limit
        or account_failures >= config.login_rate_limit
    ):
        return LoginRefusal(LoginOutcome.RATE_LIMITED, retry_after_seconds=window)

    return None


def judge_credentials(
    password: str, user: UserRecord | None, *, hasher: PasswordHasher,
) -> LoginOutcome:
    """Which outcome ``password`` earns against ``user``, at one hash cost.

    A username nobody holds is verified against a dummy hash and a deactivated
    account is judged only after that verification, so neither answers faster
    than a plain wrong password does: exactly one full verification runs on
    every path.
    """
    password_matches = hasher.verify(
        password, user.password_hash if user else None,
    )
    if user is None:
        return LoginOutcome.UNKNOWN_USER
    if not password_matches:
        return LoginOutcome.WRONG_PASSWORD
    if not user.is_active:
        return LoginOutcome.DEACTIVATED
    return LoginOutcome.ADMITTED


_REFUSAL_RESPONSES: Final[dict[LoginOutcome, tuple[int, str]]] = {
    LoginOutcome.ACCOUNT_LOCKED: (429, ACCOUNT_LOCKED_DETAIL),
    LoginOutcome.RATE_LIMITED: (429, TOO_MANY_LOGIN_ATTEMPTS_DETAIL),
    LoginOutcome.UNKNOWN_USER: (401, INVALID_CREDENTIALS_DETAIL),
    LoginOutcome.WRONG_PASSWORD: (401, INVALID_CREDENTIALS_DETAIL),
    LoginOutcome.DEACTIVATED: (401, INVALID_CREDENTIALS_DETAIL),
}


def http_refusal(refusal: LoginRefusal) -> HTTPException:
    """The FastAPI error a host raises for ``refusal`` by default.

    An unknown username and a wrong password share one 401, so the response
    never reveals which of the two occurred; a spent budget adds the
    ``Retry-After`` the refusal carries.
    """
    status_code, detail = _REFUSAL_RESPONSES[refusal.outcome]
    headers = (
        {RETRY_AFTER_HEADER: str(refusal.retry_after_seconds)}
        if refusal.retry_after_seconds is not None
        else None
    )
    return HTTPException(status_code, detail, headers=headers)
