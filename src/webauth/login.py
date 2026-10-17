"""Signing in, minus everything that touches a transaction.

The application keeps the login route itself: its advisory lock, the failed
attempt it commits before refusing, and when the request's work becomes
durable. What is left over lives here — the failure budget an address has
spent, and whether a password admits an account at all. None of it reads or
writes a store of its own, so none of it can leave half a login behind.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from fastapi import HTTPException

if TYPE_CHECKING:
    from webauth.config import WebAuthConfig
    from webauth.ports import LoginAttemptStore, PasswordHasher, UserRecord

ACCOUNT_LOCKED_DETAIL: Final = (
    "Account temporarily locked due to repeated failed attempts. Try again later."
)
TOO_MANY_LOGIN_ATTEMPTS_DETAIL: Final = "Too many login attempts. Try again later."
INVALID_CREDENTIALS_DETAIL: Final = "Invalid username or password"
RETRY_AFTER_HEADER: Final = "Retry-After"


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
    every path. An account without a password signs in only through its
    identity provider, so no password admits it, whatever the hasher answers.
    """
    stored_hash = user.password_hash if user else None
    password_matches = hasher.verify(password, stored_hash)
    if user is None:
        return LoginOutcome.UNKNOWN_USER
    if stored_hash is None or not password_matches:
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
