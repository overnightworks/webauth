"""The signed session cookie and the CSRF token bound to it."""

from __future__ import annotations

import hashlib
import hmac
from typing import Final, Literal

HOST_ONLY_COOKIE_PREFIX: Final = "__Host-"
PLAIN_SESSION_COOKIE_NAME: Final = "session_id"
PLAIN_CSRF_COOKIE_NAME: Final = "csrf_token"
DEFAULT_CSRF_HEADER_NAME: Final = "x-csrf-token"

CookieSameSite = Literal["strict", "lax"]
DEFAULT_COOKIE_SAMESITE: Final[CookieSameSite] = "strict"


def default_cookie_name(plain_name: str, *, secure: bool) -> str:
    """Return the name a cookie gets when the host names none.

    A ``__Host-`` cookie can be set only by this exact host, so a sibling
    subdomain cannot toss one in with ``Domain=parent``. Browsers accept the
    prefix only on a ``Secure`` cookie, so without ``Secure`` the plain name
    is the one that still works.
    """
    return f"{HOST_ONLY_COOKIE_PREFIX}{plain_name}" if secure else plain_name


DEFAULT_SESSION_COOKIE_NAME: Final = default_cookie_name(PLAIN_SESSION_COOKIE_NAME, secure=True)
DEFAULT_CSRF_COOKIE_NAME: Final = default_cookie_name(PLAIN_CSRF_COOKIE_NAME, secure=True)


def is_host_only_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Host-`` cookie (case-insensitively)."""
    return name.lower().startswith(HOST_ONLY_COOKIE_PREFIX.lower())


def session_reference(session_id: str) -> str:
    """Return the public SHA-256 hex reference for a raw session identifier."""
    return hashlib.sha256(session_id.encode()).hexdigest()


def sign_session_id(session_id: str, secret: bytes) -> str:
    """Return ``session_id.hmac_hex`` for use as a cookie value."""
    sig = hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest()
    return f"{session_id}.{sig}"


def verify_session_cookie(cookie_value: str, secret: bytes) -> str | None:
    """Verify the HMAC signature and return the raw session_id, or None."""
    if "." not in cookie_value:
        return None
    session_id, sig = cookie_value.rsplit(".", 1)
    if not session_id or not sig:
        return None
    expected = hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return session_id
    return None


def generate_csrf_token(session_id: str, secret: bytes) -> str:
    """Generate a CSRF token cryptographically bound to the session."""
    return hmac.new(secret, f"csrf:{session_id}".encode(), hashlib.sha256).hexdigest()


def verify_csrf_token(token: str, session_id: str, secret: bytes) -> bool:
    """Verify a CSRF token is valid for the given session."""
    expected = generate_csrf_token(session_id, secret)
    return hmac.compare_digest(token, expected)
