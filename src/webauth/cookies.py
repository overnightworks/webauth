"""The cookies webauth signs: the session, the CSRF token bound to it, and a pending login.

A pending login is the OpenID Connect login a browser began and has not yet
brought back. It travels in a cookie of its own, named after its state, so
two tabs can each have one; the value is versioned, bounded field by field and
signed under the session signing key with a prefix no other cookie uses.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal

from starlette.requests import cookie_parser

if TYPE_CHECKING:
    from starlette.requests import Request

HOST_ONLY_COOKIE_PREFIX: Final = "__Host-"
PLAIN_SESSION_COOKIE_NAME: Final = "session_id"
PLAIN_CSRF_COOKIE_NAME: Final = "csrf_token"
PLAIN_PENDING_LOGIN_COOKIE_NAME: Final = "oidc_pending"
DEFAULT_CSRF_HEADER_NAME: Final = "x-csrf-token"
MAX_PENDING_LOGIN_COOKIE_CHARS: Final = 256
PENDING_SECRET_BYTES: Final = 32
"""Random bytes in each of a pending login's state, nonce and verifier,
which are minted with ``secrets.token_urlsafe``."""

_PENDING_LOGIN_VERSION: Final = "v1"
_PENDING_LOGIN_SIGNING_PREFIX: Final = b"oidc-pending:"
_STATE_DIGEST_HEX_CHARS: Final = 16
_STATE_DIGEST: Final = re.compile(rf"[0-9a-f]{{{_STATE_DIGEST_HEX_CHARS}}}")
# Unpadded base64url spells n random bytes in exactly ceil(4n / 3)
# characters, so a field of any other shape was not minted as a pending secret.
_PENDING_SECRET: Final = rf"[A-Za-z0-9_-]{{{math.ceil(4 * PENDING_SECRET_BYTES / 3)}}}"
_PENDING_LOGIN_VALUE: Final = re.compile(
    rf"{_PENDING_LOGIN_VERSION}"
    rf"\.(?P<state>{_PENDING_SECRET})"
    rf"\.(?P<nonce>{_PENDING_SECRET})"
    rf"\.(?P<code_verifier>{_PENDING_SECRET})"
    r"\.(?P<issued_at>0|[1-9][0-9]{0,11})"
)
_PENDING_LOGIN_SIGNATURE: Final = re.compile(r"[0-9a-f]{64}")

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


def pending_login_cookie_prefix(*, secure: bool) -> str:
    """The part every pending-login cookie's name starts with."""
    return f"{default_cookie_name(PLAIN_PENDING_LOGIN_COOKIE_NAME, secure=secure)}_"


def pending_login_cookie_name(state: str, *, secure: bool) -> str:
    """The name of the cookie that carries the pending login of ``state``."""
    state_digest = hashlib.sha256(state.encode()).hexdigest()[:_STATE_DIGEST_HEX_CHARS]
    return f"{pending_login_cookie_prefix(secure=secure)}{state_digest}"


def is_pending_login_cookie_name(name: str, *, secure: bool) -> bool:
    """Whether ``name`` has the shape ``pending_login_cookie_name`` gives every
    pending-login cookie, so webauth may clear it; a name of any other shape
    was not set by webauth, and may not even be a legal cookie name."""
    prefix = pending_login_cookie_prefix(secure=secure)
    if not name.startswith(prefix):
        return False
    return _STATE_DIGEST.fullmatch(name.removeprefix(prefix)) is not None


def is_host_only_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Host-`` cookie (case-insensitively)."""
    return name.lower().startswith(HOST_ONLY_COOKIE_PREFIX.lower())


def cookie_pairs(request: Request) -> list[tuple[str, str]]:
    """Every name and value the raw ``Cookie`` headers carry, in order.

    Starlette's cookie dict silently keeps one of several same-named
    cookies, so each pair is parsed on its own with Starlette's parser to keep
    its browser-compatible trimming and unquoting.
    """
    pairs = "; ".join(request.headers.getlist("cookie")).split(";")
    return [item for pair in pairs for item in cookie_parser(pair).items()]


def cookie_values(request: Request, name: str) -> list[str]:
    """Every value the request's cookies carry under ``name``, in order."""
    return [value for key, value in cookie_pairs(request) if key == name]


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


@dataclass(frozen=True)
class PendingLogin:
    """What the browser carries between being sent to the issuer and its return:
    the login's secrets and the wall-clock second it began."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    issued_at: int


def sign_pending_login(pending: PendingLogin, secret: bytes) -> str:
    """Return the signed cookie value that carries ``pending``.

    Raises ``ValueError`` for a pending login ``webauth.oidc`` cannot have
    begun, since its cookie would never verify.
    """
    payload = ".".join((
        _PENDING_LOGIN_VERSION,
        pending.state,
        pending.nonce,
        pending.code_verifier,
        str(pending.issued_at),
    ))
    if not _PENDING_LOGIN_VALUE.fullmatch(payload):
        raise ValueError("the pending login does not fit the pending-login cookie")
    return f"{payload}.{_pending_login_signature(payload, secret)}"


def verify_pending_login(cookie_value: str, secret: bytes) -> PendingLogin | None:
    """The pending login a cookie value carries, or ``None`` when it is
    oversized, of another shape or version, or not signed under ``secret``."""
    if len(cookie_value) > MAX_PENDING_LOGIN_COOKIE_CHARS:
        return None
    payload, _, signature = cookie_value.rpartition(".")
    fields = _PENDING_LOGIN_VALUE.fullmatch(payload)
    if fields is None or not _PENDING_LOGIN_SIGNATURE.fullmatch(signature):
        return None
    if not hmac.compare_digest(signature, _pending_login_signature(payload, secret)):
        return None
    return PendingLogin(
        state=fields["state"],
        nonce=fields["nonce"],
        code_verifier=fields["code_verifier"],
        issued_at=int(fields["issued_at"]),
    )


def _pending_login_signature(payload: str, secret: bytes) -> str:
    return hmac.new(
        secret, _PENDING_LOGIN_SIGNING_PREFIX + payload.encode(), hashlib.sha256
    ).hexdigest()
