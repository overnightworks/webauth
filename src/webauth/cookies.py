"""The cookies webauth sets: the session, the CSRF token bound to it, a pending login,
and the ID token hint.

A pending login is the OpenID Connect login a browser began and has not yet
brought back. It travels in a cookie of its own, named after its state, so
two tabs can each have one; the value is versioned, bounded field by field and
signed under the session signing key with a prefix no other cookie uses.

The ID token hint is the issuer's ID token from the last login, kept in a
cookie of its own that only the logout path receives, so the issuer can end
that login's session without asking the person. It is not signed, and it is
never decoded, verified, logged or accepted as a credential: the issuer
judges it, and the reader checks only its shape and size.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal

from starlette.requests import cookie_parser

from webauth.ports import SessionReference

if TYPE_CHECKING:
    from starlette.requests import HTTPConnection
    from starlette.responses import Response

    from webauth.config import WebAuthConfig

__all__ = [
    "COOKIE_PATH",
    "DEFAULT_CSRF_COOKIE_NAME",
    "DEFAULT_SESSION_COOKIE_NAME",
    "MAX_ID_TOKEN_HINT_CHARS",
    "MAX_SESSION_COOKIE_CHARS",
    "PLAIN_CSRF_COOKIE_NAME",
    "PLAIN_SESSION_COOKIE_NAME",
    "CookieSameSite",
    "PendingLogin",
    "clear_session_cookies",
    "issue_session_cookies",
    "session_reference",
    "sign_session_id",
]

HOST_ONLY_COOKIE_PREFIX: Final = "__Host-"
SECURE_COOKIE_PREFIX: Final = "__Secure-"
PLAIN_SESSION_COOKIE_NAME: Final = "session_id"
PLAIN_CSRF_COOKIE_NAME: Final = "csrf_token"
PLAIN_PENDING_LOGIN_COOKIE_NAME: Final = "oidc_pending"
PLAIN_LOGOUT_HINT_COOKIE_NAME: Final = "oidc_id_token_hint"
DEFAULT_CSRF_HEADER_NAME: Final = "x-csrf-token"
MAX_PENDING_LOGIN_COOKIE_CHARS: Final = 256
# A signed session cookie is an identifier plus a hex digest; anything much
# longer was not issued here, so the reader rejects it before any HMAC is computed.
MAX_SESSION_COOKIE_CHARS: Final = 200
MAX_ID_TOKEN_HINT_CHARS: Final = 3072
"""Characters of ID token the hint cookie carries; a longer token is not kept."""
PENDING_SECRET_BYTES: Final = 32
"""Random bytes in each of a pending login's state, nonce and verifier,
which are minted with ``secrets.token_urlsafe``."""

_PENDING_LOGIN_VERSION: Final = "v1"
_PENDING_LOGIN_SIGNING_PREFIX: Final = b"oidc-pending:"
_SESSION_SIGNING_PREFIX: Final = b"session:"
_CSRF_SIGNING_PREFIX: Final = b"csrf:"
# The callback is a top-level navigation from the issuer's site, which a
# Strict cookie would not accompany.
_PENDING_LOGIN_SAMESITE: Final = "lax"
_LOGOUT_HINT_SAMESITE: Final = "strict"
_COMPACT_JWS: Final = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_STATE_DIGEST_HEX_CHARS: Final = 16
_STATE_DIGEST: Final = re.compile(rf"[0-9a-f]{{{_STATE_DIGEST_HEX_CHARS}}}")
_COOKIE_NAME_TOKEN: Final = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
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
COOKIE_PATH: Final = "/"


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


def is_reserved_cookie_name(name: str) -> bool:
    """Whether ``name`` is one webauth's own cookies use, in either variant.

    A session or CSRF cookie under such a name would meet the cookie webauth
    sets there, and the browser would send both.
    """
    return any(
        name == id_token_hint_cookie_name(secure=secure)
        or name.startswith(pending_login_cookie_prefix(secure=secure))
        for secure in (True, False)
    )


def is_valid_cookie_name(name: str) -> bool:
    """Whether ``name`` is an RFC 6265 ``cookie-name``; Starlette refuses most other names."""
    return _COOKIE_NAME_TOKEN.fullmatch(name) is not None


def is_host_only_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Host-`` cookie (case-insensitively)."""
    return name.lower().startswith(HOST_ONLY_COOKIE_PREFIX.lower())


def is_secure_prefixed_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Secure-`` cookie (case-insensitively)."""
    return name.lower().startswith(SECURE_COOKIE_PREFIX.lower())


def cookie_pairs(connection: HTTPConnection) -> list[tuple[str, str]]:
    """Every name and value the raw ``Cookie`` headers carry, in order.

    Starlette's cookie dict silently keeps one of several same-named
    cookies, so each pair is parsed on its own with Starlette's parser to keep
    its browser-compatible trimming and unquoting.
    """
    pairs = "; ".join(connection.headers.getlist("cookie")).split(";")
    return [item for pair in pairs for item in cookie_parser(pair).items()]


def cookie_values(connection: HTTPConnection, name: str) -> list[str]:
    """Every value the connection's cookies carry under ``name``, in order."""
    return [value for key, value in cookie_pairs(connection) if key == name]


def session_reference(session_id: str) -> SessionReference:
    """Return the public SHA-256 hex reference for a raw session identifier."""
    return SessionReference(hashlib.sha256(session_id.encode()).hexdigest())


def _session_signature(session_id: str, secret: bytes) -> str:
    return hmac.new(
        secret, _SESSION_SIGNING_PREFIX + session_id.encode(), hashlib.sha256
    ).hexdigest()


def sign_session_id(session_id: str, secret: bytes) -> str:
    """Return ``session_id.hmac_hex`` for use as a cookie value.

    Raises ``ValueError`` when the signed value would exceed
    ``MAX_SESSION_COOKIE_CHARS`` or when ``session_id`` is empty, since the
    reader would refuse that cookie.
    """
    if not session_id:
        raise ValueError("the session id must not be empty")
    signed = f"{session_id}.{_session_signature(session_id, secret)}"
    if len(signed) > MAX_SESSION_COOKIE_CHARS:
        raise ValueError("the session id does not fit the session cookie")
    return signed


def verify_session_cookie(cookie_value: str, secret: bytes) -> str | None:
    """Verify the HMAC signature and return the raw session_id, or None."""
    if "." not in cookie_value:
        return None
    session_id, sig = cookie_value.rsplit(".", 1)
    if not session_id or not sig:
        return None
    expected = _session_signature(session_id, secret)
    if hmac.compare_digest(sig.encode(), expected.encode()):
        return session_id
    return None


def generate_csrf_token(session_id: str, secret: bytes) -> str:
    """Generate a CSRF token cryptographically bound to the session."""
    return hmac.new(
        secret, _CSRF_SIGNING_PREFIX + session_id.encode(), hashlib.sha256
    ).hexdigest()


def verify_csrf_token(token: str, session_id: str, secret: bytes) -> bool:
    """Verify a CSRF token is valid for the given session."""
    expected = generate_csrf_token(session_id, secret)
    return hmac.compare_digest(token.encode(), expected.encode())


def issue_session_cookies(
    response: Response, session_id: str, config: WebAuthConfig,
) -> None:
    """Hand the browser its signed session and the CSRF token bound to it.

    Only the session cookie is kept from scripts: the CSRF token has to be
    readable, because the double-submit check compares it against a header the
    client sends back itself. Both carry ``Secure`` unless the host switched
    ``cookie_secure`` off: a request's scheme is not trusted to decide it,
    because behind an unlisted TLS proxy every request looks like plain http.
    """
    secure = config.cookie_secure
    max_age = config.cookie_max_age_seconds
    samesite = config.cookie_samesite
    response.set_cookie(
        config.session_cookie_name,
        sign_session_id(session_id, config.signing_key),
        max_age=max_age,
        httponly=True,
        samesite=samesite,
        secure=secure,
        path=COOKIE_PATH,
    )
    response.set_cookie(  # NOSONAR The client must read this CSRF token for double-submit.
        config.csrf_cookie_name,
        generate_csrf_token(session_id, config.signing_key),
        max_age=max_age,
        httponly=False,
        samesite=samesite,
        secure=secure,
        path=COOKIE_PATH,
    )


def clear_session_cookies(response: Response, config: WebAuthConfig) -> None:
    """Take both cookies back, so the browser stops carrying a dead session.

    Each deletion repeats the attributes its cookie was set with, so a browser
    that only lets a secure context overwrite a ``Secure`` cookie accepts it.
    """
    samesite = config.cookie_samesite
    secure = config.cookie_secure
    response.delete_cookie(
        config.session_cookie_name,
        path=COOKIE_PATH,
        samesite=samesite,
        secure=secure,
        httponly=True,
    )
    response.delete_cookie(
        config.csrf_cookie_name, path=COOKIE_PATH, samesite=samesite, secure=secure,
    )


def id_token_hint_cookie_name(*, secure: bool) -> str:
    """``__Host-`` would demand ``Path=/``, so the hint takes ``__Secure-``."""
    plain_name = PLAIN_LOGOUT_HINT_COOKIE_NAME
    return f"{SECURE_COOKIE_PREFIX}{plain_name}" if secure else plain_name


def issue_id_token_hint_cookie(
    response: Response, id_token: str, *, logout_path: str, config: WebAuthConfig,
) -> None:
    """Hand the browser the ID token, for the logout path alone.

    A token longer than ``MAX_ID_TOKEN_HINT_CHARS`` is not kept, and the hint
    of an earlier login is cleared instead, so a logout never carries it.
    """
    if len(id_token) > MAX_ID_TOKEN_HINT_CHARS:
        clear_id_token_hint_cookie(response, logout_path=logout_path, config=config)
        return
    response.set_cookie(
        id_token_hint_cookie_name(secure=config.cookie_secure),
        id_token,
        max_age=config.cookie_max_age_seconds,
        httponly=True,
        samesite=_LOGOUT_HINT_SAMESITE,
        secure=config.cookie_secure,
        path=logout_path,
    )


def clear_id_token_hint_cookie(
    response: Response, *, logout_path: str, config: WebAuthConfig,
) -> None:
    """Take the hint back, repeating the attributes it was set with."""
    response.delete_cookie(
        id_token_hint_cookie_name(secure=config.cookie_secure),
        path=logout_path,
        secure=config.cookie_secure,
        httponly=True,
        samesite=_LOGOUT_HINT_SAMESITE,
    )


def id_token_hint_from_request(connection: HTTPConnection, config: WebAuthConfig) -> str | None:
    """The hint the request carries: its sole cookie of that name, when it has the
    shape of a compact JWS within ``MAX_ID_TOKEN_HINT_CHARS``; otherwise ``None``."""
    values = cookie_values(connection, id_token_hint_cookie_name(secure=config.cookie_secure))
    if len(values) != 1:
        return None
    hint = values[0]
    if len(hint) > MAX_ID_TOKEN_HINT_CHARS or _COMPACT_JWS.fullmatch(hint) is None:
        return None
    return hint


@dataclass(frozen=True)
class PendingLogin:
    """What the browser carries between being sent to the issuer and its return:
    the login's secrets and the wall-clock second it began."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    issued_at: int


def issue_pending_login_cookie(
    response: Response, pending: PendingLogin, *, max_age_seconds: int, config: WebAuthConfig,
) -> None:
    """Hand the browser the signed pending login, in a cookie named for its state."""
    response.set_cookie(
        pending_login_cookie_name(pending.state, secure=config.cookie_secure),
        sign_pending_login(pending, config.signing_key),
        max_age=max_age_seconds,
        httponly=True,
        samesite=_PENDING_LOGIN_SAMESITE,
        secure=config.cookie_secure,
        path=COOKIE_PATH,
    )


def clear_pending_login_cookie(response: Response, name: str, config: WebAuthConfig) -> None:
    """Take a pending-login cookie back, repeating the attributes it was set with."""
    response.delete_cookie(
        name,
        path=COOKIE_PATH,
        secure=config.cookie_secure,
        httponly=True,
        samesite=_PENDING_LOGIN_SAMESITE,
    )


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
