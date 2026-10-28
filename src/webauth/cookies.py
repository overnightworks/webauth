"""The cookies webauth sets: the session and a pending login.

A pending login is the OpenID Connect login a browser began and has not yet
brought back. It travels in a cookie of its own, named after its state, so
two tabs can each have one; the value is versioned, bounded field by field and
signed with HMAC-SHA256 under the session signing key with a prefix no other
cookie uses, the signature compared in constant time, and at most 896
characters. Its name is ``__Host-oidc_pending_`` followed by the
first 16 hex characters of the SHA-256 of the login's state; with
``cookie_secure=False`` it is the plain ``oidc_pending_`` form and the cookie is
not ``Secure``, which is for plain http on a loopback host, where a sibling
host or a network observer can set or read it. It is ``HttpOnly``, ``Path=/``,
``Max-Age=600`` and always ``SameSite=Lax``, whatever ``cookie_samesite`` says,
because the callback is a top-level navigation from the issuer's site, which a
``Strict`` cookie would not accompany. A browser holds at most five: a start
beyond them clears the oldest by ``issued_at``, a cookie that does not verify
or whose name appears twice counting as oldest, so repeated starts never crowd
out the session cookie. Only names of exactly that shape count; any
other cookie whose name merely starts with the prefix is neither counted nor
cleared.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, Literal, TypedDict

from starlette.requests import cookie_parser

from webauth._paths import MAX_RETURN_PATH_BYTES

if TYPE_CHECKING:
    from starlette.requests import HTTPConnection, Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig

__all__ = [
    "COOKIE_PATH",
    "DEFAULT_SESSION_COOKIE_NAME",
    "MAX_SESSION_COOKIE_CHARS",
    "PLAIN_SESSION_COOKIE_NAME",
    "CookieSameSite",
    "PendingLogin",
    "clear_session_cookies",
    "issue_session_cookies",
    "sign_session_id",
]

_HOST_ONLY_COOKIE_PREFIX: Final = "__Host-"
_SECURE_COOKIE_PREFIX: Final = "__Secure-"
PLAIN_SESSION_COOKIE_NAME: Final = "session_id"
_PLAIN_PENDING_LOGIN_COOKIE_NAME: Final = "oidc_pending"
_MAX_PENDING_LOGIN_COOKIE_CHARS: Final = 896
# A signed session cookie is an identifier plus a hex digest; anything much
# longer was not issued here, so the reader rejects it before any HMAC is computed.
MAX_SESSION_COOKIE_CHARS: Final = 200
_PENDING_SECRET_BYTES: Final = 32
"""Random bytes in each of a pending login's state, nonce and verifier,
which are minted with ``secrets.token_urlsafe``."""

_PENDING_LOGIN_VERSION: Final = "v2"
_PENDING_LOGIN_SIGNING_PREFIX: Final = b"oidc-pending:"
_SESSION_SIGNING_PREFIX: Final = b"session:"
# The callback is a top-level navigation from the issuer's site, which a
# Strict cookie would not accompany.
_PENDING_LOGIN_SAMESITE: Final[CookieSameSite] = "lax"
_MAX_PENDING_LOGINS: Final = 5
# A cookie that does not verify, or whose name appears twice, ranks below
# every genuine one and is evicted first.
_UNRANKED: Final = -1
_STATE_DIGEST_HEX_CHARS: Final = 16
_STATE_DIGEST: Final = re.compile(rf"[0-9a-f]{{{_STATE_DIGEST_HEX_CHARS}}}")
_COOKIE_NAME_TOKEN: Final = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
# Unpadded base64url spells n random bytes in exactly ceil(4n / 3)
# characters, so a field of any other shape was not minted as a pending secret.
_PENDING_SECRET: Final = rf"[A-Za-z0-9_-]{{{math.ceil(4 * _PENDING_SECRET_BYTES / 3)}}}"
_RETURN_PATH_FIELD_CHARS: Final = math.ceil(4 * MAX_RETURN_PATH_BYTES / 3)
_PENDING_LOGIN_VALUE: Final = re.compile(
    rf"{_PENDING_LOGIN_VERSION}"
    rf"\.(?P<state>{_PENDING_SECRET})"
    rf"\.(?P<nonce>{_PENDING_SECRET})"
    rf"\.(?P<code_verifier>{_PENDING_SECRET})"
    r"\.(?P<issued_at>0|[1-9][0-9]{0,11})"
    rf"\.(?P<return_to>[A-Za-z0-9_-]{{0,{_RETURN_PATH_FIELD_CHARS}}})"
)
_PENDING_LOGIN_SIGNATURE: Final = re.compile(r"[0-9a-f]{64}")

CookieSameSite = Literal["strict", "lax"]
_DEFAULT_COOKIE_SAMESITE: Final[CookieSameSite] = "strict"
COOKIE_PATH: Final = "/"


class _CookieAttributes(TypedDict):
    path: str
    secure: bool
    httponly: bool
    samesite: CookieSameSite


def _default_cookie_name(plain_name: str, *, secure: bool) -> str:
    """Return the name a cookie gets when the host names none.

    A ``__Host-`` cookie can be set only by this exact host, so a sibling
    subdomain cannot toss one in with ``Domain=parent``. Browsers accept the
    prefix only on a ``Secure`` cookie, so without ``Secure`` the plain name
    is the one that still works.
    """
    return f"{_HOST_ONLY_COOKIE_PREFIX}{plain_name}" if secure else plain_name


DEFAULT_SESSION_COOKIE_NAME: Final = _default_cookie_name(PLAIN_SESSION_COOKIE_NAME, secure=True)


def _pending_login_cookie_prefix(*, secure: bool) -> str:
    """The part every pending-login cookie's name starts with."""
    return f"{_default_cookie_name(_PLAIN_PENDING_LOGIN_COOKIE_NAME, secure=secure)}_"


def _pending_login_cookie_name(state: str, *, secure: bool) -> str:
    """The name of the cookie that carries the pending login of ``state``."""
    state_digest = hashlib.sha256(state.encode()).hexdigest()[:_STATE_DIGEST_HEX_CHARS]
    return f"{_pending_login_cookie_prefix(secure=secure)}{state_digest}"


def _is_pending_login_cookie_name(name: str, *, secure: bool) -> bool:
    """Whether ``name`` has the shape ``_pending_login_cookie_name`` gives every
    pending-login cookie, so webauth may clear it; a name of any other shape
    was not set by webauth, and may not even be a legal cookie name."""
    prefix = _pending_login_cookie_prefix(secure=secure)
    if not name.startswith(prefix):
        return False
    return _STATE_DIGEST.fullmatch(name.removeprefix(prefix)) is not None


def _is_reserved_cookie_name(name: str) -> bool:
    """Whether ``name`` is one webauth's own cookies use, in either variant.

    A session cookie under such a name would meet the cookie webauth
    sets there, and the browser would send both.
    """
    return any(
        name.startswith(_pending_login_cookie_prefix(secure=secure))
        for secure in (True, False)
    )


def _is_valid_cookie_name(name: str) -> bool:
    """Whether ``name`` is an RFC 6265 ``cookie-name``; Starlette refuses most other names."""
    return _COOKIE_NAME_TOKEN.fullmatch(name) is not None


def _is_host_only_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Host-`` cookie (case-insensitively)."""
    return name.lower().startswith(_HOST_ONLY_COOKIE_PREFIX.lower())


def _is_secure_prefixed_cookie_name(name: str) -> bool:
    """Whether a browser treats ``name`` as a ``__Secure-`` cookie (case-insensitively)."""
    return name.lower().startswith(_SECURE_COOKIE_PREFIX.lower())


def _cookie_pairs(connection: HTTPConnection) -> list[tuple[str, str]]:
    """Every name and value the raw ``Cookie`` headers carry, in order.

    Starlette's cookie dict silently keeps one of several same-named
    cookies, so each pair is parsed on its own with Starlette's parser to keep
    its browser-compatible trimming and unquoting.
    """
    pairs = "; ".join(connection.headers.getlist("cookie")).split(";")
    return [item for pair in pairs for item in cookie_parser(pair).items()]


def _cookie_values(connection: HTTPConnection, name: str) -> list[str]:
    """Every value the connection's cookies carry under ``name``, in order."""
    return [value for key, value in _cookie_pairs(connection) if key == name]


def _signature(prefix: bytes, text: str, secret: bytes) -> str:
    return hmac.new(secret, prefix + text.encode(), hashlib.sha256).hexdigest()


def _session_signature(session_id: str, secret: bytes) -> str:
    return _signature(_SESSION_SIGNING_PREFIX, session_id, secret)


def sign_session_id(session_id: str, secret: bytes) -> str:
    """Return ``session_id.hmac_hex`` for use as a cookie value.

    The session cookie is signed with HMAC-SHA256 over a prefix of its own
    plus the id, so the signature of a pending login is no
    session cookie.

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


def _verify_session_cookie(cookie_value: str, secret: bytes) -> str | None:
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


def _cookie_attributes(config: WebAuthConfig, samesite: CookieSameSite) -> _CookieAttributes:
    """The attributes every cookie is set with, and repeated when it is taken back."""
    return _CookieAttributes(
        path=COOKIE_PATH, secure=config.cookie_secure, httponly=True, samesite=samesite,
    )


def issue_session_cookies(
    response: Response, session_id: str, config: WebAuthConfig,
) -> None:
    """Hand the browser its signed session.

    The cookie lives as long as ``session_lifetime.absolute_max_age_seconds``,
    the cap. It is issued once at login: renewing a session reissues nothing,
    so the browser keeps it exactly as long as the session may last. It is
    ``HttpOnly`` and carries ``Secure`` unless the host switched
    ``cookie_secure`` off: a request's scheme is not trusted to decide it,
    because behind an unlisted TLS proxy every request looks like plain http.
    """
    response.set_cookie(
        config.session_cookie_name,
        sign_session_id(session_id, config.signing_key),
        max_age=config.session_lifetime.absolute_max_age_seconds,
        **_cookie_attributes(config, config.cookie_samesite),
    )


def clear_session_cookies(response: Response, config: WebAuthConfig) -> None:
    """Take the session cookie back, so the browser stops carrying a dead session.

    The deletion repeats the attributes the cookie was set with, so a browser
    that only lets a secure context overwrite a ``Secure`` cookie accepts it.
    """
    response.delete_cookie(
        config.session_cookie_name, **_cookie_attributes(config, config.cookie_samesite),
    )


@dataclass(frozen=True)
class PendingLogin:
    """What the browser carries between being sent to the issuer and its return:
    the login's secrets, the wall-clock second it began and the path of the
    app to return to, if any."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)
    issued_at: int
    return_to: str | None = None

    def returning_to(self, return_to: str | None) -> PendingLogin:
        return PendingLogin(
            state=self.state,
            nonce=self.nonce,
            code_verifier=self.code_verifier,
            issued_at=self.issued_at,
            return_to=return_to,
        )


def _issue_pending_login_cookie(
    response: Response, pending: PendingLogin, *, max_age_seconds: int, config: WebAuthConfig,
) -> None:
    """Hand the browser the signed pending login, in a cookie named for its state."""
    response.set_cookie(
        _pending_login_cookie_name(pending.state, secure=config.cookie_secure),
        _sign_pending_login(pending, config.signing_key),
        max_age=max_age_seconds,
        **_cookie_attributes(config, _PENDING_LOGIN_SAMESITE),
    )


def _clear_pending_login_cookie(response: Response, name: str, config: WebAuthConfig) -> None:
    """Take a pending-login cookie back, repeating the attributes it was set with."""
    response.delete_cookie(name, **_cookie_attributes(config, _PENDING_LOGIN_SAMESITE))


def _begin_pending_login(
    request: Request,
    response: Response,
    pending: PendingLogin,
    *,
    max_age_seconds: int,
    config: WebAuthConfig,
) -> None:
    """Hand the browser ``pending``, first clearing the oldest pending-login
    cookies so it holds at most ``_MAX_PENDING_LOGINS`` with the new one."""
    for name in _pending_login_cookies_to_evict(request, config):
        _clear_pending_login_cookie(response, name, config)
    _issue_pending_login_cookie(response, pending, max_age_seconds=max_age_seconds, config=config)


def _take_pending_login(
    request: Request, response: Response, state: str, config: WebAuthConfig,
) -> PendingLogin | None:
    """The pending login of ``state`` the browser carried back, or ``None`` when
    its cookie is missing, repeated or does not verify; its cookie is cleared
    either way, so it works once."""
    cookie_name = _pending_login_cookie_name(state, secure=config.cookie_secure)
    _clear_pending_login_cookie(response, cookie_name, config)
    values = _cookie_values(request, cookie_name)
    if len(values) != 1:
        return None
    return _verify_pending_login(values[0], config.signing_key)


def _pending_login_cookies_to_evict(request: Request, config: WebAuthConfig) -> list[str]:
    """The names to clear so the new pending login is one of at most
    ``_MAX_PENDING_LOGINS``, oldest first."""
    issued_at_by_name: dict[str, int] = {}
    for name, value in _cookie_pairs(request):
        if _is_pending_login_cookie_name(name, secure=config.cookie_secure):
            issued_at_by_name[name] = (
                _UNRANKED if name in issued_at_by_name else _issued_at(value, config)
            )
    oldest_first = sorted(issued_at_by_name, key=issued_at_by_name.__getitem__)
    return oldest_first[: max(0, len(oldest_first) - _MAX_PENDING_LOGINS + 1)]


def _issued_at(cookie_value: str, config: WebAuthConfig) -> int:
    pending = _verify_pending_login(cookie_value, config.signing_key)
    return _UNRANKED if pending is None else pending.issued_at


def _sign_pending_login(pending: PendingLogin, secret: bytes) -> str:
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
        _encoded_return_to(pending.return_to),
    ))
    if not _PENDING_LOGIN_VALUE.fullmatch(payload):
        raise ValueError("the pending login does not fit the pending-login cookie")
    return f"{payload}.{_pending_login_signature(payload, secret)}"


def _verify_pending_login(cookie_value: str, secret: bytes) -> PendingLogin | None:
    """The pending login a cookie value carries, or ``None`` when it is
    oversized, of another shape or version, or not signed under ``secret``."""
    if len(cookie_value) > _MAX_PENDING_LOGIN_COOKIE_CHARS:
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
        return_to=_decoded_return_to(fields["return_to"]),
    )


def _encoded_return_to(return_to: str | None) -> str:
    if return_to is None:
        return ""
    return base64.urlsafe_b64encode(return_to.encode()).decode().rstrip("=")


def _decoded_return_to(field: str) -> str | None:
    if not field:
        return None
    return base64.urlsafe_b64decode(field + "=" * (-len(field) % 4)).decode()


def _pending_login_signature(payload: str, secret: bytes) -> str:
    return _signature(_PENDING_LOGIN_SIGNING_PREFIX, payload, secret)
