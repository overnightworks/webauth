"""Turning a signed session cookie into the account that made the request.

The application binds these dependencies once, over the stores it supplies,
and every protected route asks for them. Nothing here commits. Without the
session gate, the session renewal is durable when the store applies it, or,
for a store that writes into the transaction the application's
`session_store` dependency opens, when the host commits that transaction.
Behind the gate, on a gated or optional path, `current_user` returns the
gate's admission when it was made for the request's own session cookie, and
on a public path it admits by itself; the gate committed its renewal through
the host's `SessionTransaction` before the route ran, and a route that fails
afterwards does not undo it.

A request the bearer gate admitted carries no session: the records below let
the CSRF origin check and the session gate step aside for it, and `current_user`
raises on it, because a machine route asks for `bearer_caller` instead.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Final
from urllib.parse import urlencode

from fastapi import Depends, HTTPException, Request
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response

from webauth import ports
from webauth._media_types import prefers_html
from webauth._origins import origin_is_allowed
from webauth._paths import reads_as_another_host, requested_address, same_app_path
from webauth.config import SessionLifetime, WebAuthConfig, web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    _cookie_values,
    _verify_session_cookie,
)
from webauth.ports import SessionRecordStore

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "AuthDependencies",
    "LoginRedirect",
    "ConnectionRefusal",
    "admit_session",
    "authenticate_websocket",
    "current_user_dependency",
    "session_id_from_request",
    "unauthenticated_response",
]


_AUTHENTICATION_REQUIRED_DETAIL: Final = "Authentication required"
_INVALID_SESSION_DETAIL: Final = "Invalid session"
_SESSION_EXPIRED_DETAIL: Final = "Session expired"
_ADMIN_REQUIRED_DETAIL: Final = "Admin access required"
_EXPIRY_TOLERANCE: Final = timedelta(seconds=60)


@dataclass(frozen=True)
class LoginRedirect:
    """Where a server-rendered host sends a browser holding no live session.

    ``redirect_query_param`` is the host's own name for the query key that
    carries the address the browser asked for, so the login page reads it
    back under a name the host already chose rather than one this library
    invents; it carries the raw path and query the browser asked for. A
    request whose ``Accept`` header does not rate ``text/html`` above
    ``application/json`` by q-value — an API call, a fetch — still gets 401:
    only a browser navigation is redirected.

    ``path`` must be a same-origin absolute path: browsers drop tab, CR and LF
    and read a backslash as a slash, so ``/\\x`` and ``/<tab>/x`` lead off the
    site exactly as ``//x`` does, and a path written like that is refused.
    """

    path: str
    redirect_query_param: str

    def __post_init__(self) -> None:
        if not self.path.startswith("/") or reads_as_another_host(self.path):
            raise ValueError(
                "login_redirect.path must be a same-origin absolute path: "
                "one leading '/', never '//' or a backslash form of it, and no scheme",
            )


@dataclass(frozen=True)
class AuthDependencies:
    """The route dependencies built from one set of stores.

    ``admin_user`` and ``verified_session_id`` resolve ``current_user``
    themselves, so an application that replaces one in a test replaces the
    identity behind all three.
    """

    current_user: Callable[[Request, ports.SessionRecordStore], ports.AuthenticatedUser]
    admin_user: Callable[[Request, ports.AuthenticatedUser], ports.AuthenticatedUser]
    verified_session_id: Callable[[Request, ports.AuthenticatedUser], str]


def current_user_dependency(
    *,
    session_store: Callable[..., SessionRecordStore],
    on_authenticated: Callable[[ports.AuthenticatedUser], None],
    login_redirect: LoginRedirect | None = None,
) -> AuthDependencies:
    """Bind the auth dependencies to one application's stores.

    ``session_store`` is the application's own dependency. When
    ``current_user`` admits a request itself, the session renewal is written
    into whatever transaction that dependency puts the store on. Behind the
    session gate it returns the gate's admission instead, when that was made
    for this request's own session cookie under this application's
    ``WebAuthConfig``; the gate committed the renewal before the route ran, and
    the store ``session_store`` builds is not asked.
    ``on_authenticated`` is handed the account once the request's identity is
    established, so the application can bind it into its own log context.
    ``login_redirect`` is unset by default: a missing or dead session then
    keeps answering 401, byte-identically to a host that never names one.
    A dependency can only raise ``HTTPException``, so the 302 still carries
    FastAPI's default JSON body (``{"detail":"Found"}``) beside its
    ``Location`` header.
    """

    def current_user(
        request: Request,
        sessions: SessionRecordStore = Depends(session_store),
    ) -> ports.AuthenticatedUser:
        user = _gate_or_own_admission(request, sessions)
        if isinstance(user, ConnectionRefusal):
            raise _http_refusal(request, user, login_redirect)
        on_authenticated(user)
        return user

    def admin_user(
        request: Request,
        user: ports.AuthenticatedUser = Depends(current_user),
    ) -> ports.AuthenticatedUser:
        return _require_admin(request, user)

    def verified_session_id(
        request: Request,
        _account: ports.AuthenticatedUser = Depends(current_user),
    ) -> str:
        """The session this request proved it holds.

        A logout needs the identifier of the very session it just
        authenticated, and ``AuthenticatedUser`` deliberately does not carry
        one. Resolving ``current_user`` first is what makes the answer
        trustworthy: an expired or unknown session never reaches
        this line. A route ends the session through ``log_out``, never by
        deleting from the store itself.
        """
        return _session_id_from_cookie(request, web_auth_config(request), login_redirect)

    return AuthDependencies(
        current_user=current_user,
        admin_user=admin_user,
        verified_session_id=verified_session_id,
    )


def authenticate_websocket(
    connection: HTTPConnection, *, sessions: SessionRecordStore,
) -> ports.AuthenticatedUser | ConnectionRefusal:
    """The account behind a WebSocket handshake, or why the handshake is refused.

    The Origin is decided first, so a refused Origin never touches the store: a
    browser sends the session cookie on a cross-site handshake, and only the
    Origin tells a foreign page from the application's own. Exactly one Origin
    naming a host the application serves is admitted; there is no ``Referer``
    fallback and ``Sec-Fetch-Site`` does not decide. For local development list
    ``localhost`` and ``127.0.0.1`` in ``allowed_hosts_exact``.
    A client that is not a browser must send an allowed Origin too. The Origin
    keeps a foreign page from using a visitor's cookie; it is no credential.
    Then the session is decided exactly as ``current_user`` decides it for an
    HTTP request, renewal included.

    Nothing here commits, and a failing store raises rather than refusing: an
    exception never accepts the socket. The host runs a synchronous store in a
    worker, not in the receive loop, and finishes its transaction before
    ``accept`` and before waiting for a message: a transactional store holds
    the session's row until the transaction ends, which would block a logout.
    It closes a refused handshake with code 1008 before ``accept``; a real
    server answers the handshake with HTTP 403, and the browser receives no
    close frame. After success, ``session_id_from_request`` names the session
    on the same handshake.

    A socket outlives its session: a logout, a host's own revocation and
    back-channel logout delete the stored session and cannot signal an open
    socket. The host calls this again, in a fresh transaction, before protected
    work and on its own schedule while a stream runs, and on a refusal closes
    the socket and stops the work. A successful re-check renews the session
    like a request, up to the absolute cap of ``SessionLifetime``, which bounds
    a socket's life.

    A host may wrap this function in its own dependency: FastAPI resolves an
    ``HTTPConnection`` parameter on a WebSocket route as well as on an HTTP one.
    """
    origin_refusal = _origin_refusal(connection)
    if origin_refusal is not None:
        return origin_refusal
    return _resolve_session(connection, sessions)


def _origin_refusal(connection: HTTPConnection) -> ConnectionRefusal | None:
    origins = connection.headers.getlist("origin")
    if not origins:
        return ConnectionRefusal.MISSING_ORIGIN
    if len(origins) > 1 or not origin_is_allowed(origins[0], web_auth_config(connection)):
        return ConnectionRefusal.FOREIGN_ORIGIN
    return None


def unauthenticated_response(
    request: Request, login_redirect: LoginRedirect | None,
) -> Response:
    """The refusal ``current_user_dependency`` answers with for no session cookie.

    A host whose own middleware is the session authority calls this directly
    to answer what the dependency answers for a request without a usable
    session cookie (``ConnectionRefusal.NO_SESSION``): the login redirect
    (``Location``, ``next`` carrying path and query) a browser navigation
    gets, the 401 ``Authentication required`` every other request gets. For a
    forged, doubled or ended session the dependency and the session gate
    answer ``Invalid session`` or ``Session expired``, with the same redirect.
    """
    return _refusal_response(request, ConnectionRefusal.NO_SESSION, login_redirect)


def _unauthenticated(
    request: Request, detail: str, login_redirect: LoginRedirect | None,
) -> HTTPException:
    """The refusal for a missing or dead session: a 401, or a login redirect.

    A browser navigation is one whose ``Accept`` header rates ``text/html``
    above ``application/json``, by q-value negotiation; every other request —
    an API call, a fetch — keeps the 401 even when the host named a
    ``login_redirect``, because it cannot follow one.
    """
    if login_redirect is not None and prefers_html(request):
        query = urlencode({login_redirect.redirect_query_param: _asked_for_address(request)})
        return HTTPException(302, headers={"Location": f"{login_redirect.path}?{query}"})
    return HTTPException(401, detail)


def _asked_for_address(request: Request) -> str:
    """The raw path and query the guarded request named, safe to echo back.

    An address that is not a path of this app collapses to ``/`` before it is
    ever carried in a redirect.
    """
    return same_app_path(request, requested_address(request)) or "/"


class ConnectionRefusal(Enum):
    """Why a connection is refused, as a stable value a host can log or branch on.

    The session members are the one taxonomy of why no live session was
    found; the HTTP dependencies answer them with their own responses, so a
    refusal reads the same on both channels. The origin members are decided
    by ``authenticate_websocket`` alone. ``admit_session`` returns only
    ``SESSION_ENDED_OR_EXPIRED``.

    The HTTP dependencies answer a navigation with the 302 to ``login_redirect``
    when the host named one, and every other request with the 401 each session
    member names.
    """

    NO_SESSION = "no-session"
    """The session cookie is missing, empty or too long; 401 ``Authentication required``."""
    INVALID_SESSION = "invalid-session"
    """The cookie is forged or present more than once; 401 ``Invalid session``.

    A sibling subdomain can set a second cookie of the same name, so a request
    carrying two is refused rather than resolved to either.
    """
    SESSION_ENDED_OR_EXPIRED = "session-ended-or-expired"
    """The store does not know the session, its stored expiry is outside the
    session lifetime, or ``touch`` answers ``False``; 401 ``Session expired``."""
    MISSING_ORIGIN = "missing-origin"
    """The handshake carries no ``Origin`` header."""
    FOREIGN_ORIGIN = "foreign-origin"
    """The ``Origin`` is empty, repeated, ``null``, unparsable or not an allowed host."""


def session_id_from_request(connection: HTTPConnection, config: WebAuthConfig) -> str | None:
    """The session identifier the connection's one signed session cookie names.

    ``None`` when the cookie is missing, longer than
    ``webauth.cookies.MAX_SESSION_COOKIE_CHARS`` even when correctly signed,
    forged, or present more than once: a sibling subdomain can set a second cookie of the same
    name, and choosing either would let it decide whose account the connection
    runs in. A host that reads the session cookie itself calls this instead of
    ``request.cookies``.
    """
    reading = _read_session_cookie(connection, config)
    return None if isinstance(reading, ConnectionRefusal) else reading


def _session_id_from_cookie(
    request: Request, config: WebAuthConfig, login_redirect: LoginRedirect | None,
) -> str:
    reading = _read_session_cookie(request, config)
    if isinstance(reading, ConnectionRefusal):
        raise _http_refusal(request, reading, login_redirect)
    return reading


def _read_session_cookie(
    connection: HTTPConnection, config: WebAuthConfig,
) -> str | ConnectionRefusal:
    values = _cookie_values(connection, config.session_cookie_name)
    if len(values) > 1:
        return ConnectionRefusal.INVALID_SESSION
    if not values or not values[0] or len(values[0]) > MAX_SESSION_COOKIE_CHARS:
        return ConnectionRefusal.NO_SESSION
    session_id = _verify_session_cookie(values[0], config.signing_key)
    return ConnectionRefusal.INVALID_SESSION if session_id is None else session_id


def _http_refusal(
    request: Request, refusal: ConnectionRefusal, login_redirect: LoginRedirect | None,
) -> HTTPException:
    detail = _HTTP_DETAIL_OF_SESSION_REFUSAL[refusal]
    return _unauthenticated(request, detail, login_redirect)


def _refusal_response(
    request: Request, refusal: ConnectionRefusal, login_redirect: LoginRedirect | None,
) -> Response:
    """``_http_refusal`` as the response FastAPI's default handler builds from it.

    For a caller that runs outside the exception handlers: a middleware.
    """
    exc = _http_refusal(request, refusal, login_redirect)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


_HTTP_DETAIL_OF_SESSION_REFUSAL: Final = {
    ConnectionRefusal.NO_SESSION: _AUTHENTICATION_REQUIRED_DETAIL,
    ConnectionRefusal.INVALID_SESSION: _INVALID_SESSION_DETAIL,
    ConnectionRefusal.SESSION_ENDED_OR_EXPIRED: _SESSION_EXPIRED_DETAIL,
}


def _as_instant(stored: datetime) -> datetime:
    """The stored datetime pinned to the fixed offset it names, naive read as UTC.

    A zone with a clock change would subtract two instants by wall time; a
    fixed offset subtracts by the instants themselves, and unlike
    ``astimezone`` it cannot overflow at the calendar's edge.
    """
    offset = stored.utcoffset()
    if offset is None:
        return stored.replace(tzinfo=UTC)
    return stored.replace(tzinfo=timezone(offset))


def _whole_second_now(config: WebAuthConfig) -> datetime:
    return datetime.fromtimestamp(int(config.wall_clock()), UTC)


def _renewed_expiry(
    lifetime: SessionLifetime, *, now: datetime, created_at: datetime,
) -> datetime:
    idle = timedelta(seconds=lifetime.idle_seconds)
    remaining_cap = timedelta(seconds=lifetime.absolute_max_age_seconds) - (now - created_at)
    return now + min(idle, remaining_cap)


def _is_admitted(
    lifetime: SessionLifetime, record: ports.SessionRecord, now: datetime,
) -> bool:
    created_at = _as_instant(record.created_at)
    expires_at = _as_instant(record.expires_at)
    return (
        created_at <= now + _EXPIRY_TOLERANCE
        and now <= expires_at
        and expires_at - now <= timedelta(seconds=lifetime.idle_seconds) + _EXPIRY_TOLERANCE
        and expires_at - created_at <= timedelta(seconds=lifetime.absolute_max_age_seconds)
    )


def admit_session(
    session_id: str, *, sessions: SessionRecordStore, config: WebAuthConfig,
) -> ports.AuthenticatedUser | ConnectionRefusal:
    """Decide whether a session id speaks for an account, and renew it if so.

    For a host that reads the id itself, without a request or a cookie. It
    checks no ``Origin``: a host that admits a socket with it instead of
    ``authenticate_websocket`` applies that function's Origin rule first.
    Returns the account, or ``ConnectionRefusal.SESSION_ENDED_OR_EXPIRED`` for
    an unknown id, a session outside its lifetime, or one the store no longer
    holds; a refused session is not renewed. Sets no cookie. A failing store,
    or a ``touch`` that answers anything but a ``bool``, raises. Nothing here
    commits: the host finishes its transaction right after the call.

    The clock is ``config.wall_clock`` read once, as whole seconds. A stored
    session is admitted only when ``created_at <= now + 60 s`` and
    ``now <= expires_at <= min(now + idle + 60 s, created_at + cap)``, with
    ``idle`` and ``cap`` from ``WebAuthConfig.session_lifetime``: the 60 seconds
    tolerate clock skew on the idle window and on ``created_at``, and none on the
    cap. An admitted session is renewed to ``min(now + idle, created_at + cap)``,
    so it never outlives its cap.
    """
    record = sessions.load(session_id)
    now = _whole_second_now(config)
    if record is None or not _is_admitted(config.session_lifetime, record, now):
        return ConnectionRefusal.SESSION_ENDED_OR_EXPIRED

    renewed = sessions.touch(
        session_id,
        expires_at=_renewed_expiry(
            config.session_lifetime, now=now, created_at=_as_instant(record.created_at),
        ),
    )
    if type(renewed) is not bool:
        raise TypeError(
            f"SessionRecordStore.touch must return a bool, not {type(renewed).__name__}",
        )
    if not renewed:
        return ConnectionRefusal.SESSION_ENDED_OR_EXPIRED

    return ports.AuthenticatedUser(
        id=record.user.id,
        username=record.user.username,
        role=record.user.role,
    )


def _resolve_session(
    connection: HTTPConnection, sessions: SessionRecordStore,
) -> ports.AuthenticatedUser | ConnectionRefusal:
    """The one decision whom a connection's session cookie speaks for.

    Cookie and signature are read here; ``admit_session`` decides the rest.
    HTTP and WebSocket both ask here and translate the refusal into their own
    answer.
    """
    config = web_auth_config(connection)
    session_id = _read_session_cookie(connection, config)
    if isinstance(session_id, ConnectionRefusal):
        return session_id
    return admit_session(session_id, sessions=sessions, config=config)


_GATE_ADMISSION_SCOPE_KEY: Final = "webauth.session_gate"


@dataclass(frozen=True)
class _GateAdmission:
    """What the session gate decided for one request, and what it was decided from.

    ``admission`` is the account on a gated or optional path with a live
    session, the refusal on an optional path without one, and ``None`` on a
    public path, where the gate asked no store.
    """

    config: WebAuthConfig
    cookie_reading: str | ConnectionRefusal
    admission: ports.AuthenticatedUser | ConnectionRefusal | None


def _record_gate_admission(connection: HTTPConnection, record: _GateAdmission) -> None:
    connection.scope[_GATE_ADMISSION_SCOPE_KEY] = record


def _gate_admission(connection: HTTPConnection) -> _GateAdmission | None:
    """The gate's decision, only when it was made for this very request.

    Same configuration instance and a session cookie that reads as the one
    admitted; anything else, a value other code wrote included, is no decision.
    """
    record = connection.scope.get(_GATE_ADMISSION_SCOPE_KEY)
    if type(record) is not _GateAdmission:
        return None
    if record.config is not web_auth_config(connection):
        return None
    if record.cookie_reading != _read_session_cookie(connection, record.config):
        return None
    return record


_BEARER_ADMISSION_SCOPE_KEY: Final = "webauth.bearer_gate"


@dataclass(frozen=True)
class _BearerAdmission:
    """What the bearer gate admitted: this app's gate, this path, this one header.

    Only a SHA-256 digest of the `Authorization` value is kept, in request
    memory, so the record does not store the token. It says the gate admitted
    the request; it is not a freshness proof, and the gate verifies the header
    again on every request it selects.
    """

    app: object
    path: str
    authorization_digest: bytes
    caller: ports.BearerCaller


def _authorization_digest(authorization: str) -> bytes:
    return hashlib.sha256(authorization.encode("latin-1")).digest()


def _record_bearer_admission(connection: HTTPConnection, caller: ports.BearerCaller) -> None:
    (authorization,) = connection.headers.getlist("authorization")
    connection.scope[_BEARER_ADMISSION_SCOPE_KEY] = _BearerAdmission(
        app=connection.scope["app"],
        path=connection.scope["path"],
        authorization_digest=_authorization_digest(authorization),
        caller=caller,
    )


def _bearer_admission(connection: HTTPConnection) -> _BearerAdmission | None:
    """The bearer gate's admission, only when it was made for this very request.

    The strict reader: the same app, the same decoded path and exactly one
    `Authorization` line with the digest admitted. Anything else, a value other
    code wrote included, is no admission.
    """
    record = connection.scope.get(_BEARER_ADMISSION_SCOPE_KEY)
    if type(record) is not _BearerAdmission:
        return None
    authorizations = connection.headers.getlist("authorization")
    if (
        record.app is not connection.scope.get("app")
        or record.path != connection.scope["path"]
        or len(authorizations) != 1
        or record.authorization_digest != _authorization_digest(authorizations[0])
    ):
        return None
    return record


def _is_bearer_admitted(connection: HTTPConnection) -> bool:
    """The loose reader: any admission in the scope. Refusing more can only fail closed."""
    return type(connection.scope.get(_BEARER_ADMISSION_SCOPE_KEY)) is _BearerAdmission


def _raise_for_bearer_admission(connection: HTTPConnection) -> None:
    if _is_bearer_admitted(connection):
        raise RuntimeError(
            "A bearer-admitted request carries no session: a machine route takes "
            "Depends(bearer_caller), not current_user, admin_user, admitted_admin "
            "or verified_session_id.",
        )


def _require_admin(
    connection: HTTPConnection, user: ports.AuthenticatedUser,
) -> ports.AuthenticatedUser:
    """The account itself when its role is the configured admin role; else the 403."""
    if user.role != web_auth_config(connection).admin_role:
        raise HTTPException(403, _ADMIN_REQUIRED_DETAIL)
    return user


def _gate_or_own_admission(
    connection: HTTPConnection, sessions: SessionRecordStore,
) -> ports.AuthenticatedUser | ConnectionRefusal:
    _raise_for_bearer_admission(connection)
    decided = _gate_admission(connection)
    if decided is None or decided.admission is None:
        return _resolve_session(connection, sessions)
    return decided.admission
