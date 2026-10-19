"""Turning a signed session cookie into the account that made the request.

The application binds these two dependencies once, over the stores it
supplies, and every protected route asks for them. Nothing here commits:
the session renewal and the audit record land in whatever transaction the
application's stores write into, and become durable only when the endpoint
commits it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Final
from urllib.parse import urlencode

from fastapi import Depends, HTTPException, Request
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse, Response

from webauth import ports
from webauth._content_negotiation import prefers_html
from webauth._origins import origin_is_allowed
from webauth.config import WebAuthConfig, web_auth_config
from webauth.cookies import (
    MAX_SESSION_COOKIE_CHARS,
    _cookie_values,
    _verify_session_cookie,
    session_reference,
)
from webauth.ports import (
    AuditSink,
    SessionIdentityChange,
    SessionIdentityChanged,
    SessionRecordStore,
)
from webauth.proxies import client_user_agent, resolve_client_ip

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "AuthDependencies",
    "LoginRedirect",
    "WebSocketRefusal",
    "authenticate_websocket",
    "current_user_dependency",
    "session_id_from_request",
    "unauthenticated_response",
]


_AUTHENTICATION_REQUIRED_DETAIL: Final = "Authentication required"
_INVALID_SESSION_DETAIL: Final = "Invalid session"
_SESSION_EXPIRED_DETAIL: Final = "Session expired"
_ACCOUNT_DISABLED_DETAIL: Final = "Account disabled"
_ADMIN_REQUIRED_DETAIL: Final = "Admin access required"


_BROWSER_STRIPPED_CHARACTERS = str.maketrans("", "", "\t\r\n")
_ANOTHER_HOST_PREFIXES = ("//", "/\\", "\\/", "\\\\")


def _reads_as_another_host(path: str) -> bool:
    """Whether a browser reads ``path`` as an address on another host.

    Browsers drop tab, CR and LF and treat a backslash as a slash, so ``/\\x``
    and ``/<tab>/x`` lead off the site exactly as ``//x`` does.
    """
    return path.translate(_BROWSER_STRIPPED_CHARACTERS).startswith(_ANOTHER_HOST_PREFIXES)


@dataclass(frozen=True)
class LoginRedirect:
    """Where a server-rendered host sends a browser holding no live session.

    ``redirect_query_param`` is the host's own name for the query key that
    carries the address the browser asked for, so the login page reads it
    back under a name the host already chose rather than one this library
    invents. A request whose ``Accept`` header does not prefer HTML — an API
    call, a fetch — still gets 401: only a browser navigation is redirected.
    """

    path: str
    redirect_query_param: str

    def __post_init__(self) -> None:
        if not self.path.startswith("/") or _reads_as_another_host(self.path):
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

    current_user: Callable[..., ports.AuthenticatedUser]
    admin_user: Callable[..., ports.AuthenticatedUser]
    verified_session_id: Callable[..., str]


def current_user_dependency(
    *,
    session_store: Callable[..., SessionRecordStore],
    audit_sink: Callable[..., AuditSink],
    on_authenticated: Callable[[ports.AuthenticatedUser], None],
    login_redirect: LoginRedirect | None = None,
) -> AuthDependencies:
    """Bind the auth dependencies to one application's stores.

    ``session_store`` and ``audit_sink`` are the application's own
    dependencies, so whatever transaction it puts them on is the one the
    session renewal and the audit record are written into.
    ``on_authenticated`` is handed the account once the request's identity is
    established, so the application can bind it into its own log context.
    ``login_redirect`` is unset by default: a missing or dead session then
    keeps answering 401, byte-identically to a host that never names one.
    """

    def current_user(
        request: Request,
        sessions: SessionRecordStore = Depends(session_store),
        audit: AuditSink = Depends(audit_sink),
    ) -> ports.AuthenticatedUser:
        user = _resolve_session(request, sessions, audit)
        if isinstance(user, WebSocketRefusal):
            raise _http_refusal(request, user, login_redirect)
        on_authenticated(user)
        return user

    def admin_user(
        request: Request,
        user: ports.AuthenticatedUser = Depends(current_user),
    ) -> ports.AuthenticatedUser:
        if user.role != web_auth_config(request).admin_role:
            raise HTTPException(403, _ADMIN_REQUIRED_DETAIL)
        return user

    def verified_session_id(
        request: Request,
        _account: ports.AuthenticatedUser = Depends(current_user),
    ) -> str:
        """The session this request proved it holds.

        A logout needs the identifier of the very session it just
        authenticated, and ``AuthenticatedUser`` deliberately does not carry
        one. Resolving ``current_user`` first is what makes the answer
        trustworthy: an expired, unknown, or deactivated session never reaches
        this line, so a route can delete what it names here without checking
        anything again.
        """
        return _session_id_from_cookie(request, web_auth_config(request), login_redirect)

    return AuthDependencies(
        current_user=current_user,
        admin_user=admin_user,
        verified_session_id=verified_session_id,
    )


def authenticate_websocket(
    connection: HTTPConnection, *, sessions: SessionRecordStore, audit: AuditSink,
) -> ports.AuthenticatedUser | WebSocketRefusal:
    """The account behind a WebSocket handshake, or why the handshake is refused.

    The Origin is decided first, so a refused Origin never touches the store
    or the audit: a browser sends the session cookie on a cross-site
    handshake, and only the Origin tells a foreign page from the application's
    own. Exactly one Origin naming a host the application serves is admitted;
    there is no ``Referer`` fallback and ``Sec-Fetch-Site`` does not decide.
    Then the session is decided exactly as ``current_user`` decides it for an
    HTTP request, renewal and identity audit included.

    Nothing here commits, and a failing store raises rather than refusing: the
    host finishes its transaction before ``accept`` and closes a refused
    handshake with code 1008. A socket outlives its session unless the host
    calls this again, in a fresh transaction, and closes on a refusal.
    """
    origin_refusal = _origin_refusal(connection)
    if origin_refusal is not None:
        return origin_refusal
    return _resolve_session(connection, sessions, audit)


def _origin_refusal(connection: HTTPConnection) -> WebSocketRefusal | None:
    origins = connection.headers.getlist("origin")
    if not origins:
        return WebSocketRefusal.MISSING_ORIGIN
    if len(origins) > 1 or not origin_is_allowed(origins[0], web_auth_config(connection)):
        return WebSocketRefusal.FOREIGN_ORIGIN
    return None


def unauthenticated_response(
    request: Request, login_redirect: LoginRedirect | None,
) -> Response:
    """The refusal ``current_user_dependency`` answers with for no live session.

    A host whose own middleware is the session authority calls this directly
    to answer exactly as the dependency would for the same request: the same
    login redirect (``Location``, ``next`` carrying path and query) a browser
    navigation gets, the same 401 every other request gets. This is the one
    place that decision is made; ``current_user_dependency`` raises the
    identical status, headers and body as an ``HTTPException`` so FastAPI's
    own handler reaches it byte-for-byte.
    """
    exc = _unauthenticated(request, _AUTHENTICATION_REQUIRED_DETAIL, login_redirect)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


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
    """The path and query the guarded request named, safe to echo back.

    A path a browser reads as another host's address collapses to ``/``
    before it is ever carried in a redirect.
    """
    path = "/" if _reads_as_another_host(request.url.path) else request.url.path
    return f"{path}?{request.url.query}" if request.url.query else path


class WebSocketRefusal(Enum):
    """Why a connection is refused, as a stable value a host can log or branch on.

    The session members are the one taxonomy of why no live session was
    found; the HTTP dependencies answer them with their own responses, so a
    refusal reads the same on both channels. The origin members are decided
    by ``authenticate_websocket`` alone.
    """

    NO_SESSION = "no-session"
    INVALID_SESSION = "invalid-session"
    SESSION_ENDED_OR_EXPIRED = "session-ended-or-expired"
    ACCOUNT_DISABLED = "account-disabled"
    MISSING_ORIGIN = "missing-origin"
    FOREIGN_ORIGIN = "foreign-origin"


def session_id_from_request(connection: HTTPConnection, config: WebAuthConfig) -> str | None:
    """The session identifier the connection's one signed session cookie names.

    ``None`` when the cookie is missing, longer than
    ``webauth.cookies.MAX_SESSION_COOKIE_CHARS`` even when correctly signed,
    forged, or present more than once: a sibling subdomain can set a second cookie of the same
    name, and choosing either would let it decide whose account the connection
    runs in.
    """
    reading = _read_session_cookie(connection, config)
    return None if isinstance(reading, WebSocketRefusal) else reading


def _session_id_from_cookie(
    request: Request, config: WebAuthConfig, login_redirect: LoginRedirect | None,
) -> str:
    reading = _read_session_cookie(request, config)
    if isinstance(reading, WebSocketRefusal):
        raise _http_refusal(request, reading, login_redirect)
    return reading


def _read_session_cookie(
    connection: HTTPConnection, config: WebAuthConfig,
) -> str | WebSocketRefusal:
    values = _cookie_values(connection, config.session_cookie_name)
    if len(values) > 1:
        return WebSocketRefusal.INVALID_SESSION
    if not values or not values[0] or len(values[0]) > MAX_SESSION_COOKIE_CHARS:
        return WebSocketRefusal.NO_SESSION
    session_id = _verify_session_cookie(values[0], config.signing_key)
    return WebSocketRefusal.INVALID_SESSION if session_id is None else session_id


def _http_refusal(
    request: Request, refusal: WebSocketRefusal, login_redirect: LoginRedirect | None,
) -> HTTPException:
    if refusal is WebSocketRefusal.ACCOUNT_DISABLED:
        return HTTPException(403, _ACCOUNT_DISABLED_DETAIL)
    detail = _HTTP_DETAIL_OF_SESSION_REFUSAL[refusal]
    return _unauthenticated(request, detail, login_redirect)


_HTTP_DETAIL_OF_SESSION_REFUSAL: Final = {
    WebSocketRefusal.NO_SESSION: _AUTHENTICATION_REQUIRED_DETAIL,
    WebSocketRefusal.INVALID_SESSION: _INVALID_SESSION_DETAIL,
    WebSocketRefusal.SESSION_ENDED_OR_EXPIRED: _SESSION_EXPIRED_DETAIL,
}


def _record_identity_changes(
    audit: AuditSink,
    *,
    session_id: str,
    user_id: str,
    stored_ip: str,
    stored_user_agent: str,
    current_ip: str,
    current_user_agent: str,
) -> None:
    """Report each part of the session's origin that stopped matching.

    A session that was stored without an origin at all is not a change.
    """
    ip_changed = bool(stored_ip and stored_ip != current_ip)
    user_agent_changed = bool(stored_user_agent and stored_user_agent != current_user_agent)
    if ip_changed:
        audit.session_identity_changed(
            SessionIdentityChanged(
                change=SessionIdentityChange.IP_ADDRESS,
                user_id=user_id,
                session_ref=session_reference(session_id),
                previous=stored_ip,
                current=current_ip,
            ),
        )
    if user_agent_changed:
        audit.session_identity_changed(
            SessionIdentityChanged(
                change=SessionIdentityChange.USER_AGENT,
                user_id=user_id,
                session_ref=session_reference(session_id),
                previous=stored_user_agent,
                current=current_user_agent,
            ),
        )


def _resolve_session(
    connection: HTTPConnection, sessions: SessionRecordStore, audit: AuditSink,
) -> ports.AuthenticatedUser | WebSocketRefusal:
    """The one decision whom a connection's session cookie speaks for.

    Cookie, signature, load, liveness, active account, renewal, identity
    audit: HTTP and WebSocket both ask here and translate the refusal into
    their own answer.
    """
    config = web_auth_config(connection)
    session_id = _read_session_cookie(connection, config)
    if isinstance(session_id, WebSocketRefusal):
        return session_id

    record = sessions.load(session_id)
    now = datetime.fromtimestamp(config.wall_clock(), UTC)
    if record is None or not config.session_liveness.admits_stored_session(record, now):
        return WebSocketRefusal.SESSION_ENDED_OR_EXPIRED

    if not record.user.is_active:
        return WebSocketRefusal.ACCOUNT_DISABLED

    current_ip = resolve_client_ip(connection)
    current_user_agent = client_user_agent(connection)

    stored_ip = record.ip_address
    stored_user_agent = record.user_agent
    renewed = sessions.touch(
        record,
        ip_address=current_ip,
        user_agent=current_user_agent,
        now=now,
    )
    if type(renewed) is not bool:
        raise TypeError(
            f"SessionRecordStore.touch must return a bool, not {type(renewed).__name__}",
        )
    if not renewed:
        return WebSocketRefusal.SESSION_ENDED_OR_EXPIRED

    _record_identity_changes(
        audit,
        session_id=session_id,
        user_id=record.user.id,
        stored_ip=stored_ip,
        stored_user_agent=stored_user_agent,
        current_ip=current_ip,
        current_user_agent=current_user_agent,
    )

    return ports.AuthenticatedUser(
        id=record.user.id,
        username=record.user.username,
        role=record.user.role,
        is_active=record.user.is_active,
    )
