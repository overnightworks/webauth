"""Turning a signed session cookie into the account that made the request.

The application binds these two dependencies once, over the stores it
supplies, and every protected route asks for them. Nothing here commits:
the session renewal and the audit record land in whatever transaction the
application's stores write into, and become durable only when the endpoint
commits it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Final
from urllib.parse import urlencode

from fastapi import Depends, HTTPException, Request
from starlette.responses import JSONResponse, Response

from webauth.config import WebAuthConfig, web_auth_config
from webauth.cookies import verify_session_cookie
from webauth.ports import (
    AuditSink,
    SessionIdentityChange,
    SessionIdentityChanged,
    SessionRecordStore,
)
from webauth.proxies import client_user_agent, resolve_client_ip

if TYPE_CHECKING:
    from collections.abc import Callable

    from webauth.ports import SessionCache, SessionRecord

log = logging.getLogger(__name__)

AUTHENTICATION_REQUIRED_DETAIL: Final = "Authentication required"
INVALID_SESSION_DETAIL: Final = "Invalid session"
SESSION_EXPIRED_DETAIL: Final = "Session expired"
ACCOUNT_DISABLED_DETAIL: Final = "Account disabled"
ADMIN_REQUIRED_DETAIL: Final = "Admin access required"

# A signed session cookie is an identifier plus a hex digest; anything much
# longer was not issued here, so it is rejected before any HMAC is computed.
MAX_SESSION_COOKIE_CHARS: Final = 200


@dataclass(frozen=True)
class AuthenticatedUser:
    """The account behind the current request."""

    id: str
    username: str
    role: str
    is_active: bool


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
        if not self.path.startswith("/") or self.path.startswith("//"):
            raise ValueError(
                "login_redirect.path must be a same-origin absolute path: "
                "one leading '/', never '//', and no scheme",
            )


@dataclass(frozen=True)
class AuthDependencies:
    """The route dependencies built from one set of stores.

    ``admin_user`` and ``verified_session_id`` resolve ``current_user``
    themselves, so an application that replaces one in a test replaces the
    identity behind all three.
    """

    current_user: Callable[..., AuthenticatedUser]
    admin_user: Callable[..., AuthenticatedUser]
    verified_session_id: Callable[..., str]


def current_user_dependency(
    *,
    session_store: Callable[..., SessionRecordStore],
    audit_sink: Callable[..., AuditSink],
    on_authenticated: Callable[[AuthenticatedUser], None],
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
    ) -> AuthenticatedUser:
        config = web_auth_config(request)
        session_id = _session_id_from_cookie(request, config, login_redirect)

        user = _authenticate_from_cache(request, audit, session_id, config, login_redirect)
        if user is None:
            user = _authenticate_from_store(
                request, sessions, audit, session_id, config, login_redirect,
            )
        on_authenticated(user)
        return user

    def admin_user(
        request: Request,
        user: AuthenticatedUser = Depends(current_user),
    ) -> AuthenticatedUser:
        if user.role != web_auth_config(request).admin_role:
            raise HTTPException(403, ADMIN_REQUIRED_DETAIL)
        return user

    def verified_session_id(
        request: Request,
        _account: AuthenticatedUser = Depends(current_user),
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
    exc = _unauthenticated(request, AUTHENTICATION_REQUIRED_DETAIL, login_redirect)
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
    if login_redirect is not None and _prefers_html(request):
        query = urlencode({login_redirect.redirect_query_param: _asked_for_address(request)})
        return HTTPException(302, headers={"Location": f"{login_redirect.path}?{query}"})
    return HTTPException(401, detail)


def _asked_for_address(request: Request) -> str:
    """The path and query the guarded request named, safe to echo back.

    A path starting with ``//`` reads as a scheme-relative address to a
    browser, so it collapses to ``/`` before it is ever carried in a redirect.
    """
    path = "/" if request.url.path.startswith("//") else request.url.path
    return f"{path}?{request.url.query}" if request.url.query else path


def _prefers_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    if not accept:
        return False
    return _accepted_quality(accept, "text/html") > _accepted_quality(accept, "application/json")


def _accepted_quality(accept_header: str, media_type: str) -> float:
    """The quality ``accept_header`` assigns ``media_type``: exact, wildcard, or 0.

    An entry naming ``media_type`` exactly wins outright; a type or ``*/*``
    wildcard sets the floor everything unnamed falls back to; a ``media_type``
    neither named nor covered by a wildcard is not accepted at all.
    """
    main_type, _, _ = media_type.partition("/")
    wildcard_quality = 0.0
    matched_wildcard = False
    for raw_entry in accept_header.split(","):
        entry = raw_entry.strip()
        if not entry:
            continue
        type_part, *params = entry.split(";")
        type_part = type_part.strip()
        quality = 1.0
        for param in params:
            name, _, value = param.strip().partition("=")
            if name.strip() == "q":
                try:
                    quality = float(value.strip())
                except ValueError:
                    quality = 1.0
        if type_part == media_type:
            return quality
        if type_part in (f"{main_type}/*", "*/*"):
            matched_wildcard = True
            wildcard_quality = max(wildcard_quality, quality)
    return wildcard_quality if matched_wildcard else 0.0


def _session_id_from_cookie(
    request: Request, config: WebAuthConfig, login_redirect: LoginRedirect | None,
) -> str:
    raw_cookie = request.cookies.get(config.session_cookie_name)
    if not raw_cookie or len(raw_cookie) > MAX_SESSION_COOKIE_CHARS:
        raise _unauthenticated(request, AUTHENTICATION_REQUIRED_DETAIL, login_redirect)
    session_id = verify_session_cookie(raw_cookie, config.signing_key)
    if session_id is None:
        raise _unauthenticated(request, INVALID_SESSION_DETAIL, login_redirect)
    return session_id


def _record_identity_changes(
    audit: AuditSink,
    *,
    session_id: str,
    user_id: str,
    stored_ip: str,
    stored_user_agent: str,
    current_ip: str,
    current_user_agent: str,
) -> bool:
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
                session_id=session_id,
                previous=stored_ip,
                current=current_ip,
            ),
        )
    if user_agent_changed:
        audit.session_identity_changed(
            SessionIdentityChanged(
                change=SessionIdentityChange.USER_AGENT,
                user_id=user_id,
                session_id=session_id,
                previous=stored_user_agent,
                current=current_user_agent,
            ),
        )
    return ip_changed or user_agent_changed


def _authenticate_from_cache(
    request: Request,
    audit: AuditSink,
    session_id: str,
    config: WebAuthConfig,
    login_redirect: LoginRedirect | None,
) -> AuthenticatedUser | None:
    """The cached account, or None when the cache cannot answer for it."""
    session_cache = config.session_cache
    if session_cache is None:
        return None

    try:
        cached = session_cache.get(session_id)
    except Exception:
        log.warning("Redis session cache read failed, falling back to DB")
        return None

    if cached is None:
        return None

    now = datetime.now(timezone.utc)
    if not config.session_liveness.admits_cached_session(cached, now):
        raise _unauthenticated(request, SESSION_EXPIRED_DETAIL, login_redirect)

    if not cached.is_active:
        raise HTTPException(403, ACCOUNT_DISABLED_DETAIL)

    current_ip = resolve_client_ip(request)
    current_user_agent = client_user_agent(request)

    identity_changed = _record_identity_changes(
        audit,
        session_id=session_id,
        user_id=cached.user_id,
        stored_ip=cached.ip_address,
        stored_user_agent=cached.user_agent,
        current_ip=current_ip,
        current_user_agent=current_user_agent,
    )

    try:
        session_cache.refresh_ttl(session_id, config.session_max_age_seconds)
        if identity_changed:
            session_cache.update_ip_ua(session_id, current_ip, current_user_agent)
    except Exception:
        log.warning("Redis session cache write failed")

    return AuthenticatedUser(
        id=cached.user_id,
        username=cached.username,
        role=cached.role,
        is_active=cached.is_active,
    )


def _authenticate_from_store(
    request: Request,
    sessions: SessionRecordStore,
    audit: AuditSink,
    session_id: str,
    config: WebAuthConfig,
    login_redirect: LoginRedirect | None,
) -> AuthenticatedUser:
    record = sessions.load(session_id)
    now = datetime.now(timezone.utc)
    if record is None or not config.session_liveness.admits_stored_session(record, now):
        raise _unauthenticated(request, SESSION_EXPIRED_DETAIL, login_redirect)

    if not record.user.is_active:
        raise HTTPException(403, ACCOUNT_DISABLED_DETAIL)

    current_ip = resolve_client_ip(request)
    current_user_agent = client_user_agent(request)

    _record_identity_changes(
        audit,
        session_id=session_id,
        user_id=record.user.id,
        stored_ip=record.ip_address,
        stored_user_agent=record.user_agent,
        current_ip=current_ip,
        current_user_agent=current_user_agent,
    )
    sessions.touch(
        record,
        ip_address=current_ip,
        user_agent=current_user_agent,
        now=now,
    )

    _populate_cache(config.session_cache, record, config)

    return AuthenticatedUser(
        id=record.user.id,
        username=record.user.username,
        role=record.user.role,
        is_active=record.user.is_active,
    )


def _populate_cache(
    session_cache: SessionCache | None, record: SessionRecord, config: WebAuthConfig,
) -> None:
    if session_cache is None:
        return
    try:
        session_cache.store(
            record.id, record.user.id, record.user.username,
            record.user.role, record.user.is_active,
            record.ip_address, record.user_agent,
            record.expires_at, record.created_at,
            config.session_max_age_seconds,
        )
    except Exception:
        log.warning("Redis session cache populate failed")
