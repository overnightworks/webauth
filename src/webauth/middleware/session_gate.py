"""The session gate: every route needs a live session, except the host's public paths."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING

from anyio import to_thread
from anyio.lowlevel import checkpoint_if_cancelled
from starlette.requests import HTTPConnection

from webauth._paths import _has_dot_segment
from webauth.config import WebAuthConfig, web_auth_config
from webauth.dependencies import (
    ConnectionRefusal,
    LoginRedirect,
    _bearer_admission,
    _gate_admission,
    _GateAdmission,
    _is_bearer_admitted,
    _read_session_cookie,
    _record_gate_admission,
    _refusal_response,
    admit_session,
)
from webauth.middleware._refusal import RefusalMiddleware
from webauth.policies import PathRules, PublicRule

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import Scope

    from webauth.ports import AuthenticatedUser, SessionTransaction

__all__ = [
    "SessionGate",
    "SessionGateMiddleware",
    "admitted_user",
]


@dataclass(frozen=True)
class SessionGate:
    """Which requests need no session, and where the gate admits the others.

    Every request needs a live session unless a ``public`` rule names it;
    an ``optional`` path admits a live session and lets every other request
    through. Paths are the router's: ``root_path`` stripped at a segment boundary
    (under ``/app``, ``/app/x`` is ``/x`` but ``/apple`` stays ``/apple``),
    written as the routes are; the other policies' rules are the decoded ASGI
    path (``PathRules``), so a host under a ``root_path`` keeps each rule in its
    own convention. A request the bearer gate admitted passes untouched: the gate
    reads no cookie and opens no ``session_transaction`` for it. A path with a ``.``
    or ``..`` segment
    is never public or optional. WebSocket and lifespan scopes pass; ``authenticate_websocket``
    decides a handshake.

    The gate calls ``session_transaction`` once per request that carries a
    validly signed session cookie on a gated or optional path, never on a public
    path and never without such a cookie. The admission (``load``, then
    ``touch``) runs inside it, and the block is left before the route runs, so
    the renewal is durable then. An exception, or a failing exit, answers the
    library 500 without running the route, on an optional path too.

    The admission vouches for one request. Host code that carries it into
    another request with the same cookie carries that request's decision along;
    the library does not defend against it.
    """

    session_transaction: SessionTransaction
    login_redirect: LoginRedirect | None
    public: tuple[PublicRule, ...]
    optional: PathRules = PathRules()


class SessionGateMiddleware(RefusalMiddleware[SessionGate]):
    """Refuse a request without a live session, and record who the others are.

    The decision is recorded for the request, so ``current_user`` and its
    dependants return it instead of admitting the session a second time.
    """

    async def _refusal(self, request: Request) -> Response | None:
        if _bearer_admission(request) is not None:
            return None
        config = web_auth_config(request)
        reading = _read_session_cookie(request, config)
        route_path = _route_path(request.scope)
        if self._is_public(route_path, request.method):
            _record_gate_admission(request, _GateAdmission(config, reading, None))
            return None
        optional = self._is_optional(route_path)
        if isinstance(reading, ConnectionRefusal):
            return self._refused_or_passed(request, config, reading, reading, optional)
        try:
            admission = await to_thread.run_sync(partial(self._admit, reading, config))
        finally:
            await checkpoint_if_cancelled()
        return self._refused_or_passed(request, config, reading, admission, optional)

    def _refused_or_passed(
        self,
        request: Request,
        config: WebAuthConfig,
        reading: str | ConnectionRefusal,
        admission: AuthenticatedUser | ConnectionRefusal,
        optional: bool,
    ) -> Response | None:
        if isinstance(admission, ConnectionRefusal) and not optional:
            return _refusal_response(request, admission, self._policy.login_redirect)
        _record_gate_admission(request, _GateAdmission(config, reading, admission))
        return None

    def _admit(
        self, session_id: str, config: WebAuthConfig,
    ) -> AuthenticatedUser | ConnectionRefusal:
        with self._policy.session_transaction() as sessions:
            return admit_session(session_id, sessions=sessions, config=config)

    def _is_public(self, route_path: str, method: str) -> bool:
        return not _has_dot_segment(route_path) and any(
            rule.applies_to(route_path, method) for rule in self._policy.public
        )

    def _is_optional(self, route_path: str) -> bool:
        return not _has_dot_segment(route_path) and self._policy.optional.matches(route_path)


def admitted_user(connection: HTTPConnection) -> AuthenticatedUser | None:
    """The account the session gate admitted for this request, or ``None``.

    ``None`` on a public path, and on an optional path without a live session.
    ``None`` on a request the bearer gate admitted. Raises ``RuntimeError`` when
    no gate decided this request: the gate is not installed, the connection is a
    WebSocket, the route runs under another ``WebAuthConfig`` instance, or the
    decision was made for another session cookie. A forgotten gate never reads as
    signed out. For the session id use
    ``session_id_from_request``. The account is this request's own: a host must
    not hand it to another request.
    """
    if _is_bearer_admitted(connection):
        return None
    decided = _gate_admission(connection)
    if decided is None:
        raise RuntimeError(
            "The session gate made no decision for this request: install it with "
            "install_web_auth_middleware(session_gate=...) on the app that serves the route.",
        )
    return None if isinstance(decided.admission, ConnectionRefusal | None) else decided.admission


def _route_path(scope: Scope) -> str:
    """The path the app's router matches: ``root_path`` stripped at a segment boundary."""
    path: str = scope["path"]
    root_path: str = scope.get("root_path", "")
    if not root_path or not path.startswith(root_path):
        return path
    if path == root_path:
        return ""
    return path[len(root_path):] if path[len(root_path)] == "/" else path
