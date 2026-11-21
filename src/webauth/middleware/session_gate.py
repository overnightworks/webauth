"""The session gate: every route needs a live session, except the host's public paths."""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING

from logline import set_sub
from starlette.requests import HTTPConnection

from webauth._bearer_admission import (
    AUTHENTICATION_REQUIRED_DETAIL,
    admitted_token_person,
    bearer_admission,
    require_admin,
    unauthenticated_without_redirect,
)
from webauth._paths import _has_dot_segment
from webauth._worker import on_worker
from webauth.config import WebAuthConfig, web_auth_config
from webauth.dependencies import (
    ConnectionRefusal,
    LoginRedirect,
    _gate_admission,
    _GateAdmission,
    _read_session_cookie,
    _record_gate_admission,
    _refusal_response,
    admit_session,
)
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path
from webauth.policies import PathRules, PublicRule
from webauth.ports import AuthenticatedUser, BearerCaller

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.types import ASGIApp

    from webauth.ports import SessionTransaction

__all__ = [
    "SessionGate",
    "admitted_admin",
    "admitted_user",
]


@dataclass(frozen=True)
class SessionGate:
    """Which requests need no session, and where the gate admits the others.

    Every request needs a live session unless a ``public`` rule names it;
    an ``optional`` path admits a live session and lets every other request
    through. Its paths are written as ``PathRules`` says. A request the bearer gate
    admitted passes untouched: the gate reads no cookie and opens no
    ``stores.sessions`` entry for it. A path with a ``.`` or ``..`` segment is never
    public or optional. WebSocket and lifespan scopes pass; ``authenticate_websocket``
    decides a handshake.

    The gate enters the ``stores.sessions`` of its ``WebAuth`` once per request that carries a
    validly signed session cookie on a gated or optional path, never on a public
    path and never without such a cookie. The admission (``load``, then
    ``touch``) runs inside it, and the block is left before the route runs, so
    the renewal is durable then. An exception, or a failing exit, answers the
    library 500 without running the route, on an optional path too.

    The admission vouches for one request. Host code that carries it into
    another request with the same cookie carries that request's decision along;
    the library does not defend against it.
    """

    login_redirect: LoginRedirect | None
    public: tuple[PublicRule, ...]
    optional: PathRules = PathRules()


class _SessionGateMiddleware(RefusalMiddleware[SessionGate]):
    """Refuse a request without a live session, and record who the others are.

    The decision is recorded for the request, so ``current_user`` and its
    dependants return it instead of admitting the session a second time. The admitted
    account's ``id`` goes on the request line as its ``sub``.
    """

    def __init__(
        self,
        app: ASGIApp,
        policy: SessionGate,
        *,
        session_transaction: SessionTransaction,
    ) -> None:
        super().__init__(app, policy)
        self._session_transaction = session_transaction

    async def _refusal(self, request: Request) -> Response | None:
        if bearer_admission(request) is not None:
            return None
        config = web_auth_config(request)
        reading = _read_session_cookie(request, config)
        routed_path = route_path(request.scope)
        if self._is_public(routed_path, request.method):
            _record_gate_admission(request, _GateAdmission(config, reading, None))
            return None
        optional = self._is_optional(routed_path)
        if isinstance(reading, ConnectionRefusal):
            return self._refused_or_passed(request, config, reading, reading, optional)
        admission = await on_worker(partial(self._admit, reading, config))
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
        if isinstance(admission, AuthenticatedUser):
            set_sub(request.scope, admission.id)
        return None

    def _admit(
        self,
        session_id: str,
        config: WebAuthConfig,
    ) -> AuthenticatedUser | ConnectionRefusal:
        with self._session_transaction() as sessions:
            return admit_session(session_id, sessions=sessions, config=config)

    def _is_public(self, routed_path: str, method: str) -> bool:
        return not _has_dot_segment(routed_path) and any(
            rule.applies_to(routed_path, method) for rule in self._policy.public
        )

    def _is_optional(self, routed_path: str) -> bool:
        return not _has_dot_segment(routed_path) and self._policy.optional.matches(routed_path)


def admitted_user(connection: HTTPConnection) -> AuthenticatedUser | None:
    """The account the session gate admitted for this request, or ``None``.

    ``None`` on a public path, and on an optional path without a live session.
    On a person path of the bearer gate it is the account behind the token, for the
    request the gate admitted it for; at a protected resource's entry point or marked route it
    is the capped person; ``None`` on a machine path. Raises
    ``RuntimeError`` for a bearer admission that does not hold for this request, and
    when no gate decided this request: the gate is not installed, the connection is a
    WebSocket, the route runs under another ``WebAuthConfig`` instance, or the
    decision was made for another session cookie. A forgotten gate never reads as
    signed out. For the session id use ``session_id_from_request``. The account is
    this request's own: a host must not hand it to another request.
    """
    admission = bearer_admission(connection)
    if admission is not None and isinstance(admission.principal, BearerCaller):
        return None
    person = admitted_token_person(connection)
    if person is not None:
        return person
    decided = _gate_admission(connection)
    if decided is None:
        raise RuntimeError(
            "The session gate made no decision for this request: install it with "
            "WebAuth.install on the app that serves the route, built with a session gate.",
        )
    return None if isinstance(decided.admission, ConnectionRefusal | None) else decided.admission


def admitted_admin(connection: HTTPConnection) -> AuthenticatedUser:
    """The admin account the session gate admitted for this request.

    Answers 403 ``Admin access required`` for an admitted account of another role,
    as ``admin_user`` does, and 401 ``Authentication required`` where the gate
    admitted no account (a public path, or an optional path without a live
    session); it never redirects and never admits a session by itself. A
    ``Depends(current_user)`` that admits the cookie on a public path does not
    change the gate's record, so the answer there stays 401. The token person of a
    person path is admitted as an admin or answered 403 ``Admin access required``
    with ``Bearer error="insufficient_scope"``; a protected resource's capped person is
    answered the same 403 without a challenge. Raises
    ``RuntimeError`` as ``admitted_user`` does where no gate decided this request,
    and on a machine admission: a machine route takes ``Depends(bearer_caller)``.
    Usable as ``Depends(admitted_admin)``.
    """
    person = admitted_token_person(connection)
    if person is not None:
        return require_admin(connection, person)
    user = admitted_user(connection)
    if user is None:
        raise unauthenticated_without_redirect(connection, AUTHENTICATION_REQUIRED_DETAIL)
    return require_admin(connection, user)
