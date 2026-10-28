"""The start, callback, logout and back-channel logout routes of signing in through an
OpenID Connect issuer.

``install_sign_in_routes`` registers the routes on the host's ``FastAPI`` app,
and ``SignInPaths`` derives the policies the host's gate, rate limit, body-size, CSRF and
cache rules need for exactly those paths, so the host lists them once. The start, callback and
logout routes are synchronous and run in the threadpool; the back-channel route reads its body
on the event loop and then makes one worker-thread call. Configuration comes from the installed
``WebAuthConfig``, and the library adds no middleware and logs nothing.

The callback exchanges the code and verifies the ID token outside any
transaction, decides admission without writing, and then enters one
``SignInTransaction`` for the account and the session. The session cookie is
issued only after that transaction's exit returned.

The logout route ends the session the request's cookie names, reading its ID token before
deleting the row, and answers a ``no-store`` HTML page under its own Content-Security-Policy
that posts the client ID, the configured ``post_logout_redirect_uri`` and the ID token hint to
the end-session endpoint, submits itself and clears the session cookie. An expired row that
still stands is read too, and neither renewed nor admitted. The page needs no outbound call,
so the person is signed out of the app even when the issuer is down. A request without a
usable session, or whose row holds no ID token (stored before the host held them, or opened
with ``keeps_id_token=False``), still reaches the issuer, which asks the person once. The
session's stored refresh token goes to the issuer nowhere, and the security-headers
middleware leaves the page's policy and ``Cache-Control`` in place, so no host policy needs a
source for the issuer.

The logout route answers ``POST`` only, and the origin check protects it: it
runs on mutating methods alone, so the host never lists the path in
``CsrfPolicy.exempt``. A single-page app logs out by a top-level form ``POST`` to
the route. The route needs no ``current_user`` dependency, so a request without a
session still reaches the issuer. It enters one ``SignInTransaction``, only when the
request's cookie names a session, and never commits. A failure in the route, in the
transaction or in the host's callables answers the route's plain 500: no page is
sent and no cookie is cleared. Under a host whose transaction rolls back, the session
stands and a retry ends it with its hint; under per-call persistence or an uncertain
commit, the row and its ID token may already be gone, and a retry still reaches the
issuer's end-session page, without the hint.

The back-channel route is the issuer's back-channel logout, registered for ``POST`` only. The
issuer posts one URL-encoded form with one non-empty ``logout_token`` when a person's session
at the issuer ends. The route answers in this order:

1. A declared ``Content-Length`` over ``SignInPaths.backchannel_body_size_rule`` gets 413 from
   the body-size middleware before any dependency runs.
2. ``backchannel_dependencies`` run before the body is read. A host answers an empty 404 by
   raising its own exception class and mapping it with
   ``app.add_exception_handler(ThatError, lambda request, error: Response(status_code=404))``:
   an ``HTTPException(404)`` answers JSON, and a ``Response`` returned from a dependency does
   not stop the endpoint.
3. The body is read outside every catch, so a streamed oversized body gets 413.
4. A request that is not one form with exactly one non-empty ``logout_token``, or whose token
   does not verify, gets an empty 400. The token is verified before the transaction, so a
   refusal enters none.
5. 200 only after a clean exit of the one ``SignInTransaction`` entry, in which a subject
   with an account loses every session in every browser and one ``BACKCHANNEL_LOGOUT`` event
   with ``actor_id=None`` is recorded when at least one session ended. A subject without an
   account is accepted and provisions nothing. The route clears no cookie and calls no
   issuer endpoint beyond the key fetch of verification.
6. Any exception in ``relying_party``, the verification, a store, the audit sink or the exit
   gets an empty 400 and is then re-raised.

The host's transaction rolls back when the block raises, also when the audit sink fails after
the deletion, and commits only for an accepted token. A per-call host keeps the sessions
ended before the failure and emits no event again. ``relying_party`` receives the back-channel
request with the Host the issuer posted to, often an internal alias.

The route is open to anyone who can reach it, and the token is its only control: the host lets
the issuer reach it over an internal network alone, never the public route (tunnel, CDN,
access proxy). Only the exact path is exempt from the origin check and the rate limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import TYPE_CHECKING

import anyio.to_thread
from fastapi import FastAPI, Request  # noqa: TC002  # FastAPI reads the annotation at runtime
from starlette.responses import RedirectResponse, Response

from webauth._paths import _has_dot_segment, reads_as_another_host, same_app_path
from webauth._validation import require_positive_whole_number
from webauth.config import WebAuthConfig, web_auth_config
from webauth.cookies import _take_pending_login, issue_session_cookies
from webauth.dependencies import LoginRedirect, session_id_from_request
from webauth.oidc import OidcRefusal, OidcRefusalReason, _callback_state
from webauth.oidc_login import (
    AdmissionConfig,
    AdmissionRefusal,
    _AdmittedLogin,
    _BackchannelLogoutResult,
    _decide_admission,
    _log_out,
    _receive_backchannel_logout,
    _start_login,
    _UsernameTakenSignal,
    _write_sign_in,
)
from webauth.policies import BodySizeRule, CacheControlRule, PathRules, PublicRule

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from fastapi import params
    from starlette.types import Message, Receive, Scope, Send

    from webauth.cookies import PendingLogin
    from webauth.oidc import OidcRelyingParty
    from webauth.ports import SignInTransaction

__all__ = [
    "RefusalPage",
    "SignInPaths",
    "SignInRefusal",
    "install_sign_in_routes",
]

_RETURN_PATH_QUERY_NAME = "next"
_SET_COOKIE = b"set-cookie"
_BACKCHANNEL_MAX_BODY_BYTES = 32 * 1024


class RefusalPage(StrEnum):
    """Which of the host's two pages a refused sign-in shows."""

    NO_ACCESS = "no-access"
    LOGIN_FAILED = "login-failed"


@dataclass(frozen=True)
class SignInRefusal:
    """Why a sign-in ended without a session: no identity and no tokens, only the cause."""

    cause: OidcRefusal | AdmissionRefusal

    @property
    def page(self) -> RefusalPage:
        """``NO_ACCESS`` for a person who is not a member of the app; ``LOGIN_FAILED`` for
        every other cause, the setup errors (``FOREIGN_ISSUER``, ``USERNAME_TAKEN``) included."""
        if self.cause is AdmissionRefusal.NOT_A_MEMBER:
            return RefusalPage.NO_ACCESS
        return RefusalPage.LOGIN_FAILED


@dataclass(frozen=True)
class SignInPaths:
    """Where the sign-in routes live, mount-relative like every webauth policy path.

    Every path must be absolute, name nothing a browser reads as another host, hold no
    dot segment, ``?`` or ``#``, and differ from the others; ``ValueError`` at
    construction, before any route is registered, names the first that is not.
    ``logout`` is ``None`` for a host that serves no logout route, and
    ``backchannel_logout`` for one that serves no back-channel logout route. The derived
    values are the policies for exactly these paths.
    """

    start: str
    callback: str
    logout: str | None = None
    backchannel_logout: str | None = None

    def __post_init__(self) -> None:
        for name, path in self._named_paths:
            _require_sign_in_path(name, path)
        paths = [path for _, path in self._named_paths]
        if len(set(paths)) != len(paths):
            names = ", ".join(f"SignInPaths.{name}" for name, _ in self._named_paths)
            raise ValueError(f"{names} must differ")

    @property
    def public_rules(self) -> tuple[PublicRule, ...]:
        """The rules that let a browser without a session reach the routes, for
        ``SessionGate.public``: ``GET`` of the start and callback paths and ``POST`` of the
        logout and back-channel logout paths, when there are any. The logout token, not a
        session, authenticates the back-channel."""
        rules = (PublicRule(self._sign_in, methods=frozenset({"GET"})),)
        posted = {path for path in (self.logout, self.backchannel_logout) if path is not None}
        if not posted:
            return rules
        return (*rules, PublicRule(PathRules(exact=frozenset(posted)), methods=frozenset({"POST"})))

    @property
    def browser_paths(self) -> PathRules:
        """The paths a browser reaches the sign-in with, for the sign-in rate budget: the
        back-channel, which the issuer posts to, is not one."""
        return PathRules(exact=frozenset(
            path for name, path in self._named_paths if name != "backchannel_logout"
        ))

    @property
    def backchannel(self) -> PathRules:
        """The exact back-channel logout path, for ``CsrfPolicy.exempt`` and
        ``RateLimitPolicy.exempt``: the issuer sends neither an Origin nor a cookie and posts
        from shared server addresses. It exempts nothing when there is no such path, and
        logout is never exempt."""
        return PathRules(exact=frozenset(
            () if self.backchannel_logout is None else (self.backchannel_logout,),
        ))

    @property
    def backchannel_body_size_rule(self) -> BodySizeRule:
        """A bound of 32 KiB for ``POST`` of the back-channel path, which admits a Logout
        Token where a host's default may not."""
        return BodySizeRule(
            self.backchannel, _BACKCHANNEL_MAX_BODY_BYTES, methods=frozenset({"POST"}),
        )

    @property
    def cache_control_rule(self) -> CacheControlRule:
        """``no-store`` for every path: the answers carry cookies, or are the issuer's."""
        return CacheControlRule(
            PathRules(exact=frozenset(path for _, path in self._named_paths)), "no-store",
        )

    @property
    def login_redirect(self) -> LoginRedirect:
        """Send a signed-out browser to the start route, carrying the address it asked for.

        The path is browser-absolute, so it is right for an app at its origin's root; a
        host below a ``root_path`` builds its own ``LoginRedirect``."""
        return LoginRedirect(self.start, _RETURN_PATH_QUERY_NAME)

    @property
    def _named_paths(self) -> tuple[tuple[str, str], ...]:
        optional = (("logout", self.logout), ("backchannel_logout", self.backchannel_logout))
        return (
            ("start", self.start), ("callback", self.callback),
            *((name, path) for name, path in optional if path is not None),
        )

    @property
    def _sign_in(self) -> PathRules:
        return PathRules(exact=frozenset({self.start, self.callback}))


def _require_sign_in_path(name: str, path: str) -> None:
    problem = _problem_with(path)
    if problem is not None:
        raise ValueError(f"SignInPaths.{name} {problem}: {path!r}")


def _problem_with(path: object) -> str | None:
    if not isinstance(path, str) or not path.startswith("/"):
        return "must be an absolute path"
    if reads_as_another_host(path):
        return "must not read as another host"
    if "?" in path or "#" in path:
        return "must not hold a query or a fragment"
    if _has_dot_segment(path):
        return "must not hold a dot segment"
    return None


def install_sign_in_routes(
    app: FastAPI,
    *,
    paths: SignInPaths,
    relying_party: Callable[[Request], OidcRelyingParty],
    admission: AdmissionConfig,
    transaction: SignInTransaction,
    refused: Callable[[Request, SignInRefusal], Response],
    keeps_id_token: bool,
    max_sessions: int | None,
    logout_button_label: Callable[[Request], str] | None,
    backchannel_dependencies: Sequence[params.Depends] = (),
) -> None:
    """Register the start and callback routes of the sign-in, the logout route and the
    back-channel logout route on ``app``.

    The start route stores the pending login in its own signed cookie, with the
    ``next`` query value as the path to return to, and redirects (303) to the issuer. The
    callback clears exactly the pending cookie its state names and, once the transaction's
    exit returned, answers 303 to that return path, or to the app root when there is none,
    with the session cookie. Every other answer is the host's ``refused`` hook's, which
    receives the cause and returns any ``Response``. Every callback answer sent after the
    pending cookie was selected carries its deletion, also the hook's, the 500 of a failure
    in the hook or in the transaction, and an answer that fails before it starts; a failure
    is then re-raised once that 500 is sent. Nothing is sent after an answer has started.

    A callback names a usable state when it carries ``state`` exactly once,
    non-empty and decodable. Every refusal below comes before any token
    request. With a usable state, a malformed rest (a parameter named twice,
    one that does not decode, or a pair strict query parsing refuses, such as a
    trailing ``&`` or a name without ``=``) is refused to the hook as
    ``MALFORMED_CALLBACK`` when that state's cookie is genuine and
    ``STATE_MISMATCH`` otherwise. Without one, the same malformed rest is
    ``MALFORMED_CALLBACK`` and anything else ``STATE_MISMATCH``. A well-formed
    callback whose cookie is missing, forged, oversized, of an unknown version,
    duplicated or of another login is ``STATE_MISMATCH``.

    The logout route ends the session the request's cookie names and answers the page that
    ends the issuer's; ``logout_button_label`` is read per request.

    ``backchannel_dependencies`` need ``paths.backchannel_logout``, or ``ValueError`` is raised
    before a route is registered. The module docstring holds the back-channel's answers.

    ``relying_party`` is read per request. ``keeps_id_token`` has no default: ``True`` stores
    the login's ID token so the logout posts it as the hint, ``False`` stores none.
    ``max_sessions`` is ``None`` for no cap, otherwise a positive whole number or ``ValueError``
    is raised before a route is registered. ``paths.logout`` and ``logout_button_label`` come
    together: a host without a logout route passes ``None`` for both, and exactly one of them
    raises ``ValueError`` before a route is registered.
    """
    if max_sessions is not None:
        require_positive_whole_number("max_sessions", max_sessions, unit="sessions")
    if (paths.logout is None) != (logout_button_label is None):
        raise ValueError("paths.logout and logout_button_label must both be given or both be None")
    if backchannel_dependencies and paths.backchannel_logout is None:
        raise ValueError("backchannel_dependencies need paths.backchannel_logout")
    routes = _SignIn(relying_party, admission, transaction, refused, keeps_id_token, max_sessions)

    _register_routes(app, paths, routes, logout_button_label, backchannel_dependencies)


def _register_routes(
    app: FastAPI,
    paths: SignInPaths,
    routes: _SignIn,
    logout_button_label: Callable[[Request], str] | None,
    backchannel_dependencies: Sequence[params.Depends],
) -> None:
    def start(request: Request, next: str | None = None) -> Response:  # noqa: A002
        return routes.start(request, next)

    def callback(request: Request) -> Response:
        return routes.callback(request)

    app.add_api_route(paths.start, start, methods=["GET"], include_in_schema=False)
    app.add_api_route(paths.callback, callback, methods=["GET"], include_in_schema=False)
    if paths.logout is not None and logout_button_label is not None:
        button_label = logout_button_label

        def logout(request: Request) -> Response:
            return routes.logout(request, button_label)

        app.add_api_route(paths.logout, logout, methods=["POST"], include_in_schema=False)
    if paths.backchannel_logout is not None:

        async def backchannel_logout(request: Request) -> Response:
            return await routes.backchannel_logout(request)

        app.add_api_route(
            paths.backchannel_logout, backchannel_logout, methods=["POST"],
            dependencies=list(backchannel_dependencies), include_in_schema=False,
        )


@dataclass(frozen=True)
class _SignIn:
    relying_party: Callable[[Request], OidcRelyingParty]
    admission: AdmissionConfig
    transaction: SignInTransaction
    refused: Callable[[Request, SignInRefusal], Response]
    keeps_id_token: bool
    max_sessions: int | None

    def start(self, request: Request, return_to: str | None) -> Response:
        answer = Response(status_code=303)
        answer.headers["location"] = _start_login(
            self.relying_party(request), request, answer, web_auth_config(request),
            return_to=return_to,
        )
        return answer

    def logout(self, request: Request, button_label: Callable[[Request], str]) -> Response:
        try:
            return _log_out(
                self.relying_party(request), request, web_auth_config(request),
                transaction=self.transaction, button_label=button_label(request),
            )
        except Exception as failure:
            return _RouteAnswer(Response(), failure, _plain_server_error)

    async def backchannel_logout(self, request: Request) -> Response:
        form_body = await request.body()
        try:
            relying_party = self.relying_party(request)
            result = await anyio.to_thread.run_sync(partial(
                _receive_backchannel_logout, relying_party, form_body,
                request.headers.get("content-type"), transaction=self.transaction,
            ))
        except Exception as failure:
            return _RouteAnswer(Response(), failure, _empty_bad_request)
        if result is _BackchannelLogoutResult.ACCEPTED:
            return Response()
        return _empty_bad_request()

    def callback(self, request: Request) -> Response:
        config = web_auth_config(request)
        state = _callback_state(request.url.query)
        if isinstance(state, OidcRefusal):
            return self._refuse(request, state)
        carrier = Response()
        pending = _take_pending_login(request, carrier, state, config)
        try:
            answer = self._answer(request, config, pending)
        except Exception as failure:
            return _RouteAnswer(carrier, failure, _plain_server_error)
        return _RouteAnswer(carrier, answer, _plain_server_error)

    def _answer(
        self, request: Request, config: WebAuthConfig, pending: PendingLogin | None,
    ) -> Response:
        if pending is None:
            return self._refuse(request, OidcRefusal(OidcRefusalReason.STATE_MISMATCH))
        identity = self.relying_party(request).complete_login(pending, request.url.query)
        if isinstance(identity, OidcRefusal):
            return self._refuse(request, identity)
        admitted = _decide_admission(identity, admission=self.admission, config=config)
        if isinstance(admitted, AdmissionRefusal):
            return self._refuse(request, admitted)
        replaced_session_id = session_id_from_request(request, config)
        try:
            session_id = self._write(admitted, config, replaced_session_id)
        except _UsernameTakenSignal:
            return self._refuse(request, AdmissionRefusal.USERNAME_TAKEN)
        answer = RedirectResponse(
            same_app_path(request, pending.return_to) or _app_root(request), status_code=303,
        )
        issue_session_cookies(answer, session_id, config)
        return answer

    def _write(
        self, admitted: _AdmittedLogin, config: WebAuthConfig, replaced_session_id: str | None,
    ) -> str:
        with self.transaction() as stores:
            return _write_sign_in(
                stores, admitted,
                config=config,
                replaced_session_id=replaced_session_id,
                max_sessions=self.max_sessions,
                keeps_id_token=self.keeps_id_token,
            )

    def _refuse(self, request: Request, cause: OidcRefusal | AdmissionRefusal) -> Response:
        return self.refused(request, SignInRefusal(cause))


def _app_root(request: Request) -> str:
    return request.scope.get("root_path", "").rstrip("/") + "/"


def _plain_server_error() -> Response:
    return Response("Internal Server Error", status_code=500, media_type="text/plain")


def _empty_bad_request() -> Response:
    return Response(status_code=400)


class _RouteAnswer(Response):
    """A route's answer: ``outcome`` carrying the ``Set-Cookie`` headers of ``carrier``.
    A failure as the ``outcome``, or an answer that raises before it starts, is sent as the
    route's ``failure_answer`` with those headers and then raised, so no framework exception
    handler answers instead."""

    def __init__(
        self, carrier: Response, outcome: Response | Exception,
        failure_answer: Callable[[], Response],
    ) -> None:
        super().__init__()
        self._cookies = [header for header in carrier.raw_headers if header[0] == _SET_COOKIE]
        self._outcome = outcome
        self._failure_answer = failure_answer

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if isinstance(self._outcome, Exception):
            await self._send_failure_answer(scope, receive, send)
            raise self._outcome
        started = False

        async def send_with_cookies(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                message = {**message, "headers": [*message["headers"], *self._cookies]}
            await send(message)

        try:
            await self._outcome(scope, receive, send_with_cookies)
        except Exception:
            if started:
                raise
            await self._send_failure_answer(scope, receive, send)
            raise

    async def _send_failure_answer(self, scope: Scope, receive: Receive, send: Send) -> None:
        answer = self._failure_answer()
        answer.raw_headers.extend(self._cookies)
        await answer(scope, receive, send)
