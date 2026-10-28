"""The start, callback and logout routes of signing in through an OpenID Connect issuer.

``install_sign_in_routes`` registers the routes on the host's ``FastAPI`` app,
and ``SignInPaths`` derives the policies the host's gate, rate limit and cache
rules need for exactly those paths, so the host lists them once. The routes are
synchronous and run in the threadpool; configuration comes from the installed
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
transaction or in the host's callables answers the middleware's plain 500: no page is
sent and no cookie is cleared. Under a host whose transaction rolls back, the session
stands and a retry ends it with its hint; under per-call persistence or an uncertain
commit, the row and its ID token may already be gone, and a retry still reaches the
issuer's end-session page, without the hint.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

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
    _decide_admission,
    _log_out,
    _start_login,
    _UsernameTakenSignal,
    _write_sign_in,
)
from webauth.policies import CacheControlRule, PathRules, PublicRule

if TYPE_CHECKING:
    from collections.abc import Callable

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
    ``logout`` is ``None`` for a host that serves no logout route. The derived values are
    the policies for exactly these paths.
    """

    start: str
    callback: str
    logout: str | None = None

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
        ``SessionGate.public``: ``GET`` of the start and callback paths and, when
        there is one, ``POST`` of the logout path."""
        rules = (PublicRule(self._sign_in, methods=frozenset({"GET"})),)
        if self.logout is None:
            return rules
        logout = PathRules(exact=frozenset({self.logout}))
        return (*rules, PublicRule(logout, methods=frozenset({"POST"})))

    @property
    def browser_paths(self) -> PathRules:
        """The paths a browser reaches the sign-in with, for the sign-in rate budget."""
        return self._exact

    @property
    def cache_control_rule(self) -> CacheControlRule:
        """``no-store`` for every path: the answers carry cookies."""
        return CacheControlRule(self._exact, "no-store")

    @property
    def login_redirect(self) -> LoginRedirect:
        """Send a signed-out browser to the start route, carrying the address it asked for.

        The path is browser-absolute, so it is right for an app at its origin's root; a
        host below a ``root_path`` builds its own ``LoginRedirect``."""
        return LoginRedirect(self.start, _RETURN_PATH_QUERY_NAME)

    @property
    def _named_paths(self) -> tuple[tuple[str, str], ...]:
        named = (("start", self.start), ("callback", self.callback))
        return named if self.logout is None else (*named, ("logout", self.logout))

    @property
    def _sign_in(self) -> PathRules:
        return PathRules(exact=frozenset({self.start, self.callback}))

    @property
    def _exact(self) -> PathRules:
        return PathRules(exact=frozenset(path for _, path in self._named_paths))


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
) -> None:
    """Register the start and callback routes of the sign-in, and the logout route, on ``app``.

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
    ends the issuer's; ``logout_button_label`` is read per request, the text of the button
    shown where no script runs.

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
    routes = _SignIn(relying_party, admission, transaction, refused, keeps_id_token, max_sessions)

    _register_routes(app, paths, routes, logout_button_label)


def _register_routes(
    app: FastAPI,
    paths: SignInPaths,
    routes: _SignIn,
    logout_button_label: Callable[[Request], str] | None,
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
            return _RouteAnswer(Response(), failure)

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
            return _RouteAnswer(carrier, failure)
        return _RouteAnswer(carrier, answer)

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


class _RouteAnswer(Response):
    """A route's answer: ``outcome`` carrying the ``Set-Cookie`` headers of ``carrier``.
    A failure as the ``outcome``, or an answer that raises before it starts, is sent as a plain
    500 with those headers and then raised, so no framework exception handler answers instead."""

    def __init__(self, carrier: Response, outcome: Response | Exception) -> None:
        super().__init__()
        self._cookies = [header for header in carrier.raw_headers if header[0] == _SET_COOKIE]
        self._outcome = outcome

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if isinstance(self._outcome, Exception):
            await self._send_server_error(scope, receive, send)
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
            await self._send_server_error(scope, receive, send)
            raise

    async def _send_server_error(self, scope: Scope, receive: Receive, send: Send) -> None:
        answer = Response("Internal Server Error", status_code=500, media_type="text/plain")
        answer.raw_headers.extend(self._cookies)
        await answer(scope, receive, send)
