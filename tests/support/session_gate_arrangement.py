"""The gated application of the session-gate suites and the ways of asking it."""

from __future__ import annotations

from typing import Any

from httpx import Response

from tests.support.webauth_arrangement import (
    LOGIN_REDIRECT,
    AuthApp,
    SessionsRecordingTheirTransaction,
    a_session,
    an_auth_app,
    session_cookie_header,
)
from webauth.policies import PathRules, PublicRule

LOGIN_PATH = "/login"

ONLY_LOGIN_AND_HEALTH = (PublicRule(PathRules(exact=frozenset({LOGIN_PATH, "/health"}))),)


def a_gated_app(
    record: Any = None,
    *,
    public: tuple[PublicRule, ...] = (),
    **keywords: Any,
) -> AuthApp:
    """A gated application with a login redirect, whose server errors answer 500."""
    return an_auth_app(
        a_session() if record is None else record,
        gate=True,
        login_redirect=LOGIN_REDIRECT,
        public=public,
        raise_server_exceptions=False,
        **keywords,
    )


def a_plain_app(record: Any, **keywords: Any) -> AuthApp:
    """The same application guarded by the route dependency alone."""
    return an_auth_app(record, login_redirect=LOGIN_REDIRECT, **keywords)


def ask(
    app: AuthApp,
    path: str,
    *,
    method: str = "GET",
    cookie: str | None = None,
    accept: str | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    sent = dict(headers or {})
    if cookie is not None:
        sent["cookie"] = cookie
    if accept is not None:
        sent["accept"] = accept
    return app.client.request(method, path, headers=sent, follow_redirects=False)


def signed_in(app: AuthApp) -> str:
    return session_cookie_header(app.signed_cookie())


def counted(sessions: SessionsRecordingTheirTransaction, name: str) -> int:
    return sessions.event_names.count(name)
