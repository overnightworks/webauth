"""Security headers -- CSP, HSTS, and the cacheability of a response."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, NoReturn

from starlette.datastructures import MutableHeaders
from starlette.requests import HTTPConnection
from starlette.responses import PlainTextResponse

from webauth.config import installed_web_auth_config
from webauth.middleware._route_path import route_path
from webauth.policies import _OWN_POLICY_HEADER
from webauth.proxies import _client_is_recorded, _no_client_recorded

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from webauth.policies import SecurityHeadersPolicy

__all__ = [
    "CONTENT_TYPE_OPTIONS",
    "FRAME_OPTIONS",
    "REFERRER_POLICY",
    "STRICT_TRANSPORT_SECURITY",
]

CONTENT_TYPE_OPTIONS: Final = "nosniff"
FRAME_OPTIONS: Final = "DENY"
REFERRER_POLICY: Final = "strict-origin-when-cross-origin"
STRICT_TRANSPORT_SECURITY: Final = "max-age=31536000; includeSubDomains"

_ASCII_WHITESPACE: Final = " \t\n\f\r"
_ASCII_WHITESPACE_RUN: Final = re.compile(f"[{_ASCII_WHITESPACE}]+")


def _allows_no_framer(content_security_policy: str) -> bool:
    """Whether the policy allows no framer through ``frame-ancestors``.

    That is no directive, one with no source, or one whose only source is ``'none'``.

    The policy is read as CSP Level 3 parses a serialized policy: the first
    ``frame-ancestors`` directive counts, its name and ``'none'`` compared
    ASCII case-insensitively. Engines ignore ``X-Frame-Options`` when an
    enforced ``frame-ancestors`` exists, so the header only matters here.
    """
    for directive in content_security_policy.split(";"):
        name, *sources = _ASCII_WHITESPACE_RUN.split(directive.strip(_ASCII_WHITESPACE))
        if name.lower() == "frame-ancestors":
            return [source.lower() for source in sources] in ([], ["'none'"])
    return True


class _SecurityHeadersMiddleware:
    """Answer every request with this deployment's policy headers.

    HSTS follows the configured ``cookie_secure``, never the request's scheme:
    behind a TLS proxy the host has not listed, every request looks like plain
    http, and a deployment that serves Secure cookies must still pin https.
    With ``cookie_secure`` off no HSTS leaves, not even one a route set: a
    browser that pinned https could no longer reach the plain-http host.

    The stack's first middleware, it also refuses a connection the client-address writer did not
    record a client for (an app built with ``SHARED_FRONT`` and served without
    ``web_auth_front``) through ``_refuse_unrecorded_client``, so a missing writer shows on the
    first request.

    An exception before the response started is answered with a plain 500
    that carries the policy headers, and the exception still reaches the
    server: a host's 500 handler runs, but the response it returns is not
    sent, and with ``debug=True`` Starlette's traceback page is not sent
    either. After the response started, nothing more is sent.

    One answer keeps its own ``Content-Security-Policy`` and ``Cache-Control``:
    the logout page of the sign-in routes, which carries a
    private marker header that this middleware removes. Every other header,
    HSTS included, is applied to it as to any answer.

    A path a ``ContentSecurityPolicyRule`` names is answered with that rule's policy
    instead of the default; the sign-out page keeps its own either way.

    ``X-Frame-Options: DENY`` leaves with an answer whose
    ``Content-Security-Policy`` has no ``frame-ancestors`` directive, one with
    no source, or one whose only source is ``'none'``. An answer whose
    ``frame-ancestors`` lists any other source carries no ``X-Frame-Options``,
    so a host that allows a framer sends one framing rule. The sign-out page's
    own policy is judged the same way.
    """

    def __init__(self, app: ASGIApp, policy: SecurityHeadersPolicy) -> None:
        self._app = app
        self._policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in _CLIENT_SCOPES and not _client_is_recorded(HTTPConnection(scope)):
            await _refuse_unrecorded_client(scope, receive, send, self._policy)
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        await _answer_under_policy(self._app, self._policy, scope, receive, send)


_CLIENT_SCOPES: Final = frozenset({"http", "websocket"})


async def _refuse_unrecorded_client(
    scope: Scope, receive: Receive, send: Send, policy: SecurityHeadersPolicy
) -> NoReturn:
    """Refuse a connection no client-address writer stood in front of, and reach no app.

    An http request answers the library 500 with the policy's headers and the error still
    reaches the server; a WebSocket raises before the handshake is accepted.
    """
    if scope["type"] == "http":
        await _answer_under_policy(_raise_no_client_recorded, policy, scope, receive, send)
    raise _no_client_recorded()


async def _raise_no_client_recorded(scope: Scope, receive: Receive, send: Send) -> None:
    raise _no_client_recorded()


async def _answer_under_policy(
    app: ASGIApp, policy: SecurityHeadersPolicy, scope: Scope, receive: Receive, send: Send
) -> None:
    path = route_path(scope)
    cookie_secure = False
    response_started = False

    async def send_with_policy(message: Message) -> None:
        nonlocal response_started
        if message["type"] == "http.response.start":
            message.setdefault("headers", [])
            _apply_policy(policy, MutableHeaders(scope=message), path, cookie_secure)
            response_started = True
        await send(message)

    try:
        cookie_secure = installed_web_auth_config(scope["app"]).cookie_secure
        await app(scope, receive, send_with_policy)
    except Exception as original:
        if not response_started:
            try:
                await PlainTextResponse("Internal Server Error", 500)(
                    scope,
                    receive,
                    send_with_policy,
                )
            except Exception as send_failure:
                original.add_note(f"the 500 could not be sent: {send_failure!r}")
        raise


def _apply_policy(
    policy: SecurityHeadersPolicy, headers: MutableHeaders, path: str, cookie_secure: bool
) -> None:
    if _OWN_POLICY_HEADER in headers:
        del headers[_OWN_POLICY_HEADER]
    else:
        cache_control = policy.cache_control(path)
        if cache_control is not None:
            headers["Cache-Control"] = cache_control
        headers["Content-Security-Policy"] = policy.content_security_policy_for(path)
    headers["X-Content-Type-Options"] = CONTENT_TYPE_OPTIONS
    if _allows_no_framer(headers.get("Content-Security-Policy", "")):
        headers["X-Frame-Options"] = FRAME_OPTIONS
    elif "X-Frame-Options" in headers:
        del headers["X-Frame-Options"]
    headers["Referrer-Policy"] = REFERRER_POLICY
    headers["Permissions-Policy"] = policy.permissions_policy
    if cookie_secure:
        headers["Strict-Transport-Security"] = STRICT_TRANSPORT_SECURITY
    elif "Strict-Transport-Security" in headers:
        del headers["Strict-Transport-Security"]
