"""Resolve the client address once per request and record it for everything inside."""

from __future__ import annotations

from typing import TYPE_CHECKING

from logline import set_client_ip
from starlette.requests import HTTPConnection

from webauth.middleware.security_headers import _SecurityHeadersMiddleware
from webauth.proxies import _client_is_recorded, _record_client

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from webauth.policies import SecurityHeadersPolicy
    from webauth.proxies import TrustedProxies

__all__: list[str] = []

_RECORDED_SCOPES = frozenset({"http", "websocket"})


class _ClientAddressMiddleware:
    """Record the client the trusted proxies resolve, and set the ``ip`` of the request line.

    The composition call places it immediately inside logline's ``RequestLineMiddleware`` for an
    app built with ``TrustedProxies``, and ``web_auth_front`` places it around any ASGI app, a
    router of several built apps included. Everything it wraps -- the library's stack, a CORS
    layer that answers a preflight itself, a router that answers its own 404 -- then carries the
    client and not the proxy, and reads it through ``webauth.proxies.client_address``. It records
    the address and whether the connection is HTTPS for an http or websocket scope, refuses
    nothing, and passes any other scope through untouched. It rewrites neither the scope's peer
    nor its scheme.
    """

    def __init__(self, app: ASGIApp, *, trusted_proxies: TrustedProxies) -> None:
        self._app = app
        self._trusted_proxies = trusted_proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in _RECORDED_SCOPES:
            set_client_ip(scope, _record_client(HTTPConnection(scope), self._trusted_proxies))
        await self._app(scope, receive, send)


class _FrontRequiredMiddleware:
    """Refuse a request no client-address writer stood in front of, before anything answers it.

    The composition call places it outermost for an app built with ``SHARED_FRONT``, outside the
    host's ``outside`` entries, so a CORS layer that answers a preflight itself cannot answer for
    an app served without ``web_auth_front``. The refusal is the security-headers middleware's:
    an http request answers the library 500 with the headers, a WebSocket raises before the app
    runs, and the app below is never reached.
    """

    def __init__(self, app: ASGIApp, *, policy: SecurityHeadersPolicy) -> None:
        self._app = app
        self._refusal = _SecurityHeadersMiddleware(app, policy)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in _RECORDED_SCOPES and not _client_is_recorded(HTTPConnection(scope)):
            await self._refusal(scope, receive, send)
            return
        await self._app(scope, receive, send)
