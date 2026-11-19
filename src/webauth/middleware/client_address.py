"""Resolve the client address once per request and record it for everything inside."""

from __future__ import annotations

from typing import TYPE_CHECKING

from logline import set_client_ip
from starlette.requests import HTTPConnection

from webauth.proxies import _record_client

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from webauth.proxies import TrustedProxies

__all__ = [
    "ClientAddressMiddleware",
]

_RECORDED_SCOPES = frozenset({"http", "websocket"})


class ClientAddressMiddleware:
    """Record the client the trusted proxies resolve, and set the ``ip`` of the request line.

    The host adds it itself, as a plain ASGI wrapper around the app it serves, immediately
    inside logline's ``RequestLineMiddleware``: ``RequestLineMiddleware(ClientAddressMiddleware(
    app, trusted_proxies=...))``. Everything it wraps -- the library's stack, a CORS layer that
    answers a preflight itself, a router that answers its own 404 -- then carries the client and
    not the proxy, and reads it through ``webauth.proxies.client_address``. It records the
    address and whether the connection is HTTPS for an http or websocket scope, refuses nothing,
    and passes any other scope through untouched. It rewrites neither the scope's peer nor its
    scheme. ``trusted_proxies`` is the one place the host names the proxies it believes.
    """

    def __init__(self, app: ASGIApp, *, trusted_proxies: TrustedProxies) -> None:
        self._app = app
        self._trusted_proxies = trusted_proxies

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in _RECORDED_SCOPES:
            set_client_ip(scope, _record_client(HTTPConnection(scope), self._trusted_proxies))
        await self._app(scope, receive, send)
