"""Put the resolved client address on the request line before any refusal can answer."""

from __future__ import annotations

from typing import TYPE_CHECKING

from logline import set_client_ip
from starlette.requests import Request

from webauth.proxies import resolve_client_ip

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "ClientAddressMiddleware",
]


class ClientAddressMiddleware:
    """Set the ``ip`` of an http request's line to ``resolve_client_ip``'s answer.

    It sits ahead of every refusal, so the path and body-size refusals and a rate-limited
    request carry the resolved client and not the proxy that relayed it. It refuses nothing,
    and ``install_web_auth_middleware`` is the only way to add it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            set_client_ip(scope, resolve_client_ip(Request(scope)))
        await self._app(scope, receive, send)
