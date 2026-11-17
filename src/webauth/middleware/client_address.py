"""Resolve the client address once per request and put it on the request line before any refusal."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from logline import set_client_ip
from starlette.requests import Request

from webauth.proxies import resolve_client_ip

if TYPE_CHECKING:
    from starlette.requests import HTTPConnection
    from starlette.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "ClientAddressMiddleware",
]

_CLIENT_ADDRESS_SCOPE_KEY: Final = "webauth.client_address"


def resolved_client_address(connection: HTTPConnection) -> str:
    """``resolve_client_ip``'s answer, computed once for this request.

    Resolving writes a ``forwarded_for.ignored`` warning for a header it ignores, so a second
    resolution of one request would write it twice.
    """
    address = connection.scope.get(_CLIENT_ADDRESS_SCOPE_KEY)
    if address is None:
        address = resolve_client_ip(connection)
        connection.scope[_CLIENT_ADDRESS_SCOPE_KEY] = address
    return address


class ClientAddressMiddleware:
    """Set the ``ip`` of an http request's line to the request's resolved client address.

    It sits ahead of every refusal, so the path and body-size refusals and a rate-limited
    request carry the resolved client and not the proxy that relayed it; the rate limit keys
    its budget on the same answer. It refuses nothing, and ``install_web_auth_middleware`` is
    the only way to add it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            set_client_ip(scope, resolved_client_address(Request(scope)))
        await self._app(scope, receive, send)
