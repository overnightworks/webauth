"""The scopes and drives that turn the unix-socket peer on, which httpx's transport cannot build."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from starlette.requests import HTTPConnection

from tests.support.webauth_arrangement import an_http_scope, as_a_websocket_scope, drive
from webauth.middleware.client_address import _ClientAddressMiddleware
from webauth.proxies import TrustedProxies, client_address, request_is_https
from webauth.web_auth import web_auth_front

if TYPE_CHECKING:
    from collections.abc import Mapping

    from starlette.types import Receive, Scope, Send

UNIX_SOCKET_PATH = "/run/app/app.sock"


@dataclass(frozen=True)
class Recorded:
    address: str
    https: bool


def a_connection_scope(
    *,
    kind: Literal["http", "websocket"] = "http",
    server: object = (UNIX_SOCKET_PATH, None),
    client: tuple[str, int] | None = None,
    headers: Mapping[str, str] | None = None,
) -> Scope:
    """The scope a server hands the app: by default a unix socket's, which has no client.

    Built from the raw-scope builder, as httpx's transport cannot build a unix scope.
    """
    scope = an_http_scope(
        headers=[(name.encode(), value.encode()) for name, value in (headers or {}).items()],
        scheme="http",
        client=client,
        server=server,
    )
    return scope if kind == "http" else as_a_websocket_scope(scope)


def recorded_by_the_writer(trusted_proxies: TrustedProxies, scope: Scope) -> Recorded:
    """What the client-address writer records for `scope`, read by the app inside it."""
    seen: list[Recorded] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        connection = HTTPConnection(scope)
        seen.append(Recorded(client_address(connection), request_is_https(connection)))

    writer = _ClientAddressMiddleware(app, trusted_proxies=trusted_proxies)
    _, raised = asyncio.run(drive(writer, scope))
    assert raised is None
    [recorded] = seen
    return recorded


def answered_through_the_front(trusted_proxies: TrustedProxies, scope: Scope) -> None:
    """Serve one http `scope` through the front a host calls, which writes the request line."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    _, raised = asyncio.run(drive(web_auth_front(app, trusted_proxies=trusted_proxies), scope))
    assert raised is None
