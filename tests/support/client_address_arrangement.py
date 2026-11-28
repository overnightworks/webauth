"""The private writer the low-level stack tests put around their app, and the proxies it trusts."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from logline import RequestLineMiddleware
from starlette.requests import HTTPConnection

from webauth.middleware.client_address import _ClientAddressMiddleware
from webauth.proxies import TrustedProxies, client_address, request_is_https

if TYPE_CHECKING:
    from collections.abc import Mapping

    from starlette.applications import Starlette
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

TRUSTED_PROXIES = TrustedProxies.parse("172.16.0.0/12")


def behind_the_client_address_writer(app: ASGIApp) -> _ClientAddressMiddleware:
    """`app` wrapped the way a host's wiring does it, trusting the suites' proxy network."""
    return _ClientAddressMiddleware(app, trusted_proxies=TRUSTED_PROXIES)


def add_the_client_address_writer(app: Starlette) -> None:
    """Add the writer outside everything `app` carries so far; a host's wrapper line does the same.

    Call it after the stack is installed and before logline's middleware, which stays outermost.
    """
    app.add_middleware(_ClientAddressMiddleware, trusted_proxies=TRUSTED_PROXIES)


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

    `server` takes whatever form the case needs (a host and port, `None`), as the ASGI servers
    differ in it. httpx's transport cannot build a unix scope, so a test that turns the unix peer
    on builds its scope here.
    """
    return {
        "type": kind,
        "asgi": {"version": "3.0"},
        "scheme": "http" if kind == "http" else "ws",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [(name.encode(), value.encode()) for name, value in (headers or {}).items()],
        "client": client,
        "server": server,
        **({"method": "GET", "http_version": "1.1"} if kind == "http" else {}),
    }


def recorded_by_the_writer(trusted_proxies: TrustedProxies, scope: Scope) -> Recorded:
    """What the client-address writer records for `scope`, read by the app inside it."""
    seen: list[Recorded] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        connection = HTTPConnection(scope)
        seen.append(Recorded(client_address(connection), request_is_https(connection)))

    async def silent_receive() -> Message:
        raise AssertionError("the writer reads no body")

    async def silent_send(message: Message) -> None:
        raise AssertionError("the probe app answers nothing")

    writer = _ClientAddressMiddleware(app, trusted_proxies=trusted_proxies)
    asyncio.run(writer(scope, silent_receive, silent_send))
    [recorded] = seen
    return recorded


def answered_through_the_front(trusted_proxies: TrustedProxies, scope: Scope) -> None:
    """Serve one http `scope` through logline's request line and the writer, which write a line."""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        pass

    front = RequestLineMiddleware(_ClientAddressMiddleware(app, trusted_proxies=trusted_proxies))
    asyncio.run(front(scope, receive, send))
