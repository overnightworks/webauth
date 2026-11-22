"""Pure ASGI middleware that answers a store that cannot be reached while an answer can still go."""

from __future__ import annotations

from typing import TYPE_CHECKING

from webauth._outage import _session_store_unavailable_answer
from webauth.ports import StoreUnavailableError

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__: list[str] = []


class _StoreOutageMiddleware:
    """Answer 503 with ``Retry-After`` to a ``StoreUnavailableError`` that leaves the app before
    its response has started; one that comes later, and every other exception, passes on.

    It sits inside the rate limit and outside both gates, so a gate's own transaction, the host's
    ``inside`` entries, ``current_user`` and the host's routes are covered. The sign-in routes
    send their own answer before they raise and handle the outage themselves.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        started = False

        async def send_noting_the_start(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self._app(scope, receive, send_noting_the_start)
        except StoreUnavailableError:
            if started:
                raise
            await _session_store_unavailable_answer()(scope, receive, send)
