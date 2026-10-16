"""Raw ASGI middleware: reject requests exceeding their body size budget."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from webauth.policies import BodySizePolicy


class _BodyTooLarge(Exception):
    pass


def _too_large() -> JSONResponse:
    return JSONResponse({"detail": "Request body too large"}, status_code=413)


def _declares_over(scope: Scope, limit: int) -> bool:
    for name, value in scope.get("headers", []):
        if name.decode("latin-1").lower() == "content-length":
            try:
                return int(value.decode("latin-1")) > limit
            except ValueError:
                return False
    return False


class BodySizeLimitMiddleware:
    """Stop an oversized body at the door, and again while it streams in."""

    def __init__(self, app: ASGIApp, policy: BodySizePolicy) -> None:
        self.app = app
        self._policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self._policy.max_bytes(scope.get("path", ""), scope.get("method", ""))

        if _declares_over(scope, limit):
            await _too_large()(scope, receive, send)
            return

        received = 0

        async def guarded_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg.get("type") == "http.request":
                received += len(msg.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge(f"request body over {limit} bytes")
            return msg

        start_handed_over = False

        async def send_start_whole(message: Message) -> None:
            nonlocal start_handed_over
            if message["type"] != "http.response.start":
                await send(message)
                return
            start_handed_over = True
            # Shielded: a start cancelled mid-send may or may not have reached the
            # server, and only a delivered or failed start tells whether a 413 may follow.
            with anyio.CancelScope(shield=True):
                await send(message)

        try:
            await self.app(scope, guarded_receive, send_start_whole)
        except _BodyTooLarge:
            if start_handed_over:
                raise
            await _too_large()(scope, receive, send)
