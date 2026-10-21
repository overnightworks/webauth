"""Raw ASGI middleware: reject requests exceeding their body size budget."""

from __future__ import annotations

from typing import TYPE_CHECKING

import anyio
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from webauth.policies import BodySizePolicy

__all__ = [
    "BodySizeLimitMiddleware",
    "RequestBodyTooLarge",
]


class RequestBodyTooLarge(Exception):
    """A streamed request body passed its limit.

    `BodySizeLimitMiddleware` answers 413 when the response has not started and
    raises this to the server when it has. It is deliberately not a
    `WebAuthError`: it travels out of the host's route back to the middleware, and
    a host's catch-all for `WebAuthError` must not answer before the middleware does.
    """


def _too_large() -> JSONResponse:
    return JSONResponse({"detail": "Request body too large"}, status_code=413)


def _declares_over(scope: Scope, limit: int) -> bool:
    return any(
        _declared_length(value) > limit
        for name, value in scope.get("headers", [])
        if name.decode("latin-1").lower() == "content-length"
    )


def _declared_length(value: bytes) -> int:
    try:
        return int(value.decode("latin-1"))
    except ValueError:
        return 0


class BodySizeLimitMiddleware:
    """Stop an oversized body at the door, and again while it streams in.

    A body whose Content-Length is over the limit is refused with 413 before
    the route runs and spends no rate-limit budget. A streamed body (no
    Content-Length) is counted as the app reads it, so the request has already
    passed the middleware inside this one: where the rate limit is installed,
    the path is not exempt and the limiter is reached, it has spent one budget,
    and where the session gate is installed it has been admitted. What follows
    for a body found over the limit:

    - read through ``request.body()`` or ``request.stream()`` before the
      response starts: 413 with the library headers;
    - parsed by FastAPI (a typed body, ``Form()``, ``File()``/``UploadFile``):
      FastAPI's 400 "There was an error parsing the body" through the host's
      ``HTTPException`` handler, and the route never runs;
    - found over the limit after the response has started (a streaming
      response that reads the body, or any ``StreamingResponse`` under ASGI
      spec < 2.4, whose disconnect listener reads it; uvicorn reports 2.3): no
      second start and no 413, the response is cut off at its next await, one
      that already finished stays complete, and ``RequestBodyTooLarge``
      reaches the server either way;
    - never read, and the response is not a ``StreamingResponse`` under spec
      < 2.4: not size-checked, the request is answered normally.

    A response's start is sent whole: a cancellation inside the app waits until
    the start is sent, and so does a host deadline that cancels through an
    anyio cancel scope outside the stack; asyncio cancellation
    (``asyncio.timeout``, server shutdown) still interrupts it. The wait ends
    after ``BodySizePolicy.start_send_seconds``, when the start is cut off with
    an error that reaches the server; no 413 and no second start follow.
    """

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
                    raise RequestBodyTooLarge(f"request body over {limit} bytes")
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
            # Bounded: a peer that stops reading must not hold the shield for ever.
            with anyio.fail_after(self._policy.start_send_seconds, shield=True):
                await send(message)

        try:
            await self.app(scope, guarded_receive, send_start_whole)
        except RequestBodyTooLarge:
            if start_handed_over:
                raise
            await _too_large()(scope, receive, send)
