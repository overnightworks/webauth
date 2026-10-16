"""Pure ASGI middleware that refuses before the app runs, or hands it through untouched."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from starlette.requests import Request

if TYPE_CHECKING:
    from starlette.responses import Response
    from starlette.types import ASGIApp, Receive, Scope, Send


class RefusalMiddleware[PolicyT](ABC):
    """Answer an http request with its refusal, or pass every message through."""

    def __init__(self, app: ASGIApp, policy: PolicyT) -> None:
        self._app = app
        self._policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            refusal = self._refusal(Request(scope))
            if refusal is not None:
                await refusal(scope, receive, send)
                return
        await self._app(scope, receive, send)

    @abstractmethod
    def _refusal(self, request: Request) -> Response | None:
        """The response that refuses ``request``, or None to admit it."""
