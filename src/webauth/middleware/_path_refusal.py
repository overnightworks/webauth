"""Refuse a route path with a control character before any rule or route reads it."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.responses import JSONResponse

from webauth._paths import carries_control_character
from webauth.middleware._refusal import RefusalMiddleware
from webauth.middleware._route_path import route_path

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.types import ASGIApp

__all__ = []


class PathRefusalMiddleware(RefusalMiddleware[None]):
    """Answer 400 to an http request whose route path carries a control character.

    The router and the path rules disagree about such a path: Starlette's route
    patterns end in ``$``, which also matches before a final line feed, while
    the rules compare a path exactly. Refusing the path ahead of both leaves no
    spelling that reaches a route without its rules. The install order places it
    inside the security headers and ahead of everything else, and
    ``install_web_auth_middleware`` is the only way to add it.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app, None)

    async def _refusal(self, request: Request) -> JSONResponse | None:
        if carries_control_character(route_path(request.scope)):
            return JSONResponse({"detail": "Malformed request path"}, status_code=400)
        return None
