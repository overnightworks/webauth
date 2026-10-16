"""Security headers -- CSP, HSTS, and the cacheability of a response."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.datastructures import MutableHeaders
from starlette.responses import PlainTextResponse

from webauth.config import installed_web_auth_config

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

    from webauth.policies import SecurityHeadersPolicy

CONTENT_TYPE_OPTIONS: Final = "nosniff"
FRAME_OPTIONS: Final = "DENY"
REFERRER_POLICY: Final = "strict-origin-when-cross-origin"
STRICT_TRANSPORT_SECURITY: Final = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware:
    """Answer every request with this deployment's policy headers.

    HSTS follows the configured ``cookie_secure``, never the request's scheme:
    behind a TLS proxy the host has not listed, every request looks like plain
    http, and a deployment that serves Secure cookies must still pin https.
    With ``cookie_secure`` off no HSTS leaves, not even one a route set: a
    browser that pinned https could no longer reach the plain-http host.
    """

    def __init__(self, app: ASGIApp, policy: SecurityHeadersPolicy) -> None:
        self._app = app
        self._policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        cookie_secure = False
        response_started = False

        async def send_with_policy(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                self._apply_policy(MutableHeaders(scope=message), scope["path"], cookie_secure)
                response_started = True
            await send(message)

        try:
            cookie_secure = installed_web_auth_config(scope["app"]).cookie_secure
            await self._app(scope, receive, send_with_policy)
        except Exception as original:
            if not response_started:
                try:
                    await PlainTextResponse("Internal Server Error", 500)(
                        scope, receive, send_with_policy,
                    )
                except Exception as send_failure:  # noqa: BLE001
                    original.add_note(f"the 500 could not be sent: {send_failure!r}")
            raise

    def _apply_policy(self, headers: MutableHeaders, path: str, cookie_secure: bool) -> None:
        cache_control = self._policy.cache_control(path)
        if cache_control is not None:
            headers["Cache-Control"] = cache_control
        headers["X-Content-Type-Options"] = CONTENT_TYPE_OPTIONS
        headers["X-Frame-Options"] = FRAME_OPTIONS
        headers["Content-Security-Policy"] = self._policy.content_security_policy
        headers["Referrer-Policy"] = REFERRER_POLICY
        headers["Permissions-Policy"] = self._policy.permissions_policy
        if cookie_secure:
            headers["Strict-Transport-Security"] = STRICT_TRANSPORT_SECURITY
        elif "Strict-Transport-Security" in headers:
            del headers["Strict-Transport-Security"]
