"""Security headers -- CSP, HSTS, and the cacheability of a response."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.middleware.base import BaseHTTPMiddleware

from webauth.config import web_auth_config

if TYPE_CHECKING:
    from starlette.requests import Request

    from webauth.policies import SecurityHeadersPolicy

CONTENT_TYPE_OPTIONS: Final = "nosniff"
FRAME_OPTIONS: Final = "DENY"
REFERRER_POLICY: Final = "strict-origin-when-cross-origin"
PERMISSIONS_POLICY: Final = "camera=(), microphone=(), geolocation=()"
STRICT_TRANSPORT_SECURITY: Final = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Answer every request with this deployment's policy headers.

    HSTS follows the configured ``cookie_secure``, never the request's scheme:
    behind a TLS proxy the host has not listed, every request looks like plain
    http, and a deployment that serves Secure cookies must still pin https.
    """

    def __init__(self, app, policy: SecurityHeadersPolicy, **kwargs):  # type: ignore[no-untyped-def]
        super().__init__(app, **kwargs)
        self._policy = policy

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        cache_control = self._policy.cache_control(request.url.path)
        if cache_control is not None:
            response.headers["Cache-Control"] = cache_control
        response.headers["X-Content-Type-Options"] = CONTENT_TYPE_OPTIONS
        response.headers["X-Frame-Options"] = FRAME_OPTIONS
        response.headers["Content-Security-Policy"] = self._policy.content_security_policy
        response.headers["Referrer-Policy"] = REFERRER_POLICY
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY
        if web_auth_config(request).cookie_secure:
            response.headers["Strict-Transport-Security"] = STRICT_TRANSPORT_SECURITY
        return response
