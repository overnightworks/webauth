"""The HTTP middleware the library owns, each reading only its policy."""

from __future__ import annotations

from webauth.middleware.body_size import BodySizeLimitMiddleware, RequestBodyTooLarge
from webauth.middleware.csrf import CsrfOriginMiddleware, CsrfTokenMiddleware
from webauth.middleware.rate_limit import IpRateLimitMiddleware
from webauth.middleware.security_headers import SecurityHeadersMiddleware
from webauth.middleware.session_gate import SessionGate, SessionGateMiddleware, admitted_user
from webauth.middleware.stack import install_web_auth_middleware

__all__ = [
    "BodySizeLimitMiddleware",
    "CsrfOriginMiddleware",
    "CsrfTokenMiddleware",
    "IpRateLimitMiddleware",
    "RequestBodyTooLarge",
    "SecurityHeadersMiddleware",
    "SessionGate",
    "SessionGateMiddleware",
    "admitted_user",
    "install_web_auth_middleware",
]
