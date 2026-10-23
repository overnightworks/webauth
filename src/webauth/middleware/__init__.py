"""The HTTP middleware the library owns, each reading only its policy."""

from __future__ import annotations

from webauth.middleware.bearer_gate import BearerGate, BearerGateMiddleware, bearer_caller
from webauth.middleware.body_size import BodySizeLimitMiddleware, RequestBodyTooLarge
from webauth.middleware.csrf import CsrfOriginMiddleware
from webauth.middleware.rate_limit import IpRateLimitMiddleware
from webauth.middleware.security_headers import SecurityHeadersMiddleware
from webauth.middleware.session_gate import (
    SessionGate,
    SessionGateMiddleware,
    admitted_admin,
    admitted_user,
)
from webauth.middleware.stack import install_web_auth_middleware

__all__ = [
    "BearerGate",
    "BearerGateMiddleware",
    "BodySizeLimitMiddleware",
    "CsrfOriginMiddleware",
    "IpRateLimitMiddleware",
    "RequestBodyTooLarge",
    "SecurityHeadersMiddleware",
    "SessionGate",
    "SessionGateMiddleware",
    "admitted_admin",
    "admitted_user",
    "bearer_caller",
    "install_web_auth_middleware",
]
