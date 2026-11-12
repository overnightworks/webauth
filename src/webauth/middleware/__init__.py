"""The HTTP middleware the library owns, each reading only its policy."""

from __future__ import annotations

from webauth.middleware.bearer_gate import (
    BearerGate,
    BearerGateMiddleware,
    MachinePaths,
    MarkedRoute,
    PersonPaths,
    ProtectedResource,
    bearer_caller,
    exchanged_access_token,
    install_resource_metadata,
    is_resource_admission,
    resource_person,
)
from webauth.middleware.body_size import BodySizeLimitMiddleware, RequestBodyTooLarge
from webauth.middleware.csrf import CsrfOriginMiddleware
from webauth.middleware.path_refusal import PathRefusalMiddleware
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
    "MachinePaths",
    "MarkedRoute",
    "PathRefusalMiddleware",
    "PersonPaths",
    "ProtectedResource",
    "RequestBodyTooLarge",
    "SecurityHeadersMiddleware",
    "SessionGate",
    "SessionGateMiddleware",
    "admitted_admin",
    "admitted_user",
    "bearer_caller",
    "exchanged_access_token",
    "install_resource_metadata",
    "install_web_auth_middleware",
    "is_resource_admission",
    "resource_person",
]
