"""The policies the gated test apps install the library middleware with."""

from __future__ import annotations

from webauth.policies import CsrfPolicy, SecurityHeadersPolicy
from webauth.sign_in_routes import SignInPaths

GATED_APP_HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
GATED_SIGN_IN_PATHS = SignInPaths(start="/sign-in/start", callback="/sign-in/callback")
GATED_STACK_POLICIES = {
    "sign_in_paths": GATED_SIGN_IN_PATHS,
    "security_headers": GATED_APP_HEADERS_POLICY,
    "csrf_origin": CsrfPolicy(),
}
