"""The policies the gated test apps install the library middleware with."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from webauth.middleware import SessionGate, install_web_auth_middleware
from webauth.policies import CsrfPolicy, SecurityHeadersPolicy
from webauth.sign_in_routes import SignInPaths

GATED_APP_HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
GATED_SIGN_IN_PATHS = SignInPaths(start="/sign-in/start", callback="/sign-in/callback")


def install_the_gated_stack(
    app: FastAPI, *, session_gate: SessionGate | None = None, **overrides: Any
) -> None:
    """Install the library middleware with the gated apps' policies; a keyword replaces one."""
    install_web_auth_middleware(
        app,
        **{
            "sign_in_paths": GATED_SIGN_IN_PATHS,
            "security_headers": GATED_APP_HEADERS_POLICY,
            "csrf_origin": CsrfPolicy(),
            **overrides,
        },
        session_gate=session_gate,
    )
