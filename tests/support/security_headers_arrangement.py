"""Shared assertion for the headers the security-headers policy puts on a response."""

from __future__ import annotations

from collections.abc import Mapping

from webauth.middleware.security_headers import (
    CONTENT_TYPE_OPTIONS,
    FRAME_OPTIONS,
    REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY,
)
from webauth.policies import SecurityHeadersPolicy


def assert_carries_policy_headers(
    headers: Mapping[str, str], policy: SecurityHeadersPolicy, *, hsts: bool
) -> None:
    """Every header ``policy`` puts on a response is there; HSTS only when ``hsts``."""
    expected = {
        "x-content-type-options": CONTENT_TYPE_OPTIONS,
        "x-frame-options": FRAME_OPTIONS,
        "content-security-policy": policy.content_security_policy,
        "referrer-policy": REFERRER_POLICY,
        "permissions-policy": policy.permissions_policy,
    }
    if hsts:
        expected["strict-transport-security"] = STRICT_TRANSPORT_SECURITY
    carried = {name: headers.get(name) for name in (*expected, "strict-transport-security")}
    assert carried == {"strict-transport-security": None, **expected}
