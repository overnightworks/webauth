"""Shared arrangement and assertion for the security-headers policy and its response headers."""

from __future__ import annotations

from collections.abc import Mapping

from webauth.middleware.security_headers import (
    CONTENT_TYPE_OPTIONS,
    FRAME_OPTIONS,
    REFERRER_POLICY,
    STRICT_TRANSPORT_SECURITY,
)
from webauth.policies import ContentSecurityPolicyRule, PathRules, SecurityHeadersPolicy

A_CONTENT_SECURITY_POLICY = "default-src 'self'"


def assert_carries_policy_headers(
    headers: Mapping[str, str],
    policy: SecurityHeadersPolicy,
    *,
    hsts: bool,
    frame_options: str | None = FRAME_OPTIONS,
) -> None:
    """Every header ``policy`` puts on a response is there.

    HSTS only when ``hsts``; ``frame_options`` is the expected ``X-Frame-Options``,
    ``None`` when the answer carries none.
    """
    expected: dict[str, str | None] = {
        "x-content-type-options": CONTENT_TYPE_OPTIONS,
        "x-frame-options": frame_options,
        "content-security-policy": policy.content_security_policy,
        "referrer-policy": REFERRER_POLICY,
        "permissions-policy": policy.permissions_policy,
    }
    if hsts:
        expected["strict-transport-security"] = STRICT_TRANSPORT_SECURITY
    carried = {name: headers.get(name) for name in (*expected, "strict-transport-security")}
    assert carried == {"strict-transport-security": None, **expected}


def a_content_security_policy_rule(
    value: str, *, prefixes: tuple[str, ...] = (), exact: frozenset[str] = frozenset()
) -> ContentSecurityPolicyRule:
    return ContentSecurityPolicyRule(PathRules(prefixes=prefixes, exact=exact), value)


def a_policy_with_content_security_policy_rules(
    *rules: ContentSecurityPolicyRule,
) -> SecurityHeadersPolicy:
    return SecurityHeadersPolicy(A_CONTENT_SECURITY_POLICY, content_security_policy_rules=rules)
