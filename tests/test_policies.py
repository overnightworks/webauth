"""The request policies: what each one decides about a path, method, or budget."""

from __future__ import annotations

import math
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from webauth_arrangement import a_web_auth_config

from webauth.config import install_web_auth_config
from webauth.middleware import SecurityHeadersMiddleware
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    PathShape,
    RateLimitBudget,
    RateLimitClass,
    RateLimitPolicy,
    SecurityHeadersPolicy,
    default_content_security_policy,
)

_A_BUDGET = RateLimitBudget(max_requests=10, window_seconds=60)
_EVERY_BUDGET = dict.fromkeys(RateLimitClass, _A_BUDGET)


class TestPathRules:
    @pytest.mark.parametrize("path", [
        "/exactly/this",
        "/by-prefix/anything",
        "/api/jobs/some-id/stream",
        "/pattern/42",
    ])
    def test_selects_a_path_named_any_of_the_four_ways(self, path: str) -> None:
        rules = PathRules(
            exact=frozenset({"/exactly/this"}),
            prefixes=("/by-prefix/",),
            shapes=(PathShape(starts_with="/api/jobs/", ends_with="/stream"),),
            patterns=(re.compile(r"^/pattern/\d+$"),),
        )

        assert rules.matches(path) is True

    @pytest.mark.parametrize("path", [
        "/exactly/this/plus-more",
        "/by-prefix",
        "/api/jobs/some-id/streaming",
        "/pattern/not-a-number",
    ])
    def test_leaves_a_path_no_rule_names(self, path: str) -> None:
        rules = PathRules(
            exact=frozenset({"/exactly/this"}),
            prefixes=("/by-prefix/",),
            shapes=(PathShape(starts_with="/api/jobs/", ends_with="/stream"),),
            patterns=(re.compile(r"^/pattern/\d+$"),),
        )

        assert rules.matches(path) is False

    def test_a_rule_that_names_nothing_selects_nothing(self) -> None:
        assert PathRules().matches("/anything") is False


class TestRateLimitPolicy:
    def _policy(self) -> RateLimitPolicy:
        return RateLimitPolicy(
            budgets=_EVERY_BUDGET,
            exempt=PathRules(prefixes=("/static/",)),
            media=PathRules(prefixes=("/audio/",)),
            stream=PathRules(exact=frozenset({"/events"})),
        )

    @pytest.mark.parametrize(("path", "expected"), [
        ("/audio/song.mp3", RateLimitClass.MEDIA),
        ("/events", RateLimitClass.STREAM),
        ("/api/songs", RateLimitClass.API),
        ("/nothing-serves-this", RateLimitClass.API),
    ])
    def test_every_path_spends_from_exactly_one_budget(
        self, path: str, expected: RateLimitClass,
    ) -> None:
        assert self._policy().classify(path) == expected

    def test_an_exempt_path_spends_from_no_budget(self) -> None:
        policy = self._policy()

        assert policy.is_exempt("/static/app.js") is True
        assert policy.is_exempt("/api/songs") is False

    def test_a_class_without_a_budget_is_refused_at_build_time(self) -> None:
        with pytest.raises(ValueError, match="MEDIA"):
            RateLimitPolicy(budgets={
                RateLimitClass.API: _A_BUDGET, RateLimitClass.STREAM: _A_BUDGET,
            })


class TestCsrfPolicy:
    def _policy(self) -> CsrfPolicy:
        return CsrfPolicy(
            protected=PathRules(prefixes=("/api/",)),
            token_exempt=PathRules(exact=frozenset({"/api/auth/login"})),
        )

    def test_a_token_exempt_path_still_owes_a_same_origin_check(self) -> None:
        policy = self._policy()

        assert policy.requires_token("/api/auth/login") is False
        assert policy.requires_same_origin("/api/auth/login") is True

    def test_an_unprotected_path_owes_neither(self) -> None:
        policy = self._policy()

        assert policy.requires_token("/shared/slug") is False
        assert policy.requires_same_origin("/shared/slug") is False

    def test_a_protected_path_owes_both(self) -> None:
        policy = self._policy()

        assert policy.requires_token("/api/songs") is True
        assert policy.requires_same_origin("/api/songs") is True

    @pytest.mark.parametrize(("origin", "token_exempt"), [
        pytest.param(
            CsrfPolicy(exempt=PathRules(exact=frozenset({"/api/auth/login"}))),
            PathRules(prefixes=("/api/auth/",)),
            id="origin-exempts-an-exact-path-below-the-prefix",
        ),
        pytest.param(
            CsrfPolicy(exempt=PathRules(prefixes=("/api/auth/l",))),
            PathRules(prefixes=("/api/auth/",)),
            id="origin-exempts-a-prefix-below-the-prefix",
        ),
        pytest.param(
            CsrfPolicy(exempt=PathRules(prefixes=("/api/",))),
            PathRules(prefixes=("/api/auth/",)),
            id="origin-exempts-a-prefix-above-the-prefix",
        ),
        pytest.param(
            CsrfPolicy(exempt=PathRules(shapes=(PathShape("/api/auth/", "/reset"),))),
            PathRules(prefixes=("/api/auth/",)),
            id="origin-exempts-a-shape-below-the-prefix",
        ),
        pytest.param(
            CsrfPolicy(exempt=PathRules(patterns=(re.compile(r"/x"),))),
            PathRules(prefixes=("/api/auth/",)),
            id="origin-exempts-by-pattern",
        ),
        pytest.param(
            CsrfPolicy(protected=PathRules(exact=frozenset({"/api/internal/"}))),
            PathRules(prefixes=("/api/internal/",)),
            id="an-exact-protected-path-never-covers-a-prefix",
        ),
        pytest.param(
            CsrfPolicy(protected=PathRules(prefixes=("/api/internal/x",))),
            PathRules(prefixes=("/api/internal/",)),
            id="a-protected-prefix-below-the-exemption-prefix",
        ),
        pytest.param(
            CsrfPolicy(protected=PathRules(prefixes=("/api/",))),
            PathRules(exact=frozenset({"/shared/slug"})),
            id="exact-path-the-origin-check-skips",
        ),
        pytest.param(
            CsrfPolicy(),
            PathRules(shapes=(PathShape("/log", "in"),)),
            id="shape-is-unverifiable",
        ),
    ])
    def test_a_token_exemption_the_origin_check_may_not_cover_is_reported(
        self, origin: CsrfPolicy, token_exempt: PathRules,
    ) -> None:
        token_policy = CsrfPolicy(token_exempt=token_exempt)

        assert origin.token_exemptions_outside_origin_check(token_policy) != ()

    @pytest.mark.parametrize("origin", [
        pytest.param(CsrfPolicy(protected=PathRules(prefixes=("/api/",))), id="fail-open"),
        pytest.param(CsrfPolicy(exempt=PathRules(prefixes=("/webhook/",))), id="fail-closed"),
    ])
    def test_a_token_exemption_inside_the_origin_check_is_not_reported(
        self, origin: CsrfPolicy,
    ) -> None:
        token_policy = CsrfPolicy(token_exempt=PathRules(
            exact=frozenset({"/api/auth/login", "/api/auth/setup"}),
            prefixes=("/api/internal/",),
        ))

        assert origin.token_exemptions_outside_origin_check(token_policy) == ()


class TestBodySizePolicy:
    def _policy(self) -> BodySizePolicy:
        return BodySizePolicy(
            default_max_bytes=1_000,
            rules=(
                BodySizeRule(
                    paths=PathRules(exact=frozenset({"/upload"})), max_bytes=50_000,
                ),
                BodySizeRule(
                    paths=PathRules(exact=frozenset({"/cover"})),
                    max_bytes=9_000,
                    methods=frozenset({"POST"}),
                ),
            ),
        )

    @pytest.mark.parametrize(("path", "method", "expected"), [
        ("/upload", "POST", 50_000),
        ("/cover", "POST", 9_000),
        ("/cover", "post", 9_000),
        ("/cover", "PUT", 1_000),
        ("/songs", "POST", 1_000),
        ("/upload", "", 50_000),
    ])
    def test_a_route_gets_its_own_budget_and_every_other_the_default(
        self, path: str, method: str, expected: int,
    ) -> None:
        assert self._policy().max_bytes(path, method) == expected

    @pytest.mark.parametrize("seconds", [0, -1.5, math.nan, math.inf])
    def test_a_start_send_bound_that_is_not_a_positive_finite_number_is_refused(
        self, seconds: float,
    ) -> None:
        with pytest.raises(ValueError, match="start_send_seconds"):
            BodySizePolicy(default_max_bytes=1_000, start_send_seconds=seconds)


class TestSecurityHeadersPolicy:
    def test_the_first_matching_cache_rule_answers_the_path(self) -> None:
        policy = SecurityHeadersPolicy(
            content_security_policy="default-src 'none'",
            cache_control_rules=(
                CacheControlRule(
                    paths=PathRules(exact=frozenset({"/api/events"})),
                    value="no-cache, no-store",
                ),
                CacheControlRule(paths=PathRules(prefixes=("/api/",)), value="no-store"),
            ),
        )

        assert policy.cache_control("/api/events") == "no-cache, no-store"
        assert policy.cache_control("/api/songs") == "no-store"
        assert policy.cache_control("/about") is None

    @pytest.mark.parametrize(("policy", "expected"), [
        pytest.param(
            SecurityHeadersPolicy(content_security_policy="default-src 'none'"),
            "camera=(), microphone=(), geolocation=()",
            id="without-the-field",
        ),
        pytest.param(
            SecurityHeadersPolicy(
                content_security_policy="default-src 'none'",
                permissions_policy="camera=(), microphone=(self), geolocation=()",
            ),
            "camera=(), microphone=(self), geolocation=()",
            id="with-microphone-for-this-origin",
        ),
        pytest.param(
            SecurityHeadersPolicy("default-src 'none'", ()),
            "camera=(), microphone=(), geolocation=()",
            id="two-positional-arguments",
        ),
    ])
    def test_every_response_answers_the_policy_permissions(
        self, policy: SecurityHeadersPolicy, expected: str,
    ) -> None:
        app = FastAPI()
        install_web_auth_config(app, a_web_auth_config())
        app.add_middleware(SecurityHeadersMiddleware, policy=policy)
        app.get("/")(lambda: {})

        response = TestClient(app).get("/")

        assert response.headers["Permissions-Policy"] == expected

    @pytest.mark.parametrize("line_break", ["\r", "\n", "\r\n"])
    def test_refuses_a_permissions_policy_with_a_line_break(self, line_break: str) -> None:
        with pytest.raises(ValueError, match="CR or LF"):
            SecurityHeadersPolicy(
                content_security_policy="default-src 'none'",
                permissions_policy=f"camera=(){line_break}X-Injected: 1",
            )


class TestDefaultContentSecurityPolicy:
    def test_admits_this_origin_and_nothing_else(self) -> None:
        assert default_content_security_policy([]) == (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "connect-src 'self'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "manifest-src 'self'; "
            "worker-src 'self'; "
            "frame-ancestors 'none'"
        )

    def test_admits_each_named_inline_script_by_hash(self) -> None:
        policy = default_content_security_policy(["sha256-one", "sha256-two"])

        assert "script-src 'self' 'sha256-one' 'sha256-two';" in policy
