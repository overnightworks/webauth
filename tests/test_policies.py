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
    CspDirective,
    CsrfPolicy,
    PathRules,
    PathShape,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
    default_content_security_policy,
)


def _a_budget(name: str, max_requests: int = 10) -> RateLimitBudget:
    return RateLimitBudget(name, max_requests=max_requests, window_seconds=60)


_DEFAULT = _a_budget("default")
_BULK = _a_budget("bulk")
_UPLOAD = _a_budget("upload")
_BULK_RULE = RateLimitRule(paths=PathRules(prefixes=("/bulk/",)), budget=_BULK)
_UPLOAD_RULE = RateLimitRule(paths=PathRules(prefixes=("/bulk/up",)), budget=_UPLOAD)


class TestPathRules:
    @pytest.mark.parametrize("path", [
        "/exactly/this",
        "/by-prefix/anything",
        "/api/items/some-id/stream",
        "/pattern/42",
    ])
    def test_selects_a_path_named_any_of_the_four_ways(self, path: str) -> None:
        rules = PathRules(
            exact=frozenset({"/exactly/this"}),
            prefixes=("/by-prefix/",),
            shapes=(PathShape(starts_with="/api/items/", ends_with="/stream"),),
            patterns=(re.compile(r"^/pattern/\d+$"),),
        )

        assert rules.matches(path) is True

    @pytest.mark.parametrize("path", [
        "/exactly/this/plus-more",
        "/by-prefix",
        "/api/items/some-id/streaming",
        "/pattern/not-a-number",
    ])
    def test_leaves_a_path_no_rule_names(self, path: str) -> None:
        rules = PathRules(
            exact=frozenset({"/exactly/this"}),
            prefixes=("/by-prefix/",),
            shapes=(PathShape(starts_with="/api/items/", ends_with="/stream"),),
            patterns=(re.compile(r"^/pattern/\d+$"),),
        )

        assert rules.matches(path) is False

    def test_a_rule_that_names_nothing_selects_nothing(self) -> None:
        assert PathRules().matches("/anything") is False


class TestRateLimitPolicy:
    def _policy(self) -> RateLimitPolicy:
        return RateLimitPolicy(
            default=_DEFAULT,
            rules=(
                _BULK_RULE,
                RateLimitRule(paths=PathRules(exact=frozenset({"/feed"})), budget=_UPLOAD),
            ),
            exempt=PathRules(prefixes=("/static/",)),
        )

    @pytest.mark.parametrize(("path", "expected"), [
        ("/bulk/item", _BULK),
        ("/feed", _UPLOAD),
        ("/api/items", _DEFAULT),
        ("/nothing-serves-this", _DEFAULT),
        ("/", _DEFAULT),
    ])
    def test_a_path_spends_from_the_first_matching_rule_else_the_default(
        self, path: str, expected: RateLimitBudget,
    ) -> None:
        assert self._policy().budget_for(path) == expected

    @pytest.mark.parametrize(("rules", "expected"), [
        ((_BULK_RULE, _UPLOAD_RULE), _BULK),
        ((_UPLOAD_RULE, _BULK_RULE), _UPLOAD),
    ], ids=["bulk-first", "upload-first"])
    def test_the_earlier_of_two_overlapping_rules_decides(
        self, rules: tuple[RateLimitRule, ...], expected: RateLimitBudget,
    ) -> None:
        policy = RateLimitPolicy(default=_DEFAULT, rules=rules)

        assert policy.budget_for("/bulk/upload") == expected

    def test_a_policy_without_rules_spends_every_path_from_the_default(self) -> None:
        policy = RateLimitPolicy(default=_DEFAULT)

        assert policy.budget_for("/bulk/item") == _DEFAULT
        assert policy.budget_for("/") == _DEFAULT

    @pytest.mark.parametrize("name", [
        "", "API", "Media", "1a", "-a", "a:b", "a b", "a{b}", "a*", "a/b", "api\n", "ä",
    ])
    def test_a_budget_name_outside_the_grammar_is_refused(self, name: str) -> None:
        with pytest.raises(ValueError, match=re.escape(repr(name))):
            RateLimitBudget(name, max_requests=1, window_seconds=60)

    @pytest.mark.parametrize("name", ["a", "api", "bulk-2", "up_load"])
    def test_a_budget_name_inside_the_grammar_is_accepted(self, name: str) -> None:
        assert RateLimitBudget(name, max_requests=1, window_seconds=60).name == name

    def test_a_budget_name_is_judged_before_its_numbers(self) -> None:
        with pytest.raises(ValueError, match="Rate-limit budget name"):
            RateLimitBudget("API", max_requests=1, window_seconds=0)

    @pytest.mark.parametrize("field", ["max_requests", "window_seconds"])
    @pytest.mark.parametrize("value", [0, -1, True, 1.5, "5", None], ids=[
        "zero", "negative", "bool", "float", "str", "none",
    ])
    def test_a_budget_field_that_is_not_a_positive_whole_number_is_refused_and_named(
        self, field: str, value: object,
    ) -> None:
        fields = {"max_requests": 1, "window_seconds": 60, field: value}

        with pytest.raises(
            ValueError,
            match=re.escape(f"RateLimitBudget 'api' {field} must be a positive whole number"),
        ):
            RateLimitBudget("api", **fields)

    @pytest.mark.parametrize(("max_requests", "window_seconds"), [(1, 1), (300, 3600)])
    def test_a_budget_with_positive_whole_numbers_is_accepted(
        self, max_requests: int, window_seconds: int,
    ) -> None:
        budget = RateLimitBudget("api", max_requests, window_seconds)

        assert (budget.max_requests, budget.window_seconds) == (max_requests, window_seconds)

    @pytest.mark.parametrize(("default", "rules", "expected"), [
        (_DEFAULT, (RateLimitRule(PathRules(), _BULK), RateLimitRule(PathRules(), _BULK)), "bulk"),
        (_DEFAULT, (RateLimitRule(PathRules(), _a_budget("default", 99)),), "default"),
        (_DEFAULT, (RateLimitRule(PathRules(), _DEFAULT),), "default"),
    ], ids=["two-rules", "rule-and-default", "equal-limits"])
    def test_a_repeated_budget_name_is_refused_and_named(
        self, default: RateLimitBudget, rules: tuple[RateLimitRule, ...], expected: str,
    ) -> None:
        with pytest.raises(ValueError, match=rf"repeated: {expected}\."):
            RateLimitPolicy(default=default, rules=rules)


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
            CsrfPolicy(protected=PathRules(prefixes=("/api",))),
            PathRules(prefixes=("/login",)),
            id="prefix-the-origin-check-skips",
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

    @pytest.mark.parametrize("field", ["content_security_policy", "permissions_policy"])
    @pytest.mark.parametrize("outside_the_bound", ["\r", "\n", "\r\n", "\x00", "\x7f", "ä"])
    def test_refuses_a_raw_header_value_outside_visible_ascii_space_and_tab(
        self, field: str, outside_the_bound: str,
    ) -> None:
        fields = {
            "content_security_policy": "default-src 'none'",
            "permissions_policy": "camera=()",
            field: f"camera=(){outside_the_bound}X-Injected: 1",
        }

        with pytest.raises(ValueError, match=field):
            SecurityHeadersPolicy(**fields)

    @pytest.mark.parametrize("field", ["content_security_policy", "permissions_policy"])
    def test_accepts_a_tab_in_a_raw_header_value(self, field: str) -> None:
        value = "camera=()\tmicrophone=()"

        fields = {
            "content_security_policy": "default-src 'none'",
            "permissions_policy": "camera=()",
            field: value,
        }

        policy = SecurityHeadersPolicy(**fields)

        assert getattr(policy, field) == value


THE_DEFAULT_POLICY = (
    "default-src 'none'; "
    "base-uri 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data: blob:; "
    "media-src 'self' blob:; "
    "font-src 'self'; "
    "manifest-src 'self'; "
    "worker-src 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)
A_DIGEST = "abc123+/-_"
ALL_DIRECTIVES = list(CspDirective)


def directive_sources(policy: str, directive: CspDirective) -> str:
    (declaration,) = [d for d in policy.split("; ") if d.startswith(f"{directive} ")]
    return declaration.removeprefix(f"{directive} ")


def styled(sources: object) -> dict[str, object]:
    return {"added_sources": {CspDirective.STYLE_SRC: sources}}


class TestDefaultContentSecurityPolicy:
    @pytest.mark.parametrize("sources", [
        pytest.param(["'nonce-AbC'", "'nonce-abc'"], id="nonces"),
        pytest.param(["https://cdn.example/A", "https://cdn.example/a"], id="host-paths"),
    ])
    def test_sources_whose_case_carries_meaning_stay_apart(self, sources: list[str]) -> None:
        policy = default_content_security_policy(added_sources={CspDirective.SCRIPT_SRC: sources})

        assert set(sources) <= set(directive_sources(policy, CspDirective.SCRIPT_SRC).split(" "))

    @pytest.mark.parametrize(
        "arguments",
        [
            pytest.param({}, id="no-arguments"),
            pytest.param({"script_hashes": []}, id="empty-hashes"),
            pytest.param({"added_sources": None}, id="no-additions"),
        ],
    )
    def test_admits_this_origin_and_nothing_else(self, arguments: dict[str, object]) -> None:
        assert default_content_security_policy(**arguments) == THE_DEFAULT_POLICY  # type: ignore[arg-type]

    def test_holds_no_host_fact(self) -> None:
        assert "google" not in default_content_security_policy()
        assert "unsafe-inline" not in default_content_security_policy()

    @pytest.mark.parametrize(
        "script_hash",
        [
            pytest.param(f"sha256-{A_DIGEST}", id="base64"),
            pytest.param("sha256-ab_c-d", id="base64url"),
            pytest.param("sha512-abc=", id="one-padding"),
            pytest.param("sha384-abc==", id="two-paddings"),
            pytest.param("SHA384-abc==", id="mixed-case-prefix"),
        ],
    )
    def test_admits_a_named_inline_script_by_hash_as_spelled(self, script_hash: str) -> None:
        policy = default_content_security_policy(["sha256-one", script_hash])

        assert directive_sources(policy, CspDirective.SCRIPT_SRC) == (
            f"'self' 'sha256-one' '{script_hash}'"
        )

    @pytest.mark.parametrize(
        "script_hash",
        [
            pytest.param("sha256-a;b", id="semicolon"),
            pytest.param("sha256-a b", id="space"),
            pytest.param("sha256-a\tb", id="tab"),
            pytest.param("'sha256-abc'", id="quoted"),
            pytest.param("sha256-a'b", id="quote"),
            pytest.param("sha256-a\r\nb", id="crlf"),
            pytest.param("md5-abc", id="other-algorithm"),
            pytest.param("sha256-", id="empty-payload"),
            pytest.param("sha256-abc===", id="three-paddings"),
            pytest.param("sha256-ab!c", id="character-outside-the-alphabet"),
            pytest.param("sha256-äbc", id="non-ascii"),
            pytest.param("ſha256-abc", id="long-s-folds-to-s"),
            pytest.param("sha256-\u212a", id="kelvin-sign-in-payload"),
            pytest.param("", id="empty"),
        ],
    )
    def test_refuses_a_script_hash_outside_the_grammar(self, script_hash: str) -> None:
        with pytest.raises(ValueError, match="script-src"):
            default_content_security_policy([script_hash])

    def test_refuses_a_script_hash_that_would_add_a_directive(self) -> None:
        with pytest.raises(ValueError, match="script-src"):
            default_content_security_policy(["x'; style-src *; '"])

    @pytest.mark.parametrize(
        "source",
        [
            *(pytest.param(f"'{keyword}'", id=keyword) for keyword in (
                "self", "unsafe-inline", "unsafe-eval", "strict-dynamic", "unsafe-hashes",
                "report-sample", "unsafe-allow-redirects", "wasm-unsafe-eval",
            )),
            pytest.param(f"'nonce-{A_DIGEST}'", id="nonce"),
            pytest.param("'NONCE-ab_c-d=='", id="mixed-case-nonce"),
            pytest.param("'SELF'", id="upper-case-keyword"),
            pytest.param("'trusted-types-eval'", id="keyword-outside-the-old-subset"),
            pytest.param("'none'", id="none"),
            pytest.param("'sha256-abc'", id="sha256"),
            pytest.param("'sha384-abc='", id="sha384-padded"),
            pytest.param("'sha512-abc=='", id="sha512-padded"),
            pytest.param("data:", id="data-scheme"),
            pytest.param("https:", id="https-scheme"),
            pytest.param("https://cdn.example.test", id="origin"),
            pytest.param("*.example.test", id="wildcard-subdomain"),
            pytest.param("*", id="wildcard-host"),
            pytest.param("example.test:8443/path", id="port-and-path"),
            pytest.param("https://example.test:*", id="wildcard-port"),
            pytest.param("example.test/a%20b", id="percent-escape"),
            pytest.param("example.test/", id="root-path"),
            pytest.param("example.test/a//b", id="empty-later-path-segment"),
            pytest.param("https://example.test.", id="trailing-dot-origin"),
            pytest.param("*.example.test.", id="trailing-dot-wildcard"),
            pytest.param("example.test.:8443/p", id="trailing-dot-port-and-path"),
        ],
    )
    def test_appends_a_valid_added_source_verbatim(self, source: str) -> None:
        policy = default_content_security_policy(
            added_sources={CspDirective.CONNECT_SRC: [source]},
        )

        assert directive_sources(policy, CspDirective.CONNECT_SRC).split(" ") == list(
            dict.fromkeys(["'self'", source]),
        )

    @pytest.mark.parametrize(
        "source",
        [
            pytest.param("", id="empty"),
            pytest.param("a b", id="space"),
            pytest.param("https://a.example *", id="two-sources"),
            pytest.param("a;b", id="semicolon"),
            pytest.param("a,b", id="comma"),
            pytest.param("x\r\n", id="crlf"),
            pytest.param("a\tb", id="tab"),
            pytest.param("a\x00b", id="nul"),
            pytest.param("a\x7fb", id="del"),
            pytest.param("https://例え.jp", id="non-ascii-host"),
            pytest.param("x; script-src *", id="injected-directive"),
        ],
    )
    @pytest.mark.parametrize("directive", ALL_DIRECTIVES)
    def test_refuses_an_added_source_that_is_not_one_ascii_token_naming_the_directive(
        self, directive: CspDirective, source: str,
    ) -> None:
        with pytest.raises(ValueError, match=f"{directive}.*one token"):
            default_content_security_policy(added_sources={directive: [source]})

    def test_adds_a_style_source_and_leaves_every_other_directive_alone(self) -> None:
        policy = default_content_security_policy(
            added_sources={CspDirective.STYLE_SRC: ["'unsafe-inline'"]},
        )

        assert policy == THE_DEFAULT_POLICY.replace(
            "style-src 'self'", "style-src 'self' 'unsafe-inline'",
        )

    def test_keeps_the_default_directive_order_whatever_the_mapping_order(self) -> None:
        policy = default_content_security_policy(
            added_sources={
                CspDirective.FONT_SRC: ["fonts.example.test"],
                CspDirective.STYLE_SRC: ["styles.example.test"],
            },
        )

        assert policy == (
            THE_DEFAULT_POLICY
            .replace("style-src 'self'", "style-src 'self' styles.example.test")
            .replace("font-src 'self'", "font-src 'self' fonts.example.test")
        )

    def test_a_framing_parent_replaces_none_in_frame_ancestors(self) -> None:
        policy = default_content_security_policy(
            added_sources={
                CspDirective.FRAME_ANCESTORS: ["'self'", "https://parent.example.test"],
            },
        )

        assert directive_sources(policy, CspDirective.FRAME_ANCESTORS) == (
            "'self' https://parent.example.test"
        )

    @pytest.mark.parametrize(
        ("added", "expected"),
        [
            (["https://id.example.test"], "'self' https://id.example.test"),
            (["https:"], "'self' https:"),
            (["'self'"], "'self'"),
        ],
    )
    def test_an_added_form_target_extends_self_in_form_action(
        self,
        added: list[str],
        expected: str,
    ) -> None:
        policy = default_content_security_policy(
            added_sources={CspDirective.FORM_ACTION: added},
        )

        assert policy == THE_DEFAULT_POLICY.replace("form-action 'self'", f"form-action {expected}")

    @pytest.mark.parametrize("directive", ALL_DIRECTIVES)
    def test_an_empty_addition_changes_nothing(self, directive: CspDirective) -> None:
        assert default_content_security_policy(added_sources={directive: []}) == THE_DEFAULT_POLICY

    @pytest.mark.parametrize(
        ("hashes", "added", "expected"),
        [
            pytest.param([], ["a.test", "a.test"], "'self' a.test", id="duplicate-addition"),
            pytest.param([], ["'self'", "a.test"], "'self' a.test", id="duplicate-of-default"),
            pytest.param(
                ["sha256-abc"], ["'sha256-abc'", "a.test"], "'self' 'sha256-abc' a.test",
                id="hash-given-twice",
            ),
        ],
    )
    def test_lists_a_source_once_at_its_first_position(
        self, hashes: list[str], added: list[str], expected: str,
    ) -> None:
        policy = default_content_security_policy(
            hashes, added_sources={CspDirective.SCRIPT_SRC: added},
        )

        assert directive_sources(policy, CspDirective.SCRIPT_SRC) == expected

    def test_refuses_a_plain_string_for_a_directive(self) -> None:
        with pytest.raises(TypeError, match="CspDirective"):
            default_content_security_policy(
                added_sources={"style-src": ["'unsafe-inline'"]},  # type: ignore[dict-item]
            )

    @pytest.mark.parametrize(
        "kwargs, owner",
        [
            pytest.param(styled("'unsafe-inline'"), "style-src", id="str"),
            pytest.param(styled(b"x"), "style-src", id="bytes"),
            pytest.param(styled(b""), "style-src", id="empty-bytes"),
            pytest.param(styled(""), "style-src", id="empty-str"),
            pytest.param(styled(5), "style-src", id="not-a-sequence"),
            pytest.param({"script_hashes": "sha256-abc"}, "script-src", id="hashes-str"),
            pytest.param(
                {"added_sources": {CspDirective.STYLE_SRC: bytearray()}},
                "style-src",
                id="empty-bytearray",
            ),
            pytest.param(
                {"added_sources": {CspDirective.STYLE_SRC: memoryview(b"")}},
                "style-src",
                id="empty-memoryview",
            ),
            pytest.param({"script_hashes": b""}, "script-src", id="hashes-empty-bytes"),
            pytest.param(
                {"added_sources": [(CspDirective.STYLE_SRC, [])]},
                "Mapping",
                id="not-a-mapping",
            ),
            pytest.param(styled([None]), "style-src", id="none-element"),
            pytest.param(styled([b"x"]), "style-src", id="bytes-element"),
            pytest.param({"script_hashes": [b"sha256-abc"]}, "script-src", id="bytes-hash"),
        ],
    )
    def test_refuses_a_wrong_type_with_a_type_error(
        self, kwargs: dict[str, object], owner: str,
    ) -> None:
        with pytest.raises(TypeError, match=owner):
            default_content_security_policy(**kwargs)  # type: ignore[arg-type]

    def test_leaves_the_callers_mapping_and_lists_unchanged(self) -> None:
        hashes = ["sha256-abc"]
        styles = ["'unsafe-inline'", "'unsafe-inline'"]
        added = {CspDirective.STYLE_SRC: styles}

        default_content_security_policy(hashes, added_sources=added)

        assert (hashes, added) == (["sha256-abc"], {CspDirective.STYLE_SRC: styles})
        assert styles == ["'unsafe-inline'", "'unsafe-inline'"]
