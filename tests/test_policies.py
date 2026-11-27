"""The request policies: what each one decides about a path, method, or budget."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from dataclasses import replace
from functools import partial
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tests.support.gated_stack_arrangement import install_the_gated_stack
from tests.support.session_store_arrangement import SessionRecordsInMemory
from tests.support.webauth_arrangement import a_web_auth_config
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    ContentSecurityPolicyRule,
    PathRules,
    PathShape,
    PublicRule,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)


def _a_budget(name: str, max_requests: int = 10) -> RateLimitBudget:
    return RateLimitBudget(name, max_requests=max_requests, window_seconds=60)


_DEFAULT = _a_budget("default")
_BULK = _a_budget("bulk")
_UPLOAD = _a_budget("upload")
_BULK_RULE = RateLimitRule(paths=PathRules(prefixes=("/bulk/",)), budget=_BULK)
_UPLOAD_RULE = RateLimitRule(paths=PathRules(prefixes=("/bulk/up",)), budget=_UPLOAD)


class TestPathRules:
    @pytest.mark.parametrize(
        "path",
        [
            "/exactly/this",
            "/by-prefix/anything",
            "/api/items/some-id/stream",
            "/pattern/42",
        ],
    )
    def test_selects_a_path_named_any_of_the_four_ways(self, path: str) -> None:
        rules = PathRules(
            exact=frozenset({"/exactly/this"}),
            prefixes=("/by-prefix/",),
            shapes=(PathShape(starts_with="/api/items/", ends_with="/stream"),),
            patterns=(re.compile(r"^/pattern/\d+$"),),
        )

        assert rules.matches(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "/exactly/this/plus-more",
            "/by-prefix",
            "/api/items/some-id/streaming",
            "/pattern/not-a-number",
        ],
    )
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

    def test_a_single_string_for_exact_is_refused(self) -> None:
        with pytest.raises(ValueError, match=r"PathRules\.exact"):
            PathRules(exact="/hooks/stripe")  # type: ignore[arg-type]

    @pytest.mark.parametrize(("path", "expected"), [("/hooks/stripe", True), ("/", False)])
    def test_a_frozenset_of_one_path_selects_that_path_only(
        self,
        path: str,
        expected: bool,
    ) -> None:
        assert PathRules(exact=frozenset({"/hooks/stripe"})).matches(path) is expected

    def test_a_single_string_for_prefixes_stays_a_whole_prefix(self) -> None:
        assert PathRules(prefixes="/hooks/").matches("/hooks/stripe") is True  # type: ignore[arg-type]
        assert PathRules(prefixes="/hooks/").matches("/") is False  # type: ignore[arg-type]


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

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("/bulk/item", _BULK),
            ("/feed", _UPLOAD),
            ("/api/items", _DEFAULT),
            ("/nothing-serves-this", _DEFAULT),
            ("/", _DEFAULT),
        ],
    )
    def test_a_path_spends_from_the_first_matching_rule_else_the_default(
        self,
        path: str,
        expected: RateLimitBudget,
    ) -> None:
        assert self._policy().budget_for(path) == expected

    @pytest.mark.parametrize(
        ("rules", "expected"),
        [
            ((_BULK_RULE, _UPLOAD_RULE), _BULK),
            ((_UPLOAD_RULE, _BULK_RULE), _UPLOAD),
        ],
        ids=["bulk-first", "upload-first"],
    )
    def test_the_earlier_of_two_overlapping_rules_decides(
        self,
        rules: tuple[RateLimitRule, ...],
        expected: RateLimitBudget,
    ) -> None:
        policy = RateLimitPolicy(default=_DEFAULT, rules=rules)

        assert policy.budget_for("/bulk/upload") == expected

    def test_a_policy_without_rules_spends_every_path_from_the_default(self) -> None:
        policy = RateLimitPolicy(default=_DEFAULT)

        assert policy.budget_for("/bulk/item") == _DEFAULT
        assert policy.budget_for("/") == _DEFAULT

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "API",
            "Media",
            "1a",
            "-a",
            "a:b",
            "a b",
            "a{b}",
            "a*",
            "a/b",
            "api\n",
            "ä",
        ],
    )
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
    @pytest.mark.parametrize(
        "value",
        [0, -1, True, 1.5, "5", None],
        ids=[
            "zero",
            "negative",
            "bool",
            "float",
            "str",
            "none",
        ],
    )
    def test_a_budget_field_that_is_not_a_positive_whole_number_is_refused_and_named(
        self,
        field: str,
        value: object,
    ) -> None:
        fields = {"max_requests": 1, "window_seconds": 60, field: value}

        with pytest.raises(
            ValueError,
            match=re.escape(f"RateLimitBudget 'api' {field} must be a positive whole number"),
        ):
            RateLimitBudget("api", **fields)

    @pytest.mark.parametrize(("max_requests", "window_seconds"), [(1, 1), (300, 3600)])
    def test_a_budget_with_positive_whole_numbers_is_accepted(
        self,
        max_requests: int,
        window_seconds: int,
    ) -> None:
        budget = RateLimitBudget("api", max_requests, window_seconds)

        assert (budget.max_requests, budget.window_seconds) == (max_requests, window_seconds)

    @pytest.mark.parametrize(
        ("default", "rules", "expected"),
        [
            (
                _DEFAULT,
                (RateLimitRule(PathRules(), _BULK), RateLimitRule(PathRules(), _BULK)),
                "bulk",
            ),
            (_DEFAULT, (RateLimitRule(PathRules(), _a_budget("default", 99)),), "default"),
            (_DEFAULT, (RateLimitRule(PathRules(), _DEFAULT),), "default"),
        ],
        ids=["two-rules", "rule-and-default", "equal-limits"],
    )
    def test_a_repeated_budget_name_is_refused_and_named(
        self,
        default: RateLimitBudget,
        rules: tuple[RateLimitRule, ...],
        expected: str,
    ) -> None:
        with pytest.raises(ValueError, match=rf"repeated: {expected}\."):
            RateLimitPolicy(default=default, rules=rules)


METHOD_RULES = [PublicRule, partial(BodySizeRule, max_bytes=1)]
A_PATH = PathRules(exact=frozenset({"/x"}))


@pytest.mark.parametrize("rule", METHOD_RULES)
class TestAMethodsFieldRefusesASingleString:
    @pytest.mark.parametrize("methods", ["POST", "XPOST"])
    def test_a_single_string_is_refused(self, rule: Callable[..., Any], methods: str) -> None:
        with pytest.raises(ValueError, match="methods"):
            rule(A_PATH, methods=methods)

    @pytest.mark.parametrize(
        "methods",
        [frozenset({"post"}), frozenset({"GET", "Post"}), frozenset({""}), frozenset({"PO ST"})],
        ids=["lower-case", "mixed-case", "empty", "space"],
    )
    def test_a_method_that_is_not_an_upper_case_token_is_refused(
        self,
        rule: Callable[..., Any],
        methods: frozenset[str],
    ) -> None:
        with pytest.raises(ValueError, match=r"methods must hold only upper-case"):
            rule(A_PATH, methods=methods)

    @pytest.mark.parametrize(
        ("methods", "applies_to_get"),
        [(frozenset({"POST"}), False), (None, True)],
    )
    def test_a_frozenset_or_none_is_accepted_and_selects_its_methods(
        self,
        rule: Callable[..., Any],
        methods: frozenset[str] | None,
        applies_to_get: bool,
    ) -> None:
        accepted = rule(A_PATH, methods=methods)

        assert accepted.applies_to("/x", "POST") is True
        assert accepted.applies_to("/x", "GET") is applies_to_get

    def test_a_lower_case_request_method_matches_no_selected_method(
        self,
        rule: Callable[..., Any],
    ) -> None:
        assert rule(A_PATH, methods=frozenset({"POST"})).applies_to("/x", "post") is False


class TestBodySizePolicy:
    def _policy(self) -> BodySizePolicy:
        return BodySizePolicy(
            default_max_bytes=1_000,
            rules=(
                BodySizeRule(
                    paths=PathRules(exact=frozenset({"/upload"})),
                    max_bytes=50_000,
                ),
                BodySizeRule(
                    paths=PathRules(exact=frozenset({"/cover"})),
                    max_bytes=9_000,
                    methods=frozenset({"POST"}),
                ),
            ),
        )

    @pytest.mark.parametrize(
        ("path", "method", "expected"),
        [
            ("/upload", "POST", 50_000),
            ("/cover", "POST", 9_000),
            ("/cover", "post", 1_000),
            ("/cover", "PUT", 1_000),
            ("/songs", "POST", 1_000),
            ("/upload", "", 50_000),
        ],
    )
    def test_a_route_gets_its_own_budget_and_every_other_the_default(
        self,
        path: str,
        method: str,
        expected: int,
    ) -> None:
        assert self._policy().max_bytes(path, method) == expected

    @pytest.mark.parametrize("seconds", [0, -1.5, math.nan, math.inf])
    def test_a_start_send_bound_that_is_not_a_positive_finite_number_is_refused(
        self,
        seconds: float,
    ) -> None:
        with pytest.raises(ValueError, match="start_send_seconds"):
            BodySizePolicy(default_max_bytes=1_000, start_send_seconds=seconds)


RAW_HEADER_VALUE_FIELDS = [
    "content_security_policy",
    "permissions_policy",
    "CacheControlRule.value",
    "ContentSecurityPolicyRule.value",
]


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

    @pytest.mark.parametrize(
        ("policy", "expected"),
        [
            pytest.param(
                SecurityHeadersPolicy(content_security_policy="default-src 'none'"),
                "camera=(), microphone=(), geolocation=(), display-capture=()",
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
                "camera=(), microphone=(), geolocation=(), display-capture=()",
                id="two-positional-arguments",
            ),
        ],
    )
    def test_every_response_answers_the_policy_permissions(
        self,
        policy: SecurityHeadersPolicy,
        expected: str,
    ) -> None:
        """STACK-07: the default header turns off display-capture with the other features."""
        app = FastAPI()
        app.get("/")(lambda: {})
        install_the_gated_stack(
            app,
            config=a_web_auth_config(),
            sessions=SessionRecordsInMemory().in_transaction,
            security_headers=policy,
        )

        response = TestClient(app).get("/")

        assert response.headers["Permissions-Policy"] == expected

    @pytest.mark.parametrize("field", RAW_HEADER_VALUE_FIELDS)
    @pytest.mark.parametrize(
        "refused",
        [
            "camera=()\rX-Injected: 1",
            "camera=()\nX-Injected: 1",
            "camera=()\r\nX-Injected: 1",
            "camera=()\x00",
            "camera=()\x7f",
            "camera=()ä",
            " camera=()",
            "\tcamera=()",
            "camera=() ",
            "camera=()\t",
            "",
            " ",
        ],
    )
    def test_refuses_an_empty_edged_control_or_non_ascii_raw_header_value(
        self,
        field: str,
        refused: str,
    ) -> None:
        with pytest.raises(ValueError, match=field):
            a_policy_with_raw_header_value(field, refused)

    @pytest.mark.parametrize("field", RAW_HEADER_VALUE_FIELDS)
    @pytest.mark.parametrize("value", ["camera=()\tmicrophone=()", "no-store, no-cache", "a"])
    def test_accepts_an_inner_space_or_tab_in_a_raw_header_value(
        self,
        field: str,
        value: str,
    ) -> None:
        policy = a_policy_with_raw_header_value(field, value)

        assert raw_header_value(policy, field) == value


def a_policy_with_raw_header_value(field: str, value: str) -> SecurityHeadersPolicy:
    if field == "CacheControlRule.value":
        rule = CacheControlRule(paths=PathRules(prefixes=("/",)), value=value)
        return SecurityHeadersPolicy("default-src 'none'", cache_control_rules=(rule,))
    if field == "ContentSecurityPolicyRule.value":
        csp_rule = ContentSecurityPolicyRule(paths=PathRules(prefixes=("/",)), value=value)
        return SecurityHeadersPolicy(
            "default-src 'none'",
            content_security_policy_rules=(csp_rule,),
        )
    policy = SecurityHeadersPolicy("default-src 'none'", permissions_policy="camera=()")
    return replace(policy, **{field: value})


def raw_header_value(policy: SecurityHeadersPolicy, field: str) -> str | None:
    if field == "CacheControlRule.value":
        return policy.cache_control("/")
    if field == "ContentSecurityPolicyRule.value":
        return policy.content_security_policy_for("/")
    return getattr(policy, field)
