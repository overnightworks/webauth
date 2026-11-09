"""The rules the installer derives from the sign-in paths for gate, budgets, cache and CSRF.

Each case drives a FastAPI host through a `TestClient` over a stateful fake issuer.
"""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.responses import Response

from tests.support.oidc_arrangement import FakeIssuer, a_relying_party
from tests.support.oidc_login_host import (
    ADMISSION,
    BACKCHANNEL_LOGOUT_PATH,
    CALLBACK_PATH,
    LOGOUT_PATH,
    SAME_ORIGIN_FORM,
    SIGN_IN_PATHS,
    START_PATH,
)
from tests.support.webauth_arrangement import (
    HTTPS_TEST_SERVER,
    SessionRecordsInMemory,
    a_web_auth_config,
)
from webauth.config import install_web_auth_config
from webauth.middleware import SessionGate, install_web_auth_middleware
from webauth.policies import (
    BodySizePolicy,
    BodySizeRule,
    CacheControlRule,
    CsrfPolicy,
    PathRules,
    RateLimitBudget,
    RateLimitPolicy,
    RateLimitRule,
    SecurityHeadersPolicy,
)
from webauth.ports import SignInStores
from webauth.sign_in_routes import (
    LogoutPageText,
    SignInPaths,
    install_sign_in_routes,
)

FORM_HEADER = {"content-type": SAME_ORIGIN_FORM["content-type"]}
HEADERS_POLICY = SecurityHeadersPolicy(content_security_policy="default-src 'self'")
FOUR_KIB = 4 * 1024
THIRTY_TWO_KIB = 32 * 1024
SIGN_IN_BUDGET_NAME = "sign-in"


@dataclass
class GatedHost:
    client: TestClient
    issuer: FakeIssuer


def _a_gated_host(
    *,
    sign_in_paths: SignInPaths = SIGN_IN_PATHS,
    gated: bool = True,
    security_headers: SecurityHeadersPolicy = HEADERS_POLICY,
    body_size: BodySizePolicy | None = None,
    rate_limit: RateLimitPolicy | None = None,
) -> GatedHost:
    """A host the installer wires from its sign-in paths and the policies it passes."""
    config = a_web_auth_config()
    sessions = SessionRecordsInMemory()
    issuer = FakeIssuer(mint_id_token=lambda _nonce: "unused")
    relying_party = a_relying_party(post_token_request=issuer)
    app = FastAPI()
    install_web_auth_config(app, config)
    install_web_auth_middleware(
        app,
        sign_in_paths=sign_in_paths,
        security_headers=security_headers,
        body_size=body_size,
        rate_limit=rate_limit,
        csrf_origin=CsrfPolicy(),
        session_gate=SessionGate(
            session_transaction=sessions.in_transaction,
            login_redirect=sign_in_paths.login_redirect,
            public=(),
        )
        if gated
        else None,
    )
    install_sign_in_routes(
        app,
        paths=SIGN_IN_PATHS,
        relying_party=lambda _request: relying_party,
        admission=ADMISSION,
        transaction=_a_transaction_nobody_enters,
        refused=lambda _request, _refusal: Response(status_code=403),
        keeps_id_token=True,
        max_sessions=None,
        logout_page_text=lambda _request: LogoutPageText(language="en", button_label="Sign out"),
    )

    @app.get("/albums/{album_id}")
    def album(album_id: str) -> str:
        return album_id

    @app.post("/albums/{album_id}")
    def post_album(album_id: str) -> str:
        return album_id

    return GatedHost(
        TestClient(app, base_url=HTTPS_TEST_SERVER, follow_redirects=False),
        issuer,
    )


def _a_transaction_nobody_enters() -> AbstractContextManager[SignInStores]:
    raise AssertionError("the gated host never signs anyone in")


def _statuses_of_gets(host: GatedHost, path: str, count: int) -> list[int]:
    return [host.client.get(path).status_code for _ in range(count)]


def _backchannel_post(host: GatedHost, size: int = 0) -> int:
    body = b"logout_token=" + b"x" * max(size - len(b"logout_token="), 0)
    return host.client.post(BACKCHANNEL_LOGOUT_PATH, content=body, headers=FORM_HEADER).status_code


def test_the_installer_is_refused_without_sign_in_paths() -> None:
    """SIGNIN-67: the installer requires `sign_in_paths`."""
    app = FastAPI()
    csrf_origin = CsrfPolicy()

    with pytest.raises(TypeError, match="sign_in_paths"):
        install_web_auth_middleware(  # type: ignore[call-arg]
            app,
            security_headers=HEADERS_POLICY,
            csrf_origin=csrf_origin,
        )


def test_a_signed_out_page_is_sent_to_start() -> None:
    """SIGNIN-09: `login_redirect` sends a signed-out page to the start path."""
    host = _a_gated_host()

    start = host.client.get(START_PATH)
    deep_link = host.client.get("/albums/42", headers={"accept": "text/html"})

    assert start.status_code == 303
    assert (deep_link.status_code, deep_link.headers["location"]) == (
        302,
        f"{START_PATH}?next=%2Falbums%2F42",
    )


def test_a_signed_out_logout_passes_the_gate_and_enters_no_transaction() -> None:
    host = _a_gated_host()

    response = host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM)

    assert response.status_code == 200


@pytest.mark.parametrize(
    "host_cache_rules",
    [
        pytest.param((), id="no host cache rule"),
        pytest.param(
            (CacheControlRule(PathRules(prefixes=("/",)), "public, max-age=60"),),
            id="a host rule over every path",
        ),
    ],
)
def test_the_sign_in_paths_answer_no_store_ahead_of_the_hosts_cache_rules(
    host_cache_rules: tuple[CacheControlRule, ...],
) -> None:
    """SIGNIN-08: the installer marks the answers of all four routes `no-store`, first."""
    host = _a_gated_host(
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=host_cache_rules,
        ),
    )

    answers = [
        host.client.get(START_PATH),
        host.client.get(CALLBACK_PATH),
        host.client.post(LOGOUT_PATH, headers=FORM_HEADER),
        host.client.post(BACKCHANNEL_LOGOUT_PATH, content=b"logout_token=x", headers=FORM_HEADER),
    ]

    assert answers[-2].status_code == 403
    assert answers[-1].status_code == 400
    assert [answer.headers["cache-control"] for answer in answers] == ["no-store"] * 4


def test_a_host_rule_keeps_deciding_the_paths_the_sign_in_paths_do_not_name() -> None:
    host = _a_gated_host(
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=(
                CacheControlRule(PathRules(prefixes=("/",)), "public, max-age=60"),
            ),
        ),
    )

    assert host.client.get("/albums/1").headers["cache-control"] == "public, max-age=60"


def test_the_forty_first_sign_in_request_in_ten_minutes_is_refused_without_a_host_policy() -> None:
    """SIGNIN-04: start, callback and logout spend one sign-in budget of 40 per 10 minutes."""
    host = _a_gated_host()

    statuses = _statuses_of_gets(host, START_PATH, 41)

    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]


def test_the_other_paths_spend_the_default_budget_of_600_per_minute_without_a_host_policy() -> None:
    """STACK-05: a rate limit of 600 per 60 seconds is installed when the host passes none."""
    host = _a_gated_host()

    statuses = _statuses_of_gets(host, "/albums/1", 601)

    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]
    assert host.client.get(START_PATH).status_code == 303


def test_a_sign_in_flood_does_not_spend_the_budget_of_the_other_paths() -> None:
    host = _a_gated_host()
    _statuses_of_gets(host, START_PATH, 41)

    assert host.client.get("/albums/1").status_code != 429


def test_a_host_rate_policy_decides_the_rest_and_the_sign_in_budget_comes_first() -> None:
    """SIGNIN-68: the sign-in budget is the first rate rule, ahead of the host's own."""
    host = _a_gated_host(
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget("host", 2, 60),
            rules=(
                RateLimitRule(PathRules(prefixes=("/",)), RateLimitBudget("everything", 1, 60)),
            ),
        ),
    )

    assert _statuses_of_gets(host, START_PATH, 3) == [303, 303, 303]
    assert _statuses_of_gets(host, "/albums/1", 2)[-1] == 429


def test_a_host_sign_in_budget_applies_on_the_sign_in_paths() -> None:
    """SIGNIN-69: a host policy may set another sign-in budget."""
    host = _a_gated_host(
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget("host", 1000, 60),
            sign_in=RateLimitBudget(SIGN_IN_BUDGET_NAME, 3, 60),
        ),
    )

    statuses = _statuses_of_gets(host, START_PATH, 4)

    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]
    assert 429 not in _statuses_of_gets(host, "/albums/1", 4)


_DEFAULT_SIGN_IN_BUDGET = RateLimitPolicy(default=RateLimitBudget("host", 5, 60)).sign_in


@pytest.mark.parametrize(
    ("default", "rules"),
    [
        pytest.param(RateLimitBudget(SIGN_IN_BUDGET_NAME, 5, 60), (), id="as the default"),
        pytest.param(
            RateLimitBudget("host", 5, 60),
            (
                RateLimitRule(
                    PathRules(prefixes=("/api/",)), RateLimitBudget(SIGN_IN_BUDGET_NAME, 5, 60)
                ),
            ),
            id="as a rule",
        ),
        pytest.param(
            _DEFAULT_SIGN_IN_BUDGET,
            (),
            id="the default sign-in budget as the default",
        ),
        pytest.param(
            RateLimitBudget("host", 5, 60),
            (RateLimitRule(PathRules(prefixes=("/api/",)), _DEFAULT_SIGN_IN_BUDGET),),
            id="the default sign-in budget as a rule",
        ),
    ],
)
def test_a_host_budget_under_the_reserved_sign_in_name_fails_at_construction(
    default: RateLimitBudget,
    rules: tuple[RateLimitRule, ...],
) -> None:
    """SIGNIN-70: the name is reserved."""
    with pytest.raises(ValueError, match=SIGN_IN_BUDGET_NAME):
        RateLimitPolicy(default=default, rules=rules)


def test_the_back_channel_is_exempt_from_the_rate_limit_and_from_csrf() -> None:
    """SIGNIN-05, SIGNIN-06: the back-channel post spends no budget and needs no Origin."""
    host = _a_gated_host(
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget("host", 1, 60),
            sign_in=RateLimitBudget(SIGN_IN_BUDGET_NAME, 1, 60),
        ),
    )

    statuses = [_backchannel_post(host) for _ in range(4)]

    assert statuses == [400] * 4
    assert host.client.get(START_PATH).status_code == 303


def test_logout_is_never_exempt_from_csrf_or_the_rate_limit() -> None:
    """SIGNIN-43, SIGNIN-44: logout is never exempt."""
    host = _a_gated_host(
        rate_limit=RateLimitPolicy(
            default=RateLimitBudget("host", 1000, 60),
            sign_in=RateLimitBudget(SIGN_IN_BUDGET_NAME, 1, 60),
        ),
    )

    without_origin = host.client.post(LOGOUT_PATH, headers=FORM_HEADER)
    first = host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM)
    second = host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM)

    assert (without_origin.status_code, first.status_code, second.status_code) == (403, 429, 429)


@pytest.mark.parametrize(
    "body_size",
    [
        pytest.param(None, id="no host body policy"),
        pytest.param(
            BodySizePolicy(
                default_max_bytes=1024,
                rules=(BodySizeRule(PathRules(prefixes=("/",)), 100, methods=frozenset({"POST"})),),
            ),
            id="a host rule over every path",
        ),
    ],
)
def test_the_back_channel_takes_a_32_kib_post_whatever_the_host_body_policy_says(
    body_size: BodySizePolicy | None,
) -> None:
    """SIGNIN-07: the back-channel rule of 32 KiB comes ahead of the host's rules."""
    host = _a_gated_host(body_size=body_size)

    assert _backchannel_post(host, THIRTY_TWO_KIB) == 400
    assert _backchannel_post(host, THIRTY_TWO_KIB + 1) == 413


def test_a_body_over_4_kib_is_refused_without_a_host_body_policy() -> None:
    """STACK-06: a body limit of 4 KiB applies when the host passes none."""
    host = _a_gated_host()

    at_the_limit = host.client.post("/albums/1", content=b"x" * FOUR_KIB, headers=SAME_ORIGIN_FORM)
    over = host.client.post("/albums/1", content=b"x" * (FOUR_KIB + 1), headers=SAME_ORIGIN_FORM)

    assert at_the_limit.status_code != 413
    assert over.status_code == 413


def test_a_host_body_policy_decides_the_paths_the_back_channel_rule_does_not_name() -> None:
    host = _a_gated_host(body_size=BodySizePolicy(default_max_bytes=1024))

    within = host.client.post("/albums/1", content=b"x" * 1024, headers=SAME_ORIGIN_FORM)
    over = host.client.post("/albums/1", content=b"x" * 1025, headers=SAME_ORIGIN_FORM)

    assert (within.status_code, over.status_code) == (401, 413)


@pytest.mark.parametrize(
    ("method", "path", "reaches_the_route"),
    [
        pytest.param("GET", START_PATH, True, id="get start"),
        pytest.param("POST", START_PATH, False, id="post start"),
        pytest.param("GET", CALLBACK_PATH, True, id="get callback"),
        pytest.param("POST", CALLBACK_PATH, False, id="post callback"),
        pytest.param("POST", LOGOUT_PATH, True, id="post logout"),
        pytest.param("GET", LOGOUT_PATH, False, id="get logout"),
        pytest.param("POST", BACKCHANNEL_LOGOUT_PATH, True, id="post back-channel"),
        pytest.param("GET", BACKCHANNEL_LOGOUT_PATH, False, id="get back-channel"),
    ],
)
def test_a_signed_out_browser_reaches_exactly_four_methods_of_the_sign_in_paths(
    method: str,
    path: str,
    *,
    reaches_the_route: bool,
) -> None:
    """SIGNIN-03: the installer opens `GET` of start and callback and `POST` of logout and
    back-channel to the session gate, and no other method."""
    host = _a_gated_host()

    response = host.client.request(method, path, headers=SAME_ORIGIN_FORM)

    assert (response.status_code == 401) is not reaches_the_route


def test_without_a_session_gate_a_signed_out_request_reaches_any_route() -> None:
    host = _a_gated_host(gated=False)

    assert host.client.get("/albums/1").status_code == 200


def test_sign_in_paths_with_start_and_callback_only_derive_no_logout_or_back_channel_rule() -> None:
    """SIGNIN-71: a route the paths do not name gets no rule."""
    host = _a_gated_host(sign_in_paths=SignInPaths(start=START_PATH, callback=CALLBACK_PATH))

    forged_logout = host.client.post(LOGOUT_PATH, headers=FORM_HEADER)
    signed_out_logout = host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM)
    forged_back_channel = host.client.post(BACKCHANNEL_LOGOUT_PATH, headers=FORM_HEADER)

    assert (
        forged_logout.status_code,
        signed_out_logout.status_code,
        forged_back_channel.status_code,
    ) == (403, 401, 403)
    assert "cache-control" not in signed_out_logout.headers


@pytest.mark.parametrize(
    "derived_name",
    [
        "browser_paths",
        "backchannel",
        "backchannel_body_size_rule",
        "cache_control_rule",
        "public_rules",
    ],
)
def test_the_rules_the_installer_applies_are_no_attribute_of_the_sign_in_paths(
    derived_name: str,
) -> None:
    assert not hasattr(SIGN_IN_PATHS, derived_name)


_VALID_PATHS = {
    "start": "/login",
    "callback": "/callback",
    "logout": "/logout",
    "backchannel_logout": "/backchannel",
}


@pytest.mark.parametrize(
    "override",
    [
        pytest.param({"start": "login"}, id="a relative start"),
        pytest.param({"callback": "callback"}, id="a relative callback"),
        pytest.param({"logout": "logout"}, id="a relative logout"),
        pytest.param({"backchannel_logout": "backchannel"}, id="a relative back-channel"),
        pytest.param({"start": "//evil.example/login"}, id="a start another host serves"),
        pytest.param({"callback": "/\\evil.example"}, id="a callback another host serves"),
        pytest.param({"callback": "/\t/evil.example"}, id="a callback a browser strips"),
        pytest.param({"logout": "//evil.example/logout"}, id="a logout another host serves"),
        pytest.param(
            {"backchannel_logout": "//evil.example/back"},
            id="a back-channel another host serves",
        ),
        pytest.param({"start": "/a/../login"}, id="a dot segment in start"),
        pytest.param({"callback": "/a/%2e%2e/callback"}, id="an encoded dot segment"),
        pytest.param({"logout": "/a/../logout"}, id="a dot segment in logout"),
        pytest.param({"backchannel_logout": "/a/../back"}, id="a dot segment in the back-channel"),
        pytest.param({"start": "/login?x=1"}, id="a query in start"),
        pytest.param({"callback": "/callback#top"}, id="a fragment in callback"),
        pytest.param({"logout": "/logout?x=1"}, id="a query in logout"),
        pytest.param({"backchannel_logout": "/back?x=1"}, id="a query in the back-channel"),
        pytest.param({"callback": "/login"}, id="one path for start and callback"),
        pytest.param({"logout": "/login"}, id="one path for start and logout"),
        pytest.param({"logout": "/callback"}, id="one path for callback and logout"),
        pytest.param({"backchannel_logout": "/login"}, id="the back-channel equal to start"),
        pytest.param({"backchannel_logout": "/logout"}, id="the back-channel equal to logout"),
        pytest.param({"backchannel_logout": "/callback"}, id="the back-channel equal to callback"),
    ],
)
def test_a_path_that_is_not_an_absolute_distinct_path_of_this_app_is_refused_at_construction(
    override: dict[str, str],
) -> None:
    """SIGNIN-42: a back-channel path equal to the start, callback or logout path is refused."""
    with pytest.raises(ValueError, match="SignInPaths"):
        SignInPaths(**{**_VALID_PATHS, **override})
