"""The policies the sign-in paths derive for a host's gate, rate limit, cache, CSRF and body rules.

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


@dataclass
class GatedHost:
    client: TestClient
    issuer: FakeIssuer


def _install_the_derived_middleware(
    app: FastAPI,
    sessions: SessionRecordsInMemory,
    rate_budget: int | None,
    exempts_backchannel: bool,
) -> None:
    install_web_auth_middleware(
        app,
        security_headers=SecurityHeadersPolicy(
            content_security_policy="default-src 'self'",
            cache_control_rules=(SIGN_IN_PATHS.cache_control_rule,),
        ),
        body_size=BodySizePolicy(
            default_max_bytes=1024,
            rules=(SIGN_IN_PATHS.backchannel_body_size_rule,),
        ),
        rate_limit=None
        if rate_budget is None
        else RateLimitPolicy(
            default=RateLimitBudget("host", 1000, 60),
            exempt=SIGN_IN_PATHS.backchannel if exempts_backchannel else PathRules(),
            rules=(
                RateLimitRule(
                    paths=SIGN_IN_PATHS.browser_paths,
                    budget=RateLimitBudget("sign-in", rate_budget, 60),
                ),
            ),
        ),
        csrf_origin=CsrfPolicy(exempt=SIGN_IN_PATHS.backchannel),
        session_gate=SessionGate(
            session_transaction=sessions.in_transaction,
            login_redirect=SIGN_IN_PATHS.login_redirect,
            public=SIGN_IN_PATHS.public_rules,
        ),
    )


def _a_gated_host(
    rate_budget: int | None = None,
    *,
    exempts_backchannel: bool = True,
) -> GatedHost:
    """A host whose gate, rate limit, cache, CSRF and body rules are the ones the paths derive.

    Without ``exempts_backchannel`` the rate limit is left to ``browser_paths`` alone.
    """
    config = a_web_auth_config()
    sessions = SessionRecordsInMemory()
    issuer = FakeIssuer(mint_id_token=lambda _nonce: "unused")
    relying_party = a_relying_party(post_token_request=issuer)
    app = FastAPI()
    install_web_auth_config(app, config)
    _install_the_derived_middleware(app, sessions, rate_budget, exempts_backchannel)
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

    return GatedHost(
        TestClient(app, base_url=HTTPS_TEST_SERVER, follow_redirects=False),
        issuer,
    )


def _a_transaction_nobody_enters() -> AbstractContextManager[SignInStores]:
    raise AssertionError("the gated host never signs anyone in")


def test_the_derived_policies_open_the_sign_in_paths_and_send_a_signed_out_page_to_start() -> None:
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


def test_the_derived_cache_rule_marks_the_sign_in_answers_no_store() -> None:
    """SIGNIN-08: the derived cache rule marks the answers of all four routes `no-store`."""
    host = _a_gated_host()

    answers = [
        host.client.get(START_PATH),
        host.client.get(CALLBACK_PATH),
        host.client.post(LOGOUT_PATH, headers=FORM_HEADER),
        host.client.post(BACKCHANNEL_LOGOUT_PATH, content=b"logout_token=x", headers=FORM_HEADER),
    ]

    assert answers[-2].status_code == 403
    assert answers[-1].status_code == 400
    assert [answer.headers["cache-control"] for answer in answers] == ["no-store"] * 4


def test_the_derived_browser_paths_spend_one_sign_in_budget() -> None:
    """SIGNIN-04: start, callback and logout spend one sign-in budget."""
    host = _a_gated_host(rate_budget=3)

    statuses = [
        host.client.get(START_PATH).status_code,
        host.client.get(CALLBACK_PATH).status_code,
        host.client.post(LOGOUT_PATH, headers=SAME_ORIGIN_FORM).status_code,
        host.client.get(START_PATH).status_code,
    ]

    assert statuses[-1] == 429
    assert 429 not in statuses[:-1]


def test_a_back_channel_post_reaches_the_route_past_the_gate_csrf_and_sign_in_budget() -> None:
    """SIGNIN-05: the derived `backchannel` rules exempt the back-channel from the origin check."""
    host = _a_gated_host(rate_budget=1)

    statuses = [
        host.client.post(
            BACKCHANNEL_LOGOUT_PATH, content=b"logout_token=bad", headers=FORM_HEADER
        ).status_code
        for _ in range(3)
    ]

    assert statuses == [400, 400, 400]
    assert host.client.get(START_PATH).status_code == 303


def test_the_back_channel_path_is_not_a_browser_path() -> None:
    host = _a_gated_host(rate_budget=1, exempts_backchannel=False)

    for _ in range(3):
        host.client.post(BACKCHANNEL_LOGOUT_PATH, content=b"logout_token=bad", headers=FORM_HEADER)

    assert host.client.get(START_PATH).status_code == 303


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
def test_the_derived_public_rules_open_exactly_four_methods_of_the_sign_in_paths(
    method: str,
    path: str,
    *,
    reaches_the_route: bool,
) -> None:
    """SIGNIN-03: the public rules open `GET` of start and callback and `POST` of logout and
    back-channel, and no other method."""
    host = _a_gated_host()

    response = host.client.request(method, path, headers=SAME_ORIGIN_FORM)

    assert (response.status_code == 401) is not reaches_the_route


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
    """SIGNIN-40: a back-channel path equal to another path of the sign-in is refused."""
    with pytest.raises(ValueError, match="SignInPaths"):
        SignInPaths(**{**_VALID_PATHS, **override})
