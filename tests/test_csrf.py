"""CsrfOriginMiddleware: Sec-Fetch-Site first, Origin allowlist as fallback.

CsrfTokenMiddleware: the header token must match the request's one session.
"""

from __future__ import annotations

import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from webauth_arrangement import (
    ALLOWED_ORIGIN,
    API_PATH,
    SESSION_COOKIE_NAME,
    SESSION_ID,
    a_web_auth_config,
    session_cookie_header,
    signed_without_bound,
)

from webauth.config import WebAuthConfig, install_web_auth_config
from webauth.cookies import MAX_SESSION_COOKIE_CHARS, generate_csrf_token, sign_session_id
from webauth.middleware import CsrfOriginMiddleware, CsrfTokenMiddleware
from webauth.policies import CsrfPolicy, PathRules

FOREIGN_ORIGIN = "https://evil.test"
OK = {"status": "ok"}
CROSS_ORIGIN_DETAIL = {"detail": "Cross-origin request rejected"}
MISSING_ORIGIN_DETAIL = {"detail": "Missing Origin header on form submission"}
INVALID_TOKEN_DETAIL = {"detail": "CSRF token missing or invalid"}


WEBHOOK_PREFIX = "/webhook/provider/"
WEBHOOK_PATH = f"{WEBHOOK_PREFIX}event"
WEBHOOK_SIBLING_PATH = "/webhook/providerx"


def an_origin_guarded_client(config: WebAuthConfig | None = None) -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, config or a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(protected=PathRules(prefixes=("/api/",))),
    )

    @app.api_route(API_PATH, methods=["GET", "POST"])
    def ok() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


def a_protect_everything_client() -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, a_web_auth_config())
    app.add_middleware(
        CsrfOriginMiddleware,
        policy=CsrfPolicy(exempt=PathRules(prefixes=(WEBHOOK_PREFIX,))),
    )

    @app.api_route(API_PATH, methods=["POST"])
    def ok() -> dict[str, str]:
        return OK

    @app.api_route(WEBHOOK_PATH, methods=["POST"])
    def webhook() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN)


def a_client_allowing_only_pattern(pattern: str) -> TestClient:
    return an_origin_guarded_client(a_web_auth_config(
        allowed_hosts_exact=frozenset(),
        allowed_hosts_patterns=(re.compile(pattern),),
    ))


def _call(method: str, headers: dict[str, str], *, as_form: bool = False) -> Response:
    client = an_origin_guarded_client()
    if method == "GET":
        return client.get(API_PATH, headers=headers)
    if as_form:
        return client.post(
            API_PATH,
            content=b"n=1",
            headers={**headers, "content-type": "application/x-www-form-urlencoded"},
        )
    return client.post(API_PATH, json={"n": 1}, headers=headers)


@pytest.mark.parametrize(
    ("method", "headers", "as_form", "status", "body"),
    [
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin"},
            False,
            200,
            OK,
            id="same-origin-without-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-origin", "origin": FOREIGN_ORIGIN},
            False,
            200,
            OK,
            id="same-origin-with-foreign-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "cross-site", "origin": ALLOWED_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="cross-site-wins-over-allowlisted-origin",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": ALLOWED_ORIGIN},
            False,
            200,
            OK,
            id="same-site-with-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "same-site", "origin": FOREIGN_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="same-site-with-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {"origin": ALLOWED_ORIGIN},
            False,
            200,
            OK,
            id="absent-header-allowlisted-origin-passes",
        ),
        pytest.param(
            "POST",
            {"origin": FOREIGN_ORIGIN},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="absent-header-foreign-origin-refused",
        ),
        pytest.param(
            "POST",
            {},
            False,
            200,
            OK,
            id="absent-both-json-passes",
        ),
        pytest.param(
            "POST",
            {},
            True,
            403,
            MISSING_ORIGIN_DETAIL,
            id="absent-both-form-refused",
        ),
        pytest.param(
            "POST",
            {"sec-fetch-site": "none"},
            False,
            403,
            CROSS_ORIGIN_DETAIL,
            id="none-with-post-refused",
        ),
        pytest.param(
            "GET",
            {"sec-fetch-site": "cross-site"},
            False,
            200,
            OK,
            id="safe-method-cross-site-passes",
        ),
    ],
)
def test_a_request_is_judged_by_sec_fetch_site_then_origin(
    method: str,
    headers: dict[str, str],
    as_form: bool,
    status: int,
    body: dict[str, str],
) -> None:
    response = _call(method, headers, as_form=as_form)

    assert response.status_code == status
    assert response.json() == body


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"origin": "null"}, id="a null origin"),
        pytest.param({"origin": "http://"}, id="an origin without a host"),
        pytest.param({"origin": "http://[bad"}, id="an origin that cannot be parsed"),
        pytest.param({"referer": "null"}, id="a null referer"),
        pytest.param({"referer": "http://[bad"}, id="a referer that cannot be parsed"),
        pytest.param(
            {"sec-fetch-site": "same-site", "origin": "null"}, id="a null origin on same-site",
        ),
    ],
)
def test_an_origin_that_names_no_host_is_refused_like_a_foreign_one(
    headers: dict[str, str],
) -> None:
    response = _call("POST", headers)

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


@pytest.mark.parametrize(
    ("referer", "status"),
    [
        pytest.param("https://app.example/page", 200, id="the host itself"),
        pytest.param("https://app.example:8000/page", 200, id="the host with a port"),
        pytest.param("https://app.example@evil.test/", 403, id="the host as userinfo"),
        pytest.param("https://app.example.evil.test/", 403, id="the host as a prefix"),
    ],
)
def test_a_host_pattern_must_match_the_whole_host_and_port(referer: str, status: int) -> None:
    client = a_client_allowing_only_pattern(r"app\.example(:\d+)?")

    response = client.post(API_PATH, json={"n": 1}, headers={"referer": referer})

    assert response.status_code == status


def test_songmakers_json_post_without_either_header_is_unchanged() -> None:
    """Songmaker's TestClient path: JSON, no Sec-Fetch-Site, no Origin."""
    response = _call("POST", {})

    assert response.status_code == 200
    assert response.json() == OK


def test_protect_everything_refuses_a_route_nobody_listed() -> None:
    """A route added later, with no path rule naming it, is checked by default."""
    client = a_protect_everything_client()

    response = client.post(API_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


def test_protect_everything_exempts_a_named_prefix() -> None:
    """A sessionless webhook under the exempt prefix passes a foreign Origin."""
    client = a_protect_everything_client()

    response = client.post(WEBHOOK_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN})

    assert response.status_code == 200
    assert response.json() == OK


def test_protect_everything_keeps_a_sibling_of_an_exempt_prefix_protected() -> None:
    client = a_protect_everything_client()

    response = client.post(
        WEBHOOK_SIBLING_PATH, json={"n": 1}, headers={"origin": FOREIGN_ORIGIN},
    )

    assert response.status_code == 403
    assert response.json() == CROSS_ORIGIN_DETAIL


def test_explicit_protected_rules_refuse_an_exempt_rule() -> None:
    protected = PathRules(prefixes=("/api/",))
    exempt = PathRules(prefixes=(WEBHOOK_PREFIX,))

    with pytest.raises(ValueError, match="exempt"):
        CsrfPolicy(protected=protected, exempt=exempt)


CONFIG = a_web_auth_config()
SESSION_COOKIE = sign_session_id(SESSION_ID, CONFIG.signing_key)
ANOTHER_SESSION_ID = "another-session"
ANOTHER_SESSION_COOKIE = sign_session_id(ANOTHER_SESSION_ID, CONFIG.signing_key)
OVERLONG_SESSION_ID = "s" * MAX_SESSION_COOKIE_CHARS
OVERLONG_SESSION_COOKIE = signed_without_bound(OVERLONG_SESSION_ID, CONFIG.signing_key)


def a_token_guarded_client() -> TestClient:
    app = FastAPI()
    install_web_auth_config(app, CONFIG)
    app.add_middleware(CsrfTokenMiddleware, policy=CsrfPolicy())

    @app.post(API_PATH)
    def ok() -> dict[str, str]:
        return OK

    return TestClient(app, base_url=ALLOWED_ORIGIN, cookies={})


def _post_with_token(cookie_header: str, token_for: str) -> Response:
    return a_token_guarded_client().post(
        API_PATH,
        headers={
            "cookie": cookie_header,
            CONFIG.csrf_header_name: generate_csrf_token(token_for, CONFIG.signing_key),
        },
    )


@pytest.mark.parametrize(
    ("cookie_header", "token_for", "status", "body"),
    [
        pytest.param(
            session_cookie_header(SESSION_COOKIE), SESSION_ID, 200, OK, id="one session",
        ),
        pytest.param(
            f"{SESSION_COOKIE_NAME}_old={ANOTHER_SESSION_COOKIE}; "
            f"{session_cookie_header(SESSION_COOKIE)}",
            SESSION_ID, 200, OK,
            id="a cookie whose name starts like the session cookie",
        ),
        pytest.param(
            session_cookie_header(SESSION_COOKIE, SESSION_COOKIE),
            SESSION_ID, 403, INVALID_TOKEN_DETAIL,
            id="the same session cookie twice",
        ),
        pytest.param(
            session_cookie_header(SESSION_COOKIE, ANOTHER_SESSION_COOKIE),
            SESSION_ID, 403, INVALID_TOKEN_DETAIL,
            id="a token for the first of two sessions",
        ),
        pytest.param(
            session_cookie_header(SESSION_COOKIE, ANOTHER_SESSION_COOKIE),
            ANOTHER_SESSION_ID, 403, INVALID_TOKEN_DETAIL,
            id="a token for the second of two sessions",
        ),
        pytest.param(
            session_cookie_header(OVERLONG_SESSION_COOKIE),
            OVERLONG_SESSION_ID, 403, INVALID_TOKEN_DETAIL,
            id="a correctly signed cookie longer than the reader accepts",
        ),
    ],
)
def test_a_csrf_token_is_honoured_only_for_the_one_session_cookie(
    cookie_header: str, token_for: str, status: int, body: dict[str, str],
) -> None:
    response = _post_with_token(cookie_header, token_for)

    assert response.status_code == status
    assert response.json() == body


def test_a_csrf_token_with_non_ascii_characters_is_refused_like_a_forged_one() -> None:
    response = a_token_guarded_client().post(
        API_PATH,
        headers={
            "cookie": session_cookie_header(SESSION_COOKIE),
            CONFIG.csrf_header_name: "é".encode("latin-1"),
        },
    )

    assert response.status_code == 403
    assert response.json() == INVALID_TOKEN_DETAIL
