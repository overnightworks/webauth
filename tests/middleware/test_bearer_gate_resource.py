"""The bearer gate's protected resource: its entry point answers the challenge and admits no
token, its metadata document names it, and every other path is decided as without it.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import pytest

from tests.support.gate_arrangement import (
    A_TOKEN,
    EXPORT_PATH,
    PERSON_ME_PATH,
    PERSON_PATHS,
    REALM,
    BearerApp,
    a_bearer_app,
    a_token,
    bearing,
)
from tests.support.oidc_arrangement import REALM_ISSUER
from webauth.middleware import ProtectedResource
from webauth.policies import PathRules

RESOURCE = ProtectedResource("https://app.example/mcp", "mcp:tools")
CHALLENGE = (
    'Bearer resource_metadata="https://app.example/.well-known/oauth-protected-resource/mcp", '
    'scope="mcp:tools"'
)
INVALID_REQUEST_CHALLENGE = f'{CHALLENGE}, error="invalid_request"'
INVALID_TOKEN_CHALLENGE = f'{CHALLENGE}, error="invalid_token"'
MEMBER_TOKEN = a_token(groups=["/apps/x"])
FOREIGN_ORIGIN = "https://evil.example"
EVERY_METHOD = pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)


def a_resource_app(**keywords: Any) -> BearerApp:
    return a_bearer_app(paths=PathRules(), resource=RESOURCE, **keywords)


def the_challenge(app: BearerApp, **sent: Any) -> str | None:
    return app.ask(RESOURCE.entry_point, **sent).headers.get("www-authenticate")


def assert_untouched(app: BearerApp, expires_at: object) -> None:
    assert app.auth.route_runs == []
    assert app.auth.authenticated == []
    assert app.auth.sessions.stored_record.expires_at == expires_at


@EVERY_METHOD
def test_no_credential_at_the_entry_point_answers_the_challenge_on_every_method(
    method: str,
) -> None:
    app = a_resource_app()

    response = app.ask(RESOURCE.entry_point, method=method)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == CHALLENGE
    assert response.headers["cache-control"] == "no-store"
    assert app.auth.route_runs == []


@pytest.mark.parametrize(
    ("method", "cookie", "headers"),
    [
        ("POST", False, {}),
        ("POST", True, {}),
        ("POST", True, {"origin": FOREIGN_ORIGIN}),
        ("GET", True, {}),
        ("GET", False, {}),
    ],
)
def test_a_cookie_decides_nothing_at_the_entry_point_and_the_session_is_not_touched(
    method: str, cookie: bool, headers: dict[str, str],
) -> None:
    app = a_resource_app()
    expires_at = app.auth.sessions.stored_record.expires_at

    response = app.ask(RESOURCE.entry_point, method=method, cookie=cookie, headers=headers)

    assert (response.status_code, response.headers["www-authenticate"]) == (401, CHALLENGE)
    assert_untouched(app, expires_at)


@pytest.mark.parametrize(
    "token", [A_TOKEN, MEMBER_TOKEN, "not-a-token"], ids=["admin", "member", "malformed"],
)
@EVERY_METHOD
def test_any_bearer_at_the_entry_point_is_an_invalid_token_and_admits_nothing(
    method: str, token: str,
) -> None:
    app = a_resource_app()
    expires_at = app.auth.sessions.stored_record.expires_at

    response = app.ask(
        RESOURCE.entry_point, method=method, authorization=bearing(token), cookie=True,
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == INVALID_TOKEN_CHALLENGE
    assert response.headers["cache-control"] == "no-store"
    assert_untouched(app, expires_at)


def test_a_credential_the_gate_refuses_is_answered_by_that_refusal_with_the_challenge() -> None:
    app = a_resource_app()

    response = app.ask(RESOURCE.entry_point, authorization=(*bearing("a"), *bearing("b")))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == INVALID_REQUEST_CHALLENGE
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", [f"{RESOURCE.entry_point}/", f"{RESOURCE.entry_point}/more"])
def test_a_trailing_slash_and_a_longer_path_are_not_the_entry_point(path: str) -> None:
    app = a_resource_app()

    response = app.ask(path, authorization=bearing(A_TOKEN))

    assert "resource_metadata" not in response.headers.get("www-authenticate", "")


def test_a_machine_path_overlapping_the_entry_point_stays_a_machine_path() -> None:
    overlapping = ProtectedResource(f"https://app.example{EXPORT_PATH}", "mcp:tools")
    app = a_bearer_app(resource=overlapping)

    refused = app.ask(EXPORT_PATH)
    admitted = app.ask(EXPORT_PATH, authorization=bearing(A_TOKEN))

    assert refused.status_code == 401
    assert refused.headers["www-authenticate"] == REALM
    assert admitted.status_code == 200


def test_a_machine_path_beside_a_resource_keeps_its_realm_and_admits_an_admin() -> None:
    app = a_bearer_app(resource=RESOURCE)

    refused = app.ask(EXPORT_PATH)
    admitted = app.ask(EXPORT_PATH, authorization=bearing(A_TOKEN))

    assert (refused.status_code, refused.headers["www-authenticate"]) == (401, REALM)
    assert admitted.status_code == 200


def test_a_person_path_beside_a_resource_keeps_its_cookie_and_its_app_bearer() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=RESOURCE)

    with_cookie = app.ask(PERSON_ME_PATH, cookie=True)
    with_bearer = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert with_cookie.status_code == 200
    assert with_bearer.status_code == 200


def test_a_cross_origin_cookie_post_on_a_person_path_beside_a_resource_is_still_refused() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=RESOURCE)

    response = app.ask(
        PERSON_ME_PATH, method="POST", cookie=True, headers={"origin": FOREIGN_ORIGIN},
    )

    assert response.status_code == 403
    assert "www-authenticate" not in response.headers


def test_the_metadata_document_answers_without_a_session_and_names_the_resource() -> None:
    app = a_resource_app()
    metadata_path = urlsplit(RESOURCE.metadata_url).path

    response = app.ask(metadata_path)

    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE.url,
        "authorization_servers": [REALM_ISSUER],
        "scopes_supported": [RESOURCE.scope],
    }
    assert "offline_access" not in response.text


def test_the_challenge_points_at_the_url_the_metadata_document_answers_at() -> None:
    app = a_resource_app()
    advertised = the_challenge(app)
    assert advertised is not None
    advertised_url = advertised.split('resource_metadata="')[1].split('"')[0]

    response = app.ask(urlsplit(advertised_url).path)

    assert advertised_url == RESOURCE.metadata_url
    assert response.status_code == 200


def test_the_metadata_route_is_a_get_of_the_exact_path_only() -> None:
    app = a_resource_app()
    metadata_path = urlsplit(RESOURCE.metadata_url).path

    posted = app.ask(metadata_path, method="POST")
    longer = app.ask(f"{metadata_path}/more")

    assert posted.status_code != 200
    assert longer.status_code != 200


@pytest.mark.parametrize(
    "url",
    [
        "http://app.example/mcp",
        "https://app.example",
        "https://app.example/",
        "https://app.example/mcp?x=1",
        "https://app.example/mcp#top",
        'https://app.example/m"cp',
        "https://app.example/m\\cp",
        "/mcp",
        "",
    ],
)
def test_a_url_that_is_not_a_path_bearing_endpoint_url_is_refused(url: str) -> None:
    with pytest.raises(ValueError, match="url"):
        ProtectedResource(url, "mcp:tools")


@pytest.mark.parametrize("scope", ["", "two scopes", 'quo"te', "back\\slash", "tab\t", "ü"])
def test_a_scope_that_is_not_one_scope_token_is_refused(scope: str) -> None:
    with pytest.raises(ValueError, match="scope"):
        ProtectedResource("https://app.example/mcp", scope)


def test_a_non_string_scope_is_refused() -> None:
    with pytest.raises(ValueError, match="scope"):
        ProtectedResource("https://app.example/mcp", ("mcp:tools",))  # type: ignore[arg-type]
