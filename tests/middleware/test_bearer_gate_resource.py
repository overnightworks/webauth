"""The bearer gate's protected resource: its entry point answers the challenge and admits no
token, its metadata document names it, and every other path is decided as without it.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from typing import NoReturn
from urllib.parse import urlsplit

import pytest
from starlette.requests import HTTPConnection

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
    relayed,
)
from tests.support.oidc_arrangement import REALM_ISSUER
from webauth.middleware import ProtectedResource, admitted_user, bearer_caller
from webauth.policies import PathRules

EVERY_METHOD = pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)


@pytest.fixture
def resource() -> ProtectedResource:
    return ProtectedResource("https://app.example/mcp", "mcp:tools")


@pytest.fixture
def challenge() -> str:
    return (
        'Bearer resource_metadata="https://app.example/.well-known/oauth-protected-resource/mcp", '
        'scope="mcp:tools"'
    )


@pytest.fixture
def app(resource: ProtectedResource) -> BearerApp:
    return a_bearer_app(paths=PathRules(), resource=resource)


@pytest.fixture
def member_token() -> str:
    return a_token(groups=["/apps/x"])


@pytest.fixture
def foreign_origin() -> dict[str, str]:
    return {"origin": "https://evil.example"}


@pytest.fixture
def same_origin() -> dict[str, str]:
    return {"sec-fetch-site": "same-origin"}


def assert_untouched(app: BearerApp, expires_at: object) -> None:
    assert app.auth.route_runs == []
    assert app.auth.authenticated == []
    assert app.auth.sessions.stored_record.expires_at == expires_at


def assert_no_bearer_admission(
    app: BearerApp, added_to_scope: dict[str, object], path: str, authorization: str,
) -> None:
    """The request, as the gate left it, read through the public admission readers."""
    connection = HTTPConnection({
        "type": "http", "app": app.auth.app, "path": path,
        "headers": [(b"authorization", authorization.encode("latin-1"))],
        **added_to_scope,
    })
    with pytest.raises(RuntimeError):
        bearer_caller(connection)
    with pytest.raises(RuntimeError):
        admitted_user(connection)


def refusing_a_session_transaction() -> NoReturn:
    raise AssertionError("a session transaction was opened")


def a_resource_app_refusing_a_session_transaction(resource: ProtectedResource) -> BearerApp:
    return a_bearer_app(
        paths=PathRules(), resource=resource, session_transaction=refusing_a_session_transaction,
    )


@EVERY_METHOD
def test_no_credential_at_the_entry_point_answers_the_challenge_on_every_method(
    app: BearerApp, resource: ProtectedResource, challenge: str, method: str,
) -> None:
    response = app.ask(resource.entry_point, method=method)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == challenge
    assert response.headers["cache-control"] == "no-store"
    assert app.auth.route_runs == []


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("sent", [{}, {"origin": "https://evil.example"}], ids=["plain", "foreign"])
def test_a_cookie_decides_nothing_at_the_entry_point_and_opens_no_session_transaction(
    resource: ProtectedResource, challenge: str, method: str, sent: dict[str, str],
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)
    expires_at = app.auth.sessions.stored_record.expires_at

    response = app.ask(resource.entry_point, method=method, cookie=True, headers=sent)

    assert (response.status_code, response.headers["www-authenticate"]) == (401, challenge)
    assert_untouched(app, expires_at)


@pytest.mark.parametrize(
    "token", [A_TOKEN, a_token(groups=["/apps/x"]), "not-a-token"],
    ids=["admin", "member", "malformed"],
)
@EVERY_METHOD
def test_any_bearer_at_the_entry_point_is_an_invalid_token_and_admits_nothing(
    resource: ProtectedResource, challenge: str, method: str, token: str,
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)
    expires_at = app.auth.sessions.stored_record.expires_at
    relay = relayed(app.auth)

    response = app.ask(
        resource.entry_point, method=method, authorization=bearing(token), cookie=True,
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'{challenge}, error="invalid_token"'
    assert response.headers["cache-control"] == "no-store"
    assert_untouched(app, expires_at)
    assert_no_bearer_admission(app, relay.added, resource.entry_point, bearing(token)[0])


def test_a_credential_the_gate_refuses_is_answered_by_that_refusal_with_the_challenge(
    app: BearerApp, resource: ProtectedResource, challenge: str,
) -> None:
    response = app.ask(resource.entry_point, authorization=(*bearing("a"), *bearing("b")))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'{challenge}, error="invalid_request"'
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", ["/mcp/", "/mcp/more"])
def test_a_trailing_slash_and_a_longer_path_are_not_the_entry_point(
    app: BearerApp, path: str,
) -> None:
    response = app.ask(path, authorization=bearing(A_TOKEN))

    assert "resource_metadata" not in response.headers.get("www-authenticate", "")


@pytest.mark.parametrize(
    "url", ["https://app.example/mcp", f"https://app.example{EXPORT_PATH}"],
    ids=["beside", "overlapping"],
)
def test_a_machine_path_beside_a_resource_keeps_its_realm_and_admits_an_admin(url: str) -> None:
    app = a_bearer_app(resource=ProtectedResource(url, "mcp:tools"))

    refused = app.ask(EXPORT_PATH)
    admitted = app.ask(EXPORT_PATH, authorization=bearing(A_TOKEN))

    assert (refused.status_code, refused.headers["www-authenticate"]) == (401, REALM)
    assert admitted.status_code == 200


def test_a_person_path_beside_a_resource_keeps_its_cookie_and_its_app_bearer(
    resource: ProtectedResource, member_token: str,
) -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=resource)

    with_cookie = app.ask(PERSON_ME_PATH, cookie=True)
    with_bearer = app.ask(PERSON_ME_PATH, authorization=bearing(member_token))

    assert with_cookie.status_code == 200
    assert with_bearer.status_code == 200


def test_an_entry_point_below_a_person_path_is_the_resource_and_not_the_person(
    member_token: str,
) -> None:
    below_person_prefix = ProtectedResource("https://app.example/api/mcp", "mcp:tools")
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=below_person_prefix)
    challenge = (
        'Bearer resource_metadata="https://app.example/.well-known/oauth-protected-resource'
        '/api/mcp", scope="mcp:tools"'
    )

    with_bearer = app.ask("/api/mcp", authorization=bearing(member_token))
    with_cookie = app.ask("/api/mcp", cookie=True)

    assert with_bearer.status_code == 401
    assert with_bearer.headers["www-authenticate"] == f'{challenge}, error="invalid_token"'
    assert with_cookie.status_code == 401
    assert with_cookie.headers["www-authenticate"] == challenge


def test_a_cross_origin_cookie_post_on_a_person_path_beside_a_resource_is_still_refused(
    resource: ProtectedResource, foreign_origin: dict[str, str],
) -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=resource)

    response = app.ask(PERSON_ME_PATH, method="POST", cookie=True, headers=foreign_origin)

    assert response.status_code == 403
    assert "www-authenticate" not in response.headers


def test_the_metadata_document_answers_without_a_session_and_names_the_resource(
    app: BearerApp, resource: ProtectedResource,
) -> None:
    response = app.ask(urlsplit(resource.metadata_url).path)

    assert response.status_code == 200
    assert response.json() == {
        "resource": resource.url,
        "authorization_servers": [REALM_ISSUER],
        "scopes_supported": [resource.scope],
    }
    assert "offline_access" not in response.text


def test_the_challenge_points_at_the_url_the_metadata_document_answers_at(
    app: BearerApp, resource: ProtectedResource,
) -> None:
    advertised = app.ask(resource.entry_point).headers["www-authenticate"]
    advertised_url = advertised.split('resource_metadata="')[1].split('"')[0]

    response = app.ask(urlsplit(advertised_url).path)

    assert advertised_url == resource.metadata_url
    assert response.status_code == 200


def test_a_percent_encoded_url_is_selected_by_the_path_a_server_decodes(
    member_token: str,
) -> None:
    encoded = ProtectedResource("https://app.example/%6Dcp", "mcp:tools")
    app = a_resource_app_refusing_a_session_transaction(encoded)
    advertised = (
        'Bearer resource_metadata="https://app.example/.well-known/oauth-protected-resource'
        '/%6Dcp", scope="mcp:tools"'
    )

    refused = app.ask("/%6Dcp", authorization=bearing(member_token))
    metadata = app.ask("/.well-known/oauth-protected-resource/%6Dcp")

    assert refused.status_code == 401
    assert refused.headers["www-authenticate"] == f'{advertised}, error="invalid_token"'
    assert refused.headers["cache-control"] == "no-store"
    assert metadata.status_code == 200
    assert metadata.json()["resource"] == "https://app.example/%6Dcp"


def test_encoded_braces_in_the_url_stay_literal_in_the_metadata_route() -> None:
    braced = ProtectedResource("https://app.example/%7Bid:int%7D", "mcp:tools")
    app = a_resource_app_refusing_a_session_transaction(braced)

    metadata = app.ask("/.well-known/oauth-protected-resource/{id:int}")
    as_route_syntax = app.ask("/.well-known/oauth-protected-resource/7")

    assert metadata.status_code == 200
    assert metadata.json()["resource"] == "https://app.example/%7Bid:int%7D"
    assert as_route_syntax.status_code != 200


def test_the_metadata_route_answers_a_get_of_the_exact_path_only(
    app: BearerApp, resource: ProtectedResource, same_origin: dict[str, str],
) -> None:
    metadata_path = urlsplit(resource.metadata_url).path

    posted = app.ask(metadata_path, method="POST", cookie=True, headers=same_origin)
    longer = app.ask(f"{metadata_path}/more", cookie=True)

    assert posted.status_code == 405
    assert longer.status_code == 404


def test_the_metadata_path_is_public_for_a_get_of_the_exact_path_only(
    app: BearerApp, resource: ProtectedResource, same_origin: dict[str, str],
) -> None:
    metadata_path = urlsplit(resource.metadata_url).path

    posted = app.ask(metadata_path, method="POST", headers=same_origin)
    longer = app.ask(f"{metadata_path}/more")

    assert posted.status_code == 401
    assert longer.status_code == 401


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
