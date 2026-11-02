"""The bearer gate's protected resource: its entry point answers the challenge and admits an
agent's token as a capped person, its metadata document names it, and every other path is
decided as without it.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import NoReturn
from urllib.parse import urlsplit

import pytest
from fastapi import Depends, FastAPI, HTTPException
from starlette.testclient import TestClient

from tests.support.gate_arrangement import (
    A_TOKEN,
    EXPORT_PATH,
    PERSON_ME_PATH,
    PERSON_PATHS,
    REALM,
    RESOURCE_GROUP,
    BearerApp,
    a_bearer_app,
    a_known_person,
    a_resource,
    a_resource_token,
    a_token,
    assert_no_bearer_admission,
    bearing,
    relayed,
    the_accounts,
)
from tests.support.oidc_arrangement import (
    ABSENT,
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
    REALM_ISSUER,
    an_access_token,
)
from webauth.middleware import (
    ProtectedResource,
    install_resource_metadata,
)
from webauth.policies import AuthorizedParties, PathRules

EVERY_METHOD = pytest.mark.parametrize(
    "method", ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)


@pytest.fixture
def resource() -> ProtectedResource:
    return a_resource()


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
def agent_token(resource: ProtectedResource) -> str:
    return a_resource_token(resource)


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
def test_an_app_bearer_or_garbage_at_the_entry_point_is_an_invalid_token_and_admits_nothing(
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


def entry_point_answer(app: BearerApp, resource: ProtectedResource, token: str) -> tuple[int, str]:
    response = app.ask(resource.entry_point, authorization=bearing(token))
    return response.status_code, response.headers.get("www-authenticate", "")


# Tokens signed by the test issuer that the resource's check refuses as invalid.
WRONG_FOR_THE_RESOURCE: dict[str, Callable[[ProtectedResource], str]] = {
    "app-bearer": lambda resource: a_token(),
    "two-audiences": lambda resource: a_resource_token(resource, aud=[resource.url, "another-app"]),
    "other-audience": lambda resource: a_resource_token(resource, aud="https://other.example/mcp"),
    "wrong-issuer": lambda resource: a_resource_token(resource, iss="https://evil.example/r"),
    "expired": lambda resource: a_resource_token(resource, exp=ACCESS_TOKEN_NOW - 1_000),
    "bad-signature": lambda resource: an_access_token(
        key_name="forged", claims={"aud": resource.url, "scope": resource.scope},
    ),
    "not-an-access-token": lambda resource: an_access_token(
        claims={"aud": resource.url, "scope": resource.scope}, header={"typ": "JWT"},
    ),
    "unlisted-party": lambda resource: a_resource_token(resource, azp="stranger"),
    "unlisted-party-without-scope": lambda resource: a_resource_token(
        resource, azp="stranger", scope=ABSENT,
    ),
    "two-audiences-without-scope": lambda resource: a_resource_token(
        resource, aud=[resource.url, "another-app"], scope=ABSENT,
    ),
}


@pytest.mark.parametrize("name", list(WRONG_FOR_THE_RESOURCE))
def test_a_token_the_resource_check_refuses_is_an_invalid_token_with_the_challenge(
    resource: ProtectedResource, challenge: str, name: str,
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)

    status, authenticate = entry_point_answer(app, resource, WRONG_FOR_THE_RESOURCE[name](resource))

    assert (status, authenticate) == (401, f'{challenge}, error="invalid_token"')
    assert app.auth.route_runs == []


@pytest.mark.parametrize(
    "claims",
    [
        {"scope": ABSENT},
        {"scope": "mcp:other"},
        {"scope": "mcp:tools-extra xmcp:tools"},
        {"scope": ["mcp:tools"]},
        {"scope": 7},
        {"scope": ""},
    ],
    ids=["absent", "other", "substring", "list", "number", "empty"],
)
def test_a_resource_token_without_the_scope_is_an_insufficient_scope_with_the_challenge(
    resource: ProtectedResource, challenge: str, claims: dict[str, object],
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)

    response = app.ask(
        resource.entry_point, authorization=bearing(a_resource_token(resource, **claims)),
    )

    assert response.status_code == 403
    assert response.headers["www-authenticate"] == f'{challenge}, error="insufficient_scope"'
    assert "admin" not in response.text.lower()
    assert app.auth.route_runs == []


@pytest.mark.parametrize(
    "scope", ["mcp:tools", "openid mcp:tools", "mcp:tools profile", "openid mcp:tools profile"],
)
@EVERY_METHOD
def test_a_token_that_holds_but_not_the_group_gets_a_plain_403_and_admits_nothing(
    resource: ProtectedResource, method: str, scope: str,
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)
    expires_at = app.auth.sessions.stored_record.expires_at
    token = a_resource_token(resource, scope=scope)
    relay = relayed(app.auth)

    response = app.ask(
        resource.entry_point, method=method, authorization=bearing(token), cookie=True,
    )

    assert response.status_code == 403
    assert "www-authenticate" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert_untouched(app, expires_at)
    assert_no_bearer_admission(app, relay.added, resource.entry_point, bearing(token)[0])


def test_the_key_set_is_fetched_once_for_two_requests_at_the_entry_point(
    app: BearerApp, resource: ProtectedResource, agent_token: str,
) -> None:
    first = app.ask(resource.entry_point, authorization=bearing(agent_token))
    second = app.ask(resource.entry_point, authorization=bearing(agent_token))

    assert (first.status_code, second.status_code) == (403, 403)
    assert len(app.key_sets.fetched_urls) == 1


def test_a_token_for_the_resource_is_refused_on_a_person_path_and_a_machine_path() -> None:
    resource = a_resource()
    app = a_bearer_app(
        person_paths=PERSON_PATHS, resource=resource, known_accounts=(a_known_person(),),
    )
    token = a_resource_token(resource, groups=[RESOURCE_GROUP])

    on_person_path = app.ask(PERSON_ME_PATH, authorization=bearing(token))
    on_machine_path = app.ask(EXPORT_PATH, authorization=bearing(token))
    elsewhere = app.ask("/elsewhere", authorization=bearing(token))

    assert on_person_path.status_code == on_machine_path.status_code == 401
    assert on_person_path.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    assert on_machine_path.headers["www-authenticate"] == f'{REALM}, error="invalid_token"'
    assert (elsewhere.status_code, "www-authenticate" in elsewhere.headers) == (401, False)
    assert {user.id for user in the_accounts(app)} == {OPERATOR_SUBJECT, "user-1"}
    assert app.audit.account_events == []


def test_a_party_listed_only_on_the_resource_is_refused_on_the_other_kinds() -> None:
    resource = a_resource(parties=AuthorizedParties(frozenset({"agent"})))
    app = a_bearer_app(
        person_paths=PERSON_PATHS, resource=resource, known_accounts=(a_known_person(),),
    )
    token = a_resource_token(resource, azp="agent", groups=[RESOURCE_GROUP])
    app_token = a_token(azp="agent")

    assert entry_point_answer(app, resource, token) == (200, "")
    assert app.ask(PERSON_ME_PATH, authorization=bearing(app_token)).status_code == 401
    assert app.ask(EXPORT_PATH, authorization=bearing(app_token)).status_code == 401


def test_a_party_listed_only_on_a_person_or_machine_kind_is_refused_at_the_entry_point(
    challenge: str,
) -> None:
    resource = a_resource(parties=AuthorizedParties(frozenset({"agent"})))
    app = a_bearer_app(person_paths=PERSON_PATHS, resource=resource)

    status, authenticate = entry_point_answer(app, resource, a_resource_token(resource))

    assert (status, authenticate) == (401, f'{challenge}, error="invalid_token"')


@pytest.mark.parametrize("parties", ["hal", frozenset({"hal"}), None])
def test_a_resource_with_anything_but_authorized_parties_raises(parties: object) -> None:
    resource = a_resource()
    with pytest.raises(TypeError, match="authorized_parties"):
        replace(resource, authorized_parties=parties)  # type: ignore[arg-type]


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
    app = a_bearer_app(resource=a_resource(url))

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
    below_person_prefix = a_resource("https://app.example/api/mcp")
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


def test_the_metadata_route_runs_the_hosts_app_level_dependencies(
    resource: ProtectedResource,
) -> None:
    def refuse() -> NoReturn:
        raise HTTPException(status_code=418)

    host = FastAPI(dependencies=[Depends(refuse)])
    install_resource_metadata(host, resource, issuer=REALM_ISSUER)

    assert TestClient(host).get(resource.metadata_path).status_code == 418


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
        "https://app.example/%6Dcp",
        "https://app.example/%7Bid:int%7D",
        "https://app.example/{id}",
        "https://app.example/\u20ac",
        'https://app.exa"mple/mcp',
        "https://app.example\\x/mcp",
        "https://ex%61mple/mcp",
        "https://app.example/a/../mcp",
        "https://app.example/./mcp",
        "https://app.example/mcp/",
        "/mcp",
        "",
    ],
)
def test_a_url_outside_the_resource_url_rule_is_refused(url: str) -> None:
    with pytest.raises(ValueError, match="url"):
        a_resource(url)


@pytest.mark.parametrize("scope", ["", "two scopes", 'quo"te', "back\\slash", "tab\t", "ü"])
def test_a_scope_that_is_not_one_scope_token_is_refused(scope: str) -> None:
    resource = a_resource()
    with pytest.raises(ValueError, match="scope"):
        replace(resource, scope=scope)


def test_a_non_string_scope_is_refused() -> None:
    resource = a_resource()
    with pytest.raises(ValueError, match="scope"):
        replace(resource, scope=("mcp:tools",))  # type: ignore[arg-type]
