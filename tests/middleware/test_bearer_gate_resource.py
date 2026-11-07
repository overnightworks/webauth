"""The bearer gate's protected resource: its entry point answers the challenge, refuses what
the admission does not let in, and its metadata document names it, and every other path is
decided as without it. The admission itself is in test_bearer_gate_resource_admission.py.

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
    a_bearer_gate,
    a_known_person,
    a_resource,
    a_resource_token,
    a_token,
    an_interactive_agent_token,
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
from tests.support.webauth_arrangement import FakeUser
from webauth.middleware import (
    ProtectedResource,
    install_resource_metadata,
)
from webauth.policies import AuthorizedParties, PathRules

EVERY_METHOD = pytest.mark.parametrize(
    "method",
    ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
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


def a_resource_app_refusing_a_session_transaction(
    resource: ProtectedResource,
    known_accounts: tuple[FakeUser, ...] = (),
) -> BearerApp:
    return a_bearer_app(
        paths=PathRules(),
        resource=resource,
        known_accounts=known_accounts,
        session_transaction=refusing_a_session_transaction,
    )


@EVERY_METHOD
def test_no_credential_at_the_entry_point_answers_the_challenge_on_every_method(
    app: BearerApp,
    resource: ProtectedResource,
    challenge: str,
    method: str,
) -> None:
    """RESOURCE-13, RESOURCE-14: on every method the gate answers a request with no credential
    before CSRF and the session gate, with the 401 and the challenge, and runs no route."""
    response = app.ask(resource.entry_point, method=method)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == challenge
    assert response.headers["cache-control"] == "no-store"
    assert app.auth.route_runs == []


ANSWERS_AT_THE_ENTRY_POINT: dict[
    str, tuple[Callable[[ProtectedResource], tuple[str, ...]], int]
] = {
    "no-credential": (lambda resource: (), 401),
    "app-bearer": (lambda resource: bearing(a_token()), 401),
    "without-the-scope": (lambda resource: bearing(an_interactive_agent_token(resource, scope=ABSENT)), 403),
    "not-admitted": (lambda resource: bearing(a_resource_token(resource, groups=[])), 403),
    "refused-credential": (lambda resource: (*bearing("a"), *bearing("b")), 401),
    "admitted": (lambda resource: bearing(an_interactive_agent_token(resource)), 200),
}


@pytest.mark.parametrize("answer", list(ANSWERS_AT_THE_ENTRY_POINT))
@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("sent", [{}, {"origin": "https://evil.example"}], ids=["plain", "foreign"])
def test_a_cookie_decides_nothing_at_the_entry_point_and_opens_no_session_transaction(
    resource: ProtectedResource,
    answer: str,
    method: str,
    sent: dict[str, str],
) -> None:
    """RESOURCE-31: with a valid cookie beside it every answer is the one it is without, and no
    session transaction runs."""
    app = a_resource_app_refusing_a_session_transaction(resource, (a_known_person(),))
    authorization, status = ANSWERS_AT_THE_ENTRY_POINT[answer]
    expires_at = app.auth.sessions.stored_record.expires_at

    response = app.ask(
        resource.entry_point,
        method=method,
        authorization=authorization(resource),
        cookie=True,
        headers=sent,
    )

    assert response.status_code == status
    assert app.auth.route_runs == ([resource.entry_point] if status == 200 else [])
    assert app.auth.authenticated == []
    assert app.auth.sessions.stored_record.expires_at == expires_at


@pytest.mark.parametrize("answer", list(ANSWERS_AT_THE_ENTRY_POINT))
def test_every_answer_at_the_entry_point_carries_no_store(
    resource: ProtectedResource,
    answer: str,
) -> None:
    """RESOURCE-32: each of the six answers carries `no-store`."""
    app = a_bearer_app(paths=PathRules(), resource=resource, known_accounts=(a_known_person(),))
    authorization, _status = ANSWERS_AT_THE_ENTRY_POINT[answer]

    response = app.ask(resource.entry_point, authorization=authorization(resource))

    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "token",
    [A_TOKEN, a_token(groups=["/apps/x"]), "not-a-token"],
    ids=["admin", "member", "malformed"],
)
@EVERY_METHOD
def test_an_app_bearer_or_garbage_at_the_entry_point_is_an_invalid_token_and_admits_nothing(
    resource: ProtectedResource,
    challenge: str,
    method: str,
    token: str,
) -> None:
    """RESOURCE-10: an app's token is a 401 `invalid_token` on every method and admits
    nothing."""
    app = a_resource_app_refusing_a_session_transaction(resource)
    expires_at = app.auth.sessions.stored_record.expires_at
    relay = relayed(app.auth)

    response = app.ask(
        resource.entry_point,
        method=method,
        authorization=bearing(token),
        cookie=True,
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
        key_name="forged",
        claims={"aud": resource.url, "scope": resource.scope},
    ),
    "not-an-access-token": lambda resource: an_access_token(
        claims={"aud": resource.url, "scope": resource.scope},
        header={"typ": "JWT"},
    ),
    "not-rs256": lambda resource: an_access_token(
        claims={"aud": resource.url, "scope": resource.scope},
        header={"alg": "HS256"},
    ),
    "unlisted-party": lambda resource: a_resource_token(resource, azp="stranger"),
    "unlisted-party-without-scope": lambda resource: a_resource_token(
        resource,
        azp="stranger",
        scope=ABSENT,
    ),
    "two-audiences-without-scope": lambda resource: a_resource_token(
        resource,
        aud=[resource.url, "another-app"],
        scope=ABSENT,
    ),
}


@pytest.mark.parametrize("name", list(WRONG_FOR_THE_RESOURCE))
def test_a_token_the_resource_check_refuses_is_an_invalid_token_with_the_challenge(
    resource: ProtectedResource,
    challenge: str,
    name: str,
) -> None:
    """RESOURCE-15, RESOURCE-16, RESOURCE-17, RESOURCE-18, RESOURCE-19: a token that is not an
    RS256 `at+jwt` of the issuer, whose only audience is the `url` and whose `azp` is a party,
    is a 401 `invalid_token` with the challenge, and no route runs."""
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
    resource: ProtectedResource,
    challenge: str,
    claims: dict[str, object],
) -> None:
    """RESOURCE-20: a token whose `scope` claim, read as space-separated tokens, lacks the scope
    is a 403 `insufficient_scope` with the challenge, and no route runs."""
    app = a_resource_app_refusing_a_session_transaction(resource)

    response = app.ask(
        resource.entry_point,
        authorization=bearing(a_resource_token(resource, **claims)),
    )

    assert response.status_code == 403
    assert response.headers["www-authenticate"] == f'{challenge}, error="insufficient_scope"'
    assert "admin" not in response.text.lower()
    assert app.auth.route_runs == []


@pytest.mark.parametrize(
    "scope",
    ["mcp:tools", "openid mcp:tools", "mcp:tools profile", "openid mcp:tools profile"],
)
@EVERY_METHOD
def test_a_token_that_holds_but_not_the_group_gets_a_plain_403_and_admits_nothing(
    resource: ProtectedResource,
    method: str,
    scope: str,
) -> None:
    app = a_resource_app_refusing_a_session_transaction(resource)
    expires_at = app.auth.sessions.stored_record.expires_at
    token = a_resource_token(resource, scope=scope)
    relay = relayed(app.auth)

    response = app.ask(
        resource.entry_point,
        method=method,
        authorization=bearing(token),
        cookie=True,
    )

    assert response.status_code == 403
    assert "www-authenticate" not in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert_untouched(app, expires_at)
    assert_no_bearer_admission(app, relay.added, resource.entry_point, bearing(token)[0])


def test_the_key_set_is_fetched_once_for_two_requests_at_the_entry_point(
    app: BearerApp,
    resource: ProtectedResource,
    agent_token: str,
) -> None:
    first = app.ask(resource.entry_point, authorization=bearing(agent_token))
    second = app.ask(resource.entry_point, authorization=bearing(agent_token))

    assert (first.status_code, second.status_code) == (403, 403)
    assert len(app.key_sets.fetched_urls) == 1


def test_a_token_for_the_resource_is_refused_on_a_person_path_and_a_machine_path() -> None:
    """RESOURCE-08: the token for the resource is a 401 on the machine path and creates no
    account and no event."""
    resource = a_resource()
    app = a_bearer_app(
        person_paths=PERSON_PATHS,
        resource=resource,
        known_accounts=(a_known_person(),),
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
    """RESOURCE-11: a party the resource lists is refused on the machine and person paths."""
    resource = a_resource(parties=AuthorizedParties(frozenset({"agent"})))
    app = a_bearer_app(
        person_paths=PERSON_PATHS,
        resource=resource,
        known_accounts=(a_known_person(),),
    )
    token = a_resource_token(resource, azp="agent", groups=[RESOURCE_GROUP])
    app_token = a_token(azp="agent")

    assert entry_point_answer(app, resource, token) == (200, "")
    assert app.ask(PERSON_ME_PATH, authorization=bearing(app_token)).status_code == 401
    assert app.ask(EXPORT_PATH, authorization=bearing(app_token)).status_code == 401


def test_a_party_listed_only_on_a_person_or_machine_kind_is_refused_at_the_entry_point(
    challenge: str,
) -> None:
    """RESOURCE-12: a party only the machine or person paths list is refused at the entry
    point."""
    resource = a_resource(parties=AuthorizedParties(frozenset({"agent"})))
    app = a_bearer_app(person_paths=PERSON_PATHS, resource=resource)

    status, authenticate = entry_point_answer(app, resource, a_resource_token(resource))

    assert (status, authenticate) == (401, f'{challenge}, error="invalid_token"')


@pytest.mark.parametrize("parties", ["hal", frozenset({"hal"}), None])
def test_a_resource_with_anything_but_authorized_parties_raises(parties: object) -> None:
    """RESOURCE-04: `authorized_parties` that is not an `AuthorizedParties` is a `TypeError`."""
    resource = a_resource()
    with pytest.raises(TypeError, match="authorized_parties"):
        replace(resource, authorized_parties=parties)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("authorization", "error"),
    [
        pytest.param((*bearing("a"), *bearing("b")), "invalid_request", id="repeated"),
        pytest.param(("Bearer not a token",), "invalid_request", id="two-credentials"),
        pytest.param(("Bearer ?",), "invalid_token", id="not-a-b64token"),
    ],
)
def test_a_credential_the_gate_refuses_is_answered_by_that_refusal_with_the_challenge(
    app: BearerApp,
    resource: ProtectedResource,
    challenge: str,
    authorization: tuple[str, ...],
    error: str,
) -> None:
    """RESOURCE-30: a repeated or malformed credential is that refusal with the challenge, and
    no route runs."""
    response = app.ask(resource.entry_point, authorization=authorization)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'{challenge}, error="{error}"'
    assert response.headers["cache-control"] == "no-store"
    assert app.auth.route_runs == []


@pytest.mark.parametrize("path", ["/mcp/", "/mcp/more"])
def test_a_trailing_slash_and_a_longer_path_are_not_the_entry_point(
    app: BearerApp,
    path: str,
) -> None:
    """RESOURCE-33: a trailing slash and a longer path are not the entry point."""
    response = app.ask(path, authorization=bearing(A_TOKEN))

    assert "resource_metadata" not in response.headers.get("www-authenticate", "")


@pytest.mark.parametrize(
    "url",
    ["https://app.example/mcp", f"https://app.example{EXPORT_PATH}"],
    ids=["beside", "overlapping"],
)
def test_a_machine_path_beside_a_resource_keeps_its_realm_and_admits_an_admin(url: str) -> None:
    """RESOURCE-34: a machine path that overlaps the entry point stays a machine path."""
    app = a_bearer_app(resource=a_resource(url))

    refused = app.ask(EXPORT_PATH)
    admitted = app.ask(EXPORT_PATH, authorization=bearing(A_TOKEN))

    assert (refused.status_code, refused.headers["www-authenticate"]) == (401, REALM)
    assert admitted.status_code == 200


def test_a_person_path_beside_a_resource_keeps_its_cookie_and_its_app_bearer(
    resource: ProtectedResource,
    member_token: str,
) -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=resource)

    with_cookie = app.ask(PERSON_ME_PATH, cookie=True)
    with_bearer = app.ask(PERSON_ME_PATH, authorization=bearing(member_token))

    assert with_cookie.status_code == 200
    assert with_bearer.status_code == 200


def test_an_entry_point_below_a_person_path_is_the_resource_and_not_the_person(
    member_token: str,
) -> None:
    """RESOURCE-35: an entry point below a person path is decided as the entry point."""
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
    resource: ProtectedResource,
    foreign_origin: dict[str, str],
) -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS, resource=resource)

    response = app.ask(PERSON_ME_PATH, method="POST", cookie=True, headers=foreign_origin)

    assert response.status_code == 403
    assert "www-authenticate" not in response.headers


def test_the_metadata_document_answers_without_a_session_and_names_the_resource(
    app: BearerApp,
    resource: ProtectedResource,
) -> None:
    """RESOURCE-37, RESOURCE-38: the metadata document names the resource, its issuer and its
    scope, and a client without a session reads it."""
    response = app.ask(urlsplit(resource.metadata_url).path)

    assert response.status_code == 200
    assert response.json() == {
        "resource": resource.url,
        "authorization_servers": [REALM_ISSUER],
        "scopes_supported": [resource.scope],
    }
    assert "offline_access" not in response.text


def test_the_challenge_points_at_the_url_the_metadata_document_answers_at(
    app: BearerApp,
    resource: ProtectedResource,
) -> None:
    """RESOURCE-06, RESOURCE-07: the challenge names the metadata URL, which is the well-known
    path of RFC 9728 section 3.1 plus the entry point, and the document answers there."""
    advertised = app.ask(resource.entry_point).headers["www-authenticate"]
    advertised_url = advertised.split('resource_metadata="')[1].split('"')[0]

    response = app.ask(urlsplit(advertised_url).path)

    assert advertised_url == "https://app.example/.well-known/oauth-protected-resource/mcp"
    assert response.status_code == 200


def test_the_metadata_route_answers_a_get_of_the_exact_path_only(
    app: BearerApp,
    resource: ProtectedResource,
    same_origin: dict[str, str],
) -> None:
    """RESOURCE-36: the metadata route answers a `GET` of the metadata path and nothing else."""
    metadata_path = urlsplit(resource.metadata_url).path

    served = app.ask(metadata_path, cookie=True)
    posted = app.ask(metadata_path, method="POST", cookie=True, headers=same_origin)
    longer = app.ask(f"{metadata_path}/more", cookie=True)

    assert served.status_code == 200
    assert posted.status_code == 405
    assert longer.status_code == 404


def test_the_metadata_path_is_public_for_a_get_of_the_exact_path_only(
    app: BearerApp,
    resource: ProtectedResource,
    same_origin: dict[str, str],
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
    ("url", "entry_point"),
    [
        pytest.param("https://app.example/mcp", "/mcp", id="plain"),
        pytest.param("https://app.example:8443/mcp", "/mcp", id="port"),
        pytest.param("https://app.example/api/mcp", "/api/mcp", id="segments"),
        pytest.param("https://app.example/a-b/c.d_e~f/9", "/a-b/c.d_e~f/9", id="unreserved"),
        *(
            pytest.param(url, None, id=f"refused-{at}")
            for at, url in enumerate(
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
                ]
            )
        ),
    ],
)
def test_a_url_is_the_resource_only_inside_the_resource_url_rule_and_its_path_is_the_entry_point(
    url: str,
    entry_point: str | None,
) -> None:
    """RESOURCE-02: an endpoint URL with a plain host, an optional port and unreserved segments
    is the resource and its path is the entry point; any other `url` is a `ValueError`."""
    if entry_point is None:
        with pytest.raises(ValueError, match="url"):
            a_resource(url)
    else:
        assert a_resource(url).entry_point == entry_point


@pytest.mark.parametrize(
    "scope",
    [
        "mcp:tools",
        "read",
        "tools/read",
        "",
        "two scopes",
        'quo"te',
        "back\\slash",
        "tab\t",
        "ü",
        ("mcp:tools",),
    ],
)
def test_a_scope_is_one_scope_token(scope: object) -> None:
    """RESOURCE-03: a `scope` that is one scope token is taken, anything else is a
    `ValueError`."""
    resource = a_resource()
    if scope in {"mcp:tools", "read", "tools/read"}:
        assert replace(resource, scope=scope).scope == scope  # type: ignore[arg-type]
    else:
        with pytest.raises(ValueError, match="scope"):
            replace(resource, scope=scope)  # type: ignore[arg-type]


def test_a_gate_needs_one_kind_of_path_and_the_resource_counts_as_one() -> None:
    """RESOURCE-01: a gate with a resource and no path of another kind is valid; a gate with no
    kind at all is a `ValueError`."""
    no_paths = PathRules()
    assert a_bearer_gate(paths=no_paths, resource=a_resource()).resource is not None
    with pytest.raises(ValueError, match="must name"):
        a_bearer_gate(paths=no_paths)
