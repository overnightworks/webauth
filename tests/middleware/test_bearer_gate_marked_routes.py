"""The bearer gate's protected resource, marked routes: an agent's token is admitted on the
routes a host marked, capped and read-only, and refused on every other method, shape and path;
a token of another audience takes the path it would take without the marking, and a request
without a bearer keeps the session and CSRF.

The app is the real stack over `an_auth_app` behind the session gate, with the host's routes
of `a_bearer_app`; the tokens are real RS256 `at+jwt`s.
"""

from __future__ import annotations

import pytest
from starlette.middleware import Middleware

from tests.support.gate_arrangement import (
    MARKED_ADMIN_NOTES,
    MARKED_ADMITTED_USER,
    MARKED_NEW_NOTE,
    MARKED_RESOURCE_PERSON,
    MARKED_ROUTES,
    PERSON_INVALID_TOKEN,
    PERSON_PATHS,
    REALM_INVALID_TOKEN,
    RESOURCE_GROUP,
    BearerApp,
    RewritingTheRequest,
    a_bearer_app,
    a_known_person,
    a_resource,
    a_resource_token,
    a_token,
    bearing,
    the_accounts,
)
from tests.support.oidc_arrangement import ABSENT, ACCESS_TOKEN_NOW, OPERATOR_SUBJECT
from tests.support.oidc_login_host import RecordingSignInTransaction, failing
from tests.support.webauth_arrangement import ADMIN_ROLE, MEMBER_ROLE
from webauth.middleware import MarkedRoute, ProtectedResource

CHALLENGE = (
    'Bearer resource_metadata="https://app.example/.well-known/oauth-protected-resource/mcp", '
    'scope="mcp:tools"'
)
A_NOTE = "/notes/7"
A_PERSON_NOTE = "/api/notes/7"
A_MACHINE_NOTE = "/api/admin/notes/7"
THE_COOKIE_PERSON = {"id": "user-1", "username": "alice", "role": ADMIN_ROLE}


@pytest.fixture
def resource() -> ProtectedResource:
    return a_resource(marked_routes=MARKED_ROUTES)


@pytest.fixture
def app(resource: ProtectedResource) -> BearerApp:
    return a_bearer_app(
        person_paths=PERSON_PATHS, resource=resource, known_accounts=(a_known_person(),),
    )


def an_agent_token(resource: ProtectedResource, *groups: str, **claims: object) -> str:
    return a_resource_token(resource, groups=list(groups) or [RESOURCE_GROUP], **claims)


def the_transaction(app: BearerApp) -> RecordingSignInTransaction:
    assert isinstance(app.transaction, RecordingSignInTransaction)
    return app.transaction


def assert_admitted_nothing(app: BearerApp) -> None:
    assert app.auth.route_runs == []
    assert the_transaction(app).entries == 0
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", A_NOTE), ("POST", "/notes"), ("GET", A_PERSON_NOTE)],
    ids=["get", "post", "on-a-person-path"],
)
@pytest.mark.parametrize(
    "sent", [{}, {"origin": "https://evil.example"}], ids=["plain", "foreign-origin"],
)
def test_an_agent_token_on_a_marked_route_is_the_capped_person_with_no_cookie_and_no_origin(
    app: BearerApp, resource: ProtectedResource, method: str, path: str, sent: dict[str, str],
) -> None:
    response = app.ask(
        path, method=method, authorization=bearing(an_agent_token(resource)), headers=sent,
    )

    assert response.status_code == 200
    assert response.json() == {"id": OPERATOR_SUBJECT, "username": "lena", "role": MEMBER_ROLE}
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "path", [MARKED_RESOURCE_PERSON.template, MARKED_ADMITTED_USER.template],
)
def test_resource_person_and_admitted_user_read_the_capped_person_on_a_marked_route(
    app: BearerApp, resource: ProtectedResource, path: str,
) -> None:
    response = app.ask(path, method="POST", authorization=bearing(an_agent_token(resource)))

    assert (response.status_code, response.json()["role"]) == (200, MEMBER_ROLE)


def test_a_stored_admin_stays_the_person_role_and_a_marked_admin_route_is_the_plain_403(
    resource: ProtectedResource, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = a_bearer_app(resource=resource, known_accounts=(a_known_person(ADMIN_ROLE),))
    assert app.accounts is not None
    failing(app.accounts, "set_role", monkeypatch)
    token = bearing(an_agent_token(resource, RESOURCE_GROUP, "/apps/x/admin"))

    read = app.ask(A_NOTE, authorization=token)
    admin_only = app.ask(MARKED_ADMIN_NOTES.template, authorization=token)

    assert (read.status_code, read.json()["role"]) == (200, MEMBER_ROLE)
    assert admin_only.status_code == 403
    assert "www-authenticate" not in admin_only.headers
    assert [user.role for user in the_accounts(app) if user.id == OPERATOR_SUBJECT] == [ADMIN_ROLE]
    assert app.audit.account_events == []


@pytest.mark.parametrize(
    "groups", [[], ["/apps/x"], ["/apps/x/other"]], ids=["none", "login-group-only", "sibling"],
)
def test_a_person_without_the_group_gets_the_plain_403_and_the_store_is_untouched(
    app: BearerApp, resource: ProtectedResource, groups: list[str],
) -> None:
    token = a_resource_token(resource, groups=groups)

    response = app.ask(A_NOTE, authorization=bearing(token), cookie=True)

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert_admitted_nothing(app)


def test_an_unknown_subject_gets_the_plain_403_and_no_account_appears(
    resource: ProtectedResource,
) -> None:
    app = a_bearer_app(resource=resource)

    response = app.ask(A_NOTE, authorization=bearing(an_agent_token(resource)), cookie=True)

    assert (response.status_code, response.json()) == (403, {"detail": "Access denied"})
    assert "www-authenticate" not in response.headers
    assert [user.id for user in the_accounts(app)] == [THE_COOKIE_PERSON["id"]]
    assert app.audit.account_events == []


@pytest.mark.parametrize("scope", [ABSENT, "mcp:other"], ids=["absent", "other"])
def test_a_token_without_the_scope_is_an_insufficient_scope_beside_a_valid_cookie(
    app: BearerApp, resource: ProtectedResource, scope: object,
) -> None:
    token = an_agent_token(resource, scope=scope)

    response = app.ask(A_NOTE, authorization=bearing(token), cookie=True)

    assert response.status_code == 403
    assert response.headers["www-authenticate"] == f'{CHALLENGE}, error="insufficient_scope"'
    assert_admitted_nothing(app)


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": ACCESS_TOKEN_NOW - 1_000},
        {"aud": ["https://app.example/mcp", "another-app"]},
        {"iss": "https://evil.example/r"},
        {"azp": "stranger"},
    ],
    ids=["expired", "two-audiences", "wrong-issuer", "unlisted-party"],
)
def test_an_invalid_token_is_a_401_with_the_challenge_and_a_valid_cookie_decides_nothing(
    app: BearerApp, resource: ProtectedResource, claims: dict[str, object],
) -> None:
    token = an_agent_token(resource, **claims)

    response = app.ask(A_NOTE, authorization=bearing(token), cookie=True)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'{CHALLENGE}, error="invalid_token"'
    assert_admitted_nothing(app)


@pytest.mark.parametrize(
    ("authorization", "error"),
    [
        pytest.param((*bearing("a"), *bearing("b")), "invalid_request", id="repeated"),
        pytest.param(("Bearer not a token",), "invalid_request", id="two-credentials"),
        pytest.param(("Bearer ?",), "invalid_token", id="not-a-b64token"),
    ],
)
def test_a_credential_the_gate_refuses_is_answered_with_the_challenge_beside_a_cookie(
    app: BearerApp, authorization: tuple[str, ...], error: str,
) -> None:
    response = app.ask(A_NOTE, authorization=authorization, cookie=True)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == f'{CHALLENGE}, error="{error}"'
    assert_admitted_nothing(app)


def test_an_app_bearer_on_a_marked_person_path_is_admitted_as_a_sign_in_admits_it(
    app: BearerApp,
) -> None:
    response = app.ask(A_PERSON_NOTE, authorization=bearing(a_token(groups=["/apps/x"])))

    assert (response.status_code, response.json()["id"]) == (200, OPERATOR_SUBJECT)
    assert the_transaction(app).entries == 1


@pytest.mark.parametrize("claims", [{}, {"scope": "mcp:tools"}], ids=["app", "with-the-scope"])
def test_a_token_of_another_audience_gets_todays_401_on_a_person_path_and_is_no_admission(
    app: BearerApp, claims: dict[str, object],
) -> None:
    token = a_token(aud="https://other.example/mcp", groups=[RESOURCE_GROUP], **claims)

    response = app.ask(A_PERSON_NOTE, authorization=bearing(token), cookie=True)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == PERSON_INVALID_TOKEN
    assert_admitted_nothing(app)


@pytest.mark.parametrize("claims", [{}, {"scope": "mcp:tools"}], ids=["app", "with-the-scope"])
def test_a_token_of_another_audience_is_ignored_on_any_other_path_and_the_cookie_decides(
    app: BearerApp, claims: dict[str, object],
) -> None:
    token = a_token(aud="https://other.example/mcp", groups=[RESOURCE_GROUP], **claims)

    response = app.ask(A_NOTE, authorization=bearing(token), cookie=True)

    assert (response.status_code, response.json()) == (200, THE_COOKIE_PERSON)
    assert the_transaction(app).entries == 0


def test_an_agent_token_that_is_expired_still_names_the_resource_and_is_not_ignored(
    app: BearerApp, resource: ProtectedResource,
) -> None:
    token = an_agent_token(resource, exp=ACCESS_TOKEN_NOW - 1_000)

    response = app.ask(A_NOTE, authorization=bearing(token), cookie=True)

    assert response.status_code == 401


@pytest.mark.parametrize("path", [A_NOTE, A_PERSON_NOTE])
def test_with_no_bearer_a_cookie_passes_on_a_marked_route(app: BearerApp, path: str) -> None:
    response = app.ask(path, cookie=True)

    assert (response.status_code, response.json()) == (200, THE_COOKIE_PERSON)


def test_another_scheme_is_no_bearer_credential_and_the_cookie_decides(app: BearerApp) -> None:
    response = app.ask(A_NOTE, authorization=("Basic dXNlcjpwYXNz",), cookie=True)

    assert (response.status_code, response.json()) == (200, THE_COOKIE_PERSON)


def test_with_no_bearer_a_marked_route_with_no_session_is_the_session_gates_401(
    app: BearerApp,
) -> None:
    response = app.ask(A_NOTE)

    assert response.status_code == 401
    assert "resource_metadata" not in response.headers.get("www-authenticate", "")


def test_a_cross_origin_cookie_post_on_a_marked_route_is_refused_and_a_same_origin_one_passes(
    app: BearerApp,
) -> None:
    refused = app.ask(
        MARKED_NEW_NOTE.template, method="POST", cookie=True,
        headers={"origin": "https://evil.example"},
    )
    passed = app.ask(
        MARKED_NEW_NOTE.template, method="POST", cookie=True,
        headers={"sec-fetch-site": "same-origin"},
    )

    assert refused.status_code == 403
    assert (passed.status_code, passed.json()) == (200, THE_COOKIE_PERSON)


CSRF_REFUSAL = 403
NO_SESSION = 401


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        pytest.param("DELETE", A_NOTE, CSRF_REFUSAL, id="unmarked-method"),
        pytest.param("POST", A_NOTE, CSRF_REFUSAL, id="another-methods-marked-template"),
        pytest.param("HEAD", A_NOTE, NO_SESSION, id="head-on-a-marked-get"),
        pytest.param("GET", f"{A_NOTE}/", NO_SESSION, id="trailing-slash"),
        pytest.param("GET", f"{A_NOTE}/more", NO_SESSION, id="longer-path"),
        pytest.param("GET", "/notes", NO_SESSION, id="shorter-path"),
        pytest.param("GET", "/notes/", NO_SESSION, id="empty-parameter"),
        pytest.param("GET", "/notes/%2e", NO_SESSION, id="dot-parameter"),
        pytest.param("GET", "/notes/%2e%2e", NO_SESSION, id="dot-dot-parameter"),
        pytest.param("GET", "/notes/a%2Fb", NO_SESSION, id="decoded-slash-in-a-parameter"),
        pytest.param("POST", "/notes/", CSRF_REFUSAL, id="post-trailing-slash"),
        pytest.param("DELETE", A_PERSON_NOTE, NO_SESSION, id="unmarked-method-on-a-person-path"),
        pytest.param("GET", f"{A_PERSON_NOTE}/more", NO_SESSION, id="longer-path-on-a-person-path"),
        pytest.param("GET", "/other/7", NO_SESSION, id="unmarked-path"),
    ],
)
def test_the_agent_token_is_refused_on_every_method_and_shape_a_mark_does_not_cover(
    app: BearerApp, resource: ProtectedResource, method: str, path: str, status: int,
) -> None:
    response = app.ask(path, method=method, authorization=bearing(an_agent_token(resource)))

    assert response.status_code == status
    assert "resource_metadata" not in response.headers.get("www-authenticate", "")
    assert_admitted_nothing(app)


def test_a_marked_template_overlapping_a_machine_path_stays_a_machine_path(
    app: BearerApp, resource: ProtectedResource,
) -> None:
    response = app.ask(A_MACHINE_NOTE, authorization=bearing(an_agent_token(resource)))

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == REALM_INVALID_TOKEN
    assert_admitted_nothing(app)


def test_a_marked_route_at_the_entry_point_is_decided_as_the_entry_point() -> None:
    entry = a_resource(marked_routes=frozenset({MarkedRoute("GET", "/mcp")}))
    app = a_bearer_app(resource=entry, known_accounts=(a_known_person(),))

    no_credential = app.ask("/mcp", cookie=True)

    assert no_credential.status_code == 401
    assert no_credential.headers["www-authenticate"] == CHALLENGE


@pytest.mark.parametrize(
    ("path", "changes"),
    [
        pytest.param(MARKED_NEW_NOTE.template, {"method": "GET"}, id="current-user-method"),
        pytest.param(MARKED_RESOURCE_PERSON.template, {"method": "GET"}, id="resource-person"),
        pytest.param(MARKED_ADMITTED_USER.template, {"method": "GET"}, id="admitted-user"),
        pytest.param(MARKED_NEW_NOTE.template, {"app": object()}, id="current-user-app"),
    ],
)
def test_every_reader_on_a_marked_route_refuses_a_request_changed_after_admission(
    resource: ProtectedResource, path: str, changes: dict[str, object],
) -> None:
    app = a_bearer_app(
        resource=resource, known_accounts=(a_known_person(),),
        inner_middleware=(Middleware(RewritingTheRequest, changes=changes),),
    )

    response = app.ask(path, method="POST", authorization=bearing(an_agent_token(resource)))

    assert response.status_code == 500
    assert app.auth.route_runs == []


@pytest.mark.parametrize(
    "method",
    ["get", "", "GE T", "GET,POST", "GÉT", "GET\n", "G(T"],
)
def test_a_marked_route_refuses_a_method_that_is_not_an_upper_case_token(method: str) -> None:
    with pytest.raises(ValueError, match="method"):
        MarkedRoute(method, "/notes")


@pytest.mark.parametrize(
    "template",
    [
        "", "/", "notes", "/notes/", "//notes", "/notes//x", "/a/{x", "/a/x}", "/a/{}",
        "/a/x{y}", "/a/{x}y", "/a/{x}{y}", "/a/{x:path}", "/a/{x:int}", "/a/{x-y}", "/a/b c",
        "/a/%2e", "/a/%2F", "/a/./b", "/a/..", "/a/ü", "/a?x", "/a#f", "/a/*", "/a/{*x}",
        "/a/\n",
    ],
)
def test_a_marked_route_refuses_a_template_that_is_not_literals_and_whole_segment_names(
    template: str,
) -> None:
    with pytest.raises(ValueError, match="template"):
        MarkedRoute("GET", template)


@pytest.mark.parametrize("template", ["/a", "/a/{b}", "/a-b/{c_d}/e.f_g~h", "/{a}/{b}"])
def test_a_marked_route_takes_literal_and_whole_segment_name_segments(template: str) -> None:
    assert MarkedRoute("GET", template).template == template


def test_marked_routes_that_are_not_marked_routes_are_refused() -> None:
    with pytest.raises(TypeError, match="marked_routes"):
        a_resource(marked_routes=frozenset({("GET", "/notes")}))  # type: ignore[arg-type]


def test_a_resource_without_marked_routes_has_only_its_entry_point(
    resource: ProtectedResource,
) -> None:
    app = a_bearer_app(resource=a_resource(), known_accounts=(a_known_person(),))

    response = app.ask(A_NOTE, authorization=bearing(an_agent_token(resource)))

    assert response.status_code == 401
    assert_admitted_nothing(app)
