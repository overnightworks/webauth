"""The bearer gate's person paths beside the cookie, the other kind of path and the challenge.

The arrangement is that of `test_bearer_gate_person_paths`.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.support.gate_arrangement import (
    EXPORT_PATH,
    FOREIGN_SECRET_PATH,
    PERSON_ADMIN_ME_PATH,
    PERSON_ADMITTED_ADMIN_PATH,
    PERSON_INVALID_REQUEST,
    PERSON_INVALID_TOKEN,
    PERSON_ME_PATH,
    PERSON_PATHS,
    PERSON_REALM,
    REALM_INSUFFICIENT_SCOPE,
    a_bearer_app,
    a_token,
    bearing,
)
from tests.support.oidc_login_host import (
    failing,
)
from tests.support.person_paths_arrangement import (
    ADMIN_READERS,
    ADMIN_TOKEN,
    BOTH_HOSTS,
    MEMBER_TOKEN,
    UNGATED_ME_PATH,
    a_person_app,
    ran,
    the_challenge,
)
from tests.support.webauth_arrangement import (
    LOGIN_REDIRECT,
    MEMBER_ROLE,
)
from webauth.policies import (
    PathRules,
    PublicRule,
)


@BOTH_HOSTS
def test_a_person_path_refused_for_want_of_a_session_challenges_with_bearer(
    session_gate: bool,
) -> None:
    app = a_person_app(session_gate=session_gate)

    readers = [PERSON_ME_PATH, PERSON_ADMIN_ME_PATH]
    answers = [app.ask(path) for path in readers]

    assert [(answer.status_code, the_challenge(answer)) for answer in answers] == [
        (401, PERSON_REALM),
        (401, PERSON_REALM),
    ]
    outside = app.ask(UNGATED_ME_PATH)
    assert (outside.status_code, the_challenge(outside)) == (401, None)


def test_the_admitted_admin_401_of_a_person_path_without_a_gate_admission_challenges() -> None:
    opened = PublicRule(PathRules(exact=frozenset({PERSON_ADMITTED_ADMIN_PATH})))
    app = a_person_app(public=(opened,))

    response = app.ask(PERSON_ADMITTED_ADMIN_PATH)

    assert (response.status_code, the_challenge(response)) == (401, PERSON_REALM)


@BOTH_HOSTS
def test_a_navigation_to_a_person_path_still_gets_its_login_redirect(session_gate: bool) -> None:
    app = a_person_app(session_gate=session_gate, login_redirect=LOGIN_REDIRECT)

    navigation = app.ask(
        PERSON_ME_PATH,
        headers={"accept": "text/html"},
        follow_redirects=False,
    )
    api_call = app.ask(PERSON_ME_PATH, headers={"accept": "application/json"})

    assert (navigation.status_code, the_challenge(navigation)) == (302, None)
    assert (api_call.status_code, the_challenge(api_call)) == (401, PERSON_REALM)


@ADMIN_READERS
def test_a_cookie_person_refused_by_the_admin_readers_gets_no_challenge(
    session_gate: bool,
    path: str,
) -> None:
    app = a_person_app(session_gate=session_gate, cookie_role=MEMBER_ROLE)

    response = app.ask(path, cookie=True)

    assert (response.status_code, response.json(), the_challenge(response)) == (
        403,
        {"detail": "Admin access required"},
        None,
    )


def test_a_person_path_refuses_a_token_for_another_audience_with_invalid_token() -> None:
    app = a_person_app()

    response = app.ask(
        PERSON_ME_PATH,
        authorization=bearing(a_token(aud="another-application")),
    )

    assert (response.status_code, the_challenge(response)) == (401, PERSON_INVALID_TOKEN)


def test_one_admin_token_opens_both_a_machine_path_and_a_person_path() -> None:
    app = a_person_app()

    machine = app.ask(EXPORT_PATH, authorization=bearing(ADMIN_TOKEN))
    person = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

    assert (machine.status_code, person.status_code) == (200, 200)


def test_a_user_token_that_opens_a_person_path_is_refused_on_a_machine_path_with_insufficient_scope() -> (  # noqa: E501
    None
):
    app = a_person_app()

    person = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))
    machine = app.ask(EXPORT_PATH, authorization=bearing(MEMBER_TOKEN))

    assert person.status_code == 200
    assert (machine.status_code, the_challenge(machine)) == (403, REALM_INSUFFICIENT_SCOPE)


@BOTH_HOSTS
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_foreign_bearer_secret_on_a_path_neither_rule_selects_reaches_its_route_untouched(
    session_gate: bool,
    method: str,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(FOREIGN_SECRET_PATH, method=method, authorization=("Bearer s3cret",))

    assert (response.status_code, response.json(), the_challenge(response)) == (
        200,
        {"authorization": "Bearer s3cret"},
        None,
    )
    assert app.key_sets.fetched_urls == []


@BOTH_HOSTS
@pytest.mark.parametrize(
    ("authorization", "request_keywords"),
    [
        pytest.param((f"Bearer {ADMIN_TOKEN}", f"Bearer {ADMIN_TOKEN}"), {}, id="malformed"),
        pytest.param((f"Bearer {ADMIN_TOKEN}x",), {}, id="invalid"),
    ],
)
def test_an_invalid_or_malformed_token_beside_a_valid_cookie_never_falls_back_to_the_cookie(
    session_gate: bool,
    authorization: tuple[str, ...],
    request_keywords: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = a_person_app(session_gate=session_gate)
    failing(app.auth.sessions, "load", monkeypatch)

    response = app.ask(PERSON_ME_PATH, authorization=authorization, cookie=True)

    assert response.status_code == 401
    assert the_challenge(response) in {PERSON_INVALID_REQUEST, PERSON_INVALID_TOKEN}
    assert ran(app) == []


@BOTH_HOSTS
def test_a_cookie_only_post_on_a_person_path_without_origin_is_still_refused_by_csrf(
    session_gate: bool,
) -> None:
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ME_PATH, method="POST", cookie=True)

    assert (response.status_code, response.json()) == (403, {"detail": "Missing Origin header"})


def test_the_gate_names_no_machine_paths_when_it_has_person_paths_alone() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert response.status_code == 200


def test_a_gate_with_person_paths_alone_adds_no_store_to_no_path() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert "no-store" not in response.headers.get("cache-control", "")
