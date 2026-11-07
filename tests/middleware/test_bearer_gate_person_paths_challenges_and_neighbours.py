"""The bearer gate's person paths beside the cookie, the other kind of path and the challenge.

The arrangement is that of `tests/support/person_paths_arrangement.py`.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException

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
    """REFUSE-20: a path outside the person paths keeps its session answer, with no challenge."""
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


SESSION_READERS = [
    pytest.param(True, PERSON_ME_PATH, id="SG-current_user"),
    pytest.param(False, PERSON_ME_PATH, id="NG-current_user"),
    pytest.param(True, PERSON_ADMIN_ME_PATH, id="SG-admin_user"),
    pytest.param(False, PERSON_ADMIN_ME_PATH, id="NG-admin_user"),
    pytest.param(True, PERSON_ADMITTED_ADMIN_PATH, id="SG-admitted_admin"),
]


@pytest.mark.parametrize(("session_gate", "path"), SESSION_READERS)
def test_a_person_path_without_a_bearer_credential_is_refused_as_the_session_refuses_it(
    session_gate: bool,
    path: str,
) -> None:
    """REFUSE-13: without a bearer credential the session refuses, as the row says."""
    app = a_person_app(session_gate=session_gate, login_redirect=LOGIN_REDIRECT)
    api_call = {"accept": "application/json"}
    invalid_cookie = {"cookie": f"{app.auth.config.session_cookie_name}=unsigned", **api_call}

    refusals = [app.ask(path, headers=api_call), app.ask(path, headers=invalid_cookie)]
    navigation = app.ask(path, headers={"accept": "text/html"}, follow_redirects=False)

    assert [(r.status_code, r.json()["detail"], the_challenge(r)) for r in refusals] == [
        (401, "Authentication required", PERSON_REALM),
        (401, "Invalid session", PERSON_REALM),
    ]
    assert (navigation.status_code, the_challenge(navigation)) == (302, None)


@BOTH_HOSTS
def test_a_navigation_to_a_person_path_still_gets_its_login_redirect(session_gate: bool) -> None:
    """REFUSE-05: `LoginRedirect` redirects a navigation and leaves an API call its 401."""
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
    """REFUSE-19: a cookie person an admin reader refuses on a person path gets no challenge."""
    app = a_person_app(session_gate=session_gate, cookie_role=MEMBER_ROLE)

    response = app.ask(path, cookie=True)

    assert (response.status_code, response.json(), the_challenge(response)) == (
        403,
        {"detail": "Admin access required"},
        None,
    )


HOST_CHALLENGE = 'Basic realm="host"'


@BOTH_HOSTS
@pytest.mark.parametrize(
    ("path", "headers", "challenge"),
    [
        pytest.param("/api/host-refusal", None, None, id="a host that adds no challenge"),
        pytest.param(
            "/api/host-challenge",
            {"WWW-Authenticate": HOST_CHALLENGE},
            HOST_CHALLENGE,
            id="a host that adds its own",
        ),
    ],
)
@pytest.mark.parametrize("credential", ["cookie", "token"])
def test_a_hosts_own_401_on_a_person_path_carries_only_the_challenge_the_host_adds(
    session_gate: bool,
    path: str,
    headers: dict[str, str] | None,
    challenge: str | None,
    credential: str,
) -> None:
    """REFUSE-21: a host's own 401 on a person path has no challenge unless the host adds one."""
    app = a_person_app(session_gate=session_gate)

    @app.auth.app.get(path)
    def host_refusal() -> None:
        raise HTTPException(status_code=401, detail="Host refusal", headers=headers)

    response = app.ask(
        path,
        cookie=credential == "cookie",
        authorization=bearing(ADMIN_TOKEN) if credential == "token" else (),
    )

    assert (response.status_code, response.json(), the_challenge(response)) == (
        401,
        {"detail": "Host refusal"},
        challenge,
    )


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
