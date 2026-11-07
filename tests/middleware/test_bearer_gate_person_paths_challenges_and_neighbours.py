"""The bearer gate's person paths beside the cookie, the other kind of path and the challenge.

The arrangement is that of `tests/support/person_paths_arrangement.py`.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from fastapi import Depends, HTTPException
from httpx import Response
from starlette.websockets import WebSocket

from tests.support.gate_arrangement import (
    ADMISSION,
    EXPORT_PATH,
    FOREIGN_SECRET_PATH,
    PERSON_ADMIN_ME_PATH,
    PERSON_ADMITTED_ADMIN_PATH,
    PERSON_ADMITTED_ME_PATH,
    PERSON_INVALID_REQUEST,
    PERSON_INVALID_TOKEN,
    PERSON_ME_PATH,
    PERSON_PATHS,
    PERSON_PREFIX,
    PERSON_REALM,
    REALM_INSUFFICIENT_SCOPE,
    a_bearer_app,
    a_key_set_answering,
    a_token,
    bearing,
)
from tests.support.oidc_arrangement import (
    ACCESS_TOKEN_LEEWAY_SECONDS,
    ACCESS_TOKEN_LIFETIME_SECONDS,
    ACCESS_TOKEN_NOW,
    OPERATOR_SUBJECT,
    REALM_JWKS_URL,
)
from tests.support.oidc_login_host import (
    RecordingSignInTransaction,
    failing,
)
from tests.support.person_paths_arrangement import (
    ADMIN_READERS,
    ADMIN_TOKEN,
    BOTH_HOSTS,
    MEMBER_TOKEN,
    UNGATED_ADMIN_PATH,
    UNGATED_ME_PATH,
    a_lena,
    a_person_app,
    ran,
    the_account,
    the_challenge,
)
from tests.support.webauth_arrangement import (
    ADMIN_ROLE,
    LOGIN_REDIRECT,
    MEMBER_ROLE,
    SAME_ORIGIN_REQUEST,
)
from webauth.dependencies import current_user_dependency
from webauth.policies import (
    PathRules,
    PublicRule,
)
from webauth.ports import AuthenticatedUser


PERSON_READERS = [
    pytest.param(PERSON_ME_PATH, id="current_user"),
    pytest.param(PERSON_ADMIN_ME_PATH, id="admin_user"),
    pytest.param(PERSON_ADMITTED_ME_PATH, id="admitted_user"),
    pytest.param(PERSON_ADMITTED_ADMIN_PATH, id="admitted_admin"),
]
EXPIRY_TIMES = [
    pytest.param(-1, 200, id="before-expiry"),
    pytest.param(0, 200, id="at-expiry"),
    pytest.param(ACCESS_TOKEN_LEEWAY_SECONDS - 1, 200, id="inside-the-leeway"),
    pytest.param(ACCESS_TOKEN_LEEWAY_SECONDS, 401, id="at-expiry-plus-leeway"),
]
EXPIRY = ACCESS_TOKEN_NOW + ACCESS_TOKEN_LIFETIME_SECONDS


@BOTH_HOSTS
def test_a_person_path_refused_for_want_of_a_session_challenges_with_bearer(
    session_gate: bool,
) -> None:
    """A person path refused for want of a session carries the person realm."""
    app = a_person_app(session_gate=session_gate)

    readers = [PERSON_ME_PATH, PERSON_ADMIN_ME_PATH]
    answers = [app.ask(path) for path in readers]

    assert [(answer.status_code, the_challenge(answer)) for answer in answers] == [
        (401, PERSON_REALM),
        (401, PERSON_REALM),
    ]


OUTSIDE_READERS = [
    pytest.param(True, UNGATED_ME_PATH, id="SG-current_user"),
    pytest.param(False, UNGATED_ME_PATH, id="NG-current_user"),
    pytest.param(True, UNGATED_ADMIN_PATH, id="SG-admin_user"),
    pytest.param(False, UNGATED_ADMIN_PATH, id="NG-admin_user"),
]


@pytest.mark.parametrize(("session_gate", "path"), OUTSIDE_READERS)
def test_a_path_outside_the_person_paths_is_refused_with_its_session_answer_and_no_challenge(
    session_gate: bool,
    path: str,
) -> None:
    """REFUSE-20: a path outside the person paths keeps its answers."""
    app = a_person_app(session_gate=session_gate, login_redirect=LOGIN_REDIRECT)
    api_call = {"accept": "application/json"}
    invalid_cookie = {"cookie": f"{app.auth.config.session_cookie_name}=unsigned", **api_call}

    refusals = [app.ask(path, headers=api_call), app.ask(path, headers=invalid_cookie)]
    navigation = app.ask(path, headers={"accept": "text/html"}, follow_redirects=False)

    assert [(r.status_code, r.json()["detail"], the_challenge(r)) for r in refusals] == [
        (401, "Authentication required", None),
        (401, "Invalid session", None),
    ]
    assert (navigation.status_code, the_challenge(navigation)) == (302, None)


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
    """TOKEN-13: a route that takes a foreign secret in `Authorization: Bearer` keeps working."""
    app = a_person_app(session_gate=session_gate)

    response = app.ask(FOREIGN_SECRET_PATH, method=method, authorization=("Bearer s3cret",))

    assert (response.status_code, response.json(), the_challenge(response)) == (
        200,
        {"authorization": "Bearer s3cret"},
        None,
    )
    assert app.key_sets.fetched_urls == []


@BOTH_HOSTS
@pytest.mark.parametrize("path", PERSON_READERS)
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
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TOKEN-15: a bearer credential is judged by the token and never falls back to the cookie."""
    app = a_person_app(session_gate=session_gate)
    failing(app.auth.sessions, "load", monkeypatch)

    response = app.ask(path, authorization=authorization, cookie=True)

    assert response.status_code == 401
    assert the_challenge(response) in {PERSON_INVALID_REQUEST, PERSON_INVALID_TOKEN}
    assert ran(app) == []


@BOTH_HOSTS
def test_a_cookie_only_post_on_a_person_path_without_origin_is_still_refused_by_csrf(
    session_gate: bool,
) -> None:
    """TOKEN-29: a cookie-only request on a person path is checked as before."""
    app = a_person_app(session_gate=session_gate)

    response = app.ask(PERSON_ME_PATH, method="POST", cookie=True)

    assert (response.status_code, response.json()) == (403, {"detail": "Missing Origin header"})


def test_the_gate_names_no_machine_paths_when_it_has_person_paths_alone() -> None:
    """TOKEN-03: a gate with person paths alone serves them."""
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert response.status_code == 200


def test_a_gate_with_person_paths_alone_adds_no_store_to_no_path() -> None:
    app = a_bearer_app(paths=PathRules(), person_paths=PERSON_PATHS)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert "no-store" not in response.headers.get("cache-control", "")


def _the_answer(response: Response) -> tuple[int, Any, Any]:
    body = response.json()
    return (response.status_code, body.get("role"), body.get("detail"))


@pytest.mark.parametrize(
    ("method", "path"),
    [
        pytest.param("DELETE", PERSON_ME_PATH, id="current_user-delete"),
        pytest.param("GET", PERSON_ADMIN_ME_PATH, id="admin_user"),
        pytest.param("GET", PERSON_ADMITTED_ME_PATH, id="admitted_user"),
        pytest.param("GET", PERSON_ADMITTED_ADMIN_PATH, id="admitted_admin"),
    ],
)
@pytest.mark.parametrize(
    ("role", "token"),
    [
        pytest.param(ADMIN_ROLE, ADMIN_TOKEN, id="admin"),
        pytest.param(MEMBER_ROLE, MEMBER_TOKEN, id="member"),
    ],
)
def test_a_token_gets_the_answer_its_role_gets_by_cookie(
    method: str,
    path: str,
    role: str,
    token: str,
) -> None:
    """TOKEN-01, TOKEN-02, TOKEN-07, TOKEN-09, TOKEN-10: a token holds the rights of its role.

    Each reader answers a token as it answers a browser person of the same role, deletion
    included; nothing more is asked and nothing is added.
    """
    app = a_person_app(cookie_role=role)

    by_cookie = app.ask(path, method=method, cookie=True, headers=SAME_ORIGIN_REQUEST)
    by_token = app.ask(path, method=method, authorization=bearing(token))

    assert _the_answer(by_token) == _the_answer(by_cookie)


@pytest.mark.parametrize(
    ("session_gate", "path"),
    [
        pytest.param(True, PERSON_ME_PATH, id="SG-current_user"),
        pytest.param(False, PERSON_ME_PATH, id="NG-current_user"),
        pytest.param(True, PERSON_ADMIN_ME_PATH, id="SG-admin_user"),
        pytest.param(False, PERSON_ADMIN_ME_PATH, id="NG-admin_user"),
        pytest.param(True, PERSON_ADMITTED_ME_PATH, id="SG-admitted_user"),
        pytest.param(True, PERSON_ADMITTED_ADMIN_PATH, id="SG-admitted_admin"),
    ],
)
def test_every_reader_returns_the_account_behind_the_token_and_the_route_is_unchanged(
    session_gate: bool,
    path: str,
) -> None:
    """TOKEN-06: each reader returns the token's account, and the same route serves the browser."""
    app = a_person_app(session_gate=session_gate, known_accounts=(a_lena(),))

    by_token = app.ask(path, authorization=bearing(ADMIN_TOKEN))
    by_cookie = app.ask(path, cookie=True)

    assert (by_token.status_code, by_token.json()["username"]) == (200, "lena")
    assert by_cookie.status_code == 200


@pytest.mark.parametrize("login_group", ["/apps/x", "/apps/y"])
def test_a_token_issued_to_hal_is_admitted_the_same_way_in_apps_of_another_group(
    login_group: str,
) -> None:
    """TOKEN-08: a token issued to the hal registration opens the person paths of any app."""
    admission = replace(ADMISSION, login_group=login_group, admin_group=f"{login_group}/admin")
    app = a_person_app(admission=admission)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(a_token(groups=[login_group])))

    assert (response.status_code, response.json()["role"]) == (200, MEMBER_ROLE)


@BOTH_HOSTS
@pytest.mark.parametrize("path", [UNGATED_ME_PATH, UNGATED_ADMIN_PATH])
def test_a_token_on_a_path_the_host_did_not_name_is_not_admitted_and_meets_the_session_gate(
    session_gate: bool,
    path: str,
) -> None:
    """TOKEN-11, TOKEN-12: a path outside the person paths admits no token and stays untouched."""
    app = a_person_app(session_gate=session_gate)

    response = app.ask(path, authorization=bearing(ADMIN_TOKEN))

    assert isinstance(app.transaction, RecordingSignInTransaction)
    assert (response.status_code, response.json(), the_challenge(response)) == (
        401,
        {"detail": "Authentication required"},
        None,
    )
    assert (app.transaction.entries, the_account(app), app.key_sets.fetched_urls) == (0, None, [])


@BOTH_HOSTS
@pytest.mark.parametrize("method", ["POST", "DELETE"])
@pytest.mark.parametrize("credential", [ADMIN_TOKEN, "s3cret"], ids=["a-valid-token", "a-secret"])
def test_an_authorization_header_on_a_session_path_is_still_refused_by_the_csrf_origin_check(
    session_gate: bool,
    method: str,
    credential: str,
) -> None:
    """TOKEN-12: a state-changing request on a path no rule selects is still CSRF-checked."""
    app = a_person_app(session_gate=session_gate)
    cross_site = {"origin": "https://evil.test", "sec-fetch-site": "cross-site"}

    response = app.ask(
        UNGATED_ME_PATH,
        method=method,
        authorization=bearing(credential),
        cookie=True,
        headers=cross_site,
    )

    assert (response.status_code, response.json()) == (
        403,
        {"detail": "Cross-origin request rejected"},
    )
    assert app.key_sets.fetched_urls == []


@pytest.mark.parametrize("path", PERSON_READERS)
def test_a_token_admission_creates_no_session(path: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """TOKEN-22: a token admission creates no session, whichever reader asks."""
    app = a_person_app()
    failing(app.auth.sessions, "create", monkeypatch)

    response = app.ask(path, authorization=bearing(ADMIN_TOKEN))

    assert response.status_code == 200


def test_the_key_set_is_fetched_before_the_sign_in_transaction_is_entered() -> None:
    """TOKEN-25: no issuer call happens inside the sign-in transaction."""
    key_sets = a_key_set_answering()
    app = a_person_app(key_sets=key_sets)
    assert isinstance(app.transaction, RecordingSignInTransaction)
    transaction = app.transaction
    entries_at_fetch: list[int] = []
    key_sets.before_answer = lambda: entries_at_fetch.append(transaction.entries)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(ADMIN_TOKEN))

    assert (response.status_code, key_sets.fetched_urls, entries_at_fetch) == (
        200,
        [REALM_JWKS_URL],
        [0],
    )
    assert transaction.entries == 1


def test_a_host_dependency_resolves_before_the_reader_runs_on_a_token_request() -> None:
    """TOKEN-32: a host dependency of a person route still resolves on a token request."""
    app = a_person_app()
    events: list[str] = []

    def session_store() -> Any:
        events.append("session_store")
        return app.auth.sessions

    dependencies = current_user_dependency(
        session_store=session_store,
        on_authenticated=lambda _user: events.append("reader"),
    )

    @app.auth.app.get(f"{PERSON_PREFIX}resolved")
    def resolved(_user: AuthenticatedUser = Depends(dependencies.current_user)) -> dict[str, str]:
        return {}

    response = app.ask(f"{PERSON_PREFIX}resolved", authorization=bearing(ADMIN_TOKEN))

    assert (response.status_code, events) == (200, ["session_store", "reader"])


@pytest.mark.parametrize(("seconds_past_expiry", "status"), EXPIRY_TIMES)
def test_a_token_works_until_its_expiry_plus_leeway_whatever_the_issuer_decided_since(
    seconds_past_expiry: int,
    status: int,
) -> None:
    """TOKEN-33: disabling the person at Keycloak ends a token only at its exp plus leeway."""
    app = a_person_app()
    app.clock.now = float(EXPIRY + seconds_past_expiry)

    response = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert response.status_code == status
    assert set(app.key_sets.fetched_urls) == {REALM_JWKS_URL}


def test_a_token_stays_valid_after_the_persons_sessions_end() -> None:
    """TOKEN-34, TOKEN-35: ending the person's sessions, as a sign-out or a back-channel logout
    does, ends no token."""
    app = a_person_app()
    cookie_person = app.auth.sessions.stored_record.user

    ended = app.auth.sessions.delete_for_user(cookie_person.id)
    by_cookie = app.ask(PERSON_ME_PATH, cookie=True)
    by_token = app.ask(PERSON_ME_PATH, authorization=bearing(MEMBER_TOKEN))

    assert (ended, by_cookie.status_code, by_token.status_code) == (1, 401, 200)


def test_an_older_token_writes_the_role_it_carries_back_within_its_lifetime() -> None:
    """TOKEN-36: a token issued before a group change writes its old role back while it lives."""
    app = a_person_app(known_accounts=(a_lena(),))
    older = a_token(groups=["/apps/x"], iat=ACCESS_TOKEN_NOW - 60)
    newer = a_token()

    promoted = app.ask(PERSON_ME_PATH, authorization=bearing(newer)).json()["role"]
    written_back = app.ask(PERSON_ME_PATH, authorization=bearing(older)).json()["role"]

    assert (promoted, written_back, the_account(app).role) == (ADMIN_ROLE, MEMBER_ROLE, MEMBER_ROLE)


@pytest.mark.parametrize(("seconds_past_expiry", "status"), EXPIRY_TIMES)
def test_a_copied_bound_token_is_the_person_for_any_sender_until_it_expires(
    seconds_past_expiry: int,
    status: int,
) -> None:
    """TOKEN-37: a bound token sent by another sender is a plain bearer until it expires."""
    app = a_person_app()
    app.clock.now = float(EXPIRY + seconds_past_expiry)
    bound = a_token(cnf={"jkt": "thumbprint-of-the-key-it-was-bound-to"})

    response = app.ask(
        PERSON_ME_PATH,
        authorization=bearing(bound),
        headers={"dpop": "not-a-proof", "user-agent": "another-sender"},
    )

    assert response.status_code == status
    if status == 200:
        assert response.json()["id"] == OPERATOR_SUBJECT


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no-token"),
        pytest.param({"authorization": f"Bearer {ADMIN_TOKEN}"}, id="admin-token"),
        pytest.param({"authorization": "Bearer abc!def"}, id="invalid-token"),
    ],
)
def test_a_websocket_scope_on_a_person_path_reaches_the_app_untouched(
    headers: dict[str, str],
) -> None:
    """TOKEN-39: a WebSocket scope on a person path passes the bearer gate unread."""
    app = a_person_app()
    socket_path = f"{PERSON_PREFIX}socket"

    @app.auth.app.websocket(socket_path)
    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"reached": True})
        await websocket.close()

    with app.auth.client.websocket_connect(socket_path, headers=headers) as connection:
        assert connection.receive_json() == {"reached": True}
    assert app.key_sets.fetched_urls == []
