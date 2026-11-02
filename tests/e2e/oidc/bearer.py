"""Plays hal against real Keycloak: the bearer gate admits, or refuses, real access tokens.

``drive_bearer_phase`` runs after the back-channel phase of ``prove.py`` and prints
``SCENARIO <number> <width> <origin>`` for scenarios 28 to 51 and 55 to 76. hal is two public
clients (``d1-hal``, ``d1-other``) with PKCE, ``at+jwt`` access tokens and the optional
audience scopes; ``d1-app-c`` is a client that exists only to be an audience. hal gets its
codes from a browser signed in at Keycloak (the redirect to the loopback port nobody
listens on fails, and Playwright's failed request names the code), posts the code exchange
itself, and sends the access token as the ``Authorization`` header to the bearer host:
``build_app`` with ``bearer_authorized_parties``, whose routes under ``/api/admin/`` are E
(export), D (delete) and P (session probe); its person path ``/api/me`` (GET and POST)
answers the account behind the token. ``CHECK bearer-token-header-type`` records the
header ``typ`` of the first minted token. Each scenario's id is the matrix id of the item.

- 28 (E01) an admin token opens E after ``/reset``.
- 29 (E02) E01 created no account, no session and no session transaction.
- 30 (E03) D with the admin token and a cross-site origin, no cookie.
- 31 (E04) D with the admin token and another person's session cookie.
- 32 to 34 (E05 to E07) a session cookie alone opens no machine route.
- 35 (E08) the admin token and a cookie on P: a host mistake, answered 500.
- 36 and 38 (E09 and E11) an ID token and a refresh token; 37 is unused.
- 39 to 41 (E12 to E14) audiences: the foreign one, two of them, ``account``.
- 42 (E15) a token of ``d1-other``.
- 43, 44 (E16, E17) a member without the admin group, and a person in no group.
- 45 (E18) a disabled person's token. 46 (E19) the token after a browser sign-out.
- 47, 48 (E20, E21) a 15 s token before ``exp`` and after ``exp`` plus leeway.
- 49 (E22) a flipped signature character.
- 50 (E23) every machine-route answer is ``no-store`` and sets no cookie.
- 51 (E24) no token sent appears in an answer or the host log; each refusal has a line.

The person-path scenarios send tokens to ``/api/me``; their ids are the matrix's H1 to H6.

- 55 (H1) a member who never signed in to the app: the token answers that person with the
  user role and the Keycloak username; one account, one ``USER_CREATED``, no session.
- 56 (H2) the same person after a browser sign-in: the token answers the same username and id.
- 57 (H3) ``POST /api/me`` with the token, no ``Origin`` and no cookie reaches the route.
- 58 (H4) the outsider's token: 403 ``No access``, and no account is created.
- 59 (H5) a ``d1-other`` token: 401 ``invalid_token``.
- 60 (H6) after a browser sign-out the token still opens ``/api/me``.

The resource scenarios 61 to 66 (an agent's token at the entry point ``/mcp``) and 67 to 72
(the same token on the resource's marked routes)
live in ``bearer_resource``; ``CHECK bearer-resource-tokens`` runs before them. Scenarios 73 to 76
(``current_groups`` at a real Keycloak, after ``CHECK refreshed-id-token-facts``) live in
``bearer_groups``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import secrets
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from bearer_groups import (
    a_group_removed_between_two_calls_is_gone,
    an_admin_logout_asks_to_sign_in_again,
    no_token_shows_in_an_answer_or_the_log,
    refreshed_id_token_facts,
    the_apps_own_logout_ends_the_session,
)
from bearer_resource import (
    a_bearer_on_a_marked_route_is_not_the_resource_admission,
    a_marked_route_keeps_session_and_csrf_without_a_bearer,
    known_agent_is_admitted_as_a_person,
    marked_route_admin_reader_is_the_plain_403,
    marked_route_admits_the_agent_capped,
    marked_route_refusals_beside_a_cookie,
    marked_route_refuses_the_agent_beyond_its_mark,
    mint_agent_tokens,
    no_credential_and_a_cookie_get_the_challenge,
    no_group_and_unknown_subject_are_refused_plainly,
    stored_admin_is_admitted_with_the_person_role,
    the_agent_token_opens_no_other_path,
    tokens_the_resource_refuses,
)
from bearer_run import (
    EXPORT,
    HAL,
    ME,
    PERSON_CHALLENGE_INVALID_TOKEN,
    SUBJECT,
    BearerRun,
    Call,
    Person,
    as_list,
    assert_answer,
    assert_person_answer,
    claims_of,
    session_cookies,
    token_part,
)
from certificates import ThrowawayTls
from harness import (
    free_port,
    launch_pinned_chromium,
    reset_host,
    start_host,
    stop_host,
)
from host_app import (
    LEEWAY_SECONDS,
    LOOPBACK,
    RESOURCE_PATH,
    HostSettings,
)
from playwright.sync_api import Playwright
from realm import (
    ADMIN_NAME,
    CLIENT_ID,
    GROUPED_NAME,
    IDP_HOST,
    OUTSIDER_NAME,
    REALM,
    UNGROUPED_NAME,
    USER_GROUP,
    USER_NAME,
    add_resource,
    audience_scope_representation,
    create_user,
    public_client_representation,
    short_lived_tokens,
)

if TYPE_CHECKING:
    from prove import Proof

OTHER_HAL = "d1-other"
AUDIENCE_APP = "d1-app-c"
HOST_AUDIENCE = CLIENT_ID
HOST_SCOPE = "openid aud-d1-host"
SHORT_LIFESPAN_SECONDS = 15
EXPIRY_MARGIN_SECONDS = 2
AUDIENCE_SCOPES = {
    "aud-d1-host": HOST_AUDIENCE, "aud-d1-app-c": AUDIENCE_APP, "aud-account": "account",
}
EXPECTED_AUDIENCES = {
    "admin": {HOST_AUDIENCE},
    "user": {HOST_AUDIENCE},
    "outsider": {HOST_AUDIENCE},
    "audience_app": {AUDIENCE_APP},
    "audience_host_and_app": {HOST_AUDIENCE, AUDIENCE_APP},
    "audience_host_and_account": {HOST_AUDIENCE, "account"},
    "other_client": {HOST_AUDIENCE},
}
DELETE = f"/api/admin/people/{SUBJECT}"
PROBE = "/api/admin/session-probe"
PERSON_CHALLENGE_INSUFFICIENT_SCOPE = 'Bearer error="insufficient_scope"'


def header_of(token: str) -> dict[str, Any]:
    return token_part(token, 0)


def admin_token_opens_export(run: BearerRun) -> str:
    reset_host(run.host)
    answer = run.send(Call("GET", EXPORT, run.tokens["admin"]))
    assert_answer(answer, 200)
    assert answer.json() == {"caller": run.admin_id, "subject": SUBJECT}, answer.json()
    return "E answered 200 with d1-admin's Keycloak id as the caller and no challenge"


def admission_leaves_no_trace(run: BearerRun) -> str:
    held = run.state()
    assert (held["accounts"], held["sessions"], held["session_transactions"]) == (0, 0, 0), held
    return "after the admitted export: accounts 0, sessions 0, session transactions 0"


def delete_needs_no_csrf_proof(run: BearerRun) -> str:
    answer = run.send(Call("DELETE", DELETE, run.tokens["admin"], headers={
        "Origin": "https://evil.example.test", "Sec-Fetch-Site": "cross-site",
    }))
    assert_answer(answer, 200)
    assert answer.json()["caller"] == run.admin_id
    return "D with Origin evil.example.test, cross-site and no cookie: 200"


def delete_ignores_another_persons_session(run: BearerRun) -> str:
    origin = run.settings.app_origins[0]
    cookies = session_cookies(run.host_page(run.people["user"]), origin)
    run.host_page(run.people["admin"])
    before = run.state()
    answer = run.send(Call(
        "DELETE", DELETE, run.tokens["admin"], cookies
    ))
    assert_answer(answer, 200)
    assert answer.json()["caller"] == run.admin_id, "the cookie's person became the caller"
    after = run.state()
    assert (after["sessions"], after["session_transactions"]) == (
        before["sessions"], before["session_transactions"]
    ), (before, after)
    return (
        f"D with the admin token, {USER_NAME}'s session cookie: 200, caller "
        f"d1-admin; sessions {after['sessions']} and session transactions "
        f"{after['session_transactions']} as before"
    )


def cookie_only_calls(run: BearerRun) -> dict[str, Call]:
    origin = run.settings.app_origins[0]
    page = run.host_page(run.people["admin"])
    cookies = session_cookies(page, origin)
    return {
        "export": Call("GET", EXPORT, cookies=cookies),
        "delete": Call(
            "DELETE", DELETE, cookies=cookies, headers={"Origin": origin}
        ),
        "probe": Call("GET", PROBE, cookies=cookies),
    }


def a_cookie_alone_is_refused(name: str) -> Callable[[BearerRun], str]:
    def refuse(run: BearerRun) -> str:
        before = run.state()
        answer = run.send(cookie_only_calls(run)[name])
        assert_answer(answer, 401, detail="Authentication required")
        assert run.state()["session_transactions"] == before["session_transactions"]
        return (
            f"{name} with d1-admin's session cookie only: 401, challenge, "
            f"log: {run.last_gate_reason()}"
        )
    return refuse


def a_cookie_cannot_save_the_session_route(run: BearerRun) -> str:
    call = dataclasses.replace(cookie_only_calls(run)["probe"], token=run.tokens["admin"])
    answer = run.send(call)
    assert answer.status_code == 500, f"P answered {answer.status_code}"
    return (
        "P (current_user, no bearer_caller) with the admin token and a cookie: "
        "500, never 302 or 401"
    )


# --- the token scenarios ---

@dataclass(frozen=True)
class Refused:
    """A token that must be answered with ``status`` and the challenge ``error``."""

    token: str
    description: str
    status: int = 401
    error: str = "invalid_token"
    detail: str = "Invalid token"
    log_names: str | None = None


def token_is_refused(refused: Refused) -> Callable[[BearerRun], str]:
    def refuse(run: BearerRun) -> str:
        answer = run.send(Call("GET", EXPORT, run.tokens[refused.token]))
        assert_answer(answer, refused.status, refused.error, refused.detail)
        reason = run.last_gate_reason()
        assert refused.log_names is None or refused.log_names in reason, reason
        return f"{refused.description}: {refused.status} {refused.error}, log: {reason}"
    return refuse


def outsider_is_refused_and_recorded(run: BearerRun) -> str:
    answer = run.send(Call("GET", EXPORT, run.tokens["outsider"]))
    assert_answer(answer, 403, "insufficient_scope", "Admin access required")
    groups = claims_of(run.tokens["outsider"]).get("groups", "absent")
    return f"d1-outsider's token: 403 insufficient_scope; its groups claim is {groups!r}"


def disabled_person_keeps_the_token(run: BearerRun) -> str:
    run.proof.set_user_enabled(run.admin_id, False)
    try:
        person = run.proof.fresh_admin().get(f"/{REALM}/users/{run.admin_id}")
        assert person["enabled"] is False, "Keycloak did not disable d1-admin"
        answer = run.send(Call("GET", EXPORT, run.tokens["admin"]))
    finally:
        run.proof.set_user_enabled(run.admin_id, True)
    assert_answer(answer, 200)
    return "d1-admin disabled in Keycloak: the token still opens E (200) until it expires"


def sign_out_leaves_the_token(run: BearerRun) -> str:
    page = run.host_page(run.people["admin"])
    run.proof.press(page, "#logout")
    page.wait_for_url(f"{run.settings.app_origins[0]}/")
    assert run.proof.headline(page) == "Signed out", "the browser sign-out did not end the session"
    answer = run.send(Call("GET", EXPORT, run.tokens["admin"]))
    assert_answer(answer, 200)
    return "after d1-admin's browser sign-out at the host the token still opens E (200)"


def short_token_works_before_it_expires(run: BearerRun) -> str:
    person = run.people["admin"]
    with short_lived_tokens(run.proof.fresh_admin, run.client_uuids[HAL], SHORT_LIFESPAN_SECONDS):
        run.tokens["short"] = run.mint(person, HAL, HOST_SCOPE)["access_token"]
    answer = run.send(Call("GET", EXPORT, run.tokens["short"]))
    assert_answer(answer, 200)
    return f"a {SHORT_LIFESPAN_SECONDS} s token minted for d1-admin opens E before its exp (200)"


def short_token_fails_after_exp_and_leeway(run: BearerRun) -> str:
    deadline = claims_of(run.tokens["short"])["exp"] + LEEWAY_SECONDS + EXPIRY_MARGIN_SECONDS
    while time.time() < deadline:
        time.sleep(0.5)
    answer = run.send(Call("GET", EXPORT, run.tokens["short"]))
    assert_answer(answer, 401, "invalid_token", "Invalid token")
    past = LEEWAY_SECONDS + EXPIRY_MARGIN_SECONDS
    return f"{past} s past exp: 401, log: {run.last_gate_reason()}"


def flipped_signature_is_refused(run: BearerRun) -> str:
    token = run.tokens["admin"]
    position = len(token) - 10
    flipped = token[:position] + ("A" if token[position] != "A" else "B") + token[position + 1:]
    answer = run.send(Call("GET", EXPORT, flipped))
    assert_answer(answer, 401, "invalid_token", "Invalid token")
    return f"one signature character flipped: 401, log: {run.last_gate_reason()}"


def answers_are_not_stored_and_set_no_cookie(run: BearerRun) -> str:
    for answer in run.answers:
        assert answer.headers.get("cache-control") == "no-store", (
            f"{answer.request.method} {answer.request.url.path} {answer.status_code}: "
            f"cache-control {answer.headers.get('cache-control')!r}"
        )
        assert "set-cookie" not in answer.headers, "an answer set a cookie"
    return f"all {len(run.answers)} machine-route answers: Cache-Control no-store and no Set-Cookie"


def no_token_is_shown_and_refusals_are_logged(run: BearerRun) -> str:
    texts = [run.host.log_file.read_text()] + [
        f"{answer.headers}{answer.text}" for answer in run.answers
    ]
    secrets_sent = {token for token in run.sent} | {token.split(".")[2] for token in run.sent}
    for secret in secrets_sent:
        assert not any(secret in text for text in texts), "a token reached an answer or the log"
    refusals = [answer for answer in run.answers if "www-authenticate" in answer.headers]
    assert len(run.gate_lines()) == len(refusals), (len(run.gate_lines()), len(refusals))
    return (
        f"{len(run.sent)} tokens sent: none in {len(run.answers)} answers or the host log; "
        f"{len(refusals)} refusals, {len(run.gate_lines())} gate lines"
    )


# --- the person-path scenarios ---

def member_token_creates_the_account(run: BearerRun) -> str:
    reset_host(run.host)
    answer = run.send(Call("GET", ME, run.tokens["user"]))
    assert_person_answer(answer, 200)
    expected = {"id": claims_of(run.tokens["user"])["sub"], "username": USER_NAME, "role": "user"}
    assert answer.json() == expected, answer.json()
    held = run.state()
    assert (held["accounts"], held["account_events"], held["sessions"]) == (1, 1, 0), held
    assert held["session_transactions"] == 0, held
    return f"{USER_NAME}'s token on /api/me: 200; accounts 1, events 1, sessions 0"


def token_and_browser_name_the_same_person(run: BearerRun) -> str:
    origin = run.settings.app_origins[0]
    cookies = session_cookies(run.sign_in_after_reset(run.people["user"]), origin)
    browser = run.send(Call("GET", "/me", cookies=cookies))
    assert browser.status_code == 200, f"the browser's /me answered {browser.status_code}"
    token = run.send(Call("GET", ME, run.tokens["user"]))
    assert_person_answer(token, 200)
    assert token.json()["username"] == browser.json()["username"], (token.json(), browser.json())
    held = run.state()
    assert held["accounts"] == 1, held
    return f"the browser's /me and the token's /api/me name {USER_NAME}; accounts 1"


def token_post_needs_no_origin_and_no_cookie(run: BearerRun) -> str:
    answer = run.send(Call("POST", ME, run.tokens["user"]))
    assert_person_answer(answer, 200)
    return "POST /api/me with the token, no Origin and no cookie: 200"


def outsider_token_is_refused_without_an_account(run: BearerRun) -> str:
    before = run.state()["accounts"]
    answer = run.send(Call("GET", ME, run.tokens["outsider"]))
    assert_person_answer(answer, 403, PERSON_CHALLENGE_INSUFFICIENT_SCOPE, "No access")
    assert run.state()["accounts"] == before, "the outsider's token created an account"
    return f"d1-outsider's token on /api/me: 403 No access; accounts still {before}"


def other_client_token_is_refused_on_the_person_path(run: BearerRun) -> str:
    answer = run.send(Call("GET", ME, run.tokens["other_client"]))
    assert_person_answer(answer, 401, PERSON_CHALLENGE_INVALID_TOKEN, "Invalid token")
    return f"a token of d1-other on /api/me: 401 invalid_token, log: {run.last_gate_reason()}"


def sign_out_leaves_the_token_on_the_person_path(run: BearerRun) -> str:
    page = run.host_page(run.people["user"])
    run.proof.press(page, "#logout")
    page.wait_for_url(f"{run.settings.app_origins[0]}/")
    assert run.proof.headline(page) == "Signed out", "the browser sign-out did not end the session"
    answer = run.send(Call("GET", ME, run.tokens["user"]))
    assert_person_answer(answer, 200)
    return f"after {USER_NAME}'s browser sign-out the token still opens /api/me (200)"


SCENARIOS: tuple[tuple[int, Callable[[BearerRun], str]], ...] = (
    (28, admin_token_opens_export),
    (29, admission_leaves_no_trace),
    (30, delete_needs_no_csrf_proof),
    (31, delete_ignores_another_persons_session),
    (32, a_cookie_alone_is_refused("export")),
    (33, a_cookie_alone_is_refused("delete")),
    (34, a_cookie_alone_is_refused("probe")),
    (35, a_cookie_cannot_save_the_session_route),
    (36, token_is_refused(Refused("id_token", "d1-hal's ID token (typ JWT, aud d1-hal)"))),
    (38, token_is_refused(Refused("refresh_token", "d1-hal's refresh token"))),
    (39, token_is_refused(Refused("audience_app", "a token for d1-app-c only"))),
    (40, token_is_refused(Refused("audience_host_and_app", "a token for d1-host and d1-app-c"))),
    (41, token_is_refused(Refused("audience_host_and_account", "a token for d1-host and account"))),
    (42, token_is_refused(Refused(
        "other_client", "a token of d1-other (azp d1-other, aud d1-host)",
        log_names="authorized-party-mismatch",
    ))),
    (43, token_is_refused(Refused(
        "user", "a d1-user token", 403, "insufficient_scope", "Admin access required"
    ))),
    (44, outsider_is_refused_and_recorded),
    (45, disabled_person_keeps_the_token),
    (46, sign_out_leaves_the_token),
    (47, short_token_works_before_it_expires),
    (48, short_token_fails_after_exp_and_leeway),
    (49, flipped_signature_is_refused),
    (50, answers_are_not_stored_and_set_no_cookie),
    (51, no_token_is_shown_and_refusals_are_logged),
    (55, member_token_creates_the_account),
    (56, token_and_browser_name_the_same_person),
    (57, token_post_needs_no_origin_and_no_cookie),
    (58, outsider_token_is_refused_without_an_account),
    (59, other_client_token_is_refused_on_the_person_path),
    (60, sign_out_leaves_the_token_on_the_person_path),
    (61, known_agent_is_admitted_as_a_person),
    (62, stored_admin_is_admitted_with_the_person_role),
    (63, no_group_and_unknown_subject_are_refused_plainly),
    (64, the_agent_token_opens_no_other_path),
    (65, tokens_the_resource_refuses),
    (66, no_credential_and_a_cookie_get_the_challenge),
    (67, marked_route_admits_the_agent_capped),
    (68, marked_route_admin_reader_is_the_plain_403),
    (69, marked_route_refusals_beside_a_cookie),
    (70, a_bearer_on_a_marked_route_is_not_the_resource_admission),
    (71, a_marked_route_keeps_session_and_csrf_without_a_bearer),
    (72, marked_route_refuses_the_agent_beyond_its_mark),
    (73, a_group_removed_between_two_calls_is_gone),
    (74, an_admin_logout_asks_to_sign_in_again),
    (75, the_apps_own_logout_ends_the_session),
    (76, no_token_shows_in_an_answer_or_the_log),
)


# --- the phase ---

def mint_tokens(run: BearerRun) -> str:
    """One authorization request per scope variant; each person signs in at Keycloak once."""
    people = run.people
    first = run.mint(people["admin"], HAL, HOST_SCOPE)
    run.tokens |= {
        "admin": first["access_token"], "id_token": first["id_token"],
        "refresh_token": first["refresh_token"],
    }
    run.tokens["user"] = run.mint(people["user"], HAL, HOST_SCOPE)["access_token"]
    run.tokens["outsider"] = run.mint(people["outsider"], HAL, HOST_SCOPE)["access_token"]
    for name, scope in (
        ("audience_app", "openid aud-d1-app-c"),
        ("audience_host_and_app", "openid aud-d1-host aud-d1-app-c"),
        ("audience_host_and_account", "openid aud-d1-host aud-account"),
    ):
        run.tokens[name] = run.mint(people["admin"], HAL, scope)["access_token"]
    run.tokens["other_client"] = run.mint(people["admin"], OTHER_HAL, HOST_SCOPE)["access_token"]
    for name, audiences in EXPECTED_AUDIENCES.items():
        claims = claims_of(run.tokens[name])
        assert set(as_list(claims["aud"])) == audiences, f"{name} names {claims['aud']!r}"
    assert claims_of(run.tokens["id_token"])["aud"] == HAL, "the ID token's aud is not d1-hal"
    assert claims_of(run.tokens["other_client"])["azp"] == OTHER_HAL, "azp is not d1-other"
    return f"{len(run.tokens)} tokens minted for {HAL} and {OTHER_HAL} with PKCE"


def access_token_type_is_at_jwt(run: BearerRun) -> str:
    header = header_of(run.tokens["admin"])
    assert header["typ"] == "at+jwt", f"the first access token's header typ is {header['typ']!r}"
    id_token_type = header_of(run.tokens["id_token"])["typ"]
    return f"the access token's header typ is {header['typ']!r} (the ID token's: {id_token_type!r})"


def prepare_keycloak(proof: Proof, resource_url: str) -> tuple[dict[str, str], dict[str, str]]:
    """hal's clients and the audiences they may ask for; their uuids and redirect URIs."""
    admin = proof.fresh_admin()
    for name, audience in AUDIENCE_SCOPES.items():
        admin.create(f"/{REALM}/client-scopes", audience_scope_representation(name, audience))
    scopes = (*AUDIENCE_SCOPES, *add_resource(admin, resource_url, (USER_NAME, ADMIN_NAME)))
    admin.create(
        f"/{REALM}/clients", {"clientId": AUDIENCE_APP, "enabled": True, "bearerOnly": True}
    )
    redirect_uris = {
        client_id: f"http://{LOOPBACK}:{free_port()}/callback" for client_id in (HAL, OTHER_HAL)
    }
    client_uuids = {
        client_id: admin.create(
            f"/{REALM}/clients",
            public_client_representation(client_id, redirect_uri, scopes),
        )
        for client_id, redirect_uri in redirect_uris.items()
    }
    return client_uuids, redirect_uris


def drive_scenarios(run: BearerRun) -> None:
    proof = run.proof
    origin = run.settings.app_origins[0]
    if not proof.held_or_failed("CHECK bearer-tokens-minted", lambda: mint_tokens(run)):
        return
    proof.held_or_failed(
        "CHECK bearer-token-header-type", lambda: access_token_type_is_at_jwt(run)
    )
    if not proof.held_or_failed(
        "CHECK refreshed-id-token-facts",
        lambda: refreshed_id_token_facts(run, run.people["grouped"], proof),
    ):
        return
    for number, scenario in SCENARIOS:
        if scenario is known_agent_is_admitted_as_a_person and not proof.held_or_failed(
            "CHECK bearer-resource-tokens", lambda: mint_agent_tokens(run)
        ):
            return
        proof.held_or_failed(
            f"SCENARIO {number} {proof.width.label} {origin}",
            lambda scenario=scenario: scenario(run),
        )


def drive_bearer_phase(
    proof: Proof, playwright: Playwright, runtime: Path, tls: ThrowawayTls, shim_port: int,
    settings: HostSettings,
) -> None:
    """The bearer host, started and stopped here; hal's tokens come through a browser."""
    settings = dataclasses.replace(settings, bearer_authorized_parties=(HAL,))
    hostname = urllib.parse.urlsplit(settings.app_origins[0]).hostname
    assert hostname is not None
    client_uuids, redirect_uris = prepare_keycloak(
        proof, f"{settings.app_origins[0]}{RESOURCE_PATH}"
    )
    admin_id = proof.fresh_admin().get(f"/{REALM}/users?username={ADMIN_NAME}&exact=true")[0]["id"]
    people = {
        "admin": Person(ADMIN_NAME, proof.admin_password),
        "user": Person(USER_NAME, proof.user_password),
        "outsider": Person(OUTSIDER_NAME, proof.outsider_password),
        "ungrouped": Person(UNGROUPED_NAME, secrets.token_urlsafe(18)),
        "grouped": Person(GROUPED_NAME, secrets.token_urlsafe(18)),
    }
    create_user(
        proof.fresh_admin(), UNGROUPED_NAME, people["ungrouped"].password, (USER_GROUP,)
    )
    create_user(proof.fresh_admin(), GROUPED_NAME, people["grouped"].password, (USER_GROUP,))
    host = start_host(proof, runtime, settings, tls.ca_certificate)
    try:
        proof.browser = launch_pinned_chromium(
            playwright, runtime, {IDP_HOST: shim_port, hostname: host.app_port},
            tls.leaf_spki_sha256_base64,
        )
        try:
            with contextlib.ExitStack() as stack:
                drive_scenarios(BearerRun(
                    proof, host, settings, tls.ca_certificate,
                    people, client_uuids, redirect_uris,
                    stack, admin_id=admin_id,
                ))
        finally:
            proof.browser.close()
    finally:
        stop_host(host.process)
