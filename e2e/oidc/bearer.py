"""Plays hal against real Keycloak: the bearer gate admits, or refuses, real access tokens.

``drive_bearer_phase`` runs after the back-channel phase of ``prove.py`` and prints
``SCENARIO <number> <width> <origin>`` for scenarios 28 to 51. hal is two public
clients (``d1-hal``, ``d1-other``) with PKCE, ``at+jwt`` access tokens and the optional
audience scopes; ``d1-app-c`` is a client that exists only to be an audience. hal gets its
codes from a browser signed in at Keycloak (the redirect to the loopback port nobody
listens on fails, and Playwright's failed request names the code), posts the code exchange
itself, and sends the access token as the ``Authorization`` header to the bearer host:
``build_app`` with ``bearer_authorized_parties``, whose routes under ``/api/admin/`` are E
(export), D (delete) and P (session probe). ``CHECK bearer-token-header-type`` records the
header ``typ`` of the first minted token. Each scenario's id is the matrix id of the item.

- 28 (E01) an admin token opens E after ``/reset``.
- 29 (E02) E01 created no account, no session and no session transaction.
- 30 (E03) D with the admin token, no CSRF header and a cross-site origin, no cookie.
- 31 (E04) D with the admin token, another person's session cookie and a wrong CSRF token.
- 32 to 34 (E05 to E07) a session cookie alone opens no machine route.
- 35 (E08) the admin token and a cookie on P: a host mistake, answered 500.
- 36 to 38 (E09 to E11) an ID token, the ID token hint cookie and a refresh token.
- 39 to 41 (E12 to E14) audiences: the foreign one, two of them, ``account``.
- 42 (E15) a token of ``d1-other``.
- 43, 44 (E16, E17) a member without the admin group, and a person in no group.
- 45 (E18) a disabled person's token. 46 (E19) the token after a browser sign-out.
- 47, 48 (E20, E21) a 15 s token before ``exp`` and after ``exp`` plus leeway.
- 49 (E22) a flipped signature character.
- 50 (E23) every machine-route answer is ``no-store`` and sets no cookie.
- 51 (E24) no token sent appears in an answer or the host log; each refusal has a line.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import json
import re
import secrets
import ssl
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from certificates import ThrowawayTls
from harness import (
    Host,
    cookie_name_and_value,
    free_port,
    host_state,
    launch_pinned_chromium,
    reset_host,
    start_host,
    stop_host,
)
from host_app import LEEWAY_SECONDS, LOGOUT_PATH, LOOPBACK, HostSettings
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, Playwright
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from realm import (
    ADMIN_NAME,
    IDP_HOST,
    OUTSIDER_NAME,
    REALM,
    USER_NAME,
    audience_scope_representation,
    public_client_representation,
    short_lived_tokens,
)

from webauth.cookies import DEFAULT_CSRF_COOKIE_NAME, DEFAULT_SESSION_COOKIE_NAME

if TYPE_CHECKING:
    from prove import Proof

HAL = "d1-hal"
OTHER_HAL = "d1-other"
AUDIENCE_APP = "d1-app-c"
HOST_AUDIENCE = "d1-host"
HOST_SCOPE = "openid aud-d1-host"
SHORT_LIFESPAN_SECONDS = 15
EXPIRY_MARGIN_SECONDS = 2
CSRF_HEADER = "x-csrf-token"
GATE_LINE = re.compile(r"Bearer request refused: (?P<case>[a-z-]+)(?: \((?P<reason>[^)]*)\))?")
CHALLENGE = 'Bearer realm="admin"'
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
SUBJECT = "person-1"
EXPORT = f"/api/admin/people/{SUBJECT}/export"
DELETE = f"/api/admin/people/{SUBJECT}"
PROBE = "/api/admin/session-probe"


@dataclass(frozen=True)
class Person:
    username: str
    password: str


@dataclass(frozen=True)
class Call:
    """One request to a machine route: what hal (or someone else) sends."""

    method: str
    path: str
    token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class BearerRun:
    """The bearer host, hal's tokens and every answer the host gave a machine route."""

    proof: Proof
    host: Host
    settings: HostSettings
    ca_certificate: Path
    log_file: Path
    people: dict[str, Person]
    client_uuids: dict[str, str]
    redirect_uris: dict[str, str]
    stack: contextlib.ExitStack
    sso_pages: dict[str, Page] = field(default_factory=dict)
    host_pages: dict[str, Page] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict, repr=False)
    answers: list[httpx.Response] = field(default_factory=list)
    sent: list[str] = field(default_factory=list, repr=False)
    admin_id: str = ""

    # --- the host ---

    def send(self, call: Call) -> httpx.Response:
        headers = {"Host": urllib.parse.urlsplit(self.settings.app_origins[0]).netloc}
        headers |= call.headers
        if call.token is not None:
            headers["Authorization"] = f"Bearer {call.token}"
            self.sent.append(call.token)
        if call.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in call.cookies.items())
        answer = httpx.request(
            call.method, f"https://localhost:{self.host.app_port}{call.path}", headers=headers,
            verify=ssl.create_default_context(cafile=str(self.ca_certificate)),
        )
        self.answers.append(answer)
        return answer

    def state(self) -> dict[str, Any]:
        return host_state(self.host)

    def gate_lines(self) -> list[str]:
        return [line for line in self.log_file.read_text().splitlines() if GATE_LINE.search(line)]

    def last_gate_reason(self) -> str:
        match = GATE_LINE.search(self.gate_lines()[-1])
        assert match is not None
        return f"{match['case']} ({match['reason']})" if match["reason"] else match["case"]

    # --- Keycloak and the browser ---

    def sso_page(self, person: Person) -> Page:
        if person.username not in self.sso_pages:
            self.sso_pages[person.username] = self.stack.enter_context(self.proof.browsing())
        return self.sso_pages[person.username]

    def host_page(self, person: Person) -> Page:
        """A browser signed in at the bearer host as ``person``, left open."""
        if person.username not in self.host_pages:
            page = self.stack.enter_context(self.proof.browsing())
            self.proof.sign_in(
                page, None, self.settings.app_origins[0], person.username, person.password
            )
            self.host_pages[person.username] = page
        return self.host_pages[person.username]

    def follow_to_loopback(self, page: Page, url: str, person: Person, redirect_uri: str) -> str:
        """The redirect URI Keycloak sends the browser to: Chromium cannot connect to the port
        nobody listens on, and the failed request names the URL (a route does not see redirects)."""
        try:
            with page.expect_event(
                "requestfailed", lambda request: request.url.startswith(redirect_uri)
            ) as failed:
                with contextlib.suppress(PlaywrightError):
                    page.goto(url)
                if page.locator("#username").count():
                    self.proof.fill_keycloak_form(page, None, person.password, person.username)
        except PlaywrightTimeoutError as error:
            raise AssertionError(
                f"Keycloak did not redirect to hal: {page.inner_text('body')[:200]!r}"
            ) from error
        return failed.value.url

    def mint(self, person: Person, client_id: str, scope: str) -> dict[str, str]:
        """hal's authorization code request with PKCE at Keycloak, and the code exchange."""
        redirect_uri = self.redirect_uris[client_id]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(16)
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
            "scope": scope, "state": state, "code_challenge": challenge.rstrip(b"=").decode(),
            "code_challenge_method": "S256",
        })
        page = self.sso_page(person)
        authorization_url = f"{self.settings.authorization_endpoint}?{query}"
        landing = self.follow_to_loopback(page, authorization_url, person, redirect_uri)
        answer = urllib.parse.parse_qs(urllib.parse.urlsplit(landing).query)
        assert answer["state"] == [state], "Keycloak answered another state"
        exchange = httpx.post(
            self.settings.token_endpoint,
            data={
                "grant_type": "authorization_code", "code": answer["code"][0],
                "redirect_uri": redirect_uri, "client_id": client_id, "code_verifier": verifier,
            },
            verify=ssl.create_default_context(cafile=str(self.ca_certificate)),
        )
        assert exchange.status_code == 200, f"the code exchange answered {exchange.status_code}"
        return exchange.json()


def claims_of(token: str) -> dict[str, Any]:
    segment = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def as_list(claim: str | list[str]) -> list[str]:
    return [claim] if isinstance(claim, str) else claim


def header_of(token: str) -> dict[str, Any]:
    segment = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def assert_answer(
    answer: httpx.Response, status: int, error: str | None = None, detail: str | None = None
) -> None:
    assert answer.status_code == status, f"answered {answer.status_code}: {answer.text[:80]}"
    wanted = None
    if status != 200:
        wanted = CHALLENGE if error is None else f'{CHALLENGE}, error="{error}"'
    assert answer.headers.get("www-authenticate") == wanted, (
        f"challenge {answer.headers.get('www-authenticate')!r}"
    )
    if detail is not None:
        assert answer.json()["detail"] == detail, f"detail {answer.json()['detail']!r}"


def session_cookies(page: Page, origin: str) -> dict[str, str]:
    """The session and CSRF cookies the browser holds for the host."""
    wanted = (DEFAULT_SESSION_COOKIE_NAME, DEFAULT_CSRF_COOKIE_NAME)
    pairs = (cookie_name_and_value(cookie) for cookie in page.context.cookies([origin]))
    return {name: value for name, value in pairs if name in wanted}


def hint_cookie_value(page: Page, origin: str) -> str:
    """The ID token the host keeps for the logout, the only cookie scoped to the logout path."""
    (hint,) = (
        cookie for cookie in page.context.cookies([f"{origin}{LOGOUT_PATH}"])
        if cookie.get("path") == LOGOUT_PATH
    )
    return cookie_name_and_value(hint)[1]


# --- the admitted and the cookie-only scenarios ---

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
    return "D with no CSRF header, Origin evil.example.test, cross-site and no cookie: 200"


def delete_ignores_another_persons_session(run: BearerRun) -> str:
    origin = run.settings.app_origins[0]
    cookies = session_cookies(run.host_page(run.people["user"]), origin)
    run.host_page(run.people["admin"])
    before = run.state()
    answer = run.send(Call(
        "DELETE", DELETE, run.tokens["admin"], cookies, {CSRF_HEADER: "wrong"}
    ))
    assert_answer(answer, 200)
    assert answer.json()["caller"] == run.admin_id, "the cookie's person became the caller"
    after = run.state()
    assert (after["sessions"], after["session_transactions"]) == (
        before["sessions"], before["session_transactions"]
    ), (before, after)
    return (
        f"D with the admin token, {USER_NAME}'s session cookie and a wrong CSRF token: 200, caller "
        f"d1-admin; sessions {after['sessions']} and session transactions "
        f"{after['session_transactions']} as before"
    )


def cookie_only_calls(run: BearerRun) -> dict[str, Call]:
    origin = run.settings.app_origins[0]
    page = run.host_page(run.people["admin"])
    cookies = session_cookies(page, origin)
    csrf = cookies[DEFAULT_CSRF_COOKIE_NAME]
    return {
        "export": Call("GET", EXPORT, cookies=cookies),
        "delete": Call(
            "DELETE", DELETE, cookies=cookies, headers={CSRF_HEADER: csrf, "Origin": origin}
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


def hint_cookie_is_no_access_token(run: BearerRun) -> str:
    origin = run.settings.app_origins[0]
    hint = hint_cookie_value(run.host_page(run.people["admin"]), origin)
    assert claims_of(hint)["aud"] == HOST_AUDIENCE, "the hint is not an ID token for the host"
    answer = run.send(Call("GET", EXPORT, hint))
    assert_answer(answer, 401, "invalid_token", "Invalid token")
    return (
        f"the ID token hint cookie of d1-admin's host login (aud d1-host): 401, "
        f"log: {run.last_gate_reason()}"
    )


def outsider_is_refused_and_recorded(run: BearerRun) -> str:
    answer = run.send(Call("GET", EXPORT, run.tokens["outsider"]))
    assert_answer(answer, 403, "insufficient_scope", "Admin access required")
    groups = claims_of(run.tokens["outsider"]).get("groups", "absent")
    return f"d1-outsider's token: 403 insufficient_scope; its groups claim is {groups!r}"


def disabled_person_keeps_the_token(run: BearerRun) -> str:
    run.proof.set_user_enabled(run.admin_id, False)
    try:
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
    texts = [run.log_file.read_text()] + [
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
    (37, hint_cookie_is_no_access_token),
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
    assert claims_of(run.tokens["other_client"])["azp"] == OTHER_HAL, "azp is not d1-other"
    return f"{len(run.tokens)} tokens minted for {HAL} and {OTHER_HAL} with PKCE"


def access_token_type_is_at_jwt(run: BearerRun) -> str:
    header = header_of(run.tokens["admin"])
    assert header["typ"] == "at+jwt", f"the first access token's header typ is {header['typ']!r}"
    id_token_type = header_of(run.tokens["id_token"])["typ"]
    return f"the access token's header typ is {header['typ']!r} (the ID token's: {id_token_type!r})"


def prepare_keycloak(proof: Proof) -> tuple[dict[str, str], dict[str, str]]:
    """hal's clients and the audiences they may ask for; their uuids and redirect URIs."""
    admin = proof.fresh_admin()
    for name, audience in AUDIENCE_SCOPES.items():
        admin.create(f"/{REALM}/client-scopes", audience_scope_representation(name, audience))
    admin.create(
        f"/{REALM}/clients", {"clientId": AUDIENCE_APP, "enabled": True, "bearerOnly": True}
    )
    redirect_uris = {
        client_id: f"http://{LOOPBACK}:{free_port()}/callback" for client_id in (HAL, OTHER_HAL)
    }
    client_uuids = {
        client_id: admin.create(
            f"/{REALM}/clients",
            public_client_representation(client_id, redirect_uri, tuple(AUDIENCE_SCOPES)),
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
    for number, scenario in SCENARIOS:
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
    client_uuids, redirect_uris = prepare_keycloak(proof)
    admin_id = proof.fresh_admin().get(f"/{REALM}/users?username={ADMIN_NAME}&exact=true")[0]["id"]
    people = {
        "admin": Person(ADMIN_NAME, proof.admin_password),
        "user": Person(USER_NAME, proof.user_password),
        "outsider": Person(OUTSIDER_NAME, proof.outsider_password),
    }
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
                    runtime / f"host-{settings.port}.log", people, client_uuids, redirect_uris,
                    stack, admin_id=admin_id,
                ))
        finally:
            proof.browser.close()
    finally:
        stop_host(host.process)
