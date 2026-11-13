"""The bearer proof's shared run: the host, the bearer client's tokens, one request to a machine
route, and the assertions on its answer."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import re
import secrets
import ssl
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from harness import Host, cookie_name_and_value, host_state, reset_host
from host_app import HostSettings
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from webauth.cookies import DEFAULT_SESSION_COOKIE_NAME

if TYPE_CHECKING:
    from prove import Proof

BEARER_CLIENT = "d1-bearer"
GATE_LINE = re.compile(r"Bearer request refused: (?P<case>[a-z-]+)(?: \((?P<reason>[^)]*)\))?")
CHALLENGE = 'Bearer realm="admin"'
SUBJECT = "person-1"
EXPORT = f"/api/admin/people/{SUBJECT}/export"
ME = "/api/me"
PERSON_CHALLENGE_INVALID_TOKEN = 'Bearer error="invalid_token"'


@dataclass(frozen=True)
class Person:
    username: str
    password: str


@dataclass(frozen=True)
class Call:
    """One request to a machine route: what the bearer client (or someone else) sends."""

    method: str
    path: str
    token: str | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class BearerRun:
    """The bearer host, the client's tokens and every answer the host gave a machine route."""

    proof: Proof
    host: Host
    settings: HostSettings
    ca_certificate: Path
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
            call.method,
            f"https://localhost:{self.host.app_port}{call.path}",
            headers=headers,
            verify=ssl.create_default_context(cafile=str(self.ca_certificate)),
        )
        self.answers.append(answer)
        return answer

    def state(self) -> dict[str, Any]:
        return host_state(self.host)

    def gate_lines(self) -> list[str]:
        lines = self.host.log_file.read_text().splitlines()
        return [line for line in lines if GATE_LINE.search(line)]

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

    def sign_in_after_reset(self, person: Person) -> Page:
        """The host reset, ``person``'s earlier browser session forgotten with it, and a fresh
        sign-in: a cached page would hold a cookie the reset ended."""
        reset_host(self.host)
        self.host_pages.pop(person.username, None)
        return self.host_page(person)

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
                f"Keycloak did not redirect to the bearer client: {page.inner_text('body')[:200]!r}"
            ) from error
        return failed.value.url

    def mint(
        self, person: Person, client_id: str, scope: str, nonce: str | None = None
    ) -> dict[str, str]:
        """The client's authorization code request with PKCE at Keycloak, and the code exchange."""
        redirect_uri = self.redirect_uris[client_id]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        state = secrets.token_urlsafe(16)
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": challenge.rstrip(b"=").decode(),
                "code_challenge_method": "S256",
                **({} if nonce is None else {"nonce": nonce}),
            }
        )
        page = self.sso_page(person)
        authorization_url = f"{self.settings.authorization_endpoint}?{query}"
        landing = self.follow_to_loopback(page, authorization_url, person, redirect_uri)
        answer = urllib.parse.parse_qs(urllib.parse.urlsplit(landing).query)
        assert answer["state"] == [state], "Keycloak answered another state"
        exchange = httpx.post(
            self.settings.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": answer["code"][0],
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            verify=ssl.create_default_context(cafile=str(self.ca_certificate)),
        )
        assert exchange.status_code == 200, f"the code exchange answered {exchange.status_code}"
        return exchange.json()


def token_part(token: str, index: int) -> dict[str, Any]:
    """The decoded JSON of one JWT segment: 0 is the header, 1 the claims."""
    segment = token.split(".")[index]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def claims_of(token: str) -> dict[str, Any]:
    return token_part(token, 1)


def as_list(claim: str | list[str]) -> list[str]:
    return [claim] if isinstance(claim, str) else claim


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


def assert_person_answer(
    answer: httpx.Response, status: int, challenge: str | None = None, detail: str | None = None
) -> None:
    assert answer.status_code == status, f"answered {answer.status_code}: {answer.text[:80]}"
    assert answer.headers.get("www-authenticate") == challenge, (
        f"challenge {answer.headers.get('www-authenticate')!r}"
    )
    if detail is not None:
        assert answer.json()["detail"] == detail, f"detail {answer.json()['detail']!r}"


def session_cookies(page: Page, origin: str) -> dict[str, str]:
    """The session cookie the browser holds for the host."""
    wanted = (DEFAULT_SESSION_COOKIE_NAME,)
    pairs = (cookie_name_and_value(cookie) for cookie in page.context.cookies([origin]))
    return {name: value for name, value in pairs if name in wanted}
