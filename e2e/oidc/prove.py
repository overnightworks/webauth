"""Proves login and logout of a webauth host in a real browser against a real Keycloak.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --extra dev --group e2e python e2e/oidc/prove.py --edge PATH --scratch EMPTY_DIR

Read ``README.md`` beside this file first. Nothing of the OIDC path is faked:
the browser fills Keycloak's own form, the host's library talks to the real
token and key-set endpoints, and the only seams are the connection routing and
the one throwaway certificate key the browser is told to accept."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import signal
import ssl
import sys
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from evidence import (
    NetworkLog,
    SecretRegistry,
    cookie_names,
    recorded_cookie_name,
    without_query_values,
)
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    RunRecord,
    drive_browser_off_the_main_thread,
    free_port,
    keep_clean_evidence,
    leftovers,
    runtime_directory,
    start_host,
    stop_host,
    stop_on_first_signal,
)
from host_app import HostSettings
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright
from shim import LOOPBACK, TlsShim
from stack import Admin, HeldStack, require_pinned_clean_edge

from webauth.cookies import (
    DEFAULT_COOKIE_SAMESITE,
    DEFAULT_SESSION_COOKIE_NAME,
    CookieSameSite,
    is_pending_login_cookie_name,
    verify_pending_login,
)

IDP_HOST = "auth.hallucinai.de"
APP_HOST = "demo.hallucinai.de"
SECOND_APP_HOST = "demo.example.test"
UNTRUSTED_HOST = "untrusted.hallucinai.de"
REALM = "hallucinai"
EDGE_CONTAINER_FILTER = "edge-kc-probe"
ISSUER = f"https://{IDP_HOST}/realms/{REALM}"
OIDC_PATH = f"{ISSUER}/protocol/openid-connect"
APP_ORIGIN = f"https://{APP_HOST}"
CALLBACK_PATH = "/auth/callback"
SECOND_APP_ORIGIN = f"https://{SECOND_APP_HOST}"
CLIENT_ID = "d1-host"
USER_NAME = "d1-user"
USER_GROUP = "/apps/songmaker"
DISABLED_USER_NAME = "d1-disabled"
KEYCLOAK_DISABLED_MESSAGE = "Account is disabled"
SAMESITE_VALUES: tuple[CookieSameSite, ...] = ("strict", "lax")
PAGE_TIMEOUT_MILLISECONDS = 30_000
URL_PARAMETERS_THAT_ARE_CREDENTIALS = ("code", "session_state", "state")


@dataclass(frozen=True)
class Width:
    """A browser window the scenarios run at; the phone is touch with mobile emulation."""

    pixels_wide: int
    pixels_high: int
    touch: bool

    @property
    def label(self) -> str:
        return f"{self.pixels_wide}x{self.pixels_high}"

    @property
    def context_options(self) -> dict[str, Any]:
        return {
            "viewport": {"width": self.pixels_wide, "height": self.pixels_high},
            "is_mobile": self.touch,
            "has_touch": self.touch,
        }


PHONE = Width(390, 844, touch=True)
DESKTOP = Width(1280, 800, touch=False)
WIDTHS = (PHONE, DESKTOP)


class Finding(Exception):
    """A measurement that came out unfavourably: reported as found, not as a failed run."""


@dataclass
class Proof(RunRecord):
    """One run: what it created, what it saw, and what it concluded."""

    browser: Browser | None = None
    app_port: int = 0
    observe_port: int = 0
    ca_certificate: Path | None = None
    session_secret: str = ""
    user_password: str = ""
    disabled_user_password: str = ""
    disabled_user_id: str = ""
    client_secret: str = ""
    stack: HeldStack | None = None
    width: Width = DESKTOP
    browser_tmp: Path | None = None

    def held_or_failed(self, label: str, check: Callable[[], str]) -> bool:
        if self.stop_requested.is_set():
            return False
        try:
            observed = check()
        except Finding as finding:
            self.record(f"{label} FAILED-as-found: {finding}")
            return False
        except Exception as error:
            if self.stop_requested.is_set():
                self.record(f"{label} interrupted")
                return False
            failure = without_query_values(f"{type(error).__name__}: {error}")
            self.failures += 1
            self.record(f"{label} FAILED: {failure}")
            return False
        self.record(f"{label} held: {observed}")
        return True

    @contextlib.contextmanager
    def browsing(self, width: Width = DESKTOP) -> Iterator[Page]:
        assert self.browser is not None
        self.width = width
        context = self.browser.new_context(**width.context_options)
        context.set_default_timeout(PAGE_TIMEOUT_MILLISECONDS)
        context.on("request", self._remember_url_credentials)
        context.on("request", self.log.watch)
        page = context.new_page()
        try:
            yield page
        finally:
            with contextlib.ExitStack() as cleanup:
                cleanup.callback(context.close)
                cleanup.callback(self.log.collect)
                cleanup.callback(self.capture_cookies, context)

    def _remember_url_credentials(self, request: Any) -> None:
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query)
        for name in URL_PARAMETERS_THAT_ARE_CREDENTIALS:
            for value in query.get(name, []):
                self.registry.add(f"url parameter {name}", value)

    def capture_cookies(self, context: BrowserContext) -> None:
        for cookie in context.cookies():
            self.registry.add(f"cookie {recorded_cookie_name(cookie['name'])}", cookie["value"])
            if is_pending_login_cookie_name(cookie["name"], secure=True):
                self._register_pending_login(cookie["value"])

    def _register_pending_login(self, cookie_value: str) -> None:
        pending = verify_pending_login(cookie_value, self.session_secret.encode())
        if pending is None:
            raise AssertionError("a pending-login cookie did not verify; secrets unregistered")
        self.registry.add("pending login state", pending.state)
        self.registry.add("pending login nonce", pending.nonce)
        self.registry.add("pending login code_verifier", pending.code_verifier)

    def shot(self, page: Page, scenario: str | None, moment: str) -> None:
        if scenario is None:
            return
        page.screenshot(path=self.evidence_dir / f"{scenario}-{moment}.png")

    def host_state(self) -> dict[str, Any]:
        return httpx.get(f"http://{LOOPBACK}:{self.observe_port}/state").json()

    def reset_host(self) -> None:
        self._tell_host("reset")

    def deactivate_host_accounts(self) -> None:
        self._tell_host("deactivate")

    def _tell_host(self, order: str) -> None:
        httpx.post(f"http://{LOOPBACK}:{self.observe_port}/{order}").raise_for_status()

    def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        assert self.stack is not None
        admin = self.stack.admin()
        self.registry.add("admin token", admin.token)
        admin.put(f"/{REALM}/users/{user_id}", {"enabled": enabled})

    def press(self, page: Page, selector: str) -> None:
        if self.width.touch:
            page.tap(selector)
        else:
            page.click(selector)

    def assert_fits(self, page: Page, *selectors: str) -> None:
        """Every element lies inside the window's width and the page does not scroll sideways."""
        for selector in selectors:
            box = page.locator(selector).bounding_box()
            assert box is not None, f"{selector} has no box"
            assert 0 <= box["x"] and box["x"] + box["width"] <= self.width.pixels_wide, (
                f"{selector} leaves the {self.width.label} window: {box}"
            )
        scroll_width = page.evaluate("document.documentElement.scrollWidth")
        assert scroll_width <= self.width.pixels_wide, f"the page scrolls sideways: {scroll_width}"

    def start_sign_in(self, page: Page, scenario: str | None, origin: str = APP_ORIGIN) -> None:
        page.goto(f"{origin}/")
        self.shot(page, scenario, "start")
        self.press(page, "#sign-in")
        page.wait_for_selector("#username")
        self.capture_cookies(page.context)

    def fill_keycloak_form(
        self, page: Page, scenario: str | None, password: str, username: str = USER_NAME
    ) -> None:
        page.fill("#username", username)
        page.fill("#password", password)
        self.shot(page, scenario, "idp-form")
        self.press(page, "#kc-login")

    def sign_in(
        self, page: Page, scenario: str | None, origin: str = APP_ORIGIN, username: str = USER_NAME,
        password: str | None = None,
    ) -> None:
        self.start_sign_in(page, scenario, origin)
        self.fill_keycloak_form(
            page, scenario, self.user_password if password is None else password, username
        )
        page.wait_for_url(re.compile(f"^{re.escape(origin)}/"))

    def status_of(self, page: Page, path: str) -> int:
        return page.evaluate("path => fetch(path).then((answer) => answer.status)", path)

    def headline(self, page: Page) -> str:
        return page.inner_text("h1")


def issuer_document_is_canonical(proof: Proof) -> str:
    with proof.browsing() as page:
        page.goto(f"{ISSUER}/.well-known/openid-configuration")
        issuer = json.loads(page.inner_text("body"))["issuer"]
        assert page.url == f"{ISSUER}/.well-known/openid-configuration", "the URL moved"
        assert issuer == ISSUER, "the document names another issuer"
    return f"{ISSUER} answered under its canonical URL and names itself as the issuer"


def untrusted_certificate_is_refused(proof: Proof) -> str:
    with proof.browsing() as page:
        try:
            page.goto(f"https://{UNTRUSTED_HOST}/")
        except Exception as error:
            reason = re.search(r"net::ERR_\w+", str(error))
            assert reason and "CERT" in reason.group(), f"refused for another reason: {error}"
            return f"a throwaway key signed by a CA nobody trusts is refused: {reason.group()}"
    raise AssertionError("the browser accepted a certificate it was not told to trust")


def login(proof: Proof, width: Width) -> str:
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, f"1-{width.label}")
        page.goto(f"{APP_ORIGIN}/")
        headline = proof.headline(page)
        assert headline == f"Signed in as {USER_NAME}", f"the page says {headline!r}"
        me_status = proof.status_of(page, "/me")
        assert me_status == 200, f"/me answered {me_status}"
        proof.shot(page, f"1-{width.label}", "result")
    held = proof.host_state()
    assert held["accounts"] == 1 and held["sessions"] == 1, f"the host holds {held}"
    signed_in = (
        f"{USER_NAME} signed in at Keycloak's form; '/' says 'Signed in as {USER_NAME}' "
        "and GET /me answered 200"
    )
    return f"{signed_in}; {a_wrong_password_stays_at_keycloak(proof, width)}"


def a_wrong_password_stays_at_keycloak(proof: Proof, width: Width) -> str:
    scenario = f"1b-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        wrong_password = secrets.token_urlsafe(12)
        proof.registry.add("wrong password", wrong_password)
        proof.start_sign_in(page, scenario)
        proof.fill_keycloak_form(page, scenario, wrong_password)
        page.get_by_text("Invalid username or password").wait_for()
        assert urllib.parse.urlsplit(page.url).hostname == IDP_HOST, "left Keycloak's form"
        proof.shot(page, scenario, "refused-result")
    held = proof.host_state()
    assert (held["callbacks_received"], held["accounts"], held["sessions"]) == (0, 0, 0), held
    return "a wrong password stays on Keycloak's form: callbacks 0, accounts 0, sessions 0"


def disabled_user_is_refused(proof: Proof, width: Width) -> str:
    scenario = f"4-{width.label}"
    proof.reset_host()
    proof.set_user_enabled(proof.disabled_user_id, False)
    with proof.browsing(width) as page:
        proof.start_sign_in(page, scenario)
        proof.fill_keycloak_form(
            page, scenario, proof.disabled_user_password, DISABLED_USER_NAME
        )
        page.get_by_text(KEYCLOAK_DISABLED_MESSAGE).wait_for()
        assert urllib.parse.urlsplit(page.url).hostname == IDP_HOST, "left Keycloak's form"
        proof.assert_fits(
            page, "#username", "#password", "#kc-login", f"text={KEYCLOAK_DISABLED_MESSAGE}"
        )
        proof.shot(page, scenario, "refused-result")
    held = proof.host_state()
    assert held["callbacks_received"] == 0 and held["sessions"] == 0, f"the host holds {held}"
    proof.set_user_enabled(proof.disabled_user_id, True)
    with proof.browsing(width) as page:
        proof.sign_in(
            page, f"{scenario}-enabled", username=DISABLED_USER_NAME,
            password=proof.disabled_user_password,
        )
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {DISABLED_USER_NAME}", (
            f"the page says {proof.headline(page)!r}"
        )
        proof.shot(page, f"{scenario}-enabled", "result")
    proof.deactivate_host_accounts()
    sessions_before = proof.host_state()["sessions"]
    with proof.browsing(width) as page:
        proof.sign_in(
            page, f"{scenario}-deactivated", username=DISABLED_USER_NAME,
            password=proof.disabled_user_password,
        )
        assert proof.headline(page) == "Sign-in refused", f"the page says {proof.headline(page)!r}"
        proof.shot(page, f"{scenario}-deactivated", "result")
        carried = {c["name"] for c in page.context.cookies(APP_ORIGIN)}
        assert DEFAULT_SESSION_COOKIE_NAME not in carried, "a session cookie was issued"
    held = proof.host_state()
    assert held["last_refusal"] == "account-deactivated", f"the host refused {held}"
    assert held["sessions"] == sessions_before, f"the host holds {held}"
    return (
        f"Keycloak answered {KEYCLOAK_DISABLED_MESSAGE!r} and no callback reached the app "
        f"(callbacks 0, sessions 0); the same credentials signed in once the user was enabled; "
        f"a host account with is_active false reached the callback and was refused with "
        f"'account-deactivated', no session"
    )


def pages_fit_the_window(proof: Proof, width: Width) -> str:
    scenario = f"6-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        page.goto(f"{APP_ORIGIN}/")
        proof.assert_fits(page, "#sign-in")
        proof.start_sign_in(page, scenario)
        proof.assert_fits(page, "#username", "#password", "#kc-login")
        proof.fill_keycloak_form(page, scenario, proof.user_password)
        page.wait_for_url(f"{APP_ORIGIN}/")
        page.goto(f"{APP_ORIGIN}/")
        proof.assert_fits(page, "h1", "#logout")
        proof.shot(page, scenario, "result")
    return (
        f"at {width.label} the app's start page, Keycloak's username and password fields and "
        f"sign-in button, and the app's signed-in page lie inside the window, "
        f"without sideways scroll"
    )


def session_cookie_after_redirect(
    proof: Proof, origin: str, cookie_samesite: CookieSameSite
) -> str:
    proof.reset_host()
    scenario = f"5-{urllib.parse.urlsplit(origin).hostname}-{cookie_samesite}"
    with proof.browsing() as page:
        requests: list[Any] = []
        page.context.on("request", lambda request: requests.append(request))
        proof.sign_in(page, scenario=None, origin=origin)
        page.wait_for_url(f"{origin}/")
        callback = next(r for r in requests if r.url.startswith(f"{origin}{CALLBACK_PATH}"))
        landing = next(r for r in requests if r.redirected_from is callback)
        assert any(
            is_pending_login_cookie_name(name, secure=True)
            for name in cookie_names(callback.headers_array())
        ), "the callback carried no pending-login cookie; request cookies are not measured"
        names = [recorded_cookie_name(name) for name in cookie_names(landing.headers_array())]
        site = next(
            (h["value"] for h in landing.headers_array() if h["name"].lower() == "sec-fetch-site"),
            "(none)",
        )
        headline = proof.headline(page)
        proof.shot(page, scenario, "first-page")
    observed = f"first page showed {headline!r}; cookie names sent {names}; Sec-Fetch-Site {site}"
    if headline != f"Signed in as {USER_NAME}":
        raise Finding(observed)
    return observed


def logout(proof: Proof) -> str:
    proof.reset_host()
    with proof.browsing() as page:
        proof.sign_in(page, "2")
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}"
        cookies = [c for c in page.context.cookies(APP_ORIGIN)]
        held_names = {c["name"] for c in cookies}
        session = next(c for c in cookies if c["name"] == DEFAULT_SESSION_COOKIE_NAME)
        proof.registry.add("session cookie", session["value"])
        page.click("#logout")
        page.get_by_role("heading", name="Signed out").wait_for()
        page.reload()
        assert proof.headline(page) == "Signed out", "a reload of '/' did not show Sign in"
        proof.shot(page, "2", "result")
        left = held_names & {c["name"] for c in page.context.cookies(APP_ORIGIN)}
        assert not left, f"cookies survived: {sorted(left)}"
        me_status = proof.status_of(page, "/me")
        assert me_status == 401, f"/me answered {me_status}"
        back_shows = back_button_shows(proof, page)
        replay = replayed_session_status(proof, session)
        assert replay == 401, f"the old session cookie was answered {replay}"
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        silent = second_sign_in(proof, page)
    return (
        f"after the button the cookies are gone, a reload shows Sign in and /me answers 401; "
        f"the back button shows {back_shows!r} but the old session cookie replayed over HTTPS "
        f"to /me is refused ({replay}); a second Sign in {silent} (Keycloak's SSO session "
        f"is not ended by this logout)"
    )


def back_button_shows(proof: Proof, page: Page) -> str:
    page.go_back()
    page_text = page.inner_text("h1") if page.query_selector("h1") else "no page"
    return f"{page_text} (the host's last sign-in refusal: {proof.host_state()['last_refusal']})"


def replayed_session_status(proof: Proof, session: dict[str, Any]) -> int:
    assert proof.ca_certificate is not None
    return httpx.get(
        f"https://localhost:{proof.app_port}/me",
        headers={"Cookie": f"{session['name']}={session['value']}"},
        verify=ssl.create_default_context(cafile=str(proof.ca_certificate)),
    ).status_code


def second_sign_in(proof: Proof, page: Page) -> str:
    page.goto(f"{APP_ORIGIN}/")
    page.click("#sign-in")
    keycloak_form = page.locator("#username")
    signed_in = page.get_by_role("heading", name=f"Signed in as {USER_NAME}")
    keycloak_form.or_(signed_in).wait_for()
    proof.shot(page, "2", "second-sign-in")
    if keycloak_form.is_visible():
        return "shows Keycloak's form again"
    held = proof.host_state()
    assert held["sessions"] == 1, f"the host holds {held}"
    return (
        f"signs in again without a form, through the live SSO session "
        f"(host sessions: {held['sessions']})"
    )


def create_user(admin: Admin, username: str, password: str) -> str:
    user_id = admin.create(f"/{REALM}/users", {
        "username": username,
        "enabled": True,
        "email": f"{username}@d1.invalid",
        "emailVerified": True,
        "firstName": "D1",
        "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    group = admin.get(f"/{REALM}/group-by-path{USER_GROUP}")
    admin.put(f"/{REALM}/users/{user_id}/groups/{group['id']}")
    return user_id


def prepare_keycloak(admin: Admin, proof: Proof, client_secret: str) -> None:
    admin.create(f"/{REALM}/clients", {
        "clientId": CLIENT_ID,
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "redirectUris": [
            f"{APP_ORIGIN}{CALLBACK_PATH}", f"{SECOND_APP_ORIGIN}{CALLBACK_PATH}",
        ],
        "defaultClientScopes": ["basic", "profile", "groups"],
    })
    create_user(admin, USER_NAME, proof.user_password)
    proof.disabled_user_id = create_user(admin, DISABLED_USER_NAME, proof.disabled_user_password)


def register_stack_secrets(stack: HeldStack, admin: Admin, registry: SecretRegistry) -> None:
    for path in stack.secrets_dir.rglob("*"):
        if path.is_file():
            for line in path.read_text().splitlines():
                registry.add(f"stack secret {path.name}", line.strip())
                registry.add(f"stack secret {path.name}", line.partition("=")[2].strip())
    registry.add("admin token", admin.token)


def host_settings(
    proof: Proof, tls: ThrowawayTls, shim_port: int, cookie_samesite: CookieSameSite
) -> HostSettings:
    return HostSettings(
        app_origins=(APP_ORIGIN, SECOND_APP_ORIGIN),
        port=free_port(),
        observe_port=free_port(),
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=ISSUER,
        authorization_endpoint=f"{OIDC_PATH}/auth",
        token_endpoint=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/token",
        jwks_url=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/certs",
        client_id=CLIENT_ID,
        client_secret=proof.client_secret,
        session_secret=proof.session_secret,
        cookie_samesite=cookie_samesite,
    )


def run_proof(proof: Proof, edge: Path, runtime: Path) -> None:
    proof.browser_tmp = runtime / "tmp"
    proof.browser_tmp.mkdir()
    proof.session_secret = secrets.token_urlsafe(48)
    proof.user_password = secrets.token_urlsafe(18)
    proof.client_secret = secrets.token_urlsafe(24)
    proof.disabled_user_password = secrets.token_urlsafe(18)
    for label, value in (
        ("session secret", proof.session_secret), ("user password", proof.user_password),
        ("disabled user password", proof.disabled_user_password),
        ("client secret", proof.client_secret),
    ):
        proof.registry.add(label, value)
    tls = issue_throwaway_tls(runtime, "good", [IDP_HOST, APP_HOST, SECOND_APP_HOST, "localhost"])
    untrusted = issue_throwaway_tls(runtime, "untrusted", [UNTRUSTED_HOST])
    with HeldStack(edge, runtime / "stack") as stack:
        proof.stack = stack
        admin = stack.admin()
        register_stack_secrets(stack, admin, proof.registry)
        prepare_keycloak(admin, proof, proof.client_secret)
        edge_port = urllib.parse.urlsplit(stack.edge_url).port
        assert edge_port is not None
        with TlsShim(tls, edge_port, IDP_HOST) as shim, \
                TlsShim(untrusted, edge_port, IDP_HOST) as untrusted_shim:
            hosts: list[Host] = []
            proof.ca_certificate = tls.ca_certificate
            try:
                for cookie_samesite in SAMESITE_VALUES:
                    settings = host_settings(proof, tls, shim.port, cookie_samesite)
                    hosts.append(start_host(proof, runtime, settings, tls.ca_certificate))
                drive_browser_off_the_main_thread(
                    proof,
                    lambda: drive_browser(proof, tls, shim.port, untrusted_shim.port, hosts),
                )
            finally:
                proof.winding_down = True
                for host in hosts:
                    stop_host(host.process)
    print("\n".join(line for line in stack.output if line.startswith("teardown")), flush=True)


def drive_browser(
    proof: Proof, tls: ThrowawayTls, shim_port: int, untrusted_port: int, hosts: list[Host]
) -> None:
    assert proof.browser_tmp is not None
    os.environ["TMPDIR"] = str(proof.browser_tmp)
    with sync_playwright() as playwright:
        for host in hosts:
            proof.app_port, proof.observe_port = host.app_port, host.observe_port
            rules = ", ".join((
                f"MAP {IDP_HOST} {LOOPBACK}:{shim_port}",
                f"MAP {APP_HOST} {LOOPBACK}:{host.app_port}",
                f"MAP {SECOND_APP_HOST} {LOOPBACK}:{host.app_port}",
                f"MAP {UNTRUSTED_HOST} {LOOPBACK}:{untrusted_port}",
            ))
            proof.browser = playwright.chromium.launch(args=[
                f"--host-resolver-rules={rules}",
                f"--ignore-certificate-errors-spki-list={tls.leaf_spki_sha256_base64}",
            ])
            try:
                shipped_default = host.cookie_samesite == DEFAULT_COOKIE_SAMESITE
                if shipped_default and not run_default_scenarios(proof):
                    return
                for origin in (APP_ORIGIN, SECOND_APP_ORIGIN):
                    proof.held_or_failed(
                        f"SCENARIO 5 {origin} {host.cookie_samesite}",
                        lambda origin=origin, samesite=host.cookie_samesite: (
                            session_cookie_after_redirect(proof, origin, samesite)
                        ),
                    )
            finally:
                proof.browser.close()


SCENARIOS_PER_WIDTH = (
    (1, login), (4, disabled_user_is_refused), (6, pages_fit_the_window),
)


def run_default_scenarios(proof: Proof) -> bool:
    """Everything but the cookie grid runs once, on the shipped default; False stops the run."""
    if not proof.held_or_failed(
        "CHECK issuer-document", lambda: issuer_document_is_canonical(proof)
    ):
        return False
    if not proof.held_or_failed(
        "CHECK untrusted-certificate", lambda: untrusted_certificate_is_refused(proof)
    ):
        return False
    for width in WIDTHS:
        for number, scenario in SCENARIOS_PER_WIDTH:
            proof.held_or_failed(
                f"SCENARIO {number} {width.label} {APP_ORIGIN}",
                lambda scenario=scenario, width=width: scenario(proof, width),
            )
    proof.held_or_failed(f"SCENARIO 2 {DESKTOP.label} {APP_ORIGIN}", lambda: logout(proof))
    return True


def prove(edge: Path, scratch: Path) -> int:
    if scratch.exists() and any(scratch.iterdir()):
        print(f"FAILED: --scratch {scratch} is not empty")
        return 2
    evidence_dir = scratch / "evidence"
    evidence_dir.mkdir(parents=True)
    registry = SecretRegistry()
    proof = Proof(evidence_dir, registry, NetworkLog(registry))
    stop_on_first_signal(proof)
    try:
        require_pinned_clean_edge(edge)
        with runtime_directory(scratch) as runtime:
            run_proof(proof, edge, runtime)
    except Interrupted:
        pass
    except Exception as error:
        proof.fail(f"{type(error).__name__}: {error}")
    finally:
        proof.winding_down = True
        for stop_signal in STOP_SIGNALS:
            signal.signal(stop_signal, signal.SIG_IGN)
        if proof.stop_requested.is_set():
            proof.fail("interrupted")
        for left in leftovers(scratch, EDGE_CONTAINER_FILTER):
            proof.fail(left)
    return max(0 if proof.all_held else 1, keep_clean_evidence(proof))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--edge", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    arguments = parser.parse_args()
    return prove(arguments.edge.resolve(), arguments.scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
