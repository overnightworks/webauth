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
    cookie_name_and_value,
    drive_browser_off_the_main_thread,
    free_port,
    host_state,
    keep_clean_evidence,
    launch_pinned_chromium,
    leftovers,
    recording_context,
    remember_cookies,
    reset_host,
    runtime_directory,
    start_host,
    stop_host,
    stop_on_first_signal,
    tell_host,
)
from host_app import HostSettings
from playwright.sync_api import Browser, BrowserContext, Cookie, Page, sync_playwright
from shim import TlsShim
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
OUTSIDER_NAME = "d1-outsider"
ADMIN_NAME = "d1-admin"
ADMIN_GROUP = f"{USER_GROUP}/admin"
KEYCLOAK_DISABLED_MESSAGE = "Account is disabled"
KEYCLOAK_LOGOUT_CONFIRMATION = "#kc-logout"
SAMESITE_VALUES: tuple[CookieSameSite, ...] = ("strict", "lax")


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
    host: Host | None = None
    ca_certificate: Path | None = None
    session_secret: str = ""
    user_password: str = ""
    disabled_user_password: str = ""
    disabled_user_id: str = ""
    outsider_password: str = ""
    outsider_id: str = ""
    admin_password: str = ""
    client_uuid: str = ""
    client_secret: str = ""
    stack: HeldStack | None = None
    width: Width = DESKTOP

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
        with recording_context(self, self.browser, **width.context_options) as context:
            page = context.new_page()
            try:
                yield page
            finally:
                self.register_pending_logins(context)

    def register_pending_logins(self, context: BrowserContext) -> None:
        for cookie in context.cookies():
            name, value = cookie_name_and_value(cookie)
            if is_pending_login_cookie_name(name, secure=True):
                self._register_pending_login(value)

    def capture_cookies(self, context: BrowserContext) -> None:
        remember_cookies(self, context)
        self.register_pending_logins(context)

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
        assert self.host is not None
        return host_state(self.host)

    def reset_host(self) -> None:
        assert self.host is not None
        reset_host(self.host)

    def deactivate_host_accounts(self) -> None:
        assert self.host is not None
        tell_host(self.host, "deactivate")

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
        admin_status = proof.status_of(page, "/admin")
        assert admin_status == 403, f"/admin answered {admin_status} to a plain member"
        proof.shot(page, f"1-{width.label}", "result")
    held = proof.host_state()
    assert held["accounts"] == 1 and held["sessions"] == 1, f"the host holds {held}"
    signed_in = (
        f"{USER_NAME} signed in at Keycloak's form; '/' says 'Signed in as {USER_NAME}', "
        "GET /me answered 200 and GET /admin 403"
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
        carried = {cookie_name_and_value(c)[0] for c in page.context.cookies(APP_ORIGIN)}
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


def outsider_is_refused(proof: Proof, width: Width) -> str:
    scenario = f"7-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(
            page, scenario, username=OUTSIDER_NAME, password=proof.outsider_password
        )
        assert proof.headline(page) == "Sign-in refused", f"the page says {proof.headline(page)!r}"
        assert "not-a-member" in page.inner_text("body"), "the page does not name the reason"
        proof.assert_fits(page, "h1")
        proof.shot(page, scenario, "result")
        carried = {cookie_name_and_value(c)[0] for c in page.context.cookies(APP_ORIGIN)}
        assert DEFAULT_SESSION_COOKIE_NAME not in carried, "a session cookie was issued"
    held = proof.host_state()
    assert (held["accounts"], held["sessions"]) == (0, 0), f"the host holds {held}"
    assert held["last_refusal"] == "not-a-member", f"the host refused {held}"
    return (
        f"{OUTSIDER_NAME}, in no group, signed in at Keycloak and the callback was refused with "
        "'not-a-member': host accounts 0, sessions 0, no session cookie"
    )


def subgroup_member_is_admitted(proof: Proof, width: Width) -> str:
    scenario = f"8-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario, username=ADMIN_NAME, password=proof.admin_password)
        page.goto(f"{APP_ORIGIN}/")
        headline = proof.headline(page)
        assert headline == f"Signed in as {ADMIN_NAME}", f"the page says {headline!r}"
        admin_status = proof.status_of(page, "/admin")
        assert admin_status == 200, f"/admin answered {admin_status} to a member of {ADMIN_GROUP}"
        proof.shot(page, scenario, "result")
    held = proof.host_state()
    assert (held["accounts"], held["sessions"]) == (1, 1), f"the host holds {held}"
    return (
        f"{ADMIN_NAME}, a member of {ADMIN_GROUP} only, was admitted "
        "and GET /admin answered 200: host accounts 1, sessions 1"
    )


def outsiders_groups_claim_is_recorded(proof: Proof) -> str:
    assert proof.stack is not None
    admin = proof.stack.admin()
    proof.registry.add("admin token", admin.token)
    example = admin.get(
        f"/{REALM}/clients/{proof.client_uuid}/evaluate-scopes/generate-example-id-token"
        f"?userId={proof.outsider_id}&scope=openid%20groups"
    )
    if "groups" not in example:
        return "Keycloak leaves the groups claim out for a person in no group (claim absent)"
    sent = len(example["groups"])
    return f"Keycloak sends the groups claim for a person in no group ({sent} entries)"


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


def logout(proof: Proof, width: Width) -> str:
    scenario = f"2-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario)
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}"
        cookies = page.context.cookies(APP_ORIGIN)
        held_names = {cookie_name_and_value(c)[0] for c in cookies}
        session = next(
            c for c in cookies if cookie_name_and_value(c)[0] == DEFAULT_SESSION_COOKIE_NAME
        )
        proof.registry.add("session cookie", cookie_name_and_value(session)[1])
        proof.press(page, "#logout")
        confirm_at_keycloak(proof, page, scenario)
        left = held_names & {
            cookie_name_and_value(c)[0] for c in page.context.cookies(APP_ORIGIN)
        }
        assert not left, f"cookies survived: {sorted(left)}"
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        proof.press(page, KEYCLOAK_LOGOUT_CONFIRMATION)
        page.wait_for_url(f"{APP_ORIGIN}/")
        page.get_by_role("heading", name="Signed out").wait_for()
        page.reload()
        assert proof.headline(page) == "Signed out", "a reload of '/' did not show Sign in"
        proof.shot(page, scenario, "result")
        me_status = proof.status_of(page, "/me")
        assert me_status == 401, f"/me answered {me_status}"
        back_shows = back_button_shows(proof, page)
        replay = replayed_session_status(proof, session)
        assert replay == 401, f"the old session cookie was answered {replay}"
        again = second_sign_in(proof, page, scenario)
    return (
        f"the button led to Keycloak's confirmation with the host already at 0 sessions and "
        f"no app cookie; after confirming, the app showed Signed out and /me answered 401; "
        f"the back button shows {back_shows!r} but the old session cookie replayed over HTTPS "
        f"to /me is refused ({replay}); a second Sign in {again}"
    )


def confirm_at_keycloak(proof: Proof, page: Page, scenario: str) -> None:
    page.locator(KEYCLOAK_LOGOUT_CONFIRMATION).wait_for()
    proof.assert_fits(page, KEYCLOAK_LOGOUT_CONFIRMATION)
    proof.shot(page, scenario, "keycloak-confirmation")


def logout_after_the_app_session_ended(proof: Proof, width: Width) -> str:
    scenario = f"9-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario)
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}"
        proof.reset_host()
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        proof.press(page, "#logout")
        confirm_at_keycloak(proof, page, scenario)
        proof.press(page, KEYCLOAK_LOGOUT_CONFIRMATION)
        page.wait_for_url(f"{APP_ORIGIN}/")
        page.get_by_role("heading", name="Signed out").wait_for()
        proof.shot(page, scenario, "result")
        again = second_sign_in(proof, page, scenario)
    return (
        f"with the app session already gone, the button still led to Keycloak's confirmation "
        f"and back to the app, signed out; a second Sign in {again}"
    )


def back_button_shows(proof: Proof, page: Page) -> str:
    page.go_back()
    page_text = page.inner_text("h1") if page.query_selector("h1") else "no page"
    return f"{page_text} (the host's last sign-in refusal: {proof.host_state()['last_refusal']})"


def replayed_session_status(proof: Proof, session: Cookie) -> int:
    assert proof.ca_certificate is not None and proof.host is not None
    name, value = cookie_name_and_value(session)
    return httpx.get(
        f"https://localhost:{proof.host.app_port}/me",
        headers={"Cookie": f"{name}={value}"},
        verify=ssl.create_default_context(cafile=str(proof.ca_certificate)),
    ).status_code


def second_sign_in(proof: Proof, page: Page, scenario: str) -> str:
    page.goto(f"{APP_ORIGIN}/")
    proof.press(page, "#sign-in")
    keycloak_form = page.locator("#username")
    signed_in = page.get_by_role("heading", name=f"Signed in as {USER_NAME}")
    keycloak_form.or_(signed_in).wait_for()
    proof.shot(page, scenario, "second-sign-in")
    if not keycloak_form.is_visible():
        raise Finding("a second Sign in passed through Keycloak's live SSO session without a form")
    return "shows Keycloak's form again"


def create_user(admin: Admin, username: str, password: str, groups: tuple[str, ...]) -> str:
    user_id = admin.create(f"/{REALM}/users", {
        "username": username,
        "enabled": True,
        "email": f"{username}@d1.invalid",
        "emailVerified": True,
        "firstName": "D1",
        "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    for path in groups:
        group = admin.get(f"/{REALM}/group-by-path{path}")
        admin.put(f"/{REALM}/users/{user_id}/groups/{group['id']}")
    return user_id


def prepare_keycloak(admin: Admin, proof: Proof, client_secret: str) -> None:
    proof.client_uuid = admin.create(f"/{REALM}/clients", {
        "clientId": CLIENT_ID,
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "attributes": {"post.logout.redirect.uris": f"{APP_ORIGIN}/##{SECOND_APP_ORIGIN}/"},
        "redirectUris": [
            f"{APP_ORIGIN}{CALLBACK_PATH}", f"{SECOND_APP_ORIGIN}{CALLBACK_PATH}",
        ],
        "defaultClientScopes": ["basic", "profile", "groups"],
    })
    songmaker = admin.get(f"/{REALM}/group-by-path{USER_GROUP}")
    admin.create(f"/{REALM}/groups/{songmaker['id']}/children", {"name": "admin"})
    create_user(admin, USER_NAME, proof.user_password, (USER_GROUP,))
    proof.disabled_user_id = create_user(
        admin, DISABLED_USER_NAME, proof.disabled_user_password, (USER_GROUP,)
    )
    proof.outsider_id = create_user(admin, OUTSIDER_NAME, proof.outsider_password, ())
    create_user(admin, ADMIN_NAME, proof.admin_password, (ADMIN_GROUP,))


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
        login_group=USER_GROUP,
        admin_group=ADMIN_GROUP,
        authorization_endpoint=f"{OIDC_PATH}/auth",
        end_session_endpoint=f"{OIDC_PATH}/logout",
        token_endpoint=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/token",
        jwks_url=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/certs",
        client_id=CLIENT_ID,
        client_secret=proof.client_secret,
        session_secret=proof.session_secret,
        cookie_samesite=cookie_samesite,
    )


def run_proof(proof: Proof, edge: Path, runtime: Path) -> None:
    proof.session_secret = secrets.token_urlsafe(48)
    proof.user_password = secrets.token_urlsafe(18)
    proof.client_secret = secrets.token_urlsafe(24)
    proof.disabled_user_password = secrets.token_urlsafe(18)
    proof.outsider_password = secrets.token_urlsafe(18)
    proof.admin_password = secrets.token_urlsafe(18)
    for label, value in (
        ("session secret", proof.session_secret), ("user password", proof.user_password),
        ("disabled user password", proof.disabled_user_password),
        ("outsider password", proof.outsider_password), ("admin password", proof.admin_password),
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
                    lambda: drive_browser(
                        proof, runtime, tls, shim.port, untrusted_shim.port, hosts
                    ),
                )
            finally:
                proof.winding_down = True
                for host in hosts:
                    stop_host(host.process)
    print("\n".join(line for line in stack.output if line.startswith("teardown")), flush=True)


def drive_browser(
    proof: Proof, runtime: Path, tls: ThrowawayTls, shim_port: int, untrusted_port: int,
    hosts: list[Host],
) -> None:
    with sync_playwright() as playwright:
        for host in hosts:
            proof.host = host
            proof.browser = launch_pinned_chromium(
                playwright, runtime,
                {
                    IDP_HOST: shim_port,
                    APP_HOST: host.app_port,
                    SECOND_APP_HOST: host.app_port,
                    UNTRUSTED_HOST: untrusted_port,
                },
                tls.leaf_spki_sha256_base64,
            )
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
    (1, login), (2, logout), (4, disabled_user_is_refused), (6, pages_fit_the_window),
    (7, outsider_is_refused),
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
    proof.held_or_failed(
        "CHECK outsider-groups-claim", lambda: outsiders_groups_claim_is_recorded(proof)
    )
    for width in WIDTHS:
        for number, scenario in SCENARIOS_PER_WIDTH:
            proof.held_or_failed(
                f"SCENARIO {number} {width.label} {APP_ORIGIN}",
                lambda scenario=scenario, width=width: scenario(proof, width),
            )
    proof.held_or_failed(
        f"SCENARIO 8 {DESKTOP.label} {APP_ORIGIN}",
        lambda: subgroup_member_is_admitted(proof, DESKTOP),
    )
    proof.held_or_failed(
        f"SCENARIO 9 {DESKTOP.label} {APP_ORIGIN}",
        lambda: logout_after_the_app_session_ended(proof, DESKTOP),
    )
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
    if not __debug__:
        raise SystemExit("prove.py checks with assert; run it without python -O")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--edge", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    arguments = parser.parse_args()
    return prove(arguments.edge.resolve(), arguments.scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
