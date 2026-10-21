"""Proves login and logout of a webauth host in a real browser against a real Keycloak.

    flock -o /tmp/probe-stack.lock timeout --kill-after=240 900 \\
        uv run --group dev --group e2e python e2e/oidc/prove.py --edge PATH --scratch EMPTY_DIR

Read ``README.md`` beside this file first. Nothing of the OIDC path is faked:
the browser fills Keycloak's own form, the host's library talks to the real
token and key-set endpoints, and the only seams are the connection routing and
the one throwaway certificate key the browser is told to accept."""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import re
import secrets
import signal
import ssl
import sys
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, cast

import httpx
from certificates import ThrowawayTls, issue_throwaway_tls
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    RunRecord,
    browser_context,
    cookie_name_and_value,
    drive_browser_off_the_main_thread,
    free_port,
    host_state,
    keep_results,
    launch_pinned_chromium,
    leftovers,
    reset_host,
    runtime_directory,
    start_host,
    stop_host,
    stop_on_first_signal,
    without_query_values,
)
from host_app import ACCESS_TOKEN_PATH, LOGOUT_PATH, WORKLOAD_TOKEN_PATH, HostSettings
from playwright.sync_api import (
    Browser,
    Cookie,
    Page,
    Playwright,
    Request,
    Response,
    Route,
    sync_playwright,
)
from shim import CallbackBridge, TlsShim
from stack import Admin, HeldStack, require_pinned_clean_edge

from webauth.config import WebAuthConfig
from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    CookieSameSite,
    _id_token_hint_cookie_name,
    _is_pending_login_cookie_name,
    _pending_login_cookie_prefix,
)

SHIPPED_COOKIE_SAMESITE = cast(
    CookieSameSite,
    next(
        config_field.default
        for config_field in fields(WebAuthConfig)
        if config_field.name == "cookie_samesite"
    ),
)

IDP_HOST = "auth.hallucinai.de"
APP_HOST = "demo.hallucinai.de"
SECOND_APP_HOST = "demo.example.test"
UNTRUSTED_HOST = "untrusted.hallucinai.de"
REALM = "hallucinai"
EDGE_CONTAINER_FILTER = "edge-kc-probe"
ISSUER = f"https://{IDP_HOST}/realms/{REALM}"
OIDC_PATH = f"{ISSUER}/protocol/openid-connect"
END_SESSION_ENDPOINT = f"{OIDC_PATH}/logout"
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
ID_TOKEN_HINT_COOKIE_NAME = _id_token_hint_cookie_name(secure=True)
SAMESITE_VALUES: tuple[CookieSameSite, ...] = ("strict", "lax")
CALLBACK_WAIT_SECONDS = 15
CALLBACK_POLL_SECONDS = 0.2
SHORT_TOKEN_LIFESPAN_SECONDS = 15
EXPIRY_MARGIN_SECONDS = 2
LIFESPAN_ATTRIBUTE = "access.token.lifespan"


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


@dataclass(frozen=True)
class AppConfiguration:
    """What one back-channel app is told apart by: its origin, its client and its cookies."""

    origin: str
    client_id: str
    cookie_samesite: CookieSameSite


@dataclass(frozen=True)
class App:
    """A started app: one host process, with its own client, stores and signing secret."""

    configuration: AppConfiguration
    host: Host
    client_secret: str

    @property
    def origin(self) -> str:
        return self.configuration.origin

    def state(self) -> dict[str, Any]:
        return host_state(self.host)

    def reset(self) -> None:
        reset_host(self.host)


BACKCHANNEL_APPS = (
    AppConfiguration(APP_ORIGIN, "d1-app-a", SHIPPED_COOKIE_SAMESITE),
    AppConfiguration(SECOND_APP_ORIGIN, "d1-app-b", "lax"),
)

PHONE = Width(390, 844, touch=True)
DESKTOP = Width(1280, 800, touch=False)
WIDTHS = (PHONE, DESKTOP)


class Finding(Exception):
    """A measurement that came out unfavourably: reported as found, not as a failed run."""


def app_cookies(page: Page, origin: str = APP_ORIGIN) -> list[Cookie]:
    """What the browser sends the app, including the cookie that lives at the logout path."""
    return page.context.cookies([origin, f"{origin}{LOGOUT_PATH}"])


def hint_cookies(page: Page, origin: str = APP_ORIGIN) -> list[Cookie]:
    return [
        cookie for cookie in app_cookies(page, origin)
        if cookie_name_and_value(cookie)[0] == ID_TOKEN_HINT_COOKIE_NAME
    ]


def hints_anywhere(page: Page) -> list[Cookie]:
    return [
        cookie for cookie in page.context.cookies()
        if cookie_name_and_value(cookie)[0] == ID_TOKEN_HINT_COOKIE_NAME
    ]


@dataclass
class Proof(RunRecord):
    """One run: what it created, what it saw, and what it concluded."""

    browser: Browser | None = None
    host: Host | None = None
    ca_certificate: Path | None = None
    session_secret: str = ""
    apps: tuple[App, ...] = ()
    user_id: str = ""
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
        with browser_context(self.browser, **width.context_options) as context:
            yield context.new_page()

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

    def fresh_admin(self) -> Admin:
        assert self.stack is not None
        return self.stack.admin()

    def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        self.fresh_admin().put(f"/{REALM}/users/{user_id}", {"enabled": enabled})

    def log_out_user_everywhere(self, user_id: str) -> None:
        self.fresh_admin().post(f"/{REALM}/users/{user_id}/logout")

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
    return (
        f"Keycloak answered {KEYCLOAK_DISABLED_MESSAGE!r} and no callback reached the app "
        f"(callbacks 0, sessions 0); the same credentials signed in once the user was enabled"
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
        carried = {cookie_name_and_value(c)[0] for c in app_cookies(page)}
        assert DEFAULT_SESSION_COOKIE_NAME not in carried, "a session cookie was issued"
        assert not hints_anywhere(page), "a refused sign-in left an ID token hint"
    held = proof.host_state()
    assert (held["accounts"], held["sessions"]) == (0, 0), f"the host holds {held}"
    assert held["last_refusal"] == "not-a-member", f"the host refused {held}"
    return (
        f"{OUTSIDER_NAME}, in no group, signed in at Keycloak and the callback was refused with "
        "'not-a-member': host accounts 0, sessions 0, no session cookie and no ID token hint"
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


def deep_link_survives_the_login(proof: Proof, width: Width) -> str:
    scenario = f"24-{width.label}"
    deep_link = "/albums/42?page=2"
    proof.reset_host()
    with proof.browsing(width) as page:
        page.goto(f"{APP_ORIGIN}{deep_link}")
        page.wait_for_selector("#username")
        proof.fill_keycloak_form(page, scenario, proof.user_password)
        page.wait_for_url(re.compile(f"^{re.escape(APP_ORIGIN)}/"))
        landed = page.url.removeprefix(APP_ORIGIN)
        assert landed == deep_link, f"the browser landed on {landed!r}"
        headline = proof.headline(page)
        assert headline == "Album 42", f"the page says {headline!r}"
        proof.shot(page, scenario, "result")
    return (
        f"a browser without a session opened {deep_link}, signed in at Keycloak "
        f"and landed on {deep_link}"
    )


def outsiders_groups_claim_is_recorded(proof: Proof) -> str:
    example = proof.fresh_admin().get(
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


def cookie_names(request: Request) -> list[str]:
    return [
        pair.split("=", 1)[0].strip()
        for header in request.headers_array() if header["name"].lower() == "cookie"
        for pair in header["value"].split(";") if pair.strip()
    ]


def recorded_cookie_name(name: str) -> str:
    """A pending-login cookie's name ends in a digest of the login's state;
    the table keeps the shape only."""
    if _is_pending_login_cookie_name(name, secure=True):
        return f"{_pending_login_cookie_prefix(secure=True)}*"
    return name


def raw_header(request: Request, name: str) -> str:
    return next(
        (h["value"] for h in request.headers_array() if h["name"].lower() == name), "(none)"
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
            _is_pending_login_cookie_name(name, secure=True)
            for name in cookie_names(callback)
        ), "the callback carried no pending-login cookie; request cookies are not measured"
        names = [recorded_cookie_name(name) for name in cookie_names(landing)]
        site = raw_header(landing, "sec-fetch-site")
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
        cookies = app_cookies(page)
        held_names = {cookie_name_and_value(c)[0] for c in cookies}
        assert ID_TOKEN_HINT_COOKIE_NAME in held_names, "the sign-in left no ID token hint"
        session = next(
            c for c in cookies if cookie_name_and_value(c)[0] == DEFAULT_SESSION_COOKIE_NAME
        )

        def nothing_of_the_app_is_left() -> None:
            left = held_names & {cookie_name_and_value(c)[0] for c in app_cookies(page)}
            assert not left, f"cookies survived: {sorted(left)}"
            assert proof.host_state()["sessions"] == 0, "the host still holds a session"

        log_out_through_keycloak(proof, page, scenario, APP_ORIGIN, nothing_of_the_app_is_left)
        assert not hints_anywhere(page), "an ID token hint remains after the logout"
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
        f"the button led straight back to the app with no confirmation page (the end-session "
        f"answer was a redirect to '/' and {KEYCLOAK_LOGOUT_CONFIRMATION} never attached), the "
        f"host already at 0 sessions and no app cookie, the hint cookie included; the app "
        f"showed Signed out and /me answered 401; "
        f"the back button shows {back_shows!r} but the old session cookie replayed over HTTPS "
        f"to /me is refused ({replay}); a second Sign in {again}"
    )


def confirm_at_keycloak(proof: Proof, page: Page, scenario: str) -> None:
    page.locator(KEYCLOAK_LOGOUT_CONFIRMATION).wait_for()
    proof.assert_fits(page, KEYCLOAK_LOGOUT_CONFIRMATION)
    proof.shot(page, scenario, "logout-confirmation")


def logout_after_the_app_session_ended(proof: Proof, width: Width) -> str:
    scenario = f"9-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario)
        page.goto(f"{APP_ORIGIN}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}"
        proof.reset_host()
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        log_out_through_keycloak(proof, page, scenario, APP_ORIGIN)
        proof.shot(page, scenario, "result")
        again = second_sign_in(proof, page, scenario)
    return (
        f"with the app session already gone, the button still led back to the app, signed out, "
        f"with no confirmation page; a second Sign in {again}"
    )


def signed_in_with_a_hint(
    proof: Proof, page: Page, scenario: str, origin: str = APP_ORIGIN
) -> Cookie:
    proof.sign_in(page, scenario, origin)
    page.goto(f"{origin}/")
    assert proof.headline(page) == f"Signed in as {USER_NAME}"
    (hint,) = hint_cookies(page, origin)
    return hint


def hint_cookie_stays_at_the_logout_path(proof: Proof, width: Width) -> str:
    scenario = f"14-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        requests: list[Any] = []
        page.context.on("request", lambda request: requests.append(request))
        hint = signed_in_with_a_hint(proof, page, scenario)
        assert proof.status_of(page, "/me") == 200
        attributes = (
            hint.get("path"), hint.get("httpOnly"), hint.get("secure"), hint.get("sameSite")
        )
        assert attributes == (LOGOUT_PATH, True, True, "Strict"), (
            f"the hint is stored as {attributes}"
        )
        assert hint.get("expires", 0) > time.time(), "the hint is a session cookie or expired"
        ordinary = [
            cookie_names(r) for r in requests
            if urllib.parse.urlsplit(r.url).path in ("/", "/me") and r.url.startswith(APP_ORIGIN)
        ]
        assert any(DEFAULT_SESSION_COOKIE_NAME in names for names in ordinary), (
            "no request to / or /me carried the session; request cookies are not measured"
        )
        assert not any(ID_TOKEN_HINT_COOKIE_NAME in names for names in ordinary), (
            "a request to / or /me carried the ID token hint"
        )
    return (
        f"the hint cookie is stored for Path={LOGOUT_PATH}, HttpOnly, Secure, SameSite=Strict, "
        f"with an expiry; {len(ordinary)} requests to / and /me carried the session and never "
        "the hint"
    )


def second_login_and_logout_show_no_page(proof: Proof, width: Width) -> str:
    scenario = f"15-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        first = signed_in_with_a_hint(proof, page, scenario)
        log_out_through_keycloak(proof, page, f"{scenario}-first", APP_ORIGIN)
        second = signed_in_with_a_hint(proof, page, f"{scenario}-second")
        assert cookie_name_and_value(second)[1] != cookie_name_and_value(first)[1], (
            "the second login kept the first login's hint"
        )
        log_out_through_keycloak(proof, page, f"{scenario}-second", APP_ORIGIN)
        assert not hints_anywhere(page), "an ID token hint remains after the second logout"
    return "after a logout and a second login, the second logout, with the new hint, showed no page"


def logout_on_the_cross_site_origin(proof: Proof, width: Width) -> str:
    scenario = f"17-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in_with_a_hint(proof, page, scenario, SECOND_APP_ORIGIN)
        log_out_through_keycloak(proof, page, scenario, SECOND_APP_ORIGIN)
        assert not hints_anywhere(page), "an ID token hint remains after the logout"
    return f"at {SECOND_APP_ORIGIN} the hint was stored and the logout showed no page"


def id_token_expiry(hint: Cookie) -> float:
    payload = cookie_name_and_value(hint)[1].split(".")[1]
    return float(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])


@contextlib.contextmanager
def short_lived_id_tokens(proof: Proof, seconds: int) -> Iterator[None]:
    """App A's client issues tokens that live `seconds`; its previous setting returns afterwards."""
    path = f"/{REALM}/clients/{proof.client_uuid}"
    before = proof.fresh_admin().get(path)
    previous = before["attributes"].get(LIFESPAN_ATTRIBUTE)
    try:
        proof.fresh_admin().put(
            path,
            {**before, "attributes": {**before["attributes"], LIFESPAN_ATTRIBUTE: str(seconds)}},
        )
        yield
    finally:
        admin = proof.fresh_admin()
        current = admin.get(path)
        attributes = {
            name: value for name, value in current["attributes"].items()
            if name != LIFESPAN_ATTRIBUTE
        }
        if previous is not None:
            attributes[LIFESPAN_ATTRIBUTE] = previous
        admin.put(path, {**current, "attributes": attributes})


def end_session_hint_is(end_session_url: str, token: str) -> bool:
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(end_session_url).query)
    return query.get("id_token_hint") == [token]


def wait_until_past(expiry: float) -> float:
    """Waits until the clock is the margin past `expiry`; returns how far past it stands."""
    deadline = time.monotonic() + SHORT_TOKEN_LIFESPAN_SECONDS + 2 * EXPIRY_MARGIN_SECONDS
    while time.time() < expiry + EXPIRY_MARGIN_SECONDS:
        assert time.monotonic() < deadline, "the clock did not pass the ID token's expiry in time"
        time.sleep(CALLBACK_POLL_SECONDS)
    return time.time() - expiry


def logout_after_the_id_token_expired(proof: Proof, width: Width) -> str:
    scenario = f"21-{width.label}"
    proof.reset_host()
    with short_lived_id_tokens(proof, SHORT_TOKEN_LIFESPAN_SECONDS), proof.browsing(width) as page:
        end_session_urls: list[str] = []
        page.context.on(
            "request",
            lambda request: end_session_urls.extend(
                [request.url] if is_end_session_request(request.url) else []
            ),
        )
        hint = signed_in_with_a_hint(proof, page, scenario)
        token = cookie_name_and_value(hint)[1]
        expiry = id_token_expiry(hint)
        assert expiry - time.time() <= SHORT_TOKEN_LIFESPAN_SECONDS, "the ID token is long-lived"
        past = wait_until_past(expiry)
        log_out_through_keycloak(proof, page, scenario, APP_ORIGIN)
        (end_session_url,) = end_session_urls
        assert end_session_hint_is(
            end_session_url, token
        ), "the end-session request did not carry the ID token whose expiry was measured"
        assert not hints_anywhere(page), "an ID token hint remains after the logout"
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        again = second_sign_in(proof, page, scenario)
    return (
        f"with an ID token {SHORT_TOKEN_LIFESPAN_SECONDS} s long, logged out {past:.1f} s past "
        f"its exp, the end-session request carried the hint and Keycloak answered with a redirect "
        f"to the app with no confirmation page; a second Sign in {again}"
    )


def back_button_shows(proof: Proof, page: Page) -> str:
    page.go_back()
    page_text = page.inner_text("h1") if page.query_selector("h1") else "no page"
    return f"{page_text} (the host's last sign-in refusal: {proof.host_state()['last_refusal']})"


def host_answer(proof: Proof, path: str, session: Cookie | None = None) -> httpx.Response:
    """A request to the default host as the app's origin, with the session cookie if given."""
    assert proof.ca_certificate is not None and proof.host is not None
    headers = {"Host": APP_HOST}
    if session is not None:
        name, value = cookie_name_and_value(session)
        headers["Cookie"] = f"{name}={value}"
    return httpx.get(
        f"https://localhost:{proof.host.app_port}{path}",
        headers=headers,
        verify=ssl.create_default_context(cafile=str(proof.ca_certificate)),
    )


def replayed_session_status(proof: Proof, session: Cookie) -> int:
    return host_answer(proof, "/me", session).status_code


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


def sign_in_through_keycloaks_session(
    proof: Proof, page: Page, origin: str, username: str = USER_NAME
) -> None:
    page.goto(f"{origin}/")
    proof.press(page, "#sign-in")
    page.get_by_role("heading", name=f"Signed in as {username}").wait_for()


def wait_for_accepted_callbacks(app: App, accepted: int) -> None:
    deadline = time.monotonic() + CALLBACK_WAIT_SECONDS
    while app.state()["backchannel_accepted"] < accepted:
        assert time.monotonic() < deadline, f"{app.origin} was not called back: {app.state()}"
        time.sleep(CALLBACK_POLL_SECONDS)


def assert_callbacks(app: App, accepted: int, sessions: int) -> None:
    held = app.state()
    assert (held["backchannel_accepted"], held["backchannel_refused"], held["sessions"]) == (
        accepted, 0, sessions,
    ), f"{app.origin} holds {held}"


def assert_signed_out(proof: Proof, page: Page, origin: str) -> None:
    page.goto(f"{origin}/")
    assert proof.headline(page) == "Signed out", f"{origin} says {proof.headline(page)!r}"
    me_status = proof.status_of(page, "/me")
    assert me_status == 401, f"{origin} /me answered {me_status}"


END_SESSION_REQUESTS = f"{END_SESSION_ENDPOINT}?**"


def is_end_session_request(url: str) -> bool:
    return url.startswith(f"{END_SESSION_ENDPOINT}?")


def press_logout(
    proof: Proof, page: Page, at_end_session: Callable[[], None] | None = None
) -> Response:
    """Press the app's button; run `at_end_session` while the browser stands at Keycloak's
    end-session request, before Keycloak has seen it; return Keycloak's answer to it."""

    def hold_end_session(route: Route) -> None:
        assert at_end_session is not None
        at_end_session()
        route.continue_()

    if at_end_session is not None:
        page.route(END_SESSION_REQUESTS, hold_end_session)
    try:
        with page.expect_response(lambda answer: is_end_session_request(answer.url)) as answer:
            proof.press(page, "#logout")
        return answer.value
    finally:
        if at_end_session is not None:
            page.unroute(END_SESSION_REQUESTS, hold_end_session)


def log_out_through_keycloak(
    proof: Proof, page: Page, scenario: str, origin: str,
    at_end_session: Callable[[], None] | None = None, *, asks_for_confirmation: bool = False,
) -> None:
    """The one logout step: the button, Keycloak's end-session, and back to the app.

    With the ID token hint Keycloak answers with a redirect to the app and shows no page;
    without a usable hint it asks first."""
    answer = press_logout(proof, page, at_end_session)
    if asks_for_confirmation:
        assert answer.status == 200, f"Keycloak answered the end-session request {answer.status}"
        confirm_at_keycloak(proof, page, scenario)
        proof.press(page, KEYCLOAK_LOGOUT_CONFIRMATION)
    else:
        landing = answer.header_value("location") or ""
        assert 300 <= answer.status < 400 and landing.startswith(f"{origin}/"), (
            f"Keycloak answered the end-session request {answer.status} {landing!r}, "
            "not a redirect to the app"
        )
    page.wait_for_url(f"{origin}/")
    page.get_by_role("heading", name="Signed out").wait_for()
    proof.shot(page, scenario, "logout-result")
    if not asks_for_confirmation:
        assert page.locator(KEYCLOAK_LOGOUT_CONFIRMATION).count() == 0, "Keycloak's page showed"


def logout_ends_every_session_of_the_subject(proof: Proof, width: Width) -> str:
    scenario = f"10-{width.label}"
    app, _ = proof.apps
    app.reset()
    with proof.browsing(width) as first, proof.browsing(width) as second:
        proof.sign_in(first, scenario, app.origin)
        proof.sign_in(second, None, app.origin)
        assert proof.status_of(second, "/me") == 200, "the second context is not signed in"
        assert app.state()["sessions"] == 2, f"the host holds {app.state()}"

        def second_session_still_stands() -> None:
            assert_callbacks(app, accepted=0, sessions=1)

        log_out_through_keycloak(proof, first, scenario, app.origin, second_session_still_stands)
        wait_for_accepted_callbacks(app, 1)
        proof.shot(first, scenario, "result")
        assert_callbacks(app, accepted=1, sessions=0)
        assert_signed_out(proof, second, app.origin)
        proof.shot(second, scenario, "other-context-result")
    return (
        "two contexts signed in to the app as one person; one logged out through Keycloak with no "
        "confirmation page, the other session still standing when the request reached Keycloak "
        "(sessions 1, callbacks 0); then "
        "Keycloak's callback was accepted once (refused 0), the host holds 0 sessions and the "
        "other context's page says Signed out with /me 401"
    )


def logout_in_one_app_ends_the_sessions_of_the_other(proof: Proof, width: Width) -> str:
    scenario = f"11-{width.label}"
    app_a, app_b = proof.apps
    app_a.reset()
    app_b.reset()
    with proof.browsing(width) as first, proof.browsing(width) as second:
        proof.sign_in(first, scenario, app_a.origin)
        sign_in_through_keycloaks_session(proof, first, app_b.origin)
        proof.sign_in(second, None, app_b.origin)
        assert (app_a.state()["sessions"], app_b.state()["sessions"]) == (1, 2), "setup"
        first.goto(f"{app_a.origin}/")

        def both_apps_still_hold_their_sessions() -> None:
            assert_callbacks(app_a, accepted=0, sessions=0)
            assert_callbacks(app_b, accepted=0, sessions=2)

        log_out_through_keycloak(
            proof, first, scenario, app_a.origin, both_apps_still_hold_their_sessions
        )
        wait_for_accepted_callbacks(app_b, 1)
        assert_callbacks(app_b, accepted=1, sessions=0)
        assert_signed_out(proof, first, app_b.origin)
        proof.shot(first, scenario, "result")
        assert_signed_out(proof, second, app_b.origin)
        proof.shot(second, scenario, "other-context-result")
    return (
        "a person signed in to app A and, through Keycloak's session, to app B, and a second "
        "context signed in to B; a logout in A, with no confirmation page, reached Keycloak "
        "with B holding 2 sessions and 0 callbacks, then Keycloak called B back (accepted 1, "
        "refused 0): B holds 0 sessions and both contexts' B pages say Signed out with /me 401"
    )


def admin_logout_ends_the_sessions_in_every_app(proof: Proof, width: Width) -> str:
    scenario = f"12-{width.label}"
    app_a, app_b = proof.apps
    # Scenarios 10 and 11 leave their second contexts' sessions standing at Keycloak, and the
    # admin logout would call the apps back for them too.
    proof.log_out_user_everywhere(proof.user_id)
    app_a.reset()
    app_b.reset()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario, app_a.origin)
        sign_in_through_keycloaks_session(proof, page, app_b.origin)
        assert (app_a.state()["sessions"], app_b.state()["sessions"]) == (1, 1), "setup"
        proof.log_out_user_everywhere(proof.user_id)
        for app in (app_a, app_b):
            wait_for_accepted_callbacks(app, 1)
            assert_callbacks(app, accepted=1, sessions=0)
            assert_signed_out(proof, page, app.origin)
            proof.shot(page, scenario, f"result-{app.configuration.client_id}")
    return (
        "a person signed in to apps A and B; Keycloak's admin API ended the user's sessions "
        "(204): each app was called back once (accepted 1, refused 0), holds 0 sessions, "
        "and answers /me with 401"
    )


def disabled_account_is_logged_out_everywhere(proof: Proof, width: Width) -> str:
    scenario = f"13-{width.label}"
    app_a, app_b = proof.apps
    app_a.reset()
    app_b.reset()
    try:
        with proof.browsing(width) as page:
            proof.sign_in(
                page, scenario, app_a.origin, DISABLED_USER_NAME, proof.disabled_user_password
            )
            sign_in_through_keycloaks_session(proof, page, app_b.origin, DISABLED_USER_NAME)
            proof.set_user_enabled(proof.disabled_user_id, False)
            page.goto(f"{app_a.origin}/")
            assert proof.headline(page) == f"Signed in as {DISABLED_USER_NAME}", (
                "the disable alone ended the session in A"
            )
            proof.shot(page, scenario, "still-signed-in-after-disable")
            for app in (app_a, app_b):
                assert_callbacks(app, accepted=0, sessions=1)
            proof.log_out_user_everywhere(proof.disabled_user_id)
            for app in (app_a, app_b):
                wait_for_accepted_callbacks(app, 1)
                assert_callbacks(app, accepted=1, sessions=0)
                assert_signed_out(proof, page, app.origin)
                proof.shot(page, scenario, f"result-{app.configuration.client_id}")

        logins_before = app_a.state()["callbacks_received"]
        with proof.browsing(width) as fresh:
            refused = f"{scenario}-fresh"
            proof.start_sign_in(fresh, refused, app_a.origin)
            proof.fill_keycloak_form(
                fresh, refused, proof.disabled_user_password, DISABLED_USER_NAME
            )
            fresh.get_by_text(KEYCLOAK_DISABLED_MESSAGE).wait_for()
            proof.shot(fresh, refused, "refused-result")
        held = app_a.state()
        assert (held["callbacks_received"], held["sessions"]) == (logins_before, 0), held
    finally:
        proof.set_user_enabled(proof.disabled_user_id, True)
    return (
        "a person signed in to apps A and B, then the account was disabled at Keycloak: both apps "
        "still held 1 session with 0 callbacks and A's page still said signed in; Keycloak's "
        "admin logout (204) then called each app back exactly once (accepted 1, refused 0), "
        "so the disable itself sent none: 0 sessions and /me 401 in each; a fresh sign in met "
        f"{KEYCLOAK_DISABLED_MESSAGE!r} at Keycloak and reached no app"
    )


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


def client_representation(
    client_id: str, client_secret: str, origins: tuple[str, ...],
    backchannel_logout_url: str | None = None,
) -> dict[str, Any]:
    attributes = {"post.logout.redirect.uris": "##".join(f"{origin}/" for origin in origins)}
    if backchannel_logout_url is not None:
        attributes |= {
            "backchannel.logout.url": backchannel_logout_url,
            "backchannel.logout.session.required": "false",
            "backchannel.logout.revoke.offline.tokens": "false",
            "id.token.signed.response.alg": "RS256",
        }
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "attributes": attributes,
        "redirectUris": [f"{origin}{CALLBACK_PATH}" for origin in origins],
        "defaultClientScopes": ["basic", "profile", "groups"],
    }


def prepare_keycloak(admin: Admin, proof: Proof, client_secret: str) -> None:
    proof.client_uuid = admin.create(
        f"/{REALM}/clients",
        client_representation(CLIENT_ID, client_secret, (APP_ORIGIN, SECOND_APP_ORIGIN)),
    )
    proof.user_id = create_user(admin, USER_NAME, proof.user_password, (USER_GROUP,))
    proof.disabled_user_id = create_user(
        admin, DISABLED_USER_NAME, proof.disabled_user_password, (USER_GROUP,)
    )
    proof.outsider_id = create_user(admin, OUTSIDER_NAME, proof.outsider_password, ())
    create_user(admin, ADMIN_NAME, proof.admin_password, (ADMIN_GROUP,))


def host_settings(
    tls: ThrowawayTls, shim_port: int, app_origins: tuple[str, ...], client_id: str,
    client_secret: str, session_secret: str, cookie_samesite: CookieSameSite,
) -> HostSettings:
    return HostSettings(
        app_origins=app_origins,
        port=free_port(),
        observe_port=free_port(),
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=ISSUER,
        login_group=USER_GROUP,
        admin_group=ADMIN_GROUP,
        authorization_endpoint=f"{OIDC_PATH}/auth",
        end_session_endpoint=END_SESSION_ENDPOINT,
        token_endpoint=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/token",
        jwks_url=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/certs",
        client_id=client_id,
        client_secret=client_secret,
        session_secret=session_secret,
        cookie_samesite=cookie_samesite,
    )


@contextlib.contextmanager
def backchannel_apps(
    proof: Proof, runtime: Path, tls: ThrowawayTls, shim_port: int
) -> Iterator[tuple[App, ...]]:
    """The apps of the back-channel phase, each behind its own bridge that Keycloak's client
    names, all gone again before the stack is released."""
    assert proof.stack is not None
    network = proof.stack.keycloak_network()
    with contextlib.ExitStack() as running:
        apps: list[App] = []
        for configuration in BACKCHANNEL_APPS:
            client_secret = secrets.token_urlsafe(24)
            session_secret = secrets.token_urlsafe(48)
            settings = host_settings(
                tls, shim_port, (configuration.origin,), configuration.client_id,
                client_secret, session_secret, configuration.cookie_samesite,
            )
            host = start_host(proof, runtime, settings, tls.ca_certificate)
            running.callback(stop_host, host.process)
            bridge = running.enter_context(
                CallbackBridge(network, host.app_port, tls.ca_certificate)
            )
            proof.fresh_admin().create(
                f"/{REALM}/clients",
                client_representation(
                    configuration.client_id, client_secret, (configuration.origin,),
                    bridge.url,
                ),
            )
            apps.append(App(configuration, host, client_secret))
        yield tuple(apps)


def run_proof(proof: Proof, edge: Path, runtime: Path) -> None:
    proof.session_secret = secrets.token_urlsafe(48)
    proof.user_password = secrets.token_urlsafe(18)
    proof.client_secret = secrets.token_urlsafe(24)
    proof.disabled_user_password = secrets.token_urlsafe(18)
    proof.outsider_password = secrets.token_urlsafe(18)
    proof.admin_password = secrets.token_urlsafe(18)
    tls = issue_throwaway_tls(runtime, "good", [IDP_HOST, APP_HOST, SECOND_APP_HOST, "localhost"])
    untrusted = issue_throwaway_tls(runtime, "untrusted", [UNTRUSTED_HOST])
    with HeldStack(edge, runtime / "stack") as stack:
        proof.stack = stack
        admin = stack.admin()
        prepare_keycloak(admin, proof, proof.client_secret)
        edge_port = urllib.parse.urlsplit(stack.edge_url).port
        assert edge_port is not None
        with TlsShim(tls, edge_port, IDP_HOST) as shim, \
                TlsShim(untrusted, edge_port, IDP_HOST) as untrusted_shim:
            hosts: list[Host] = []
            proof.ca_certificate = tls.ca_certificate
            try:
                for cookie_samesite in SAMESITE_VALUES:
                    settings = host_settings(
                        tls, shim.port, (APP_ORIGIN, SECOND_APP_ORIGIN), CLIENT_ID,
                        proof.client_secret, proof.session_secret, cookie_samesite,
                    )
                    hosts.append(start_host(proof, runtime, settings, tls.ca_certificate))
                with backchannel_apps(proof, runtime, tls, shim.port) as apps:
                    proof.apps = apps
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
                shipped_default = host.cookie_samesite == SHIPPED_COOKIE_SAMESITE
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
        drive_backchannel_phase(proof, playwright, runtime, tls, shim_port, untrusted_port)


def session_cookie(page: Page) -> Cookie:
    return next(
        c for c in app_cookies(page) if cookie_name_and_value(c)[0] == DEFAULT_SESSION_COOKIE_NAME
    )


def access_token_answer(proof: Proof, session: Cookie) -> dict[str, Any]:
    answer = host_answer(proof, ACCESS_TOKEN_PATH, session)
    assert answer.status_code == 200, f"{ACCESS_TOKEN_PATH} answered {answer.status_code}"
    return answer.json()


def keycloak_rotates_the_refresh_token(proof: Proof, width: Width) -> str:
    scenario = f"25-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario)
        session = session_cookie(page)
        first = access_token_answer(proof, session)
        second = access_token_answer(proof, session)
    assert first["outcome"] == "token", f"the first call answered {first}"
    assert second["outcome"] == "token", f"the second call answered {second}"
    assert (first["refresh_tokens_stored"], second["refresh_tokens_stored"]) == (1, 2), (
        f"the stored refresh token did not change between the calls: {first}, {second}"
    )
    return (
        "after a sign-in two calls of fresh_access_token both answered token, and the host "
        "stored a different refresh token after each: Keycloak rotates the string on every refresh"
    )


def a_person_ended_at_the_issuer_signs_in_again(proof: Proof, width: Width) -> str:
    scenario = f"26-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario)
        session = session_cookie(page)
        proof.log_out_user_everywhere(proof.user_id)
        refused = access_token_answer(proof, session)
        assert refused["outcome"] == "sign-in-again", f"after the admin logout: {refused}"
        assert refused["refresh_tokens_stored"] == 1, f"no refresh token was stored: {refused}"
        me_status = proof.status_of(page, "/me")
        assert me_status == 200, f"/me answered {me_status}, the app session should stand"
        log_out_through_keycloak(proof, page, scenario, APP_ORIGIN)
        ended = access_token_answer(proof, session)
    assert ended["outcome"] == "session-ended", f"after the app logout: {ended}"
    return (
        "Keycloak's admin logout of the user's sessions made the next call answer sign-in-again "
        "(invalid_grant) while /me still answered 200; after the app's own logout, replaying the "
        "old session cookie made it answer session-ended"
    )


def a_client_without_service_account_is_refused_its_workload_token(
    proof: Proof, width: Width
) -> str:
    refused = host_answer(proof, WORKLOAD_TOKEN_PATH).json()
    assert refused == {
        "outcome": "token-request-refused", "issuer_error": "unauthorized_client",
    }, f"the workload call answered {refused}"
    return (
        f"the probe's client, created with serviceAccountsEnabled false, was refused its "
        f"client_credentials grant: {refused['outcome']} with {refused['issuer_error']}"
    )


REFRESH_SCENARIOS = (
    (25, keycloak_rotates_the_refresh_token),
    (26, a_person_ended_at_the_issuer_signs_in_again),
    (27, a_client_without_service_account_is_refused_its_workload_token),
)


BACKCHANNEL_SCENARIOS = (
    (10, logout_ends_every_session_of_the_subject),
    (11, logout_in_one_app_ends_the_sessions_of_the_other),
    (12, admin_logout_ends_the_sessions_in_every_app),
    (13, disabled_account_is_logged_out_everywhere),
)


CROSS_SITE_LOGOUT_PATH = "/cross-site-logout"
CROSS_ORIGIN_REFUSAL = "Cross-origin request rejected"


def cross_site_logout_page(target_origin: str) -> str:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>another site</title></head>"
        "<body><h1>Another site</h1>"
        f'<form method="post" action="{target_origin}{LOGOUT_PATH}">'
        '<button id="logout" type="submit">Log out</button></form></body></html>'
    )


def logout_from_a_page_of_another_site_is_refused(proof: Proof, width: Width) -> str:
    scenario = f"22-{width.label}"
    app_a, app_b = proof.apps
    app_a.reset()
    with proof.browsing(width) as page:
        hint = signed_in_with_a_hint(proof, page, scenario, app_a.origin)
        page.route(
            f"{app_b.origin}{CROSS_SITE_LOGOUT_PATH}",
            lambda route: route.fulfill(
                body=cross_site_logout_page(app_a.origin), content_type="text/html"
            ),
        )
        page.goto(f"{app_b.origin}{CROSS_SITE_LOGOUT_PATH}")
        page.unroute_all()
        proof.shot(page, scenario, "cross-site-page")
        logout_url = f"{app_a.origin}{LOGOUT_PATH}"
        with page.expect_response(lambda answer: answer.url == logout_url) as answer:
            proof.press(page, "#logout")
        page.wait_for_url(logout_url)
        refusal = page.inner_text("body")
        proof.shot(page, scenario, "refused-result")
        assert answer.value.status == 403, f"the logout was answered {answer.value.status}"
        site = raw_header(answer.value.request, "sec-fetch-site")
        assert site == "cross-site", f"the logout carried Sec-Fetch-Site {site!r}"
        assert CROSS_ORIGIN_REFUSAL in refusal, f"the refusal is {refusal!r}"
        page.goto(f"{app_a.origin}/")
        assert proof.headline(page) == f"Signed in as {USER_NAME}", "the session did not stand"
        proof.shot(page, scenario, "result")
        me_status = proof.status_of(page, "/me")
        assert me_status == 200, f"/me answered {me_status}"
        assert hint_cookies(page, app_a.origin) == [hint], "the ID token hint cookie changed"
        assert_callbacks(app_a, accepted=0, sessions=1)
        log_out_through_keycloak(proof, page, scenario, app_a.origin)
        wait_for_accepted_callbacks(app_a, 1)
    return (
        f"a form on {app_b.origin} posting to {app_a.origin}{LOGOUT_PATH} was answered 403 "
        f"({CROSS_ORIGIN_REFUSAL!r}) with Sec-Fetch-Site {site}; the session stood (/me 200, "
        "host at 1 session) and the ID token hint cookie was not cleared, so the person's own "
        "logout then showed no page"
    )


def logout_with_the_hint_of_another_keycloak_session(proof: Proof, width: Width) -> str:
    scenario = f"23-{width.label}"
    app_a, app_b = proof.apps
    proof.log_out_user_everywhere(proof.user_id)
    app_a.reset()
    app_b.reset()
    with proof.browsing(width) as page_a:
        end_session_urls: list[str] = []
        page_a.context.on(
            "request",
            lambda request: end_session_urls.extend(
                [request.url] if is_end_session_request(request.url) else []
            ),
        )
        hint_of_first_session = signed_in_with_a_hint(proof, page_a, scenario, app_a.origin)
        proof.log_out_user_everywhere(proof.user_id)
        wait_for_accepted_callbacks(app_a, 1)
        assert_callbacks(app_a, accepted=1, sessions=0)
        page_b = page_a.context.new_page()
        hint_of_second_session = signed_in_with_a_hint(proof, page_b, f"{scenario}-b", app_b.origin)
        assert cookie_name_and_value(hint_of_second_session)[1] != cookie_name_and_value(
            hint_of_first_session
        )[1], "the second Keycloak session issued the first session's ID token"
        assert hint_cookies(page_a, app_a.origin) == [hint_of_first_session], "A's hint changed"
        log_out_through_keycloak(
            proof, page_a, scenario, app_a.origin, asks_for_confirmation=True
        )
        (end_session_url,) = end_session_urls
        sent_hint = cookie_name_and_value(hint_of_first_session)[1]
        assert end_session_hint_is(
            end_session_url, sent_hint
        ), "A's logout did not send the first session's ID token"
        wait_for_accepted_callbacks(app_b, 1)
        assert_signed_out(proof, page_b, app_b.origin)
    return (
        "A's session was ended through Keycloak's admin logout (A's hint cookie stayed), a sign-in "
        "to B opened a second Keycloak session, and A's logout, sending the first session's ID "
        "token (asserted in the end-session request), led to Keycloak's confirmation page; after "
        "confirming, Keycloak called B back and B says Signed out"
    )


BACKCHANNEL_DESKTOP_SCENARIOS = (
    (22, logout_from_a_page_of_another_site_is_refused),
    (23, logout_with_the_hint_of_another_keycloak_session),
)


def drive_backchannel_phase(
    proof: Proof, playwright: Playwright, runtime: Path, tls: ThrowawayTls, shim_port: int,
    untrusted_port: int,
) -> None:
    """The apps are two hosts; the browser reaches each on its own origin."""
    app_a, app_b = proof.apps
    proof.browser = launch_pinned_chromium(
        playwright, runtime,
        {
            IDP_HOST: shim_port,
            APP_HOST: app_a.host.app_port,
            SECOND_APP_HOST: app_b.host.app_port,
            UNTRUSTED_HOST: untrusted_port,
        },
        tls.leaf_spki_sha256_base64,
    )
    try:
        for width in WIDTHS:
            for number, scenario in BACKCHANNEL_SCENARIOS:
                proof.held_or_failed(
                    f"SCENARIO {number} {width.label} {app_a.origin} {app_b.origin}",
                    lambda scenario=scenario, width=width: scenario(proof, width),
                )
        for number, scenario in BACKCHANNEL_DESKTOP_SCENARIOS:
            proof.held_or_failed(
                f"SCENARIO {number} {DESKTOP.label} {app_a.origin} {app_b.origin}",
                lambda scenario=scenario: scenario(proof, DESKTOP),
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
    proof.held_or_failed(
        f"SCENARIO 24 {DESKTOP.label} {APP_ORIGIN}",
        lambda: deep_link_survives_the_login(proof, DESKTOP),
    )
    run_hint_scenarios(proof)
    for number, scenario in REFRESH_SCENARIOS:
        proof.held_or_failed(
            f"SCENARIO {number} {DESKTOP.label} {APP_ORIGIN}",
            lambda scenario=scenario: scenario(proof, DESKTOP),
        )
    return True


def run_hint_scenarios(proof: Proof) -> None:
    for number, origin, scenario in (
        (14, APP_ORIGIN, hint_cookie_stays_at_the_logout_path),
        (15, APP_ORIGIN, second_login_and_logout_show_no_page),
        (17, SECOND_APP_ORIGIN, logout_on_the_cross_site_origin),
        (21, APP_ORIGIN, logout_after_the_id_token_expired),
    ):
        proof.held_or_failed(
            f"SCENARIO {number} {DESKTOP.label} {origin}",
            lambda scenario=scenario: scenario(proof, DESKTOP),
        )


def prove(edge: Path, scratch: Path) -> int:
    if scratch.exists() and any(scratch.iterdir()):
        print(f"FAILED: --scratch {scratch} is not empty")
        return 2
    evidence_dir = scratch / "evidence"
    evidence_dir.mkdir(parents=True)
    proof = Proof(evidence_dir)
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
    return max(0 if proof.all_held else 1, keep_results(proof))


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
