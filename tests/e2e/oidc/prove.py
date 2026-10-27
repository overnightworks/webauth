"""Proves login and logout of a webauth host in a real browser against a real Keycloak.

    scripts/run_oidc_proof.sh prove --edge PATH

``README.md`` beside this file is the runbook. Nothing of the OIDC path is faked:
the browser fills Keycloak's own form, the host's library talks to the real
token and key-set endpoints, and the only seams are the connection routing and
the one throwaway certificate key the browser is told to accept.

The host application is ``build_app`` in ``host_app.py``. The scenarios below
are registered in ``run_default_scenarios``, ``run_token_scenarios``,
``drive_backchannel_phase``, ``drive_bearer_phase`` and ``run_proof``, which print
``SCENARIO <number> <width> <origin>`` for each, except that the back-channel scenarios
(10 to 13, 22 and 23) print both app origins after the width and scenario 5 prints
``SCENARIO 5 <origin> <cookie_samesite>``; there are no scenarios 3, 16 and 18 to 20.
Scenarios 52 to 54 are the engine phase (``engines.py``), which runs before the back-channel
phase. Scenarios 28 onwards are the bearer phase: ``bearer.py`` states each of them.

Screenshots are taken only at fixed moments of a scenario: the start page,
Keycloak's form with the password filled (or Keycloak's refusal, where Keycloak
clears the field), the result page (the refusal page in scenario 7), the app's
page after every logout through the button, the second sign-in of scenarios 2, 9
and 21, the cross-site page and the app's answer to it in scenario 22, Keycloak's
confirmation page in scenario 23, A's page after the disable and before the
admin logout in scenario 13, in scenarios 10 to 13 also the other context's or
app's result page, and, in scenario 5, only the first page, named after the
origin and the ``cookie_samesite``. A pending-login cookie's name carries a
digest of the login's state; the result table keeps ``__Host-oidc_pending_*``.

Login and logout (the host's ``login_group`` is ``/apps/songmaker`` and its
``admin_group`` ``/apps/songmaker/admin``):

- Scenario 1 is the login (the plain member ``d1-user`` gets 403 from
  ``/admin``); its wrong-password step stays at Keycloak (screenshots
  ``1b-*``).
- Scenario 2 is the logout, at both widths: the host's ``#logout`` is a plain
  form POST that the origin check admits; the browser
  reaches Keycloak's end-session request, where the host already holds 0
  sessions and the browser no app cookie; Keycloak answers with a redirect to
  the app's ``/`` and ``#kc-logout`` never attaches, because the host sent the
  login's ID token, held in the session row, as ``id_token_hint`` (the POST
  carries one); the app shows "Signed out", and a second "Sign in" shows
  Keycloak's form again (a silent sign-in is a failure).
- Scenario 9 (1280x800) ends the app session in the host while the page still
  shows the button: the logout sends no hint, so Keycloak asks once; after
  confirming, the app shows "Signed out" and the next sign-in shows Keycloak's
  form.

The token scenarios, all at 1280x800:

- Scenario 14: after the sign-in the browser holds exactly the session cookie
  for the app, and no cookie of the app on any path parses as a JWS.
- Scenario 15: a login and logout, then a second login and a second logout,
  show no page, and the second logout's hint differs from the first's.
- Scenario 17: one login and logout on the cross-site origin
  ``demo.example.test`` show no page. A refused sign-in (scenario 7) leaves no
  session cookie and no cookie that parses as a JWS.
- Scenario 21 gives the default host's client (``d1-host``)
  ``access.token.lifespan`` 15 s through the admin API (the previous setting is
  restored afterwards), signs in, waits from the callback until the clock is 2 s
  past the token's lifespan and logs out: the end-session request carries
  ``id_token_hint`` and, at the send, the clock is at least 2 s past the hint's
  ``exp``; Keycloak still answers with a redirect to the app, no ``#kc-logout``
  page appears, the app shows "Signed out", and the next sign-in shows
  Keycloak's form. This is the production case: Keycloak's ID token lasts 5
  minutes by default, the session cookie 12 hours.

Sign-in outcomes:

- Scenario 4 is the disabled user: Keycloak's form refuses, no callback reaches
  the app; enabled again, the same credentials sign in.
- Scenario 24 (1280x800) is the deep link: a browser without a session opens
  ``/albums/42?page=2``, is sent to Keycloak, signs in and lands on
  ``/albums/42?page=2``, which says "Album 42".
- Scenario 6 asserts by bounding boxes that the forms and pages lie inside the
  window.
- Scenario 7 is the outsider: ``d1-outsider`` is in no group, signs in at
  Keycloak, reaches the callback and sees "Sign-in refused" with
  ``not-a-member``; the host holds 0 accounts and 0 sessions and the browser
  carries no session cookie. ``CHECK outsider-groups-claim`` records, as a
  count only, whether Keycloak sends the outsider a ``groups`` claim at all;
  Keycloak leaves the claim out for a person in no group (claim absent).
- Scenario 8 (1280x800) is ``d1-admin``, a member of ``/apps/songmaker/admin``
  only (the subgroup the pinned realm declares under ``/apps/songmaker``): it
  is admitted, ``/admin`` answers 200 and the host holds 1 account.

``CHECK untrusted-certificate`` proves that the browser refuses a certificate with
another key, signed by a CA nobody trusts, with a ``net::ERR_*CERT*`` error.

Scenarios 1, 2, 4, 6 and 7 run at 390x844 (mobile emulation, touch) and
1280x800; the scenarios not listed otherwise run at 1280x800. The run stays
inside its 900 s budget (``run_cap_seconds`` in ``scripts/run_oidc_proof.sh``).

The back-channel phase, scenarios 10 to 13 at 390x844 and 1280x800 and
scenarios 22 and 23 at 1280x800, runs against two further hosts, app A on
``https://demo.hallucinai.de`` and app B on ``https://demo.example.test``
(cookie ``lax``), each configured independently: its own Keycloak client
(``d1-app-a``, ``d1-app-b``), its own session and account stores and its own
signing secret, and each with ``build_app``'s ``/auth/backchannel-logout``
route (the body-size, cache-control and CSRF exemptions ``build_app`` sets; no
rate limit in this host). Each client carries ``frontchannelLogout: false``,
``backchannel.logout.url`` (its bridge, see ``shim.py``),
``backchannel.logout.session.required: "false"``,
``backchannel.logout.revoke.offline.tokens: "false"``,
``id.token.signed.response.alg: "RS256"`` and its ``post.logout.redirect.uris``.
The ``d1-host`` client of the scenarios above has no callback URL, so they are
unchanged. The host counts accepted and refused callbacks beside its sessions,
and no scenario calls ``/reset`` between its sign-in and its assertions. The
result is counts, response outcomes and screenshots, never a Logout Token.

- Scenario 10, subject-wide: two contexts sign in to app A as the same person.
  One logs out through the host's button, with no confirmation page; when the
  request reaches Keycloak the host still holds the other session and no
  callback. Then Keycloak's callback is accepted once, the host holds 0
  sessions, and the other context's next ``/me`` is 401 and its reloaded page
  says "Signed out".
- Scenario 11, cross-app: one context signs in to A and B, a second context to
  B (2 sessions). A logout in A calls B back, and both B sessions end.
- Scenario 12, admin logout: ``POST /admin/realms/hallucinai/users/{id}/logout``
  answers 204; both apps are called back and answer ``/me`` with 401.
- Scenario 13, disable, then admin logout (the lock flow): a person signs in to
  A and B and the account is disabled; that alone ends nothing: both apps still
  hold 1 session with 0 callbacks and A's page still says signed in. Keycloak's
  admin logout (204) then calls each app back exactly once, which also shows
  the disable sent none; each holds 0 sessions and answers ``/me`` with 401. A
  fresh sign in is refused at Keycloak's form.
- Scenario 22, a logout from another site (proves a sentence of the ``log_out``
  docstring): the browser holds a signed-in session at app A. A page on
  ``https://demo.example.test``, which the harness fulfils in the browser (the
  hosts' policies would not let a served page post across origins), submits a
  form to A's ``/logout``. A answers 403 ``Cross-origin request rejected`` from
  the origin check; ``/`` still says signed in, ``/me`` answers 200, the host
  holds 1 session. The person's own logout then ends the session with no page.
- Scenario 23, a logout after the back-channel logout ended the row (proves a
  sentence of the ``log_out`` docstring): a person signs in to A (Keycloak
  session S1), Keycloak's admin logout ends S1 (A's back-channel call ends A's
  row), a sign-in to B in the same browser opens S2, and A's page, still showing
  its button, posts the logout, which sends no hint. Keycloak asks "Do you want
  to log out?" (status 200 and ``#kc-logout``), as the docstring says; after
  confirming, it ends S2 and calls B back.

The refresh phase, scenarios 25 to 27 on the default host at 1280x800. The
host's ``GET /access-token`` calls ``fresh_access_token`` for the request's
session and ``GET /workload-token`` calls ``workload_access_token``; each
answers the outcome only, never a token, and the first adds how many different
refresh tokens the host has found stored after these calls since its last
reset.

- Scenario 25, rotation: after a sign-in two calls both answer ``token``, and
  the host has stored a different refresh token after each (Keycloak rotates
  the string on every refresh); the logout after them still sends an
  ``id_token_hint`` and Keycloak answers with a redirect to the app.
- Scenario 26, the issuer ends the person: Keycloak's admin logout of the
  user's sessions (the ``d1-host`` client has no back-channel URL, so the app
  session stands) makes the next call answer ``sign-in-again`` while ``/me``
  still answers 200; after the app's own logout, the old session cookie
  replayed makes it answer ``session-ended``.
- Scenario 27, the workload grant: the probe's client is created with
  ``serviceAccountsEnabled: false``, so its ``client_credentials`` request is
  answered ``token-request-refused`` with ``unauthorized_client``.

Scenario 5 is the session cookie after the callback redirect. One host process
per ``cookie_samesite`` serves both app origins; each cell uses a fresh browser
context and is measured on the ``GET /`` that the ``/auth/callback`` redirect
leads to: the cookie names it carried, its ``Sec-Fetch-Site``, and the page it
rendered. A logged-out first page is ``FAILED-as-found``: a finding to file,
not a failed run. A second sign-in that passes through Keycloak's live session
without a form (scenarios 2, 9 and 21) is a finding of the same kind.

Deliberately unproven: the demotion of a person taken out of the admin group is
proven at the ``finish_login`` layer, not here (a D1 step would need an
``Admin.delete`` in ``stack.py``), and a successful workload token is not
proven (scenario 27 proves only the refusal)."""

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
from bearer import drive_bearer_phase
from certificates import ThrowawayTls, issue_throwaway_tls
from engines import EngineRun, drive_engine_phase
from harness import (
    STOP_SIGNALS,
    Finding,
    Host,
    Interrupted,
    RunRecord,
    browser_context,
    cookie_name_and_value,
    drive_browser_off_the_main_thread,
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
from host_app import (
    ACCESS_TOKEN_PATH,
    CALLBACK_PATH,
    LOGOUT_PATH,
    WORKLOAD_TOKEN_PATH,
)
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
from realm import (
    ADMIN_GROUP,
    ADMIN_NAME,
    CLIENT_ID,
    END_SESSION_ENDPOINT,
    IDP_HOST,
    ISSUER,
    OUTSIDER_NAME,
    REALM,
    USER_GROUP,
    USER_NAME,
    client_representation,
    create_user,
    host_settings,
    short_lived_tokens,
)
from shim import CallbackBridge, TlsShim
from stack import Admin, HeldStack, require_pinned_clean_edge

from webauth.config import WebAuthConfig
from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    CookieSameSite,
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

APP_HOST = "demo.hallucinai.de"
SECOND_APP_HOST = "demo.example.test"
UNTRUSTED_HOST = "untrusted.hallucinai.de"
EDGE_CONTAINER_FILTER = "edge-kc-probe"
APP_ORIGIN = f"https://{APP_HOST}"
SECOND_APP_ORIGIN = f"https://{SECOND_APP_HOST}"
DISABLED_USER_NAME = "d1-disabled"
KEYCLOAK_DISABLED_MESSAGE = "Account is disabled"
KEYCLOAK_LOGOUT_CONFIRMATION = "#kc-logout"
COMPACT_JWS = re.compile(r"[\w-]+\.[\w-]+\.[\w-]*", re.ASCII)
SAMESITE_VALUES: tuple[CookieSameSite, ...] = ("strict", "lax")
CALLBACK_WAIT_SECONDS = 15
CALLBACK_POLL_SECONDS = 0.2
SHORT_TOKEN_LIFESPAN_SECONDS = 15
EXPIRY_MARGIN_SECONDS = 2


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


def app_cookies(page: Page, origin: str = APP_ORIGIN) -> list[Cookie]:
    """Every cookie the browser holds for the app's host, on every path."""
    host = urllib.parse.urlsplit(origin).hostname
    return [
        cookie for cookie in page.context.cookies()
        if cookie.get("domain", "").lstrip(".") == host
    ]


def jws_cookies(page: Page, origin: str = APP_ORIGIN) -> list[str]:
    """The names of the app's cookies whose value has the shape of a compact JWS."""
    return [
        name for name, value in map(cookie_name_and_value, app_cookies(page, origin))
        if COMPACT_JWS.fullmatch(value)
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
    def browsing(self, width: Width = DESKTOP, **options: Any) -> Iterator[Page]:
        assert self.browser is not None
        self.width = width
        with browser_context(self.browser, **width.context_options, **options) as context:
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
        assert not jws_cookies(page), "a refused sign-in left a cookie shaped like a JWS"
    held = proof.host_state()
    assert (held["accounts"], held["sessions"]) == (0, 0), f"the host holds {held}"
    assert held["last_refusal"] == "not-a-member", f"the host refused {held}"
    return (
        f"{OUTSIDER_NAME}, in no group, signed in at Keycloak and the callback was refused with "
        "'not-a-member': host accounts 0, sessions 0, no session cookie and no cookie shaped "
        "like a JWS"
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
        session = next(
            c for c in cookies if cookie_name_and_value(c)[0] == DEFAULT_SESSION_COOKIE_NAME
        )

        def nothing_of_the_app_is_left(_end_session_request: Request) -> None:
            left = held_names & {cookie_name_and_value(c)[0] for c in app_cookies(page)}
            assert not left, f"cookies survived: {sorted(left)}"
            assert proof.host_state()["sessions"] == 0, "the host still holds a session"

        end_session_request = log_out_through_keycloak(
            proof, page, scenario, APP_ORIGIN, nothing_of_the_app_is_left
        )
        assert sent_hint(end_session_request), "the end-session request carried no ID token hint"
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
        f"host already at 0 sessions and no app cookie, and the POST carried an id_token_hint; "
        f"the app showed Signed out and /me answered 401; "
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
        end_session_request = log_out_through_keycloak(
            proof, page, scenario, APP_ORIGIN, asks_for_confirmation=True
        )
        assert sent_hint(end_session_request) is None, "the end-session request carried a hint"
        proof.shot(page, scenario, "result")
        again = second_sign_in(proof, page, scenario)
    return (
        "with the app session already gone, the logout sent no hint, Keycloak asked once and, "
        f"after confirming, led back to the app, signed out; a second Sign in {again}"
    )


def signed_in(proof: Proof, page: Page, scenario: str, origin: str = APP_ORIGIN) -> None:
    proof.sign_in(page, scenario, origin)
    page.goto(f"{origin}/")
    assert proof.headline(page) == f"Signed in as {USER_NAME}"


def the_browser_holds_no_id_token(proof: Proof, width: Width) -> str:
    scenario = f"14-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in(proof, page, scenario)
        assert proof.status_of(page, "/me") == 200
        held = sorted(cookie_name_and_value(cookie)[0] for cookie in app_cookies(page))
        assert held == [DEFAULT_SESSION_COOKIE_NAME], f"the browser holds {held}"
        assert not jws_cookies(page), f"cookies shaped like a JWS: {jws_cookies(page)}"
    return f"after the sign-in the browser holds exactly {held} for the app, none shaped like a JWS"


def second_login_and_logout_show_no_page(proof: Proof, width: Width) -> str:
    scenario = f"15-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in(proof, page, scenario)
        first = log_out_through_keycloak(proof, page, f"{scenario}-first", APP_ORIGIN)
        signed_in(proof, page, f"{scenario}-second")
        second = log_out_through_keycloak(proof, page, f"{scenario}-second", APP_ORIGIN)
        assert sent_hint(second), "the second logout carried no ID token hint"
        assert sent_hint(second) != sent_hint(first), "the second logout sent the first hint"
    return "after a logout and a second login, the second logout, with a new hint, showed no page"


def logout_on_the_cross_site_origin(proof: Proof, width: Width) -> str:
    scenario = f"17-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in(proof, page, scenario, SECOND_APP_ORIGIN)
        log_out_through_keycloak(proof, page, scenario, SECOND_APP_ORIGIN)
        assert not jws_cookies(page, SECOND_APP_ORIGIN), "a cookie shaped like a JWS remains"
    return f"at {SECOND_APP_ORIGIN} the logout showed no page"


def id_token_expiry(token: str) -> float:
    payload = token.split(".")[1]
    return float(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"])


def sent_hint(end_session_request: Request) -> str | None:
    """The `id_token_hint` the end-session POST carried, or None."""
    form = urllib.parse.parse_qs(end_session_request.post_data or "")
    hints = form.get("id_token_hint", []) if end_session_request.method == "POST" else []
    return hints[0] if hints else None


def logout_after_the_id_token_expired(proof: Proof, width: Width) -> str:
    scenario = f"21-{width.label}"
    proof.reset_host()
    with (
        short_lived_tokens(proof.fresh_admin, proof.client_uuid, SHORT_TOKEN_LIFESPAN_SECONDS),
        proof.browsing(width) as page,
    ):
        signed_in(proof, page, scenario)
        time.sleep(SHORT_TOKEN_LIFESPAN_SECONDS + EXPIRY_MARGIN_SECONDS)
        margins_at_the_send: list[float] = []

        def record_the_clock_past_the_expiry(end_session_request: Request) -> None:
            hint = sent_hint(end_session_request)
            if hint is not None:
                margins_at_the_send.append(time.time() - id_token_expiry(hint))

        log_out_through_keycloak(
            proof, page, scenario, APP_ORIGIN, record_the_clock_past_the_expiry
        )
        assert margins_at_the_send, "the end-session request carried no ID token hint"
        [past] = margins_at_the_send
        assert past >= EXPIRY_MARGIN_SECONDS, f"the clock was only {past:.1f} s past the exp"
        assert proof.host_state()["sessions"] == 0, "the host still holds a session"
        again = second_sign_in(proof, page, scenario)
    return (
        f"with an ID token {SHORT_TOKEN_LIFESPAN_SECONDS} s long, logged out {past:.1f} s past "
        f"its exp at the send, the end-session request carried the hint and Keycloak answered "
        f"with a redirect to the app with no confirmation page; a second Sign in {again}"
    )


def back_button_shows(proof: Proof, page: Page) -> str:
    page.go_back()
    page_text = page.inner_text("h1") if page.query_selector("h1") else "no page"
    if page.query_selector("input[name=id_token_hint]"):
        raise Finding("the back button restored the hint")
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


def press_logout(
    proof: Proof, page: Page, at_end_session: Callable[[Request], None] | None = None
) -> Response:
    """Press the app's button; run `at_end_session` with the end-session request while the
    browser stands at it, before Keycloak has seen it; return Keycloak's answer to it."""

    def hold_end_session(route: Route) -> None:
        assert at_end_session is not None
        at_end_session(route.request)
        route.continue_()

    if at_end_session is not None:
        page.route(END_SESSION_ENDPOINT, hold_end_session)
    try:
        with page.expect_response(END_SESSION_ENDPOINT) as answer:
            proof.press(page, "#logout")
        return answer.value
    finally:
        if at_end_session is not None:
            page.unroute(END_SESSION_ENDPOINT, hold_end_session)


def log_out_through_keycloak(
    proof: Proof, page: Page, scenario: str, origin: str,
    at_end_session: Callable[[Request], None] | None = None, *, asks_for_confirmation: bool = False,
) -> Request:
    """The one logout step: the button, Keycloak's end-session, and back to the app;
    answers the end-session request.

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
    return answer.request


def logout_ends_every_session_of_the_subject(proof: Proof, width: Width) -> str:
    scenario = f"10-{width.label}"
    app, _ = proof.apps
    app.reset()
    with proof.browsing(width) as first, proof.browsing(width) as second:
        proof.sign_in(first, scenario, app.origin)
        proof.sign_in(second, None, app.origin)
        assert proof.status_of(second, "/me") == 200, "the second context is not signed in"
        assert app.state()["sessions"] == 2, f"the host holds {app.state()}"

        def second_session_still_stands(_end_session_request: Request) -> None:
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

        def both_apps_still_hold_their_sessions(_end_session_request: Request) -> None:
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
        default_host = next(h for h in hosts if h.cookie_samesite == SHIPPED_COOKIE_SAMESITE)
        drive_engine_phase(
            EngineRun(proof, APP_ORIGIN, KEYCLOAK_LOGOUT_CONFIRMATION), playwright, runtime, tls,
            {IDP_HOST: shim_port, APP_HOST: default_host.app_port}, default_host, WIDTHS,
        )
        drive_backchannel_phase(proof, playwright, runtime, tls, shim_port, untrusted_port)
        drive_bearer_phase(
            proof, playwright, runtime, tls, shim_port,
            host_settings(
                tls, shim_port, (APP_ORIGIN,), CLIENT_ID, proof.client_secret,
                secrets.token_urlsafe(48), SHIPPED_COOKIE_SAMESITE,
            ),
        )


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
        end_session_request = log_out_through_keycloak(proof, page, scenario, APP_ORIGIN)
    assert sent_hint(end_session_request), "the logout after the rotation carried no hint"
    assert first["outcome"] == "token", f"the first call answered {first}"
    assert second["outcome"] == "token", f"the second call answered {second}"
    assert (first["refresh_tokens_stored"], second["refresh_tokens_stored"]) == (1, 2), (
        f"the stored refresh token did not change between the calls: {first}, {second}"
    )
    return (
        "after a sign-in two calls of fresh_access_token both answered token, and the host "
        "stored a different refresh token after each: Keycloak rotates the string on every "
        "refresh; the logout after them sent an id_token_hint and Keycloak redirected to the app"
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
        signed_in(proof, page, scenario, app_a.origin)
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
        assert_callbacks(app_a, accepted=0, sessions=1)
        log_out_through_keycloak(proof, page, scenario, app_a.origin)
        wait_for_accepted_callbacks(app_a, 1)
    return (
        f"a form on {app_b.origin} posting to {app_a.origin}{LOGOUT_PATH} was answered 403 "
        f"({CROSS_ORIGIN_REFUSAL!r}) with Sec-Fetch-Site {site}; the session stood (/me 200, "
        "host at 1 session), so the person's own logout then showed no page"
    )


def logout_after_the_back_channel_logout_ended_the_row(proof: Proof, width: Width) -> str:
    scenario = f"23-{width.label}"
    app_a, app_b = proof.apps
    proof.log_out_user_everywhere(proof.user_id)
    app_a.reset()
    app_b.reset()
    with proof.browsing(width) as page_a:
        signed_in(proof, page_a, scenario, app_a.origin)
        proof.log_out_user_everywhere(proof.user_id)
        wait_for_accepted_callbacks(app_a, 1)
        assert_callbacks(app_a, accepted=1, sessions=0)
        page_b = page_a.context.new_page()
        signed_in(proof, page_b, f"{scenario}-b", app_b.origin)
        end_session_request = log_out_through_keycloak(
            proof, page_a, scenario, app_a.origin, asks_for_confirmation=True
        )
        assert sent_hint(end_session_request) is None, "A's logout sent a hint"
        wait_for_accepted_callbacks(app_b, 1)
        assert_signed_out(proof, page_b, app_b.origin)
    return (
        "A's row was ended by Keycloak's back-channel logout, a sign-in to B opened a second "
        "Keycloak session, and A's logout sent no hint (asserted in the end-session request) and "
        "led to Keycloak's confirmation page; after confirming, Keycloak called B back and B "
        "says Signed out"
    )


BACKCHANNEL_DESKTOP_SCENARIOS = (
    (22, logout_from_a_page_of_another_site_is_refused),
    (23, logout_after_the_back_channel_logout_ended_the_row),
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
    run_token_scenarios(proof)
    for number, scenario in REFRESH_SCENARIOS:
        proof.held_or_failed(
            f"SCENARIO {number} {DESKTOP.label} {APP_ORIGIN}",
            lambda scenario=scenario: scenario(proof, DESKTOP),
        )
    return True


def run_token_scenarios(proof: Proof) -> None:
    for number, origin, scenario in (
        (14, APP_ORIGIN, the_browser_holds_no_id_token),
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
