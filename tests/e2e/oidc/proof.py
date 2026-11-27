"""The run state of the browser proof: its widths, apps and the ``Proof`` the scenarios share."""

from __future__ import annotations

import contextlib
import re
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any, cast

from harness import (
    Finding,
    Host,
    RunRecord,
    browser_context,
    cookie_name_and_value,
    host_state,
    reset_host,
    without_query_values,
)
from playwright.sync_api import Browser, Cookie, Page
from realm import REALM, USER_NAME
from stack import Admin, HeldStack

from webauth.config import WebAuthConfig
from webauth.cookies import CookieSameSite

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
APP_ORIGIN = f"https://{APP_HOST}"
SECOND_APP_ORIGIN = f"https://{SECOND_APP_HOST}"
COMPACT_JWS = re.compile(r"[\w-]+\.[\w-]+\.[\w-]*", re.ASCII)
SAMESITE_VALUES: tuple[CookieSameSite, ...] = ("strict", "lax")
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
        cookie for cookie in page.context.cookies() if cookie.get("domain", "").lstrip(".") == host
    ]


def jws_cookies(page: Page, origin: str = APP_ORIGIN) -> list[str]:
    """The names of the app's cookies whose value has the shape of a compact JWS."""
    return [
        name
        for name, value in map(cookie_name_and_value, app_cookies(page, origin))
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
        self,
        page: Page,
        scenario: str | None,
        origin: str = APP_ORIGIN,
        username: str = USER_NAME,
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
