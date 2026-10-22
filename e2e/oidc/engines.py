"""Drives the logout page in Chromium without JavaScript, Firefox and WebKit.

``drive_engine_phase`` runs in ``prove.py``'s ``drive_browser`` after the default host's
scenarios and prints ``SCENARIO <number> <width> <origin>`` for scenarios 52 to 54. Each
signs in at Keycloak, presses the host's button and holds the browser to the standard
logout: a POST to the bare end-session endpoint whose form body carries ``id_token_hint``,
Keycloak's redirect to the app, the app saying "Signed out" and no confirmation page.

- 52 Chromium with JavaScript off, at both widths: the page shows its one button inside
  the window and pressing it ends as above.
- 53 Firefox at 1280x800: with the page's script, then with JavaScript off, then the back
  button after the script's run.
- 54 WebKit at 390x844: as 53. It is the Linux port of the engine, not Safari.

The back button's page is recorded, and it fails when it holds the ID token again.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from harness import Host, launch_behind_host_mapping, launch_pinned_chromium
from host_app import LOGOUT_PATH
from realm import END_SESSION_ENDPOINT

if TYPE_CHECKING:
    from certificates import ThrowawayTls
    from playwright.sync_api import Browser, BrowserType, Playwright, Request
    from prove import Proof, Width


@dataclass(frozen=True)
class EngineRun:
    """The proof, the apps' origin and what the host application and Keycloak call things."""

    proof: Proof
    app_origin: str
    confirmation_selector: str


def logout_through_the_page(
    run: EngineRun, browser: Browser, width: Width, scenario: str, *, javascript: bool,
    back_button: bool = False,
) -> str:
    proof = run.proof
    proof.browser = browser
    proof.reset_host()
    options = {"ignore_https_errors": True, "java_script_enabled": javascript}
    with proof.browsing(width, **options) as page:
        proof.sign_in(page, scenario, run.app_origin)
        end_session_requests: list[Request] = []
        page.context.on(
            "request",
            lambda request: end_session_requests.extend(
                [request] if request.url == END_SESSION_ENDPOINT else []
            ),
        )
        with page.expect_response(END_SESSION_ENDPOINT) as answer:
            proof.press(page, "#logout")
            if not javascript:
                page.wait_for_url(f"{run.app_origin}{LOGOUT_PATH}")
                proof.assert_fits(page, "button")
                proof.shot(page, scenario, "logout-page")
                proof.press(page, "button")
        landing = answer.value.header_value("location") or ""
        assert 300 <= answer.value.status < 400 and landing.startswith(f"{run.app_origin}/"), (
            f"Keycloak answered the end-session request {answer.value.status} {landing!r}, "
            "not a redirect to the app"
        )
        (end_session_request,) = end_session_requests
        sent = urllib.parse.parse_qs(end_session_request.post_data or "")
        assert end_session_request.method == "POST", "the end-session request was no POST"
        [token] = sent["id_token_hint"]
        page.wait_for_url(f"{run.app_origin}/")
        page.get_by_role("heading", name="Signed out").wait_for()
        assert page.locator(run.confirmation_selector).count() == 0, "Keycloak's page showed"
        proof.shot(page, scenario, "logout-result")
        back_shows = ""
        if back_button:
            page.go_back()
            assert token not in page.content(), "the page holding the ID token came back"
            back_shows = f"; the back button shows {page.title()!r}"
    mode = "its script" if javascript else "no JavaScript, the button"
    return (
        f"{mode} posted id_token_hint to the bare end-session endpoint and Keycloak "
        f"redirected to the app{back_shows}"
    )


def other_engine(
    run: EngineRun, engine: BrowserType, mapped_hosts: dict[str, int], width: Width, number: int,
) -> str:
    with launch_behind_host_mapping(engine, mapped_hosts) as browser:
        scripted = logout_through_the_page(
            run, browser, width, f"{number}-{width.label}", javascript=True, back_button=True,
        )
        pressed = logout_through_the_page(
            run, browser, width, f"{number}-{width.label}-no-javascript", javascript=False,
        )
    return f"{scripted}; {pressed}"


def drive_engine_phase(
    run: EngineRun, playwright: Playwright, runtime: Path, tls: ThrowawayTls,
    mapped_hosts: dict[str, int], host: Host, widths: tuple[Width, ...],
) -> None:
    run.proof.host = host
    chromium = launch_pinned_chromium(
        playwright, runtime, mapped_hosts, tls.leaf_spki_sha256_base64
    )
    try:
        for width in widths:
            run.proof.held_or_failed(
                f"SCENARIO 52 {width.label} {run.app_origin}",
                lambda width=width: logout_through_the_page(
                    run, chromium, width, f"52-{width.label}", javascript=False,
                ),
            )
    finally:
        chromium.close()
    phone = next(width for width in widths if width.touch)
    desktop = next(width for width in widths if not width.touch)
    engines = ((53, playwright.firefox, desktop), (54, playwright.webkit, phone))
    for number, engine, width in engines:
        run.proof.held_or_failed(
            f"SCENARIO {number} {width.label} {run.app_origin}",
            lambda number=number, engine=engine, width=width: other_engine(
                run, engine, mapped_hosts, width, number
            ),
        )
