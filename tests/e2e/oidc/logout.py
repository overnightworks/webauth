"""The logout and session scenarios of the browser proof: 2, 5, 9, 10 to 15, 17 and 21 to 23, and
the logout steps every logout scenario shares (``prove.py`` states each).

Scenario 10 ends every session of one subject, 11 ends the sessions of a second app, 12 is the
admin logout and 13 disables an account and then logs it out everywhere (``prove.py``'s
docstring states each). They run against the two back-channel apps of ``run_proof`` and print
``SCENARIO <number> <width> <origin>``. ``log_out_through_keycloak`` is the one logout step of
every logout scenario of ``prove.py``, and the callback assertions wait for Keycloak's
back-channel logout to reach an app.
"""

from __future__ import annotations

import base64
import json
import ssl
import time
import urllib.parse
from collections.abc import Callable
from typing import Any

import httpx
from harness import (
    Finding,
    cookie_name_and_value,
)
from host_app import (
    CALLBACK_PATH,
    LOGOUT_PATH,
)
from playwright.sync_api import (
    Cookie,
    Page,
    Request,
    Response,
    Route,
)
from proof import (
    APP_HOST,
    APP_ORIGIN,
    EXPIRY_MARGIN_SECONDS,
    SECOND_APP_ORIGIN,
    SHORT_TOKEN_LIFESPAN_SECONDS,
    App,
    Proof,
    Width,
    app_cookies,
    jws_cookies,
)
from realm import (
    DISABLED_USER_NAME,
    END_SESSION_ENDPOINT,
    KEYCLOAK_DISABLED_MESSAGE,
    KEYCLOAK_LOGOUT_CONFIRMATION,
    USER_NAME,
    short_lived_tokens,
)

from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
    CookieSameSite,
    _is_pending_login_cookie_name,
    _pending_login_cookie_prefix,
)

CALLBACK_WAIT_SECONDS = 15
CALLBACK_POLL_SECONDS = 0.2


def confirm_at_keycloak(proof: Proof, page: Page, scenario: str) -> None:
    page.locator(KEYCLOAK_LOGOUT_CONFIRMATION).wait_for()
    proof.assert_fits(page, KEYCLOAK_LOGOUT_CONFIRMATION)
    proof.shot(page, scenario, "logout-confirmation")


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
        accepted,
        0,
        sessions,
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
    proof: Proof,
    page: Page,
    scenario: str,
    origin: str,
    at_end_session: Callable[[Request], None] | None = None,
    *,
    asks_for_confirmation: bool = False,
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


def cookie_names(request: Request) -> list[str]:
    return [
        pair.split("=", 1)[0].strip()
        for header in request.headers_array()
        if header["name"].lower() == "cookie"
        for pair in header["value"].split(";")
        if pair.strip()
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
            _is_pending_login_cookie_name(name, secure=True) for name in cookie_names(callback)
        ), "the callback carried no pending-login cookie; request cookies are not measured"
        names = [recorded_cookie_name(name) for name in cookie_names(landing)]
        site = raw_header(landing, "sec-fetch-site")
        headline = proof.headline(page)
        proof.shot(page, scenario, "first-page")
    observed = f"first page showed {headline!r}; cookie names sent {names}; Sec-Fetch-Site {site}"
    if headline != f"Signed in as {USER_NAME}":
        raise Finding(observed)
    return observed


def test_logout(proof: Proof, width: Width) -> str:
    """REFUSE-23, APP-26, APP-28, APP-31, APP-34: logout ends the session and clears cookies."""
    scenario = f"2-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in(proof, page, scenario)
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


def test_logout_after_the_app_session_ended(proof: Proof, width: Width) -> str:
    """APP-36, APP-37: with the app session gone the logout sends no hint and Keycloak asks."""
    scenario = f"9-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        signed_in(proof, page, scenario)
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


CROSS_SITE_LOGOUT_PATH = "/cross-site-logout"
CROSS_ORIGIN_REFUSAL = "Cross-origin request rejected"


def cross_site_logout_page(target_origin: str) -> str:
    return (
        '<!doctype html><html><head><meta charset="utf-8"><title>another site</title></head>'
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
