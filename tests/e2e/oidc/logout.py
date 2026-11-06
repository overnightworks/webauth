"""Proves the logout across sessions and apps: scenarios 10 to 13 and the steps every logout
scenario shares.

Scenario 10 ends every session of one subject, 11 ends the sessions of a second app, 12 is the
admin logout and 13 disables an account and then logs it out everywhere (``prove.py``'s
docstring states each). They run against the two back-channel apps of ``run_proof`` and print
``SCENARIO <number> <width> <origin>``. ``log_out_through_keycloak`` is the one logout step of
every logout scenario of ``prove.py``, and the callback assertions wait for Keycloak's
back-channel logout to reach an app.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING

from playwright.sync_api import Page, Request, Response, Route
from realm import (
    DISABLED_USER_NAME,
    END_SESSION_ENDPOINT,
    KEYCLOAK_DISABLED_MESSAGE,
    KEYCLOAK_LOGOUT_CONFIRMATION,
    USER_NAME,
)

if TYPE_CHECKING:
    from prove import App, Proof, Width

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
