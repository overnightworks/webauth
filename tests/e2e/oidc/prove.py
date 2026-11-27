"""Proves login and logout of a webauth host in a real browser against a real Keycloak.

    scripts/run_oidc_proof.sh prove --platform PATH

``docs/runbooks/run-the-browser-proof.md`` is the runbook. Nothing of the OIDC path is faked:
the browser fills Keycloak's own form, the host's library talks to the real
token and key-set endpoints, and the only seams are the connection routing and
the one throwaway certificate key the browser is told to accept.

The host application is ``build_app`` in ``host_app.py``. The sign-in scenarios live in
``login.py``, the logout and session scenarios in ``logout.py`` and the token and refresh
scenarios in ``tokens.py``. The scenarios below
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
route (the body-size, cache-control and CSRF exemptions ``build_app`` sets; a rate
limit whose budgets the proof cannot exhaust). Each client carries ``frontchannelLogout: false``,
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
- Scenario 22, a logout from another site (proves a sentence of the ``webauth.sign_in_routes``
  module docstring): the browser holds a signed-in session at app A. A page on
  ``https://demo.example.test``, which the harness fulfils in the browser (the hosts' policies
  would not let a served page post across origins), submits a form to A's ``/logout``. A
  answers 403 ``Cross-origin request rejected`` from the origin check; ``/`` still says signed
  in, ``/me`` answers 200, the host holds 1 session. The person's own logout then ends the
  session with no page.
- Scenario 23, a logout after the back-channel logout ended the row (proves a sentence of the
  ``webauth.sign_in_routes`` module docstring): a person signs in to A (Keycloak session S1),
  Keycloak's admin logout ends S1 (A's back-channel call ends A's row), a sign-in to B in the
  same browser opens S2, and A's page, still showing its button, posts the logout, which sends
  no hint. Keycloak asks "Do you want to log out?" (status 200 and ``#kc-logout``), as the
  docstring says; after confirming, it ends S2 and calls B back.

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
proven at the admission layer, not here (scenario 73 of ``bearer_groups`` removes a
person from a group, but not from the admin one), and a successful workload token is not
proven (scenario 27 proves only the refusal)."""
# ruff: noqa: T201 - the proof prints its scenario table for the operator

from __future__ import annotations

import argparse
import contextlib
import secrets
import signal
import sys
import urllib.parse
from collections.abc import Iterator
from pathlib import Path

from bearer import drive_bearer_phase
from certificates import ThrowawayTls, issue_throwaway_tls
from engines import EngineRun, test_drive_engine_phase
from harness import (
    STOP_SIGNALS,
    Host,
    Interrupted,
    drive_browser_off_the_main_thread,
    keep_results,
    launch_pinned_chromium,
    leftovers,
    runtime_directory,
    start_host,
    stop_host,
    stop_on_first_signal,
)
from login import (
    disabled_user_is_refused,
    issuer_document_is_canonical,
    login,
    outsiders_groups_claim_is_recorded,
    pages_fit_the_window,
    subgroup_member_is_admitted,
    test_deep_link_survives_the_login,
    test_outsider_is_refused,
    untrusted_certificate_is_refused,
)
from logout import (
    admin_logout_ends_the_sessions_in_every_app,
    disabled_account_is_logged_out_everywhere,
    logout_after_the_back_channel_logout_ended_the_row,
    logout_after_the_id_token_expired,
    logout_ends_every_session_of_the_subject,
    logout_from_a_page_of_another_site_is_refused,
    logout_in_one_app_ends_the_sessions_of_the_other,
    logout_on_the_cross_site_origin,
    second_login_and_logout_show_no_page,
    session_cookie_after_redirect,
    test_logout,
    test_logout_after_the_app_session_ended,
    the_browser_holds_no_id_token,
)
from playwright.sync_api import (
    Playwright,
    sync_playwright,
)
from proof import (
    APP_HOST,
    APP_ORIGIN,
    BACKCHANNEL_APPS,
    DESKTOP,
    SAMESITE_VALUES,
    SECOND_APP_HOST,
    SECOND_APP_ORIGIN,
    SHIPPED_COOKIE_SAMESITE,
    UNTRUSTED_HOST,
    WIDTHS,
    App,
    Proof,
)
from realm import (
    ADMIN_GROUP,
    ADMIN_NAME,
    CLIENT_ID,
    DISABLED_USER_NAME,
    IDP_HOST,
    KEYCLOAK_LOGOUT_CONFIRMATION,
    OUTSIDER_NAME,
    REALM,
    USER_GROUP,
    USER_NAME,
    client_representation,
    create_user,
    host_settings,
)
from shim import CallbackBridge, TlsShim, relay_name_prefix
from stack import HOLD_SCRATCH_NAME, Admin, HeldStack, require_pinned_clean_platform
from tokens import (
    a_client_without_service_account_is_refused_its_workload_token,
    a_person_ended_at_the_issuer_signs_in_again,
    keycloak_rotates_the_refresh_token,
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
    with contextlib.ExitStack() as running:
        apps: list[App] = []
        for configuration in BACKCHANNEL_APPS:
            client_secret = secrets.token_urlsafe(24)
            session_secret = secrets.token_urlsafe(48)
            settings = host_settings(
                tls,
                shim_port,
                (configuration.origin,),
                configuration.client_id,
                client_secret,
                session_secret,
                configuration.cookie_samesite,
            )
            host = start_host(proof, runtime, settings, tls.ca_certificate)
            running.callback(stop_host, host.process)
            bridge = running.enter_context(
                CallbackBridge(proof.stack, host.app_port, tls.ca_certificate)
            )
            proof.fresh_admin().create(
                f"/{REALM}/clients",
                client_representation(
                    configuration.client_id,
                    client_secret,
                    (configuration.origin,),
                    bridge.url,
                ),
            )
            apps.append(App(configuration, host, client_secret))
        yield tuple(apps)


def run_proof(proof: Proof, platform: Path, runtime: Path) -> None:
    proof.session_secret = secrets.token_urlsafe(48)
    proof.user_password = secrets.token_urlsafe(18)
    proof.client_secret = secrets.token_urlsafe(24)
    proof.disabled_user_password = secrets.token_urlsafe(18)
    proof.outsider_password = secrets.token_urlsafe(18)
    proof.admin_password = secrets.token_urlsafe(18)
    tls = issue_throwaway_tls(runtime, "good", [IDP_HOST, APP_HOST, SECOND_APP_HOST, "localhost"])
    untrusted = issue_throwaway_tls(runtime, "untrusted", [UNTRUSTED_HOST])
    with HeldStack(platform, runtime / HOLD_SCRATCH_NAME) as stack:
        proof.stack = stack
        admin = stack.admin()
        prepare_keycloak(admin, proof, proof.client_secret)
        edge_port = urllib.parse.urlsplit(stack.edge_url).port
        assert edge_port is not None
        with (
            TlsShim(tls, edge_port, IDP_HOST) as shim,
            TlsShim(untrusted, edge_port, IDP_HOST) as untrusted_shim,
        ):
            hosts: list[Host] = []
            proof.ca_certificate = tls.ca_certificate
            try:
                for cookie_samesite in SAMESITE_VALUES:
                    settings = host_settings(
                        tls,
                        shim.port,
                        (APP_ORIGIN, SECOND_APP_ORIGIN),
                        CLIENT_ID,
                        proof.client_secret,
                        proof.session_secret,
                        cookie_samesite,
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


def drive_browser(
    proof: Proof,
    runtime: Path,
    tls: ThrowawayTls,
    shim_port: int,
    untrusted_port: int,
    hosts: list[Host],
) -> None:
    with sync_playwright() as playwright:
        for host in hosts:
            if not drive_host_scenarios(
                proof, playwright, runtime, tls, shim_port, untrusted_port, host
            ):
                return
        default_host = next(h for h in hosts if h.cookie_samesite == SHIPPED_COOKIE_SAMESITE)
        test_drive_engine_phase(
            EngineRun(proof, APP_ORIGIN, KEYCLOAK_LOGOUT_CONFIRMATION),
            playwright,
            runtime,
            tls,
            {IDP_HOST: shim_port, APP_HOST: default_host.app_port},
            default_host,
            WIDTHS,
        )
        drive_backchannel_phase(proof, playwright, runtime, tls, shim_port, untrusted_port)
        drive_bearer_phase(
            proof,
            playwright,
            runtime,
            tls,
            shim_port,
            host_settings(
                tls,
                shim_port,
                (APP_ORIGIN,),
                CLIENT_ID,
                proof.client_secret,
                secrets.token_urlsafe(48),
                SHIPPED_COOKIE_SAMESITE,
            ),
        )


def drive_host_scenarios(
    proof: Proof,
    playwright: Playwright,
    runtime: Path,
    tls: ThrowawayTls,
    shim_port: int,
    untrusted_port: int,
    host: Host,
) -> bool:
    """One host in its own Chromium: the default scenarios where the host has the shipped cookie
    policy, and scenario 5 for both origins; False when the default scenarios stopped the run."""
    proof.host = host
    proof.browser = launch_pinned_chromium(
        playwright,
        runtime,
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
            return False
        for origin in (APP_ORIGIN, SECOND_APP_ORIGIN):
            proof.held_or_failed(
                f"SCENARIO 5 {origin} {host.cookie_samesite}",
                lambda origin=origin, samesite=host.cookie_samesite: session_cookie_after_redirect(
                    proof, origin, samesite
                ),
            )
        return True
    finally:
        proof.browser.close()


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


BACKCHANNEL_DESKTOP_SCENARIOS = (
    (22, logout_from_a_page_of_another_site_is_refused),
    (23, logout_after_the_back_channel_logout_ended_the_row),
)


def drive_backchannel_phase(
    proof: Proof,
    playwright: Playwright,
    runtime: Path,
    tls: ThrowawayTls,
    shim_port: int,
    untrusted_port: int,
) -> None:
    """The apps are two hosts; the browser reaches each on its own origin."""
    app_a, app_b = proof.apps
    proof.browser = launch_pinned_chromium(
        playwright,
        runtime,
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
    (1, login),
    (2, test_logout),
    (4, disabled_user_is_refused),
    (6, pages_fit_the_window),
    (7, test_outsider_is_refused),
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
        lambda: test_logout_after_the_app_session_ended(proof, DESKTOP),
    )
    proof.held_or_failed(
        f"SCENARIO 24 {DESKTOP.label} {APP_ORIGIN}",
        lambda: test_deep_link_survives_the_login(proof, DESKTOP),
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


def prove(platform: Path, scratch: Path) -> int:
    if scratch.exists() and any(scratch.iterdir()):
        print(f"FAILED: --scratch {scratch} is not empty")
        return 2
    evidence_dir = scratch / "evidence"
    evidence_dir.mkdir(parents=True)
    proof = Proof(evidence_dir)
    stop_on_first_signal(proof)
    try:
        require_pinned_clean_platform(platform)
        with runtime_directory(scratch) as runtime:
            run_proof(proof, platform, runtime)
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
        relay_prefix = relay_name_prefix(proof.stack) if proof.stack else None
        for left in leftovers(scratch, relay_prefix):
            proof.fail(left)
    return max(0 if proof.all_held else 1, keep_results(proof))


def main() -> int:
    if not __debug__:
        raise SystemExit("prove.py checks with assert; run it without python -O")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--platform", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    arguments = parser.parse_args()
    return prove(arguments.platform.resolve(), arguments.scratch.resolve())


if __name__ == "__main__":
    sys.exit(main())
