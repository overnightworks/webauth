"""The sign-in scenarios of the browser proof: 1, 4, 6 to 8 and 24 (``prove.py`` states each)."""

from __future__ import annotations

import json
import re
import secrets
import urllib.parse

from harness import (
    cookie_name_and_value,
)
from proof import (
    APP_ORIGIN,
    UNTRUSTED_HOST,
    Proof,
    Width,
    app_cookies,
    jws_cookies,
)
from realm import (
    ADMIN_GROUP,
    ADMIN_NAME,
    DISABLED_USER_NAME,
    IDP_HOST,
    ISSUER,
    KEYCLOAK_DISABLED_MESSAGE,
    OUTSIDER_NAME,
    REALM,
    USER_NAME,
)

from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
)


def issuer_document_is_canonical(proof: Proof) -> str:
    with proof.browsing() as page:
        page.goto(url := f"{ISSUER}/.well-known/openid-configuration")
        document = json.loads(page.inner_text("body"))
        assert (page.url, document["issuer"]) == (url, ISSUER), "the URL moved or another issuer"
        assert document.get("authorization_response_iss_parameter_supported"), "iss unannounced"
    return f"{ISSUER} answered under its canonical URL, names itself as the issuer, announces iss"


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
        proof.fill_keycloak_form(page, scenario, proof.disabled_user_password, DISABLED_USER_NAME)
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
            page,
            f"{scenario}-enabled",
            username=DISABLED_USER_NAME,
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


def test_outsider_is_refused(proof: Proof, width: Width) -> str:
    """REFUSE-28: a person outside the app signs in at Keycloak and is refused with no session."""
    scenario = f"7-{width.label}"
    proof.reset_host()
    with proof.browsing(width) as page:
        proof.sign_in(page, scenario, username=OUTSIDER_NAME, password=proof.outsider_password)
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


def test_deep_link_survives_the_login(proof: Proof, width: Width) -> str:
    """REFUSE-01, REFUSE-02: the page asked for without a session is returned to."""
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
