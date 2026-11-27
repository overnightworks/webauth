"""The token and refresh scenarios of the browser proof: 25 to 27 (``prove.py`` states each)."""

from __future__ import annotations

from typing import Any

from harness import (
    cookie_name_and_value,
)
from host_app import (
    ACCESS_TOKEN_PATH,
    WORKLOAD_TOKEN_PATH,
)
from logout import (
    host_answer,
    log_out_through_keycloak,
    sent_hint,
)
from playwright.sync_api import (
    Cookie,
    Page,
)
from proof import (
    APP_ORIGIN,
    Proof,
    Width,
    app_cookies,
)

from webauth.cookies import (
    DEFAULT_SESSION_COOKIE_NAME,
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
        "outcome": "token-request-refused",
        "issuer_error": "unauthorized_client",
    }, f"the workload call answered {refused}"
    return (
        f"the probe's client, created with serviceAccountsEnabled false, was refused its "
        f"client_credentials grant: {refused['outcome']} with {refused['issuer_error']}"
    )
