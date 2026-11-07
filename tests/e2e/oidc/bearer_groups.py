"""``current_groups`` at a real Keycloak: ``CHECK refreshed-id-token-facts`` and scenarios 73 to 76.

The check: hal's client mints with a nonce, refreshes, and reads the ID token's claims and its
groups; then a group is removed by the admin API and the next refresh must lack it. The
scenarios drive ``GET /current-groups`` of the bearer host with a signed-in person's cookie.

- 73 a member of a child group G of ``USER_GROUP``: the first call lists G, the group is removed
  by the admin API, the second call lacks it; ``/me`` still answers 200 and the host stored two
  refresh tokens. Only the group's disappearance counts, never ``iat``.
- 74 Keycloak's admin logout of the person: ``sign-in-again``, while ``/me`` answers 200.
- 75 the app's own logout, the cookie replayed: ``session-ended``.
- 76 no compact JWS in any answer of the route or in the host's log."""

from __future__ import annotations

import re
import ssl
import time
from typing import TYPE_CHECKING, Any

import httpx
from bearer_run import HAL, BearerRun, Call, Person, claims_of, session_cookies
from host_app import CURRENT_GROUPS_PATH
from realm import USER_GROUP, add_child_group, remove_from_group, user_id_of

if TYPE_CHECKING:
    from prove import Proof

CHECK_GROUP_NAME = "d1-check-group"
REVOKED_GROUP_NAME = "d1-revoked-group"
CHECK_SCOPE = "openid"
COMPACT_JWS = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def refresh(run: BearerRun, refresh_token: str) -> dict[str, str]:
    answer = httpx.post(
        run.settings.token_endpoint,
        data={"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": HAL},
        verify=ssl.create_default_context(cafile=str(run.ca_certificate)),
    )
    assert answer.status_code == 200, f"the refresh answered {answer.status_code}"
    return answer.json()


def refreshed_id_token_facts(run: BearerRun, person: Person, proof: Proof) -> str:
    admin = proof.fresh_admin()
    group_id = add_child_group(admin, CHECK_GROUP_NAME, person.username)
    group_path = f"{USER_GROUP}/{CHECK_GROUP_NAME}"
    nonce = f"nonce-{time.time_ns()}"
    minted = run.mint(person, HAL, CHECK_SCOPE, nonce=nonce)
    original = claims_of(minted["id_token"])
    assert original["nonce"] == nonce, "the minted ID token carries another nonce"
    assert group_path in original["groups"], "the minted ID token lacks the group"
    started = int(time.time())
    refreshed = refresh(run, minted["refresh_token"])
    assert "id_token" in refreshed, "a refresh reply holds no id_token"
    claims = claims_of(refreshed["id_token"])
    assert "nonce" not in claims, "the refreshed ID token carries a nonce key"
    assert claims["sub"] == original["sub"], "the refreshed sub differs"
    assert claims["aud"] == HAL, f"the refreshed aud is {claims['aud']!r}"
    assert claims["azp"] == original["azp"], "the refreshed azp differs"
    assert claims["iss"] == original["iss"], "the refreshed iss differs"
    assert claims["iat"] >= started, "the refreshed iat precedes the grant's start"
    assert claims["exp"] > claims["iat"], "the refreshed exp is not after iat"
    assert group_path in claims["groups"], "the refreshed ID token lacks the group"
    remove_from_group(proof.fresh_admin(), person.username, group_id)
    second = refresh(run, refreshed.get("refresh_token", minted["refresh_token"]))
    again = claims_of(second["id_token"])
    assert group_path not in again.get("groups", []), "the removed group is still listed"
    return (
        f"refreshed ID token: no nonce key, sub, aud, azp and iss as minted, iat-started="
        f"{claims['iat'] - started}s, rotated={'refresh_token' in refreshed}; "
        f"after removal the group is gone (groups claim has {len(again.get('groups', []))} paths)"
    )


def groups_answer(run: BearerRun, cookies: dict[str, str]) -> dict[str, Any]:
    answer = run.send(Call("GET", CURRENT_GROUPS_PATH, cookies=cookies))
    assert answer.status_code == 200, f"{CURRENT_GROUPS_PATH} answered {answer.status_code}"
    return answer.json()


def a_group_removed_between_two_calls_is_gone(run: BearerRun) -> str:
    """GROUPS-01, GROUPS-04: the second call answers the groups the issuer holds then."""
    person = run.people["grouped"]
    group_path = f"{USER_GROUP}/{REVOKED_GROUP_NAME}"
    group_id = add_child_group(run.proof.fresh_admin(), REVOKED_GROUP_NAME, person.username)
    page = run.sign_in_after_reset(person)
    cookies = session_cookies(page, run.settings.app_origins[0])
    first = groups_answer(run, cookies)
    assert first["outcome"] == "groups", first
    assert group_path in first["groups"], f"the first call lacks the group: {first}"
    remove_from_group(run.proof.fresh_admin(), person.username, group_id)
    second = groups_answer(run, cookies)
    assert second["outcome"] == "groups", second
    assert group_path not in second["groups"], f"the removed group is still listed: {second}"
    me = run.send(Call("GET", "/me", cookies=cookies))
    assert me.status_code == 200, f"/me answered {me.status_code}"
    assert second["refresh_tokens_stored"] == 2, second
    return "the group removed at Keycloak between two calls is gone from the second; /me 200"


def an_admin_logout_asks_to_sign_in_again(run: BearerRun) -> str:
    """GROUPS-07: a refresh token the issuer refuses as `invalid_grant` signs in again."""
    person = run.people["grouped"]
    cookies = session_cookies(run.sign_in_after_reset(person), run.settings.app_origins[0])
    run.proof.log_out_user_everywhere(user_id_of(run.proof.fresh_admin(), person.username))
    refused = groups_answer(run, cookies)
    assert refused["outcome"] == "sign-in-again", refused
    me = run.send(Call("GET", "/me", cookies=cookies))
    assert me.status_code == 200, f"/me answered {me.status_code}, the app session should stand"
    return "after Keycloak's admin logout the call answers sign-in-again while /me answers 200"


def the_apps_own_logout_ends_the_session(run: BearerRun) -> str:
    """GROUPS-06: a session the app ended answers `session-ended`."""
    origin = run.settings.app_origins[0]
    page = run.sign_in_after_reset(run.people["grouped"])
    cookies = session_cookies(page, origin)
    run.proof.press(page, "#logout")
    page.wait_for_url(f"{origin}/")
    ended = groups_answer(run, cookies)
    assert ended["outcome"] == "session-ended", ended
    return "after the app's own logout the replayed cookie answers session-ended"


def no_token_shows_in_an_answer_or_the_log(run: BearerRun) -> str:
    """GROUPS-03: no token is in an answer of the route or in the host log."""
    answers = [a for a in run.answers if a.url.path == CURRENT_GROUPS_PATH]
    assert answers, "no answer of the route was recorded"
    for answer in answers:
        shown = answer.text + repr(dict(answer.headers))
        assert COMPACT_JWS.search(shown) is None, "a compact JWS is in an answer"
    assert COMPACT_JWS.search(run.host.log_file.read_text()) is None, "a compact JWS is in the log"
    return f"no compact JWS in {len(answers)} answers of {CURRENT_GROUPS_PATH} or in the host log"
