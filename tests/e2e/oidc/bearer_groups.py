"""``CHECK refreshed-id-token-facts``: what Keycloak puts into the ID token of a refresh grant.

hal's client mints with a nonce, refreshes, and reads the ID token's claims and its groups;
then a group is removed by the admin API and the next refresh must lack it."""

from __future__ import annotations

import ssl
import time
from typing import TYPE_CHECKING

import httpx
from bearer_run import HAL, BearerRun, Person, claims_of
from host_app import LEEWAY_SECONDS
from realm import REALM, USER_GROUP, add_child_group, remove_from_group

if TYPE_CHECKING:
    from prove import Proof

CHECK_GROUP_NAME = "d1-check-group"
CHECK_SCOPE = "openid"


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
    assert claims.get("nonce") == nonce, f"the refreshed nonce is {claims.get('nonce')!r}"
    assert claims["sub"] == original["sub"], "the refreshed sub differs"
    assert claims["aud"] == HAL, f"the refreshed aud is {claims['aud']!r}"
    assert claims["azp"] == original["azp"], "the refreshed azp differs"
    assert claims["iss"] == original["iss"], "the refreshed iss differs"
    assert claims["iat"] >= started - LEEWAY_SECONDS, "the refreshed iat precedes the grant"
    assert claims["exp"] > claims["iat"], "the refreshed exp is not after iat"
    assert group_path in claims["groups"], "the refreshed ID token lacks the group"
    remove_from_group(proof.fresh_admin(), person.username, group_id)
    second = refresh(run, refreshed.get("refresh_token", minted["refresh_token"]))
    again = claims_of(second["id_token"])
    assert group_path not in again.get("groups", []), "the removed group is still listed"
    return (
        f"refreshed ID token: nonce equal, sub, aud, azp and iss as minted, iat-started="
        f"{claims['iat'] - started}s, rotated={'refresh_token' in refreshed}; "
        f"after removal the group is gone (groups claim has {len(again.get('groups', []))} paths); "
        f"realm {REALM}"
    )
