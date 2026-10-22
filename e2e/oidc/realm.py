"""The realm the proof drives and the admin calls that shape it."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Any

from host_app import CALLBACK_PATH
from stack import Admin

REALM = "hallucinai"
LIFESPAN_ATTRIBUTE = "access.token.lifespan"


def create_user(admin: Admin, username: str, password: str, groups: tuple[str, ...]) -> str:
    user_id = admin.create(f"/{REALM}/users", {
        "username": username,
        "enabled": True,
        "email": f"{username}@d1.invalid",
        "emailVerified": True,
        "firstName": "D1",
        "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    })
    for path in groups:
        group = admin.get(f"/{REALM}/group-by-path{path}")
        admin.put(f"/{REALM}/users/{user_id}/groups/{group['id']}")
    return user_id


def client_representation(
    client_id: str, client_secret: str, origins: tuple[str, ...],
    backchannel_logout_url: str | None = None,
) -> dict[str, Any]:
    attributes = {"post.logout.redirect.uris": "##".join(f"{origin}/" for origin in origins)}
    if backchannel_logout_url is not None:
        attributes |= {
            "backchannel.logout.url": backchannel_logout_url,
            "backchannel.logout.session.required": "false",
            "backchannel.logout.revoke.offline.tokens": "false",
            "id.token.signed.response.alg": "RS256",
        }
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": False,
        "clientAuthenticatorType": "client-secret",
        "secret": client_secret,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "attributes": attributes,
        "redirectUris": [f"{origin}{CALLBACK_PATH}" for origin in origins],
        "defaultClientScopes": ["basic", "profile", "groups"],
    }


@contextlib.contextmanager
def short_lived_tokens(
    fresh_admin: Callable[[], Admin], client_uuid: str, seconds: int
) -> Iterator[None]:
    """The client `client_uuid` issues tokens that live `seconds`; its previous setting returns."""
    path = f"/{REALM}/clients/{client_uuid}"
    before = fresh_admin().get(path)
    previous = before["attributes"].get(LIFESPAN_ATTRIBUTE)
    try:
        fresh_admin().put(
            path,
            {**before, "attributes": {**before["attributes"], LIFESPAN_ATTRIBUTE: str(seconds)}},
        )
        yield
    finally:
        admin = fresh_admin()
        current = admin.get(path)
        attributes = {
            name: value for name, value in current["attributes"].items()
            if name != LIFESPAN_ATTRIBUTE
        }
        if previous is not None:
            attributes[LIFESPAN_ATTRIBUTE] = previous
        admin.put(path, {**current, "attributes": attributes})
