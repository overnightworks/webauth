"""The realm the proof drives and the admin calls that shape it."""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from typing import Any

from certificates import ThrowawayTls
from harness import free_port
from host_app import CALLBACK_PATH, HostSettings
from stack import Admin

from webauth.cookies import CookieSameSite

REALM = "hallucinai"
IDP_HOST = "auth.hallucinai.de"
ISSUER = f"https://{IDP_HOST}/realms/{REALM}"
OIDC_PATH = f"{ISSUER}/protocol/openid-connect"
END_SESSION_ENDPOINT = f"{OIDC_PATH}/logout"
CLIENT_ID = "d1-host"
USER_NAME = "d1-user"
USER_GROUP = "/apps/songmaker"
OUTSIDER_NAME = "d1-outsider"
ADMIN_NAME = "d1-admin"
ADMIN_GROUP = f"{USER_GROUP}/admin"
LIFESPAN_ATTRIBUTE = "access.token.lifespan"
ACCESS_TOKEN_TYPE_ATTRIBUTE = "access.token.header.type.rfc9068"  # noqa: S105  # an attribute name


def host_settings(
    tls: ThrowawayTls, shim_port: int, app_origins: tuple[str, ...], client_id: str,
    client_secret: str, session_secret: str, cookie_samesite: CookieSameSite,
) -> HostSettings:
    return HostSettings(
        app_origins=app_origins,
        port=free_port(),
        observe_port=free_port(),
        tls_certificate=str(tls.leaf_certificate),
        tls_key=str(tls.leaf_key),
        issuer=ISSUER,
        login_group=USER_GROUP,
        admin_group=ADMIN_GROUP,
        authorization_endpoint=f"{OIDC_PATH}/auth",
        end_session_endpoint=END_SESSION_ENDPOINT,
        token_endpoint=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/token",
        jwks_url=f"https://localhost:{shim_port}/realms/{REALM}/protocol/openid-connect/certs",
        client_id=client_id,
        client_secret=client_secret,
        session_secret=session_secret,
        cookie_samesite=cookie_samesite,
    )


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


def public_client_representation(
    client_id: str, redirect_uri: str, optional_scopes: tuple[str, ...]
) -> dict[str, Any]:
    """A public client with PKCE whose access tokens carry the ``at+jwt`` header type."""
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "attributes": {
            "pkce.code.challenge.method": "S256",
            ACCESS_TOKEN_TYPE_ATTRIBUTE: "true",
        },
        "redirectUris": [redirect_uri],
        "defaultClientScopes": ["basic", "groups"],
        "optionalClientScopes": list(optional_scopes),
    }


def audience_scope_representation(name: str, audience: str) -> dict[str, Any]:
    """A client scope that adds the client ``audience`` to the access token's ``aud``."""
    return {
        "name": name,
        "protocol": "openid-connect",
        "attributes": {
            "include.in.token.scope": "false",
            "display.on.consent.screen": "false",
        },
        "protocolMappers": [{
            "name": name,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": audience,
                "id.token.claim": "false",
                "access.token.claim": "true",
                "userinfo.token.claim": "false",
                "introspection.token.claim": "true",
            },
        }],
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
