"""The client configuration of one registration, read once from the issuer's metadata document."""

from __future__ import annotations

import json
from collections.abc import Callable

from pydantic import SecretStr

from webauth import WebAuthError
from webauth.oidc._authorization_url import CODE_CHALLENGE_METHOD
from webauth.oidc._client_config import OPENID_SCOPE, OidcClientConfig, require_endpoint_url

__all__ = ["OidcDiscoveryError", "ProviderMetadataFetch", "discover_oidc_client_config"]

ProviderMetadataFetch = Callable[[str], bytes]
"""Fetches the document at the URL whole, raising on any failure; an oversized
answer is the fetch's refusal."""

_WELL_KNOWN_PATH = "/.well-known/openid-configuration"
_ENDPOINT_MEMBERS = {
    "authorization_endpoint": "authorization_endpoint",
    "token_endpoint": "token_endpoint",
    "jwks_uri": "jwks_url",
    "end_session_endpoint": "end_session_endpoint",
}


class OidcDiscoveryError(WebAuthError):
    """The issuer's metadata document cannot make a client configuration. The message
    names the member at fault and never repeats the document's value."""


def discover_oidc_client_config(
    issuer: str,
    *,
    fetch_provider_metadata: ProviderMetadataFetch,
    client_id: str,
    client_secret: SecretStr,
    redirect_uri: str,
    post_logout_redirect_uri: str,
    scopes: tuple[str, ...] = (OPENID_SCOPE,),
    leeway_seconds: int,
) -> OidcClientConfig:
    """The `OidcClientConfig` of one client at `issuer`, its four endpoints read from
    the issuer's OpenID Connect Discovery 1.0 document.

    A host calls it once at startup and fails to start when it raises: the document
    decides where the client secret, the code and the PKCE verifier are sent, so
    nothing is read at login time and nothing is refreshed. The document is read at
    `issuer` with one trailing `/` removed (section 4.1); its `issuer` must equal
    `issuer` exactly (section 4.3). If it lists `code_challenge_methods_supported`,
    that list must hold `S256`, the one method the library sends.

    Raises the `ValueError` of `OidcClientConfig` for an issuer it refuses before any
    fetch, the fetch's own error when the document cannot be fetched,
    `OidcDiscoveryError` when it is not a JSON object or lacks or misstates a
    member, and the `ValueError` of `OidcClientConfig` for a URL or value it refuses."""
    require_endpoint_url("issuer", issuer)
    metadata = _parsed_object(
        fetch_provider_metadata(f"{issuer.removesuffix('/')}{_WELL_KNOWN_PATH}")
    )
    if metadata.get("issuer") != issuer:
        raise OidcDiscoveryError("the metadata document's issuer is not the configured issuer")
    _require_pkce_method(metadata)
    endpoints = {
        field_name: _string_member(metadata, member)
        for member, field_name in _ENDPOINT_MEMBERS.items()
    }
    return OidcClientConfig(
        issuer=issuer,
        **endpoints,
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        post_logout_redirect_uri=post_logout_redirect_uri,
        scopes=scopes,
        leeway_seconds=leeway_seconds,
    )


def _parsed_object(document: bytes) -> dict[str, object]:
    try:
        metadata = json.loads(document)
    except ValueError, RecursionError:
        metadata = None
    if not isinstance(metadata, dict):
        raise OidcDiscoveryError("the metadata document is not a JSON object") from None
    return metadata


def _string_member(metadata: dict[str, object], member: str) -> str:
    value = metadata.get(member)
    if not isinstance(value, str):
        raise OidcDiscoveryError(f"the metadata document's {member} is missing or not a string")
    return value


def _require_pkce_method(metadata: dict[str, object]) -> None:
    member = "code_challenge_methods_supported"
    if member not in metadata:
        return
    methods = metadata[member]
    if not isinstance(methods, list) or CODE_CHALLENGE_METHOD not in methods:
        raise OidcDiscoveryError(
            f"the metadata document's {member} does not list {CODE_CHALLENGE_METHOD}"
        )
