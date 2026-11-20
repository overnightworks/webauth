"""The host's client configuration, read from the held issuer's own discovery document."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

from pydantic import SecretStr

from webauth.https_client import fetch_provider_metadata_over_https
from webauth.oidc import OidcClientConfig, discover_oidc_client_config

if TYPE_CHECKING:
    from host_app import HostSettings


def discovered_client_config(
    settings: HostSettings,
    redirect_uri: str,
    post_logout_redirect_uri: str,
    *,
    scopes: tuple[str, ...],
    leeway_seconds: int,
) -> OidcClientConfig:
    """The four endpoints are the issuer's document's. The host process cannot resolve the
    issuer's public name, so it reads the document, and calls the token and key-set endpoints,
    at the host of ``settings.token_endpoint``, a shim that forwards under the public host."""
    shim = urlsplit(settings.token_endpoint).netloc

    def through_the_shim(url: str) -> str:
        return urlunsplit(urlsplit(url)._replace(netloc=shim))

    discovered = discover_oidc_client_config(
        settings.issuer,
        fetch_provider_metadata=lambda url: fetch_provider_metadata_over_https(
            through_the_shim(url)
        ),
        client_id=settings.client_id,
        client_secret=SecretStr(settings.client_secret),
        redirect_uri=redirect_uri,
        post_logout_redirect_uri=post_logout_redirect_uri,
        scopes=scopes,
        leeway_seconds=leeway_seconds,
    )
    return dataclasses.replace(
        discovered,
        token_endpoint=through_the_shim(discovered.token_endpoint),
        jwks_url=through_the_shim(discovered.jwks_url),
    )
