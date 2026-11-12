"""OpenID Connect login against one issuer; the public names of `webauth.oidc`."""

from __future__ import annotations

from webauth.oidc._client_config import OidcClientConfig
from webauth.oidc._relying_party import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    AuthorizationRequest,
    OidcIdentity,
    OidcRelyingParty,
    RenewedAccess,
    VerifiedAccessToken,
    VerifiedLogout,
)
from webauth.oidc._token_endpoint import (
    OidcRefusal,
    OidcRefusalReason,
    TokenEndpointAnswer,
    TokenEndpointError,
    TokenRequest,
    TokenRequestPost,
)

__all__ = [
    "PENDING_LOGIN_MAX_AGE_SECONDS",
    "AuthorizationRequest",
    "OidcClientConfig",
    "OidcIdentity",
    "OidcRefusal",
    "OidcRefusalReason",
    "OidcRelyingParty",
    "RenewedAccess",
    "TokenEndpointAnswer",
    "TokenEndpointError",
    "TokenRequest",
    "TokenRequestPost",
    "VerifiedAccessToken",
    "VerifiedLogout",
]
