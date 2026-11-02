"""OpenID Connect login against one issuer; the public names of `webauth.oidc`."""

from __future__ import annotations

from webauth.oidc._client_config import OidcClientConfig
from webauth.oidc._relying_party import (
    LOGOUT_TOKEN_MAX_AGE_SECONDS,
    MAX_AUTHORIZATION_CODE_CHARS,
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    AuthorizationRequest,
    OidcIdentity,
    OidcRefusal,
    OidcRefusalReason,
    OidcRelyingParty,
    RenewedAccess,
    TokenEndpointAnswer,
    TokenEndpointError,
    TokenRequest,
    TokenRequestPost,
    VerifiedAccessToken,
    VerifiedLogout,
)

__all__ = [
    "MAX_AUTHORIZATION_CODE_CHARS",
    "MAX_TOKEN_RESPONSE_BYTES",
    "LOGOUT_TOKEN_MAX_AGE_SECONDS",
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
