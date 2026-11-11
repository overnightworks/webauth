"""The authorization request's URL: the parameters of OpenID Connect Core section 3.1.2.1 and
PKCE, encoded together so no value can add a parameter of its own."""

from __future__ import annotations

import base64
import hashlib
import urllib.parse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from webauth.cookies import PendingLogin
    from webauth.oidc._client_config import OidcClientConfig

__all__ = ["authorization_url"]


def authorization_url(config: OidcClientConfig, pending: PendingLogin) -> str:
    """The issuer's authorization endpoint with the query that begins ``pending``."""
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_uri,
            "scope": " ".join(config.scopes),
            "state": pending.state,
            "nonce": pending.nonce,
            "code_challenge": _s256_code_challenge(pending.code_verifier),
            "code_challenge_method": "S256",
        }
    )
    return f"{config.authorization_endpoint}?{query}"


def _s256_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
