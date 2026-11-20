"""The discovery document an issuer publishes, and a JSON document of a chosen size."""

from __future__ import annotations

import json
from typing import Any

ABSENT = object()
"""A member change that removes the member instead of setting it."""

OPENID_CONNECT_PATH = "/protocol/openid-connect"
METADATA_LIMIT_BYTES = 64 * 1024


def a_provider_metadata(realm_issuer: str, /, **changes: Any) -> bytes:
    """The discovery document of the realm at `realm_issuer` as Keycloak serves it: the members
    the relying party reads, `code_challenge_methods_supported` and
    `authorization_response_iss_parameter_supported`; `changes` replace or,
    with `ABSENT`, remove members."""
    members = {
        "issuer": realm_issuer,
        "authorization_endpoint": f"{realm_issuer}{OPENID_CONNECT_PATH}/auth",
        "token_endpoint": f"{realm_issuer}{OPENID_CONNECT_PATH}/token",
        "jwks_uri": f"{realm_issuer}{OPENID_CONNECT_PATH}/certs",
        "end_session_endpoint": f"{realm_issuer}{OPENID_CONNECT_PATH}/logout",
        "code_challenge_methods_supported": ["plain", "S256"],
        "authorization_response_iss_parameter_supported": True,
        **changes,
    }
    return json.dumps(
        {name: value for name, value in members.items() if value is not ABSENT}
    ).encode()


def a_json_object_of_bytes(size: int) -> bytes:
    """A valid JSON object of exactly `size` bytes."""
    frame = len(json.dumps({"padding": ""}))
    return json.dumps({"padding": "a" * (size - frame)}).encode()
