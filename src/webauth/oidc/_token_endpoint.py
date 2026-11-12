"""The token endpoint's requests, its answers, the refusals it can cause, and the
readers that turn an answer into the tokens a login or a grant needs.

`OidcRelyingParty` posts a `TokenRequest` through an injected `TokenRequestPost`
and reads the `TokenEndpointAnswer` back; the readers here refuse an answer that
does not hold as `TOKEN_ENDPOINT_FAILED`. The module keeps no relying-party state.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from typing import TypeGuard

from pydantic import SecretStr

from webauth import WebAuthError
from webauth.https_client import ExchangeFailure
from webauth.jwt_verification import RejectionReason, _json_object

__all__ = [
    "OidcRefusal",
    "OidcRefusalReason",
    "TokenEndpointAnswer",
    "TokenEndpointError",
    "TokenRequest",
    "TokenRequestPost",
]

_MAX_TOKEN_RESPONSE_BYTES = 64 * 1024

# A strict subset of RFC 6749's error code characters: every registered code
# fits, and nothing that could carry markup or a sentence does.
_IDP_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# RFC 6749 Appendix A.17: refresh-token = 1*VSCHAR, printable ASCII.
_REFRESH_TOKEN = re.compile(r"[\x20-\x7e]+")
# RFC 6750 section 2.1: a bearer token is a b64token, so it can sit in an
# `Authorization` header without a CR, LF or space.
_ACCESS_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_BEARER_TOKEN_TYPE = "bearer"  # noqa: S105 - token type not a credential
_TOKEN_ERROR_STATUSES = frozenset({HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED})
# Keycloak refuses a token exchange its client may not make with 403 and `access_denied`.
_EXCHANGE_ERROR_STATUSES = _TOKEN_ERROR_STATUSES | {HTTPStatus.FORBIDDEN}
_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - grant type
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - token type


@dataclass(frozen=True)
class TokenRequest:
    """A form POST to the token endpoint, authenticated by `authorization`,
    the whole `Authorization` header value (client_secret_basic)."""

    url: str
    form: Mapping[str, str] = field(repr=False)
    authorization: SecretStr


@dataclass(frozen=True)
class TokenEndpointAnswer:
    status: int
    body: bytes = field(repr=False)


class TokenEndpointError(WebAuthError):
    """The token request did not reach an answer: refused, timed out, or broken off.

    `failure` names why, so a caller can tell a timeout from another transport
    failure without reading the message; it is `None` for an error raised
    without one."""

    def __init__(self, message: str, failure: ExchangeFailure | None = None) -> None:
        super().__init__(message)
        self.failure = failure


TokenRequestPost = Callable[[TokenRequest], TokenEndpointAnswer]
"""Posts the token request, raising `TokenEndpointError` when no answer arrives."""


class OidcRefusalReason(StrEnum):
    MALFORMED_CALLBACK = "malformed-callback"
    STATE_MISMATCH = "state-mismatch"
    PENDING_LOGIN_EXPIRED = "pending-login-expired"
    ISSUER_MISMATCH = "issuer-mismatch"
    AUTHORIZATION_DENIED = "authorization-denied"
    # A refusal reason, not a credential
    TOKEN_REQUEST_REFUSED = "token-request-refused"  # noqa: S105 - refusal reason not a credential
    TOKEN_ENDPOINT_FAILED = "token-endpoint-failed"  # noqa: S105 - refusal reason not a credential
    ID_TOKEN_REJECTED = "id-token-rejected"  # noqa: S105 - refusal reason not a credential
    NONCE_MISMATCH = "nonce-mismatch"
    AUTHORIZED_PARTY_MISMATCH = "authorized-party-mismatch"
    INVALID_IDENTITY_CLAIM = "invalid-identity-claim"
    LOGOUT_TOKEN_REJECTED = "logout-token-rejected"  # noqa: S105 - refusal reason not a credential
    INVALID_LOGOUT_CLAIM = "invalid-logout-claim"
    ACCESS_TOKEN_REJECTED = "access-token-rejected"  # noqa: S105 - refusal reason not a credential
    INVALID_ACCESS_CLAIM = "invalid-access-claim"
    INSUFFICIENT_SCOPE = "insufficient-scope"
    SUBJECT_MISMATCH = "subject-mismatch"
    STALE_ID_TOKEN = "stale-id-token"  # noqa: S105 - refusal reason not a credential


@dataclass(frozen=True)
class OidcRefusal:
    """Why a login or logout token does not stand. `idp_error` is the IdP's
    error code when it named a well-formed one; `token_rejection` is the
    verifier's reason when the ID token or logout token was rejected."""

    reason: OidcRefusalReason
    idp_error: str | None = None
    token_rejection: RejectionReason | None = None


class _RefusalError(Exception):
    def __init__(self, refusal: OidcRefusal) -> None:
        super().__init__(refusal.reason)
        self.refusal = refusal


def _idp_error_code(error: str) -> str | None:
    return error if _IDP_ERROR_CODE.fullmatch(error) else None


def _token_answer_document(body: bytes) -> Mapping[str, object]:
    """The answer's JSON object, or an empty one for an answer too large, not
    JSON, or not an object.

    The production transport refuses an oversize body first (`TOO_LARGE`); the
    size check here guards an injected `TokenRequestPost`, which may return any
    body."""
    if len(body) > _MAX_TOKEN_RESPONSE_BYTES:
        return {}
    return _json_object(body) or {}


def _is_refresh_token(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and _REFRESH_TOKEN.fullmatch(value) is not None


def _issued_refresh_token(document: Mapping[str, object]) -> SecretStr | None:
    if "refresh_token" not in document:
        return None
    refresh_token = document["refresh_token"]
    if not _is_refresh_token(refresh_token):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
    return SecretStr(refresh_token)


def _bearer_access_token(document: Mapping[str, object]) -> SecretStr:
    token_type = document.get("token_type")
    access_token = document.get("access_token")
    if (
        not isinstance(token_type, str)
        or not token_type.isascii()
        or token_type.lower() != _BEARER_TOKEN_TYPE
        or not isinstance(access_token, str)
        or not _ACCESS_TOKEN.fullmatch(access_token)
    ):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
    return SecretStr(access_token)


def _exchanged_lifetime_seconds(document: Mapping[str, object]) -> int:
    """The `expires_in` of an exchange's answer, which must be of the access-token type and
    carry a whole number of seconds of at least 1."""
    expires_in = document.get("expires_in")
    if (
        document.get("issued_token_type") != _ACCESS_TOKEN_TYPE
        or not isinstance(expires_in, int)
        or isinstance(expires_in, bool)
        or expires_in < 1
    ):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
    return expires_in


def _raw_id_token_of(document: Mapping[str, object]) -> str:
    id_token = document.get("id_token")
    if not isinstance(id_token, str):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
    return id_token
