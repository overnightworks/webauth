"""OpenID Connect login against one issuer: the authorization-code flow with PKCE.

`OidcRelyingParty.begin_login` answers the URL a browser is sent to and the
`PendingLogin` the host keeps until the browser returns. `complete_login` takes
that pending login and the raw query of the callback and answers a verified
`OidcIdentity`, or an `OidcRefusal` naming why the login does not stand.

The callback is judged in a fixed order. Its state comes first, so a forged
callback is refused as such even when it also reports an error; then the
RFC 9207 `iss` parameter, when the issuer sends one; only then the IdP's own
`error`, of which nothing but a short error code is carried — never its
`error_description`, which is text the IdP's caller controls. The code is
exchanged with the PKCE verifier over the injected `TokenRequestPost`, the
client authenticating with HTTP Basic. The ID token is verified by a
`JwtVerifier` of `webauth.jwt_verification` whose one accepted audience is the
client ID; its nonce and authorized party are checked here, as OpenID Connect
Core asks of the relying party.

The state, nonce and verifier are each 32 random bytes, and the received state
and nonce are compared in constant time. The client secret enters only through
`OidcClientConfig`; it, the code and the verifier stay out of every repr and
message this module writes.

Install the `jwt` extra to use this module.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from types import MappingProxyType

from pydantic import SecretStr

from webauth.jwt_verification import (
    JwtVerifier,
    KeySetFetch,
    MonotonicClock,
    Rejected,
    RejectionReason,
    VerifiedClaims,
    WallClock,
    is_https_url,
)

MAX_TOKEN_RESPONSE_BYTES = 64 * 1024

_OPENID_SCOPE = "openid"
_RANDOM_BYTES = 32
# RFC 6749 section 3.3: a scope token is one or more printable ASCII
# characters other than space, `"` and `\`.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")
# A strict subset of RFC 6749's error code characters: every registered code
# fits, and nothing that could carry markup or a sentence does.
_IDP_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_TOKEN_ERROR_STATUSES = frozenset({HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED})
_URL_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_url", "redirect_uri")


@dataclass(frozen=True, kw_only=True)
class OidcClientConfig:
    """One client registered at one issuer.

    Every URL is https, names a host and carries no control character, space,
    credentials, query or fragment; `scopes` includes `openid`. `leeway_seconds`
    is checked by the `JwtVerifier` the relying party builds from it."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    client_id: str
    client_secret: SecretStr
    redirect_uri: str
    scopes: tuple[str, ...] = (_OPENID_SCOPE,)
    leeway_seconds: int

    def __post_init__(self) -> None:
        for name in _URL_FIELDS:
            if not _is_endpoint_url(getattr(self, name)):
                raise ValueError(
                    f"{name} must be an https URL naming a host, a valid port if any,"
                    " and no control character, space, credentials, query or fragment"
                )
        if not isinstance(self.client_id, str) or not self.client_id:
            raise ValueError("client_id must be a non-empty string")
        if (
            not isinstance(self.client_secret, SecretStr)
            or not self.client_secret.get_secret_value()
        ):
            raise ValueError("client_secret must be a non-empty SecretStr")
        if not _is_scope_list_with_openid(self.scopes):
            raise ValueError("scopes must be a tuple of scope tokens that includes openid")


@dataclass(frozen=True)
class PendingLogin:
    """What the host keeps between sending the browser away and its return."""

    state: str = field(repr=False)
    nonce: str = field(repr=False)
    code_verifier: str = field(repr=False)


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    pending: PendingLogin


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


class TokenEndpointError(Exception):
    """The token request did not reach an answer: refused, timed out, or broken off."""


TokenRequestPost = Callable[[TokenRequest], TokenEndpointAnswer]
"""Posts the token request, raising `TokenEndpointError` when no answer arrives."""


class OidcRefusalReason(StrEnum):
    MALFORMED_CALLBACK = "malformed-callback"
    STATE_MISMATCH = "state-mismatch"
    ISSUER_MISMATCH = "issuer-mismatch"
    AUTHORIZATION_DENIED = "authorization-denied"
    TOKEN_REQUEST_REFUSED = "token-request-refused"
    TOKEN_ENDPOINT_FAILED = "token-endpoint-failed"
    ID_TOKEN_REJECTED = "id-token-rejected"
    NONCE_MISMATCH = "nonce-mismatch"
    AUTHORIZED_PARTY_MISMATCH = "authorized-party-mismatch"
    INVALID_IDENTITY_CLAIM = "invalid-identity-claim"


@dataclass(frozen=True)
class OidcRefusal:
    """Why a login does not stand. `idp_error` is the IdP's error code when it
    named a well-formed one; `token_rejection` is the verifier's reason when
    the ID token was rejected."""

    reason: OidcRefusalReason
    idp_error: str | None = None
    token_rejection: RejectionReason | None = None


@dataclass(frozen=True)
class OidcIdentity:
    """The person the issuer vouched for. `groups` are the issuer's full group
    paths, uninterpreted; `session_id` is the issuer's `sid`."""

    subject: str
    issuer: str
    groups: tuple[str, ...]
    session_id: str | None
    preferred_username: str | None


class _RefusalError(Exception):
    def __init__(self, refusal: OidcRefusal) -> None:
        super().__init__(refusal.reason)
        self.refusal = refusal


class OidcRelyingParty:
    """Logs people in at one issuer for one client."""

    def __init__(
        self,
        config: OidcClientConfig,
        *,
        post_token_request: TokenRequestPost,
        fetch_key_set: KeySetFetch,
        wall_clock: WallClock,
        monotonic_clock: MonotonicClock,
    ) -> None:
        self._config = config
        self._post_token_request = post_token_request
        self._client_authorization = _basic_authorization(config.client_id, config.client_secret)
        self._id_token_verifier = JwtVerifier(
            issuer=config.issuer,
            audiences=[config.client_id],
            jwks_url=config.jwks_url,
            leeway_seconds=config.leeway_seconds,
            fetch_key_set=fetch_key_set,
            wall_clock=wall_clock,
            monotonic_clock=monotonic_clock,
        )

    def begin_login(self) -> AuthorizationRequest:
        pending = PendingLogin(
            state=secrets.token_urlsafe(_RANDOM_BYTES),
            nonce=secrets.token_urlsafe(_RANDOM_BYTES),
            code_verifier=secrets.token_urlsafe(_RANDOM_BYTES),
        )
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self._config.client_id,
                "redirect_uri": self._config.redirect_uri,
                "scope": " ".join(self._config.scopes),
                "state": pending.state,
                "nonce": pending.nonce,
                "code_challenge": _s256_code_challenge(pending.code_verifier),
                "code_challenge_method": "S256",
            }
        )
        return AuthorizationRequest(
            url=f"{self._config.authorization_endpoint}?{query}", pending=pending
        )

    def complete_login(
        self, pending: PendingLogin, callback_query: str
    ) -> OidcIdentity | OidcRefusal:
        try:
            return self._identity(pending, callback_query)
        except _RefusalError as refusal:
            return refusal.refusal

    def _identity(self, pending: PendingLogin, callback_query: str) -> OidcIdentity:
        code = self._authorization_code(pending, _callback_parameters(callback_query))
        id_token = self._verified_id_token(self._exchanged_id_token(pending, code))
        if not _is_same_secret(id_token.claims.get("nonce"), pending.nonce):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.NONCE_MISMATCH))
        if not self._is_authorized_party(id_token):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH))
        return _identity_of(id_token)

    def _authorization_code(self, pending: PendingLogin, callback: Mapping[str, str]) -> str:
        if not _is_same_secret(callback.get("state"), pending.state):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.STATE_MISMATCH))
        if callback.get("iss", self._config.issuer) != self._config.issuer:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.ISSUER_MISMATCH))
        if "error" in callback:
            raise _RefusalError(
                OidcRefusal(
                    OidcRefusalReason.AUTHORIZATION_DENIED,
                    idp_error=_idp_error_code(callback["error"]),
                )
            )
        code = callback.get("code")
        if not code:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK))
        return code

    def _exchanged_id_token(self, pending: PendingLogin, code: str) -> str:
        request = TokenRequest(
            url=self._config.token_endpoint,
            form=MappingProxyType(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._config.redirect_uri,
                    "code_verifier": pending.code_verifier,
                }
            ),
            authorization=self._client_authorization,
        )
        try:
            answer = self._post_token_request(request)
        except TokenEndpointError as error:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)) from error
        document = _token_answer_document(answer.body)
        if answer.status == HTTPStatus.OK:
            id_token = document.get("id_token")
            if isinstance(id_token, str):
                return id_token
        elif answer.status in _TOKEN_ERROR_STATUSES and isinstance(document.get("error"), str):
            raise _RefusalError(
                OidcRefusal(
                    OidcRefusalReason.TOKEN_REQUEST_REFUSED,
                    idp_error=_idp_error_code(document["error"]),
                )
            )
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))

    def _verified_id_token(self, id_token: str) -> VerifiedClaims:
        outcome = self._id_token_verifier.verify(id_token)
        if isinstance(outcome, Rejected):
            raise _RefusalError(
                OidcRefusal(OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=outcome.reason)
            )
        return outcome

    def _is_authorized_party(self, id_token: VerifiedClaims) -> bool:
        """OpenID Connect Core 3.1.3.7: a token for several audiences must
        name this client as its `azp`, and any `azp` it names must be this
        client. The verifier already holds the client among the audiences."""
        if "azp" in id_token.claims:
            return id_token.claims["azp"] == self._config.client_id
        return len(id_token.audiences) == 1


def _is_endpoint_url(url: object) -> bool:
    return is_https_url(url) and "?" not in url and "#" not in url


def _is_scope_list_with_openid(scopes: object) -> bool:
    return (
        isinstance(scopes, tuple)
        and all(isinstance(scope, str) and _SCOPE_TOKEN.fullmatch(scope) for scope in scopes)
        and _OPENID_SCOPE in scopes
    )


def _basic_authorization(client_id: str, client_secret: SecretStr) -> SecretStr:
    """RFC 6749 section 2.3.1: both parts form-encoded before Basic encoding."""
    credentials = ":".join(
        urllib.parse.quote_plus(part) for part in (client_id, client_secret.get_secret_value())
    )
    return SecretStr(f"Basic {base64.b64encode(credentials.encode()).decode()}")


def _s256_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _is_same_secret(received: object, expected: str) -> bool:
    if not expected or not isinstance(received, str):
        return False
    try:
        received_bytes = received.encode()
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(received_bytes, expected.encode())


def _callback_parameters(callback_query: str) -> Mapping[str, str]:
    """The callback's parameters, each named once. A repeated name is refused
    rather than resolved, so no reader of the query can pick another value.
    A query that does not encode as UTF-8 is refused before parsing, since
    the parser lets a character through that was never percent-encoded."""
    try:
        callback_query.encode()
        pairs = urllib.parse.parse_qsl(
            callback_query, keep_blank_values=True, strict_parsing=True, errors="strict"
        )
    except ValueError as error:
        raise _RefusalError(OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK)) from error
    parameters = dict(pairs)
    if len(parameters) != len(pairs):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK))
    return parameters


def _idp_error_code(error: str) -> str | None:
    return error if _IDP_ERROR_CODE.fullmatch(error) else None


def _token_answer_document(body: bytes) -> Mapping[str, object]:
    """The answer's JSON object, or an empty one for an answer too large,
    not JSON, or not an object."""
    if len(body) > MAX_TOKEN_RESPONSE_BYTES:
        return {}
    try:
        document = json.loads(body)
    # The stdlib parser recurses per nesting level, and the size bound alone
    # leaves room for nesting deep enough to exhaust the recursion limit.
    except (ValueError, RecursionError):
        return {}
    return document if isinstance(document, dict) else {}


def _identity_of(id_token: VerifiedClaims) -> OidcIdentity:
    if id_token.subject is None:
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return OidcIdentity(
        subject=id_token.subject,
        issuer=id_token.issuer,
        groups=_groups(id_token.claims),
        session_id=_optional_string_claim(id_token.claims, "sid"),
        preferred_username=_optional_string_claim(id_token.claims, "preferred_username"),
    )


def _groups(claims: Mapping[str, object]) -> tuple[str, ...]:
    groups = claims.get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return tuple(groups)


def _optional_string_claim(claims: Mapping[str, object], name: str) -> str | None:
    value = claims.get(name)
    if value is not None and not isinstance(value, str):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return value
