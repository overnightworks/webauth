"""OpenID Connect login against one issuer: the authorization-code flow with PKCE.

`OidcRelyingParty.begin_login` answers the URL a browser is sent to and the
`PendingLogin` that must come back with it, which `webauth.oidc_login` carries
in the browser's pending-login cookie. `complete_login` takes that pending
login and the raw query of the callback and answers a verified `OidcIdentity`,
or an `OidcRefusal` naming why the login does not stand.

The callback is judged in a fixed order. Its state comes first, so a forged
callback is refused as such even when it also reports an error; then the
pending login's age; then the RFC 9207 `iss` parameter, when the issuer sends
one; only then the IdP's own `error`, of which nothing but a short error code
is carried — never its `error_description`, which is text the IdP's caller
controls. The code is exchanged with the PKCE verifier over the injected
`TokenRequestPost`, the client authenticating with HTTP Basic. The ID token
is verified by a `JwtVerifier` of `webauth.jwt_verification` whose one
accepted audience is the client ID; its nonce and authorized party are
checked here, as OpenID Connect Core asks of the relying party. A refresh
token in the answer must be RFC 6749 Appendix A.17's `1*VSCHAR`, or the login
is refused as `TOKEN_ENDPOINT_FAILED`; the access token is not read.

`OidcRelyingParty.renew_access` posts a refresh token the issuer gave and
answers a `RenewedAccess`: the new access token and the refresh token the
issuer rotated to, or `None` when it sent none. `workload_access_token` posts
a `client_credentials` grant and answers the client's own access token. Each
is one POST with the code exchange's client authentication, no cache and no
lock, so every call is a fresh token. The issuer's answer must be a Bearer
token (`token_type` compared in ASCII case-insensitively) whose `access_token`
has RFC 6750's `b64token` shape; anything else, and a sent or received refresh
token outside `1*VSCHAR`, is `TOKEN_ENDPOINT_FAILED`. The status handling is
the code exchange's, so an issuer's `error` is `TOKEN_REQUEST_REFUSED`. No
token is decoded: judging its claims belongs to whoever receives it.

The state, nonce and verifier are each `_PENDING_SECRET_BYTES` random bytes,
and the received state and nonce are compared in constant time. A pending
login is stamped with the wall clock when it begins and stands for
`PENDING_LOGIN_MAX_AGE_SECONDS`; one older than that, or dated in the future,
is refused before its code is exchanged. The client secret enters only through
`OidcClientConfig`; it, the code and the verifier stay out of every repr and
message this module writes.

`OidcRelyingParty.verify_logout_token` judges the back-channel Logout Token the
issuer posts (OpenID Connect Back-Channel Logout 1.0, section 2.6) with the
same verifier and key cache, and answers the `VerifiedLogout` naming the
subject whose sessions end, or an `OidcRefusal`. The token must be an RS256
`logout+jwt` of the configured issuer whose one audience is the client ID,
issued no more than `LOGOUT_TOKEN_MAX_AGE_SECONDS` plus the leeway ago, with
an `exp` after its `iat`, the back-channel logout event, a `sub` and no
`nonce`. Its `sid` is never read. There is no replay store: the age bound is
what limits a copy.

`OidcRelyingParty.logout_url` answers the issuer's end-session URL, which
carries the client ID, the configured post-logout redirect URI and, when the
caller has one, the `id_token_hint` of the login being ended. With the hint
the issuer ends the session without asking the person to confirm; without it
the issuer asks. The hint is only passed along, never decoded or verified
here, and no target is taken from a request. It makes no outbound call.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeGuard

from pydantic import SecretStr

from webauth import WebAuthError
from webauth.cookies import _PENDING_SECRET_BYTES, PendingLogin
from webauth.https_client import ExchangeFailure, is_https_url
from webauth.jwt_verification import (
    JwtVerifier,
    KeySetFetch,
    MonotonicClock,
    Rejected,
    RejectionReason,
    VerifiedClaims,
    _json_object,
)

if TYPE_CHECKING:
    from webauth.ports import WallClock

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
    "VerifiedLogout",
]

MAX_TOKEN_RESPONSE_BYTES = 64 * 1024
MAX_AUTHORIZATION_CODE_CHARS = 2048
PENDING_LOGIN_MAX_AGE_SECONDS = 600
LOGOUT_TOKEN_MAX_AGE_SECONDS = 120

_LOGOUT_TOKEN_TYPE = "logout+jwt"  # noqa: S105
# An identifier fixed by OpenID Connect Back-Channel Logout 1.0 section 2.4, never fetched.
_BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"  # NOSONAR(S5332)

_OPENID_SCOPE = "openid"
# RFC 6749 section 3.3: a scope token is one or more printable ASCII
# characters other than space, `"` and `\`.
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]+")
# A strict subset of RFC 6749's error code characters: every registered code
# fits, and nothing that could carry markup or a sentence does.
_IDP_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# RFC 3986 pchar and "/", without ";" which would end a cookie's Path attribute.
_LOGOUT_PATH_CHARACTERS = re.compile(r"/[A-Za-z0-9\-._~!$&'()*+,=:@/%]*")
_UNFINISHED_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
# RFC 6749 Appendix A.17: refresh-token = 1*VSCHAR, printable ASCII.
_REFRESH_TOKEN = re.compile(r"[\x20-\x7e]+")
# RFC 6750 section 2.1: a bearer token is a b64token, so it can sit in an
# `Authorization` header without a CR, LF or space.
_ACCESS_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")
_BEARER_TOKEN_TYPE = "bearer"  # noqa: S105
_TOKEN_ERROR_STATUSES = frozenset({HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED})
_ENDPOINT_URL_FIELDS = (
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "jwks_url",
    "end_session_endpoint",
)
_APP_URL_FIELDS = ("redirect_uri", "post_logout_redirect_uri")
# RFC 8252 sections 7.3 and 8.3: the loopback literals and localhost.
# `urlsplit` lowercases the hostname and drops the brackets of an IPv6 literal.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_URL_RULE = (
    "a host, a valid port if any, and no control character, space,"
    " credentials, query or fragment"
)


@dataclass(frozen=True, kw_only=True)
class OidcClientConfig:
    """One client registered at one issuer.

    `end_session_endpoint` is the issuer's logout page and
    `post_logout_redirect_uri` the app page it sends the browser back to; the
    issuer checks the latter against the client's registered post-logout URIs.
    `logout_path` is the browser-visible path of the host's logout route, or a
    parent of all its logout routes; the cookie that carries the ID token hint
    is scoped to it. It starts with `/` and holds only RFC 3986 path characters
    other than `;`.
    Every URL names a host and carries no control character, space,
    credentials, query or fragment. The issuer, the three endpoints and
    `jwks_url` are https, because the library connects to them or trusts what
    they sign. `redirect_uri` and `post_logout_redirect_uri` are only values
    the browser is sent to, so they may also be http when the host is exactly
    `localhost`, `127.0.0.1` or `[::1]`, for local and CI test stacks.
    `scopes` includes `openid`. `leeway_seconds`
    is checked by the `JwtVerifier` the relying party builds from it."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_url: str
    end_session_endpoint: str
    client_id: str
    client_secret: SecretStr
    redirect_uri: str
    post_logout_redirect_uri: str
    logout_path: str
    scopes: tuple[str, ...] = (_OPENID_SCOPE,)
    leeway_seconds: int

    def __post_init__(self) -> None:
        for name in _ENDPOINT_URL_FIELDS:
            if not _is_endpoint_url(getattr(self, name)):
                raise ValueError(f"{name} must be an https URL naming {_URL_RULE}")
        for name in _APP_URL_FIELDS:
            if not _is_app_url(getattr(self, name)):
                raise ValueError(
                    f"{name} must be an https URL, or an http URL whose host is"
                    f" localhost, 127.0.0.1 or [::1], naming {_URL_RULE}"
                )
        if (
            not isinstance(self.logout_path, str)
            or not _LOGOUT_PATH_CHARACTERS.fullmatch(self.logout_path)
            or _UNFINISHED_PERCENT_ESCAPE.search(self.logout_path)
        ):
            raise ValueError(
                "logout_path must start with / and hold only URL path characters"
                " other than ;"
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
    TOKEN_REQUEST_REFUSED = "token-request-refused"  # noqa: S105
    TOKEN_ENDPOINT_FAILED = "token-endpoint-failed"  # noqa: S105
    ID_TOKEN_REJECTED = "id-token-rejected"  # noqa: S105
    NONCE_MISMATCH = "nonce-mismatch"
    AUTHORIZED_PARTY_MISMATCH = "authorized-party-mismatch"
    INVALID_IDENTITY_CLAIM = "invalid-identity-claim"
    LOGOUT_TOKEN_REJECTED = "logout-token-rejected"  # noqa: S105
    INVALID_LOGOUT_CLAIM = "invalid-logout-claim"


@dataclass(frozen=True)
class OidcRefusal:
    """Why a login or logout token does not stand. `idp_error` is the IdP's
    error code when it named a well-formed one; `token_rejection` is the
    verifier's reason when the ID token or logout token was rejected."""

    reason: OidcRefusalReason
    idp_error: str | None = None
    token_rejection: RejectionReason | None = None


@dataclass(frozen=True)
class OidcIdentity:
    """The person the issuer vouched for. `groups` are the issuer's full group
    paths, uninterpreted; `session_id` is the issuer's `sid`; `id_token` is the
    verified ID token as received, which only ever goes back to the issuer as
    the logout hint; `refresh_token` is the one the code exchange issued, or
    `None` when the issuer gave none. The exchange's access token is never
    kept."""

    subject: str
    issuer: str
    groups: tuple[str, ...]
    session_id: str | None
    preferred_username: str | None
    id_token: str = field(repr=False)
    refresh_token: SecretStr | None


@dataclass(frozen=True)
class RenewedAccess:
    """What a refresh grant yields: the new access token, and the refresh token
    the issuer rotated to, or `None` when it kept the one sent (RFC 6749
    section 6)."""

    access_token: SecretStr
    refresh_token: SecretStr | None


@dataclass(frozen=True)
class VerifiedLogout:
    """A Logout Token that held: the issuer's `subject` whose sessions end."""

    subject: str


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
        self._wall_clock = wall_clock
        self._client_authorization = _basic_authorization(config.client_id, config.client_secret)
        self._jwt_verifier = JwtVerifier(
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
            state=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            nonce=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            code_verifier=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            issued_at=int(self._wall_clock()),
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

    @property
    def logout_path(self) -> str:
        return self._config.logout_path

    def logout_url(self, *, id_token_hint: str | None = None) -> str:
        parameters = {
            "client_id": self._config.client_id,
            "post_logout_redirect_uri": self._config.post_logout_redirect_uri,
        }
        if id_token_hint is not None:
            parameters["id_token_hint"] = id_token_hint
        query = urllib.parse.urlencode(parameters)
        return f"{self._config.end_session_endpoint}?{query}"

    def complete_login(
        self, pending: PendingLogin, callback_query: str
    ) -> OidcIdentity | OidcRefusal:
        try:
            return self._identity(pending, callback_query)
        except _RefusalError as refusal:
            return refusal.refusal

    def _identity(self, pending: PendingLogin, callback_query: str) -> OidcIdentity:
        code = self._authorization_code(pending, _callback_parameters(callback_query))
        raw_id_token, refresh_token = self._exchanged_tokens(pending, code)
        id_token = self._verified_id_token(raw_id_token)
        if not _is_same_secret(id_token.claims.get("nonce"), pending.nonce):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.NONCE_MISMATCH))
        if not self._is_authorized_party(id_token):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH))
        return _identity_of(id_token, raw_id_token, refresh_token)

    def _authorization_code(self, pending: PendingLogin, callback: Mapping[str, str]) -> str:
        if not _is_same_secret(callback.get("state"), pending.state):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.STATE_MISMATCH))
        if not self._is_unexpired(pending):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.PENDING_LOGIN_EXPIRED))
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
        if not code or len(code) > MAX_AUTHORIZATION_CODE_CHARS:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK))
        return code

    def _is_unexpired(self, pending: PendingLogin) -> bool:
        age_seconds = self._wall_clock() - pending.issued_at
        return 0 <= age_seconds <= PENDING_LOGIN_MAX_AGE_SECONDS

    def renew_access(self, refresh_token: SecretStr) -> RenewedAccess | OidcRefusal:
        try:
            return self._renewed_access(refresh_token.get_secret_value())
        except _RefusalError as refusal:
            return refusal.refusal

    def _renewed_access(self, refresh_token: str) -> RenewedAccess:
        if not _is_refresh_token(refresh_token):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
        document = self._token_answer(
            self._grant_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        )
        return RenewedAccess(_bearer_access_token(document), _issued_refresh_token(document))

    def workload_access_token(self) -> SecretStr | OidcRefusal:
        try:
            document = self._token_answer(self._grant_request({"grant_type": "client_credentials"}))
            return _bearer_access_token(document)
        except _RefusalError as refusal:
            return refusal.refusal

    def _grant_request(self, form: Mapping[str, str]) -> TokenRequest:
        return TokenRequest(
            url=self._config.token_endpoint,
            form=MappingProxyType(dict(form)),
            authorization=self._client_authorization,
        )

    def _exchanged_tokens(self, pending: PendingLogin, code: str) -> tuple[str, SecretStr | None]:
        request = self._grant_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._config.redirect_uri,
                "code_verifier": pending.code_verifier,
            }
        )
        document = self._token_answer(request)
        id_token = document.get("id_token")
        if not isinstance(id_token, str):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
        return id_token, _issued_refresh_token(document)

    def _token_answer(self, request: TokenRequest) -> Mapping[str, object]:
        try:
            answer = self._post_token_request(request)
        except TokenEndpointError as error:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)) from error
        document = _token_answer_document(answer.body)
        if answer.status == HTTPStatus.OK:
            return document
        if answer.status in _TOKEN_ERROR_STATUSES and isinstance(
            error := document.get("error"), str
        ):
            raise _RefusalError(
                OidcRefusal(
                    OidcRefusalReason.TOKEN_REQUEST_REFUSED,
                    idp_error=_idp_error_code(error),
                )
            )
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))

    def verify_logout_token(self, logout_token: str) -> VerifiedLogout | OidcRefusal:
        outcome = self._jwt_verifier.verify(logout_token, expected_type=_LOGOUT_TOKEN_TYPE)
        if isinstance(outcome, Rejected):
            return OidcRefusal(
                OidcRefusalReason.LOGOUT_TOKEN_REJECTED, token_rejection=outcome.reason
            )
        if not self._is_logout_profile(outcome) or outcome.subject is None:
            return OidcRefusal(OidcRefusalReason.INVALID_LOGOUT_CLAIM)
        return VerifiedLogout(subject=outcome.subject)

    def _is_logout_profile(self, token: VerifiedClaims) -> bool:
        age_seconds = self._wall_clock() - token.issued_at
        return (
            token.audiences == (self._config.client_id,)
            and age_seconds <= LOGOUT_TOKEN_MAX_AGE_SECONDS + self._config.leeway_seconds
            and token.expires_at > token.issued_at
            and "nonce" not in token.claims
            and _is_backchannel_logout_events(token.claims.get("events"))
        )

    def _verified_id_token(self, id_token: str) -> VerifiedClaims:
        outcome = self._jwt_verifier.verify(id_token)
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


def _callback_state(callback_query: str) -> str | OidcRefusal:
    """The state a callback query names once, non-empty and decodable, or the
    refusal `complete_login` answers for a query that names no such state.

    The state is read on its own, so a callback whose rest is malformed still
    names the pending login it ends; `complete_login` then refuses it."""
    states = [
        value
        for name, value in urllib.parse.parse_qsl(
            callback_query, keep_blank_values=True, errors="surrogateescape"
        )
        if name == "state"
    ]
    if len(states) == 1 and states[0] and _is_utf8(states[0]):
        return states[0]
    try:
        _callback_parameters(callback_query)
    except _RefusalError as refusal:
        return refusal.refusal
    return OidcRefusal(OidcRefusalReason.STATE_MISMATCH)


def _is_backchannel_logout_events(events: object) -> bool:
    return (
        isinstance(events, dict)
        and events.keys() == {_BACKCHANNEL_LOGOUT_EVENT}
        and isinstance(events[_BACKCHANNEL_LOGOUT_EVENT], dict)
    )


def _is_utf8(text: str) -> bool:
    """Whether ``text`` holds no byte that failed to decode as UTF-8."""
    try:
        text.encode()
    except UnicodeEncodeError:
        return False
    return True


def _is_endpoint_url(url: object) -> bool:
    return is_https_url(url) and "?" not in url and "#" not in url


def _is_app_url(url: object) -> bool:
    """An endpoint URL, or the same shape over http on a loopback host.

    The http form is judged by `is_https_url` with its scheme swapped, so the
    control character, space, credential and port guards stay in one place."""
    if _is_endpoint_url(url):
        return True
    if not isinstance(url, str) or url[:5].lower() != "http:":
        return False
    try:
        host = urllib.parse.urlsplit(url).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS and _is_endpoint_url(f"https:{url[5:]}")


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
    if not expected or not isinstance(received, str) or not _is_utf8(received):
        return False
    return hmac.compare_digest(received.encode(), expected.encode())


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
    """The answer's JSON object, or an empty one for an answer too large, not
    JSON, or not an object.

    The production transport refuses an oversize body first (`TOO_LARGE`); the
    size check here guards an injected `TokenRequestPost`, which may return any
    body."""
    if len(body) > MAX_TOKEN_RESPONSE_BYTES:
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


def _identity_of(
    id_token: VerifiedClaims, raw_id_token: str, refresh_token: SecretStr | None
) -> OidcIdentity:
    if id_token.subject is None:
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return OidcIdentity(
        subject=id_token.subject,
        issuer=id_token.issuer,
        groups=_groups(id_token.claims),
        session_id=_optional_string_claim(id_token.claims, "sid"),
        preferred_username=_optional_string_claim(id_token.claims, "preferred_username"),
        id_token=raw_id_token,
        refresh_token=refresh_token,
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
