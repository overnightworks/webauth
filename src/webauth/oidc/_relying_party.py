"""OpenID Connect login against one issuer: the authorization-code flow with PKCE.

`begin_login` answers the URL a browser is sent to and the `PendingLogin` that must
come back with it; `complete_login` answers a verified `OidcIdentity` or an
`OidcRefusal` naming why the login does not stand.

The callback is judged in a fixed order. Its state comes first, so a forged
callback is refused as such even when it also reports an error; then the
pending login's age; then the RFC 9207 `iss` parameter, when the issuer sends
one; only then the IdP's own `error`, of which nothing but a short error code
is carried — never its `error_description`, which is text the IdP's caller
controls. The code is exchanged with the PKCE verifier over the injected
`TokenRequestPost`, the client authenticating with HTTP Basic. The ID token
is verified by a `_JwtVerifier` of `webauth.jwt_verification` whose one
accepted audience is the client ID; its nonce and authorized party are
checked here, as OpenID Connect Core asks of the relying party. A refresh
token in the answer must be RFC 6749 Appendix A.17's `1*VSCHAR`, or the login
is refused as `TOKEN_ENDPOINT_FAILED`; the access token is not read.

`renew_access`, `workload_access_token` (a `client_credentials` grant for the
host's scopes) and the bearer gate's token exchange (RFC 8693, of the access
token a resource admitted) are each one POST with the code exchange's client
authentication, no cache and no lock, so every call is a fresh token. The
issuer's answer must be a Bearer token (`token_type` compared in ASCII
case-insensitively) whose `access_token` has RFC 6750's `b64token` shape;
anything else is `TOKEN_ENDPOINT_FAILED`, and so is a sent or received refresh
token outside `1*VSCHAR`, except that the token exchange never reads a
`refresh_token`. The status handling is the code exchange's, so an issuer's
`error` is `TOKEN_REQUEST_REFUSED`; the token exchange also reads it from a
403. No token is decoded: judging its claims belongs to whoever receives it.

The state, nonce and verifier are each `_PENDING_SECRET_BYTES` random bytes,
and the received state and nonce are compared in constant time. A pending
login is stamped with the wall clock when it begins and stands for
`PENDING_LOGIN_MAX_AGE_SECONDS`; one older than that, or dated in the future,
is refused before its code is exchanged. The client secret enters only through
`OidcClientConfig`; it, the code and the verifier stay out of every repr and
message this module writes.
"""

from __future__ import annotations

import base64
import hmac
import secrets
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http import HTTPStatus
from types import MappingProxyType
from typing import TYPE_CHECKING

from pydantic import SecretStr

from webauth._end_session_page import EndSessionForm
from webauth._validation import is_scope_token_tuple, is_utf8
from webauth.cookies import _PENDING_SECRET_BYTES, PendingLogin
from webauth.jwt_verification import (
    KeySetFetch,
    MonotonicClock,
    RejectionReason,
    _JwtVerifier,
    _Rejected,
    _VerifiedClaims,
)
from webauth.oidc._authorization_url import authorization_url
from webauth.oidc._client_config import OidcClientConfig
from webauth.oidc._locale_claim import account_language_claim
from webauth.oidc._token_endpoint import (
    _ACCESS_TOKEN_TYPE,
    _EXCHANGE_ERROR_STATUSES,
    _TOKEN_ERROR_STATUSES,
    _TOKEN_EXCHANGE_GRANT,
    OidcRefusal,
    OidcRefusalReason,
    TokenEndpointError,
    TokenRequest,
    TokenRequestPost,
    _bearer_access_token,
    _exchanged_lifetime_seconds,
    _idp_error_code,
    _is_refresh_token,
    _issued_refresh_token,
    _raw_id_token_of,
    _RefusalError,
    _token_answer_document,
)
from webauth.policies import AuthorizedParties, _require_authorized_parties
from webauth.ports import AgentFacts

if TYPE_CHECKING:
    from webauth.ports import WallClock

__all__ = [
    "PENDING_LOGIN_MAX_AGE_SECONDS",
    "AuthorizationRequest",
    "ExchangedAccess",
    "OidcIdentity",
    "OidcRelyingParty",
    "RenewedAccess",
    "VerifiedAccessToken",
    "VerifiedLogout",
]

_MAX_AUTHORIZATION_CODE_CHARS = 2048
PENDING_LOGIN_MAX_AGE_SECONDS = 600
_LOGOUT_TOKEN_MAX_AGE_SECONDS = 120
_AGENT_NAME_MAX_LENGTH = 64

_LOGOUT_TOKEN_TYPE = "logout+jwt"  # noqa: S105 - token type not a credential
_ACCESS_TOKEN_MEDIA_TYPES = frozenset({"at+jwt", "application/at+jwt"})
# An identifier fixed by OpenID Connect Back-Channel Logout 1.0 section 2.4, never fetched.
_BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"  # NOSONAR(S5332)


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str
    pending: PendingLogin


@dataclass(frozen=True)
class OidcIdentity:
    """The person the issuer vouched for. `groups` are the issuer's full group
    paths, uninterpreted; `session_id` is the issuer's `sid`; `id_token` is the
    verified ID token as received, which only ever goes back to the issuer as
    the logout hint; `refresh_token` is the one the code exchange issued, or
    `None` when the issuer gave none; `account_language` is the `locale` claim, or `None`.
    The exchange's access token is never kept."""

    subject: str
    issuer: str
    groups: tuple[str, ...]
    session_id: str | None
    preferred_username: str | None
    id_token: str = field(repr=False)
    refresh_token: SecretStr | None
    account_language: str | None


@dataclass(frozen=True)
class RenewedAccess:
    """What a refresh grant yields: the new access token, and the refresh token
    the issuer rotated to, or `None` when it kept the one sent (RFC 6749
    section 6)."""

    access_token: SecretStr
    refresh_token: SecretStr | None


@dataclass(frozen=True)
class ExchangedAccess:
    """What a token exchange yields: the access token and the whole wall-clock second it
    expires at."""

    access_token: SecretStr
    expires_at: int


@dataclass(frozen=True)
class _RefreshedGroups:
    """The rotation of a refresh grant, kept apart from what its ID token yielded."""

    refresh_token: SecretStr | None
    groups: tuple[str, ...] | OidcRefusal


@dataclass(frozen=True)
class VerifiedLogout:
    """A Logout Token that held: the issuer's `subject` whose sessions end."""

    subject: str


@dataclass(frozen=True)
class VerifiedAccessToken:
    """An access token that held: the issuer's `subject`, its full group paths, the
    `preferred_username` it carries, `None` when absent or not a string, and the agent's facts
    when the resource's agent group admitted it, `None` otherwise."""

    subject: str
    groups: tuple[str, ...]
    preferred_username: str | None = None
    agent: AgentFacts | None = None


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
        self._fetch_key_set = fetch_key_set
        self._monotonic_clock = monotonic_clock
        self._jwt_verifier = self._verifier_for(config.client_id)

    def _verifier_for(self, audience: str) -> _JwtVerifier:
        return _JwtVerifier(
            issuer=self._config.issuer,
            audiences=[audience],
            jwks_url=self._config.jwks_url,
            leeway_seconds=self._config.leeway_seconds,
            fetch_key_set=self._fetch_key_set,
            wall_clock=self._wall_clock,
            monotonic_clock=self._monotonic_clock,
        )

    @property
    def issuer(self) -> str:
        return self._config.issuer

    def begin_login(self, *, ui_locales: str | None) -> AuthorizationRequest:
        """The authorization URL to send the browser to, and the `PendingLogin`
        (state, nonce, PKCE verifier and `issued_at`, the wall-clock second it
        began) the host keeps until the callback returns.

        `ui_locales` is the language tag the host names for the issuer's pages, sent as the
        `ui_locales` parameter of OpenID Connect Core section 3.1.2.1 and not kept in the
        `PendingLogin`; `None` sends none. A string that is not a language tag in shape
        raises `ValueError`."""
        pending = PendingLogin(
            state=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            nonce=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            code_verifier=secrets.token_urlsafe(_PENDING_SECRET_BYTES),
            issued_at=int(self._wall_clock()),
        )
        return AuthorizationRequest(
            url=authorization_url(self._config, pending, ui_locales=ui_locales),
            pending=pending,
        )

    def _end_session_form(self, *, id_token_hint: SecretStr | None) -> EndSessionForm:
        return EndSessionForm(
            end_session_endpoint=self._config.end_session_endpoint,
            client_id=self._config.client_id,
            post_logout_redirect_uri=self._config.post_logout_redirect_uri,
            id_token_hint=id_token_hint,
        )

    def complete_login(
        self, pending: PendingLogin, callback_query: str
    ) -> OidcIdentity | OidcRefusal:
        """The identity the callback `callback_query` (its raw query string)
        proves for `pending`, or the refusal naming why it does not.

        A `code` longer than `_MAX_AUTHORIZATION_CODE_CHARS` is
        `MALFORMED_CALLBACK`. The ID token must name this client as its `azp` when it is for several
        audiences, and any `azp` it names must be this client. A refresh token
        in the answer that is `null` or outside `1*VSCHAR` is
        `TOKEN_ENDPOINT_FAILED`. A token answer that names a member twice keeps
        its last value."""
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
        if not code or len(code) > _MAX_AUTHORIZATION_CODE_CHARS:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.MALFORMED_CALLBACK))
        return code

    def _is_unexpired(self, pending: PendingLogin) -> bool:
        age_seconds = self._wall_clock() - pending.issued_at
        return 0 <= age_seconds <= PENDING_LOGIN_MAX_AGE_SECONDS

    def renew_access(self, refresh_token: SecretStr) -> RenewedAccess | OidcRefusal:
        """Posts `refresh_token` as a `refresh_token` grant, so each call is one
        POST and a fresh access token.

        A refresh token outside `1*VSCHAR` reaches no request. The issuer's
        `error` is carried as `idp_error`: `invalid_grant` for a refresh token it
        no longer accepts."""
        try:
            return self._renewed_access(refresh_token.get_secret_value())
        except _RefusalError as refusal:
            return refusal.refusal

    def _renewed_access(self, refresh_token: str) -> RenewedAccess:
        document = self._refresh_answer(refresh_token)
        return RenewedAccess(_bearer_access_token(document), _issued_refresh_token(document))

    def _refresh_answer(self, refresh_token: str) -> Mapping[str, object]:
        if not _is_refresh_token(refresh_token):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))
        return self._token_answer(
            self._grant_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        )

    def _refreshed_groups(
        self, refresh_token: SecretStr, *, subject: str
    ) -> _RefreshedGroups | OidcRefusal:
        """The groups of the ID token a refresh grant answers, and its rotated refresh token.

        Only the issuer's refusal of the grant itself is an `OidcRefusal` here; an ID token
        that does not hold is carried in `groups`, so the caller still stores the rotation.
        The new ID token must carry `subject`, no `nonce` key at all (section 12.2 says it
        SHOULD NOT, section 2 requires a present one to be verified, and nothing is kept to
        verify it against), and an `iat` within the leeway of the grant's start
        (OpenID Connect Core 1.0)."""
        started_at = int(self._wall_clock())
        try:
            document = self._refresh_answer(refresh_token.get_secret_value())
            rotated = _issued_refresh_token(document)
        except _RefusalError as refusal:
            return refusal.refusal
        try:
            groups = self._refreshed_id_token_groups(document, subject, started_at)
        except _RefusalError as refusal:
            groups = refusal.refusal
        return _RefreshedGroups(rotated, groups)

    def _refreshed_id_token_groups(
        self, document: Mapping[str, object], subject: str, started_at: int
    ) -> tuple[str, ...]:
        id_token = self._verified_id_token(_raw_id_token_of(document))
        if "nonce" in id_token.claims:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.NONCE_MISMATCH))
        if not self._is_authorized_party(id_token):
            raise _RefusalError(OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH))
        if id_token.subject != subject:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.SUBJECT_MISMATCH))
        if id_token.issued_at + self._config.leeway_seconds < started_at:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.STALE_ID_TOKEN))
        groups = _group_paths(id_token.claims)
        if groups is None:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
        return groups

    def workload_access_token(self, *, scopes: tuple[str, ...]) -> SecretStr | OidcRefusal:
        """The client's own access token, from a `client_credentials` grant for
        `scopes`, the scope tokens of the service the token is for.

        `scopes` is a non-empty tuple of RFC 6749 scope tokens, none trimmed;
        anything else raises `ValueError` and posts nothing. The realm must
        give the client a service account holding the role the receiver
        demands; an issuer `error` such as `unauthorized_client` (no service
        account) or `invalid_scope` (not assigned) is carried as `idp_error`."""
        _require_scopes(scopes)
        try:
            document = self._token_answer(
                self._grant_request({"grant_type": "client_credentials", "scope": " ".join(scopes)})
            )
            return _bearer_access_token(document)
        except _RefusalError as refusal:
            return refusal.refusal

    def _token_exchange(
        self, subject_token: str, scopes: tuple[str, ...]
    ) -> ExchangedAccess | OidcRefusal:
        """The access token an RFC 8693 exchange of `subject_token` for `scopes` yields.

        `scopes` is judged as `workload_access_token` judges it. The grant names no audience and
        no resource; the answer's `expires_in` counts from the wall clock read before the post,
        and its refresh token and scope are not read. An issuer's `error` is carried also from
        a 403."""
        _require_scopes(scopes)
        started_at = int(self._wall_clock())
        try:
            document = self._token_answer(
                self._grant_request(
                    {
                        "grant_type": _TOKEN_EXCHANGE_GRANT,
                        "subject_token": subject_token,
                        "subject_token_type": _ACCESS_TOKEN_TYPE,
                        "requested_token_type": _ACCESS_TOKEN_TYPE,
                        "scope": " ".join(scopes),
                    }
                ),
                error_statuses=_EXCHANGE_ERROR_STATUSES,
            )
            return ExchangedAccess(
                _bearer_access_token(document), started_at + _exchanged_lifetime_seconds(document)
            )
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
        return _raw_id_token_of(document), _issued_refresh_token(document)

    def _token_answer(
        self,
        request: TokenRequest,
        *,
        error_statuses: frozenset[HTTPStatus] = _TOKEN_ERROR_STATUSES,
    ) -> Mapping[str, object]:
        try:
            answer = self._post_token_request(request)
        except TokenEndpointError as error:
            raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED)) from error
        document = _token_answer_document(answer.body)
        if answer.status == HTTPStatus.OK:
            return document
        if answer.status in error_statuses and isinstance(error := document.get("error"), str):
            raise _RefusalError(
                OidcRefusal(
                    OidcRefusalReason.TOKEN_REQUEST_REFUSED,
                    idp_error=_idp_error_code(error),
                )
            )
        raise _RefusalError(OidcRefusal(OidcRefusalReason.TOKEN_ENDPOINT_FAILED))

    def verify_logout_token(self, logout_token: str) -> VerifiedLogout | OidcRefusal:
        """The subject whose sessions end, or the refusal.

        Stricter than the Back-Channel Logout profile asks: `iat` must be an
        integer and no more than the leeway in the future, `events` must hold
        the logout event and no other key, that event's member an object, `sub`
        non-empty (a token naming only a `sid` is refused) and `nonce` absent,
        even as `null`. An RS256 `logout+jwt` of the configured issuer whose one
        audience is the client ID, issued no more than `_LOGOUT_TOKEN_MAX_AGE_SECONDS`
        plus the leeway ago, and expiring after its `iat`. The token, its claims and
        its `sid` are never returned, so no session id is stored. There is no replay
        store: the age bound is what limits a copy, which ends the subject's sessions
        again until it ages out, and a person who signed in again in that time is
        signed out once more."""
        outcome = self._jwt_verifier.verify(logout_token, expected_type=_LOGOUT_TOKEN_TYPE)
        if isinstance(outcome, _Rejected):
            return OidcRefusal(
                OidcRefusalReason.LOGOUT_TOKEN_REJECTED, token_rejection=outcome.reason
            )
        if not self._is_logout_profile(outcome) or outcome.subject is None:
            return OidcRefusal(OidcRefusalReason.INVALID_LOGOUT_CLAIM)
        return VerifiedLogout(subject=outcome.subject)

    def verify_access_token(
        self,
        access_token: str,
        *,
        authorized_parties: AuthorizedParties,
    ) -> VerifiedAccessToken | OidcRefusal:
        """The subject and groups of an access token presented to this app, or the refusal.

        Stricter than RFC 9068 section 4: an RS256 `at+jwt` whose only audience is the
        client ID and whose `azp` is one `authorized_parties` admits, with a `sub`
        and `groups` absent or a list of strings. `client_id`,
        `jti` and `scope` are not read. `TypeError` for anything but
        `AuthorizedParties`."""
        _require_authorized_parties(authorized_parties)
        outcome = _verify_access_jwt(self._jwt_verifier, access_token)
        if isinstance(outcome, OidcRefusal):
            return outcome
        return self._access_token_profile(
            outcome, authorized_parties, audience=self._config.client_id
        )

    def resource_token_verifier(
        self,
        *,
        resource_url: str,
        scope: str,
        authorized_parties: AuthorizedParties,
        agent_group: str,
        admits_client_audience: bool = False,
    ) -> Callable[[str], VerifiedAccessToken | OidcRefusal]:
        """A check of an access token presented to the resource at `resource_url`.

        The verifier owns a key-set cache, so build it once. The token's only
        audience is `resource_url` and its `azp` one `authorized_parties` admits,
        unless its `groups` list holds `agent_group` as one element (not a path below it):
        then any `azp` passes, and the token must carry `agent_owner`, a non-empty string,
        and `agent_name`, a printable string of 1 to 64 characters, which become
        `VerifiedAccessToken.agent`; anything else is `INVALID_ACCESS_CLAIM`, decided before
        the scope. Its `scope` claim, a string of space-separated tokens, must include
        `scope` exactly, or the refusal is `INSUFFICIENT_SCOPE`. The realm alone decides
        which clients can mint a token for `resource_url`. With `admits_client_audience`
        the audiences may also be exactly `resource_url` and this client's ID, in either
        order. `TypeError` for anything but `AuthorizedParties`."""
        _require_authorized_parties(authorized_parties)
        jwt_verifier = self._verifier_for(resource_url)

        def verify(access_token: str) -> VerifiedAccessToken | OidcRefusal:
            outcome = _verify_access_jwt(jwt_verifier, access_token)
            if isinstance(outcome, OidcRefusal):
                return outcome
            profile = self._access_token_profile(
                outcome,
                authorized_parties,
                audience=resource_url,
                agent_group=agent_group,
                admits_client_audience=admits_client_audience,
            )
            if isinstance(profile, VerifiedAccessToken) and not _holds_scope(outcome.claims, scope):
                return OidcRefusal(OidcRefusalReason.INSUFFICIENT_SCOPE)
            return profile

        return verify

    def _access_token_profile(
        self,
        token: _VerifiedClaims,
        authorized_parties: AuthorizedParties,
        *,
        audience: str,
        agent_group: str | None = None,
        admits_client_audience: bool = False,
    ) -> VerifiedAccessToken | OidcRefusal:
        admitted_audiences = {(audience,)}
        if admits_client_audience and self._config.client_id != audience:
            admitted_audiences |= {
                (audience, self._config.client_id),
                (self._config.client_id, audience),
            }
        if token.subject is None or token.audiences not in admitted_audiences:
            return OidcRefusal(OidcRefusalReason.INVALID_ACCESS_CLAIM)
        groups = _group_paths(token.claims)
        is_agent = groups is not None and agent_group in groups
        if not is_agent and not authorized_parties.admits(token.claims.get("azp")):
            return OidcRefusal(OidcRefusalReason.AUTHORIZED_PARTY_MISMATCH)
        if groups is None:
            return OidcRefusal(OidcRefusalReason.INVALID_ACCESS_CLAIM)
        agent = _agent_facts(token.claims) if is_agent else None
        if is_agent and agent is None:
            return OidcRefusal(OidcRefusalReason.INVALID_ACCESS_CLAIM)
        username = token.claims.get("preferred_username")
        return VerifiedAccessToken(
            subject=token.subject,
            groups=groups,
            preferred_username=username if isinstance(username, str) else None,
            agent=agent,
        )

    def _is_logout_profile(self, token: _VerifiedClaims) -> bool:
        age_seconds = self._wall_clock() - token.issued_at
        return (
            token.audiences == (self._config.client_id,)
            and age_seconds <= _LOGOUT_TOKEN_MAX_AGE_SECONDS + self._config.leeway_seconds
            and token.expires_at > token.issued_at
            and "nonce" not in token.claims
            and _is_backchannel_logout_events(token.claims.get("events"))
        )

    def _verified_id_token(self, id_token: str) -> _VerifiedClaims:
        outcome = self._jwt_verifier.verify(id_token)
        if isinstance(outcome, _Rejected):
            raise _RefusalError(
                OidcRefusal(OidcRefusalReason.ID_TOKEN_REJECTED, token_rejection=outcome.reason)
            )
        return outcome

    def _is_authorized_party(self, id_token: _VerifiedClaims) -> bool:
        """OpenID Connect Core 3.1.3.7: a token for several audiences must
        name this client as its `azp`, and any `azp` it names must be this
        client. The verifier already holds the client among the audiences."""
        if "azp" in id_token.claims:
            return id_token.claims["azp"] == self._config.client_id
        return len(id_token.audiences) == 1


def _require_scopes(scopes: object) -> None:
    if not scopes or not is_scope_token_tuple(scopes):
        raise ValueError("scopes must be a non-empty tuple of RFC 6749 scope tokens")


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
    if len(states) == 1 and states[0] and is_utf8(states[0]):
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


def _names_another_audience(refusal: OidcRefusal) -> bool:
    return refusal.token_rejection is RejectionReason.INVALID_AUDIENCE


def _basic_authorization(client_id: str, client_secret: SecretStr) -> SecretStr:
    """RFC 6749 section 2.3.1: both parts form-encoded before Basic encoding."""
    credentials = ":".join(
        urllib.parse.quote_plus(part) for part in (client_id, client_secret.get_secret_value())
    )
    return SecretStr(f"Basic {base64.b64encode(credentials.encode()).decode()}")


def _is_same_secret(received: object, expected: str) -> bool:
    if not expected or not isinstance(received, str) or not is_utf8(received):
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


def _identity_of(
    id_token: _VerifiedClaims, raw_id_token: str, refresh_token: SecretStr | None
) -> OidcIdentity:
    groups = _group_paths(id_token.claims)
    if id_token.subject is None or groups is None:
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return OidcIdentity(
        subject=id_token.subject,
        issuer=id_token.issuer,
        groups=groups,
        session_id=_optional_string_claim(id_token.claims, "sid"),
        preferred_username=_optional_string_claim(id_token.claims, "preferred_username"),
        id_token=raw_id_token,
        refresh_token=refresh_token,
        account_language=account_language_claim(id_token.claims),
    )


def _group_paths(claims: Mapping[str, object]) -> tuple[str, ...] | None:
    groups = _groups_claim(claims, "groups")
    return None if groups is None else tuple(groups)


def _groups_claim(claims: Mapping[str, object], claim_name: str) -> list[str] | None:
    """The listed groups; none when the claim is missing, ``None`` when it is no list of strings."""
    groups = claims.get(claim_name, [])
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        return None
    return groups


def _verify_access_jwt(verifier: _JwtVerifier, access_token: str) -> _VerifiedClaims | OidcRefusal:
    outcome = verifier.verify(access_token, expected_media_types=_ACCESS_TOKEN_MEDIA_TYPES)
    if isinstance(outcome, _Rejected):
        return OidcRefusal(OidcRefusalReason.ACCESS_TOKEN_REJECTED, token_rejection=outcome.reason)
    return outcome


def _agent_facts(claims: Mapping[str, object]) -> AgentFacts | None:
    owner, name = claims.get("agent_owner"), claims.get("agent_name")
    if not isinstance(owner, str) or not owner:
        return None
    if not isinstance(name, str) or not 1 <= len(name) <= _AGENT_NAME_MAX_LENGTH:
        return None
    return AgentFacts(owner, name) if name.isprintable() else None


def _holds_scope(claims: Mapping[str, object], scope: str) -> bool:
    granted = claims.get("scope")
    return isinstance(granted, str) and scope in granted.split(" ")


def _optional_string_claim(claims: Mapping[str, object], name: str) -> str | None:
    value = claims.get(name)
    if value is not None and not isinstance(value, str):
        raise _RefusalError(OidcRefusal(OidcRefusalReason.INVALID_IDENTITY_CLAIM))
    return value
