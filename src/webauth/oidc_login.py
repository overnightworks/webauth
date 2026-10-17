"""Signing a person in through an OpenID Connect issuer, from the host's two routes.

``start_login`` answers the URL the host's start route sends the browser to,
and hands the browser the pending login in a signed cookie of its own, one
per login, so two tabs never overwrite each other. ``finish_login`` takes the
callback the browser brings back, consumes exactly the cookie its state
names, and answers the account to open a session for, or why there is none.
The cookie is cleared on every outcome; together with the issuer's one-time
code, that makes a pending login single-use. There is no server-side store,
so this is not a replay store: a copy of the cookie taken before the callback
is stopped by the issuer refusing the spent code, not by webauth.

The host's store is bound to one issuer — the ``issuer`` of its
``OidcClientConfig`` — and an account it provisions has the issuer's subject
as its ``id``. Moving to another issuer is therefore a migration of the
host's accounts, never a configuration change. This module builds on
``webauth.oidc``, so a host using it installs the ``jwt`` extra.

Admission holds the host's write lock and never commits: the host commits or
rolls back, and a refusal writes nothing.

``post_token_request_over_https`` is the production ``TokenRequestPost`` the
host gives its ``OidcRelyingParty``, beside ``fetch_key_set_over_https``; both
send their request through ``webauth.https_client``.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Final

from webauth.cookies import (
    clear_pending_login_cookie,
    cookie_pairs,
    cookie_values,
    is_pending_login_cookie_name,
    issue_pending_login_cookie,
    pending_login_cookie_name,
    verify_pending_login,
)
from webauth.https_client import (
    TOKEN_EXCHANGE_DEADLINE_SECONDS,
    HttpsExchangeError,
    post_form_over_https,
)
from webauth.oidc import (
    MAX_TOKEN_RESPONSE_BYTES,
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcRefusal,
    OidcRefusalReason,
    TokenEndpointAnswer,
    TokenEndpointError,
    callback_state,
)
from webauth.ports import UserManagementEvent, UserManagementEventKind, UsernameTakenError

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig
    from webauth.cookies import PendingLogin
    from webauth.oidc import OidcIdentity, OidcRelyingParty, TokenRequest
    from webauth.ports import AuditSink, SubjectUserStore, UserRecord, WriteLock

__all__ = [
    "AdmissionRefusal",
    "admit_identity",
    "finish_login",
    "post_token_request_over_https",
    "start_login",
]

MAX_PENDING_LOGINS: Final = 5
"""Pending-login cookies a browser keeps at once. A start beyond them
evicts the oldest, so repeated starts never crowd out the session cookies."""
TOKEN_REQUEST_TIMEOUT_SECONDS: Final = 5
"""Seconds ``post_token_request_over_https`` waits to connect, and for each
read, by default."""

# A cookie that does not verify, or whose name appears twice, ranks below
# every genuine one and is evicted first.
_UNRANKED: Final = -1


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    ACCOUNT_DEACTIVATED = "account-deactivated"
    USERNAME_TAKEN = "username-taken"


def start_login(
    relying_party: OidcRelyingParty, request: Request, response: Response, config: WebAuthConfig,
) -> str:
    """Begin a login: set its pending-login cookie on ``response`` and return
    the authorization URL the host redirects the browser to."""
    authorization = relying_party.begin_login()
    for name in _pending_login_cookies_to_evict(request, config):
        clear_pending_login_cookie(response, name, config)
    issue_pending_login_cookie(
        response,
        authorization.pending,
        max_age_seconds=PENDING_LOGIN_MAX_AGE_SECONDS,
        config=config,
    )
    return authorization.url


def finish_login(
    relying_party: OidcRelyingParty,
    request: Request,
    response: Response,
    config: WebAuthConfig,
    *,
    bound_issuer: str,
    accounts: SubjectUserStore,
    lock: WriteLock,
    audit: AuditSink,
) -> UserRecord | OidcRefusal | AdmissionRefusal:
    """Complete the login the callback ``request`` returns from.

    The callback's state selects exactly one pending-login cookie, which is
    cleared on ``response`` whatever the outcome, so the host answers with
    ``response`` on every outcome, refusals included; every other tab's
    cookie stays. A callback naming no state or naming it twice, or whose state
    names no single genuine cookie, is refused before any token request. On
    an account, the host opens its session and then calls
    ``issue_session_cookies``.
    """
    callback_query = request.url.query
    state = callback_state(callback_query)
    if isinstance(state, OidcRefusal):
        return state
    cookie_name = pending_login_cookie_name(state, secure=config.cookie_secure)
    clear_pending_login_cookie(response, cookie_name, config)
    pending = _sole_pending_login(request, cookie_name, config)
    if pending is None:
        return OidcRefusal(OidcRefusalReason.STATE_MISMATCH)
    identity = relying_party.complete_login(pending, callback_query)
    if isinstance(identity, OidcRefusal):
        return identity
    return admit_identity(
        identity,
        bound_issuer=bound_issuer,
        accounts=accounts,
        lock=lock,
        audit=audit,
        config=config,
    )


def _sole_pending_login(
    request: Request, cookie_name: str, config: WebAuthConfig,
) -> PendingLogin | None:
    values = cookie_values(request, cookie_name)
    if len(values) != 1:
        return None
    return verify_pending_login(values[0], config.signing_key)


def _pending_login_cookies_to_evict(request: Request, config: WebAuthConfig) -> list[str]:
    """The names to clear so the new pending login is one of at most
    ``MAX_PENDING_LOGINS``, oldest first."""
    issued_at_by_name: dict[str, int] = {}
    for name, value in cookie_pairs(request):
        if is_pending_login_cookie_name(name, secure=config.cookie_secure):
            issued_at_by_name[name] = (
                _UNRANKED if name in issued_at_by_name else _issued_at(value, config)
            )
    oldest_first = sorted(issued_at_by_name, key=issued_at_by_name.__getitem__)
    return oldest_first[: max(0, len(oldest_first) - MAX_PENDING_LOGINS + 1)]


def _issued_at(cookie_value: str, config: WebAuthConfig) -> int:
    pending = verify_pending_login(cookie_value, config.signing_key)
    return _UNRANKED if pending is None else pending.issued_at


def admit_identity(
    identity: OidcIdentity,
    *,
    bound_issuer: str,
    accounts: SubjectUserStore,
    lock: WriteLock,
    audit: AuditSink,
    config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    """The account ``identity`` signs in as, created on its first visit.

    A known subject keeps its account as it is, whatever username the issuer
    now suggests. Any stored account whose ``id`` equals the subject character
    for character is that subject's account and signs in as it is, whatever
    created it; ``SubjectUserStore.get`` must compare exactly. A host that
    migrates legacy accounts makes sure that no legacy ``id`` can equal a
    subject of the bound issuer.
    """
    if identity.issuer != bound_issuer:
        return AdmissionRefusal.FOREIGN_ISSUER
    with lock.hold():
        account = accounts.get(identity.subject)
        if account is None:
            return _provision(identity, accounts=accounts, audit=audit, config=config)
        if not account.is_active:
            return AdmissionRefusal.ACCOUNT_DEACTIVATED
        return account


def _provision(
    identity: OidcIdentity,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
    config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    username = _username_for(identity)
    if accounts.get_by_username(username) is not None:
        return AdmissionRefusal.USERNAME_TAKEN
    try:
        account = accounts.create_for_subject(identity.subject, username, config.user_role)
    except UsernameTakenError:
        return AdmissionRefusal.USERNAME_TAKEN
    audit.user_management_event(UserManagementEvent(
        kind=UserManagementEventKind.USER_CREATED,
        actor_id=None,
        subject_id=account.id,
        role=account.role,
    ))
    return account


def _username_for(identity: OidcIdentity) -> str:
    """The issuer's suggested username, or the subject when it suggests a blank one."""
    suggested = identity.preferred_username
    return suggested if suggested and not suggested.isspace() else identity.subject


def post_token_request_over_https(
    request: TokenRequest,
    *,
    timeout_seconds: float = TOKEN_REQUEST_TIMEOUT_SECONDS,
    deadline_seconds: float = TOKEN_EXCHANGE_DEADLINE_SECONDS,
) -> TokenEndpointAnswer:
    """The production ``TokenRequestPost``: the request POSTed under the
    bounded posture of ``webauth.https_client``, reading at most one byte past
    ``MAX_TOKEN_RESPONSE_BYTES`` of the answer.

    Any answer but a redirect comes back whatever its status, so the relying
    party reads an issuer's refusal such as ``invalid_grant``. A redirect, an
    oversized answer, a refused URL, an unreachable origin, a failed TLS
    handshake, a timeout or a broken exchange raises ``TokenEndpointError`` in
    this library's words, never quoting the request.

    ``timeout_seconds`` bounds connecting and each read on its own;
    ``deadline_seconds`` bounds the exchange in total and is owned by
    ``webauth.https_client``. A ``timeout_seconds`` above ``deadline_seconds``
    raises ``ValueError`` rather than being silently capped, as does a
    ``deadline_seconds`` or ``timeout_seconds`` of zero or less.
    ``TokenEndpointError.failure`` names why the request failed."""
    if timeout_seconds > deadline_seconds > 0:
        raise ValueError(
            f"timeout_seconds ({timeout_seconds}) must not exceed"
            f" deadline_seconds ({deadline_seconds})"
        )
    try:
        answer = post_form_over_https(
            request.url,
            request.form,
            authorization=request.authorization,
            max_body_bytes=MAX_TOKEN_RESPONSE_BYTES,
            timeout_seconds=timeout_seconds,
            deadline_seconds=deadline_seconds,
        )
    except HttpsExchangeError as refusal:
        failure = refusal.failure
    else:
        return TokenEndpointAnswer(answer.status, answer.body)
    # Raised outside the handler so not even the exchange error is its context.
    raise TokenEndpointError(f"the token request failed: {failure}", failure)
