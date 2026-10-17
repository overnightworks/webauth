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
rolls back, and a refusal writes nothing. An ``AdmissionConfig`` states who
may enter and who is admin: the bound issuer, the app's ``login_group``, a
Keycloak group path such as ``/apps/songmaker``, and its ``admin_group``, a
path below it such as ``/apps/songmaker/admin`` (or ``NoAdmins``). Only the
issuer's groups decide the role: it is rewritten at every login, so a person
taken out of the admin group is a plain user from the next login and, the
role living on the account, on every device at once. Until that login an open
session keeps the old role. A person is a member when one of their
groups is that path or a subgroup of it, compared character for character
and by path segment, so ``/apps/songmaker/admin`` counts and
``/apps/songmaker2`` does not. The check runs on every login, before any
account is looked up or created, so a person removed from the group is
refused at their next login while their account and data stay, and a person
put back returns to the same account. It ends no session that is already
open; that lasts until the host's session lifetime runs out. The groups claim
must carry full paths (Keycloak's group mapper with ``full.path`` on); a
missing or empty claim means no membership.

``post_token_request_over_https`` is the production ``TokenRequestPost`` the
host gives its ``OidcRelyingParty``, beside ``fetch_key_set_over_https``; both
send their request through ``webauth.https_client``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum, StrEnum
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
    "AdmissionConfig",
    "AdmissionRefusal",
    "EverySubject",
    "NoAdmins",
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


class EverySubject(Enum):
    """Admit every subject of the bound issuer, whatever their groups.

    That includes the issuer's people who belong to other apps."""

    OF_THE_BOUND_ISSUER = "every-subject"


class NoAdmins(Enum):
    """This app has no admins: every account is ``user_role``, and a stored
    ``admin_role`` is overwritten at the next login."""

    IN_THIS_APP = "no-admins"


@dataclass(frozen=True, kw_only=True)
class AdmissionConfig:
    """Who may enter and who is admin: the issuer the host's store is bound to,
    the group path of the app (or ``EverySubject.OF_THE_BOUND_ISSUER``), and the
    group path of its admins (or ``NoAdmins.IN_THIS_APP``).

    ``ValueError`` at construction names a ``login_group`` or ``admin_group``
    that is not a group path: one that does not start with ``/``, ends with
    ``/``, has an empty segment, whitespace around a segment, or a control,
    format or line-separator character. Under a ``login_group`` path, the
    ``admin_group`` must lie strictly below it, such as ``/apps/songmaker/admin``."""

    bound_issuer: str
    login_group: str | EverySubject
    admin_group: str | NoAdmins

    def __post_init__(self) -> None:
        if not isinstance(self.login_group, EverySubject):
            if not isinstance(self.login_group, str):
                raise ValueError("login_group must be a group path or EverySubject")
            _require_group_path("login_group", self.login_group)
        if isinstance(self.admin_group, NoAdmins):
            return
        if not isinstance(self.admin_group, str):
            raise ValueError("admin_group must be a group path or NoAdmins")
        _require_group_path("admin_group", self.admin_group)
        if isinstance(self.login_group, str) and not _is_below(self.login_group, self.admin_group):
            raise ValueError(
                f"admin_group must lie below login_group, such as {self.login_group}/admin"
            )


_FORBIDDEN_PATH_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _require_group_path(field: str, path: str) -> None:
    segments = path.split("/")
    if segments[0] != "" or len(segments) < 2 or not all(segments[1:]):
        raise ValueError(f"{field} must be a group path such as /apps/name")
    if any(segment != segment.strip() for segment in segments):
        raise ValueError(f"{field} must not have whitespace around a segment")
    if any(unicodedata.category(character) in _FORBIDDEN_PATH_CATEGORIES for character in path):
        raise ValueError(f"{field} must not contain control, format or line-separator characters")


def _is_below(group_path: str, group: str) -> bool:
    return group.startswith(group_path + "/")


def _is_member_of(group_path: str, groups: tuple[str, ...]) -> bool:
    return any(group == group_path or _is_below(group_path, group) for group in groups)


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    NOT_A_MEMBER = "not-a-member"
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
    admission: AdmissionConfig,
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
        admission=admission,
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
    admission: AdmissionConfig,
    accounts: SubjectUserStore,
    lock: WriteLock,
    audit: AuditSink,
    config: WebAuthConfig,
) -> UserRecord | AdmissionRefusal:
    """The account ``identity`` signs in as, created on its first visit.

    A known subject keeps its account and username, whatever username the
    issuer now suggests, but its role follows the groups: ``admin_role`` when
    the identity is a member of ``admission.admin_group`` (or below it),
    otherwise ``user_role``, whatever role the account stored and whatever
    created it. A role that differs is written with ``SubjectUserStore.set_role``
    and recorded as ``ROLE_CHANGED``; an equal role writes nothing.
    ``SubjectUserStore.get`` must compare exactly. A host that migrates legacy
    accounts makes sure that no legacy ``id`` can equal a subject of the bound
    issuer.

    The order of refusals is ``FOREIGN_ISSUER``, then ``NOT_A_MEMBER`` (the
    identity's groups hold no path of ``admission.login_group``, or are
    missing or empty), then the account's own state. The first two write
    nothing and look up no account; a deactivated account is refused before
    any role is written.
    """
    if identity.issuer != admission.bound_issuer:
        return AdmissionRefusal.FOREIGN_ISSUER
    if not _admits(admission.login_group, identity):
        return AdmissionRefusal.NOT_A_MEMBER
    role = _derived_role(admission.admin_group, identity, config)
    with lock.hold():
        account = accounts.get(identity.subject)
        if account is None:
            return _provision(identity, role, accounts=accounts, audit=audit)
        if not account.is_active:
            return AdmissionRefusal.ACCOUNT_DEACTIVATED
        return _with_role(account, role, accounts=accounts, audit=audit)


def _derived_role(
    admin_group: str | NoAdmins, identity: OidcIdentity, config: WebAuthConfig,
) -> str:
    if isinstance(admin_group, str) and _is_member_of(admin_group, identity.groups):
        return config.admin_role
    return config.user_role


def _with_role(
    account: UserRecord, role: str, *, accounts: SubjectUserStore, audit: AuditSink,
) -> UserRecord:
    previous_role = account.role
    if previous_role == role:
        return account
    updated = accounts.set_role(account.id, role)
    audit.user_management_event(UserManagementEvent(
        kind=UserManagementEventKind.ROLE_CHANGED,
        actor_id=None,
        subject_id=updated.id,
        role=role,
        previous_role=previous_role,
    ))
    return updated


def _admits(login_group: str | EverySubject, identity: OidcIdentity) -> bool:
    if isinstance(login_group, EverySubject):
        return True
    return _is_member_of(login_group, identity.groups)


def _provision(
    identity: OidcIdentity,
    role: str,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord | AdmissionRefusal:
    username = _username_for(identity)
    if accounts.get_by_username(username) is not None:
        return AdmissionRefusal.USERNAME_TAKEN
    try:
        account = accounts.create_for_subject(identity.subject, username, role)
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
