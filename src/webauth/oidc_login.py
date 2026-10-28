"""The steps of signing a person in, and the issuer's logout, behind the host's routes.

``webauth.sign_in_routes`` serves the start, callback and logout routes over these
private steps. The start step hands the browser the pending login in a signed
cookie of its own, one per login, so two tabs never overwrite each other. The
callback consumes exactly the cookie its state names and clears it on every
outcome; together with the issuer's one-time code, that makes a pending login
single-use. There is no server-side store, so this is not a replay store: a copy
of the cookie taken before the callback is stopped by the issuer refusing the
spent code, not by webauth.

The host's store is bound to one issuer — the ``issuer`` of its
``OidcClientConfig`` — and an account it provisions has the issuer's subject
as its ``id``. Moving to another issuer is therefore a migration of the
host's accounts, never a configuration change. This module builds on
``webauth.oidc``.

Admission runs inside the host's ``SignInTransaction`` and never commits: the host's
exit commits or rolls back, and a refusal writes nothing. An ``AdmissionConfig`` states who
may enter and who is admin: the bound issuer, the app's ``login_group``, a
Keycloak group path such as ``/apps/notes``, and its ``admin_group``, a
path below it such as ``/apps/notes/admin`` (or ``NoAdmins``). Only the
issuer's groups decide the role: it is rewritten at every login, so a person
taken out of the admin group is a plain user from the next login and, the
role living on the account, on every device at once. Until that login an open
session keeps the old role. A person is a member when one of their
groups is that path or a subgroup of it, compared character for character
and by path segment, so ``/apps/notes/admin`` counts and
``/apps/notes2`` does not. ``app_role`` is that rule's public form, for a second
service that verifies the issuer's token itself. The check runs on every login, before any
account is looked up or created, so a person removed from the group is
refused at their next login while their account and data stay, and a person
put back returns to the same account. It ends no session that is already
open; that lasts until the host's session lifetime runs out. The groups claim
must carry full paths (Keycloak's group mapper with ``full.path`` on); a
missing or empty claim means no membership.

After the callback admits an account, one ``SignInTransaction`` ends the session the
request's cookie names, prunes the account to a cap, and creates its new session,
holding the login's refresh token and, when the host logs out, its ID token (the browser
keeps none), at the configured clock's instant, never committing and setting no cookie,
so the route issues the cookies only after the transaction's exit returned.

The logout route's step ends the session the request's cookie names, if any, in one
``SignInTransaction`` entry and answers a page that posts the ID token hint to the issuer's
end-session endpoint, clearing the session cookie. It makes no outbound call and never
commits, so the person is signed out of the app even when the issuer is down, and a request
without a usable session still reaches the issuer. A forged, oversized or duplicated cookie
counts as missing: it ends no stored session, which leaves a duplicated cookie's session until
it expires, while the browser's own cookies are still cleared.

The step reads the login's ID token from the session row before it deletes the row and
passes it to the issuer as ``id_token_hint``, so the issuer ends its session without asking
the person to confirm. The hint is never decoded or verified here and is no credential;
without a row to read (ended, swept, pruned or stored before the host held ID tokens) the
issuer asks.

``receive_backchannel_logout`` is the issuer's back-channel logout: it reads the
form body (one non-empty ``logout_token`` field, as the issuer posts it) and
verifies the Logout Token before taking the lock, then, under the lock, ends every
session of the account the token's subject names, and records one
``BACKCHANNEL_LOGOUT`` event when a session ended. A subject without an account
is accepted and provisions nothing. It never
commits, clears a cookie or calls the issuer; a store or audit failure
propagates so the host can roll back, and the host commits before it
answers ``ACCEPTED``.

The production ``TokenRequestPost`` is ``webauth.oidc_transport``'s, not this
module's.
"""

from __future__ import annotations

import unicodedata
import urllib.parse
from dataclasses import dataclass
from enum import Enum, StrEnum
from typing import TYPE_CHECKING, Final

from pydantic import SecretStr

from webauth._end_session_page import end_session_page
from webauth._media_types import media_type_of
from webauth._paths import same_app_path
from webauth.cookies import _begin_pending_login, _clear_session_cookies
from webauth.dependencies import (
    _is_admitted,
    _renewed_expiry,
    _whole_second_now,
    session_id_from_request,
)
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcRefusal,
    OidcRefusalReason,
)
from webauth.ports import AccountEvent, AccountEventKind, UsernameTakenError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig
    from webauth.oidc import OidcIdentity, OidcRelyingParty
    from webauth.ports import (
        AuditSink,
        SessionRecordStore,
        SessionTransaction,
        SignInStores,
        SignInTransaction,
        SubjectUserStore,
        UserRecord,
        WriteLock,
    )

__all__ = [
    "AdmissionConfig",
    "AdmissionRefusal",
    "AccessTokenRefusal",
    "AccessTokenRefusalReason",
    "AppRole",
    "BackchannelLogoutResult",
    "EverySubject",
    "NoAdmins",
    "app_role",
    "fresh_access_token",
    "receive_backchannel_logout",
]


class EverySubject(Enum):
    """Admit every subject of the bound issuer, whatever their groups.

    That includes the issuer's people who belong to other apps, so a host
    states it on purpose and only when the issuer already limits who can sign
    in."""

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

    ``bound_issuer`` is the ``issuer`` of the host's ``OidcClientConfig``. Whether
    a group exists at the issuer is not checked.

    ``ValueError`` at construction names a ``login_group`` or ``admin_group``
    that is not a group path: one that does not start with ``/``, ends with
    ``/``, has an empty segment, whitespace around a segment, or a control,
    format or line-separator character. Under a ``login_group`` path, the
    ``admin_group`` must lie strictly below it, such as ``/apps/notes/admin``."""

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


def _is_member_of(group_path: str, groups: Sequence[str]) -> bool:
    return any(group == group_path or _is_below(group_path, group) for group in groups)


class AppRole(StrEnum):
    """The kind of role an app's groups carry, not the host's spelling of it."""

    ADMIN = "admin"
    USER = "user"


def app_role(groups: Sequence[str], admission: AdmissionConfig) -> AppRole | None:
    """The role ``groups`` carry in the app ``admission`` describes.

    ``None`` means no member: the groups hold no path of ``admission.login_group``
    (under ``EverySubject`` every set of groups is a member, the empty one
    included). ``ADMIN`` means they hold ``admission.admin_group`` or a path below
    it, which ``NoAdmins`` never matches; ``USER`` is every other member.

    It reads nothing but its arguments. It does not look at
    ``admission.bound_issuer``: the caller has checked that the groups come from
    that issuer, as the callback's admission does. The caller also validates the raw
    groups claim, refusing any shape but a list of strings as webauth's login
    does, and passes the normalized sequence of strings.
    """
    login_group = admission.login_group
    if isinstance(login_group, str) and not _is_member_of(login_group, groups):
        return None
    admin_group = admission.admin_group
    if isinstance(admin_group, str) and _is_member_of(admin_group, groups):
        return AppRole.ADMIN
    return AppRole.USER


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    NOT_A_MEMBER = "not-a-member"
    USERNAME_TAKEN = "username-taken"


class _UsernameTakenSignal(Exception):  # noqa: N818  # a signal inside the transaction, not an error
    """The store refused a new account's username. It leaves the transaction block as an
    exception, so the host's exit rolls back as it does for any failure, and the callback
    route answers it as ``AdmissionRefusal.USERNAME_TAKEN`` once the exit returned."""


@dataclass(frozen=True)
class _AdmittedLogin:
    """An identity the bound issuer vouched for, admitted as ``role``."""

    identity: OidcIdentity
    role: str


def _start_login(
    relying_party: OidcRelyingParty,
    request: Request,
    response: Response,
    config: WebAuthConfig,
    *,
    return_to: str | None,
) -> str:
    """Begin a login: set its pending-login cookie on ``response`` and return
    the authorization URL the start route redirects the browser to.

    ``return_to`` is the raw path and query as the app sees them, ``root_path``
    included and not the percent-decoded ``request.url.path``, that the callback
    hands back after the login. It is kept only as a
    same-origin path of this app, ASCII (other characters are percent-encoded)
    and at most 512 bytes once encoded; anything else is dropped and the login
    still succeeds, landing on the app root. Dropped are a path a
    browser reads as another host (``//x``, ``/\\x``, a tab, CR or LF between
    the slashes), an absolute URL, a bare host, a control character, the empty
    string, a ``.`` or ``..`` segment (also as ``%2e``), a literal ``#`` and a
    path outside ``root_path``. Under a ``root_path`` the path must already lie
    below it at a segment boundary and nothing is prepended: with
    ``root_path="/app"``, ``/app/albums/42`` is kept and ``/albums/42`` is
    dropped; a ``root_path`` with a character other than ASCII letters, digits,
    ``-._~`` and ``/`` keeps no return path. A login route inside a mounted
    sub-app is judged against that mount's ``root_path``. The fragment is lost,
    because browsers never send it.
    """
    authorization = relying_party.begin_login()
    pending = authorization.pending.returning_to(same_app_path(request, return_to))
    _begin_pending_login(
        request, response, pending, max_age_seconds=PENDING_LOGIN_MAX_AGE_SECONDS, config=config,
    )
    return authorization.url


def _write_sign_in(
    stores: SignInStores,
    admitted: _AdmittedLogin,
    *,
    config: WebAuthConfig,
    replaced_session_id: str | None,
    max_sessions: int | None,
    keeps_id_token: bool,
) -> str:
    """The writes of one sign-in, inside the host's ``SignInTransaction``: the account, then
    the session. Answers the new session's id, copied before the exit.

    The session is opened at the instant of one ``config.wall_clock`` reading, the same whole
    second the session decider reads, in this order: the session the request's cookie names
    (``replaced_session_id``) is ended, whoever it belongs to; when ``max_sessions`` is a number,
    the account's newest ``max_sessions - 1`` sessions are kept and the rest ended, so neither
    the replaced session nor the new one counts against the cap; the new session is created,
    expiring one idle period later, and holds the login's refresh token and, when
    ``keeps_id_token`` is true, its ID token. Never commits, takes no lock and sets no cookie.
    Raises ``_UsernameTakenSignal`` before any session is touched.
    """
    account = _admit_account(admitted, accounts=stores.accounts, audit=stores.audit)
    now = _whole_second_now(config)
    if replaced_session_id is not None:
        stores.sessions.delete(replaced_session_id)
    if max_sessions is not None:
        stores.sessions.prune_overflow(account.id, max_sessions - 1)
    identity = admitted.identity
    return stores.sessions.create(
        account.id,
        now=now,
        expires_at=_renewed_expiry(config.session_lifetime, now=now, created_at=now),
        refresh_token=identity.refresh_token,
        id_token=SecretStr(identity.id_token) if keeps_id_token else None,
    ).id



def _log_out(
    relying_party: OidcRelyingParty,
    request: Request,
    config: WebAuthConfig,
    *,
    transaction: SignInTransaction,
    button_label: str,
) -> Response:
    """The logout route's whole sequence: end the session the request's cookie names, if any,
    and answer the page that ends the issuer's.

    The row is read and then deleted in one ``transaction`` entry, and only when the cookie names
    a session; the ID token's value is copied inside the block. The answer clears the session
    cookie in every case. Never commits and makes no outbound call."""
    session_id = session_id_from_request(request, config)
    id_token: SecretStr | None = None
    if session_id is not None:
        with transaction() as stores:
            id_token = _id_token_of_ended_session(stores.sessions, session_id)
    form = relying_party._end_session_form(id_token_hint=id_token)
    answer = end_session_page(form, button_label=button_label)
    _clear_session_cookies(answer, config)
    return answer


def _id_token_of_ended_session(sessions: SessionRecordStore, session_id: str) -> SecretStr | None:
    record = sessions.load(session_id)
    id_token = None
    if record is not None and record.id_token is not None:
        id_token = SecretStr(record.id_token.get_secret_value())
    sessions.delete(session_id)
    return id_token


class AccessTokenRefusalReason(StrEnum):
    """Why a session yields no access token."""

    SESSION_ENDED = "session-ended"
    """The session is gone or outside its lifetime: the person is signed out.
    The host treats them as signed out, as after a refused request."""
    SIGN_IN_AGAIN = "sign-in-again"
    """The session holds no refresh token (it began before the host stored them,
    or the issuer gave none), or the issuer refused it as ``invalid_grant``,
    which includes a realm SSO session that ended while the app session stands.
    The host sends the person to sign in again; the app session itself stands,
    and only this call is refused."""
    ISSUER_UNAVAILABLE = "issuer-unavailable"
    """The issuer is unreachable, answered something unusable, or refused for a
    reason other than ``invalid_grant``; ``AccessTokenRefusal.issuer_refusal``
    says which. The host fails the call and logs it; the person stays signed in."""


@dataclass(frozen=True)
class AccessTokenRefusal:
    """A session that yields no access token. ``issuer_refusal`` is the issuer's
    answer for ``ISSUER_UNAVAILABLE`` (``invalid_client`` shows its cause here),
    and ``None`` otherwise."""

    reason: AccessTokenRefusalReason
    issuer_refusal: OidcRefusal | None = None


_SESSION_ENDED: Final = AccessTokenRefusal(AccessTokenRefusalReason.SESSION_ENDED)
_SIGN_IN_AGAIN: Final = AccessTokenRefusal(AccessTokenRefusalReason.SIGN_IN_AGAIN)
_INVALID_GRANT: Final = "invalid_grant"
"""The error code (RFC 6749 section 5.2) of a refresh token the issuer no longer honours."""


def fresh_access_token(
    relying_party: OidcRelyingParty,
    session_id: str,
    *,
    session_transaction: SessionTransaction,
    config: WebAuthConfig,
) -> SecretStr | AccessTokenRefusal:
    """A new access token for the person ``session_id`` signs in, in memory only.

    Reads the session in one transaction, sends its refresh token to the issuer
    with no transaction and no lock open, then reads the session again in a
    second transaction and stores the issuer's new refresh token when it
    differs from the one sent (not the one read again). The token is handed
    out only when the second transaction has been left and the session still
    stood in it; a session gone by then is ``SESSION_ENDED`` whatever the
    issuer returned. Admission's own decision judges the session both times,
    and nothing renews it: asking for a token is not the person's request.

    A call that finds the session ended or without a refresh token answers
    before the issuer is contacted; every other call costs one refresh grant at
    the issuer. The host holds the token in memory for the one call it serves
    and stores it nowhere. No session row or lock is held during the grant, so
    a slow issuer holds only the caller's thread, for as long as the
    transport's documented bounds allow (its deadline excludes the host name
    lookup and connecting).

    The second transaction is the last check: a token handed out stays valid at the
    service it is sent to, and at the issuer's own endpoints, until its own
    ``exp``, even after a logout or an expiry that lands later. No revocation
    call is made. Where the issuer lets a refresh token be used again, two
    overlapping calls for one session each get a valid token and the later
    write wins; where it revokes the token on use, the second is refused as
    ``invalid_grant`` and answers a false ``SIGN_IN_AGAIN``.

    Call it from a worker thread, outside any open session transaction and
    outside the host's write lock, with a ``session_id`` that
    ``session_id_from_request`` bounded. It raises when the store fails, when
    ``replace_refresh_token`` answers anything but a ``bool``, or when the
    transaction's exit fails; no token is handed out then.
    """
    sent = _refresh_token_of_standing_session(session_id, session_transaction, config)
    if isinstance(sent, AccessTokenRefusal):
        return sent
    renewed = relying_party.renew_access(sent)
    if isinstance(renewed, OidcRefusal):
        return _refusal_of_grant(renewed)
    with session_transaction() as sessions:
        record = sessions.load(session_id)
        stands = record is not None and _is_admitted(
            config.session_lifetime, record, _whole_second_now(config),
        )
        rotated = renewed.refresh_token
        if stands and rotated is not None and rotated != sent:
            stands = _stored(sessions, session_id, rotated)
    return renewed.access_token if stands else _SESSION_ENDED


def _refresh_token_of_standing_session(
    session_id: str, session_transaction: SessionTransaction, config: WebAuthConfig,
) -> SecretStr | AccessTokenRefusal:
    with session_transaction() as sessions:
        record = sessions.load(session_id)
        if record is None or not _is_admitted(
            config.session_lifetime, record, _whole_second_now(config),
        ):
            return _SESSION_ENDED
        return _SIGN_IN_AGAIN if record.refresh_token is None else record.refresh_token


def _refusal_of_grant(refusal: OidcRefusal) -> AccessTokenRefusal:
    if (
        refusal.reason is OidcRefusalReason.TOKEN_REQUEST_REFUSED
        and refusal.idp_error == _INVALID_GRANT
    ):
        return _SIGN_IN_AGAIN
    return AccessTokenRefusal(AccessTokenRefusalReason.ISSUER_UNAVAILABLE, refusal)


def _stored(sessions: SessionRecordStore, session_id: str, refresh_token: SecretStr) -> bool:
    stored = sessions.replace_refresh_token(session_id, refresh_token=refresh_token)
    if type(stored) is not bool:
        raise TypeError(
            "SessionRecordStore.replace_refresh_token must return a bool, "
            f"not {type(stored).__name__}",
        )
    return stored


class BackchannelLogoutResult(Enum):
    """The host's route answers 200 for ``ACCEPTED`` only after it has committed,
    and 400 for ``REFUSED`` and for any failure. The function deletes sessions
    before it emits its audit event and rolls nothing back, so a failure leaves
    every session in place only when the host's transaction rolls back."""

    ACCEPTED = "accepted"
    """The token held: the subject's sessions, if any, are deleted in the
    host's transaction."""
    REFUSED = "refused"
    """The form or the token did not hold; nothing was changed."""


def receive_backchannel_logout(
    relying_party: OidcRelyingParty,
    form_body: bytes,
    content_type: str | None,
    *,
    accounts: SubjectUserStore,
    sessions: SessionRecordStore,
    lock: WriteLock,
    audit: AuditSink,
) -> BackchannelLogoutResult:
    """End every session of the subject a verified Logout Token names.

    The issuer posts the Logout Token to the client's ``backchannel.logout.url``
    when a person's session at the issuer ends. A request that is not one
    URL-encoded form with exactly one non-empty ``logout_token`` is refused
    before anything is verified or locked. The token is verified before the
    lock is taken. Under the lock, a subject with no account is accepted and
    creates none; a known subject loses every session in every browser, and one
    ``backchannel_logout`` audit event with ``actor_id=None`` is emitted when
    at least one session ended. It never commits, rolls back, clears a cookie
    or calls the issuer. Run it inside one host transaction that rolls back
    when it raises, including when the audit sink fails after the deletion, and
    commits only after it returns ``ACCEPTED``.

    The verification, the lock and the stores are synchronous: run it in a
    worker thread that creates and uses its stores there.

    The route is open to anyone who can reach it, and the token is its only
    control, so set it up for the issuer alone. The issuer sends neither an
    Origin nor a cookie, so list the exact path (never a prefix) in
    ``CsrfPolicy.exempt``. It posts from shared server addresses, so exempt the
    exact path from the rate limit too, or one budget refuses a real logout.
    Give it a ``BodySizeRule`` that admits a Logout Token, which the default
    may not, and a ``CacheControlRule`` of ``no-store``. Let the issuer reach
    it over an internal network alone, never the public route (tunnel, CDN,
    access proxy); its URL may name the public hostname via an internal alias.
    """
    logout_token = _logout_token_of(form_body, content_type)
    if logout_token is None:
        return BackchannelLogoutResult.REFUSED
    logout = relying_party.verify_logout_token(logout_token)
    if isinstance(logout, OidcRefusal):
        return BackchannelLogoutResult.REFUSED
    with lock.hold():
        account = accounts.get(logout.subject)
        if account is not None and sessions.delete_for_user(account.id):
            audit.account_event(AccountEvent(
                kind=AccountEventKind.BACKCHANNEL_LOGOUT,
                actor_id=None,
                subject_id=account.id,
            ))
    return BackchannelLogoutResult.ACCEPTED


def _logout_token_of(form_body: bytes, content_type: str | None) -> str | None:
    if media_type_of(content_type) != "application/x-www-form-urlencoded":
        return None
    try:
        fields = urllib.parse.parse_qsl(
            form_body.decode(), keep_blank_values=True, strict_parsing=True, errors="strict",
        )
    except ValueError:
        return None
    tokens = [value for name, value in fields if name == "logout_token"]
    return tokens[0] if len(tokens) == 1 and tokens[0] else None


def _decide_admission(
    identity: OidcIdentity, *, admission: AdmissionConfig, config: WebAuthConfig,
) -> _AdmittedLogin | AdmissionRefusal:
    """Whether ``identity`` may sign in, and as which role. Pure: it reads nothing but its
    arguments and writes nothing.

    The role is ``admin_role`` when the identity is a member of ``admission.admin_group``
    (or below it), otherwise ``user_role``, whatever role a stored account holds. The
    order of refusals is ``FOREIGN_ISSUER``, then ``NOT_A_MEMBER`` (the identity's groups
    hold no path of ``admission.login_group``, or are missing or empty). Both write nothing and
    look up no account.

    A groups claim that is not a list of strings never reaches this function:
    ``OidcRelyingParty.complete_login`` refuses it as ``INVALID_IDENTITY_CLAIM``.
    A missing claim is an empty list of groups.
    """
    if identity.issuer != admission.bound_issuer:
        return AdmissionRefusal.FOREIGN_ISSUER
    derived = app_role(identity.groups, admission)
    if derived is None:
        return AdmissionRefusal.NOT_A_MEMBER
    return _AdmittedLogin(
        identity, config.admin_role if derived is AppRole.ADMIN else config.user_role,
    )


def _admit_account(
    admitted: _AdmittedLogin, *, accounts: SubjectUserStore, audit: AuditSink,
) -> UserRecord:
    """The account ``admitted`` signs in as, created on its first visit.

    A new subject gets an account with the issuer's ``preferred_username``, or
    the subject when it suggests none or only whitespace, and ``USER_CREATED``
    is recorded with no actor. A known subject keeps its account and username, whatever username the
    issuer now suggests, but its role follows the groups: a role that differs is written with
    ``SubjectUserStore.set_role`` and recorded as ``ROLE_CHANGED``; an equal role writes nothing.
    ``SubjectUserStore.get`` must compare exactly. A host that migrates legacy
    accounts makes sure that no legacy ``id`` can equal a subject of the bound
    issuer.

    ``_UsernameTakenSignal`` is raised when the store refuses a new account's username. No
    username is looked up, so a store without a unique username admits a
    second subject whose ``preferred_username`` another account holds; disabling
    a person is done at the issuer. No local flag locks an account.

    Only the derived role is stored, never the groups. A host that migrates from
    a store with its own admins puts them into the admin group first, or they are
    demoted at their next login.
    """
    account = accounts.get(admitted.identity.subject)
    if account is None:
        return _provision(admitted.identity, admitted.role, accounts=accounts, audit=audit)
    return _with_role(account, admitted.role, accounts=accounts, audit=audit)


def _with_role(
    account: UserRecord, role: str, *, accounts: SubjectUserStore, audit: AuditSink,
) -> UserRecord:
    previous_role = account.role
    if previous_role == role:
        return account
    updated = accounts.set_role(account.id, role)
    audit.account_event(AccountEvent(
        kind=AccountEventKind.ROLE_CHANGED,
        actor_id=None,
        subject_id=updated.id,
        role=role,
        previous_role=previous_role,
    ))
    return updated


def _provision(
    identity: OidcIdentity,
    role: str,
    *,
    accounts: SubjectUserStore,
    audit: AuditSink,
) -> UserRecord:
    username = _username_for(identity)
    try:
        account = accounts.create_for_subject(identity.subject, username, role)
    except UsernameTakenError as refused:
        raise _UsernameTakenSignal from refused
    audit.account_event(AccountEvent(
        kind=AccountEventKind.USER_CREATED,
        actor_id=None,
        subject_id=account.id,
        role=account.role,
    ))
    return account


def _username_for(identity: OidcIdentity) -> str:
    """The issuer's suggested username, or the subject when it suggests a blank one."""
    suggested = identity.preferred_username
    return suggested if suggested and not suggested.isspace() else identity.subject
