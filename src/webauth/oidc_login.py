"""Signing a person in through an OpenID Connect issuer, from the host's routes.

``start_login`` answers the URL the host's start route sends the browser to,
and hands the browser the pending login in a signed cookie of its own, one
per login, so two tabs never overwrite each other. ``finish_login`` takes the
callback the browser brings back, consumes exactly the cookie its state
names, and answers the account to open a session for and the path to return to,
or why there is none.
The cookie is cleared on every outcome; together with the issuer's one-time
code, that makes a pending login single-use. There is no server-side store,
so this is not a replay store: a copy of the cookie taken before the callback
is stopped by the issuer refusing the spent code, not by webauth.

The host's store is bound to one issuer — the ``issuer`` of its
``OidcClientConfig`` — and an account it provisions has the issuer's subject
as its ``id``. Moving to another issuer is therefore a migration of the
host's accounts, never a configuration change. This module builds on
``webauth.oidc``.

Admission holds the host's write lock and never commits: the host commits or
rolls back, and a refusal writes nothing. An ``AdmissionConfig`` states who
may enter and who is admin: the bound issuer, the app's ``login_group``, a
Keycloak group path such as ``/apps/notes``, and its ``admin_group``, a
path below it such as ``/apps/notes/admin`` (or ``NoAdmins``). Only the
issuer's groups decide the role: it is rewritten at every login, so a person
taken out of the admin group is a plain user from the next login and, the
role living on the account, on every device at once. Until that login an open
session keeps the old role. A person is a member when one of their
groups is that path or a subgroup of it, compared character for character
and by path segment, so ``/apps/notes/admin`` counts and
``/apps/notes2`` does not. The check runs on every login, before any
account is looked up or created, so a person removed from the group is
refused at their next login while their account and data stay, and a person
put back returns to the same account. It ends no session that is already
open; that lasts until the host's session lifetime runs out. The groups claim
must carry full paths (Keycloak's group mapper with ``full.path`` on); a
missing or empty claim means no membership.

After ``finish_login`` admits an account, ``open_session`` under the host's lock
ends the session the request's cookie names, prunes the account to a cap, creates
its new one, holding the login's refresh token, at the configured clock's instant, never
committing and setting no cookie, so the host commits and then issues the cookies.

``log_out`` is the third route's whole sequence: it ends the session the
request's cookie names, if any, clears the session cookies, and answers the
issuer's end-session URL for the host to send the browser to, as a 303 for a
form or as JSON for ``fetch``. It makes no outbound call and never commits,
so the person is signed out of the app even when the issuer is down, and a
request without a usable session still reaches the issuer. A forged,
oversized or duplicated cookie counts as missing: it ends no stored session,
which leaves a duplicated cookie's session until it expires, while the
browser's own cookies are still cleared.

``finish_login`` hands the browser the login's ID token in a cookie that only
the logout path receives, and ``log_out`` passes it to the issuer as
``id_token_hint`` and clears it, so the issuer ends its session without asking
the person to confirm. The hint is never decoded or verified here and is no
credential; without a usable one (missing, duplicated, oversized or not shaped
like a compact JWS) the issuer asks. Because the logout is a GET to the
issuer, the hint reaches the browser's history and any TLS-terminating edge;
once the session has ended it has no power left.

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

from webauth._media_types import media_type_of
from webauth._paths import same_app_path
from webauth._validation import require_positive_whole_number
from webauth.cookies import (
    _clear_id_token_hint_cookie,
    _clear_pending_login_cookie,
    _cookie_pairs,
    _cookie_values,
    _id_token_hint_from_request,
    _is_pending_login_cookie_name,
    _issue_id_token_hint_cookie,
    _issue_pending_login_cookie,
    _pending_login_cookie_name,
    _verify_pending_login,
    clear_session_cookies,
)
from webauth.dependencies import _renewed_expiry, _whole_second_now, session_id_from_request
from webauth.oidc import (
    PENDING_LOGIN_MAX_AGE_SECONDS,
    OidcRefusal,
    OidcRefusalReason,
    _callback_state,
)
from webauth.ports import AccountEvent, AccountEventKind, UsernameTakenError

if TYPE_CHECKING:
    from pydantic import SecretStr
    from starlette.requests import Request
    from starlette.responses import Response

    from webauth.config import WebAuthConfig
    from webauth.cookies import PendingLogin
    from webauth.oidc import OidcIdentity, OidcRelyingParty
    from webauth.ports import (
        AuditSink,
        SessionRecord,
        SessionRecordStore,
        SubjectUserStore,
        UserRecord,
        WriteLock,
    )

__all__ = [
    "AdmissionConfig",
    "AdmissionRefusal",
    "AdmittedLogin",
    "BackchannelLogoutResult",
    "EverySubject",
    "NoAdmins",
    "admit_identity",
    "finish_login",
    "log_out",
    "open_session",
    "receive_backchannel_logout",
    "start_login",
]

_MAX_PENDING_LOGINS: Final = 5
"""Pending-login cookies a browser keeps at once. A start beyond them
evicts the oldest, so repeated starts never crowd out the session cookies."""

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


def _is_member_of(group_path: str, groups: tuple[str, ...]) -> bool:
    return any(group == group_path or _is_below(group_path, group) for group in groups)


class AdmissionRefusal(StrEnum):
    """Why a verified identity does not become a signed-in account."""

    FOREIGN_ISSUER = "foreign-issuer"
    NOT_A_MEMBER = "not-a-member"
    USERNAME_TAKEN = "username-taken"


@dataclass(frozen=True)
class AdmittedLogin:
    """An admitted account, the path of this app to send the browser to (or
    ``None`` for the host's default page), and the refresh token the login's
    code exchange issued (``None`` when the issuer gave none), which
    ``open_session`` stores in the new session's row."""

    account: UserRecord
    return_to: str | None
    refresh_token: SecretStr | None


def start_login(
    relying_party: OidcRelyingParty,
    request: Request,
    response: Response,
    config: WebAuthConfig,
    *,
    return_to: str | None,
) -> str:
    """Begin a login: set its pending-login cookie on ``response`` and return
    the authorization URL the host redirects the browser to.

    ``return_to`` is the raw path and query, ``root_path`` included, that
    ``finish_login`` hands back after the login. A value that is not a path of
    this app is dropped and the login lands on the host's default page.
    """
    authorization = relying_party.begin_login()
    pending = authorization.pending.returning_to(same_app_path(request, return_to))
    for name in _pending_login_cookies_to_evict(request, config):
        _clear_pending_login_cookie(response, name, config)
    _issue_pending_login_cookie(
        response,
        pending,
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
) -> AdmittedLogin | OidcRefusal | AdmissionRefusal:
    """Complete the login the callback ``request`` returns from.

    The callback's state selects exactly one pending-login cookie, which is
    cleared on ``response`` whatever the outcome, so the host answers with
    ``response`` on every outcome, refusals included; every other tab's
    cookie stays. A callback naming no state or naming it twice, or whose state
    names no single genuine cookie, is refused before any token request. On
    an admitted login, the host opens its session for ``account`` with
    ``open_session``, commits, calls ``issue_session_cookies`` and sends the
    browser to ``return_to``, or to its default page when that is ``None``;
    ``response`` also carries the ID token hint cookie for the logout path,
    replacing an older one (see ``log_out``).
    """
    callback_query = request.url.query
    state = _callback_state(callback_query)
    if isinstance(state, OidcRefusal):
        return state
    cookie_name = _pending_login_cookie_name(state, secure=config.cookie_secure)
    _clear_pending_login_cookie(response, cookie_name, config)
    pending = _sole_pending_login(request, cookie_name, config)
    if pending is None:
        return OidcRefusal(OidcRefusalReason.STATE_MISMATCH)
    identity = relying_party.complete_login(pending, callback_query)
    if isinstance(identity, OidcRefusal):
        return identity
    admitted = admit_identity(
        identity,
        admission=admission,
        accounts=accounts,
        lock=lock,
        audit=audit,
        config=config,
    )
    if isinstance(admitted, AdmissionRefusal):
        return admitted
    _issue_id_token_hint_cookie(
        response,
        identity.id_token,
        logout_path=relying_party.logout_path,
        config=config,
    )
    return AdmittedLogin(
        account=admitted,
        return_to=same_app_path(request, pending.return_to),
        refresh_token=identity.refresh_token,
    )


def open_session(
    request: Request,
    config: WebAuthConfig,
    admitted: AdmittedLogin,
    *,
    sessions: SessionRecordStore,
    lock: WriteLock,
    max_sessions: int | None,
) -> SessionRecord:
    """Open the new session of an ``admitted`` login, ending the one the request carries.

    Under one ``lock.hold()``, reads ``config.wall_clock`` once, the same
    whole-second instant the session decider reads, and in this order: the session the
    request's cookie names is ended, whoever it belongs to; when ``max_sessions``
    is a number, the account's newest ``max_sessions - 1`` sessions are kept and
    the rest ended, so neither the replaced session nor the new one counts
    against the cap; the new session is created at that instant, expiring one
    idle period later, and holds ``admitted.refresh_token``. ``None``
    states that the host sets no cap; any other value must be a positive whole
    number. A forged, oversized or duplicated cookie ends nothing.

    Never commits and sets no cookie: the host commits, then calls
    ``issue_session_cookies`` with the returned id.
    """
    if max_sessions is not None:
        require_positive_whole_number("max_sessions", max_sessions, unit="sessions")
    replaced_session_id = session_id_from_request(request, config)
    with lock.hold():
        now = _whole_second_now(config)
        if replaced_session_id is not None:
            sessions.delete(replaced_session_id)
        if max_sessions is not None:
            sessions.prune_overflow(admitted.account.id, max_sessions - 1)
        return sessions.create(
            admitted.account.id,
            now=now,
            expires_at=_renewed_expiry(config.session_lifetime, now=now, created_at=now),
            refresh_token=admitted.refresh_token,
        )


def log_out(
    relying_party: OidcRelyingParty,
    request: Request,
    response: Response,
    config: WebAuthConfig,
    *,
    sessions: SessionRecordStore,
    lock: WriteLock,
) -> str:
    """End this browser's app session and return the issuer's end-session URL.

    The session the request's cookie names is deleted under ``lock`` and the
    session cookies are cleared on ``response`` in every case; the host then
    commits and sends the browser to the returned URL. The ID token hint the
    request carries goes into that URL, and its cookie is cleared in every case."""
    session_id = session_id_from_request(request, config)
    if session_id is not None:
        with lock.hold():
            sessions.delete(session_id)
    clear_session_cookies(response, config)
    id_token_hint = _id_token_hint_from_request(request, config)
    _clear_id_token_hint_cookie(response, logout_path=relying_party.logout_path, config=config)
    return relying_party.logout_url(id_token_hint=id_token_hint)


class BackchannelLogoutResult(Enum):
    ACCEPTED = "accepted"
    REFUSED = "refused"


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

    A request that is not one URL-encoded form with exactly one non-empty
    ``logout_token`` is refused before anything is verified or locked.
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


def _sole_pending_login(
    request: Request, cookie_name: str, config: WebAuthConfig,
) -> PendingLogin | None:
    values = _cookie_values(request, cookie_name)
    if len(values) != 1:
        return None
    return _verify_pending_login(values[0], config.signing_key)


def _pending_login_cookies_to_evict(request: Request, config: WebAuthConfig) -> list[str]:
    """The names to clear so the new pending login is one of at most
    ``_MAX_PENDING_LOGINS``, oldest first."""
    issued_at_by_name: dict[str, int] = {}
    for name, value in _cookie_pairs(request):
        if _is_pending_login_cookie_name(name, secure=config.cookie_secure):
            issued_at_by_name[name] = (
                _UNRANKED if name in issued_at_by_name else _issued_at(value, config)
            )
    oldest_first = sorted(issued_at_by_name, key=issued_at_by_name.__getitem__)
    return oldest_first[: max(0, len(oldest_first) - _MAX_PENDING_LOGINS + 1)]


def _issued_at(cookie_value: str, config: WebAuthConfig) -> int:
    pending = _verify_pending_login(cookie_value, config.signing_key)
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
    missing or empty), then ``USERNAME_TAKEN`` when the store refuses a new
    account's username. The first two write nothing and look up no account.
    No username is looked up and no local flag locks an account.
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
    audit.account_event(AccountEvent(
        kind=AccountEventKind.ROLE_CHANGED,
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
    try:
        account = accounts.create_for_subject(identity.subject, username, role)
    except UsernameTakenError:
        return AdmissionRefusal.USERNAME_TAKEN
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
